//! RISC Zero prover worker binary.
//!
//! Long-running process that communicates with the host via stdin/stdout IPC.
//! Stderr is used for logging (captured and forwarded by host).

use std::io::{self, BufReader, BufWriter};
use std::time::Instant;

mod groth16_component;
#[cfg(feature = "metal")]
mod metal_host;
/// The Metal sizing table and the macOS footprint ceiling, shared with the host (single source of
/// truth, M6). The worker does not depend on `zkminer-prover`, so it compiles that crate's
/// dependency-free file into itself.
#[cfg(target_os = "macos")]
#[allow(dead_code)]
#[path = "../../zkminer-prover/src/metal_sizing.rs"]
mod metal_sizing;
#[cfg(feature = "metal")]
mod metal_start;
// `mac_footprint`: inline at the end of this file.
#[cfg(all(feature = "metal", not(target_os = "macos")))]
compile_error!("feature `metal` builds the Apple Silicon worker: build it on macOS (aarch64-apple-darwin)");

use anyhow::{Context, Result};
use risc0_zkvm::Prover as _;
use zkminer_prover_protocol::types::CUDA_VRAM_BYTES_ENV;
use zkminer_prover_protocol::{
    is_gpu_oom, read_message, write_message, BenchmarkEntry, ErrorKind, WorkerCommand,
    WorkerResponse, BACKEND_RISC0, BENCH_BIGINT_MUL, BENCH_CHACHA_MIX, BENCH_ECDSA_VERIFY,
    BENCH_FIBONACCI, BENCH_MEMORY_MERKLE, BENCH_SHA256_CHAIN, EXECUTE_JOURNAL_MAX_BYTES,
    PROTOCOL_VERSION, RISC0_JOB_PO2_MAX, RISC0_JOB_PO2_MIN,
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

/// Test only (cargo feature `testing`, never in a release build's defaults): a worker that leaks
/// `ZKMINER_TEST_LEAK_MIB_PER_PROOF` MiB of touched host memory after every successful proof, so
/// `tests/metal_worker.rs` can drive the dispatcher's memory-growth recycle net (M9) against a real
/// leaking Metal worker.
#[cfg(feature = "testing")]
mod test_leak {
    pub(crate) const ENV: &str = "ZKMINER_TEST_LEAK_MIB_PER_PROOF";

    pub(crate) fn after_proof() {
        static LEAKED: std::sync::Mutex<Vec<Box<[u8]>>> = std::sync::Mutex::new(Vec::new());
        let Some(mib) = std::env::var(ENV)
            .ok()
            .and_then(|v| v.trim().parse::<usize>().ok())
            .filter(|&m| m > 0)
        else {
            return;
        };
        // Written, not just allocated: untouched pages are not in the footprint.
        let block = vec![0xA5u8; mib << 20].into_boxed_slice();
        let mut leaked = LEAKED.lock().unwrap_or_else(|e| e.into_inner());
        leaked.push(block);
        tracing::warn!(
            "testing: leaked {mib} MiB after this proof ({} MiB in all, {ENV})",
            leaked.len() * mib
        );
    }
}

fn main() {
    // M9: proving threads at user-initiated QoS, and out of the Darwin background policy if started
    // under it. First of all, so rayon's global pool is built with it before anything uses it.
    #[cfg(feature = "metal")]
    let qos = metal_start::apply_proving_qos();
    #[cfg(feature = "intel")]
    use_shipped_level_zero_driver();
    // M8: drop the segment prover before recursion on every proof unless the operator chose a
    // mode (`metal_host::release_seg_mode_default`). First thing, before any thread exists.
    #[cfg(feature = "metal")]
    metal_host::default_release_segment_prover_before_recursion();
    // W7-M11: the offline Metal archives the installer packaged beside this binary, if any
    // (`ZKMINER_METAL_AOT=0` off). Before any thread reads the environment or opens a library.
    #[cfg(feature = "metal")]
    metal_start::apply_packaged_aot_dir();

    // `--metal-arch`: print this Mac's GPU architecture (the offline archive set it can use) for
    // the installer, and exit. Speaks no IPC.
    #[cfg(feature = "metal")]
    if std::env::args().any(|a| a == "--metal-arch") {
        match metal_start::gpu_architecture() {
            Some(arch) => println!("{arch}"),
            None => {
                eprintln!("no Metal device architecture");
                std::process::exit(2);
            }
        }
        return;
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
        #[cfg(feature = "metal")]
        {
            metal_start::log_qos(&qos);
            metal_start::log_aot_decision();
        }
        if let Some(refusal) = gpu_refusal() {
            eprintln!("{refusal}");
            std::process::exit(2);
        }
        // W7-M10: here only, `ZKMINER_OWNER_ACTIVE=1` plans with the owner-active tier; with
        // `ZKMINER_METAL_ENFORCE_BUDGET=1` the plan is enforced. Before any proof or HAL runtime
        // (which read these variables); rayon's idle pool and the Metal device already exist.
        #[cfg(feature = "metal")]
        if let Some(plan) = metal_host::apply_planned_budget(true) {
            tracing::info!("Metal budget: {}", plan.note);
            eprintln!("Metal budget: {}", plan.note);
        }
        // Not orphan-watched: run by hand, its parent is a shell.
        #[cfg(target_os = "macos")]
        mac_footprint::start_guard(false);
        // The witness graph builds on the CPU while the pipelines warm up and the first program
        // proves, so the first wrap does not wait for it (M7).
        #[cfg(feature = "metal")]
        metal_host::start_groth16_graph_preload("benchmark start");
        #[cfg(feature = "metal")]
        {
            let host = metal_host::support()
                .as_ref()
                .expect("checked by gpu_refusal");
            eprintln!(
                "Metal device {} ({:.0} GiB RAM): {:.1} GiB recommended working set, limit {:.1} \
                 GiB, default segment po2 {}",
                host.name,
                host.host_memory as f64 / (1u64 << 30) as f64,
                host.recommended_working_set as f64 / (1u64 << 30) as f64,
                metal_host::working_set_limit().unwrap_or(0) as f64 / (1u64 << 30) as f64,
                default_job_po2(),
            );
            let power = metal_start::log_power_state("benchmark start");
            eprintln!("Power state: {}", power.describe());
            if let Some(why) = power.reduced() {
                eprintln!("WARNING: {why}: these results are below this Mac's full proving speed");
            }
            // Pipelines, then the first job's warm state (M9), so the first program is measured
            // at the speed every later job runs at.
            eprintln!("{}", metal_start::prewarm_first_job(default_job_po2()));
        }
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
    let ipc_stdout = {
        use std::os::unix::io::{AsRawFd, FromRawFd};
        let stdout_fd = io::stdout().as_raw_fd(); // FD 1
        let ipc_fd = dup_cloexec(stdout_fd).expect("dup(stdout) failed");
        unsafe { libc::dup2(io::stderr().as_raw_fd(), stdout_fd) };
        unsafe { std::fs::File::from_raw_fd(ipc_fd) }
    };
    #[cfg(not(unix))]
    let ipc_stdout = io::stdout();

    {
        use tracing_subscriber::prelude::*;
        tracing_subscriber::registry()
            .with(
                tracing_subscriber::fmt::layer()
                    .with_writer(io::stderr)
                    .with_filter(
                        tracing_subscriber::EnvFilter::try_from_default_env()
                            .unwrap_or_else(|_| "info".into()),
                    ),
            )
            // Whatever RUST_LOG says: an Execute reports how often its guest read host entropy.
            .with(sys_rand_draws::Counter.with_filter(sys_rand_draws::filter()))
            .init();
    }

    // Load (or create) the `sys_rand` key now, outside any job: a failure inside a job's panic
    // containment would be blamed on that job's program.
    sys_rand_key();

    // W7-M10: with `ZKMINER_METAL_ENFORCE_BUDGET=1` the HAL enforces the limit this worker plans
    // with (the dispatcher's figure for this job tier); set before the first request, so before
    // any proof or HAL runtime reads it. rayon's (idle) pool and the Metal device `gpu_refusal`
    // opens already exist; neither reads the environment. Off by default (measured slower and
    // larger; `metal_sizing::ENFORCE_BUDGET_ENV`).
    #[cfg(feature = "metal")]
    if gpu_refusal().is_none() {
        if let Some(plan) = metal_host::apply_planned_budget(false) {
            tracing::info!("Metal budget: {}", plan.note);
        }
    }

    // macOS: the footprint ceiling the dispatcher hands every worker (there are no cgroups), and an
    // exit when the dispatcher dies (there is no PR_SET_PDEATHSIG): without it a worker orphaned
    // mid-proof proved on to the end, holding up to tens of GB of the owner's unified memory (M6).
    #[cfg(target_os = "macos")]
    mac_footprint::start_guard(true);

    // Metal: build the Groth16 witness graph in the background from the start, so the first wrap
    // of this process does not wait ~3-5 s for it (M7). Not on an unsupported Mac, and not in a
    // measure-only worker, which never wraps.
    #[cfg(feature = "metal")]
    {
        metal_start::log_qos(&qos);
        metal_start::log_aot_decision();
        if gpu_refusal().is_none() && !measure_only_worker() {
            metal_host::start_groth16_graph_preload("worker start");
            metal_start::log_power_state("worker start");
            // M9: the pipelines, this Mac's specialized eval pipeline and identity_p254's ctrl
            // group, in the background, so the first job (a respawned worker gets no Warmup)
            // runs at warm speed.
            metal_start::start_first_job_prewarm(default_job_po2());
        }
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
                let resp = WorkerResponse::CapabilitiesReport {
                    backend: BACKEND_RISC0.to_string(),
                    version: risc0_zkvm::VERSION.to_string(),
                    supported_benchmarks: vec![
                        BENCH_FIBONACCI.to_string(),
                        BENCH_SHA256_CHAIN.to_string(),
                        BENCH_ECDSA_VERIFY.to_string(),
                        BENCH_BIGINT_MUL.to_string(),
                        BENCH_MEMORY_MERKLE.to_string(),
                        BENCH_CHACHA_MIX.to_string(),
                    ],
                    gpu_available,
                    gpu_name,
                };
                write_message(&mut stdout, &resp)?;
            }

            WorkerCommand::Benchmark => {
                tracing::info!("Running benchmarks...");
                let results = if let Some(refusal) = gpu_refusal() {
                    tracing::error!("not benchmarking: {refusal}");
                    Vec::new()
                } else {
                    #[cfg(feature = "metal")]
                    {
                        metal_start::log_power_state("benchmark");
                        metal_start::prewarm_first_job(default_job_po2());
                    }
                    run_benchmarks_streaming(&mut stdout)?
                };
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
                    if let Some(refusal) = gpu_refusal() {
                        anyhow::bail!("this worker cannot prove here: {refusal}");
                    }
                    run_proof(&elf, &input_data, po2, program_id)
                }));
                match outcome {
                    Ok(Ok((journal, seal, duration_secs, cycles))) => {
                        #[cfg(feature = "testing")]
                        test_leak::after_proof();
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
                        let kind = if is_gpu_oom(detail)
                            || detail.contains("allocation failed")
                            || is_metal_oom(detail)
                        {
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
                        // On Metal a prove panic leaves this thread's provers unusable: a mutex the
                        // panic unwound through stays poisoned (every later proof failed with
                        // `PoisonError`), and the zkvm's cached segment prover keeps its pool, which
                        // the worker cannot drop. Exit after answering, so the dispatcher starts a
                        // clean worker (it kills one on ResourceExhausted, and respawns one that died
                        // idle) instead of sending the next job to this one.
                        #[cfg(feature = "metal")]
                        {
                            use std::io::Write as _;
                            let _ = stdout.flush();
                            tracing::error!(
                                "exiting after a Metal prove panic so a clean worker replaces this one"
                            );
                            std::process::exit(METAL_PANIC_EXIT_CODE);
                        }
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
                        } else if is_gpu_oom(&msg) || is_metal_oom(&msg) {
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
                    Ok(Ok((cycles, journal, duration_secs, host_entropy_reads))) => {
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
                            host_entropy_reads,
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

            WorkerCommand::ProgramId { request_id, elf } => {
                // The image id alone: no execution. The ELF is submitter-controlled and reaches
                // risc0's parser here, which can panic on a malformed one (see the Execute arm), so a
                // panic is contained and reported as a property of the ELF. Under the same RSS
                // self-guard as Execute: the image id maps every loadable word up to a segment's
                // `p_memsz`, so a tiny crafted ELF can ask for gigabytes, and the worker exits rather
                // than let it OOM the host.
                let started = std::time::Instant::now();
                let outcome = with_rss_self_guard(execute_max_rss_bytes(), || {
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        verify_program_id(&elf, None)
                    }))
                });
                let resp = match outcome {
                    Ok(Ok(program_id)) => WorkerResponse::ProgramIdResult {
                        request_id,
                        program_id,
                        duration_secs: started.elapsed().as_secs_f64(),
                    },
                    Ok(Err(e)) => WorkerResponse::Error {
                        request_id,
                        kind: ErrorKind::InvalidInput,
                        message: format!("{e:#}"),
                    },
                    Err(_) => WorkerResponse::Error {
                        request_id,
                        kind: ErrorKind::InvalidInput,
                        message: "deriving the image id panicked on this ELF".to_string(),
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
                let calibrated = match gpu_refusal() {
                    Some(refusal) => Err(anyhow::anyhow!("{refusal}")),
                    None => run_po2_calibration(request_id, po2),
                };
                match calibrated {
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
    #[cfg(feature = "metal")]
    {
        // An unsupported Mac (Intel, 8 GB, Rosetta) reports no GPU: `metal_host::support` logs why.
        if let Ok(host) = metal_host::support() {
            return (true, Some(host.name.clone()));
        }
    }
    (false, None)
}

/// Why this worker refuses to use the GPU on this machine, or `None`. Only the Metal worker refuses
/// (Intel Macs, 8 GB Macs (`hw.memsize` under 12 GiB) and x86_64 builds under Rosetta; PLAN 9.1).
fn gpu_refusal() -> Option<String> {
    #[cfg(feature = "metal")]
    if let Err(msg) = metal_host::support() {
        return Some(msg.clone());
    }
    None
}

/// Whether host-generated text is a Metal out-of-memory (`metal_host::is_metal_oom`); always false
/// without the `metal` feature. Classified like `is_gpu_oom`, after any guest-fault text.
fn is_metal_oom(text: &str) -> bool {
    #[cfg(feature = "metal")]
    {
        metal_host::is_metal_oom(text)
    }
    #[cfg(not(feature = "metal"))]
    {
        let _ = text;
        false
    }
}

/// Exit status of a Metal worker that ends itself after a prove panic (see the Prove handler).
#[cfg(feature = "metal")]
const METAL_PANIC_EXIT_CODE: i32 = 70;

/// Why a proof at segment `po2` must not start here (`metal_host::po2_refusal`), or `None`.
fn po2_refusal(po2: u8) -> Option<String> {
    #[cfg(feature = "metal")]
    {
        metal_host::po2_refusal(po2)
    }
    #[cfg(not(feature = "metal"))]
    {
        let _ = po2;
        None
    }
}

/// The segment size used when the host names none: [`zkminer_prover_protocol::RISC0_DEFAULT_JOB_PO2`], or on a Mac the size its
/// Metal working-set limit allows (`metal_sizing::job_po2_for_limit`, PLAN 9.1: the table the host
/// sizes this Mac's jobs and benchmark row with, M6).
fn default_job_po2() -> u8 {
    #[cfg(feature = "metal")]
    {
        static PO2: std::sync::OnceLock<u8> = std::sync::OnceLock::new();
        *PO2.get_or_init(|| {
            // `metal_host` (M1) still has its own copy of the table; the shared one wins, and a
            // disagreement (pinned by `m6_tests`) is logged rather than silently followed.
            let local = metal_host::default_job_po2();
            match metal_host::working_set_limit() {
                Some(limit) => {
                    let shared = metal_sizing::job_po2_for_limit(limit);
                    if shared != local {
                        tracing::warn!(
                            "metal_host's table says po2 {local}, the shared table {shared}: using \
                             {shared}, which is what the host sizes this Mac's jobs with"
                        );
                    }
                    shared
                }
                None => local,
            }
        })
    }
    #[cfg(not(feature = "metal"))]
    {
        zkminer_prover_protocol::RISC0_DEFAULT_JOB_PO2
    }
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

/// macOS: the task's resident size from `task_info(MACH_TASK_BASIC_INFO)`, the analogue of VmRSS.
#[cfg(target_os = "macos")]
#[allow(deprecated)] // libc points at the mach2 crate for these; the call is the same.
fn self_vmrss_bytes() -> Option<u64> {
    let mut info: libc::mach_task_basic_info = unsafe { std::mem::zeroed() };
    let mut count = (std::mem::size_of::<libc::mach_task_basic_info>()
        / std::mem::size_of::<libc::natural_t>())
        as libc::mach_msg_type_number_t;
    let kr = unsafe {
        libc::task_info(
            libc::mach_task_self(),
            libc::MACH_TASK_BASIC_INFO,
            (&mut info as *mut libc::mach_task_basic_info).cast(),
            &mut count,
        )
    };
    (kr == libc::KERN_SUCCESS).then_some(info.resident_size)
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
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

/// The charge for one keccak request ([`KECCAK_REQUEST_CYCLES`]) at the request's po2.
///
/// The request's po2 is the po2 the request is PROVED at, not the session's keccak max po2: since
/// risc0 K10 the executor sizes each request to the smallest circuit that holds its permutations
/// (`request_po2`, never above the max), and the prover proves it at exactly that po2. So the charge
/// follows the proving work. Under the default max (17) every request is charged 2^20 (a smaller one
/// still pays for its lift and join). Under `RISC0_KECCAK_PO2=18` a partial batch that fits 17 is
/// charged 2^20, a full one 2^21; capped to 17 (risc0 W7-V2's headroom cap below 7084 MiB) the
/// guest makes twice the requests at 17 instead, for the same total. The charge is this build's
/// cost estimate for pricing and the deadline (`estimated_cycles` in the miner); no receipt, journal
/// or other host compares it, so it need not match across builds.
fn keccak_request_charge(po2: usize) -> u64 {
    KECCAK_REQUEST_CYCLES << po2.saturating_sub(17).min(8)
}

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
            .saturating_add(keccak_request_charge(request.po2));
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

/// The segment size a job is executed or proven at: the host's, or [`default_job_po2`]. One
/// outside [`RISC0_JOB_PO2_MIN`]..=[`RISC0_JOB_PO2_MAX`] is refused (an InvalidInput, by its "po2
/// value" text): the host measures and proves a job at sizes in that range only.
fn job_segment_po2(po2: Option<u8>) -> anyhow::Result<u8> {
    let po2 = po2.unwrap_or_else(default_job_po2);
    if !(RISC0_JOB_PO2_MIN..=RISC0_JOB_PO2_MAX).contains(&po2) {
        anyhow::bail!(
            "po2 value {po2} is outside the job range {RISC0_JOB_PO2_MIN}..={RISC0_JOB_PO2_MAX}"
        );
    }
    Ok(po2)
}

/// A keccak request the guest never assumes is charged in the cycle count but binds nothing in the
/// receipt, so a prover need not prove it: that part of the count is free to inflate. Reports the
/// evidence as unknown (`None` fails closed in `simulate`); the miner's own sizing ignores the field.
fn reads_given_keccak(reads: Option<u64>, keccak_cycles: u64, assumptions: usize) -> Option<u64> {
    if keccak_cycles > 0 && assumptions == 0 {
        None
    } else {
        reads
    }
}

/// Counts the guest's `sys_rand` calls during an execution, for `ExecuteResult.host_entropy_reads`.
///
/// `sys_rand` is the one syscall risc0's executor answers from host entropy (seeded here, see
/// [`sys_rand_seed`], but by a key the job's prover does not share): `sys_getenv` and `sys_argv` read
/// an environment and arguments this worker leaves empty, `sys_read` the job's input, `sys_cycle_count`
/// the run itself, and the keccak and verify calls are checked functions of what the guest passes.
/// So reading none beyond its runtime's own draw rules out a guest whose path depends on host
/// entropy. It does not bind the run to the proven one: the chain never checks the input, so a
/// requester who is also the prover can prove another input with the same journal.
///
/// The executor exposes no count, so this counts the line the pinned fork's handler logs at DEBUG
/// for each call (`risc0/zkvm/src/host/server/exec/syscall/random.rs`: `SYS_RANDOM: <words>`), with a
/// layer that sees that target only, whatever `RUST_LOG` filters. On the thread that logs it, which
/// is the one that runs the guest (risc0 runs the emulator on the caller's thread and only builds
/// segments on others). A fork that stops logging it reads as no draw at all, which reports `None`
/// (unknown), never 0: the real-worker test (`measure_only.rs`, the risc0 one) pins the count.
mod sys_rand_draws {
    use std::cell::Cell;

    /// The module of the fork's `sys_rand` handler.
    pub(super) const TARGET: &str = "risc0_zkvm::host::server::exec::syscall::random";
    /// Its DEBUG line for one call, before the number of words drawn.
    const PREFIX: &str = "SYS_RANDOM: ";
    /// What risc0's guest runtime draws before `main`, once: four words of memory-image entropy
    /// (`risc0_zkvm::guest::env::init`, `MEMORY_IMAGE_ENTROPY`).
    pub(super) const RUNTIME_DRAW_WORDS: u64 = 4;

    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub(super) struct Draws {
        pub calls: u64,
        /// The words the first call drew.
        pub first_words: Option<u64>,
    }

    thread_local! {
        static DRAWS: Cell<Draws> = const { Cell::new(Draws { calls: 0, first_words: None }) };
    }

    pub(super) fn reset() {
        DRAWS.with(|d| d.set(Draws::default()));
    }

    pub(super) fn take() -> Draws {
        DRAWS.with(|d| d.replace(Draws::default()))
    }

    fn note(words: u64) {
        DRAWS.with(|d| {
            let mut v = d.get();
            v.calls = v.calls.saturating_add(1);
            v.first_words.get_or_insert(words);
            d.set(v);
        });
    }

    /// The draws past the runtime's own: `None` when there was no draw at all (a guest without
    /// risc0's runtime, or a fork whose handler no longer logs the line this counts).
    pub(super) fn host_entropy_reads(d: Draws) -> Option<u64> {
        match d.first_words? {
            RUNTIME_DRAW_WORDS => Some(d.calls - 1),
            _ => Some(d.calls),
        }
    }

    pub(super) fn filter() -> tracing_subscriber::filter::Targets {
        tracing_subscriber::filter::Targets::new().with_target(TARGET, tracing::Level::DEBUG)
    }

    pub(super) struct Counter;

    impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for Counter {
        fn on_event(
            &self,
            event: &tracing::Event<'_>,
            _ctx: tracing_subscriber::layer::Context<'_, S>,
        ) {
            if event.metadata().target() != TARGET {
                return;
            }
            struct Message(Option<String>);
            impl tracing::field::Visit for Message {
                fn record_debug(
                    &mut self,
                    field: &tracing::field::Field,
                    value: &dyn std::fmt::Debug,
                ) {
                    if field.name() == "message" {
                        self.0 = Some(format!("{value:?}"));
                    }
                }
            }
            let mut m = Message(None);
            event.record(&mut m);
            if let Some(words) = m
                .0
                .as_deref()
                .and_then(|t| t.strip_prefix(PREFIX))
                .and_then(|w| w.trim().parse::<u64>().ok())
            {
                note(words);
            }
        }
    }
}

/// Execute the guest as a proof of it would, without proving: its proving cycle count, its journal,
/// how long it took, and its host-entropy reads (see [`sys_rand_draws`]).
fn run_execute(
    elf: &[u8],
    input_data: &[u8],
    program_id: Option<[u8; 32]>,
    po2: Option<u8>,
) -> anyhow::Result<(u64, Vec<u8>, f64, Option<u64>)> {
    use std::time::Instant;
    let po2 = job_segment_po2(po2)?;
    // Bind the ELF to the job's programId before spending any execution on it (the pre-claim
    // measurement path runs UNCLAIMED, submitter-controlled ELFs).
    let image_id = verify_program_id(elf, program_id)?;
    let started = Instant::now();

    let mut env_builder = risc0_zkvm::ExecutorEnv::builder();
    if !input_data.is_empty() {
        env_builder.write_slice(input_data);
    }
    env_builder.random_seed(sys_rand_seed(&sys_rand_key(), &image_id, input_data));
    // At the size the job will be proven at, on the card the host asked for: the guest can tell (see
    // `RISC0_DEFAULT_JOB_PO2`).
    env_builder.segment_limit_po2(po2 as u32);
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
    sys_rand_draws::reset();
    let session = with_rss_self_guard(execute_max_rss_bytes(), || {
        // The in-process executor, never one chosen by RISC0_EXECUTOR (an external r0vm).
        risc0_zkvm::local_executor().execute(env, elf)
    })
    .map_err(|e| anyhow::anyhow!("execute: {e}"))?;
    let host_entropy_reads = sys_rand_draws::host_entropy_reads(sys_rand_draws::take());

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
    let host_entropy_reads =
        reads_given_keccak(host_entropy_reads, keccak.cycles, assumptions.0.len());
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
        host_entropy_reads,
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
fn release_groth16_cache_if_tight() {
    static DECISION: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    let release = *DECISION.get_or_init(|| {
        // Unified memory: the GPU budget is the Metal working-set limit (which also honours
        // `RISC0_METAL_MAX_WORKING_SET_BYTES` and the host's `ZKMINER_CUDA_VRAM_BYTES`), and the key
        // is kept only if it fits beside the next proof's largest STARK phase at this Mac's segment
        // size: a kept key is 5.6 GB of the owner's RAM held between jobs.
        #[cfg(feature = "metal")]
        {
            let po2 = default_job_po2();
            let release = metal_host::working_set_limit()
                .is_none_or(|limit| !metal_host::keep_groth16_cache(limit, po2));
            tracing::info!(
                "Metal working-set limit {:.1} GiB at segment po2 {po2}: {} the Groth16 proving key \
                 between proofs",
                metal_host::working_set_limit().unwrap_or(0) as f64 / (1u64 << 30) as f64,
                if release { "releasing" } else { "keeping" },
            );
            #[allow(clippy::needless_return)]
            return release;
        }
        #[allow(unreachable_code)]
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

/// After every proof, failed or not: the Groth16 cache decision above, and on Metal the provers this
/// thread caches, so their GPU memory (the owner's RAM on a Mac) is returned between jobs.
fn release_after_proof() {
    release_groth16_cache_if_tight();
    #[cfg(feature = "metal")]
    metal_host::release_after_proof();
}

/// The in-process prover, never one `RISC0_PROVER` names (an external r0vm, or a remote service,
/// which would also refuse our `sys_rand` seed). Every caller pairs it with options built with dev
/// mode off, whatever `RISC0_DEV_MODE` says: a dev-mode receipt is fake, and claiming on one ends in a
/// penalized release.
fn local_prover() -> risc0_zkvm::LocalProver {
    risc0_zkvm::LocalProver::new("local")
}

/// Calls [`release_after_proof`] when dropped, so it also runs while a panic unwinds.
struct ReleaseOnDrop;

impl Drop for ReleaseOnDrop {
    fn drop(&mut self) {
        if std::thread::panicking() {
            tracing::warn!("prove panicked: releasing this thread's cached provers");
        }
        release_after_proof();
    }
}

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
    // Refused before any work: on a Mac a segment size whose STARK cannot fit in the working set does
    // not fail, it thrashes swap for as long as it is left to run. Typed ResourceExhausted (the text
    // is the fork's out-of-memory wording), so the job goes to a bigger card.
    if let Some(refusal) = po2_refusal(po2.unwrap_or_else(default_job_po2)) {
        anyhow::bail!("{refusal}");
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
        match run_proof_once(elf, input_data, po2, seed, &image_id) {
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
fn failed_segment(msg: &str) -> Option<u64> {
    let rest = msg.split("verify segment ").nth(1)?;
    let rest = rest.strip_prefix("(last) ").unwrap_or(rest);
    let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
    digits.parse().ok()
}

/// Whether an invalid proof failed at the segment the one before it did (both known).
fn failed_twice(segment: Option<u64>, last: Option<u64>) -> bool {
    segment.is_some() && segment == last
}

/// W7-M11 revert knob: `1` makes every proof attempt compute the image id it verifies against again
/// (before: once per attempt, after the proof), instead of using the one [`run_proof`] computed when
/// it bound the ELF to the job's programId.
const RECOMPUTE_IMAGE_ID_ENV: &str = "ZKMINER_RISC0_RECOMPUTE_IMAGE_ID";

/// The image id `run_proof_once` verifies the receipt against: `computed` ([`run_proof`]'s, from
/// the same ELF bytes), or a fresh `compute_image_id` of `elf` with [`RECOMPUTE_IMAGE_ID_ENV`]`=1`.
fn verify_image_id(elf: &[u8], computed: &[u8; 32]) -> Result<risc0_zkvm::Digest> {
    if std::env::var(RECOMPUTE_IMAGE_ID_ENV).is_ok_and(|v| v.trim() == "1") {
        return risc0_zkvm::compute_image_id(elf)
            .context("Failed to compute image ID for verification");
    }
    Ok(risc0_zkvm::Digest::from(*computed))
}

fn run_proof_once(
    elf: &[u8],
    input_data: &[u8],
    po2: Option<u8>,
    seed: [u8; 32],
    image_id: &[u8; 32],
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
    let po2 = po2.unwrap_or_else(default_job_po2);
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
    #[cfg(feature = "metal")]
    if let Some(limit) = metal_host::working_set_limit() {
        // Above the default but under the hard ceiling `run_proof` enforces (`po2_refusal`).
        if po2 > default_job_po2() {
            tracing::warn!(
                "segment po2 {po2} is above the default {} for this Mac's {:.1} GiB Metal working set",
                default_job_po2(),
                limit as f64 / (1u64 << 30) as f64
            );
        }
    }
    #[cfg(feature = "metal")]
    let sampler = metal_host::PeakSampler::start();
    #[cfg(target_os = "macos")]
    let footprint = mac_footprint::Phases::start();
    let start = Instant::now();
    let proved = {
        // Releases on unwind too: a prove-path panic (a Metal budget panic mid-STARK) must not skip
        // returning the recursion provers' memory. The normal path releases when this scope ends.
        let _release = ReleaseOnDrop;
        prover.prove_with_opts(env, elf, &opts)
    };
    #[cfg(feature = "metal")]
    sampler.phase("proof");
    #[cfg(feature = "metal")]
    {
        sampler.held("held after release");
        tracing::info!("Metal peak GPU memory: {}", sampler.summary());
    }
    #[cfg(target_os = "macos")]
    {
        footprint.phase("proof");
        tracing::info!(
            "peak process footprint (host + GPU): {}",
            footprint.summary()
        );
    }
    let prove_info = proved?;
    let duration_secs = start.elapsed().as_secs_f64();

    let receipt = prove_info.receipt;

    // Verify proof locally before returning — catches GPU corruption (e.g., ROCm SHA-256 bug). The
    // image id is the one `run_proof` computed from these ELF bytes before proving (W7-M11: it was
    // computed a second time here, per attempt).
    let image_id = verify_image_id(elf, image_id)?;

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
        .segment_limit_po2(default_job_po2() as u32)
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
    // W7-M11: the power state the program is measured under, read before and after it.
    let power_before = bench_power_state();
    #[cfg(feature = "metal")]
    let sampler = metal_host::PeakSampler::start();
    #[cfg(target_os = "macos")]
    let footprint = mac_footprint::Phases::start();

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
    #[cfg(feature = "metal")]
    sampler.phase("segments");
    #[cfg(target_os = "macos")]
    footprint.phase("segments");

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
    #[cfg(feature = "metal")]
    sampler.phase("recursion");
    #[cfg(target_os = "macos")]
    footprint.phase("recursion");

    // Stage 3: STARK-to-SNARK. Proves the fixed `stark_verify` circuit with a fixed proving key
    // (`~/.risc0/extensions/*-risc0-groth16/stark_verify_final.zkey`), so it does not depend on the
    // program at all — which is the reason to report it apart from the stages above.
    let started = Instant::now();
    let wrapped = prover.compress(
        &risc0_zkvm::ProverOpts::groth16().with_dev_mode(false),
        &succinct,
    );
    let wrap_secs = started.elapsed().as_secs_f64();
    #[cfg(feature = "metal")]
    sampler.phase("wrap");
    #[cfg(target_os = "macos")]
    footprint.phase("wrap");
    // Outside the stopwatch: the release is not part of the wrap, and on a card that releases, the NEXT
    // wrap pays the reload — which is that card's honest per-proof cost.
    release_after_proof();
    #[cfg(feature = "metal")]
    {
        sampler.held("held after release");
        tracing::info!(
            "{name}: Metal peak GPU memory at po2 {}: {}",
            default_job_po2(),
            sampler.summary()
        );
    }
    #[cfg(target_os = "macos")]
    {
        footprint.phase("held after release");
        tracing::info!(
            "{name}: peak process footprint (host + GPU) at po2 {}: {}",
            default_job_po2(),
            footprint.summary()
        );
    }
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
    dump_benchmark_receipt(name, &groth16, image_id);

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

    let power_state = match (power_before, bench_power_state()) {
        (Some(a), Some(b)) => Some(a.merge(b)),
        (a, b) => a.or(b),
    };
    if let Some(why) = power_state.and_then(|p| p.reduced()) {
        tracing::warn!(
            "{name}: measured in reduced power ({why}); the host prices it as measured and \
             advises a re-benchmark once the Mac is back at full power (a thermal mark is \
             informational)"
        );
    }

    Some(BenchmarkEntry {
        program_name: name.to_string(),
        prover_backend: BACKEND_RISC0.to_string(),
        cycles,
        duration_secs,
        throughput,
        weight,
        precompile,
        wrap_secs: Some(wrap_secs),
        power_state,
    })
}

/// Test aid (P31-19): with `ZKMINER_BENCH_RECEIPT_DIR` set, write each verified benchmark Groth16
/// receipt there as `<name>.groth16.receipt` (bincode 1.3 `risc0_zkvm::Receipt`, the encoding an
/// independent verifier such as risc0's `tools/stock_verify31` reads) with `<name>.image_id` (hex).
/// Unset (the default): nothing is written. A failed write is logged, never fatal.
fn dump_benchmark_receipt(name: &str, receipt: &risc0_zkvm::Receipt, image_id: risc0_zkvm::Digest) {
    let Some(dir) = std::env::var_os("ZKMINER_BENCH_RECEIPT_DIR") else {
        return;
    };
    let dir = std::path::PathBuf::from(dir);
    let written = std::fs::create_dir_all(&dir)
        .map_err(anyhow::Error::from)
        .and_then(|()| Ok(bincode::serialize(receipt)?))
        .and_then(|bytes| {
            std::fs::write(dir.join(format!("{name}.groth16.receipt")), bytes)?;
            std::fs::write(dir.join(format!("{name}.image_id")), image_id.to_string())?;
            Ok(())
        });
    match written {
        Ok(()) => tracing::info!("{name}: Groth16 receipt written to {}", dir.display()),
        Err(e) => tracing::warn!("{name}: could not write the Groth16 receipt: {e:#}"),
    }
}

/// The power state a benchmark entry reports (protocol v12, W7-M11): on a Mac, M9's reading;
/// elsewhere, and with `ZKMINER_POWER_STATE_IN_BENCH=0`, none.
fn bench_power_state() -> Option<zkminer_prover_protocol::BenchPowerState> {
    if zkminer_prover_protocol::power_state_in_bench_off() {
        return None;
    }
    #[cfg(feature = "metal")]
    {
        Some(metal_start::power_state().to_bench())
    }
    #[cfg(not(feature = "metal"))]
    {
        None
    }
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
const CALIBRATION_ITERS: u32 = 6_000_000;

/// The one-time setup before a first proof (`WorkerCommand::Warmup`), which the miner runs before it
/// claims any risc0 job. Every backend: the `risc0-groth16` component every proof's Groth16 wrap
/// needs, installed if it is missing (`groth16_component`). On Intel, also the kernels: SYCL compiles
/// those shipped as SPIR-V (the zkp and Groth16 ones) for the device on first use, which took ~8
/// minutes on an Arc B580, longer than a benchmark's whole budget; the driver caches the result on
/// disk (`~/.cache/libsycl_cache`, `~/.cache/neo_compiler_cache`), so one small proof through the
/// full Groth16 pipeline compiles everything once for every later process. It is verified, so a
/// broken card fails here, not on a job.
#[cfg(feature = "intel")]
fn warm_up() -> Result<String> {
    let component = groth16_component::ensure_installed()?;
    let start = Instant::now();
    let env = risc0_zkvm::ExecutorEnv::builder()
        .write_slice(&1000u32.to_le_bytes())
        .segment_limit_po2(zkminer_prover_protocol::RISC0_DEFAULT_JOB_PO2 as u32)
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

/// A dedicated measure worker: it only executes guests on the CPU (the dispatcher gives it an RSS
/// cap and no GPU figure), so it never proves or wraps.
#[cfg(feature = "metal")]
fn measure_only_worker() -> bool {
    std::env::var_os("ZKMINER_RISC0_EXECUTE_MAX_RSS_BYTES").is_some()
        && std::env::var_os(CUDA_VRAM_BYTES_ENV).is_none()
}

/// The Metal worker's one-time setup: the `risc0-groth16` component, then every circuit's Metal
/// pipeline states (`metal_host::warm_up_pipelines`; minutes cold on a newly built binary, PLAN 9.1),
/// then one small verified Groth16 proof at this Mac's default segment size, so a broken GPU fails
/// here and not on a job. A dedicated measure worker (it only executes guests on the CPU) installs
/// the component only.
#[cfg(feature = "metal")]
fn warm_up() -> Result<String> {
    if let Some(refusal) = gpu_refusal() {
        anyhow::bail!("{refusal}");
    }
    let component = groth16_component::ensure_installed()?;
    if measure_only_worker() {
        return Ok(component);
    }
    // A no-op if worker start already began it; starts it if this call just installed the component.
    metal_host::start_groth16_graph_preload("warm-up");
    let pipelines = metal_start::prewarm_first_job(default_job_po2());
    let start = Instant::now();
    let env = risc0_zkvm::ExecutorEnv::builder()
        .write_slice(&1000u32.to_le_bytes())
        .segment_limit_po2(default_job_po2() as u32)
        .build()?;
    let opts = risc0_zkvm::ProverOpts::groth16().with_dev_mode(false);
    let proved = local_prover().prove_with_opts(env, FIBONACCI_ELF, &opts);
    release_after_proof();
    proved?
        .receipt
        .verify(FIBONACCI_ID)
        .context("the warm-up proof does not verify")?;
    let summary = format!(
        "{component}; {pipelines}; verified a Groth16 proof at po2 {} in {:.1} s",
        default_job_po2(),
        start.elapsed().as_secs_f64()
    );
    tracing::info!("{summary}");
    Ok(summary)
}

#[cfg(not(any(feature = "intel", feature = "metal")))]
fn warm_up() -> Result<String> {
    groth16_component::ensure_installed()
}

/// Run a po2 calibration: prove fibonacci at the specified segment po2 and measure throughput.
fn run_po2_calibration(request_id: u64, po2: u8) -> Result<WorkerResponse> {
    if let Some(refusal) = po2_refusal(po2) {
        anyhow::bail!("{refusal}");
    }
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
    release_after_proof();
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

    /// W7-M11: a Metal worker reports the power state each benchmark entry was measured under
    /// (protocol v12); this dev Mac (mains power) reads it, at full power.
    #[cfg(feature = "metal")]
    #[test]
    fn a_metal_benchmark_entry_reports_its_power_state() {
        if zkminer_prover_protocol::power_state_in_bench_off() {
            assert_eq!(bench_power_state(), None);
            return;
        }
        let p = bench_power_state().expect("a Mac reads its power state");
        assert!(p.low_power_mode.is_some() && p.thermal.is_some(), "{p:?}");
        assert_eq!(p, metal_start::power_state().to_bench());
    }

    /// W7-M11: `run_proof_once` verifies against the image id `run_proof` bound the ELF with; it is
    /// the digest a recomputation gives (what it did before, per attempt). Prints what that
    /// recomputation cost per benchmark guest.
    #[test]
    fn the_image_id_passed_through_is_the_recomputed_one() {
        if FIBONACCI_ELF.is_empty() {
            return;
        }
        for (name, elf) in [
            ("fibonacci", FIBONACCI_ELF),
            ("sha256-chain", SHA256_CHAIN_ELF),
            ("memory-merkle", MEMORY_MERKLE_ELF),
        ] {
            let bound = verify_program_id(elf, None).unwrap();
            let t = std::time::Instant::now();
            let again = risc0_zkvm::compute_image_id(elf).unwrap();
            let cost = t.elapsed();
            assert_eq!(verify_image_id(elf, &bound).unwrap(), again, "{name}");
            eprintln!(
                "{name}: compute_image_id {:.2} ms ({} bytes ELF)",
                cost.as_secs_f64() * 1e3,
                elf.len()
            );
        }
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

#[cfg(test)]
mod sys_rand_draw_tests {
    use super::sys_rand_draws::{self, Draws};
    use super::*;

    /// W7-M10 (K10 rightsizing, W7-V2 capping): pins the charge to the PROVED po2.
    #[test]
    fn the_keccak_charge_follows_the_proved_po2() {
        let mib = 1u64 << 20;
        // Rightsized requests under the default max 17 (K10: 14, 15, 16 or 17): 2^20 each.
        for po2 in [14, 15, 16, 17] {
            assert_eq!(keccak_request_charge(po2), mib, "po2 {po2}");
        }
        // Under RISC0_KECCAK_PO2=18: a full request (18) 2^21, a partial one rightsized to 17 2^20.
        assert_eq!(keccak_request_charge(18), 2 * mib);
        // Capped to 17 (W7-V2, below 7084 MiB): two full requests at 17 for one at 18, same total.
        assert_eq!(2 * keccak_request_charge(17), keccak_request_charge(18));
        // Out of range values cannot overflow.
        assert_eq!(keccak_request_charge(usize::MAX), mib << 8);
    }

    #[test]
    fn a_keccak_charge_the_guest_never_assumes_is_no_evidence() {
        assert_eq!(reads_given_keccak(Some(0), 1 << 20, 0), None, "charged, assumed by nothing");
        assert_eq!(reads_given_keccak(Some(0), 1 << 20, 1), Some(0), "assumed: bound in the receipt");
        assert_eq!(reads_given_keccak(Some(0), 0, 0), Some(0), "no keccak at all");
        assert_eq!(reads_given_keccak(Some(3), 1 << 20, 1), Some(3));
    }

    #[test]
    fn only_draws_past_the_runtimes_own_count() {
        let reads = |calls, first_words| sys_rand_draws::host_entropy_reads(Draws { calls, first_words });
        assert_eq!(reads(0, None), None, "no draw at all is unknown, never 0");
        assert_eq!(reads(1, Some(4)), Some(0), "the runtime's own memory-image draw");
        assert_eq!(reads(2, Some(4)), Some(1));
        assert_eq!(reads(1, Some(2)), Some(1), "a first draw of another size is the guest's");
        assert_eq!(reads(3, Some(8)), Some(3));
    }

    /// The layer counts the handler's line by its target and text, on the thread that logs it.
    #[test]
    fn the_layer_counts_the_handlers_line_only() {
        use tracing_subscriber::prelude::*;
        let subscriber = tracing_subscriber::registry()
            .with(sys_rand_draws::Counter.with_filter(sys_rand_draws::filter()));
        tracing::subscriber::with_default(subscriber, || {
            sys_rand_draws::reset();
            tracing::debug!(target: "risc0_zkvm::host::server::exec::syscall::random", "SYS_RANDOM: {}", 4);
            tracing::debug!(target: "risc0_zkvm::host::server::exec::syscall::random", "SYS_RANDOM: {}", 2);
            // Not the handler: another module, or another line of it.
            tracing::debug!(target: "risc0_zkvm::host::server::exec::syscall::read", "SYS_RANDOM: {}", 9);
            tracing::debug!(target: "risc0_zkvm::host::server::exec::syscall::random", "SYS_READ: {}", 9);
            let d = sys_rand_draws::take();
            assert_eq!(d, Draws { calls: 2, first_words: Some(4) });
            assert_eq!(sys_rand_draws::host_entropy_reads(d), Some(1));
            assert_eq!(sys_rand_draws::take(), Draws::default(), "taken");
        });
    }

    /// The fibonacci guest draws nothing but its runtime's entropy: 0, which also proves this build's
    /// fork still logs the line the count reads (else `None`).
    #[test]
    fn a_guest_that_reads_no_entropy_counts_zero() {
        use tracing_subscriber::prelude::*;
        if FIBONACCI_ELF.is_empty() {
            return; // stubbed guests; nothing to validate
        }
        let image = verify_program_id(FIBONACCI_ELF, None).unwrap();
        let subscriber = tracing_subscriber::registry()
            .with(sys_rand_draws::Counter.with_filter(sys_rand_draws::filter()));
        let (_, journal, _, reads) = tracing::subscriber::with_default(subscriber, || {
            run_execute(FIBONACCI_ELF, &10u32.to_le_bytes(), Some(image), Some(20)).unwrap()
        });
        assert_eq!(journal, 55u64.to_le_bytes());
        assert_eq!(reads, Some(0));
    }
}

#[cfg(test)]
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
        assert_eq!(job_segment_po2(None).unwrap(), default_job_po2());
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

/// macOS: the worker's own memory ceiling and orphan exit, and per-phase peaks of its process
/// footprint (M6).
///
/// Linux bounds a worker from outside (a systemd `MemoryMax` cgroup cap, `oom_score_adj`,
/// `PR_SET_PDEATHSIG`); macOS has none of those, so the worker does it itself. `phys_footprint` is
/// the kernel's own accounting of what a process costs the machine (Activity Monitor's "Memory",
/// what jetsam acts on): dirty anonymous memory, compressed pages, and on a Mac the GPU allocations
/// the process made, which is what makes it the right figure on unified memory.
#[cfg(target_os = "macos")]
mod mac_footprint {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Mutex, Once};
    use std::time::Duration;

    use crate::metal_sizing::{FOOTPRINT_EXIT_CODE, WORKER_MAX_FOOTPRINT_ENV};

    /// How often the guard looks. A prover allocates GiBs per second at worst, so the ceiling can be
    /// overshot by about that much before the exit; the host reserve (3 GiB) absorbs it.
    const POLL: Duration = Duration::from_millis(50);

    /// Highest footprint seen since the last [`Phases`] boundary.
    static PHASE_PEAK: AtomicU64 = AtomicU64::new(0);

    /// `(phys_footprint, lifetime max phys_footprint)` of this process.
    pub fn self_footprint() -> Option<(u64, u64)> {
        // SAFETY: plain old data; the call fills at most one `rusage_info_v4`.
        let mut ri: libc::rusage_info_v4 = unsafe { std::mem::zeroed() };
        let rc = unsafe {
            libc::proc_pid_rusage(
                libc::getpid(),
                libc::RUSAGE_INFO_V4,
                (&mut ri as *mut libc::rusage_info_v4).cast(),
            )
        };
        (rc == 0).then_some((ri.ri_phys_footprint, ri.ri_lifetime_max_phys_footprint))
    }

    /// The ceiling from the environment: `None` if unset, `0` or malformed (a malformed value is
    /// reported, not guessed at).
    pub fn ceiling() -> Option<u64> {
        parse_ceiling(std::env::var(WORKER_MAX_FOOTPRINT_ENV).ok().as_deref())
    }

    /// [`ceiling`] without the environment: `None` for unset, `0` or malformed text.
    pub fn parse_ceiling(text: Option<&str>) -> Option<u64> {
        let text = text?;
        match text.trim().parse::<u64>() {
            Ok(0) => None,
            Ok(n) => Some(n),
            Err(_) => {
                tracing::error!("{WORKER_MAX_FOOTPRINT_ENV}={text:?} is not a byte count; ignored");
                None
            }
        }
    }

    /// Why the guard ends the process on one poll.
    #[derive(Debug, PartialEq, Eq)]
    pub enum Verdict {
        /// The footprint `now` passed the ceiling `limit`.
        OverCeiling { now: u64, limit: u64 },
        /// The worker was reparented: the dispatcher that spawned it (`parent`) is gone.
        Orphaned { parent: i32 },
    }

    impl Verdict {
        pub fn exit_code(&self) -> i32 {
            match self {
                Verdict::OverCeiling { .. } => FOOTPRINT_EXIT_CODE,
                Verdict::Orphaned { .. } => 1,
            }
        }
    }

    /// One poll's decision, free of side effects so it can be tested: `now` is the current
    /// footprint (`None` if it could not be read), `parent` the parent PID at start and `ppid` the
    /// current one. A `parent` of 0/1 (started under launchd) is never treated as orphaned.
    pub fn guard_verdict(
        now: Option<u64>,
        limit: Option<u64>,
        parent: i32,
        ppid: i32,
        watch_parent: bool,
    ) -> Option<Verdict> {
        if let (Some(now), Some(limit)) = (now, limit) {
            if now > limit {
                return Some(Verdict::OverCeiling { now, limit });
            }
        }
        (watch_parent && parent > 1 && ppid != parent).then_some(Verdict::Orphaned { parent })
    }

    /// Start the guard thread once: tracks [`PHASE_PEAK`], exits at the ceiling, and (when
    /// `watch_parent`) exits when the dispatcher that spawned this worker is gone.
    pub fn start_guard(watch_parent: bool) {
        static STARTED: Once = Once::new();
        STARTED.call_once(|| {
            let limit = ceiling();
            // SAFETY: getppid has no preconditions.
            let parent = unsafe { libc::getppid() };
            if let Some(limit) = limit {
                tracing::info!(
                    "process footprint ceiling {:.1} GiB ({WORKER_MAX_FOOTPRINT_ENV})",
                    limit as f64 / (1u64 << 30) as f64
                );
            }
            let spawned = std::thread::Builder::new()
                .name("footprint-guard".into())
                .spawn(move || loop {
                    let now = self_footprint().map(|f| f.0);
                    if let Some(now) = now {
                        PHASE_PEAK.fetch_max(now, Ordering::Relaxed);
                    }
                    // SAFETY: getppid has no preconditions.
                    let ppid = unsafe { libc::getppid() };
                    match guard_verdict(now, limit, parent, ppid, watch_parent) {
                        Some(v @ Verdict::OverCeiling { now, limit }) => {
                            tracing::error!(
                                "process footprint {} MiB passed the {} MiB ceiling \
                                 ({WORKER_MAX_FOOTPRINT_ENV}); exiting so the proof fails here \
                                 instead of pushing the Mac into swap",
                                now >> 20,
                                limit >> 20
                            );
                            std::process::exit(v.exit_code());
                        }
                        // Reparented (to launchd) means the dispatcher died: nothing will read
                        // this proof, and its memory is the owner's.
                        Some(v @ Verdict::Orphaned { parent }) => {
                            tracing::error!(
                                "the dispatcher (PID {parent}) is gone; exiting instead of \
                                 proving for nobody"
                            );
                            std::process::exit(v.exit_code());
                        }
                        None => {}
                    }
                    std::thread::sleep(POLL);
                });
            if let Err(e) = spawned {
                tracing::warn!("could not start the footprint guard: {e}");
            }
        });
    }

    /// `task_vm_info` (`<mach/task_info.h>`, through rev 7), which libc does not bind. The C struct
    /// is declared under `#pragma pack(4)`, hence `packed(4)` (without it Rust pads after
    /// `decompressions` and every later field is misplaced).
    #[repr(C, packed(4))]
    #[derive(Default)]
    struct TaskVmInfo {
        virtual_size: u64,
        region_count: i32,
        page_size: i32,
        resident_size: u64,
        resident_size_peak: u64,
        device: u64,
        device_peak: u64,
        internal: u64,
        internal_peak: u64,
        external: u64,
        external_peak: u64,
        reusable: u64,
        reusable_peak: u64,
        purgeable_volatile_pmap: u64,
        purgeable_volatile_resident: u64,
        purgeable_volatile_virtual: u64,
        compressed: u64,
        compressed_peak: u64,
        compressed_lifetime: u64,
        phys_footprint: u64,
        min_address: u64,
        max_address: u64,
        ledger: [i64; 23],
        limit_bytes_remaining: u64,
        decompressions: i32,
        ledger_swapins: i64,
        neural_nofootprint_total: i64,
        neural_nofootprint_peak: i64,
    }

    /// Where the footprint is right now: `(internal, compressed, graphics, resident)` in bytes.
    /// `internal` is the process's dirty anonymous memory (heap, Rust vectors); `graphics` is memory
    /// the GPU driver charges to the process (`ledger_tag_graphics_footprint`, Metal buffers and
    /// the driver's own allocations); `compressed` is what the compressor holds of either.
    pub fn breakdown() -> Option<(u64, u64, u64, u64)> {
        const TASK_VM_INFO: u32 = 22;
        let mut info = TaskVmInfo::default();
        let mut count = (std::mem::size_of::<TaskVmInfo>() / 4) as libc::mach_msg_type_number_t;
        // SAFETY: `info` is `count` natural_t words long and the kernel writes at most `count`.
        #[allow(deprecated)]
        let kr = unsafe {
            libc::task_info(
                libc::mach_task_self(),
                TASK_VM_INFO,
                (&mut info as *mut TaskVmInfo).cast(),
                &mut count,
            )
        };
        if kr != libc::KERN_SUCCESS {
            return None;
        }
        // ledger[0] = phys_footprint_peak; graphics_footprint is ledger index 13.
        let ledger = info.ledger; // copied out: no references into a packed struct
        let graphics = ledger[13].max(0) as u64;
        Some((info.internal, info.compressed, graphics, info.resident_size))
    }

    fn mib(b: u64) -> u64 {
        b >> 20
    }

    /// Peak footprint per named phase, like `metal_host::PeakSampler` for GPU memory.
    pub struct Phases {
        phases: Mutex<Vec<(String, u64)>>,
    }

    impl Phases {
        pub fn start() -> Self {
            let now = self_footprint().map_or(0, |f| f.0);
            PHASE_PEAK.store(now, Ordering::Relaxed);
            // The baseline: what the worker already holds before this proof (pipelines, the
            // executor's and the provers' caches), so a phase's own cost is the difference.
            Self {
                phases: Mutex::new(vec![("start".to_string(), now)]),
            }
        }

        /// Close the current phase: record its peak (including the current figure, in case the
        /// guard thread is not running) and start the next from the current figure.
        pub fn phase(&self, name: &str) {
            let now = self_footprint().map_or(0, |f| f.0);
            let peak = PHASE_PEAK.swap(now, Ordering::Relaxed).max(now);
            self.phases
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push((name.to_string(), peak));
            if let Some((internal, compressed, graphics, resident)) = breakdown() {
                tracing::info!(
                    "footprint after {name}: {} MiB = internal {} + compressed {} + graphics {} \
                     MiB (+ other); resident {} MiB",
                    mib(now),
                    mib(internal),
                    mib(compressed),
                    mib(graphics),
                    mib(resident)
                );
            }
        }

        pub fn summary(&self) -> String {
            let lifetime = self_footprint().map_or(0, |f| f.1);
            let phases = self.phases.lock().unwrap_or_else(|e| e.into_inner());
            let mut out: Vec<String> = phases
                .iter()
                .map(|(n, b)| format!("{n} {:.0} MiB", *b as f64 / (1u64 << 20) as f64))
                .collect();
            out.push(format!(
                "process lifetime peak {:.0} MiB",
                lifetime as f64 / (1u64 << 20) as f64
            ));
            out.join(", ")
        }
    }
}

#[cfg(all(test, feature = "metal"))]
mod m6_tests {
    /// M6: the host and this worker size a Mac from ONE table. `metal_host` (M1) still carries its
    /// own copy for `keep_groth16_cache` / the po2 ceiling; this pins the two together until that
    /// copy is removed.
    #[test]
    fn the_worker_and_the_host_share_the_metal_table() {
        for mib in (256..=256 * 1024u64).step_by(256) {
            let limit = mib << 20;
            assert_eq!(
                crate::metal_sizing::job_po2_for_limit(limit),
                crate::metal_host::job_po2_for_limit(limit),
                "{mib} MiB"
            );
        }
        for po2 in 13..=24 {
            assert_eq!(
                crate::metal_sizing::stark_peak_bytes(po2),
                crate::metal_host::stark_peak_bytes(po2),
                "po2 {po2}"
            );
        }
        assert_eq!(
            crate::metal_sizing::DEFAULT_JOB_PO2_CAP,
            zkminer_prover_protocol::RISC0_DEFAULT_JOB_PO2
        );
    }
}

/// M6 round 1: the footprint guard's decisions (ceiling and orphan exit) and the ceiling's parsing,
/// plus one end-to-end check that a process over the ceiling really exits with 137. None of these
/// exist on base 7469b2a (no guard at all), so they fail to compile there.
#[cfg(all(test, target_os = "macos"))]
mod mac_footprint_tests {
    use super::mac_footprint::{guard_verdict, parse_ceiling, Verdict};
    use crate::metal_sizing::{FOOTPRINT_EXIT_CODE, WORKER_MAX_FOOTPRINT_ENV};

    const GIB: u64 = 1 << 30;

    #[test]
    fn the_ceiling_parses_only_a_positive_byte_count() {
        assert_eq!(parse_ceiling(None), None);
        assert_eq!(parse_ceiling(Some("0")), None, "0 disables the guard");
        assert_eq!(parse_ceiling(Some("")), None);
        assert_eq!(parse_ceiling(Some("13G")), None, "no unit suffixes");
        assert_eq!(parse_ceiling(Some("-5")), None);
        assert_eq!(parse_ceiling(Some("13958643712")), Some(13 * GIB));
        assert_eq!(parse_ceiling(Some(" 4096\n")), Some(4096));
    }

    #[test]
    fn over_the_ceiling_exits_137() {
        let v = guard_verdict(Some(9 * GIB), Some(8 * GIB), 100, 100, true);
        assert_eq!(
            v,
            Some(Verdict::OverCeiling {
                now: 9 * GIB,
                limit: 8 * GIB
            })
        );
        assert_eq!(v.unwrap().exit_code(), FOOTPRINT_EXIT_CODE);
        assert_eq!(FOOTPRINT_EXIT_CODE, 137);
        // The ceiling wins over the orphan check when both apply.
        let both = guard_verdict(Some(9 * GIB), Some(8 * GIB), 100, 1, true).unwrap();
        assert_eq!(both.exit_code(), 137);
    }

    #[test]
    fn at_or_under_the_ceiling_or_without_one_the_guard_stays_quiet() {
        assert_eq!(
            guard_verdict(Some(8 * GIB), Some(8 * GIB), 100, 100, true),
            None
        );
        assert_eq!(
            guard_verdict(Some(GIB), Some(8 * GIB), 100, 100, true),
            None
        );
        assert_eq!(guard_verdict(Some(64 * GIB), None, 100, 100, true), None);
        assert_eq!(
            guard_verdict(None, Some(1), 100, 100, true),
            None,
            "unreadable footprint"
        );
    }

    #[test]
    fn a_reparented_worker_exits_1_only_when_watching_a_real_parent() {
        let v = guard_verdict(Some(GIB), Some(8 * GIB), 4242, 1, true);
        assert_eq!(v, Some(Verdict::Orphaned { parent: 4242 }));
        assert_eq!(v.unwrap().exit_code(), 1);
        // --benchmark (watch_parent = false) runs from a shell that may exit.
        assert_eq!(guard_verdict(Some(GIB), None, 4242, 1, false), None);
        // Started directly under launchd: there is no dispatcher to lose.
        assert_eq!(guard_verdict(Some(GIB), None, 1, 1, true), None);
        assert_eq!(guard_verdict(Some(GIB), None, 0, 1, true), None);
        assert_eq!(guard_verdict(Some(GIB), None, 4242, 4242, true), None);
    }

    /// Child half of [`a_process_over_the_ceiling_exits_137`]: inert unless the parent test set
    /// `M6_FOOTPRINT_GUARD_CHILD`.
    #[test]
    fn footprint_guard_child() {
        if std::env::var_os("M6_FOOTPRINT_GUARD_CHILD").is_none() {
            return;
        }
        super::mac_footprint::start_guard(false);
        std::thread::sleep(std::time::Duration::from_secs(10));
        // Still alive: the guard did not fire. Exit with a status the parent can tell apart.
        std::process::exit(3);
    }

    #[test]
    fn a_process_over_the_ceiling_exits_137() {
        let exe = std::env::current_exe().unwrap();
        let status = std::process::Command::new(exe)
            .args([
                "--exact",
                "mac_footprint_tests::footprint_guard_child",
                "--nocapture",
            ])
            .env("M6_FOOTPRINT_GUARD_CHILD", "1")
            // Any process's footprint is above 1 MiB.
            .env(WORKER_MAX_FOOTPRINT_ENV, (1u64 << 20).to_string())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap();
        assert_eq!(status.code(), Some(FOOTPRINT_EXIT_CODE), "{status:?}");
    }
}

#[cfg(test)]
mod sdk_version_tests {
    /// The sdk_version this worker reports at its handshake ("risc0-zkvm {VERSION}") is the one the
    /// host's protocol crate accepts: the risc0 whose seal selector the host prefixes (P31-19).
    #[test]
    fn the_handshake_sdk_version_is_the_hosts_risc0() {
        let sdk = format!("risc0-zkvm {}", risc0_zkvm::VERSION);
        assert_eq!(zkminer_prover_protocol::risc0_sdk_mismatch(&sdk), None, "{sdk}");
    }
}
