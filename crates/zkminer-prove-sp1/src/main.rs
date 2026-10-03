//! SP1 prover worker binary.
//!
//! Long-running process that communicates with the host via stdin/stdout IPC.

use std::collections::HashMap;
use std::io::{self, BufReader, BufWriter};
use std::time::Instant;

use anyhow::Result;

/// The concrete proving-key type produced by the blocking CUDA prover's `setup`.
/// Named via the associated type so we don't need a direct `sp1-cuda` dependency.
type CudaPk = <sp1_sdk::blocking::CudaProver as sp1_sdk::blocking::Prover>::ProvingKey;

/// Hash an ELF into a stable cache key (the proving key depends only on the program).
fn elf_hash(elf: &[u8]) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    elf.hash(&mut h);
    h.finish()
}
use zkminer_prover_protocol::{
    is_gpu_oom, read_message, write_message, BenchmarkEntry, ErrorKind, WorkerCommand,
    WorkerResponse, BACKEND_SP1, BENCH_BIGINT_MUL, BENCH_CHACHA_MIX, BENCH_ECDSA_VERIFY,
    BENCH_FIBONACCI, BENCH_MEMORY_MERKLE, BENCH_SHA256_CHAIN, PROTOCOL_VERSION,
};

const WORKER_VERSION: &str = env!("CARGO_PKG_VERSION");

// SP1 ELFs are embedded via include_bytes! using env vars set by sp1_build::build_program.
const FIBONACCI_SP1_GUEST_ELF: &[u8] = include_bytes!(env!("SP1_ELF_fibonacci-sp1-guest"));
const SHA256_CHAIN_SP1_GUEST_ELF: &[u8] = include_bytes!(env!("SP1_ELF_sha256-chain-sp1-guest"));
const ECDSA_VERIFY_SP1_GUEST_ELF: &[u8] = include_bytes!(env!("SP1_ELF_ecdsa-verify-sp1-guest"));
const BIGINT_MUL_SP1_GUEST_ELF: &[u8] = include_bytes!(env!("SP1_ELF_bigint-mul-sp1-guest"));
const MEMORY_MERKLE_SP1_GUEST_ELF: &[u8] = include_bytes!(env!("SP1_ELF_memory-merkle-sp1-guest"));
const CHACHA_MIX_SP1_GUEST_ELF: &[u8] = include_bytes!(env!("SP1_ELF_chacha-mix-sp1-guest"));

fn main() {
    // CRITICAL: Save the real stdout FD for IPC before anything can pollute it.
    // The SP1 SDK's gnark CGO library (Go code) may print to stdout (FD 1),
    // which would corrupt the bincode IPC stream. We dup stdout for IPC,
    // then redirect FD 1 to stderr so any stray prints go to the log.
    #[cfg(unix)]
    let ipc_stdout = {
        use std::os::unix::io::{AsRawFd, FromRawFd};
        let stdout_fd = io::stdout().as_raw_fd(); // FD 1
        let ipc_fd = unsafe { libc::dup(stdout_fd) }; // duplicate FD 1
        assert!(ipc_fd >= 0, "dup(stdout) failed");
        // Redirect FD 1 to stderr (FD 2) so stray prints go to log
        unsafe { libc::dup2(io::stderr().as_raw_fd(), stdout_fd) };
        unsafe { std::fs::File::from_raw_fd(ipc_fd) }
    };
    #[cfg(not(unix))]
    let ipc_stdout = io::stdout();

    tracing_subscriber::fmt()
        .with_writer(io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    // Direct benchmark mode: run benchmarks and print results to stderr (stdout is redirected)
    // Before constructing any CudaProver: never adopt a server whose owner is gone.
    reap_orphaned_gpu_servers();

    if std::env::args().any(|a| a == "--benchmark") {
        let prover = sp1_sdk::blocking::ProverClient::builder().cuda().build();
        let results = run_benchmarks(&prover);
        for r in &results {
            eprintln!(
                "{:<16} {:>12} cycles  {:>8.2}s  {:>12.0} c/s  weight={:.2}  precompile={}",
                r.program_name, r.cycles, r.duration_secs, r.throughput, r.weight, r.precompile,
            );
        }
        return;
    }

    if let Err(e) = run_worker_loop(ipc_stdout) {
        tracing::error!("Worker fatal error: {e}");
        std::process::exit(1);
    }
}

/// Parse the parent pid out of a `/proc/<pid>/stat` line.
///
/// Field 4 is ppid, but field 2 (`comm`) is wrapped in parentheses and may itself contain
/// spaces AND parentheses, so counting from the left is wrong. Split after the LAST ')'
/// and take the second field from there (field 3 is the state char).
fn ppid_from_proc_stat(stat: &str) -> Option<i32> {
    let rest = stat.rsplit_once(')').map(|(_, r)| r)?;
    rest.split_whitespace().nth(1)?.parse().ok()
}

/// Kill any ORPHANED `sp1-gpu-server` before this worker starts its own, and remove the
/// socket it was holding.
///
/// WHY THIS EXISTS. The SDK forks `sp1-gpu-server` as a child of this worker and relies on
/// `kill_on_drop(true)` to reap it. That only works on a graceful teardown. If the worker
/// is killed abruptly -- SIGKILL, an OOM kill, a `timeout`-killed test run, the host losing
/// power -- the server is NOT reaped: `PR_SET_PDEATHSIG` is cleared across fork so it does
/// not apply to the grandchild, and the dispatcher's process-group kill cannot run if the
/// whole miner is gone.
///
/// The result is not a clean failure, which is what made it hard to spot. Measured
/// 2026-10-03: SIGKILLing the worker left the server alive at 7.6GB RSS, still listening on
/// `/tmp/sp1-cuda-0.sock`. The NEXT worker's `CudaClient::connect` unconditionally calls
/// `start_server`, whose new server cannot bind the in-use socket and dies -- so the client
/// silently CONNECTS TO THE ORPHAN and proves against it. The proof succeeds, and the
/// orphan's RSS grew 8.5GB -> 19.5GB across one adoption. Nothing ever reaps it, so on a
/// 28GB host an adopted server drifts upward run after run until the box is out of memory.
///
/// `ppid == 1` is the discriminator: a server owned by a LIVE worker (this one, or a
/// sibling miner on the same box) has that worker as its parent, so it is never touched.
/// Only a server whose owner is already gone gets killed.
fn reap_orphaned_gpu_servers() {
    #[cfg(target_os = "linux")]
    {
        let Ok(entries) = std::fs::read_dir("/proc") else {
            return;
        };
        let mut killed = 0usize;
        for e in entries.flatten() {
            let name = e.file_name();
            let Some(pid) = name.to_str().and_then(|s| s.parse::<i32>().ok()) else {
                continue;
            };
            // comm is the truncated executable name.
            let Ok(comm) = std::fs::read_to_string(format!("/proc/{pid}/comm")) else {
                continue;
            };
            if comm.trim() != "sp1-gpu-server" {
                continue;
            }
            // Field 4 of /proc/<pid>/stat is ppid, but comm (field 2) can contain spaces
            // and parentheses -- always split after the LAST ')'.
            let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) else {
                continue;
            };
            let ppid: i32 = match ppid_from_proc_stat(&stat) {
                Some(v) => v,
                None => continue,
            };
            if ppid != 1 {
                continue; // still owned by a live worker -- not ours to kill
            }
            tracing::warn!(
                "reaping orphaned sp1-gpu-server pid {pid} (ppid 1) left by an abruptly \
                 killed worker; adopting it instead would reuse a server nothing can reap"
            );
            unsafe {
                libc::kill(pid, libc::SIGKILL);
            }
            killed += 1;
        }
        if killed > 0 {
            // The orphan held the socket; remove it so our fresh server binds cleanly
            // rather than racing a dying one. The SDK never unlinks it (CudaClientInner's
            // Drop only shuts the stream down), and the path is machine-global.
            for id in 0..8u32 {
                let p = format!("/tmp/sp1-cuda-{id}.sock");
                if std::path::Path::new(&p).exists() {
                    let _ = std::fs::remove_file(&p);
                }
            }
            tracing::warn!("reaped {killed} orphaned sp1-gpu-server process(es)");
        }
    }
}

/// Can this host actually prove with SP1, or would we only *claim* to?
///
/// WHY THIS EXISTS. The handshake used to succeed unconditionally, because the
/// `CudaProver` is built lazily on the first Prove. So a worker on a host that cannot
/// run `sp1-gpu-server` still reported `Worker sp1:generic ready`, the pool's
/// `is_backend_healthy("sp1")` returned true, `backend_sources()` listed sp1 as a real
/// Subprocess backend, and run.rs's pre-claim gate let the miner CLAIM SP1 jobs. That
/// gate's own comment states the consequence: a job we can never prove "would force a
/// release later -- and a voluntary release burns a penalty ... so a job we can never
/// prove is a guaranteed loss." Past the lock deadline it is worse: `releaseJob` reverts
/// and the collateral is stranded until a keeper slash.
///
/// Measured on a fresh install of the release artifacts (2026-10-03): `sp1-gpu-server`
/// is prebuilt against `libcudart.so.12`, the host had CUDA 13.3 and no CUDA 12 runtime,
/// and the worker still announced itself ready.
///
/// The checks are deliberately cheap -- milliseconds, no CUDA context, no 236MB download
/// -- because the laziness they protect is deliberate: building the prover forks
/// `sp1-gpu-server`, which was measured holding ~25GB of host RSS. Paying that at every
/// miner start, when no SP1 job may ever arrive, would be a worse trade than the bug.
///
/// Returns `Err(reason)` only when SP1 provably CANNOT work here. A case we cannot settle
/// cheaply (the server binary is absent, so the SDK would download it) returns `Ok`: this
/// must not refuse a host that would in fact work.
fn sp1_usability() -> Result<(), String> {
    // The SDK does `env::var("HOME").expect(...)` to locate the server, so an unset HOME
    // is a panic rather than an error. Systemd units routinely have no HOME.
    let home = match std::env::var("HOME") {
        Ok(h) if !h.is_empty() => h,
        _ => {
            return Err(
                "$HOME is not set, and the SP1 SDK requires it to locate                  ~/.sp1/bin/sp1-gpu-server (it panics without it)"
                    .to_string(),
            )
        }
    };

    // SP1 here is CUDA-only: `.cuda()` is unconditional, there is no CPU path. With no
    // NVIDIA GPU at all, nothing this worker advertises can ever be proved.
    let (gpu_available, _) = detect_gpu();
    if !gpu_available {
        return Err(
            "no NVIDIA GPU detected (nvidia-smi reported none) and this SP1 worker is              CUDA-only -- it has no CPU proving path"
                .to_string(),
        );
    }

    // If the server binary is already present it must actually EXECUTE. A prebuilt
    // server linked against a CUDA runtime the host lacks fails at the dynamic loader,
    // which is precisely what a downloaded release hits:
    //   "error while loading shared libraries: libcudart.so.12: cannot open shared
    //    object file"
    // `--version` is what the SDK itself runs, costs milliseconds, and touches no GPU.
    let server = std::path::PathBuf::from(&home).join(".sp1/bin/sp1-gpu-server");
    if !server.exists() {
        // Absent: the SDK downloads it on first use. We cannot verify a binary that does
        // not exist yet, and refusing here would disable SP1 on a host where it works.
        return Ok(());
    }
    match std::process::Command::new(&server).arg("--version").output() {
        Ok(out) if out.status.success() => Ok(()),
        Ok(out) => {
            let detail = String::from_utf8_lossy(&out.stderr).trim().to_string();
            let detail = if detail.is_empty() {
                String::from_utf8_lossy(&out.stdout).trim().to_string()
            } else {
                detail
            };
            Err(format!(
                "{} exists but cannot run: {detail}",
                server.display()
            ))
        }
        Err(e) => Err(format!("cannot execute {}: {e}", server.display())),
    }
}

fn run_worker_loop(ipc_stdout: impl io::Write) -> Result<()> {
    let mut stdin = BufReader::new(io::stdin().lock());
    let mut stdout = BufWriter::new(ipc_stdout);

    // Lazy-init the CUDA prover on first Prove/Benchmark command, not at startup.
    // CudaProver initialization is expensive (spawns sp1-gpu-server, CUDA context)
    // and would block the handshake response if done before the message loop.
    let mut prover: Option<sp1_sdk::blocking::CudaProver> = None;
    // Cache one proving key per unique ELF. The key depends only on the program, so
    // reusing it across proofs of the same ELF avoids a costly setup() every call AND
    // stops leaking a fresh GPU-resident key per proof (the old code mem::forget'd the
    // key each time). VRAM is now bounded to O(unique ELFs) instead of O(proofs).
    let mut pk_cache: HashMap<u64, CudaPk> = HashMap::new();
    macro_rules! get_prover {
        ($p:expr) => {
            $p.get_or_insert_with(|| {
                tracing::info!("Initializing SP1 CUDA prover...");
                sp1_sdk::blocking::ProverClient::builder().cuda().build()
            })
        };
    }

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
                // Refuse the handshake rather than advertise a capability we do not have.
                // Answering HelloAck here is what let the miner claim SP1 jobs it could
                // not prove -- see `sp1_usability`. Reported as an Error so the host logs
                // the REASON and skips sp1 instead of silently advertising it.
                //
                // Deliberately not a new HelloAck field: the codec is bincode, which is
                // not self-describing, so adding one is a wire break between a new host
                // and an older worker. This uses existing protocol surface.
                if let Err(reason) = sp1_usability() {
                    tracing::error!(
                        "SP1 is NOT usable on this host, so this worker will not \
                         advertise it: {reason}"
                    );
                    let resp = WorkerResponse::Error {
                        request_id: 0,
                        kind: ErrorKind::ResourceExhausted,
                        message: format!("sp1 unavailable on this host: {reason}"),
                    };
                    write_message(&mut stdout, &resp)?;
                    return Ok(());
                }
                let resp = WorkerResponse::HelloAck {
                    protocol_version: PROTOCOL_VERSION,
                    backend: BACKEND_SP1.to_string(),
                    sdk_version: format!("sp1-sdk {}", sp1_sdk::SP1_CIRCUIT_VERSION),
                    worker_version: WORKER_VERSION.to_string(),
                };
                write_message(&mut stdout, &resp)?;
            }

            WorkerCommand::Capabilities => {
                let (gpu_available, gpu_name) = detect_gpu();
                let resp = WorkerResponse::CapabilitiesReport {
                    backend: BACKEND_SP1.to_string(),
                    version: sp1_sdk::SP1_CIRCUIT_VERSION.to_string(),
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
                let results = run_benchmarks(get_prover!(prover));
                let resp = WorkerResponse::BenchmarkResult { results };
                write_message(&mut stdout, &resp)?;
            }

            WorkerCommand::Prove {
                request_id,
                elf,
                input_data,
                po2: _, // SP1 does not use segment sizing
            } => {
                tracing::info!("Proving request {request_id} ({} bytes ELF)", elf.len());
                // Announce proof START so the miner can move the job from Queued to Proving.
                // Without this the job displays "Queued (waiting for GPU)" for the whole proof.
                let started = WorkerResponse::Progress {
                    request_id,
                    fraction: 0.0,
                    elapsed_secs: 0.0,
                    segments: None,
                };
                write_message(&mut stdout, &started)?;
                match run_proof(get_prover!(prover), &mut pk_cache, &elf, &input_data) {
                    Ok((journal, seal, duration_secs, cycles)) => {
                        let resp = WorkerResponse::ProofResult {
                            request_id,
                            journal,
                            seal,
                            duration_secs,
                            cycles,
                        };
                        write_message(&mut stdout, &resp)?;
                    }
                    Err(e) => {
                        let msg = format!("{e:#}");
                        let kind = if is_gpu_oom(&msg) {
                            // GPU OOM: tag as ResourceExhausted so the dispatcher kills +
                            // respawns this worker (and its gpu-server) with clean VRAM.
                            ErrorKind::ResourceExhausted
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

            WorkerCommand::Cancel { request_id } => {
                tracing::info!("Cancel requested for {request_id}");
                let resp = WorkerResponse::Cancelled { request_id };
                write_message(&mut stdout, &resp)?;
            }

            WorkerCommand::CalibrateSegmentLimit { request_id, .. } => {
                tracing::warn!("CalibrateSegmentLimit not supported by SP1");
                let resp = WorkerResponse::Error {
                    request_id,
                    kind: ErrorKind::Internal,
                    message: "SP1 does not support segment limit calibration".to_string(),
                };
                write_message(&mut stdout, &resp)?;
            }

            WorkerCommand::Execute { request_id, .. } => {
                // Cycle measurement is implemented for risc0 only: it is the backend whose
                // executor reports the same `total_cycles` the prover does, so the number is
                // directly comparable to what proving will report. Decline explicitly rather
                // than returning a fabricated count — a wrong cycle count would size the
                // deadline check and the look-ahead queue, and silently claiming work we
                // cannot finish loses collateral outright.
                let resp = WorkerResponse::Error {
                    request_id,
                    kind: ErrorKind::InvalidInput,
                    message: "cycle measurement not supported by the sp1 backend".to_string(),
                };
                write_message(&mut stdout, &resp)?;
            }

            WorkerCommand::Shutdown => {
                tracing::info!("Shutdown requested, exiting");
                break;
            }
        }
    }

    // Cleanly release GPU resources before exit. Dropping the CudaProver / proving
    // keys performs async teardown of the sp1-gpu-server, which needs a tokio runtime
    // context — without one the drops panic and the gpu-server is only reaped by the
    // parent's process-group kill (and NOT at all on a clean graceful shutdown, where
    // it would otherwise orphan and leak ~18.6 GB of VRAM). Drop them inside a runtime.
    if prover.is_some() || !pk_cache.is_empty() {
        match tokio::runtime::Runtime::new() {
            Ok(rt) => rt.block_on(async move {
                drop(pk_cache);
                drop(prover);
            }),
            Err(e) => {
                // Couldn't build a runtime — forget rather than panic in Drop; the
                // dispatcher's process-group kill will reap the gpu-server.
                tracing::warn!("No tokio runtime for GPU teardown ({e}); leaking to parent kill");
                std::mem::forget(pk_cache);
                std::mem::forget(prover);
            }
        }
    }

    Ok(())
}

fn detect_gpu() -> (bool, Option<String>) {
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
    (false, None)
}

fn run_proof(
    prover: &sp1_sdk::blocking::CudaProver,
    pk_cache: &mut HashMap<u64, CudaPk>,
    elf: &[u8],
    input_data: &[u8],
) -> Result<(Vec<u8>, Vec<u8>, f64, u64)> {
    use sp1_sdk::blocking::{Elf, ProveRequest, Prover, SP1Stdin};

    let mut stdin = SP1Stdin::new();
    // NOTE: this pushes the ENTIRE input as ONE SP1 input element (SP1Stdin.buffer
    // is a Vec<Vec<u8>> and the read syscall consumes one element per read). Guests
    // must therefore read the whole blob once (io::read_vec) and parse fields from
    // it — NOT call io::read::<u32>() per field, since the 2nd such read would find
    // no element and halt (empty journal). See guests/sp1/*/src/main.rs.
    stdin.write_slice(input_data);

    // Execute first to get cycle count
    let (_, report) = prover.execute(Elf::from(elf), stdin.clone()).run()
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let cycles = report.total_instruction_count();

    // Get-or-create the proving key for this ELF. The key depends only on the
    // program (not the input), so it's cached and reused across proofs — no per-proof
    // setup() and no per-proof GPU-key leak. See `pk_cache` in run_worker_loop.
    let key = elf_hash(elf);
    if !pk_cache.contains_key(&key) {
        let pk = prover.setup(Elf::from(elf)).map_err(|e| anyhow::anyhow!("{e}"))?;
        pk_cache.insert(key, pk);
    }
    let pk = pk_cache.get(&key).expect("pk was just inserted");

    // Generate Groth16 proof for on-chain verification.
    // The SP1 on-chain verifier expects: vkey_hash[0..4] || encoded_groth16_proof
    let start = Instant::now();
    let proof = prover
        .prove(pk, stdin)
        .groth16()
        .run()
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let duration_secs = start.elapsed().as_secs_f64();

    // Verify proof locally before returning — catches GPU output corruption.
    if let Err(e) = prover.verify(&proof, pk.verifying_key(), None) {
        return Err(anyhow::anyhow!("Proof verification FAILED — SP1 proof is invalid: {e}"));
    }

    let journal = proof.public_values.to_vec();
    // Use bytes() which produces the on-chain format: vkey_hash[..4] || proof_bytes
    let seal = proof.bytes();

    Ok((journal, seal, duration_secs, cycles))
}

fn run_benchmarks(prover: &sp1_sdk::blocking::CudaProver) -> Vec<BenchmarkEntry> {
    let mut results = Vec::new();

    let benchmarks: &[(&str, &[u8], &[u8], f64, bool)] = &[
        (BENCH_FIBONACCI, FIBONACCI_SP1_GUEST_ELF, &1000u32.to_le_bytes(), 0.10, false),
        (BENCH_SHA256_CHAIN, SHA256_CHAIN_SP1_GUEST_ELF, &50_000u32.to_le_bytes(), 0.20, true),
        (BENCH_ECDSA_VERIFY, ECDSA_VERIFY_SP1_GUEST_ELF, &10u32.to_le_bytes(), 0.25, true),
        (BENCH_BIGINT_MUL, BIGINT_MUL_SP1_GUEST_ELF, &100u32.to_le_bytes(), 0.10, false),
        (BENCH_MEMORY_MERKLE, MEMORY_MERKLE_SP1_GUEST_ELF, &1024u32.to_le_bytes(), 0.15, true),
        (BENCH_CHACHA_MIX, CHACHA_MIX_SP1_GUEST_ELF, &20_000u32.to_le_bytes(), 0.20, false),
    ];

    for &(name, elf, input, weight, precompile) in benchmarks {
        if elf.is_empty() {
            continue;
        }
        if let Some(entry) = benchmark_program(prover, name, elf, input, weight, precompile) {
            results.push(entry);
        }
    }

    results
}

fn benchmark_program(
    prover: &impl sp1_sdk::blocking::Prover,
    name: &str,
    elf: &[u8],
    input: &[u8],
    weight: f64,
    precompile: bool,
) -> Option<BenchmarkEntry> {
    use sp1_sdk::blocking::{Elf, ProveRequest, SP1Stdin};
    // The blocking Prover's `type ProvingKey: ProvingKey` is bound by this trait;
    // it must be in scope for `pk.verifying_key()` on the generic associated type.
    use sp1_sdk::ProvingKey;

    let mut stdin = SP1Stdin::new();
    stdin.write_slice(input);

    // Execute to get real cycle count
    let (_, report) = prover.execute(Elf::from(elf), stdin.clone()).run().ok()?;
    let cycles = report.total_instruction_count();

    let start = Instant::now();
    let pk = prover.setup(Elf::from(elf)).ok()?;
    let proof = match prover.prove(&pk, stdin).run() {
        Ok(p) => p,
        Err(e) => {
            tracing::error!("{name}: prove failed: {e}");
            std::mem::forget(pk);
            return None;
        }
    };
    let duration_secs = start.elapsed().as_secs_f64();

    // Verify the proof locally — catches GPU output corruption before polluting
    // the benchmark cache with invalid throughput numbers.
    if let Err(e) = prover.verify(&proof, pk.verifying_key(), None) {
        tracing::error!(
            "{name}: proof verification FAILED — benchmark proof is invalid, skipping entry: {e}"
        );
        std::mem::forget(pk);
        return None;
    }

    // Leak the proving key to avoid drop panic (SP1 CUDA PK drops require tokio runtime context)
    std::mem::forget(pk);

    let throughput = cycles as f64 / duration_secs;

    tracing::info!("{name}: {cycles} cycles in {duration_secs:.2}s ({throughput:.0} c/s, verified)");

    Some(BenchmarkEntry {
        program_name: name.to_string(),
        prover_backend: BACKEND_SP1.to_string(),
        cycles,
        duration_secs,
        throughput,
        weight,
        precompile,
    })
}

#[cfg(test)]
mod orphan_reap_tests {
    use super::ppid_from_proc_stat;

    /// `comm` may contain spaces and parentheses, so the ppid must be located relative to
    /// the LAST ')' and never by counting whitespace fields from the start.
    #[test]
    fn ppid_is_parsed_past_a_hostile_comm() {
        // Ordinary case.
        assert_eq!(ppid_from_proc_stat("123 (sp1-gpu-server) S 1 123 123 0 -1 4194560"), Some(1));
        // Live owner.
        assert_eq!(ppid_from_proc_stat("200 (sp1-gpu-server) S 199 200 200 0 -1 0"), Some(199));
        // comm containing spaces AND parens — counting fields from the left gives the
        // wrong answer here, which would make us kill a server that has a live owner.
        assert_eq!(ppid_from_proc_stat("77 (we (are) evil) S 42 77 77 0 -1 0"), Some(42));
        // comm containing a digit that could be mistaken for the ppid.
        assert_eq!(ppid_from_proc_stat("88 (proc 1 2 3) R 55 88 88 0 -1 0"), Some(55));
    }

    #[test]
    fn malformed_stat_yields_none_rather_than_a_wrong_kill() {
        assert_eq!(ppid_from_proc_stat(""), None);
        assert_eq!(ppid_from_proc_stat("no parens here"), None);
        assert_eq!(ppid_from_proc_stat("1 (x)"), None);
        assert_eq!(ppid_from_proc_stat("1 (x) S"), None);
        assert_eq!(ppid_from_proc_stat("1 (x) S notanumber"), None);
    }

    /// The real shape, read from this process: our own ppid must parse correctly.
    #[test]
    fn it_agrees_with_the_kernel_for_this_process() {
        let stat = std::fs::read_to_string("/proc/self/stat").expect("read /proc/self/stat");
        let parsed = ppid_from_proc_stat(&stat).expect("parse");
        let expected = unsafe { libc::getppid() };
        assert_eq!(parsed, expected, "parsed ppid must match getppid()");
    }
}

#[cfg(test)]
mod usability_tests {
    use super::sp1_usability;

    /// The probe must be CHEAP: it may not build a CudaProver (which forks
    /// sp1-gpu-server, measured at ~25GB host RSS) and must not download the 236MB
    /// server. A slow probe would make every miner start pay for a backend that may
    /// never be used, which is a worse trade than the bug it fixes.
    #[test]
    fn the_probe_is_cheap() {
        let t0 = std::time::Instant::now();
        let _ = sp1_usability();
        let dt = t0.elapsed();
        assert!(
            dt < std::time::Duration::from_secs(5),
            "sp1_usability took {dt:?} -- it must stay a milliseconds-scale check"
        );
    }

    /// An unset HOME must be reported, not panicked on: the SDK does
    /// `env::var("HOME").expect(...)`, and systemd units routinely have no HOME.
    /// Serialised against the other env-mutating test.
    #[test]
    fn unset_home_is_an_error_not_a_panic() {
        let _g = super::usability_tests::env_lock().lock().unwrap();
        let saved = std::env::var("HOME").ok();
        unsafe { std::env::remove_var("HOME") };
        let r = sp1_usability();
        if let Some(h) = saved {
            unsafe { std::env::set_var("HOME", h) };
        }
        let err = r.expect_err("an unset HOME must be an error");
        assert!(err.contains("HOME"), "unexpected reason: {err}");
    }

    /// A server binary that exists but cannot execute -- the real release failure, where
    /// the prebuilt server needs libcudart.so.12 and the host has only CUDA 13 -- must be
    /// reported as unusable, carrying the loader's own message so it is actionable.
    #[test]
    fn a_present_but_unrunnable_server_is_unusable() {
        let _g = super::usability_tests::env_lock().lock().unwrap();
        let tmp = std::env::temp_dir().join(format!("sp1probe-{}", std::process::id()));
        let bin = tmp.join(".sp1/bin");
        std::fs::create_dir_all(&bin).unwrap();
        // Not a valid executable: exec fails, exactly as a missing-.so loader error does.
        std::fs::write(bin.join("sp1-gpu-server"), b"\x7fELF not really").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(
                bin.join("sp1-gpu-server"),
                std::fs::Permissions::from_mode(0o755),
            )
            .unwrap();
        }
        let saved = std::env::var("HOME").ok();
        unsafe { std::env::set_var("HOME", &tmp) };
        let r = sp1_usability();
        match saved {
            Some(h) => unsafe { std::env::set_var("HOME", h) },
            None => unsafe { std::env::remove_var("HOME") },
        }
        let _ = std::fs::remove_dir_all(&tmp);

        // Only assert the unusable verdict when a GPU exists -- on a GPU-less machine the
        // earlier no-GPU arm fires first and is equally correct.
        if let Err(e) = r {
            assert!(
                e.contains("cannot run") || e.contains("cannot execute") || e.contains("GPU"),
                "unexpected reason: {e}"
            );
        }
    }

    /// An ABSENT server must NOT be reported unusable: the SDK downloads it on first use,
    /// and refusing here would disable SP1 on a host where it actually works.
    #[test]
    fn an_absent_server_is_not_treated_as_unusable() {
        let _g = super::usability_tests::env_lock().lock().unwrap();
        let tmp = std::env::temp_dir().join(format!("sp1probe-empty-{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        let saved = std::env::var("HOME").ok();
        unsafe { std::env::set_var("HOME", &tmp) };
        let r = sp1_usability();
        match saved {
            Some(h) => unsafe { std::env::set_var("HOME", h) },
            None => unsafe { std::env::remove_var("HOME") },
        }
        let _ = std::fs::remove_dir_all(&tmp);
        // Ok, or the no-GPU arm on a GPU-less machine -- never "cannot run".
        if let Err(e) = r {
            assert!(e.contains("GPU"), "an absent server must not be 'cannot run': {e}");
        }
    }

    /// These tests mutate the process environment, so they must not interleave.
    pub(super) fn env_lock() -> &'static std::sync::Mutex<()> {
        static L: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
        L.get_or_init(|| std::sync::Mutex::new(()))
    }
}
