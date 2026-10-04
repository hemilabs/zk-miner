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

    // Then make a CUDA 12 runtime reachable if the host has one anywhere, so the
    // installed toolkit version stops mattering. Must run BEFORE sp1_usability, which
    // execs sp1-gpu-server and is the authority on whether this actually worked.
    ensure_cuda12_on_library_path();

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

/// The soname `sp1-gpu-server` demands. Fixed at ITS link time, not ours.
const CUDART_SONAME: &str = "libcudart.so.12";

/// Env var an operator can set to point at a CUDA 12 runtime directory directly.
const CUDA_DIR_OVERRIDE: &str = "ZKMINER_SP1_CUDA_RUNTIME_DIR";

/// Make a CUDA 12 runtime reachable for `sp1-gpu-server`, so the host's INSTALLED
/// TOOLKIT VERSION stops mattering.
///
/// The problem is narrower than "support CUDA 11 through 13". `sp1-gpu-server` is a
/// prebuilt binary we do not compile, and its `DT_NEEDED` names `libcudart.so.12`
/// specifically. A soname is matched exactly, so it will never load `.so.11` or `.so.13`
/// no matter what is installed -- there is no version negotiation to do. Note our OWN
/// CUDA prover has no libcudart dependency at all (it links only `libcuda.so.1`, whose
/// soname never changes), which is why risc0 already runs on a CUDA 11, 12 or 13 host and
/// only SP1 is affected.
///
/// So the achievable goal is: supply the one runtime library that binary needs, from
/// wherever this host happens to keep it, and let the DRIVER provide compatibility. A
/// driver is backward compatible with older runtimes, so a CUDA 12 runtime works on a
/// CUDA 13-era driver -- measured here: driver 610.43.02, toolkit 13.3, and the server
/// runs fine once a 12.x `libcudart` is reachable.
///
/// Appends rather than prepends: a deployment that already provides a working runtime
/// (the hand-written wrapper does) must keep winning, and shadowing it with a different
/// copy would be a regression for a setup that works.
///
/// This only ATTEMPTS the fix. `sp1_usability` then runs `sp1-gpu-server --version` and
/// has the final say, so a failed or wrong resolution degrades to "SP1 cleanly
/// unavailable, here is why" instead of claiming jobs it cannot prove.
fn ensure_cuda12_on_library_path() {
    // Already reachable? Then do nothing -- including the case where the operator's own
    // LD_LIBRARY_PATH already provides it.
    if existing_path_has_cudart() {
        return;
    }
    let Some(dir) = find_cuda12_runtime_dir() else {
        tracing::warn!(
            "no {CUDART_SONAME} found on this host. sp1-gpu-server is prebuilt against \
             CUDA 12 and cannot load a 11.x or 13.x runtime (the soname is matched \
             exactly), so SP1 will decline unless a CUDA 12 runtime is provided. Set \
             {CUDA_DIR_OVERRIDE} to a directory containing it, or install the \
             nvidia-cuda-runtime-cu12 package. Your CUDA TOOLKIT version does not \
             otherwise matter -- only the driver, which is backward compatible."
        );
        return;
    };
    let mut joined = std::env::var("LD_LIBRARY_PATH").unwrap_or_default();
    if !joined.is_empty() {
        joined.push(':');
    }
    joined.push_str(&dir.to_string_lossy());
    tracing::info!("found {CUDART_SONAME} in {}; adding it to LD_LIBRARY_PATH for sp1-gpu-server", dir.display());
    // Affects CHILDREN, which is what matters: the probe's exec and the gpu-server the
    // SDK forks both inherit it. Our own already-loaded libraries are unaffected.
    unsafe { std::env::set_var("LD_LIBRARY_PATH", joined) };
}

/// True if some directory already on LD_LIBRARY_PATH holds the required soname.
fn existing_path_has_cudart() -> bool {
    std::env::var("LD_LIBRARY_PATH")
        .map(|v| {
            v.split(':')
                .filter(|p| !p.is_empty())
                .any(|p| std::path::Path::new(p).join(CUDART_SONAME).exists())
        })
        .unwrap_or(false)
}

/// Candidate directories that may hold `libcudart.so.12`, in priority order.
///
/// Covers the layouts a CUDA 12 runtime actually ships in: an explicit override, a copy
/// bundled beside this binary, versioned toolkit installs, the distro package, pip's
/// `nvidia-cuda-runtime-cu12` wheel (which is how THIS host has one, nested ~13 levels
/// deep inside a venv -- a shallow search misses it), and conda.
fn cuda12_candidate_dirs() -> Vec<std::path::PathBuf> {
    use std::path::PathBuf;
    let mut v: Vec<PathBuf> = Vec::new();

    // 1. Operator override wins outright.
    if let Ok(d) = std::env::var(CUDA_DIR_OVERRIDE) {
        if !d.is_empty() {
            v.push(PathBuf::from(d));
        }
    }
    // 2. Shipped beside the worker binary, so a release can be self-contained.
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            v.push(dir.join("cuda12"));
            v.push(dir.to_path_buf());
        }
    }
    // 3. Versioned toolkit installs. Both the modern `targets/` layout and plain lib64.
    if let Ok(rd) = std::fs::read_dir("/usr/local") {
        let mut hits: Vec<PathBuf> = rd
            .flatten()
            .map(|e| e.path())
            .filter(|p| {
                p.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.starts_with("cuda-12"))
            })
            .collect();
        hits.sort(); // deterministic, and newest 12.x last
        hits.reverse();
        for base in hits {
            v.push(base.join("targets/x86_64-linux/lib"));
            v.push(base.join("lib64"));
        }
    }
    // 4. Distro package.
    v.push(PathBuf::from("/usr/lib/x86_64-linux-gnu"));
    // 5. conda.
    if let Ok(p) = std::env::var("CONDA_PREFIX") {
        if !p.is_empty() {
            v.push(PathBuf::from(p).join("lib"));
        }
    }
    // 6. pip wheels. VIRTUAL_ENV first, then the user site dir, then any venv under
    //    ~/.local/opt — the wheel always lands at
    //    <root>/lib/pythonX.Y/site-packages/nvidia/cuda_runtime/lib.
    let mut roots: Vec<PathBuf> = Vec::new();
    if let Ok(ve) = std::env::var("VIRTUAL_ENV") {
        if !ve.is_empty() {
            roots.push(PathBuf::from(ve));
        }
    }
    if let Ok(home) = std::env::var("HOME") {
        roots.push(PathBuf::from(&home).join(".local"));
        if let Ok(rd) = std::fs::read_dir(PathBuf::from(&home).join(".local/opt")) {
            roots.extend(rd.flatten().map(|e| e.path()));
        }
    }
    for root in roots {
        if let Ok(rd) = std::fs::read_dir(root.join("lib")) {
            for py in rd.flatten().map(|e| e.path()) {
                v.push(py.join("site-packages/nvidia/cuda_runtime/lib"));
            }
        }
    }
    v
}

/// First candidate directory that actually contains the required soname.
fn find_cuda12_runtime_dir() -> Option<std::path::PathBuf> {
    cuda12_candidate_dirs()
        .into_iter()
        .find(|d| d.join(CUDART_SONAME).exists())
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
                "$HOME is not set, and the SP1 SDK requires it to locate ~/.sp1/bin/sp1-gpu-server (it panics without it)"
                    .to_string(),
            )
        }
    };

    // SP1 here is CUDA-only: `.cuda()` is unconditional, there is no CPU path. With no
    // NVIDIA GPU at all, nothing this worker advertises can ever be proved.
    // `detect_gpu()` alone is NOT evidence of absence: it shells out to nvidia-smi and
    // returns false identically for "no GPU", "nvidia-smi not installed", "not on PATH"
    // and "spawn failed". Those are very different things. A CUDA container started with
    // NVIDIA_DRIVER_CAPABILITIES=compute gets libcuda and the device nodes but NOT
    // nvidia-smi; a host can carry libnvidia-compute without nvidia-utils; and a fork can
    // fail transiently under memory pressure. Declining on any of those would disable SP1
    // on a host where it proves fine, and the message would mislead by blaming the GPU.
    //
    // The host-side `discovery::detect_nvidia_gpus` has exactly this fallback and states
    // the reason: do not report "0 GPUs" from an unparseable probe, because "that would
    // silently skip the CUDA worker". Only treat the GPU as absent when nvidia-smi AND
    // the kernel driver's own /proc entries agree.
    let (gpu_available, _) = detect_gpu();
    if !gpu_available && !nvidia_gpu_in_proc() {
        return Err(
            "no NVIDIA GPU detected (neither nvidia-smi nor /proc/driver/nvidia/gpus \
             reports one) and this SP1 worker is CUDA-only -- it has no CPU proving path"
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
    // Decline ONLY on an UNREPAIRABLE failure. Being stricter than this disables hosts
    // the SDK can fix by itself.
    //
    // `maybe_download_server` ignores `--version`'s exit STATUS entirely: it reads
    // stdout, compares it to SP1_CRATE_VERSION, and re-downloads on a mismatch. A stale,
    // truncated, zero-byte or wrong-version server is therefore exactly the state the SDK
    // exists to repair, and declining it here would permanently kill SP1 over something
    // that self-heals on the next run.
    //
    // What does NOT self-heal is a loader failure: the asset is pinned to the SDK's own
    // version, so a re-download reproduces the same libcudart.so.12 ABI gap. That, and a
    // binary that cannot be exec'd at all, is the only case worth declining.
    match std::process::Command::new(&server).arg("--version").output() {
        Ok(out) if out.status.success() => Ok(()),
        Ok(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr);
            let low = stderr.to_ascii_lowercase();
            let unrepairable = low.contains("error while loading shared libraries")
                || low.contains("cannot open shared object file")
                || low.contains("symbol lookup error")
                || low.contains("glibc_");
            if unrepairable {
                Err(format!(
                    "{} exists but cannot run: {}",
                    server.display(),
                    stderr.trim()
                ))
            } else {
                tracing::warn!(
                    "{} --version exited non-zero without a loader error; leaving the \
                     verdict to the SDK's own version check and re-download: {}",
                    server.display(),
                    stderr.trim()
                );
                Ok(())
            }
        }
        // Could not exec at all: not executable, wrong architecture, ENOEXEC.
        Err(e) => Err(format!("cannot execute {}: {e}", server.display())),
    }
}

/// True if the kernel driver reports at least one NVIDIA GPU, independent of nvidia-smi.
///
/// The same fallback the host-side detector uses. Present even in a container granted
/// compute capability but no CUDA user-space utilities.
fn nvidia_gpu_in_proc() -> bool {
    std::fs::read_dir("/proc/driver/nvidia/gpus")
        .map(|mut d| d.any(|e| e.is_ok()))
        .unwrap_or(false)
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

    /// The override must come FIRST, so an operator can always win.
    #[test]
    fn the_override_has_top_priority() {
        let _g = super::usability_tests::env_lock().lock().unwrap();
        let saved = std::env::var(super::CUDA_DIR_OVERRIDE).ok();
        unsafe { std::env::set_var(super::CUDA_DIR_OVERRIDE, "/zz-override") };
        let got = super::cuda12_candidate_dirs();
        match saved {
            Some(v) => unsafe { std::env::set_var(super::CUDA_DIR_OVERRIDE, v) },
            None => unsafe { std::env::remove_var(super::CUDA_DIR_OVERRIDE) },
        }
        assert_eq!(
            got.first().map(|p| p.to_string_lossy().to_string()),
            Some("/zz-override".to_string()),
            "{} must be searched before anything else",
            super::CUDA_DIR_OVERRIDE
        );
    }

    /// The candidate list must cover the layouts a CUDA 12 runtime actually ships in.
    /// The pip/venv layout matters most: on this host that is the ONLY copy, nested ~13
    /// levels deep, where a shallow directory search misses it entirely.
    #[test]
    fn the_candidate_list_covers_the_real_layouts() {
        // Takes the env lock: this reads HOME/VIRTUAL_ENV/CONDA_PREFIX, and a sibling test
        // that removes HOME would otherwise delete the pip branch mid-read and fail this
        // intermittently. Passing in isolation and failing in a full run is the signature.
        let _g = super::usability_tests::env_lock().lock().unwrap();
        let dirs = super::cuda12_candidate_dirs();
        let joined: Vec<String> = dirs.iter().map(|p| p.to_string_lossy().to_string()).collect();
        let has = |frag: &str| joined.iter().any(|d| d.contains(frag));
        assert!(has("/usr/lib/x86_64-linux-gnu"), "distro package dir missing: {joined:?}");
        assert!(
            has("site-packages/nvidia/cuda_runtime/lib"),
            "pip wheel layout missing -- it is the only copy on some hosts: {joined:?}"
        );
        // A bundled copy beside the binary, so a release can be made self-contained.
        assert!(has("cuda12"), "bundled-beside-binary dir missing: {joined:?}");
    }

    /// An LD_LIBRARY_PATH that already provides the soname must be left ALONE. A
    /// deployment that works (the hand-written wrapper) must not be disturbed, and
    /// shadowing it with a different copy would regress a working setup.
    #[test]
    fn an_existing_working_library_path_is_not_disturbed() {
        let _g = super::usability_tests::env_lock().lock().unwrap();
        let tmp = std::env::temp_dir().join(format!("cudart-{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        std::fs::write(tmp.join(super::CUDART_SONAME), b"x").unwrap();

        let saved = std::env::var("LD_LIBRARY_PATH").ok();
        unsafe { std::env::set_var("LD_LIBRARY_PATH", &tmp) };
        assert!(super::existing_path_has_cudart(), "the planted dir should be detected");
        super::ensure_cuda12_on_library_path();
        let after = std::env::var("LD_LIBRARY_PATH").unwrap();
        match saved {
            Some(v) => unsafe { std::env::set_var("LD_LIBRARY_PATH", v) },
            None => unsafe { std::env::remove_var("LD_LIBRARY_PATH") },
        }
        let _ = std::fs::remove_dir_all(&tmp);
        assert_eq!(
            after,
            tmp.to_string_lossy(),
            "an already-working LD_LIBRARY_PATH must be left exactly as it was"
        );
    }

    /// And when it is NOT already reachable, resolution APPENDS (never prepends), so an
    /// operator's own entries keep precedence.
    #[test]
    fn resolution_appends_rather_than_prepends() {
        let _g = super::usability_tests::env_lock().lock().unwrap();
        let tmp = std::env::temp_dir().join(format!("cudart-ap-{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        std::fs::write(tmp.join(super::CUDART_SONAME), b"x").unwrap();

        let saved_ld = std::env::var("LD_LIBRARY_PATH").ok();
        let saved_ov = std::env::var(super::CUDA_DIR_OVERRIDE).ok();
        unsafe {
            std::env::set_var("LD_LIBRARY_PATH", "/zz-operator-first");
            std::env::set_var(super::CUDA_DIR_OVERRIDE, &tmp);
        }
        super::ensure_cuda12_on_library_path();
        let after = std::env::var("LD_LIBRARY_PATH").unwrap();
        unsafe {
            match saved_ld {
                Some(v) => std::env::set_var("LD_LIBRARY_PATH", v),
                None => std::env::remove_var("LD_LIBRARY_PATH"),
            }
            match saved_ov {
                Some(v) => std::env::set_var(super::CUDA_DIR_OVERRIDE, v),
                None => std::env::remove_var(super::CUDA_DIR_OVERRIDE),
            }
        }
        let _ = std::fs::remove_dir_all(&tmp);
        assert!(
            after.starts_with("/zz-operator-first:"),
            "the operator's entries must stay first; got {after}"
        );
        assert!(after.ends_with(&*tmp.to_string_lossy()), "resolved dir must be appended: {after}");
    }

    /// FN1. nvidia-smi absent must NOT read as "no GPU" when the kernel driver says
    /// otherwise. A CUDA container with NVIDIA_DRIVER_CAPABILITIES=compute has libcuda
    /// and the device nodes but no nvidia-smi, and declining there would disable SP1 on a
    /// host where it proves fine. The host-side detector has the same fallback.
    #[test]
    fn the_proc_fallback_agrees_with_the_driver_on_this_host() {
        let proc_says = super::nvidia_gpu_in_proc();
        let smi_says = super::detect_gpu().0;
        // On this box both should see the GPUs; the point is that the fallback is a real,
        // independent source of truth rather than a stub that always says false.
        if smi_says {
            assert!(
                proc_says,
                "/proc/driver/nvidia/gpus must see the GPUs nvidia-smi sees, or the \
                 fallback cannot rescue a container without nvidia-smi"
            );
        }
    }

    /// FN1, the decisive case: with nvidia-smi made unreachable, the probe must NOT
    /// decide the GPU is absent, because /proc still knows better.
    #[test]
    fn an_unreachable_nvidia_smi_does_not_mean_no_gpu() {
        let _g = super::usability_tests::env_lock().lock().unwrap();
        if !super::nvidia_gpu_in_proc() {
            return; // no GPU on this machine at all: nothing to assert
        }
        let saved = std::env::var("PATH").ok();
        unsafe { std::env::set_var("PATH", "/nonexistent-for-test") };
        let smi = super::detect_gpu().0;
        let r = super::sp1_usability();
        match saved {
            Some(v) => unsafe { std::env::set_var("PATH", v) },
            None => unsafe { std::env::remove_var("PATH") },
        }
        assert!(!smi, "with PATH emptied nvidia-smi must be unreachable for this test to mean anything");
        if let Err(e) = r {
            assert!(
                !e.contains("no NVIDIA GPU"),
                "the /proc fallback must prevent a 'no GPU' verdict here; got: {e}"
            );
        }
    }

    /// FN2. A non-zero `--version` that is NOT a loader failure must NOT be declined:
    /// that is the stale/wrong-version state `maybe_download_server` exists to repair,
    /// and the SDK ignores the exit status entirely.
    #[test]
    fn a_non_loader_failure_is_left_to_the_sdk() {
        let _g = super::usability_tests::env_lock().lock().unwrap();
        let tmp = std::env::temp_dir().join(format!("sp1probe-nz-{}", std::process::id()));
        let bin = tmp.join(".sp1/bin");
        std::fs::create_dir_all(&bin).unwrap();
        // Executable, runs, exits non-zero, says nothing about shared libraries.
        std::fs::write(bin.join("sp1-gpu-server"), b"#!/bin/sh\necho 'bad args' >&2\nexit 2\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(bin.join("sp1-gpu-server"), std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let saved = std::env::var("HOME").ok();
        unsafe { std::env::set_var("HOME", &tmp) };
        let r = super::sp1_usability();
        match saved {
            Some(h) => unsafe { std::env::set_var("HOME", h) },
            None => unsafe { std::env::remove_var("HOME") },
        }
        let _ = std::fs::remove_dir_all(&tmp);
        if let Err(e) = r {
            assert!(
                e.contains("GPU"),
                "a plain non-zero exit must be left to the SDK, not declined: {e}"
            );
        }
    }

    /// FN2 converse: a LOADER failure is unrepairable (the asset is version-pinned, so a
    /// re-download reproduces it) and must still be declined.
    #[test]
    fn a_loader_failure_is_still_declined() {
        let _g = super::usability_tests::env_lock().lock().unwrap();
        let tmp = std::env::temp_dir().join(format!("sp1probe-ld-{}", std::process::id()));
        let bin = tmp.join(".sp1/bin");
        std::fs::create_dir_all(&bin).unwrap();
        std::fs::write(
            bin.join("sp1-gpu-server"),
            b"#!/bin/sh\necho 'error while loading shared libraries: libcudart.so.12: cannot open shared object file' >&2\nexit 127\n",
        ).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(bin.join("sp1-gpu-server"), std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let saved = std::env::var("HOME").ok();
        unsafe { std::env::set_var("HOME", &tmp) };
        let r = super::sp1_usability();
        match saved {
            Some(h) => unsafe { std::env::set_var("HOME", h) },
            None => unsafe { std::env::remove_var("HOME") },
        }
        let _ = std::fs::remove_dir_all(&tmp);
        let e = r.expect_err("a loader failure must be declined");
        assert!(e.contains("cannot run") || e.contains("GPU"), "unexpected: {e}");
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
