//! SP1 prover worker binary.
//!
//! Long-running process that communicates with the host via stdin/stdout IPC.

use std::collections::HashMap;
use std::io::{self, BufReader, BufWriter};
use std::time::{Duration, Instant};

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
use zkminer_prover_protocol::proc::{self, Outcome};
use zkminer_prover_protocol::types::{
    CUDA_DEVICE_ID_ENV, CUDA_VRAM_AVAILABLE_BYTES_ENV, CUDA_VRAM_BYTES_ENV, HOST_MEM_BUDGET_ENV,
};
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

/// Duplicate `fd` with close-on-exec set.
///
/// `dup` deliberately CLEARS `FD_CLOEXEC` on the new descriptor, so without this every
/// process the worker forks -- `sp1-gpu-server`, the `--version` probe, anything the SDK
/// spawns -- inherits a writable copy of the host's IPC pipe. A grandchild that outlives us
/// then keeps the write end open, so the host's blocking `read_exact` never sees EOF and the
/// dispatcher waits forever on a worker that is already dead. The host never passes this
/// descriptor to anyone, so close-on-exec is unconditionally correct.
///
/// Extracted from `main` so the guarantee is testable: `main` cannot be called from a test
/// (it would redirect the test harness's own stdout), and a silent revert here produces a hang
/// rather than a failure.
#[cfg(unix)]
fn dup_cloexec(fd: std::os::unix::io::RawFd) -> std::io::Result<std::os::unix::io::RawFd> {
    // F_DUPFD_CLOEXEC does the dup and the flag in one step, so there is no window in which
    // a concurrent fork could inherit the descriptor.
    let new = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) };
    if new < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(new)
}

fn main() {
    // CRITICAL: Save the real stdout FD for IPC before anything can pollute it.
    // The SP1 SDK's gnark CGO library (Go code) may print to stdout (FD 1),
    // which would corrupt the bincode IPC stream. We dup stdout for IPC,
    // then redirect FD 1 to stderr so any stray prints go to the log.
    #[cfg(unix)]
    let ipc_stdout = {
        use std::os::unix::io::{AsRawFd, FromRawFd};
        let stdout_fd = io::stdout().as_raw_fd(); // FD 1
        let ipc_fd = dup_cloexec(stdout_fd).expect("dup(stdout) failed");
        // Redirect FD 1 to stderr (FD 2) so stray prints go to log
        unsafe { libc::dup2(io::stderr().as_raw_fd(), stdout_fd) };
        unsafe { std::fs::File::from_raw_fd(ipc_fd) }
    };
    #[cfg(not(unix))]
    let ipc_stdout = io::stdout();

    tracing_subscriber::fmt()
        .with_writer(io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    // Which card this worker drives, set by the dispatcher. Read here as well as in the worker loop
    // because the orphan reaping below must be scoped to it: there is one SP1 worker per card now,
    // and each must leave its siblings' servers and sockets alone.
    let our_cuda_device: Option<u32> = std::env::var(CUDA_DEVICE_ID_ENV)
        .ok()
        .and_then(|v| v.trim().parse().ok());

    // Direct benchmark mode: run benchmarks and print results to stderr (stdout is redirected)
    // Before constructing any CudaProver: never adopt a server whose owner is gone.
    reap_orphaned_gpu_servers(our_cuda_device);

    // Then make a CUDA 12 runtime reachable if the host has one anywhere, so the
    // installed toolkit version stops mattering. Must run BEFORE sp1_usability, which
    // execs sp1-gpu-server and is the authority on whether this actually worked.
    ensure_cuda12_on_library_path();

    if std::env::args().any(|a| a == "--benchmark") {
        // Honour the assigned device here too. Without this, benchmarking card 1 by hand silently
        // measured card 0 — a figure that is then persisted as that card's.
        let prover = {
            let builder = sp1_sdk::blocking::ProverClient::builder().cuda();
            match std::env::var(CUDA_DEVICE_ID_ENV)
                .ok()
                .and_then(|v| v.trim().parse::<u32>().ok())
            {
                Some(id) => builder.with_device_id(id).build(),
                None => builder.build(),
            }
        };
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
fn reap_orphaned_gpu_servers(our_device: Option<u32>) {
    #[cfg(target_os = "linux")]
    {
        let Ok(entries) = std::fs::read_dir("/proc") else {
            return;
        };
        let mut killed = 0usize;
        // Devices whose orphaned server we actually killed, so only their sockets are removed.
        let mut reaped_devices: std::collections::HashSet<u32> = std::collections::HashSet::new();
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
            // Deliberately NOT scoped to our own device.
            //
            // The `ppid != 1` test above already spares every server a live worker owns — this one's,
            // a sibling's, another miner's — because such a server has that worker as its parent. So
            // anything reaching this line is owned by nobody, and killing it is right whichever card
            // it sat on. Scoping the kill by device was a mistake in the other direction: the next
            // thing this process does is `CudaClient::connect`, which ADOPTS a reachable orphan
            // (measured: RSS 8.5 GB -> 19.5 GB across one adoption), so "cannot tell, leave it"
            // re-opens the exact bug this function exists to prevent. It is only the SOCKET cleanup
            // that has to be narrowed, because that is the part that can harm a live sibling.
            //
            // Note the device anyway, so the cleanup below can unlink precisely what was freed.
            if let Some(d) = server_device_of_pid(pid) {
                reaped_devices.insert(d);
            }
            tracing::warn!(
                "reaping orphaned sp1-gpu-server pid {pid} (ppid 1) left by an abruptly \
                 killed worker; adopting it instead would reuse a server nothing can reap"
            );
            // Count only an ACTUAL kill. Ignoring the return counted an EPERM (a server owned by
            // another user) or a zombie as reaped, which fired the loud "reaping orphaned
            // sp1-gpu-server" warning and the socket unlink for nothing — training the operator to
            // ignore the one alarm that means "go look".
            let rc = unsafe { libc::kill(pid, libc::SIGKILL) };
            if rc != 0 {
                tracing::warn!(
                    "could not SIGKILL orphaned sp1-gpu-server pid {pid}: {}. It may belong to \
                     another user, or already be a zombie.",
                    std::io::Error::last_os_error()
                );
                continue;
            }
            killed += 1;
        }
        if killed > 0 {
            // The orphan held the socket; remove it so our fresh server binds cleanly rather than
            // racing a dying one. The SDK never unlinks it (CudaClientInner's Drop only shuts the
            // stream down), and the path is machine-global.
            //
            // ONLY OUR OWN. This used to sweep `/tmp/sp1-cuda-{0..7}.sock` unconditionally, which
            // contradicted the `ppid != 1` check a few lines above: that check exists to spare a
            // server owned by a live worker, and then the cleanup pulled the socket out from under
            // it, breaking the sibling's reconnect path. With one SP1 worker per card that is no
            // longer a corner case — it is what happens every time two workers start.
            // ONLY the sockets whose server we just killed, plus our own.
            //
            // This used to sweep `/tmp/sp1-cuda-{0..7}.sock` unconditionally, which contradicted the
            // `ppid != 1` check above: that check spares a server a live worker owns, and then the
            // sweep pulled the socket out from under it, breaking the sibling's reconnect. With one
            // SP1 worker per card that stopped being a corner case and became what happens on every
            // startup. (The server also unlinks a stale socket itself before binding, so this is
            // hygiene rather than the thing that makes a bind succeed.)
            let mut to_unlink = reaped_devices.clone();
            to_unlink.insert(our_device.unwrap_or(0));
            for id in to_unlink {
                let p = format!("/tmp/sp1-cuda-{id}.sock");
                if std::path::Path::new(&p).exists() {
                    let _ = std::fs::remove_file(&p);
                }
            }
            tracing::warn!("reaped {killed} orphaned sp1-gpu-server process(es)");
        }
    }
}

/// Which CUDA device a running `sp1-gpu-server` was started for, read from its own environment.
///
/// The SDK sets `CUDA_VISIBLE_DEVICES=<id>` on the child it spawns, so the child's `environ` is the
/// authoritative record of which card it owns — more reliable than guessing from its socket, which we
/// cannot see from `/proc`. Unreadable `environ` (a server owned by another user, or one that exited
/// between the two reads) yields `None`, which the caller treats as "cannot tell", and it then leaves
/// the process alone rather than killing something that may not be ours.
#[cfg(target_os = "linux")]
fn server_device_of_pid(pid: i32) -> Option<u32> {
    let raw = std::fs::read(format!("/proc/{pid}/environ")).ok()?;
    for entry in raw.split(|b| *b == 0) {
        // `continue`, NOT `?`. An `environ` blob is arbitrary bytes, and one non-UTF8 entry
        // anywhere before ours — a path, LS_COLORS, anything inherited from an operator's shell —
        // used to abort the whole scan and answer "cannot tell".
        let Ok(text) = std::str::from_utf8(entry) else {
            continue;
        };
        if let Some(v) = text.strip_prefix("CUDA_VISIBLE_DEVICES=") {
            return v.trim().parse().ok();
        }
    }
    None
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
    tracing::info!(
        "found {CUDART_SONAME} in {}; adding it to LD_LIBRARY_PATH for sp1-gpu-server",
        dir.display()
    );
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
    match probe_server_version(&server, PROBE_TIMEOUT) {
        Outcome::Ran { success: true, .. } => Ok(()),
        // Never came back inside the budget. The verdict stays `Ok` because this function's
        // contract is to decline only what provably cannot work, and a timeout is also what a
        // transiently overloaded host produces. But the warning must not pretend this is an
        // absence of evidence: the SDK's own `maybe_download_server` runs THE SAME
        // `path --version`, with no timeout, as the first step of prover init — so a probe
        // that hung is direct evidence about the very next thing SP1 will do.
        Outcome::TimedOut { stderr } => {
            tracing::warn!(
                "{} --version did not return within {:?} and was killed; leaving SP1 \
                 advertised, because an overloaded host produces this too. If a later SP1 job \
                 hangs at prover init, this is why: the SDK runs the same command with no \
                 timeout, so it will wedge where we gave up, and the job will be killed by \
                 the proving watchdog and released. Anything it managed to say first: {}",
                server.display(),
                PROBE_TIMEOUT,
                if stderr.trim().is_empty() {
                    "(nothing)"
                } else {
                    stderr.trim()
                },
            );
            Ok(())
        }
        // The child started but the WAIT failed — realistically ECHILD, i.e. something else
        // reaped it (a `SIGCHLD` disposition of `SIG_IGN` inherited from a parent auto-reaps
        // every child and makes every waitpid return ECHILD). That says nothing about the
        // binary, so it must not reach the decline: `WORKER_DECLINED` is permanent for the
        // process, and `slot_eligible` never re-enables a declined slot.
        Outcome::Unsettled(e) => {
            tracing::warn!(
                "could not determine the outcome of {} --version ({e}); leaving SP1 \
                 advertised rather than declining on a verdict we do not have",
                server.display()
            );
            Ok(())
        }
        Outcome::Ran {
            success: false,
            stderr,
        } => {
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
        // Could not exec at all. Decline only when that is a property of the binary; a
        // transient condition (the file being rewritten, a fork failing under memory
        // pressure) must leave SP1 advertised, per this function's contract.
        Outcome::SpawnFailed {
            err,
            transient: true,
        } => {
            tracing::warn!(
                "{} could not be started right now ({err}); treating it as transient and \
                 leaving SP1 advertised",
                server.display()
            );
            Ok(())
        }
        Outcome::SpawnFailed { err, .. } => {
            Err(format!("cannot execute {}: {err}", server.display()))
        }
    }
}

/// How long `sp1-gpu-server --version` may take before we stop waiting.
///
/// The ceiling is set by the host, not the binary: this runs inside the Hello handshake,
/// which the host caps at `HANDSHAKE_TIMEOUT` and enforces by SIGKILLing the worker. The
/// floor is set by what an HONEST `--version` costs — the server here is 236 MB, and on a
/// cold page cache under the memory pressure this project documents (provers measured at
/// ~25 GB RSS) the loader alone can take seconds, so too tight a budget would SIGKILL a
/// healthy check. 5s, with `nvidia-smi` separately bounded, keeps the handshake's worst case
/// near 7.5s; `the_handshake_budget_is_not_oversubscribed` asserts the sum.
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// How long `nvidia-smi` may take. It is the other fork in the handshake, and the one most
/// likely to hang: after an Xid, a bus fall-off or an ECC remap it blocks in the driver, in
/// uninterruptible sleep, on exactly the sick host this check exists to characterise.
const NVIDIA_SMI_TIMEOUT: Duration = Duration::from_secs(2);

/// Upper bound on captured probe stderr. A loader error is one line; anything willing to
/// write more than this is not telling us something we will read.
const PROBE_STDERR_CAP: u64 = 64 * 1024;

/// Run `sp1-gpu-server --version` under a hard wall-clock bound.
///
/// `Command::output()` -- what this replaces -- waits forever. That mattered because of
/// WHERE it runs: inside the Hello handshake, on the one thread that forks every worker in
/// the process. See `zkminer_prover_protocol::proc` for the rest of the reasoning and for
/// the capture/cap/kill details, all of which are shared with the other bounded probes.
fn probe_server_version(server: &std::path::Path, timeout: Duration) -> Outcome {
    proc::output_with_timeout(
        std::process::Command::new(server).arg("--version"),
        timeout,
        PROBE_STDERR_CAP,
    )
}

/// True if the kernel driver reports at least one NVIDIA GPU, independent of nvidia-smi.
///
/// The same fallback the host-side detector uses. Present even in a container granted
/// compute capability but no CUDA user-space utilities.
fn nvidia_gpu_in_proc() -> bool {
    match std::fs::read_dir("/proc/driver/nvidia/gpus") {
        Ok(mut d) => d.any(|e| e.is_ok()),
        // NotFound is real evidence: the driver is not loaded. Anything else — EMFILE under the
        // fd pressure this project documents, EACCES, EIO — means we could not LOOK, and folding
        // that into "there is no GPU" hands `sp1_usability` an `Err`, which is a permanent
        // decline for the process. That would undo the whole point of treating EMFILE as
        // transient two screens away.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
        Err(e) => {
            tracing::warn!(
                "could not read /proc/driver/nvidia/gpus ({e}); assuming a GPU IS present rather \
                 than declining SP1 permanently on an answer we do not have"
            );
            true
        }
    }
}

/// Cap SP1's core element threshold to a value this host's memory budget can actually carry.
///
/// Lives in `zkminer-prover-protocol` (`sp1_element_threshold_for_host_scale`, where the measurements
/// behind it are recorded) so the dispatcher computes exactly the threshold this worker will settle on
/// — it needs that figure to decide how much room to make for this worker on a shared card.
///
/// Caveat on the measured timings there: the test program is fibonacci(100), 5,466 cycles, so those
/// 55-58s are almost entirely the fixed Groth16 wrap (~23s reading the R1CS, ~5s solving 15.9M
/// constraints). The shard-count cost of a lower threshold barely registers there and WILL be larger
/// on a real job of millions of cycles. Treat the ordering as established and the magnitude as
/// unpriced.
fn sp1_element_threshold_for(scale: f64) -> Option<u64> {
    zkminer_prover_protocol::types::sp1_element_threshold_for_host_scale(scale)
}

/// Settle `SP1_GPU_ELEMENT_THRESHOLD`, the one knob measured to decide whether a proof completes
/// at all rather than merely slower.
///
/// TWO independent bounds, and the smaller wins:
///
/// * the HOST's memory, via `scale` — measured on this box, the wrap stage died at 18.0 GiB of
///   heap plus 7.0 GiB of shared memory against a 25.1 GiB per-worker ceiling;
/// * the CARD's FREE memory. SP1's own `local_gpu_opts` sizes from `cuda_memory_info().1`, the
///   card's TOTAL, discarding the free figure returned beside it. On a card with a display
///   attached that commits to a tier larger than what is actually free and fails part-way
///   through — after the job is claimed and the collateral bonded. The dispatcher measures what
///   is free and passes it in `CUDA_VRAM_AVAILABLE_BYTES_ENV`; this turns it into the tier that
///   fits.
///
/// The fork treats the variable as a CAP on its own tier choice, never a raise, so the worst this
/// can do is leave performance on the table. That direction also matters for soundness: the shape
/// allow-list is enumerated against the compile-time `PADDED_ELEMENT_THRESHOLD`, so a value below
/// the constant yields shapes the circuit already accepts while one above it does not.
fn apply_sp1_element_threshold(scale: f64, available_vram: Option<u64>) {
    // Never override what the operator set by hand.
    if std::env::var(zkminer_prover_protocol::types::SP1_ELEMENT_THRESHOLD_ENV).is_ok() {
        return;
    }
    // For the log line only. The threshold itself comes from `sp1_element_threshold_cap`, the shared
    // function whose inputs the dispatcher reads too when it predicts this worker's tier.
    let from_host = sp1_element_threshold_for(scale);
    let from_vram = available_vram.map(|a| {
        match zkminer_prover_protocol::types::sp1_element_threshold_for_available_vram(a) {
            Some(t) => t.to_string(),
            None => format!(
                "{} ({} MiB free is below every measured tier; using the smallest)",
                zkminer_prover_protocol::types::sp1_smallest_measured_threshold(),
                a / (1024 * 1024)
            ),
        }
    });
    let Some(threshold) =
        zkminer_prover_protocol::types::sp1_element_threshold_cap(scale, available_vram)
    else {
        return;
    };
    // Only say so when it lowers the fork's own default. With today's tables every computed value
    // does (the largest measured tier is 268M), so this is a guard for a future table that measures
    // the default itself, not a branch that fires now.
    const DEFAULT_THRESHOLD: u64 = 402_653_184;
    if threshold >= DEFAULT_THRESHOLD {
        return;
    }
    tracing::info!(
        "SP1 tuning: SP1_GPU_ELEMENT_THRESHOLD={threshold} (default {DEFAULT_THRESHOLD}) — \
         host budget allows {}, free VRAM allows {}",
        from_host
            .map(|t| t.to_string())
            .unwrap_or_else(|| "no limit".into()),
        from_vram.unwrap_or_else(|| "unknown".into()),
    );
    // SAFETY: single-threaded startup, before any prover, server or thread exists.
    unsafe {
        std::env::set_var(
            zkminer_prover_protocol::types::SP1_ELEMENT_THRESHOLD_ENV,
            threshold.to_string(),
        )
    };
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
    // Which card this worker drives, chosen by the dispatcher.
    //
    // NOT `CUDA_VISIBLE_DEVICES`. The SDK sets that itself on the `sp1-gpu-server` child from the id
    // given here, and reaches that child over a per-device socket `/tmp/sp1-cuda-<id>.sock`. If the
    // dispatcher had filtered OUR view instead, the runtime would renumber the surviving card to
    // ordinal 0, the id the SDK derives and the id the server is told would disagree, and the server
    // — which asserts "Expected only one CUDA device as a u32" — exits within seconds. That was the
    // failure that made SP1 look unpinnable, and it is why the device arrives in a variable of our
    // own while the CUDA runtime keeps seeing every card.
    //
    // Absent or unparsable means "let the SDK choose", which is device 0 — the previous behaviour, so
    // a worker started by hand or by an older dispatcher is unaffected.
    let cuda_device_id: Option<u32> = std::env::var(CUDA_DEVICE_ID_ENV)
        .ok()
        .and_then(|v| v.trim().parse().ok());
    let host_budget: Option<u64> = std::env::var(HOST_MEM_BUDGET_ENV)
        .ok()
        .and_then(|v| v.trim().parse().ok());
    let vram_bytes: Option<u64> = std::env::var(CUDA_VRAM_BYTES_ENV)
        .ok()
        .and_then(|v| v.trim().parse().ok());
    // What is actually FREE on this card, which is what the sizing must use. Falls back to the
    // capacity figure when the dispatcher did not measure it (an older dispatcher, or a card
    // `nvidia-smi` could not read), which is the behaviour that predates this variable.
    let available_vram: Option<u64> = std::env::var(CUDA_VRAM_AVAILABLE_BYTES_ENV)
        .ok()
        .and_then(|v| v.trim().parse().ok())
        .or(vram_bytes);
    let sp1_scale = sp1_memory_scale(host_budget);
    tracing::info!(
        "SP1 memory scale {:.2} (host budget {}, card VRAM {})",
        sp1_scale,
        host_budget
            .map(|b| format!("{:.1} GiB", b as f64 / 1024.0 / 1024.0 / 1024.0))
            .unwrap_or_else(|| "unknown".into()),
        vram_bytes
            .map(|b| format!("{:.1} GB", b as f64 / 1e9))
            .unwrap_or_else(|| "unknown".into()),
    );
    apply_sp1_worker_tuning(sp1_scale, available_vram);
    match cuda_device_id {
        Some(id) => tracing::info!("SP1 worker will drive CUDA device {id}"),
        None => tracing::info!(
            "no {CUDA_DEVICE_ID_ENV} set; the SP1 SDK will choose its own CUDA device (0)"
        ),
    }
    // Scale SP1's memory appetite to the machine it is actually on.
    //
    // WHAT THIS DOES AND DOES NOT FIX. It does NOT lower `sp1-gpu-server`'s hard VRAM floor (16 GB in
    // the fork this repo pins, 24 GB upstream — see `min_vram_bytes_for_backend` in the dispatcher):
    // that is a tier check on the device, made before any proving option exists, and
    // `SP1CoreOpts` never even crosses into the server crate. A card below the floor is refused
    // whatever we set, which is why the dispatcher declines to create a slot there at all.
    //
    // What it does address is the limit that actually bound on this box, measured on 2026-10-05 with
    // SP1 pinned to the 24,564 MiB RTX 4090. The core proof and the Groth16 witness completed; the
    // worker then died in the wrap at 18.0 GiB of heap plus 7.0 GiB of shared memory — 25.0 GiB
    // against a 25.1 GiB per-worker ceiling, killed by its own cgroup (CONSTRAINT_MEMCG) rather than
    // by the host. So on a 28 GiB box SP1 is HOST-memory-bound, not VRAM-bound, once it is on a card
    // its server will accept.
    //
    // AND WHAT IT DOES NOT REACH, measured the same day by running it both ways. With the tuning
    // below applied (SHARD_SIZE 2^23, 3 core workers, 6 recursion provers) the worker died at
    // `anon-rss 18909692kB, shmem-rss 7329476kB` — BYTE-IDENTICAL to the untuned run's
    // `18911064kB / 7329476kB`, on the same 15,965,950 constraints. The tuning changed nothing,
    // because the phase that fails is the Groth16 WRAP, whose cost is fixed by the circuit:
    // `~/.sp1/circuits/groth16/v6.0.0` holds a 5.9 GB proving key and a 2.4 GB R1CS, ~8 GB of
    // artifacts loaded every time, and the 7.0 GiB of shared memory is that key mapped in. No shard
    // size or worker count moves it.
    //
    // So this tuning helps a host where the CORE and RECURSION phases bind — they are the ones it
    // scales, and both already completed here. It does not make SP1 fit a small host: the wrap alone
    // sets a floor above this 28 GiB box's 25.1 GiB per-worker ceiling, on either card. Anyone
    // reading this hoping to run SP1 on 16 GiB should know that up front.
    //
    // The levers are the stage concurrency and queue depths the prover uses, which is what drives
    // both figures: `DEFAULT_NUM_CORE_WORKERS = 4`, `DEFAULT_NUM_RECURSION_PROVER_WORKERS = 8` and
    // their buffer depths (`sp1/crates/prover/src/worker/config.rs`). Every one is read from the
    // environment, and the server inherits our environment — and SP1's own source carries
    // `TODO: base default values on system information`, i.e. upstream agrees these should scale
    // with the machine and currently do not. Plus `SP1CoreOpts::shard_size`, cycles per shard, on
    // our side of the SDK.
    //
    // DIRECTION IS ONE-WAY. The factor is clamped to at most 1.0, so this can only ever reduce the
    // defaults. Scaling them UP on a bigger machine might well be correct, but nothing here has
    // measured that, and a guess in that direction risks the freeze this whole subsystem exists to
    // prevent. The floor of 1 per stage keeps every pipeline stage alive.
    //
    // `ZKMINER_SP1_NO_AUTOTUNE=1` disables it, for bisecting a proving failure against stock SDK
    // behaviour.
    // Host budget the STOCK defaults are assumed to need, and how far below it the defaults are
    // scaled: `SP1_REFERENCE_BUDGET_BYTES` and `SP1_MIN_SCALE` in `zkminer-prover-protocol`, shared so
    // the dispatcher can predict the tier this worker settles on.
    fn sp1_memory_scale(host_budget: Option<u64>) -> f64 {
        zkminer_prover_protocol::types::sp1_memory_scale(
            host_budget,
            std::env::var(zkminer_prover_protocol::types::SP1_NO_AUTOTUNE_ENV).is_ok(),
        )
    }

    /// Apply the scaled stage concurrency to our own environment, which the forked
    /// `sp1-gpu-server` inherits.
    ///
    /// `set_var` is sound here: this runs once, before any prover or server exists, on the single
    /// thread that has not yet spawned anything.
    fn apply_sp1_worker_tuning(scale: f64, available_vram: Option<u64>) {
        // The element threshold is settled FIRST and unconditionally, because the two inputs are
        // independent: a host with plenty of RAM gives `scale >= 1.0` and no host-derived threshold,
        // while the card it is attached to may still be half full. Returning early on `scale` alone —
        // which is what this did — skipped the VRAM cap in exactly the case it exists for.
        apply_sp1_element_threshold(scale, available_vram);
        if scale >= 1.0 {
            return;
        }
        // (variable, SDK default). Scaled together so the pipeline stays balanced — shrinking the
        // provers without shrinking the queues that feed them just moves the backlog.
        let knobs: &[(&str, usize)] = &[
            // The executor's shared-memory trace ring. Included, but MEASURED NOT TO HELP here —
            // recorded because the arithmetic is seductive and the measurement is the only thing that
            // settles it.
            //
            // The theory: `TRACE_CHUNK_SLOTS` slots of a fixed 2 GiB each
            // (`MINIMAL_TRACE_CHUNK_THRESHOLD = 2147483648 / size_of::<MemValue>()`, so slots × that ×
            // size_of is exactly 2 GiB per slot), i.e. 10 GiB at the default 5. It survives the GPU
            // override, unlike `SHARD_SIZE` — `local_gpu_opts` rewrites only `shard_size`,
            // `sharding_threshold.element_threshold` and `global_dependencies_opt`.
            //
            // The measurement, on the 4090 across three runs: `shmem-rss` in the OOM record was
            // 7,329,476 kB at slots=5, at slots=4, and at an explicit slots=2 — byte-identical every
            // time. So whatever that ~7.0 GiB is, this knob does not reach it, and `anon-rss` sat at
            // ~18.0 GiB throughout as well. Env-level tuning does not move this workload.
            //
            // Kept anyway: it is honest about the cap on hosts where the ring IS the binding cost, it
            // costs nothing when it is not, and the next person deserves to know it was tried.
            ("TRACE_CHUNK_SLOTS", 5),
            // NO `SHARD_SIZE` HERE, and it is worth saying why, because it is the obvious knob.
            //
            // `SP1CoreOpts::default()` does read `SHARD_SIZE` from the environment, so setting it
            // looks like it works — and on the CPU path it would. On the GPU path it is inert:
            // `sp1-gpu/crates/prover_components/src/builder.rs::local_gpu_opts` calls
            // `SP1CoreOpts::default()` and then immediately overwrites `opts.shard_size = 1 << 24`
            // unconditionally, before handing the result to `with_core_opts`. The server decides its
            // own shard size and its own `sharding_threshold` from the card's VRAM tier, and neither
            // can be influenced from outside. Setting it would only log a change that does not happen.
            //
            // The same goes for `ELEMENT_THRESHOLD`, which is the knob that would actually matter —
            // overwritten by the tier on the same lines. And it must never be raised anyway: the
            // recursion shape allow-list is enumerated against the compile-time
            // `PADDED_ELEMENT_THRESHOLD`, so a larger value produces a shape the circuit cannot
            // accept, while lowering stays inside the enumerated set.
            ("SP1_WORKER_NUM_CORE_WORKERS", 4),
            ("SP1_WORKER_CORE_BUFFER_SIZE", 4),
            ("SP1_WORKER_NUM_RECURSION_PROVER_WORKERS", 8),
            ("SP1_WORKER_RECURSION_PROVER_BUFFER_SIZE", 8),
            ("SP1_WORKER_NUM_RECURSION_EXECUTOR_WORKERS", 4),
            ("SP1_WORKER_RECURSION_EXECUTOR_BUFFER_SIZE", 4),
            ("SP1_WORKER_NUM_SPLICING_WORKERS", 2),
            ("SP1_WORKER_SPLICING_BUFFER_SIZE", 2),
            ("SP1_WORKER_NUM_DEFERRED_WORKERS", 4),
            ("SP1_WORKER_DEFERRED_BUFFER_SIZE", 2),
        ];
        for (name, default) in knobs {
            // Never override what the operator set by hand.
            if std::env::var(name).is_ok() {
                continue;
            }
            let floor = if *name == "TRACE_CHUNK_SLOTS" { 2 } else { 1 };
            let scaled = (((*default as f64) * scale).round() as usize).max(floor);
            if scaled < *default {
                tracing::info!("SP1 tuning: {name}={scaled} (default {default})");
                // SAFETY: single-threaded startup, before any prover, server or thread exists.
                unsafe { std::env::set_var(name, scaled.to_string()) };
            }
        }
    }

    // Build the prover, turning a PANIC into a decline.
    //
    // The SDK ends `build()` with `.expect("Failed to create the CUDA prover impl")`, so anything that
    // stops `sp1-gpu-server` coming up kills this process outright. The dispatcher then sees only EOF
    // and reads it as worker ill-health: it excludes a slot, burns a retry, respawns, and does it all
    // again on the next job. But the commonest cause is categorical, not transient — the server
    // refuses a card below its hard VRAM floor — upstream's reads "Unsupported GPU memory: 20, must be
    // at least 24GB"; the fork this repo pins lowers it to 16 — which will be just as true next time.
    //
    // Catching it lets us answer the protocol properly. `WORKER_DECLINED` is the dispatcher's existing
    // signal for "I spoke to you, and I cannot prove here": it stops the backend being advertised on
    // this slot instead of being rediscovered job after job.
    //
    // `AssertUnwindSafe` is sound here because the panic path leaves nothing of ours half-written: the
    // prover slot is still `None` (we only assign on success), and the SDK's own state dies with the
    // server it failed to reach.
    fn build_prover(
        cuda_device_id: Option<u32>,
    ) -> std::result::Result<sp1_sdk::blocking::CudaProver, String> {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            tracing::info!("Initializing SP1 CUDA prover...");
            let builder = sp1_sdk::blocking::ProverClient::builder().cuda();
            let builder = match cuda_device_id {
                Some(id) => builder.with_device_id(id),
                None => builder,
            };
            builder.build()
        }))
        .map_err(|e| {
            let detail = e
                .downcast_ref::<&str>()
                .map(|s| (*s).to_string())
                .or_else(|| e.downcast_ref::<String>().cloned())
                .unwrap_or_else(|| "panic with no message".to_string());
            format!(
                "{}: could not initialise the SP1 CUDA prover on device {}: {detail}. The most \
                 likely cause is a card below sp1-gpu-server's hard VRAM floor (16 GB in the pinned \
                 fork, 24 GB upstream), which no proving option can change.",
                zkminer_prover_protocol::types::WORKER_DECLINED,
                cuda_device_id
                    .map(|d| d.to_string())
                    .unwrap_or_else(|| "default".to_string()),
            )
        })
    }

    macro_rules! get_prover {
        ($p:expr) => {
            match $p {
                Some(ref mut p) => Ok(p),
                None => match build_prover(cuda_device_id) {
                    Ok(built) => Ok($p.insert(built)),
                    Err(msg) => Err(msg),
                },
            }
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
                match get_prover!(prover) {
                    Ok(p) => {
                        let results = run_benchmarks(p);
                        let resp = WorkerResponse::BenchmarkResult { results };
                        write_message(&mut stdout, &resp)?;
                    }
                    Err(message) => {
                        tracing::error!("{message}");
                        let resp = WorkerResponse::Error {
                            request_id: 0,
                            kind: ErrorKind::Internal,
                            message,
                        };
                        write_message(&mut stdout, &resp)?;
                    }
                }
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
                let prover_for_proof = match get_prover!(prover) {
                    Ok(p) => p,
                    Err(message) => {
                        // A DECLINE, answered on the protocol, rather than a panic the dispatcher can
                        // only read as "the worker vanished". See `build_prover`.
                        tracing::error!("{message}");
                        let resp = WorkerResponse::Error {
                            request_id,
                            kind: ErrorKind::Internal,
                            message,
                        };
                        write_message(&mut stdout, &resp)?;
                        continue;
                    }
                };
                match run_proof(prover_for_proof, &mut pk_cache, &elf, &input_data) {
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
    // Bounded, because this is the OTHER fork inside the Hello handshake and the one most
    // likely to hang: `nvidia-smi` blocks in the driver after an Xid, a bus fall-off or an
    // ECC remap. Bounding the `sp1-gpu-server` probe while leaving this unbounded would have
    // left the handshake — and with it the process-wide spawner thread — wedgeable anyway.
    let (outcome, stdout) = proc::output_with_timeout_capturing_stdout(
        std::process::Command::new("nvidia-smi")
            .args(["--query-gpu=name", "--format=csv,noheader,nounits"]),
        NVIDIA_SMI_TIMEOUT,
        16 * 1024,
    );
    if let Outcome::Ran { success: true, .. } = outcome {
        let name = stdout.trim().to_string();
        if !name.is_empty() {
            return (true, Some(name));
        }
    } else {
        // Absence of an answer is not absence of a GPU; `sp1_usability` cross-checks
        // /proc/driver/nvidia/gpus for exactly this reason.
        tracing::warn!("nvidia-smi did not answer ({}) ", outcome.describe());
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
    let (_, report) = prover
        .execute(Elf::from(elf), stdin.clone())
        .run()
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let cycles = report.total_instruction_count();

    // Get-or-create the proving key for this ELF. The key depends only on the
    // program (not the input), so it's cached and reused across proofs — no per-proof
    // setup() and no per-proof GPU-key leak. See `pk_cache` in run_worker_loop.
    let key = elf_hash(elf);
    if let std::collections::hash_map::Entry::Vacant(e) = pk_cache.entry(key) {
        let pk = prover
            .setup(Elf::from(elf))
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        e.insert(pk);
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
        return Err(anyhow::anyhow!(
            "Proof verification FAILED — SP1 proof is invalid: {e}"
        ));
    }

    let journal = proof.public_values.to_vec();
    // Use bytes() which produces the on-chain format: vkey_hash[..4] || proof_bytes
    let seal = proof.bytes();

    Ok((journal, seal, duration_secs, cycles))
}

fn run_benchmarks(prover: &sp1_sdk::blocking::CudaProver) -> Vec<BenchmarkEntry> {
    let mut results = Vec::new();

    let benchmarks: &[(&str, &[u8], &[u8], f64, bool)] = &[
        (
            BENCH_FIBONACCI,
            FIBONACCI_SP1_GUEST_ELF,
            &1000u32.to_le_bytes(),
            0.10,
            false,
        ),
        (
            BENCH_SHA256_CHAIN,
            SHA256_CHAIN_SP1_GUEST_ELF,
            &50_000u32.to_le_bytes(),
            0.20,
            true,
        ),
        (
            BENCH_ECDSA_VERIFY,
            ECDSA_VERIFY_SP1_GUEST_ELF,
            &10u32.to_le_bytes(),
            0.25,
            true,
        ),
        (
            BENCH_BIGINT_MUL,
            BIGINT_MUL_SP1_GUEST_ELF,
            &100u32.to_le_bytes(),
            0.10,
            false,
        ),
        (
            BENCH_MEMORY_MERKLE,
            MEMORY_MERKLE_SP1_GUEST_ELF,
            &1024u32.to_le_bytes(),
            0.15,
            true,
        ),
        (
            BENCH_CHACHA_MIX,
            CHACHA_MIX_SP1_GUEST_ELF,
            &20_000u32.to_le_bytes(),
            0.20,
            false,
        ),
    ];

    // The Groth16 wrap is measured on ONE program per slot, by difference — see `benchmark_program`.
    // The LAST one, not the first: the difference assumes the Groth16 run's STARK repeats at the
    // compressed run's speed, and the first proof in a fresh worker also pays GPU warm-up, which would
    // land in one run and not the other. By the last program that has long been paid.
    let last_runnable = benchmarks.iter().rposition(|&(_, elf, ..)| !elf.is_empty());
    for (idx, &(name, elf, input, weight, precompile)) in benchmarks.iter().enumerate() {
        if elf.is_empty() {
            continue;
        }
        let measure_wrap = Some(idx) == last_runnable;
        if let Some(entry) =
            benchmark_program(prover, name, elf, input, weight, precompile, measure_wrap)
        {
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
    // Also prove this program in Groth16 mode and report the wrap. See `run_benchmarks`.
    measure_wrap: bool,
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

    // Key setup OUTSIDE the timed region. It is not proving, and production caches the key per ELF
    // (`pk_cache` in `run_worker_loop`) so never pays it per proof. Measured on 2026-10-06 the cost is
    // almost entirely a FIRST-CALL warm-up, not per-program key generation: 5.37 s and 5.46 s for the
    // first program on each card, then 0.02-0.03 s for every one after. Inside the stopwatch it was
    // most of why a 9,966-cycle fibonacci "took" 6 s, and it landed on whichever program ran first.
    let started = Instant::now();
    let pk = prover.setup(Elf::from(elf)).ok()?;
    let setup_secs = started.elapsed().as_secs_f64();

    // STARK: the core shard proofs and the recursion that compresses them into one constant-size
    // proof. This used to run in the SDK's default Core mode, which stops before the recursion — and
    // the recursion scales with shard count, so it belongs here rather than with the wrap.
    let started = Instant::now();
    let proof = match prover.prove(&pk, stdin.clone()).compressed().run() {
        Ok(p) => p,
        Err(e) => {
            tracing::error!("{name}: prove failed: {e}");
            std::mem::forget(pk);
            return None;
        }
    };
    let duration_secs = started.elapsed().as_secs_f64();

    // Verify the proof locally — catches GPU output corruption before polluting
    // the benchmark cache with invalid throughput numbers.
    if let Err(e) = prover.verify(&proof, pk.verifying_key(), None) {
        tracing::error!(
            "{name}: proof verification FAILED — benchmark proof is invalid, skipping entry: {e}"
        );
        std::mem::forget(pk);
        return None;
    }

    // The Groth16 wrap, by DIFFERENCE. `sp1-gpu-server` runs the whole pipeline as one request —
    // its wire API is `Setup`, `ProveWithMode` and `Destroy`, nothing that takes a compressed proof
    // and wraps it — so the wrap cannot be timed on its own from here. Proving the same program again
    // in Groth16 mode and subtracting the compressed run isolates it, at the cost of one extra STARK.
    // That cost is why this runs on one program per slot: the wrap proves a fixed circuit with a
    // fixed key (`~/.sp1/circuits/groth16/*/groth16_pk.bin`), so one measurement stands for all.
    let wrap_secs = if measure_wrap {
        let started = Instant::now();
        match prover.prove(&pk, stdin).groth16().run() {
            Ok(g) => {
                let total = started.elapsed().as_secs_f64();
                if let Err(e) = prover.verify(&g, pk.verifying_key(), None) {
                    tracing::error!(
                        "{name}: Groth16 proof verification FAILED — not reporting a wrap time: {e}"
                    );
                    None
                } else if total < duration_secs {
                    // The Groth16 run includes the same STARK, so it cannot be FASTER than the
                    // compressed run alone. If it is, the difference is noise, not a measurement.
                    tracing::warn!(
                        "{name}: Groth16 run ({total:.2}s) finished faster than its own STARK \
                         ({duration_secs:.2}s); not reporting a wrap time"
                    );
                    None
                } else {
                    Some(total - duration_secs)
                }
            }
            Err(e) => {
                tracing::error!("{name}: Groth16 prove failed — not reporting a wrap time: {e}");
                None
            }
        }
    } else {
        None
    };

    // Leak the proving key to avoid drop panic (SP1 CUDA PK drops require tokio runtime context)
    std::mem::forget(pk);

    let throughput = cycles as f64 / duration_secs;

    match wrap_secs {
        Some(w) => tracing::info!(
            "{name}: {cycles} cycles — STARK {duration_secs:.2}s ({throughput:.0} c/s), Groth16 \
             wrap {w:.2}s by difference, key setup {setup_secs:.2}s not counted, verified"
        ),
        None => tracing::info!(
            "{name}: {cycles} cycles — STARK {duration_secs:.2}s ({throughput:.0} c/s), key setup \
             {setup_secs:.2}s not counted, verified"
        ),
    }

    Some(BenchmarkEntry {
        program_name: name.to_string(),
        prover_backend: BACKEND_SP1.to_string(),
        cycles,
        duration_secs,
        throughput,
        weight,
        precompile,
        wrap_secs,
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
        assert_eq!(
            ppid_from_proc_stat("123 (sp1-gpu-server) S 1 123 123 0 -1 4194560"),
            Some(1)
        );
        // Live owner.
        assert_eq!(
            ppid_from_proc_stat("200 (sp1-gpu-server) S 199 200 200 0 -1 0"),
            Some(199)
        );
        // comm containing spaces AND parens — counting fields from the left gives the
        // wrong answer here, which would make us kill a server that has a live owner.
        assert_eq!(
            ppid_from_proc_stat("77 (we (are) evil) S 42 77 77 0 -1 0"),
            Some(42)
        );
        // comm containing a digit that could be mistaken for the ppid.
        assert_eq!(
            ppid_from_proc_stat("88 (proc 1 2 3) R 55 88 88 0 -1 0"),
            Some(55)
        );
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

        // This MUST decline. The `|| contains("GPU")` escape covers a GPU-less machine, where the
        // earlier no-GPU arm fires first and is equally correct — but the verdict has to be `Err`
        // either way. The previous `if let Err(e)` had no `else`, so replacing the `SpawnFailed`
        // arm with `Ok(())` left this test green while SP1 stayed advertised on a host whose
        // server cannot be executed: it would then claim a job it cannot prove and pay a
        // voluntary-release penalty.
        let e = r.expect_err("a present-but-unrunnable server must be declined");
        assert!(
            e.contains("cannot run") || e.contains("cannot execute") || e.contains("GPU"),
            "unexpected reason: {e}"
        );
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
        let joined: Vec<String> = dirs
            .iter()
            .map(|p| p.to_string_lossy().to_string())
            .collect();
        let has = |frag: &str| joined.iter().any(|d| d.contains(frag));
        assert!(
            has("/usr/lib/x86_64-linux-gnu"),
            "distro package dir missing: {joined:?}"
        );
        assert!(
            has("site-packages/nvidia/cuda_runtime/lib"),
            "pip wheel layout missing -- it is the only copy on some hosts: {joined:?}"
        );
        // A bundled copy beside the binary, so a release can be made self-contained.
        assert!(
            has("cuda12"),
            "bundled-beside-binary dir missing: {joined:?}"
        );
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
        assert!(
            super::existing_path_has_cudart(),
            "the planted dir should be detected"
        );
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
        assert!(
            after.ends_with(&*tmp.to_string_lossy()),
            "resolved dir must be appended: {after}"
        );
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
        assert!(
            !smi,
            "with PATH emptied nvidia-smi must be unreachable for this test to mean anything"
        );
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
        std::fs::write(
            bin.join("sp1-gpu-server"),
            b"#!/bin/sh\necho 'bad args' >&2\nexit 2\n",
        )
        .unwrap();
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
            std::fs::set_permissions(
                bin.join("sp1-gpu-server"),
                std::fs::Permissions::from_mode(0o755),
            )
            .unwrap();
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
        assert!(
            e.contains("cannot run") || e.contains("GPU"),
            "unexpected: {e}"
        );
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
            assert!(
                e.contains("GPU"),
                "an absent server must not be 'cannot run': {e}"
            );
        }
    }

    /// These tests mutate the process environment, so they must not interleave.
    pub(super) fn env_lock() -> &'static std::sync::Mutex<()> {
        static L: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
        L.get_or_init(|| std::sync::Mutex::new(()))
    }
}

/// The IPC descriptor must not survive an exec into a child.
#[cfg(all(test, unix))]
mod ipc_fd_tests {
    /// A descriptor the host's protocol depends on must be close-on-exec, or a forked
    /// grandchild holds the pipe open and the host hangs forever on a dead worker.
    #[test]
    fn the_ipc_descriptor_is_close_on_exec() {
        use std::os::unix::io::AsRawFd;
        // Any fd will do; a pipe is what this really guards.
        let (r, w) = {
            let mut fds = [0i32; 2];
            assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
            (fds[0], fds[1])
        };
        let duped = super::dup_cloexec(w).expect("dup_cloexec");
        let flags = unsafe { libc::fcntl(duped, libc::F_GETFD) };
        assert!(flags >= 0, "F_GETFD failed");
        assert_eq!(
            flags & libc::FD_CLOEXEC,
            libc::FD_CLOEXEC,
            "the duplicated IPC descriptor must be close-on-exec; without it every child \
             inherits the host's pipe and a surviving grandchild wedges the dispatcher"
        );

        // And the plain `dup` it replaced must NOT be — i.e. this is a real difference, not a
        // property the OS was giving us anyway.
        let plain = unsafe { libc::dup(w) };
        assert!(plain >= 0);
        let plain_flags = unsafe { libc::fcntl(plain, libc::F_GETFD) };
        assert_eq!(
            plain_flags & libc::FD_CLOEXEC,
            0,
            "dup() is specified to clear FD_CLOEXEC; if that changed, this guard is moot"
        );

        // The duplicate must still be the same pipe.
        let msg = b"x";
        assert_eq!(
            unsafe { libc::write(duped, msg.as_ptr() as *const libc::c_void, 1) },
            1
        );
        let mut got = [0u8; 1];
        assert_eq!(
            unsafe { libc::read(r, got.as_mut_ptr() as *mut libc::c_void, 1) },
            1
        );
        assert_eq!(&got, msg);

        for fd in [r, w, duped, plain] {
            unsafe { libc::close(fd) };
        }
        let _ = std::io::stdout().as_raw_fd();
    }
}

/// [D4] What the SP1 worker must guarantee about the handshake. The bounded-runner
/// behaviour itself (timeout, kill, capture, cap, spawn-retry classification) is tested in
/// `zkminer_prover_protocol::proc`, which owns it; these are the SP1-specific obligations.
#[cfg(test)]
mod threshold_tests {
    use zkminer_prover_protocol::types::{
        sp1_element_threshold_cap as cap, sp1_element_threshold_for_available_vram as from_vram,
    };

    const GIB: u64 = 1024 * 1024 * 1024;
    const SMALL: u64 = 134_217_728;
    /// The largest MEASURED configuration. The fork's own default is 402,653,184 and is deliberately
    /// absent from the measured table, so nothing here may select it.
    const LARGEST_MEASURED: u64 = 268_435_456;
    /// What the fork would choose for itself, and the ceiling we may only cap.
    const FORK_DEFAULT: u64 = 402_653_184;

    /// The two bounds are independent and the SMALLER must win.
    ///
    /// `apply_sp1_element_threshold` writes to the process environment, so the arithmetic is asserted
    /// here rather than the side effect. The combination is what regressed in the first draft: the
    /// function returned early on `scale >= 1.0`, skipping the VRAM cap in exactly the case it exists
    /// for — a roomy host attached to an occupied card.
    #[test]
    fn the_smaller_of_the_host_and_vram_bounds_wins() {
        // A roomy HOST gives no host-derived limit, so a constrained CARD must still bind.
        assert_eq!(super::sp1_element_threshold_for(1.0), None);
        assert_eq!(from_vram(16 * GIB), Some(SMALL));
        // Through the function the worker actually calls, not a re-implementation of it.
        let combined = cap(1.0, Some(16 * GIB));
        assert_eq!(
            combined,
            Some(SMALL),
            "a host with plenty of RAM must not let an occupied card size itself for a tier that \
             does not fit"
        );

        // And the converse: a roomy CARD must not let a constrained host off.
        assert_eq!(from_vram(24 * GIB), Some(LARGEST_MEASURED));
        let host_bound = super::sp1_element_threshold_for(0.3);
        assert!(
            host_bound.is_some_and(|t| t < LARGEST_MEASURED),
            "a tight host budget must still produce a limit: {host_bound:?}"
        );
        assert_eq!(cap(0.3, Some(24 * GIB)), host_bound);
    }

    /// Only ever a CAP. The fork treats `SP1_GPU_ELEMENT_THRESHOLD` as a bound on its own tier, and the
    /// shape allow-list is enumerated against the compile-time `PADDED_ELEMENT_THRESHOLD` — so a value
    /// above the default would produce shapes the stock verifier rejects.
    #[test]
    fn no_computed_threshold_ever_exceeds_what_is_allowed() {
        // The VRAM path may only ever select a MEASURED configuration, which is stricter than the
        // fork's default: an unmeasured tier is one whose peak VRAM we cannot vouch for.
        for gib in 0..=64u64 {
            if let Some(t) = from_vram(gib * GIB) {
                assert!(
                    t <= LARGEST_MEASURED,
                    "{gib} GiB free produced {t}, above the largest measured configuration \
                     {LARGEST_MEASURED}"
                );
            }
        }
        // The host path snaps to its own measured steps, bounded by what the fork would do anyway.
        for scale in [0.0, 0.1, 0.25, 0.5, 0.75, 0.99, 1.0, 2.0] {
            if let Some(t) = super::sp1_element_threshold_for(scale) {
                assert!(
                    t <= FORK_DEFAULT,
                    "scale {scale} produced {t}, above the fork default {FORK_DEFAULT}"
                );
            }
        }
    }

    /// The threshold must be settled BEFORE the `scale >= 1.0` early return.
    ///
    /// The two bounds are independent, so a host roomy enough to produce no host-derived limit must
    /// still let an occupied CARD bind. Returning on `scale` first — what the first draft did — skipped
    /// the VRAM cap in precisely the configuration it exists for. The arithmetic tests above cannot see
    /// this, because the ordering is control flow and not a value.
    #[test]
    fn the_vram_cap_is_not_skipped_by_a_roomy_host() {
        let src = include_str!("main.rs");
        let body = src
            .split_once("fn apply_sp1_worker_tuning(")
            .expect("apply_sp1_worker_tuning no longer exists; move this assertion with it")
            .1;
        let body = match body.find("\nfn ") {
            Some(end) => &body[..end],
            None => body,
        };
        // The CALL, not the name: the doc comment above mentions the function.
        let threshold = body.find("apply_sp1_element_threshold(").expect(
            "apply_sp1_worker_tuning no longer settles the element threshold, so nothing applies the \
             free-VRAM cap",
        );
        let early_return = body
            .find("if scale >= 1.0 {")
            .expect("the scale early-return is gone; re-check that the VRAM cap still runs");
        assert!(
            threshold < early_return,
            "the element threshold is settled AFTER the `scale >= 1.0` early return, so a host with \
             plenty of RAM skips the free-VRAM cap entirely and an occupied card sizes itself for a \
             tier that does not fit"
        );
    }
}
