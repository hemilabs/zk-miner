//! Apple GPU (Metal) specifics of the risc0 worker (feature `metal`).
//!
//! Unified memory changes three things against a discrete card:
//! - The GPU's memory is the owner's RAM. Metal's own ceiling for one process is the device's
//!   `recommendedMaxWorkingSetSize` (about 75% of RAM; 30.15 GB of 36 GiB on the dev machine), and the
//!   risc0 fork honours an artificial lower one, `RISC0_METAL_MAX_WORKING_SET_BYTES` (PLAN 9.1, Z6).
//!   [`working_set_limit`] is the smallest of those and the host's figure (`ZKMINER_CUDA_VRAM_BYTES`,
//!   which the dispatcher sets to `hw.memsize` less an 8 GiB host reserve on a Mac).
//! - The segment size a Mac can prove at follows from that limit, not from a fixed default
//!   ([`job_po2_for_limit`]).
//! - Pipeline-state (PSO) creation for the big translated kernels takes tens of seconds to minutes
//!   the first time on a machine (PLAN 9.1, notes R4/R6/C4/K3/G7), so the worker builds every
//!   circuit's PSOs once at start ([`warm_up_pipelines`]), outside any job deadline.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use zkminer_prover_protocol::types::CUDA_VRAM_BYTES_ENV;

const GIB: u64 = 1 << 30;

/// Macs with less RAM than this are refused (PLAN 9.1: "any 8 GB Mac" is not supported). 12 GiB, not
/// 16, so a 16 GB machine is never refused over how the OS rounds `hw.memsize`.
pub const MIN_HOST_MEMORY_BYTES: u64 = 12 * GIB;


/// The Mac this worker runs on, if it is one the worker supports.
#[derive(Debug, Clone)]
pub struct MetalHost {
    /// The Metal device's name (`risc0_zkp::hal::metal::device_name`), e.g. "Apple M5 Max".
    pub name: String,
    /// `recommendedMaxWorkingSetSize` of the system default device.
    pub recommended_working_set: u64,
    /// `hw.memsize`.
    pub host_memory: u64,
}

fn sysctl_u64(name: &str) -> Option<u64> {
    let cname = std::ffi::CString::new(name).ok()?;
    let mut buf = [0u8; 8];
    let mut len: libc::size_t = buf.len();
    let rc = unsafe {
        libc::sysctlbyname(
            cname.as_ptr(),
            buf.as_mut_ptr().cast(),
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    match (rc, len) {
        (0, 4) => Some(u32::from_ne_bytes(buf[..4].try_into().ok()?) as u64),
        (0, 8) => Some(u64::from_ne_bytes(buf)),
        _ => None,
    }
}

/// Whether this Mac can run the worker: `Err` carries the message the worker refuses with.
pub fn support() -> &'static Result<MetalHost, String> {
    static SUPPORT: OnceLock<Result<MetalHost, String>> = OnceLock::new();
    SUPPORT.get_or_init(|| {
        let refused = check_support();
        if let Err(msg) = &refused {
            tracing::error!("{msg}");
        }
        refused
    })
}

fn check_support() -> Result<MetalHost, String> {
    // An x86_64 build runs on an Intel Mac, or under Rosetta on Apple Silicon; neither is supported
    // (Rosetta does not translate Metal's Apple-GPU families the kernels are built for).
    if !cfg!(target_arch = "aarch64") {
        return Err(
            "the Metal risc0 worker needs an Apple Silicon Mac and an aarch64-apple-darwin build: \
             Intel Macs (and x86_64 builds under Rosetta) are not supported"
                .to_string(),
        );
    }
    if sysctl_u64("sysctl.proc_translated") == Some(1) {
        return Err(
            "the Metal risc0 worker is running under Rosetta translation; build it for \
             aarch64-apple-darwin"
                .to_string(),
        );
    }
    let Some(device) = metal::Device::system_default() else {
        return Err("no Metal device: the Metal risc0 worker needs an Apple Silicon GPU".into());
    };
    let name = risc0_zkp::hal::metal::device_name().unwrap_or_else(|| device.name().to_string());
    if !name.starts_with("Apple") || !device.has_unified_memory() {
        return Err(format!(
            "Metal device {name:?} is not an Apple Silicon GPU: the Metal risc0 worker supports \
             Apple Silicon Macs only (Intel Macs and discrete GPUs are not supported)"
        ));
    }
    let host_memory = sysctl_u64("hw.memsize").unwrap_or(0);
    if host_memory < MIN_HOST_MEMORY_BYTES {
        return Err(format!(
            "this Mac has {:.1} GiB of memory: the Metal risc0 worker needs at least 16 GB \
             (8 GB Macs cannot hold a proof beside macOS; PLAN 9.1)",
            host_memory as f64 / GIB as f64
        ));
    }
    Ok(MetalHost {
        name,
        recommended_working_set: device.recommended_max_working_set_size(),
        host_memory,
    })
}

/// `RISC0_METAL_MAX_WORKING_SET_BYTES`, parsed with the fork's grammar (`4294967296`, `4G`, ...).
fn budget_env() -> Option<u64> {
    risc0_groth16_sys::metal::working_set_budget()
}

/// The GPU memory this worker may plan with: the smallest of the device's
/// `recommendedMaxWorkingSetSize`, `RISC0_METAL_MAX_WORKING_SET_BYTES` and the host's
/// `ZKMINER_CUDA_VRAM_BYTES`. `None` on an unsupported Mac.
pub fn working_set_limit() -> Option<u64> {
    let host = support().as_ref().ok()?;
    let vram_env = std::env::var(CUDA_VRAM_BYTES_ENV)
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|&v| v > 0);
    Some(
        [Some(host.recommended_working_set), budget_env(), vram_env]
            .into_iter()
            .flatten()
            .min()
            .unwrap_or(host.recommended_working_set),
    )
}

/// What [`apply_planned_budget`] did, for the start-up log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BudgetPlan {
    /// The limit the worker plans with after this ([`working_set_limit`]).
    pub plan: u64,
    /// `RISC0_METAL_MAX_WORKING_SET_BYTES` as exported here, or `None` when left as it was.
    pub exported: Option<u64>,
    /// One line for the log.
    pub note: String,
}

/// The keccak max po2 18 needs this much working set (risc0 W7-V2's measured minimum peak,
/// `KECCAK_MIN_PEAK_MIB[18]` = 7084 MiB); below it only po2 17 fits.
pub const KECCAK_PO2_18_MIN_LIMIT: u64 = 7084 << 20;

/// W7-M10, at worker start, before any proof or Metal HAL runtime (the readers of the variables
/// set here; rayon's idle pool and the Metal device [`support`] opened already exist): with
/// `ZKMINER_METAL_ENFORCE_BUDGET=1`, makes the HAL enforce the limit the worker plans with
/// (`metal_sizing::enforced_budget`; the HAL reads `RISC0_METAL_MAX_WORKING_SET_BYTES` when each
/// runtime is created, the Groth16 prover at each call). Without it the plan (the host's figure,
/// 8 GiB on a 16 GB Mac) sizes the segments while the HAL runs to `recommendedMaxWorkingSetSize`
/// (~10.7 GiB there, pool cap 5.35 GiB). Off by default: enforcing measured slower and larger (see
/// `metal_sizing::ENFORCE_BUDGET_ENV`). A no-op on the 36 GB dev Mac either way (plan 28.00 GiB,
/// device 28.08 GiB) and wherever the plan is the device's limit.
///
/// `simulate_owner`: the `--benchmark` run only. `ZKMINER_OWNER_ACTIVE=1` there plans with the
/// owner-active tier's figure (`metal_sizing::active_limit` of the plan), so the active tier can be
/// measured on any Mac. An IPC worker never reads it: the dispatcher picks the tier per job and
/// hands it the figure (`ZKMINER_CUDA_VRAM_BYTES`).
pub fn apply_planned_budget(simulate_owner: bool) -> Option<BudgetPlan> {
    use crate::metal_sizing as ms;
    let host = support().as_ref().ok()?;
    let gib = |b: u64| b as f64 / GIB as f64;
    let mut note = String::new();
    if simulate_owner && ms::owner_force() == ms::OwnerForce::Active {
        let idle = working_set_limit()?;
        let active = ms::active_limit(idle);
        if active < idle {
            std::env::set_var(CUDA_VRAM_BYTES_ENV, active.to_string());
        }
        note += &format!(
            "owner-active tier (ZKMINER_OWNER_ACTIVE=1): {:.1} GiB instead of {:.1} GiB; ",
            gib(active),
            gib(idle)
        );
    }
    let plan = working_set_limit()?;
    let hal = budget_env().map_or(host.recommended_working_set, |b| {
        b.min(host.recommended_working_set)
    });
    let exported = ms::enforced_budget(plan, hal, ms::enforce_budget_off());
    match exported {
        Some(b) => {
            std::env::set_var(ms::MAX_WORKING_SET_ENV, b.to_string());
            note += &format!(
                "enforcing the planned {:.2} GiB as the Metal budget (the HAL's limit was {:.2} GiB)",
                gib(b),
                gib(hal)
            );
        }
        None if ms::enforce_budget_off() => {
            note += &format!(
                "planned {:.2} GiB, not enforced ({} is not 1; the HAL's limit is {:.2} GiB)",
                gib(plan),
                ms::ENFORCE_BUDGET_ENV,
                gib(hal)
            )
        }
        None => {
            note += &format!(
                "planned {:.2} GiB, within a GiB of the HAL's {:.2} GiB limit: nothing to enforce",
                gib(plan),
                gib(hal)
            )
        }
    }
    if let Some(warning) =
        keccak_po2_warning(std::env::var("RISC0_KECCAK_PO2").ok().as_deref(), plan)
    {
        note += "; ";
        note += &warning;
    }
    Some(BudgetPlan {
        plan,
        exported,
        note,
    })
}

/// A warning when the operator's keccak max po2 (`RISC0_KECCAK_PO2`) cannot fit `limit`: po2 18
/// needs [`KECCAK_PO2_18_MIN_LIMIT`]. The worker never sets that variable; the zkvm default (17)
/// fits every tier, also 4 GiB (3968-4094 MiB measured there with the budget enforced, risc0
/// W7-V2), so this is only for an override.
pub fn keccak_po2_warning(var: Option<&str>, limit: u64) -> Option<String> {
    let po2: u32 = var?.trim().parse().ok()?;
    (po2 >= 18 && limit < KECCAK_PO2_18_MIN_LIMIT).then(|| {
        format!(
            "RISC0_KECCAK_PO2={po2} needs about {:.1} GiB of Metal working set and this worker has \
             {:.1} GiB: a keccak proof at po2 {po2} may fail here; leave it unset (17)",
            KECCAK_PO2_18_MIN_LIMIT as f64 / GIB as f64,
            limit as f64 / GIB as f64
        )
    })
}

/// The default segment size for a working-set limit (PLAN 9.1): the shared table
/// (`metal_sizing::job_po2_for_limit`, M8 tiers; `ZKMINER_METAL_PO2_TABLE=m1` restores M1's).
///
/// The Groth16 wrap needs ~3.9 GB under an enforced budget (the key is not kept there), so the 4 GiB
/// tier is the floor. Never above [`zkminer_prover_protocol::RISC0_DEFAULT_JOB_PO2`].
pub fn job_po2_for_limit(limit: u64) -> u8 {
    crate::metal_sizing::job_po2_for_limit(limit)
        .min(zkminer_prover_protocol::RISC0_DEFAULT_JOB_PO2)
}

/// This Mac's default segment size ([`job_po2_for_limit`] of [`working_set_limit`]), or the protocol
/// default on an unsupported Mac (which proves nothing anyway).
pub fn default_job_po2() -> u8 {
    static PO2: OnceLock<u8> = OnceLock::new();
    *PO2.get_or_init(|| match working_set_limit() {
        Some(limit) => {
            let po2 = job_po2_for_limit(limit);
            tracing::info!(
                "Metal working-set limit {:.1} GiB: default segment po2 {po2}",
                limit as f64 / GIB as f64
            );
            po2
        }
        None => zkminer_prover_protocol::RISC0_DEFAULT_JOB_PO2,
    })
}

/// Peak GPU memory of the largest STARK phase at `po2` with no budget enforced (the recursion phase,
/// beside the segment prover's cached pool): the shared `metal_sizing::stark_peak_bytes`. Used for the
/// Groth16 keep decision and the refusal text; not what sizes the job.
pub fn stark_peak_bytes(po2: u8) -> u64 {
    crate::metal_sizing::stark_peak_bytes(po2)
}

/// The largest segment po2 allowed to start under `limit`, or `None` when none is
/// (`metal_sizing::max_po2_for_limit`). This is a hard ceiling, not the default
/// ([`job_po2_for_limit`] is): on the 36 GB dev machine (28.1 GiB) it is 21, and po2 22 is refused.
/// Without it a po2 22 Prove there did not fail but thrashed swap for 40 minutes (18 GB of swap,
/// the whole machine starved), because with no `RISC0_METAL_MAX_WORKING_SET_BYTES` Metal
/// over-commits past `recommendedMaxWorkingSetSize` instead of failing the allocation (M1 note, fix
/// round 1). Below po2 21 the M8 table admits what proved under an enforced budget of that size
/// (po2 18 at 4 GiB, where M1's ceiling was 17).
pub fn max_po2_for_limit(limit: u64) -> Option<u8> {
    crate::metal_sizing::max_po2_for_limit(limit)
}

/// The risc0 fork's Z12 knob: `0` keeps the segment prover cached through recursion (pre-Z12), `1`
/// always drops it before lift/join, anything else (`auto`) drops it only when the enforced
/// working-set limit cannot hold both.
pub const RELEASE_SEG_BEFORE_REC_ENV: &str = "RISC0_METAL_RELEASE_SEG_BEFORE_REC";

/// The worker's value for [`RELEASE_SEG_BEFORE_REC_ENV`] when the operator set none: `1` (M8).
///
/// `auto` only sees an ENFORCED limit, and a real Mac enforces none, so there the segment prover's
/// pool stays allocated beside recursion and the sum is real RAM. Dropping it always costs nothing
/// in this worker: the wrap's `release_hal_buffers` drops the prover after every proof anyway, and
/// 7 interleaved pairs each (M8 note, memory-merkle, quiet machine) put the STARK time inside the
/// spread at 8 / 10 / 16 GiB and the default budget, while the process footprint fell 10.57 -> 8.38
/// GB at po2 19 under a 10 GiB limit (the 16 GB Mac case: back to po2 18's 8.4 GB) and 16.15 ->
/// 14.19 GB at po2 20 by default. Set the variable (`auto`, `0`) to override.
pub fn release_seg_mode_default(current: Option<&std::ffi::OsStr>) -> Option<&'static str> {
    current.is_none().then_some("1")
}

/// Applies [`release_seg_mode_default`] to this process. Call at start, before any thread proves.
pub fn default_release_segment_prover_before_recursion() {
    if let Some(mode) =
        release_seg_mode_default(std::env::var_os(RELEASE_SEG_BEFORE_REC_ENV).as_deref())
    {
        std::env::set_var(RELEASE_SEG_BEFORE_REC_ENV, mode);
    }
}

/// Lets an operator (or a test of the out-of-memory path) prove above [`max_po2_for_limit`].
pub const NO_PO2_CEILING_ENV: &str = "ZKMINER_METAL_NO_PO2_CEILING";

/// Why a proof at segment `po2` must not start on this Mac, or `None`. The text starts with the
/// fork's own out-of-memory wording so [`is_metal_oom`] types it `ResourceExhausted`, which sends
/// the job to a bigger card instead of failing it here.
pub fn po2_refusal(po2: u8) -> Option<String> {
    if std::env::var(NO_PO2_CEILING_ENV).is_ok_and(|v| v.trim() == "1") {
        return None;
    }
    let limit = working_set_limit()?;
    let max = max_po2_for_limit(limit);
    if max.is_some_and(|m| po2 <= m) {
        return None;
    }
    Some(format!(
        "Metal working-set budget exceeded: segment po2 {po2} needs a working-set limit of about \
         {:.1} GiB, above this Mac's {:.1} GiB ({})",
        crate::metal_sizing::min_limit_for_po2(po2, crate::metal_sizing::env_po2_table()) as f64
            / GIB as f64,
        limit as f64 / GIB as f64,
        match max {
            Some(m) => format!("largest po2 here: {m}"),
            None => "no segment size fits".to_string(),
        }
    ))
}

/// Whether host-generated error or panic text is a Metal out-of-memory: the fork's working-set budget
/// check (`hal/metal/runtime.rs`, also behind the Groth16 key load), a failed `newBuffer`, or
/// [`po2_refusal`]. `is_gpu_oom` (CUDA/HIP/Level Zero wording) matches none of these. Callers must
/// classify guest-fault text first, as they do for `is_gpu_oom`.
pub fn is_metal_oom(text: &str) -> bool {
    text.contains("Metal working-set budget exceeded")
        || text.contains("Metal allocation failed")
        || text.contains("Metal private allocation failed")
}

/// Whether the Groth16 proving key may stay cached on the GPU between proofs: only when it fits
/// beside the next proof's largest STARK phase with headroom. On unified memory a kept key is 5.6 GB
/// of the owner's RAM held while idle, so this is the high-end tier only. The rule and its constants
/// live in `metal_sizing` (shared with the host, which compares tiers by it).
pub fn keep_groth16_cache(limit: u64, po2: u8) -> bool {
    crate::metal_sizing::keep_groth16_cache(limit, po2)
}

/// The device's `currentAllocatedSize` (this process's GPU allocations), or 0 without a device.
pub fn allocated_bytes() -> u64 {
    static DEVICE: OnceLock<Option<metal::Device>> = OnceLock::new();
    DEVICE
        .get_or_init(metal::Device::system_default)
        .as_ref()
        .map_or(0, |d| d.current_allocated_size())
}

pub fn mib(bytes: u64) -> f64 {
    bytes as f64 / (1u64 << 20) as f64
}

/// After every proof (success or failure), on the proving thread: drop the recursion provers this
/// thread caches (their HALs' pools). The zkvm already does this, and drops the segment prover too,
/// after every Groth16 wrap (`release_hal_buffers`), so on a successful proof this finds nothing; a
/// proof that failed before its wrap leaves the segment prover's pool cached until the next
/// proof, because the zkvm has no public entry point to drop it (M1 note, issue for the zkvm owner).
pub fn release_after_proof() {
    risc0_circuit_recursion::prove::release_cached_provers();
    tracing::info!(
        "Metal GPU memory held after the proof: {:.1} MiB",
        mib(allocated_bytes())
    );
}

/// Samples `currentAllocatedSize` every 2 ms on a background thread and records the peak per named
/// phase (PLAN 9.1: peak GPU memory per phase is a first-class metric).
pub struct PeakSampler {
    stop: Arc<AtomicBool>,
    peak: Arc<AtomicU64>,
    handle: Option<std::thread::JoinHandle<()>>,
    phases: Mutex<Vec<(String, u64)>>,
}

impl PeakSampler {
    pub fn start() -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let peak = Arc::new(AtomicU64::new(allocated_bytes()));
        let handle = {
            let (stop, peak) = (stop.clone(), peak.clone());
            std::thread::Builder::new()
                .name("metal-mem-sampler".into())
                .spawn(move || {
                    while !stop.load(Ordering::Relaxed) {
                        peak.fetch_max(allocated_bytes(), Ordering::Relaxed);
                        std::thread::sleep(Duration::from_millis(2));
                    }
                })
                .ok()
        };
        Self {
            stop,
            peak,
            handle,
            phases: Mutex::new(Vec::new()),
        }
    }

    /// Close the current phase: record its peak and start the next one from the current size.
    pub fn phase(&self, name: &str) -> u64 {
        let now = allocated_bytes();
        let peak = self.peak.swap(now, Ordering::Relaxed).max(now);
        self.phases
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push((name.to_string(), peak));
        peak
    }

    /// Record what is allocated now (not a peak), e.g. after the post-proof release.
    pub fn held(&self, name: &str) -> u64 {
        let now = allocated_bytes();
        self.peak.store(now, Ordering::Relaxed);
        self.phases
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push((name.to_string(), now));
        now
    }

    /// "phase peak MiB, ..." for a log line.
    pub fn summary(&self) -> String {
        self.phases
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .map(|(n, b)| format!("{n} {:.0} MiB", mib(*b)))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

impl Drop for PeakSampler {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

/// Revert knob for the worker-start Groth16 witness-graph preload (M7): `0`, `off` or `false` leaves
/// the graph to the zkvm, which starts building it only when a proof begins (`prove_with_opts` with
/// a Groth16 receipt) or, for a staged proof such as `--benchmark`'s, when the wrap begins, so that
/// wrap waits for it.
pub const G16_PRELOAD_ENV: &str = "ZKMINER_G16_PRELOAD";

static G16_PRELOAD_STARTED: AtomicBool = AtomicBool::new(false);

/// Why the worker-start graph preload must not run, or `None` when it should: the knob is off, or the
/// `risc0-groth16` component is not installed yet. The second matters: risc0 keeps a failed graph
/// load for the life of the process (`OnceLock`), so a preload that ran before `Warmup` installed the
/// component would fail every wrap of this worker.
fn graph_preload_refusal(knob: Option<&str>, component_installed: bool) -> Option<&'static str> {
    if knob.is_some_and(|v| matches!(v.trim(), "0" | "off" | "false")) {
        return Some("disabled by ZKMINER_G16_PRELOAD");
    }
    if !component_installed {
        return Some("the risc0-groth16 component is not installed yet");
    }
    None
}

/// Start building the Groth16 witness graph (`risc0_groth16::prove::preload_graph`) on a background
/// thread, once per process, so the first wrap does not wait for it. The build is CPU only (~5 s on
/// one core, ~2 GB of host memory that risc0 keeps for the life of the process) and touches no GPU
/// memory, so it overlaps pipeline warm-up and the first STARK. Later callers (the zkvm's own
/// preload at proof start, `prestart_prover` before the wrap, the wrap itself) share the one build
/// (risc0 caches it in a `OnceLock`), so nothing is built twice. The proving key is deliberately not
/// loaded here (M7 note: its load, 0.13-0.55 s, already runs beside the witness and was on the wrap's
/// critical path for at most 87 ms in 5 of 49 measured wraps, while loading it early would put
/// 3.9 GB of device memory beside the STARK pools). Returns whether it started a build.
pub fn start_groth16_graph_preload(at: &str) -> bool {
    let knob = std::env::var(G16_PRELOAD_ENV).ok();
    let installed = crate::groth16_component::installed();
    if let Some(why) = graph_preload_refusal(knob.as_deref(), installed) {
        tracing::info!("not preloading the Groth16 witness graph at {at}: {why}");
        return false;
    }
    if G16_PRELOAD_STARTED.swap(true, Ordering::SeqCst) {
        return false;
    }
    let at = at.to_string();
    let spawned = std::thread::Builder::new()
        .name("g16-graph-preload".into())
        .spawn(move || {
            let t = Instant::now();
            match risc0_groth16::prove::preload_graph() {
                Ok(()) => tracing::info!(
                    "Groth16 witness graph ready {:.2} s after the preload started at {at}",
                    t.elapsed().as_secs_f64()
                ),
                Err(e) => tracing::warn!("Groth16 witness graph preload failed: {e:#}"),
            }
        });
    if let Err(e) = spawned {
        G16_PRELOAD_STARTED.store(false, Ordering::SeqCst);
        tracing::warn!("could not start the Groth16 witness graph preload: {e}");
        return false;
    }
    true
}

/// Build every circuit's Metal pipeline states once per process: rv32im (with the zkp kernels),
/// recursion, keccak (through its binary archive, K5) and the Groth16 prover, each on its own thread
/// so the compiler service builds them in parallel. None of them takes the GPU lock for long, and
/// each is process-wide, so later proofs find them built. Returns (and logs) how long each took: tens
/// of seconds to minutes cold (first run of a newly built binary), well under a second warm.
pub fn warm_up_pipelines() -> &'static str {
    static DONE: OnceLock<String> = OnceLock::new();
    DONE.get_or_init(|| {
        let started = Instant::now();
        let timed = |f: fn()| {
            move || {
                let t = Instant::now();
                f();
                t.elapsed()
            }
        };
        let (rv32im, recursion, keccak, groth16) = std::thread::scope(|s| {
            let rv32im = s.spawn(timed(risc0_circuit_rv32im::prove::metal_warmup));
            let recursion = s.spawn(timed(risc0_circuit_recursion::prove::metal_warmup));
            let keccak = s.spawn(timed(risc0_circuit_keccak::prove::metal_warmup));
            let groth16 = s.spawn(|| {
                let t = Instant::now();
                if let Err(e) = risc0_groth16_sys::metal_warmup() {
                    tracing::warn!("Groth16 Metal warmup failed: {e:#}");
                }
                t.elapsed()
            });
            let get = |h: std::thread::ScopedJoinHandle<'_, Duration>| h.join().unwrap_or_default();
            (get(rv32im), get(recursion), get(keccak), get(groth16))
        });
        let total = started.elapsed();
        let cold = total > Duration::from_secs(10);
        let summary = format!(
            "built the Metal pipelines in {:.1} s ({}): rv32im+zkp {:.1} s, recursion {:.1} s, \
             keccak {:.1} s, groth16 {:.1} s",
            total.as_secs_f64(),
            if cold { "cold" } else { "warm" },
            rv32im.as_secs_f64(),
            recursion.as_secs_f64(),
            keccak.as_secs_f64(),
            groth16.as_secs_f64(),
        );
        tracing::info!("{summary}");
        summary
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// M8 table (these tests run without `ZKMINER_METAL_PO2_TABLE`).
    #[test]
    fn po2_follows_the_working_set_limit() {
        if crate::metal_sizing::env_po2_table() != crate::metal_sizing::Po2Table::M8 {
            return;
        }
        assert_eq!(job_po2_for_limit(4 * GIB), 18);
        assert_eq!(job_po2_for_limit(8 * GIB), 19);
        // A 16 GB Mac: ~10.7 GB recommended, 8 GiB host figure (the smaller wins, 19); an 18 GB
        // Mac's 10 GiB host figure.
        assert_eq!(job_po2_for_limit(10_700_000_000), 19);
        assert_eq!(job_po2_for_limit(10 * GIB), 19);
        assert_eq!(job_po2_for_limit(12 * GIB), 20);
        assert_eq!(job_po2_for_limit(16 * GIB), 20);
        // The 36 GB dev machine: min(30.15 GB, 28 GiB).
        assert_eq!(job_po2_for_limit(28 * GIB), 20);
        assert_eq!(job_po2_for_limit(180 * GIB), 20);
    }

    #[test]
    fn the_po2_ceiling_follows_the_table() {
        if crate::metal_sizing::env_po2_table() != crate::metal_sizing::Po2Table::M8 {
            return;
        }
        assert_eq!(max_po2_for_limit(3 * GIB), None);
        assert_eq!(max_po2_for_limit(4 * GIB), Some(18));
        assert_eq!(max_po2_for_limit(8 * GIB), Some(19));
        assert_eq!(
            max_po2_for_limit(10 * GIB),
            Some(20),
            "proved at a 10 GiB budget (M8)"
        );
        assert_eq!(max_po2_for_limit(16 * GIB), Some(20));
        // The 36 GB dev machine: po2 21 proved there (M1 review), po2 22 thrashed swap.
        assert_eq!(max_po2_for_limit(28 * GIB), Some(21));
        assert_eq!(max_po2_for_limit(180 * GIB), Some(23));
        // Never below the default for the same limit.
        for limit in [4 * GIB, 8 * GIB, 10_700_000_000, 16 * GIB, 28 * GIB] {
            assert!(max_po2_for_limit(limit).unwrap() >= job_po2_for_limit(limit));
        }
    }

    #[test]
    fn the_worker_releases_the_segment_prover_unless_told_otherwise() {
        use std::ffi::OsStr;
        assert_eq!(release_seg_mode_default(None), Some("1"));
        for set in ["0", "1", "auto", ""] {
            assert_eq!(
                release_seg_mode_default(Some(OsStr::new(set))),
                None,
                "{set:?}"
            );
        }
    }

    #[test]
    fn metal_oom_text_is_recognised() {
        assert!(is_metal_oom(
            "risc0 prover panicked: Metal working-set budget exceeded: allocating 3152 bytes"
        ));
        assert!(is_metal_oom(
            "failed to load the groth16 proving key: Metal working-set budget exceeded: x"
        ));
        assert!(is_metal_oom("Metal allocation failed on evaluated: 7 bytes"));
        assert!(!is_metal_oom("called `Result::unwrap()` on an `Err` value: PoisonError"));
    }

    #[test]
    fn the_groth16_cache_is_kept_on_the_high_end_only() {
        assert!(!keep_groth16_cache(8 * GIB, 18));
        assert!(!keep_groth16_cache(16 * GIB, 19));
        // The 36 GB dev machine (28.1 GiB) releases it; a 48 GB Mac (~36 GiB) keeps it.
        assert!(!keep_groth16_cache(28 * GIB, 20));
        assert!(keep_groth16_cache(36 * GIB, 20));
    }

    #[test]
    fn the_graph_preload_needs_the_component_and_honours_its_knob() {
        assert_eq!(graph_preload_refusal(None, true), None);
        assert_eq!(graph_preload_refusal(Some("1"), true), None);
        for off in ["0", "off", "false", " 0 "] {
            assert!(graph_preload_refusal(Some(off), true).is_some(), "{off:?}");
        }
        // Never before the component is installed: risc0 would cache the failure.
        assert!(graph_preload_refusal(None, false).is_some());
    }

    /// W7-M10: on this Mac the dispatcher's figure (RAM less 8 GiB) is within a GiB of the
    /// device's own limit, so enforcement exports nothing; a simulated 16 GB figure, the
    /// owner-active tier and a 4 GiB figure are enforced.
    #[test]
    fn enforcement_on_this_mac() {
        use crate::metal_sizing as ms;
        let host = support().as_ref().expect("an Apple Silicon Mac");
        let rec = host.recommended_working_set;
        let figure = host.host_memory - ms::HOST_RESERVE_BYTES;
        let plan = figure.min(rec);
        eprintln!(
            "hw.memsize {} B, recommendedMaxWorkingSetSize {rec} B, figure {figure} B",
            host.host_memory
        );
        if host.host_memory == 36 * GIB {
            assert_eq!(
                ms::enforced_budget(plan, rec, false),
                None,
                "a no-op on the 36 GB Mac"
            );
        }
        if rec >= 9 * GIB {
            assert_eq!(ms::enforced_budget(8 * GIB, rec, false), Some(8 * GIB));
        }
        let active = ms::active_limit(plan);
        assert!(active <= plan);
        assert_eq!(ms::enforced_budget(4 * GIB, rec, false), Some(4 * GIB));
        assert_eq!(ms::enforced_budget(4 * GIB, rec, true), None, "the knob");
    }

    #[test]
    fn a_keccak_po2_that_cannot_fit_is_warned_about() {
        assert_eq!(
            keccak_po2_warning(None, 4 * GIB),
            None,
            "unset: the default 17 fits"
        );
        assert_eq!(keccak_po2_warning(Some("17"), 4 * GIB), None);
        assert!(keccak_po2_warning(Some("18"), 4 * GIB).is_some());
        assert!(keccak_po2_warning(Some("18"), 6 * GIB).is_some());
        assert_eq!(keccak_po2_warning(Some("18"), 8 * GIB), None);
        assert_eq!(keccak_po2_warning(Some("x"), 4 * GIB), None);
    }

    #[test]
    fn this_mac_is_supported() {
        let host = support()
            .as_ref()
            .expect("the dev machine is an Apple Silicon Mac");
        assert!(host.name.starts_with("Apple"));
        assert!(working_set_limit().unwrap() <= host.recommended_working_set);
    }
}
