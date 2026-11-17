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
/// (`metal_sizing::job_po2_for_limit`: W7-M11's tiers and footprint model; `ZKMINER_METAL_TIER_TABLE=m8`
/// restores M8's, `ZKMINER_METAL_PO2_TABLE=m1` M1's).
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

/// The Groth16 prover's memory layouts (risc0 groth16-sys `MemOptions`, items P31-12 / B9-4G), named
/// as the worker logs them, with the switches that force each one.
const GROTH16_LAYOUTS: [(&str, bool, bool); 4] = [
    ("whole", false, false),
    ("split_h", true, false),
    ("whole + tw_lent", false, true),
    ("split_h + tw_lent", true, true),
];

/// Whether risc0's `choose_layout` can build the layout (`split`, `lent`) under these switches: a
/// forced switch admits only its own side; under `auto` for both, whole + tw_lent is never taken
/// (its plan is above split_h's, which is tried first, so it is never the first that fits nor the
/// smallest). Release-line review finding: at a 4300 MiB budget the prover took split_h, 2 MiB from
/// whole + tw_lent's plan, and the line named both.
fn groth16_layout_reachable(
    split_h: risc0_groth16_sys::metal::prover::SplitH,
    tw_lent: risc0_groth16_sys::metal::prover::TwLent,
    split: bool,
    lent: bool,
) -> bool {
    use risc0_groth16_sys::metal::prover::{SplitH, TwLent};
    let split_ok = match split_h {
        SplitH::On => split,
        SplitH::Off => !split,
        SplitH::Auto => true,
    };
    let lent_ok = match tw_lent {
        TwLent::On => lent,
        TwLent::Off => !lent,
        TwLent::Auto => true,
    };
    let auto_never = split_h == SplitH::Auto && tw_lent == TwLent::Auto && !split && lent;
    split_ok && lent_ok && !auto_never
}

/// Device bytes each Groth16 layout reachable under this process's memory switches plans (header
/// reads only; kept once read, retried while the component is missing). Each layout is forced, so
/// the figure does not depend on the room at the moment it is read. [warm_up_pipelines] reads it at
/// start, so no proof waits for it.
fn groth16_layout_plans() -> Option<&'static [(&'static str, u64)]> {
    static PLANS: OnceLock<Vec<(&'static str, u64)>> = OnceLock::new();
    if let Some(plans) = PLANS.get() {
        return Some(plans);
    }
    use risc0_groth16_sys::metal::prover::{planned_bytes, MemOptions, SplitH, TwLent};
    let dir = crate::groth16_component::dir()?;
    let setup = risc0_groth16_sys::SetupParams::new(&dir).ok()?;
    let base = MemOptions::from_env();
    let plans: Vec<_> = GROTH16_LAYOUTS
        .iter()
        .filter(|&&(_, split, lent)| {
            groth16_layout_reachable(base.split_h, base.tw_lent, split, lent)
        })
        .filter_map(|&(name, split, lent)| {
            let mem = MemOptions {
                split_h: if split { SplitH::On } else { SplitH::Off },
                tw_lent: if lent { TwLent::On } else { TwLent::Off },
                ..base
            };
            Some((name, planned_bytes(&setup, mem).ok()?))
        })
        .collect();
    if plans.is_empty() {
        return None;
    }
    Some(PLANS.get_or_init(|| plans))
}

/// The layout whose planned footprint is nearest to `freed` (the device bytes a release of the
/// cached prover gave back; the plan is the real growth plus at most a few MiB, B9-4G), or both
/// names when two are within 8 MiB of each other (split_h and whole + tw_lent are 2 MiB apart with
/// the v0.2.0 key; under the default `auto` switches whole + tw_lent is never chosen). `None`
/// when nothing is within 64 MiB (no prover was cached, or the switches changed).
fn groth16_layout_of(freed: u64, plans: &[(&'static str, u64)]) -> Option<String> {
    const NEAR: u64 = 64 << 20;
    const TIE: u64 = 8 << 20;
    let mut by_distance: Vec<(u64, &str)> = plans
        .iter()
        .map(|&(name, planned)| (planned.abs_diff(freed), name))
        .collect();
    by_distance.sort();
    let &(best, name) = by_distance.first()?;
    if best > NEAR {
        return None;
    }
    Some(match by_distance.get(1) {
        Some(&(next, other)) if next <= best + TIE => format!("{name} or {other}"),
        _ => name.to_string(),
    })
}

/// Logs what releasing the Groth16 proving key gave back (`before` / `after`: the device allocation
/// around `release_srs`), and the prover layout that size identifies (B9-4G open issue: the 4 GiB
/// tier must build split_h + tw_lent, the 8 GiB tier the whole layout). One info line per release:
/// the evidence that the worker frees the key between jobs below the keep threshold.
pub fn log_groth16_release(before: u64, after: u64) {
    let freed = before.saturating_sub(after);
    if freed < (256 << 20) {
        tracing::info!(
            "Groth16 proving key released: no prover was cached ({:.1} MiB freed); device \
             allocation now {:.1} MiB",
            mib(freed),
            mib(after)
        );
        return;
    }
    let layout = groth16_layout_plans()
        .and_then(|plans| groth16_layout_of(freed, plans))
        .unwrap_or_else(|| "unidentified".to_string());
    // Only when every named layout lends the twiddles (a tie can name one that does not).
    let prefault = if layout.split(" or ").all(|name| name.contains("tw_lent")) {
        if std::env::var("RISC0_G16_METAL_TW_PREFAULT").as_deref() == Ok("0") {
            ", tw_prefault off"
        } else {
            ", tw_prefault on"
        }
    } else {
        ""
    };
    tracing::info!(
        "Groth16 proving key released: {:.1} MiB of device memory freed (prover layout {layout}\
         {prefault}; planned {}), device allocation now {:.1} MiB",
        mib(freed),
        groth16_layout_plans().map_or_else(
            || "unknown".to_string(),
            |plans| plans
                .iter()
                .map(|(n, b)| format!("{n} {:.1}", mib(*b)))
                .collect::<Vec<_>>()
                .join(", ")
                + " MiB"
        ),
        mib(after)
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
                    "Groth16 witness graph ready {:.2} s after the preload started at {at} \
                     (risc0-groth16 {}, graph sha256 {}... checked by risc0)",
                    t.elapsed().as_secs_f64(),
                    crate::groth16_component::VERSION,
                    crate::groth16_component::GRAPH_SHA256_PREFIX
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

/// Knob for the keccak part of the worker-start pipeline build (P31-19): `on` builds the keccak
/// pipelines at start with the others (wave 7's behaviour), `off` never does (the first keccak proof
/// builds them, through its binary archive), `auto` (the default) builds them unless the Groth16
/// prover would then no longer fit the working-set limit beside the pipelines ([keccak_prewarm_refusal]).
pub const KECCAK_PREWARM_ENV: &str = "ZKMINER_METAL_PREWARM_KECCAK";

/// What the keccak pipelines add to the device allocation, with room to spare: 16 MiB measured on
/// risc0 3.1 (process-wide pipelines 45.9 -> 62.1 MiB with them, P31-19 note), reserved twice.
const KECCAK_PIPELINES_RESERVE: u64 = 32 << 20;

/// Under `auto`, a working-set limit at least this much above the Groth16 prover's planned footprint
/// can hold every process-wide pipeline beside it (62 MiB of them measured), so the keccak build
/// keeps running in parallel with the others; below it, it runs after them, so the decision can
/// read what they allocated.
const KECCAK_PREWARM_TIGHT_MARGIN: u64 = 512 << 20;

/// The Groth16 prover's planned footprint assumed while it cannot be read (the v0.2.0 component not
/// installed yet: a host upgraded from risc0 3.0 gets it from the first Warmup, after this decision
/// is latched): risc0 3.1's smallest plan, split_h + tw_lent, which a 4 GiB limit takes since B9-4G
/// (3885.0 MiB in the worker's release line, B9-ZK; rounded up). Was 4235118872 B (P31-19, before
/// B9-4G made the check exact and lent the NTT twiddles). Below about 3.9 GiB + the pipelines this
/// still defers keccak instead of building it and then refusing every wrap; a roomy limit is
/// unaffected. It assumes the default `auto` split_h/tw_lent switches; with either not `auto` the
/// smallest buildable plan can be larger, so [groth16_plan_fallback] takes
/// [GROTH16_PLAN_FALLBACK_FORCED] instead.
const GROTH16_PLAN_FALLBACK: u64 = 3886 << 20;

/// The fallback when the split_h or tw_lent switch is not `auto`: the whole layout's plan, the
/// largest of the four split_h/tw_lent layouts (4141.0 MiB with the v0.2.0 key, B9-4G), rounded
/// up. Defers keccak where the forced layout might not fit. It covers those two switches only: with
/// compact, mmap or alias off (`RISC0_G16_METAL_G10=0`, which is the G9 layout, or
/// `RISC0_G16_METAL_G10_OFF=compact|alias`) the real plan is about 1.3 GB larger and both fallbacks
/// understate it. That only matters before the component is installed and with a debug knob set.
const GROTH16_PLAN_FALLBACK_FORCED: u64 = 4142 << 20;

/// [GROTH16_PLAN_FALLBACK] under the default switches, [GROTH16_PLAN_FALLBACK_FORCED] otherwise.
fn groth16_plan_fallback_for(
    split_h: risc0_groth16_sys::metal::prover::SplitH,
    tw_lent: risc0_groth16_sys::metal::prover::TwLent,
) -> u64 {
    use risc0_groth16_sys::metal::prover::{SplitH, TwLent};
    if split_h == SplitH::Auto && tw_lent == TwLent::Auto {
        GROTH16_PLAN_FALLBACK
    } else {
        GROTH16_PLAN_FALLBACK_FORCED
    }
}

/// [groth16_plan_fallback_for] this process's switches.
fn groth16_plan_fallback() -> u64 {
    let mem = risc0_groth16_sys::metal::prover::MemOptions::from_env();
    groth16_plan_fallback_for(mem.split_h, mem.tw_lent)
}

/// Why the worker-start keccak pipeline build must not run, or `None` when it should. `limit` is
/// the working-set limit, `allocated` the device allocation after the other circuits' pipelines,
/// `groth16` the Groth16 prover's planned footprint (`None`: unknown, e.g. no component yet), and
/// `fallback` the footprint assumed when it is unknown (production passes
/// [groth16_plan_fallback], which reads this process's layout switches; taking it as an argument
/// keeps this function pure, so its tests do not depend on the environment's revert knobs).
///
/// The keccak pipelines are never freed once built, so building them at start under a limit that
/// then cannot hold the Groth16 prover beside them would fail every wrap of the worker's life,
/// keccak or not. Before B9-4G that was the 4 GiB tier (a 4039 MiB plan + 62 MiB of pipelines >
/// 4096 MiB). Since B9-4G the prover plans 3885 MiB there (split_h + tw_lent) and keccak is built at
/// start (151.8 MiB of headroom measured with every pipeline built); the rule still guards
/// smaller limits.
fn keccak_prewarm_refusal(
    knob: Option<&str>,
    limit: Option<u64>,
    allocated: u64,
    groth16: Option<u64>,
    fallback: u64,
) -> Option<String> {
    match knob.map(|v| v.trim().to_ascii_lowercase()).as_deref() {
        Some("off" | "0" | "false") => return Some(format!("{KECCAK_PREWARM_ENV}=off")),
        Some("on" | "1" | "true") => return None,
        _ => {}
    }
    let (limit, groth16) = (limit?, groth16.unwrap_or(fallback));
    let need = allocated
        .saturating_add(groth16)
        .saturating_add(KECCAK_PIPELINES_RESERVE);
    (need > limit).then(|| {
        format!(
            "the Groth16 prover ({:.0} MiB planned) would not fit the {:.0} MiB working-set limit \
             beside {:.0} MiB of pipelines plus keccak's; the first keccak proof builds them",
            groth16 as f64 / (1u64 << 20) as f64,
            limit as f64 / (1u64 << 20) as f64,
            allocated as f64 / (1u64 << 20) as f64,
        )
    })
}

/// The Groth16 prover's planned device footprint with this process's memory switches and limit, if
/// the component is installed (reads only file headers).
fn groth16_planned_bytes() -> Option<u64> {
    let dir = crate::groth16_component::dir()?;
    let setup = risc0_groth16_sys::SetupParams::new(&dir).ok()?;
    risc0_groth16_sys::metal_planned_bytes(&setup).ok()
}

/// Build every circuit's Metal pipeline states once per process: rv32im (with the zkp kernels),
/// recursion, keccak (through its binary archive, K5) and the Groth16 prover, each on its own thread
/// so the compiler service builds them in parallel. None of them takes the GPU lock for long, and
/// each is process-wide, so later proofs find them built. Returns (and logs) how long each took: tens
/// of seconds to minutes cold (first run of a newly built binary), well under a second warm.
/// Under a tight working-set limit the keccak build may be left to the first keccak proof
/// ([KECCAK_PREWARM_ENV], [keccak_prewarm_refusal]).
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
        let knob = std::env::var(KECCAK_PREWARM_ENV).ok();
        if let Some(v) = knob.as_deref() {
            let v = v.trim().to_ascii_lowercase();
            if !matches!(
                v.as_str(),
                "auto" | "" | "on" | "1" | "true" | "off" | "0" | "false"
            ) {
                tracing::warn!(
                    "{KECCAK_PREWARM_ENV}={v:?} is not auto, on or off: treated as auto"
                );
            }
        }
        let limit = risc0_groth16_sys::effective_working_set_limit();
        let groth16_plan = groth16_planned_bytes();
        // Read now (header reads, off any proof's path) for the per-release layout line.
        let _ = groth16_layout_plans();
        // Decide now when the answer cannot depend on what the other builds allocate.
        let early = match knob
            .as_deref()
            .map(|v| v.trim().to_ascii_lowercase())
            .as_deref()
        {
            Some("off" | "0" | "false") | Some("on" | "1" | "true") => {
                Some(keccak_prewarm_refusal(
                    knob.as_deref(),
                    limit,
                    0,
                    groth16_plan,
                    groth16_plan_fallback(),
                ))
            }
            _ => match limit {
                Some(l)
                    if l < groth16_plan
                        .unwrap_or_else(groth16_plan_fallback)
                        .saturating_add(KECCAK_PREWARM_TIGHT_MARGIN) =>
                {
                    None
                }
                _ => Some(None),
            },
        };
        let (rv32im, recursion, mut keccak, groth16) = std::thread::scope(|s| {
            let rv32im = s.spawn(timed(risc0_circuit_rv32im::prove::metal_warmup));
            let recursion = s.spawn(timed(risc0_circuit_recursion::prove::metal_warmup));
            let keccak = matches!(early, Some(None))
                .then(|| s.spawn(timed(risc0_circuit_keccak::prove::metal_warmup)));
            let groth16 = s.spawn(|| {
                let t = Instant::now();
                if let Err(e) = risc0_groth16_sys::metal_warmup() {
                    tracing::warn!("Groth16 Metal warmup failed: {e:#}");
                }
                t.elapsed()
            });
            let get = |h: std::thread::ScopedJoinHandle<'_, Duration>| h.join().unwrap_or_default();
            (
                get(rv32im),
                get(recursion),
                keccak.map(|h| Ok(get(h))),
                get(groth16),
            )
        });
        if keccak.is_none() {
            let refusal = match early {
                Some(r) => r,
                None => keccak_prewarm_refusal(
                    knob.as_deref(),
                    limit,
                    allocated_bytes(),
                    groth16_plan,
                    groth16_plan_fallback(),
                ),
            };
            keccak = Some(match refusal {
                None => Ok(timed(risc0_circuit_keccak::prove::metal_warmup)()),
                Some(why) => Err(why),
            });
        }
        let keccak_text = match keccak.expect("decided above") {
            Ok(t) => format!("keccak {:.1} s", t.as_secs_f64()),
            Err(why) => format!("keccak not built ({why})"),
        };
        let total = started.elapsed();
        let cold = total > Duration::from_secs(10);
        let summary = format!(
            "built the Metal pipelines in {:.1} s ({}): rv32im+zkp {:.1} s, recursion {:.1} s, \
             {keccak_text}, groth16 {:.1} s",
            total.as_secs_f64(),
            if cold { "cold" } else { "warm" },
            rv32im.as_secs_f64(),
            recursion.as_secs_f64(),
            groth16.as_secs_f64(),
        );
        tracing::info!("{summary}");
        summary
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The default table (W7-M11's W7: M8's rows plus po2 20 from 10 GiB where the footprint model
    /// fits this Mac's RAM), and M8's behind `ZKMINER_METAL_TIER_TABLE=m8`. These tests run without
    /// the table knobs; under one they check only that table's rows.
    #[test]
    fn po2_follows_the_working_set_limit() {
        use crate::metal_sizing::{env_po2_table, job_po2_in, Po2Table};
        let table = env_po2_table();
        if !matches!(table, Po2Table::M8 | Po2Table::W7) {
            return;
        }
        // The worker reads this Mac's RAM (or ZKMINER_METAL_HOST_RAM_BYTES); pin what it decides
        // against the pure rule with that RAM.
        let ram = crate::metal_sizing::host_ram_bytes();
        for limit in [
            4 * GIB,
            8 * GIB,
            10_700_000_000,
            10 * GIB,
            12 * GIB,
            28 * GIB,
        ] {
            assert_eq!(job_po2_for_limit(limit), job_po2_in(limit, table, ram));
        }
        let m8 = |l| job_po2_in(l, Po2Table::M8, None);
        assert_eq!(m8(4 * GIB), 18);
        assert_eq!(m8(8 * GIB), 19);
        // A 16 GB Mac: ~10.7 GB recommended, 8 GiB host figure (the smaller wins, 19); an 18 GB
        // Mac's 10 GiB host figure: 19 in M8, and in W7 too (po2 20's footprint does not fit its
        // RAM); R2 (opt-in) gives it 20. A 10 GiB budget on a 36 GB Mac: 20 in W7.
        assert_eq!(m8(10_700_000_000), 19);
        assert_eq!(m8(10 * GIB), 19);
        assert_eq!(job_po2_in(10 * GIB, Po2Table::W7, Some(18 * GIB)), 19);
        assert_eq!(job_po2_in(10 * GIB, Po2Table::R2, Some(18 * GIB)), 20);
        assert_eq!(job_po2_in(10 * GIB, Po2Table::W7, Some(36 * GIB)), 20);
        assert_eq!(job_po2_in(8 * GIB, Po2Table::W7, Some(16 * GIB)), 19);
        assert_eq!(m8(12 * GIB), 20);
        assert_eq!(m8(16 * GIB), 20);
        // The 36 GB dev machine: min(30.15 GB, 28 GiB).
        assert_eq!(m8(28 * GIB), 20);
        assert_eq!(m8(180 * GIB), 20);
        assert_eq!(job_po2_in(180 * GIB, Po2Table::W7, Some(192 * GIB)), 20);
    }

    #[test]
    fn the_po2_ceiling_follows_the_table() {
        use crate::metal_sizing::{env_po2_table, Po2Table};
        if !matches!(env_po2_table(), Po2Table::M8 | Po2Table::W7) {
            return;
        }
        // W7 keeps M8's ceiling.
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
        assert!(is_metal_oom(
            "Metal allocation failed on evaluated: 7 bytes"
        ));
        assert!(!is_metal_oom(
            "called `Result::unwrap()` on an `Err` value: PoisonError"
        ));
    }

    #[test]
    fn the_groth16_cache_is_kept_on_the_high_end_only() {
        assert!(!keep_groth16_cache(8 * GIB, 18));
        assert!(!keep_groth16_cache(16 * GIB, 19));
        // The 36 GB dev machine (28.1 GiB) releases it; a 48 GB Mac (~36 GiB) keeps it.
        assert!(!keep_groth16_cache(28 * GIB, 20));
        assert!(keep_groth16_cache(36 * GIB, 20));
    }

    /// P31-19: the keccak pipelines are left to the first keccak proof only when the Groth16
    /// prover would not fit beside them, or when the knob says so.
    #[test]
    fn the_keccak_prewarm_yields_to_the_groth16_prover_under_a_tight_limit() {
        const MIB: u64 = 1 << 20;
        // The default switches' fallback, named explicitly: the env's revert knobs must not matter.
        const FB: u64 = GROTH16_PLAN_FALLBACK;
        let g16 = 4039 * MIB;
        // The 4 GiB tier on risc0 3.1 before B9-4G: 46 MiB of other pipelines, 4039 MiB prover.
        assert!(keccak_prewarm_refusal(None, Some(4 * GIB), 46 * MIB, Some(g16), FB).is_some());
        assert!(
            keccak_prewarm_refusal(Some("auto"), Some(4 * GIB), 46 * MIB, Some(g16), FB).is_some()
        );
        // Since B9-4G: 3885 MiB (split_h + tw_lent) beside 46 MiB of pipelines leaves room: built.
        assert_eq!(
            keccak_prewarm_refusal(None, Some(4 * GIB), 46 * MIB, Some(3885 * MIB), FB),
            None
        );
        // Room enough: built.
        assert_eq!(
            keccak_prewarm_refusal(None, Some(8 * GIB), 46 * MIB, Some(g16), FB),
            None
        );
        assert_eq!(
            keccak_prewarm_refusal(None, Some(4 * GIB + 100 * MIB), 46 * MIB, Some(g16), FB),
            None
        );
        // Unknown limit: built (wave 7's behaviour).
        assert_eq!(
            keccak_prewarm_refusal(None, None, 46 * MIB, Some(g16), FB),
            None
        );
        // Unknown prover footprint (a host upgraded from 3.0, the v0.2.0 component not installed
        // yet when the decision is latched): assumed the smallest plan, as at a known 4 GiB plan
        // (built at 4 GiB); a limit that cannot hold it beside the pipelines defers keccak.
        assert_eq!(
            keccak_prewarm_refusal(None, Some(4 * GIB), 46 * MIB, None, FB),
            None
        );
        assert!(keccak_prewarm_refusal(None, Some(3900 * MIB), 46 * MIB, None, FB).is_some());
        assert_eq!(
            keccak_prewarm_refusal(None, Some(8 * GIB), 46 * MIB, None, FB),
            None
        );
        // The knob wins either way.
        assert_eq!(
            keccak_prewarm_refusal(Some("on"), Some(4 * GIB), 46 * MIB, Some(g16), FB),
            None
        );
        assert!(keccak_prewarm_refusal(Some("off"), Some(28 * GIB), 0, Some(g16), FB).is_some());
        assert!(keccak_prewarm_refusal(Some("0"), None, 0, None, FB).is_some());
    }

    /// B9-ZK: the release line names the layout from the freed size (B9-4G's v0.2.0 plans: whole
    /// 4141.0, split_h 4010.9, whole + tw_lent 4013.0, split_h + tw_lent 3885.0 MiB; real growth
    /// 2.7-2.9 MiB below each).
    #[test]
    fn a_released_prover_is_named_by_its_size() {
        const MIB: u64 = 1 << 20;
        let mb = |m: f64| (m * MIB as f64) as u64;
        let plans = [
            ("whole", mb(4141.0)),
            ("split_h", mb(4010.9)),
            ("whole + tw_lent", mb(4013.0)),
            ("split_h + tw_lent", mb(3885.0)),
        ];
        assert_eq!(
            groth16_layout_of(mb(4138.1), &plans).as_deref(),
            Some("whole")
        );
        assert_eq!(
            groth16_layout_of(mb(3882.2), &plans).as_deref(),
            Some("split_h + tw_lent")
        );
        // split_h and whole + tw_lent are 2.1 MiB apart: both named.
        let mid = groth16_layout_of(mb(4008.0), &plans).unwrap();
        assert!(
            mid.contains("split_h") && mid.contains("whole + tw_lent"),
            "{mid}"
        );
        // Nothing near any layout: not named.
        assert_eq!(groth16_layout_of(mb(3000.0), &plans), None);
        assert_eq!(groth16_layout_of(mb(4141.0), &[]), None);
        // Review finding (4300 MiB budget): under the default auto switches whole + tw_lent is not
        // reachable, so the 4008 MiB release of a split_h prover is named split_h alone.
        use risc0_groth16_sys::metal::prover::{SplitH, TwLent};
        let reachable: Vec<_> = GROTH16_LAYOUTS
            .iter()
            .zip(plans)
            .filter(|((_, s, l), _)| groth16_layout_reachable(SplitH::Auto, TwLent::Auto, *s, *l))
            .map(|(_, p)| p)
            .collect();
        assert_eq!(
            reachable.iter().map(|p| p.0).collect::<Vec<_>>(),
            ["whole", "split_h", "split_h + tw_lent"]
        );
        assert_eq!(
            groth16_layout_of(mb(4008.0), &reachable).as_deref(),
            Some("split_h")
        );
    }

    #[test]
    fn a_forced_layout_switch_admits_only_its_side() {
        use risc0_groth16_sys::metal::prover::{SplitH, TwLent};
        let names = |s: SplitH, t: TwLent| -> Vec<&str> {
            GROTH16_LAYOUTS
                .iter()
                .filter(|&&(_, sp, l)| groth16_layout_reachable(s, t, sp, l))
                .map(|l| l.0)
                .collect()
        };
        assert_eq!(names(SplitH::Off, TwLent::Off), ["whole"]);
        assert_eq!(
            names(SplitH::On, TwLent::Auto),
            ["split_h", "split_h + tw_lent"]
        );
        assert_eq!(
            names(SplitH::Off, TwLent::Auto),
            ["whole", "whole + tw_lent"]
        );
        assert_eq!(
            names(SplitH::Auto, TwLent::On),
            ["whole + tw_lent", "split_h + tw_lent"]
        );
        assert_eq!(names(SplitH::Auto, TwLent::Off), ["whole", "split_h"]);
    }

    /// Review finding: the fallback plan (no component yet) is the smallest auto plan; with a
    /// forced switch the real plan can be larger, so the fallback is the largest one, and a 4 GiB
    /// host then defers keccak instead of building it beside a prover that may not fit.
    #[test]
    fn the_keccak_fallback_plan_follows_the_layout_switches() {
        use risc0_groth16_sys::metal::prover::{SplitH, TwLent};
        assert_eq!(
            groth16_plan_fallback_for(SplitH::Auto, TwLent::Auto),
            GROTH16_PLAN_FALLBACK
        );
        for (s, t) in [
            (SplitH::On, TwLent::Auto),
            (SplitH::Auto, TwLent::Off),
            (SplitH::Off, TwLent::Off),
        ] {
            assert_eq!(
                groth16_plan_fallback_for(s, t),
                GROTH16_PLAN_FALLBACK_FORCED
            );
        }
        const GIB: u64 = 1 << 30;
        const MIB: u64 = 1 << 20;
        let forced = GROTH16_PLAN_FALLBACK_FORCED;
        assert!(keccak_prewarm_refusal(None, Some(4 * GIB), 62 * MIB, Some(forced), 0).is_some());
        assert!(keccak_prewarm_refusal(
            None,
            Some(4 * GIB),
            62 * MIB,
            Some(GROTH16_PLAN_FALLBACK),
            0
        )
        .is_none());
        // Unknown plan: the fallback passed in decides (the default one builds keccak at 4 GiB,
        // the forced one defers it).
        assert!(keccak_prewarm_refusal(None, Some(4 * GIB), 46 * MIB, None, forced).is_some());
        assert!(
            keccak_prewarm_refusal(None, Some(4 * GIB), 46 * MIB, None, GROTH16_PLAN_FALLBACK)
                .is_none()
        );
    }

    /// Round-2 review finding: the env-reading path, checked against the environment the suite
    /// runs in (so it passes with or without a layout revert knob set). With none of the knobs set
    /// it must be the default fallback; with any, one of the two.
    #[test]
    fn the_process_fallback_plan_reads_the_layout_knobs() {
        const GIB: u64 = 1 << 30;
        const MIB: u64 = 1 << 20;
        let fb = groth16_plan_fallback();
        let knobs = [
            "RISC0_G16_METAL_G10",
            "RISC0_G16_METAL_G10_OFF",
            "RISC0_G16_METAL_SPLIT_H",
            "RISC0_G16_METAL_TW_LENT",
        ];
        if knobs.iter().all(|k| std::env::var_os(k).is_none()) {
            assert_eq!(fb, GROTH16_PLAN_FALLBACK);
        } else {
            assert!(fb == GROTH16_PLAN_FALLBACK || fb == GROTH16_PLAN_FALLBACK_FORCED);
        }
        assert_eq!(
            keccak_prewarm_refusal(None, Some(4 * GIB), 46 * MIB, None, fb).is_some(),
            fb == GROTH16_PLAN_FALLBACK_FORCED
        );
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
