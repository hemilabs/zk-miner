//! Apple GPU (Metal) sizing shared by the host and the risc0 Metal worker: the one table that says
//! which segment size (po2) a Mac proves at for a given GPU working-set limit, and how much GPU
//! memory that size needs.
//!
//! **Single source of truth.** The host (`benchmark::risc0_slot_job_po2`, the benchmark device row,
//! the Metal benchmark timeout) and the worker (`zkminer-prove-risc0`'s default segment size and po2
//! ceiling) both read this file. The worker does not depend on `zkminer-prover`, so it compiles this
//! file into itself with `#[path]`; that is why it uses `std` only and must stay that way. Before
//! this (M6), the host gave po2 20 to any Metal figure of at least 14 GiB while the worker's own table
//! said 19 for a 24 GB Mac, and gave a 16 GB Mac no job size at all.
//!
//! The numbers are the M1 measurements (worker benchmark, memory-merkle, M5 Max, merged fork;
//! zk-miner `docs/metal-port-notes/M1.md`).

/// One GiB.
pub const GIB: u64 = 1 << 30;

/// The fork's artificial working-set budget (PLAN 9.1, Z6). Both processes read it: the worker gets
/// the miner's environment, so the host sizing a Mac must honour the same figure.
pub const MAX_WORKING_SET_ENV: &str = "RISC0_METAL_MAX_WORKING_SET_BYTES";

/// The footprint ceiling a macOS worker enforces on itself, in bytes (set by the dispatcher at spawn;
/// an operator's own value wins; `0` disables). macOS has no cgroups, so the systemd `MemoryMax` cap
/// the dispatcher puts on a Linux worker does not exist there; without it one runaway proof thrashes
/// the Mac into swap instead of failing (M1: 18 GB of swap for 40 minutes at po2 22). The worker
/// polls its `phys_footprint` (which on a Mac includes its GPU allocations) and exits when it passes
/// this, the same outcome as a cgroup OOM kill: a bounded slot failure, then a respawn.
pub const WORKER_MAX_FOOTPRINT_ENV: &str = "ZKMINER_WORKER_MAX_FOOTPRINT_BYTES";

/// Exit status of a worker that ended itself at [`WORKER_MAX_FOOTPRINT_ENV`].
pub const FOOTPRINT_EXIT_CODE: i32 = 137;

/// The largest default segment size, equal to the protocol's `RISC0_DEFAULT_JOB_PO2` (a test on each
/// side pins that; this file cannot import it).
pub const DEFAULT_JOB_PO2_CAP: u8 = 20;

/// Revert knob for M8's tier table: `m1` restores the M1/M6 table (one po2 lower below 20 GiB) and
/// its po2 ceiling. It wins over [`TIER_TABLE_ENV`]. Host and worker both read it (the worker
/// inherits the miner's environment), so setting it on the miner moves both.
pub const PO2_TABLE_ENV: &str = "ZKMINER_METAL_PO2_TABLE";

/// W7-M11's tier knob: `m8` restores M8's table (today's before W7-M11), `r2` selects the small-Mac
/// rows that need risc0 W7-R2 (po2 19 from 4 GiB, po2 20 from 8 GiB); unset or anything else is
/// [`DEFAULT_TABLE`]. Same host/worker reach as [`PO2_TABLE_ENV`].
pub const TIER_TABLE_ENV: &str = "ZKMINER_METAL_TIER_TABLE";

/// Which segment-size table a Mac is sized with ([`PO2_TABLE_ENV`], [`TIER_TABLE_ENV`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Po2Table {
    /// M1's table (M6 made it the shared one): sized by the unconstrained recursion-phase peak.
    M1,
    /// M8's table: sized by what proves under an enforced working-set budget (risc0 Z12).
    M8,
    /// W7-M11: M8's GPU rows plus po2 20 from 10 GiB, each row above M8's admitted only where the
    /// footprint model fits the Mac's RAM ([`footprint_po2_cap`]). With today's risc0 that keeps an
    /// 18 GB Mac at 19 (po2 20's full-suite footprint is 16.2 GiB), so on every real Mac it decides
    /// as M8 does; only a budget run on a Mac with >= 20.75 GiB of RAM moves (10-12 GiB: 20).
    W7,
    /// W7-M11 with risc0 W7-R2's small-Mac rows: po2 19 from 4 GiB and po2 20 from 8 GiB, under the
    /// same footprint rule with that risc0's footprints. Needs a risc0 with W7-A1, W7-R2 and W7-G1
    /// (without W7-R2 these sizes are refused in the accum commit under an enforced budget; the
    /// footprints assume W7-G1's graph release, [`spawn_without_malloc_large_cache`]), so it is
    /// opt-in until those are merged. Per Mac: 16 GB 19 (8 GiB) / 19 (4 GiB active), 18 GB 20 / 19.
    R2,
}

/// The table used when neither knob says otherwise.
pub const DEFAULT_TABLE: Po2Table = Po2Table::W7;

/// [`PO2_TABLE_ENV`] / [`TIER_TABLE_ENV`] from this process's environment.
pub fn env_po2_table() -> Po2Table {
    let var = |k: &str| std::env::var(k).ok().map(|v| v.trim().to_ascii_lowercase());
    po2_table_from(
        var(PO2_TABLE_ENV).as_deref(),
        var(TIER_TABLE_ENV).as_deref(),
    )
}

/// [`env_po2_table`] as a pure function of the two variables (lower-cased, trimmed).
pub fn po2_table_from(po2_table: Option<&str>, tier_table: Option<&str>) -> Po2Table {
    if po2_table == Some("m1") {
        return Po2Table::M1;
    }
    match tier_table {
        Some("m8") => Po2Table::M8,
        Some("m1") => Po2Table::M1,
        Some("r2") => Po2Table::R2,
        Some("w7") => Po2Table::W7,
        _ => DEFAULT_TABLE,
    }
}

/// The working-set limit from which [`Po2Table::M8`] gives a Mac po2 20 by default.
///
/// po2 20 proves, wraps and verifies under a 10 GiB enforced budget (segments 9420 MiB, process
/// footprint 13.4 GB; M8 note), which is therefore its ceiling ([`PO2_20_MIN_LIMIT`]). The default is
/// one step more cautious because an 18 GB Mac (10 GiB host figure) enforces no budget: its proof's
/// process footprint (13.4-13.7 GB at po2 20 against 8.4 GB at 19 with the worker's segment-prover
/// release) would be ~70% of its RAM. From
/// 12 GiB up (a 24 GB Mac, 16 GiB) po2 20 is the default. [`Po2Table::W7`] replaces this caution by
/// the footprint model ([`footprint_po2_cap`]).
pub const PO2_20_DEFAULT_LIMIT: u64 = 12 * GIB;

/// The smallest working-set limit po2 20 may start under ([`min_limit_for_po2`]): measured to prove.
pub const PO2_20_MIN_LIMIT: u64 = 10 * GIB;

/// [`Po2Table::R2`]: po2 20 proves under an 8 GiB budget and po2 19 under 4 GiB with risc0 W7-R2
/// (96.5 % of the budget live at the FRI mix; W7-R2 asks that these stay the tiers' own budgets,
/// never lower).
pub const R2_PO2_20_MIN_LIMIT: u64 = 8 * GIB;
/// See [`R2_PO2_20_MIN_LIMIT`].
pub const R2_PO2_19_MIN_LIMIT: u64 = 4 * GIB;

// ---- W7-M11: the footprint model ----

/// RAM a Mac keeps for macOS and the owner's apps beside a proof: a tier above M8's is used only
/// when the proof's peak process footprint ([`footprint_bytes`]) leaves this much of `hw.memsize`
/// free (18 GB Mac: po2 20 only with a footprint of at most 13.5 GiB). A fixed amount, not a RAM
/// fraction (PLAN 9.1): what macOS and a browser need does not grow with the Mac.
pub const FOOTPRINT_RESERVE_BYTES: u64 = 4608 << 20;

/// Simulation and test override of the RAM the footprint model sees (bytes, the
/// [`MAX_WORKING_SET_ENV`] grammar); unset, `hw.memsize`.
pub const HOST_RAM_ENV: &str = "ZKMINER_METAL_HOST_RAM_BYTES";

/// The peak process footprint (`phys_footprint`, which on a Mac includes the GPU allocations) of the
/// worker proving the full six-program benchmark suite at segment `po2`, the worst over the budgets
/// that size is tiered at, rounded up to a quarter GiB (W7-M11 note, "Footprint model"; M5 Max,
/// `/usr/bin/time -l`, every program wrapped and verified):
///
/// | po2 | [`Po2Table::W7`] (risc0 `zkminer/metal` b5fa9a97a) | [`Po2Table::R2`] (+ W7-A1, W7-R2, W7-G1, `MallocLargeCache=0`) |
/// |---|---|---|
/// | <= 18 | 7.5 GiB (M8: 7.31 GiB at 4 GiB) | 6 GiB (5.94 GiB at 4 GiB) |
/// | 19 | 10.5 GiB (10.45 GiB at 10 GiB) | 7 GiB (6.20 at 4 GiB, 6.82 at a 16 GB Mac's 10.67 GiB HAL / 8 GiB plan) |
/// | 20 | 16.25 GiB (16.18 GiB at 10 GiB) | 12 GiB (10.63 at 8, 11.07 at 10.67 / 8, 11.86 at 10, 11.04 at 12 / 10) |
///
/// At po2 20 the big programs' segment phase is the peak: 9.3-9.5 GB of Metal allocations plus
/// 2-7 GB of host state. Above 20 nothing is tiered here (only Macs whose RAM is far above these
/// reach those sizes), so the model doubles per step. M1 and M8 do not use it.
pub fn footprint_bytes(po2: u8, table: Po2Table) -> u64 {
    const Q: u64 = GIB / 4;
    let (le18, p19, p20) = match table {
        Po2Table::R2 => (24 * Q, 28 * Q, 48 * Q),
        _ => (30 * Q, 42 * Q, 65 * Q),
    };
    match po2 {
        0..=18 => le18,
        19 => p19,
        20 => p20,
        p => p20 << (p - 20).min(4),
    }
}

/// The largest segment po2 whose [`footprint_bytes`] leaves [`FOOTPRINT_RESERVE_BYTES`] of `ram`.
/// `None` when not even po2 16 does.
pub fn footprint_po2_cap(ram: u64, table: Po2Table) -> Option<u8> {
    (16..=24u8)
        .rev()
        .find(|&p| footprint_bytes(p, table).saturating_add(FOOTPRINT_RESERVE_BYTES) <= ram)
}

/// W7-G1 releases the Groth16 witness graph (~1.2-1.8 GiB of footprint) only in a worker spawned with
/// `MallocLargeCache=0` (libmalloc reads it at process start) and a working-set limit below 20 GiB;
/// [`Po2Table::R2`]'s footprint model assumes it. Whether the dispatcher spawns a Metal worker with
/// it: with that table, below 20 GiB, unless the operator set `MallocLargeCache` (`operator_set`).
pub fn spawn_without_malloc_large_cache(limit: u64, table: Po2Table, operator_set: bool) -> bool {
    table == Po2Table::R2 && limit < 20 * GIB && !operator_set
}

/// The libmalloc variable [`spawn_without_malloc_large_cache`] sets to `0`.
pub const MALLOC_LARGE_CACHE_ENV: &str = "MallocLargeCache";

/// The RAM the footprint model sizes against: [`HOST_RAM_ENV`], else `hw.memsize` (macOS), else
/// `None` (no row above M8's is then used).
pub fn host_ram_bytes() -> Option<u64> {
    if let Some(v) = std::env::var(HOST_RAM_ENV)
        .ok()
        .and_then(|v| parse_bytes(&v))
    {
        return Some(v);
    }
    hw_memsize()
}

#[cfg(target_os = "macos")]
fn hw_memsize() -> Option<u64> {
    use std::ffi::{c_char, c_int, c_void};
    extern "C" {
        // libSystem; std links it on every Apple target. Declared here so this file stays std-only.
        fn sysctlbyname(
            name: *const c_char,
            oldp: *mut c_void,
            oldlenp: *mut usize,
            newp: *mut c_void,
            newlen: usize,
        ) -> c_int;
    }
    let mut v: u64 = 0;
    let mut len = std::mem::size_of::<u64>();
    // SAFETY: a NUL-terminated name, an 8-byte out buffer and its length; nothing is written.
    let rc = unsafe {
        sysctlbyname(
            c"hw.memsize".as_ptr(),
            (&mut v as *mut u64).cast(),
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    (rc == 0 && len == 8 && v > 0).then_some(v)
}

#[cfg(not(target_os = "macos"))]
fn hw_memsize() -> Option<u64> {
    None
}

/// The default segment size for a GPU working-set limit (PLAN 9.1), with the table
/// [`PO2_TABLE_ENV`] / [`TIER_TABLE_ENV`] select and this Mac's RAM ([`host_ram_bytes`]).
pub fn job_po2_for_limit(limit: u64) -> u8 {
    job_po2_for_limit_in(limit, env_po2_table())
}

/// The GPU rule of each table: the largest size that proves under `limit`, before the footprint
/// model.
///
/// [`Po2Table::M8`]. Measured with the worker's `--benchmark` (memory-merkle, M5 Max, risc0
/// fork with Z12) under `RISC0_METAL_MAX_WORKING_SET_BYTES`; Metal peak MiB segments / recursion /
/// wrap, all proofs wrapped and verified (zk-miner `docs/metal-port-notes/M8.md`, risc0 `Z12.md`):
///
/// | limit                  | po2 | peaks (MiB)          | next po2 up                       | typical Mac          |
/// |------------------------|-----|----------------------|-----------------------------------|----------------------|
/// | < 6 GiB                | 18  | 2492 / 3337 / 3942   | 19 refused in segments at 4 GiB   | 16 GB, ~4 GB cap     |
/// | 6 GiB to < 12 GiB      | 19  | 4784 / 4788 / 5347   | 20 refused in segments at 8 GiB   | 16 / 18 GB           |
/// | >= 12 GiB              | 20  | 9420 / 7740 / 7740   | -                                 | 24 GB and up         |
///
/// (po2 18 at 4 GiB: 2492 / 3337 / 3942; po2 20 also proves at 10 GiB, see [`PO2_20_DEFAULT_LIMIT`].)
///
/// Under an enforced budget the fork drains its pools before refusing an allocation, and Z12 drops
/// the cached segment prover before recursion when both would not fit, so the stacked
/// recursion-phase peak ([`stark_peak_bytes`]) is not what decides the size; the segment phase is.
///
/// [`Po2Table::M1`]: < 6 GiB 17, < 12 GiB 18, < 20 GiB 19, else 20 (M1 note: sized by the
/// unconstrained recursion-phase peak, 3971 / 4390 / 6668 / 11169 MiB at 17 / 18 / 19 / 20).
///
/// [`Po2Table::W7`]: < 6 GiB 18, < 10 GiB 19, else 20. [`Po2Table::R2`]: < 8 GiB 19, else 20.
pub fn gpu_po2_for_limit_in(limit: u64, table: Po2Table) -> u8 {
    let po2 = match table {
        Po2Table::M1 => {
            if limit < 6 * GIB {
                17
            } else if limit < 12 * GIB {
                18
            } else if limit < 20 * GIB {
                19
            } else {
                20
            }
        }
        Po2Table::M8 => {
            if limit < 6 * GIB {
                18
            } else if limit < PO2_20_DEFAULT_LIMIT {
                19
            } else {
                20
            }
        }
        Po2Table::W7 => {
            if limit < 6 * GIB {
                18
            } else if limit < PO2_20_MIN_LIMIT {
                19
            } else {
                20
            }
        }
        Po2Table::R2 => {
            if limit < R2_PO2_20_MIN_LIMIT {
                19
            } else {
                20
            }
        }
    };
    po2.min(DEFAULT_JOB_PO2_CAP)
}

/// The default segment size for a GPU working-set limit and table, on this Mac
/// ([`host_ram_bytes`]): [`job_po2_in`].
pub fn job_po2_for_limit_in(limit: u64, table: Po2Table) -> u8 {
    job_po2_in(limit, table, host_ram_bytes())
}

/// The default segment size for a GPU working-set limit, a table and the Mac's RAM.
///
/// M1 and M8: their GPU rule ([`gpu_po2_for_limit_in`]). W7 and R2: `min(GPU rule, footprint
/// model)`, where the footprint model only ever removes a row above M8's (M8's rows are shipped and
/// measured on every Mac size): a size above M8's is kept only when its [`footprint_bytes`] leaves
/// [`FOOTPRINT_RESERVE_BYTES`] of `ram`; an unknown `ram` keeps M8's. Never above
/// [`DEFAULT_JOB_PO2_CAP`].
pub fn job_po2_in(limit: u64, table: Po2Table, ram: Option<u64>) -> u8 {
    let gpu = gpu_po2_for_limit_in(limit, table);
    match table {
        Po2Table::M1 | Po2Table::M8 => gpu,
        Po2Table::W7 | Po2Table::R2 => {
            let m8 = gpu_po2_for_limit_in(limit, Po2Table::M8);
            if gpu <= m8 {
                return gpu;
            }
            let cap = ram.and_then(|r| footprint_po2_cap(r, table)).unwrap_or(0);
            gpu.min(cap.max(m8))
        }
    }
}

/// Peak GPU memory of the largest STARK phase at `po2` with no budget enforced (the recursion phase,
/// beside the segment prover's cached pool): 3971 / 4390 / 6668 / 11169-11938 MiB measured at po2 17 /
/// 18 / 19 / 20, rounded up; doubling per step above 20. This is the real footprint on a Mac whose
/// limit is not enforced, used for the Groth16 keep decision and the device row's memory figure; it
/// is not what sizes the job (see [`job_po2_for_limit_in`]).
pub fn stark_peak_bytes(po2: u8) -> u64 {
    match po2 {
        0..=17 => 4 * GIB,
        18 => 5 * GIB,
        19 => 7 * GIB,
        20 => 12 * GIB,
        p => (12 * GIB) << (p - 20).min(4),
    }
}

/// The smallest working-set limit a proof at segment `po2` is allowed to start under (the hard
/// ceiling, [`max_po2_for_limit_in`]).
///
/// [`Po2Table::M8`]: the bottom of the table row that proves it (4 GiB for 18 and below, where the
/// Groth16 wrap's 3926 MiB is the largest phase; 6 GiB for 19; [`PO2_20_MIN_LIMIT`] for 20), and above
/// 20, where nothing was measured under a budget, [`stark_peak_bytes`] as before.
/// [`Po2Table::M1`]: [`stark_peak_bytes`].
/// [`Po2Table::W7`]: M8's. [`Po2Table::R2`]: 4 GiB up to 19 ([`R2_PO2_19_MIN_LIMIT`]),
/// [`R2_PO2_20_MIN_LIMIT`] for 20, then [`stark_peak_bytes`].
pub fn min_limit_for_po2(po2: u8, table: Po2Table) -> u64 {
    match (table, po2) {
        (Po2Table::M1, p) => stark_peak_bytes(p),
        (Po2Table::M8 | Po2Table::W7, 0..=18) => 4 * GIB,
        (Po2Table::M8 | Po2Table::W7, 19) => 6 * GIB,
        (Po2Table::M8 | Po2Table::W7, 20) => PO2_20_MIN_LIMIT,
        (Po2Table::R2, 0..=19) => R2_PO2_19_MIN_LIMIT,
        (Po2Table::R2, 20) => R2_PO2_20_MIN_LIMIT,
        (_, p) => stark_peak_bytes(p),
    }
}

/// The largest segment po2 allowed to start under `limit`, or `None` when none is: the worker's hard
/// ceiling (`zkminer-prove-risc0` `metal_host::po2_refusal`), never below [`job_po2_for_limit_in`] for
/// a limit of at least 4 GiB.
pub fn max_po2_for_limit_in(limit: u64, table: Po2Table) -> Option<u8> {
    (13..=24u8)
        .rev()
        .find(|&p| min_limit_for_po2(p, table) <= limit)
}

/// [`max_po2_for_limit_in`] with the table [`PO2_TABLE_ENV`] selects.
pub fn max_po2_for_limit(limit: u64) -> Option<u8> {
    max_po2_for_limit_in(limit, env_po2_table())
}

/// A byte count with an optional binary suffix (`4294967296`, `4G`, `4GiB`, `512M`), the fork's
/// grammar for [`MAX_WORKING_SET_ENV`] (`risc0-zkp` `hal/metal/runtime.rs::parse_bytes`). `None` if
/// malformed or zero.
pub fn parse_bytes(text: &str) -> Option<u64> {
    let t = text.trim();
    let t = t
        .strip_suffix("iB")
        .or_else(|| t.strip_suffix("ib"))
        .or_else(|| t.strip_suffix('B'))
        .or_else(|| t.strip_suffix('b'))
        .unwrap_or(t);
    let (digits, shift) = match t.chars().last()? {
        'k' | 'K' => (&t[..t.len() - 1], 10),
        'm' | 'M' => (&t[..t.len() - 1], 20),
        'g' | 'G' => (&t[..t.len() - 1], 30),
        't' | 'T' => (&t[..t.len() - 1], 40),
        _ => (t, 0),
    };
    let n: u64 = digits.trim().parse().ok()?;
    n.checked_mul(1u64 << shift).filter(|&b| b > 0)
}

/// [`MAX_WORKING_SET_ENV`] from this process's environment, if set and valid.
pub fn env_working_set_budget() -> Option<u64> {
    parse_bytes(&std::env::var(MAX_WORKING_SET_ENV).ok()?)
}

/// The working-set limit the host can see for a Mac: the smaller of its own figure for the GPU
/// (`hw.memsize` less the 8 GiB host reserve, which it also hands the worker) and
/// [`MAX_WORKING_SET_ENV`]. The worker additionally takes `recommendedMaxWorkingSetSize`, which only
/// the Metal API can read; on every Mac size that is at least the host figure below 32 GiB (about 75%
/// of RAM against RAM less 8 GiB) and at least 20 GiB above it, so the table row comes out the same.
pub fn host_working_set_limit(host_figure: Option<u64>) -> Option<u64> {
    working_set_limit_of(host_figure, env_working_set_budget())
}

/// [`host_working_set_limit`] with the budget passed in, for tests that must not depend on the
/// environment (the budget runs set [`MAX_WORKING_SET_ENV`] for the whole process).
pub fn working_set_limit_of(host_figure: Option<u64>, budget: Option<u64>) -> Option<u64> {
    [host_figure, budget].into_iter().flatten().min()
}

// ---- W7-M10: budget enforcement and the owner-active tier ----

/// Host RAM withheld from an Apple GPU's "VRAM" figure: the dispatcher's `METAL_HOST_RESERVE_BYTES`
/// (that constant is this one; see its comment for why 8 GiB). The idle plan is `hw.memsize` less it.
pub const HOST_RESERVE_BYTES: u64 = 8 * GIB;

/// Budget enforcement (W7-M10), OFF by default: `1` lets the worker export its planned limit as
/// [`MAX_WORKING_SET_ENV`] at start ([`enforced_budget`]); unset or `0` leaves the HAL's limit at
/// `recommendedMaxWorkingSetSize`, as before.
///
/// Off because it measured slower and LARGER on a simulated 16 GB Mac (worker `--benchmark`, the
/// HAL limited to that Mac's 10.67 GiB as the unenforced reference, W7-M10 note): enforcing the
/// 8 GiB idle tier cost +0.55 s STARK (+5 %) and +0.47 GB of peak footprint on memory-merkle, +1.86 s
/// and +1.17 GB on bigint-mul, and enforcing the 4 GiB owner-active tier +0.64 s and +0.42 GB. The
/// fork's pool cap is half the limit, so a smaller limit frees and re-allocates the segment pools'
/// buffers every segment, and freed Metal pages stay in the footprint for seconds (M9 open issue 2).
/// The tier's po2 is what makes it smaller, not the budget.
pub const ENFORCE_BUDGET_ENV: &str = "ZKMINER_METAL_ENFORCE_BUDGET";

/// The budget the worker exports as [`MAX_WORKING_SET_ENV`] at start, or `None` to leave the HAL as
/// it is.
///
/// - `plan`: the limit the worker plans with (the smallest of `recommendedMaxWorkingSetSize`, an
///   explicit [`MAX_WORKING_SET_ENV`] and the host's figure).
/// - `hal_limit`: what the HAL would use without this: `recommendedMaxWorkingSetSize`, or the
///   explicit budget when that is smaller.
///
/// Enforced only when the plan is at least a whole GiB under the HAL's limit. The table rows, every
/// measured budget (4 / 8 / 10 / 12 / 16 GiB) and every risc0 threshold sit on whole GiB, so a
/// smaller gap changes no decision: it is only the host reserve's rounding against macOS's own. On
/// the 36 GB dev Mac the plan is 28.00 GiB against a device limit of 28.08 GiB (30150672384 B), so
/// nothing is exported there and the worker runs exactly as before. On a 16 GB Mac the plan is
/// 8 GiB against ~10.7 GiB: the 8 GiB tier the M8 table was measured under, instead of an unenforced
/// 10.7 GiB limit with a 5.35 GiB pool cap.
pub fn enforced_budget(plan: u64, hal_limit: u64, knob_off: bool) -> Option<u64> {
    (!knob_off && plan.saturating_add(GIB) <= hal_limit).then_some(plan)
}

/// [`ENFORCE_BUDGET_ENV`] from this process's environment: `true` unless enforcement is switched
/// on (`1`).
pub fn enforce_budget_off() -> bool {
    !std::env::var(ENFORCE_BUDGET_ENV).is_ok_and(|v| v.trim() == "1")
}

/// The Groth16 prover's resident footprint on the GPU while its proving key is cached
/// (`risc0-groth16-sys` Metal prover, note G7: 5628.7 MiB measured, 5655.5 MiB planned).
pub const GROTH16_RESIDENT_BYTES: u64 = 5_930_236_936;

/// Headroom kept free beside the largest GPU phase when deciding whether to keep the Groth16 cache.
/// Large because on unified memory the proof's host-side state (preflight traces, recursion
/// witnesses) comes out of the same RAM: the full po2 20 benchmark on the 36 GB dev machine peaked
/// at 17.6 GB of GPU allocations (5.7 GB of it the kept key) but at a 31 GB process footprint, so
/// ~13 GB of host-side state.
pub const KEEP_HEADROOM_BYTES: u64 = 12 * GIB;

/// Whether the worker keeps the Groth16 proving key cached on the GPU between proofs under `limit`
/// at segment po2 `po2`: only when it fits beside the next proof's largest STARK phase with
/// headroom. On unified memory a kept key is 5.6 GB of the owner's RAM held while idle, so this is
/// the high-end tier only. Shared with the worker (`metal_host::keep_groth16_cache`) so the host can
/// tell when a tier changes it ([`same_for_job_in`]).
pub fn keep_groth16_cache(limit: u64, po2: u8) -> bool {
    limit >= stark_peak_bytes(po2) + GROTH16_RESIDENT_BYTES + KEEP_HEADROOM_BYTES
}

/// Whether a worker started with the working-set figure `a` proves a job of segment po2 `po2`
/// (`None`: the worker's default, a benchmark) exactly as a worker started with `b` would, so
/// respawning a live worker from one figure to the other buys nothing and costs a cold worker
/// (W7-M10, review finding: a respawn on a 36 GB Mac's switch to its 20 GiB active tier changed
/// nothing). A worker reads its figure for four things only:
/// - the budget it enforces (`enforced`: `ZKMINER_METAL_ENFORCE_BUDGET=1`): any other figure
///   differs;
/// - its hard po2 ceiling ([`max_po2_for_limit_in`]): whether it admits `po2`;
/// - its Groth16 key decision ([`keep_groth16_cache`]) at that po2;
/// - its default segment po2 ([`job_po2_for_limit_in`]): the size a benchmark proves at, and the
///   size its first-job prewarm (M9) warms. A job names its po2, so for a job only the first three
///   count: a warm worker whose prewarm was at another size is still faster than a cold one.
pub fn same_for_job_in(a: u64, b: u64, po2: Option<u8>, enforced: bool, table: Po2Table) -> bool {
    if a == b {
        return true;
    }
    if enforced {
        return false;
    }
    let (pa, pb) = match po2 {
        Some(p) => (p, p),
        None => (
            job_po2_for_limit_in(a, table),
            job_po2_for_limit_in(b, table),
        ),
    };
    let admits = |l: u64, p: u8| max_po2_for_limit_in(l, table).is_some_and(|c| p <= c);
    pa == pb
        && admits(a, pa) == admits(b, pb)
        && keep_groth16_cache(a, pa) == keep_groth16_cache(b, pb)
}

/// [`same_for_job_in`] for two host figures, each as the worker will see it (capped by an explicit
/// [`MAX_WORKING_SET_ENV`]), with this process's table; `enforced`: whether the worker enforces its
/// figure (`!enforce_budget_off()` in the miner).
pub fn same_for_job(a: u64, b: u64, po2: Option<u8>, enforced: bool) -> bool {
    let seen = |f: u64| host_working_set_limit(Some(f)).unwrap_or(f);
    same_for_job_in(seen(a), seen(b), po2, enforced, env_po2_table())
}

/// Whether a worker started with figure `limit` admits a job of segment po2 `po2` (its hard ceiling,
/// [`max_po2_for_limit`], of the figure as the worker sees it).
pub fn admits_po2(limit: u64, po2: u8) -> bool {
    max_po2_for_limit(host_working_set_limit(Some(limit)).unwrap_or(limit))
        .is_some_and(|c| po2 <= c)
}

/// The figure a slot reports on the claim side for `tier` (`WorkerPool::risc0_slots`): the tier's
/// own when it measures claims at another segment po2 than the idle figure does, else the idle
/// figure, so a tier that changes no claim size (a 36 GB Mac: po2 20 at 28 and at 20 GiB) never
/// moves anything.
pub fn claim_limit(idle_limit: u64, tier: OwnerTier) -> u64 {
    let t = tier_limit(idle_limit, tier);
    let po2 = |f: u64| job_po2_for_limit(host_working_set_limit(Some(f)).unwrap_or(f));
    if po2(t) == po2(idle_limit) {
        idle_limit
    } else {
        t
    }
}

/// `ZKMINER_OWNER_ACTIVE`: unset or `0` (default) keeps the idle tier; `auto` reads the owner's
/// activity; `1` forces the owner-active tier (tests and simulations).
///
/// Off by default (W7-M10 review): `auto` lowers a slot's claim-side figure while the owner is
/// active, and a job measured at the idle po2 that is still queued when another job's start
/// switches the tier is then proved at the active po2, a size it was never measured at, and
/// planned at the idle rate (+37 % STARK at the active po2 on a 16 GB Mac). Closing that needs the
/// prove step to size from the idle figure and the claim step from the tier's (run.rs), so `auto`
/// stays opt-in until then.
pub const OWNER_ACTIVE_ENV: &str = "ZKMINER_OWNER_ACTIVE";

/// `ZKMINER_OWNER_IDLE_SECS`: seconds without keyboard or mouse input after which the owner counts as
/// idle again (default [`DEFAULT_OWNER_IDLE_SECS`]). Leaving the active tier takes twice this
/// ([`OwnerTierState::update`]).
pub const OWNER_IDLE_SECS_ENV: &str = "ZKMINER_OWNER_IDLE_SECS";

/// Five minutes: macOS's own default screen-saver delay, so a Mac the owner walked away from counts
/// as idle about when its screen would blank.
pub const DEFAULT_OWNER_IDLE_SECS: u64 = 300;

/// Which budget tier a Metal job runs at (PLAN 9.1: "GPU budget, owner active / idle").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnerTier {
    /// The planned limit (`hw.memsize` less [`HOST_RESERVE_BYTES`]): the full tier.
    Idle,
    /// The owner is using the Mac: [`active_limit`].
    Active,
}

impl OwnerTier {
    /// `idle` / `active`, for logs.
    pub fn name(self) -> &'static str {
        match self {
            OwnerTier::Idle => "idle",
            OwnerTier::Active => "active",
        }
    }
}

/// The working-set limit of the owner-active tier, from the idle tier's limit.
///
/// The owner's apps get as much again as macOS keeps ([`HOST_RESERVE_BYTES`]), but never less than
/// the table's smallest row (the bottom of the lowest default row: 4 GiB, where the Groth16 wrap's
/// 3.9 GiB is the largest phase) and never more than the idle limit. No new RAM fraction: it is the
/// idle plan, the existing reserve and the table. Per Mac (idle limit -> active limit, M8 po2):
///
/// | Mac | idle | active | PLAN 9.1 (active / idle) |
/// |---|---|---|---|
/// | 16 GB | 8 GiB, po2 19 | 4 GiB, po2 18 | ~4 GB / ~7-8 GB |
/// | 18 GB | 10 GiB, po2 19 | 4 GiB, po2 18 | - |
/// | 24 GB | 16 GiB, po2 20 | 8 GiB, po2 19 | 6-12 GB / 12-28 GB |
/// | 36 GB | 28 GiB, po2 20 | 20 GiB, po2 20 | 16-64 GB / 40-180+ GB (high end) |
pub fn active_limit_in(idle_limit: u64, table: Po2Table) -> u64 {
    let floor = min_limit_for_po2(job_po2_for_limit_in(0, table), table);
    idle_limit
        .saturating_sub(HOST_RESERVE_BYTES)
        .max(floor)
        .min(idle_limit)
}

/// [`active_limit_in`] with the table [`PO2_TABLE_ENV`] selects.
pub fn active_limit(idle_limit: u64) -> u64 {
    active_limit_in(idle_limit, env_po2_table())
}

/// The working-set limit of `tier` for a Mac whose idle limit is `idle_limit`.
pub fn tier_limit(idle_limit: u64, tier: OwnerTier) -> u64 {
    match tier {
        OwnerTier::Idle => idle_limit,
        OwnerTier::Active => active_limit(idle_limit),
    }
}

/// How the owner tier is chosen ([`OWNER_ACTIVE_ENV`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnerForce {
    /// Read the owner's activity.
    Auto,
    /// Always the owner-active tier.
    Active,
    /// Always the idle tier (the default).
    Idle,
}

/// [`OWNER_ACTIVE_ENV`] from this process's environment.
pub fn owner_force() -> OwnerForce {
    match std::env::var(OWNER_ACTIVE_ENV).as_deref().map(str::trim) {
        Ok("1") => OwnerForce::Active,
        Ok(v) if v.eq_ignore_ascii_case("auto") => OwnerForce::Auto,
        _ => OwnerForce::Idle,
    }
}

/// [`OWNER_IDLE_SECS_ENV`] from this process's environment (a positive whole number of seconds).
pub fn owner_idle_after() -> std::time::Duration {
    let secs = std::env::var(OWNER_IDLE_SECS_ENV)
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|&s| s > 0)
        .unwrap_or(DEFAULT_OWNER_IDLE_SECS);
    std::time::Duration::from_secs(secs)
}

/// What the host can read about its owner at a job's start. `None`: could not be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct OwnerReading {
    /// Time since the last keyboard, mouse or trackpad input (IOHIDSystem `HIDIdleTime`).
    pub hid_idle: Option<std::time::Duration>,
    /// Whether the main display is asleep (`CGDisplayIsAsleep`).
    pub display_asleep: Option<bool>,
    /// On battery power (M9's power state).
    pub on_battery: Option<bool>,
    /// Low Power Mode (M9's power state).
    pub low_power_mode: Option<bool>,
}

impl OwnerReading {
    /// One line for logs.
    pub fn describe(&self) -> String {
        let b = |v: Option<bool>| match v {
            Some(true) => "yes",
            Some(false) => "no",
            None => "unknown",
        };
        format!(
            "input idle {}, display asleep {}, on battery {}, Low Power Mode {}",
            self.hid_idle
                .map_or("unknown".to_string(), |d| format!("{} s", d.as_secs())),
            b(self.display_asleep),
            b(self.on_battery),
            b(self.low_power_mode),
        )
    }
}

/// The owner tier with its hysteresis: at most one switch per job start, and a switch back to idle
/// only after the owner has been away for twice [`OWNER_IDLE_SECS_ENV`].
///
/// Policy (auto), in order:
/// 1. Display asleep: idle at once (nobody is looking at the Mac; any input wakes the display).
///    This wins over the power signals, so a closed-lid laptop on battery counts as idle: the tier
///    sizes memory for the owner's apps, and none are in use; battery drain is not its concern.
/// 2. Input within the idle threshold, on battery, or Low Power Mode: active at once (an unplugged
///    laptop is with its owner, and Low Power Mode is the owner asking for less).
/// 3. Back to idle from active only once the input has been idle for twice the threshold and
///    neither power signal holds. Between one and two thresholds the tier stays as it was: that is
///    the hysteresis band, so an owner who touches the mouse every few minutes keeps one tier.
/// 4. Nothing readable: the tier stays as it was (idle at start: today's behaviour).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OwnerTierState {
    /// The tier now.
    pub tier: OwnerTier,
    /// How many times the tier changed (for the logs and tests).
    pub switches: u32,
}

impl Default for OwnerTierState {
    fn default() -> Self {
        OwnerTierState {
            tier: OwnerTier::Idle,
            switches: 0,
        }
    }
}

impl OwnerTierState {
    /// Applies one reading and returns the tier now. `idle_after` is [`owner_idle_after`].
    pub fn update(
        &mut self,
        reading: &OwnerReading,
        idle_after: std::time::Duration,
        force: OwnerForce,
    ) -> OwnerTier {
        let next = match force {
            OwnerForce::Active => OwnerTier::Active,
            OwnerForce::Idle => OwnerTier::Idle,
            OwnerForce::Auto => Self::decide(self.tier, reading, idle_after),
        };
        if next != self.tier {
            self.tier = next;
            self.switches = self.switches.saturating_add(1);
        }
        self.tier
    }

    fn decide(
        now: OwnerTier,
        reading: &OwnerReading,
        idle_after: std::time::Duration,
    ) -> OwnerTier {
        if reading.display_asleep == Some(true) {
            return OwnerTier::Idle;
        }
        let power = reading.on_battery == Some(true) || reading.low_power_mode == Some(true);
        let input_recent = reading.hid_idle.is_some_and(|d| d < idle_after);
        if input_recent || power {
            return OwnerTier::Active;
        }
        match (now, reading.hid_idle) {
            (OwnerTier::Active, Some(d)) if d >= idle_after.saturating_mul(2) => OwnerTier::Idle,
            (OwnerTier::Active, _) => OwnerTier::Active,
            (OwnerTier::Idle, _) => OwnerTier::Idle,
        }
    }
}

/// The tier a Metal job proves at, given the owner tier now (`owner`), the tier the slot's worker
/// was started at (`worker`) and the job's segment po2 (`None` for benchmarks and calibrations).
///
/// The po2 is fixed before this (the job was measured at it, and a guest can tell the size it runs
/// at), so it is never changed here; only the budget is chosen:
/// - no job po2 (benchmark, calibration): idle, so benchmark rows keep the idle rate;
/// - a po2 the active tier cannot hold (`po2 > active_ceiling`, e.g. a job measured at 19 just
///   before the owner came back): idle;
/// - owner active: active;
/// - owner idle, job fits both: the worker's tier as it is, so no respawn before the proof (the
///   respawn back to idle happens after it, in the idle gap).
pub fn job_tier(
    owner: OwnerTier,
    worker: OwnerTier,
    po2: Option<u8>,
    active_ceiling: Option<u8>,
) -> OwnerTier {
    let Some(po2) = po2 else {
        return OwnerTier::Idle;
    };
    if active_ceiling.is_none_or(|c| po2 > c) {
        return OwnerTier::Idle;
    }
    match owner {
        OwnerTier::Active => OwnerTier::Active,
        OwnerTier::Idle => worker,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The host figure of a Mac with `ram_gib` of RAM (`hw.memsize` less the 8 GiB host reserve).
    fn host_figure(ram_gib: u64) -> Option<u64> {
        Some((ram_gib - 8) * GIB)
    }

    #[test]
    fn enforcement_is_a_no_op_on_the_36_gb_mac_and_binds_on_small_ones() {
        // This Mac (M5 Max, 36 GiB): plan 28 GiB, recommendedMaxWorkingSetSize 30150672384 B.
        let rec36 = 30_150_672_384;
        assert_eq!(enforced_budget(28 * GIB, rec36, false), None);
        // A plan above the device limit (48 GB and up: RAM less 8 GiB > 75 % of RAM) is clamped by
        // the worker to the device limit already: plan == limit, nothing to export.
        assert_eq!(enforced_budget(rec36, rec36, false), None);
        // 16 GB Mac: ~10.67 GiB recommended (11453251584 B), plan 8 GiB: enforced.
        assert_eq!(
            enforced_budget(8 * GIB, 11_453_251_584, false),
            Some(8 * GIB)
        );
        // 18 GB: 12 GiB recommended, plan 10 GiB.
        assert_eq!(enforced_budget(10 * GIB, 12 * GIB, false), Some(10 * GIB));
        // 24 GB: 16 GiB recommended, plan 16 GiB: nothing to enforce.
        assert_eq!(enforced_budget(16 * GIB, 16 * GIB, false), None);
        // The owner-active tier on this Mac (20 GiB) and on a simulated 16 GB one (4 GiB).
        assert_eq!(enforced_budget(20 * GIB, rec36, false), Some(20 * GIB));
        assert_eq!(enforced_budget(4 * GIB, rec36, false), Some(4 * GIB));
        // An explicit budget the plan equals (the operator's or gpu-run's): left alone.
        assert_eq!(enforced_budget(8 * GIB, 8 * GIB, false), None);
        // The knob.
        assert_eq!(enforced_budget(8 * GIB, 11_453_251_584, true), None);
        // Off unless switched on (measured slower and larger; see ENFORCE_BUDGET_ENV).
        if std::env::var_os(ENFORCE_BUDGET_ENV).is_none() {
            assert!(enforce_budget_off());
        }
    }

    #[test]
    fn the_active_tier_per_mac_size() {
        let idle = |ram: u64| host_figure(ram).unwrap();
        let tier = |ram: u64, t: OwnerTier| {
            let limit = match t {
                OwnerTier::Idle => idle(ram),
                OwnerTier::Active => active_limit_in(idle(ram), Po2Table::M8),
            };
            (limit / GIB, job_po2_for_limit_in(limit, Po2Table::M8))
        };
        use OwnerTier::*;
        assert_eq!((tier(16, Idle), tier(16, Active)), ((8, 19), (4, 18)));
        assert_eq!((tier(18, Idle), tier(18, Active)), ((10, 19), (4, 18)));
        assert_eq!((tier(24, Idle), tier(24, Active)), ((16, 20), (8, 19)));
        assert_eq!((tier(36, Idle), tier(36, Active)), ((28, 20), (20, 20)));
        // The floor is the table's smallest row in either table, and the active tier is never
        // above the idle one (a 4 GiB budget run stays at 4 GiB).
        assert_eq!(active_limit_in(4 * GIB, Po2Table::M8), 4 * GIB);
        assert_eq!(active_limit_in(4 * GIB, Po2Table::M1), 4 * GIB);
        assert_eq!(active_limit_in(3 * GIB, Po2Table::M8), 3 * GIB);
        assert_eq!(active_limit_in(10 * GIB, Po2Table::M1), 4 * GIB);
        for mib in (4096..=256 * 1024u64).step_by(256) {
            let l = mib << 20;
            let a = active_limit_in(l, Po2Table::M8);
            assert!(a <= l && a >= 4 * GIB, "{mib} MiB -> {a}");
            // The active tier's default po2 is always one the hard ceiling admits.
            let ceiling = max_po2_for_limit_in(a, Po2Table::M8).unwrap();
            assert!(job_po2_for_limit_in(a, Po2Table::M8) <= ceiling);
        }
    }

    /// W7-M10 review: which tier switches change what a live worker does for a job, per Mac size.
    /// Unenforced, none does for a job the active tier admits: the respawn it used to trigger (36 GB:
    /// 28 -> 20 GiB at po2 20; 16 GB: 8 -> 4 GiB at po2 18) only cost a cold worker.
    #[test]
    fn a_tier_switch_changes_a_job_only_where_the_worker_would_prove_it_otherwise() {
        let t = Po2Table::M8;
        for ram in [16u64, 18, 24, 36, 48, 64, 128] {
            let idle = host_figure(ram).unwrap();
            let active = active_limit_in(idle, t);
            for po2 in 14..=21u8 {
                let both = max_po2_for_limit_in(active, t).is_some_and(|c| po2 <= c);
                let same = same_for_job_in(idle, active, Some(po2), false, t);
                let keeps = keep_groth16_cache(idle, po2) == keep_groth16_cache(active, po2);
                // Unenforced: the same exactly when both admit the po2 (or neither) and the
                // Groth16 decision agrees.
                let idle_admits = max_po2_for_limit_in(idle, t).is_some_and(|c| po2 <= c);
                assert_eq!(same, (both == idle_admits) && keeps, "{ram} GB po2 {po2}");
                // Enforced: any other figure is another budget.
                assert!(!same_for_job_in(idle, active, Some(po2), true, t) || idle == active);
                assert!(same_for_job_in(idle, idle, Some(po2), true, t));
            }
            // At the tier's own po2 nothing differs on any of these Macs, so a switch never
            // respawns a worker for a job that fits it.
            let job = job_po2_for_limit_in(active, t);
            assert!(
                same_for_job_in(idle, active, Some(job), false, t),
                "{ram} GB po2 {job}"
            );
            // A benchmark (no po2) proves at the figure's default size: differs where that does.
            assert_eq!(
                same_for_job_in(idle, active, None, false, t),
                job_po2_for_limit_in(idle, t) == job
                    && keep_groth16_cache(idle, job) == keep_groth16_cache(active, job),
                "{ram} GB benchmark"
            );
        }
        // 16 GB: a po2 19 job at the 4 GiB tier is refused there: never the same.
        assert!(!same_for_job_in(8 * GIB, 4 * GIB, Some(19), false, t));
        // 36 GB: po2 20 at 28 and 20 GiB, key released at both (it needs ~29.5 GiB): the same.
        assert!(same_for_job_in(28 * GIB, 20 * GIB, Some(20), false, t));
        assert!(same_for_job_in(28 * GIB, 20 * GIB, None, false, t));
        // Where the key decision differs (36 GiB keeps it at po2 20, 28 GiB does not): differs.
        assert!(keep_groth16_cache(36 * GIB, 20) && !keep_groth16_cache(28 * GIB, 20));
        assert!(!same_for_job_in(36 * GIB, 28 * GIB, Some(20), false, t));
    }

    #[test]
    fn the_owner_tier_is_off_unless_asked_for() {
        // Runs with whatever this process has; the parser itself is pinned below.
        if std::env::var_os(OWNER_ACTIVE_ENV).is_none() {
            assert_eq!(owner_force(), OwnerForce::Idle);
        }
    }

    fn reading(hid_secs: Option<u64>) -> OwnerReading {
        OwnerReading {
            hid_idle: hid_secs.map(std::time::Duration::from_secs),
            display_asleep: Some(false),
            on_battery: Some(false),
            low_power_mode: Some(false),
        }
    }

    #[test]
    fn owner_tier_policy_and_hysteresis() {
        let t = std::time::Duration::from_secs(300);
        let mut s = OwnerTierState::default();
        let auto = OwnerForce::Auto;
        assert_eq!(s.update(&reading(Some(3600)), t, auto), OwnerTier::Idle);
        // Input 5 s ago: active at once.
        assert_eq!(s.update(&reading(Some(5)), t, auto), OwnerTier::Active);
        assert_eq!(s.switches, 1);
        // Inside the band (one to two thresholds): stays active.
        for secs in [300, 450, 599] {
            assert_eq!(
                s.update(&reading(Some(secs)), t, auto),
                OwnerTier::Active,
                "{secs}"
            );
        }
        assert_eq!(s.switches, 1);
        // Away twice the threshold: idle.
        assert_eq!(s.update(&reading(Some(600)), t, auto), OwnerTier::Idle);
        assert_eq!(s.switches, 2);
        // From idle the band does not switch it back up; only recent input does.
        assert_eq!(s.update(&reading(Some(450)), t, auto), OwnerTier::Idle);
        assert_eq!(s.update(&reading(Some(299)), t, auto), OwnerTier::Active);
        // A display that sleeps: idle at once, whatever the input timer says.
        let asleep = OwnerReading {
            display_asleep: Some(true),
            ..reading(Some(10))
        };
        assert_eq!(s.update(&asleep, t, auto), OwnerTier::Idle);
        // Battery or Low Power Mode with the display on: active, also with no input for hours.
        let battery = OwnerReading {
            on_battery: Some(true),
            ..reading(Some(7200))
        };
        assert_eq!(s.update(&battery, t, auto), OwnerTier::Active);
        let lpm = OwnerReading {
            low_power_mode: Some(true),
            ..reading(Some(7200))
        };
        assert_eq!(s.update(&lpm, t, auto), OwnerTier::Active);
        // Nothing readable: no change, in either tier.
        assert_eq!(
            s.update(&OwnerReading::default(), t, auto),
            OwnerTier::Active
        );
        let mut fresh = OwnerTierState::default();
        assert_eq!(
            fresh.update(&OwnerReading::default(), t, auto),
            OwnerTier::Idle
        );
        // Forced values win over any reading.
        assert_eq!(
            fresh.update(&reading(Some(1)), t, OwnerForce::Idle),
            OwnerTier::Idle
        );
        assert_eq!(
            fresh.update(&asleep, t, OwnerForce::Active),
            OwnerTier::Active
        );
    }

    #[test]
    fn a_flapping_owner_switches_the_tier_rarely() {
        // Input every 6 minutes for 8 hours, read every 30 s: one switch to active, none back.
        let t = std::time::Duration::from_secs(300);
        let mut s = OwnerTierState::default();
        for tick in 0..(8 * 3600 / 30) {
            let since_input = (tick * 30) % 360;
            s.update(&reading(Some(since_input)), t, OwnerForce::Auto);
        }
        assert_eq!((s.tier, s.switches), (OwnerTier::Active, 1));
        // Input every 12 minutes: back to idle after 10 min each time: two switches per 12 min.
        let mut s = OwnerTierState::default();
        for tick in 0..(3600 / 30) {
            let since_input = (tick * 30) % 720;
            s.update(&reading(Some(since_input)), t, OwnerForce::Auto);
        }
        assert!(s.switches <= 2 * 5 + 1, "{}", s.switches);
    }

    #[test]
    fn a_job_keeps_its_po2_and_gets_a_tier_that_holds_it() {
        use OwnerTier::*;
        let ceil = Some(18);
        // Benchmarks and calibrations: idle, whatever the owner does.
        assert_eq!(job_tier(Active, Active, None, ceil), Idle);
        // A job measured at 19 cannot run in a 4 GiB tier: idle.
        assert_eq!(job_tier(Active, Active, Some(19), ceil), Idle);
        // A job at 18 while the owner is active: active.
        assert_eq!(job_tier(Active, Idle, Some(18), ceil), Active);
        // The owner left: the worker's tier, so no respawn before the proof.
        assert_eq!(job_tier(Idle, Active, Some(18), ceil), Active);
        assert_eq!(job_tier(Idle, Idle, Some(18), ceil), Idle);
        assert_eq!(job_tier(Idle, Idle, Some(19), ceil), Idle);
        // A tier with no admissible po2 at all.
        assert_eq!(job_tier(Active, Idle, Some(18), None), Idle);
    }

    #[test]
    fn each_mac_tier_gets_its_table_row() {
        let po2 = |ram, budget| {
            job_po2_for_limit_in(
                working_set_limit_of(host_figure(ram), budget).unwrap(),
                Po2Table::M8,
            )
        };
        // PLAN 9.1 tiers: 16 GB base chip, 18 GB, 24 GB primary target, 36 GB and up.
        assert_eq!(
            po2(16, None),
            19,
            "a 16 GB Mac (8 GiB figure) proves at 19 (M8)"
        );
        assert_eq!(
            po2(18, None),
            19,
            "an 18 GB Mac (10 GiB figure): 19, for its host RAM (M8)"
        );
        assert_eq!(po2(24, None), 20, "a 24 GB Mac proves at 20 (M8)");
        assert_eq!(po2(32, None), 20);
        assert_eq!(po2(36, None), 20);
        assert_eq!(po2(128, None), 20, "never above the protocol default");
        // The fork's artificial budget wins when smaller (the 4 / 8 GB budget runs).
        assert_eq!(po2(36, Some(4 * GIB)), 18);
        assert_eq!(po2(36, Some(8 * GIB)), 19);
        assert_eq!(
            po2(16, Some(64 * GIB)),
            19,
            "a bigger budget never raises it"
        );
    }

    #[test]
    fn the_m1_table_is_kept_behind_the_knob() {
        let m1 = |gib: u64| job_po2_for_limit_in(gib * GIB, Po2Table::M1);
        assert_eq!((m1(4), m1(8), m1(16), m1(28)), (17, 18, 19, 20));
        let ceil = |gib: u64| max_po2_for_limit_in(gib * GIB, Po2Table::M1);
        assert_eq!(
            (ceil(3), ceil(4), ceil(8), ceil(16), ceil(28), ceil(180)),
            (None, Some(17), Some(19), Some(20), Some(21), Some(23))
        );
    }

    #[test]
    fn the_ceiling_admits_the_default_and_stays_put_above_20() {
        for table in [Po2Table::M1, Po2Table::M8] {
            let mut last = 0;
            for mib in (4096..=256 * 1024u64).step_by(128) {
                let limit = mib << 20;
                let po2 = job_po2_for_limit_in(limit, table);
                assert!(po2 >= last, "{table:?} {mib} MiB");
                last = po2;
                let ceiling = max_po2_for_limit_in(limit, table).unwrap();
                assert!(ceiling >= po2, "{table:?} {mib} MiB: {ceiling} < {po2}");
            }
            assert_eq!(max_po2_for_limit_in(3 * GIB, table), None);
        }
        let m8 = |gib: u64| max_po2_for_limit_in(gib * GIB, Po2Table::M8);
        assert_eq!(
            (m8(4), m8(6), m8(8), m8(10)),
            (Some(18), Some(19), Some(19), Some(20))
        );
        // Above 20 nothing was measured under a budget: the M1 ceiling, which refused po2 22 on
        // the 36 GB dev machine after it thrashed swap (M1 note).
        for gib in [16, 28, 64, 180] {
            assert_eq!(
                m8(gib),
                max_po2_for_limit_in(gib * GIB, Po2Table::M1),
                "{gib} GiB"
            );
        }
    }

    /// W7-M11: the knobs. `ZKMINER_METAL_PO2_TABLE=m1` still wins; `ZKMINER_METAL_TIER_TABLE=m8`
    /// restores M8's table, `r2` opts into W7-R2's small-Mac rows.
    #[test]
    fn the_tier_knobs_select_the_table() {
        use Po2Table::*;
        assert_eq!(po2_table_from(None, None), DEFAULT_TABLE);
        assert_eq!(DEFAULT_TABLE, W7);
        assert_eq!(po2_table_from(Some("m1"), Some("r2")), M1);
        assert_eq!(po2_table_from(None, Some("m8")), M8);
        assert_eq!(po2_table_from(None, Some("m1")), M1);
        assert_eq!(po2_table_from(None, Some("r2")), R2);
        assert_eq!(po2_table_from(None, Some("w7")), W7);
        assert_eq!(
            po2_table_from(Some("other"), Some("nonsense")),
            DEFAULT_TABLE
        );
    }

    /// W7-M11: the rule is min(GPU rule, footprint model), and the footprint model only removes rows
    /// above M8's. Per Mac (RAM, host figure = RAM less 8 GiB), with the measured footprints:
    #[test]
    fn the_w7_tiers_follow_the_gpu_rule_and_the_footprint_model() {
        use Po2Table::*;
        let ram = |gib: u64| Some(gib * GIB);
        let w7 = |ram_gib: u64, limit_gib: u64| job_po2_in(limit_gib * GIB, W7, ram(ram_gib));
        let r2 = |ram_gib: u64, limit_gib: u64| job_po2_in(limit_gib * GIB, R2, ram(ram_gib));
        // 18 GB Mac, 10 GiB figure: W7 keeps 19 (po2 20's 16.25 GiB + 4.5 GiB > 18 GiB); R2 (12 GiB
        // with the graph release) gives 20.
        assert_eq!(w7(18, 10), 19);
        assert_eq!(r2(18, 10), 20);
        // The same figure on a big Mac (a budget run): 20 in both; unknown RAM keeps M8's 19.
        assert_eq!(w7(36, 10), 20);
        assert_eq!(job_po2_in(10 * GIB, W7, None), 19);
        assert_eq!(job_po2_in(10 * GIB, R2, None), 19);
        // 16 GB Mac, 8 GiB figure: 19 in both (R2's po2 20 needs 12 + 4.5 GiB).
        assert_eq!(w7(16, 8), 19);
        assert_eq!(r2(16, 8), 19);
        // R2's 4 GiB row (a 16 or 18 GB Mac's owner-active tier): 19 (7 + 4.5 GiB).
        assert_eq!(r2(16, 4), 19);
        assert_eq!(r2(18, 4), 19);
        assert_eq!(w7(16, 4), 18);
        // 24 GB: 20 in every table; its owner-active 8 GiB tier: 20 in R2 (12 + 4.5 <= 24).
        for t in [M8, W7, R2] {
            assert_eq!(job_po2_in(16 * GIB, t, ram(24)), 20);
            assert_eq!(job_po2_in(28 * GIB, t, ram(36)), 20);
        }
        assert_eq!(r2(24, 8), 20);
        assert_eq!(w7(24, 8), 19);
        // W7 changes no real Mac's idle tier (only budget runs on Macs with >= 20.75 GiB of RAM).
        for ram_gib in [16u64, 18, 24, 32, 36, 48, 64, 96, 128, 192] {
            let figure = (ram_gib - 8) * GIB;
            assert_eq!(
                job_po2_in(figure, W7, ram(ram_gib)),
                job_po2_in(figure, M8, None),
                "{ram_gib} GB"
            );
        }
        // Never below M8, never above the cap, monotonic in the limit, and the ceiling admits it.
        for t in [W7, R2] {
            for ram_gib in [12u64, 16, 18, 24, 36, 64] {
                let mut last = 0;
                for mib in (4096..=64 * 1024u64).step_by(256) {
                    let limit = mib << 20;
                    let p = job_po2_in(limit, t, ram(ram_gib));
                    assert!(p >= job_po2_in(limit, M8, None), "{t:?} {ram_gib} {mib}");
                    assert!(p <= DEFAULT_JOB_PO2_CAP);
                    assert!(p >= last, "{t:?} {ram_gib} GB {mib} MiB");
                    last = p;
                    let ceiling = max_po2_for_limit_in(limit, t).unwrap();
                    assert!(
                        ceiling >= p,
                        "{t:?} {ram_gib} GB {mib} MiB: {ceiling} < {p}"
                    );
                }
            }
        }
    }

    #[test]
    fn the_footprint_model_and_the_r2_ceiling() {
        use Po2Table::*;
        // W7: 18 GiB of RAM holds 19 (10.5 + 4.5), 20.75 GiB holds 20; R2: 16.5 GiB holds 20.
        assert_eq!(footprint_po2_cap(18 * GIB, W7), Some(19));
        assert_eq!(footprint_po2_cap(20 * GIB + 3 * GIB / 4, W7), Some(20));
        assert_eq!(footprint_po2_cap(16 * GIB, R2), Some(19));
        assert_eq!(footprint_po2_cap(16 * GIB + GIB / 2, R2), Some(20));
        assert_eq!(footprint_po2_cap(8 * GIB, W7), None);
        for t in [W7, R2] {
            for p in 16..24u8 {
                assert!(footprint_bytes(p, t) <= footprint_bytes(p + 1, t));
            }
        }
        let r2 = |gib: u64| max_po2_for_limit_in(gib * GIB, R2);
        assert_eq!(
            (r2(3), r2(4), r2(6), r2(8)),
            (None, Some(19), Some(19), Some(20))
        );
        let w7 = |gib: u64| max_po2_for_limit_in(gib * GIB, W7);
        assert_eq!((w7(4), w7(8), w7(10)), (Some(18), Some(19), Some(20)));
        // Above 20 every table keeps M1's ceiling.
        for gib in [16, 28, 64, 180] {
            for t in [W7, R2] {
                assert_eq!(
                    max_po2_for_limit_in(gib * GIB, t),
                    max_po2_for_limit_in(gib * GIB, M1)
                );
            }
        }
        // The active tier's floor stays the smallest row's budget, 4 GiB.
        assert_eq!(active_limit_in(10 * GIB, R2), 4 * GIB);
        assert_eq!(active_limit_in(10 * GIB, W7), 4 * GIB);
        // W7-G1's graph release: only with R2, below 20 GiB, and not over the operator's value.
        assert!(spawn_without_malloc_large_cache(10 * GIB, R2, false));
        assert!(!spawn_without_malloc_large_cache(10 * GIB, R2, true));
        assert!(!spawn_without_malloc_large_cache(20 * GIB, R2, false));
        assert!(!spawn_without_malloc_large_cache(10 * GIB, W7, false));
        assert!(!spawn_without_malloc_large_cache(10 * GIB, M8, false));
    }

    #[test]
    fn budget_grammar_matches_the_fork() {
        assert_eq!(parse_bytes("4294967296"), Some(4 * GIB));
        assert_eq!(parse_bytes("4G"), Some(4 * GIB));
        assert_eq!(parse_bytes(" 4GiB "), Some(4 * GIB));
        assert_eq!(parse_bytes("512M"), Some(512 << 20));
        assert_eq!(parse_bytes("8gb"), Some(8 * GIB));
        assert_eq!(parse_bytes("0"), None);
        assert_eq!(parse_bytes("lots"), None);
        assert_eq!(parse_bytes(""), None);
    }
}
