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

/// The default segment size for a GPU working-set limit (PLAN 9.1). Peak GPU memory, segments /
/// recursion phase:
///
/// | limit           | po2 | STARK peak (MiB) | typical Mac                                     |
/// |-----------------|-----|------------------|-------------------------------------------------|
/// | < 6 GiB         | 17  | 2082 / 3971      | 16 GB base chip under a ~4 GB owner-active cap  |
/// | 6 to < 12 GiB   | 18  | 2700 / 4390      | 16 GB Mac (8 GiB host figure)                   |
/// | 12 to < 20 GiB  | 19  | 4976 / 6668      | 24 GB Mac (16 GiB host figure)                  |
/// | >= 20 GiB       | 20  | 9473 / 11169     | 32 GB and up                                    |
pub fn job_po2_for_limit(limit: u64) -> u8 {
    let po2 = if limit < 6 * GIB {
        17
    } else if limit < 12 * GIB {
        18
    } else if limit < 20 * GIB {
        19
    } else {
        20
    };
    po2.min(DEFAULT_JOB_PO2_CAP)
}

/// Peak GPU memory of the largest STARK phase at `po2` (the recursion phase, beside the segment
/// prover's cached pool): 3971 / 4390 / 6668 / 11169-11938 MiB measured at po2 17 / 18 / 19 / 20,
/// rounded up; doubling per step above 20.
pub fn stark_peak_bytes(po2: u8) -> u64 {
    match po2 {
        0..=17 => 4 * GIB,
        18 => 5 * GIB,
        19 => 7 * GIB,
        20 => 12 * GIB,
        p => (12 * GIB) << (p - 20).min(4),
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The host figure of a Mac with `ram_gib` of RAM (`hw.memsize` less the 8 GiB host reserve).
    fn host_figure(ram_gib: u64) -> Option<u64> {
        Some((ram_gib - 8) * GIB)
    }

    #[test]
    fn each_mac_tier_gets_its_table_row() {
        let po2 = |ram, budget| {
            job_po2_for_limit(working_set_limit_of(host_figure(ram), budget).unwrap())
        };
        // PLAN 9.1 tiers: 16 GB base chip, 24 GB primary target, 36 GB and up.
        assert_eq!(po2(16, None), 18);
        assert_eq!(
            po2(24, None),
            19,
            "a 24 GB Mac proves at 19, not the discrete-card 20"
        );
        assert_eq!(po2(32, None), 20);
        assert_eq!(po2(36, None), 20);
        assert_eq!(po2(128, None), 20, "never above the protocol default");
        // The fork's artificial budget wins when smaller (the 4 / 8 GB budget runs).
        assert_eq!(po2(36, Some(4 * GIB)), 17);
        assert_eq!(po2(36, Some(8 * GIB)), 18);
        assert_eq!(
            po2(16, Some(64 * GIB)),
            18,
            "a bigger budget never raises it"
        );
    }

    #[test]
    fn the_stark_peak_fits_the_limit_that_chose_it() {
        // Every row's own peak fits the bottom of the next row up, and the table is monotone.
        let mut last = 0;
        for limit_gib in 1..=128u64 {
            let po2 = job_po2_for_limit(limit_gib * GIB);
            assert!(po2 >= last);
            last = po2;
            if limit_gib >= 6 {
                assert!(
                    stark_peak_bytes(po2) <= limit_gib * GIB,
                    "{limit_gib} GiB -> po2 {po2}"
                );
            }
        }
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
