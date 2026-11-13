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
/// its po2 ceiling; unset or anything else is the M8 table. Host and worker both read it (the worker
/// inherits the miner's environment), so setting it on the miner moves both.
pub const PO2_TABLE_ENV: &str = "ZKMINER_METAL_PO2_TABLE";

/// Which segment-size table a Mac is sized with ([`PO2_TABLE_ENV`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Po2Table {
    /// M1's table (M6 made it the shared one): sized by the unconstrained recursion-phase peak.
    M1,
    /// M8's table: sized by what proves under an enforced working-set budget (risc0 Z12).
    M8,
}

/// [`PO2_TABLE_ENV`] from this process's environment.
pub fn env_po2_table() -> Po2Table {
    match std::env::var(PO2_TABLE_ENV) {
        Ok(v) if v.trim().eq_ignore_ascii_case("m1") => Po2Table::M1,
        _ => Po2Table::M8,
    }
}

/// The working-set limit from which [`Po2Table::M8`] gives a Mac po2 20 by default.
///
/// po2 20 proves, wraps and verifies under a 10 GiB enforced budget (segments 9420 MiB, process
/// footprint 13.4 GB; M8 note), which is therefore its ceiling ([`PO2_20_MIN_LIMIT`]). The default is
/// one step more cautious because an 18 GB Mac (10 GiB host figure) enforces no budget: its proof's
/// process footprint (13.4-13.7 GB at po2 20 against 8.4 GB at 19 with the worker's segment-prover
/// release) would be ~70% of its RAM. From
/// 12 GiB up (a 24 GB Mac, 16 GiB) po2 20 is the default.
pub const PO2_20_DEFAULT_LIMIT: u64 = 12 * GIB;

/// The smallest working-set limit po2 20 may start under ([`min_limit_for_po2`]): measured to prove.
pub const PO2_20_MIN_LIMIT: u64 = 10 * GIB;

/// The default segment size for a GPU working-set limit (PLAN 9.1), with the table
/// [`PO2_TABLE_ENV`] selects.
pub fn job_po2_for_limit(limit: u64) -> u8 {
    job_po2_for_limit_in(limit, env_po2_table())
}

/// The default segment size for a GPU working-set limit and table.
///
/// [`Po2Table::M8`] (default). Measured with the worker's `--benchmark` (memory-merkle, M5 Max, risc0
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
/// Never above [`DEFAULT_JOB_PO2_CAP`].
pub fn job_po2_for_limit_in(limit: u64, table: Po2Table) -> u8 {
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
    };
    po2.min(DEFAULT_JOB_PO2_CAP)
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
pub fn min_limit_for_po2(po2: u8, table: Po2Table) -> u64 {
    match (table, po2) {
        (Po2Table::M1, p) => stark_peak_bytes(p),
        (Po2Table::M8, 0..=18) => 4 * GIB,
        (Po2Table::M8, 19) => 6 * GIB,
        (Po2Table::M8, 20) => PO2_20_MIN_LIMIT,
        (Po2Table::M8, p) => stark_peak_bytes(p),
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
