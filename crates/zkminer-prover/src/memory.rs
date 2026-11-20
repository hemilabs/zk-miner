//! Host memory: how much is left, how hard the box is stalling, and who the kernel should kill.
//!
//! WHY THIS EXISTS. Prover processes can take the whole host down, and they do it in two very
//! different shapes that rule out most of the obvious single defences:
//!
//! | | the freeze | the cgroup kill |
//! |---|---|---|
//! | victim | 4x `zkminer-prove-risc0` | `sp1-gpu-server` |
//! | `total_vm` | 54-72 GB each | **139 GB** |
//! | anon RSS | **2-11 MB each** | 17.6 GB |
//! | constraint | `global_oom` | `CONSTRAINT_MEMCG` |
//! | outcome | hard reboot | one failed proof |
//!
//! What that table forces:
//!
//! * **Virtual size is meaningless for a CUDA process.** 139 GB mapped against 17.6 GB resident.
//!   So `RLIMIT_AS` and `RLIMIT_DATA` are not options — either would kill the prover at startup —
//!   and neither is `vm.overcommit_memory=2`, because this box's `CommitLimit` (23 GB) is already
//!   BELOW its `MemTotal` (28 GB). Everything here measures RESIDENT memory.
//! * **Two different failure shapes.** SP1 is one process with a real multi-gigabyte heap. The
//!   risc0 case had negligible anon RSS per process: the pressure came from driver, pinned and
//!   file-backed pages across four concurrent provers. A per-process budget alone would have
//!   missed the freeze, and a concurrency cap alone would miss SP1. Both are needed.
//! * **Kill order decides whether the host survives.** Same prover, same appetite, both times. The
//!   only difference was which process the kernel was allowed to pick.
//!
//! The defence is layered, and the layers have deliberately different jobs:
//!
//! 1. `oom_score_adj` on every worker (see `worker::spawn_on_this_thread`) so the kernel's victim
//!    is always a prover rather than sshd, systemd or the miner itself.
//! 2. `cap_process_memory` — a kernel-enforced ceiling per worker, so ONE runaway cannot take the
//!    host down. Summing across concurrent workers is deliberately NOT this layer's job.
//! 3. `oom_kill_count` — so a kill is reported as a host OOM rather than as a prover bug. Mistaking
//!    one for the other is an easy and costly error.

use std::time::Duration;

/// Leave this much for the rest of the system when sizing a worker's ceiling.
///
/// The OS, the miner, the TUI, and the page cache the prover itself needs to read a 236 MB binary.
/// Too small and the cap does not prevent a freeze; too large and a legitimate proof is refused.
pub const DEFAULT_HOST_RESERVE_BYTES: u64 = 3 * 1024 * 1024 * 1024;

/// Host memory SP1's one-time warm-up (`WorkerPool::warm_up`) may use at peak: where the server
/// runs Groth16 in a helper, building the stripped circuit reads the full one (13.9 GB measured on
/// the v6.1.0 circuit). The artifact download alone needs little.
pub const SP1_WARMUP_PEAK_BYTES: u64 = 15 * 1024 * 1024 * 1024;

/// What SP1's Groth16 helper process peaks at (16.0 GiB measured on the v6.1.0 circuit with Go's
/// default GC), for a peak read from live processes only, by which time the helper has exited.
pub const SP1_GROTH16_HELPER_PEAK_BYTES: u64 = 16 * 1024 * 1024 * 1024;

/// SP1's own `DEFAULT_MEMORY_LIMIT` (executor `opts.rs`): the executor SIGKILLs the guest at this RSS.
pub const SP1_DEFAULT_MEMORY_LIMIT_BYTES: u64 = 24 * 1024 * 1024 * 1024;

/// Host-RAM charged to the shared ledger for ONE risc0/openvm pre-claim execute (finding H4), and the
/// enforced ceiling the risc0 worker's in-process RSS self-guard aborts at. Charge == enforced ceiling
/// (the `charge == enforced-cap` discipline the SP1 path follows), so admission reserves the true
/// worst case and the aggregate across per-GPU risc0 slots cannot under-count into the host reserve.
/// Must equal the risc0 worker's `ZKMINER_RISC0_EXECUTE_MAX_RSS_BYTES` default; an operator who RAISES
/// that env raises the enforced ceiling above this charge (documented: then size the host reserve up).
pub const RISC0_EXECUTE_PEAK_BYTES: u64 = 8 * 1024 * 1024 * 1024;

/// The enforced SP1 EXECUTE memory cap for a host with `total` bytes of RAM: `min(SP1's 24 GiB
/// default, the admissible budget)` (locked #1).
///
/// This single number is used in THREE coupled places, and MUST be the same in all of them:
/// * the `MEMORY_LIMIT` env set on the dedicated MEASURE worker — the in-band ceiling SP1's own
///   100 ms RSS monitor enforces, turning a ballooning guest into a clean `TooMuchMemory` decline
///   instead of a host-OOM that kills the warm `sp1-gpu-server`;
/// * the `MEMORY_LIMIT` env set on the SP1 PROVE worker — EQUAL to the measure one so a guest whose
///   execute is too heavy declines identically at measure and at prove (measurable ⇔ provable,
///   finding F); a legitimately-claimed job was measured under this cap, so its prove-phase execute
///   never trips it, making this a pure safety backstop on the prove path;
/// * the host-RAM ledger CHARGE for a measurement — so the charge equals the worst-case RSS the cap
///   allows (charge == enforced cap), closing the old 4 GiB under-charge that let a measure plus
///   admitted proofs sum past physical RAM.
///
/// On a sub-36 GiB host the budget clamps it below 24 GiB (≈18 GiB on a 28 GiB box), which serialises
/// measurements and leans on prover eviction — the accepted trade. Honors
/// `ZKMINER_SP1_MEASURE_PEAK_BYTES`, clamped to the computed cap `min(24 GiB, budget)`, so an operator
/// can only ever LOWER the enforced cap — never raise it above SP1's own default nor past what the
/// host can actually admit (which would desync the charge from the enforced ceiling).
pub fn sp1_measure_cap_bytes(total: u64) -> u64 {
    // An RSS ceiling, so bounded by physical memory: on Windows `total` is the commit limit, which
    // can be larger and moves as the page file grows, and the three places above must agree.
    let total = total.min(physical_total_bytes().unwrap_or(u64::MAX));
    let mut cap = SP1_DEFAULT_MEMORY_LIMIT_BYTES.min(max_admissible_budget(total));
    // /dev/shm clamp (finding H3). The native executor stages the guest memory IMAGE in /dev/shm,
    // whose resident backing grows with touched pages; a tmpfs-FULL write SIGBUSes SYNCHRONOUSLY,
    // beating the 100 ms-poll `MEMORY_LIMIT`, so if `MEMORY_LIMIT` lets the image reach the tmpfs size
    // the guest SIGBUSes (→ a strike on a feasible job, or a prove-side slash) instead of declining
    // cleanly. The resident image + ring ≤ total_RSS, and `MEMORY_LIMIT` bounds total_RSS, so keeping
    // `MEMORY_LIMIT ≤ dev_shm` holds the shm resident below the tmpfs. We do NOT credit the executor's
    // anon working set: it was ~7.2 GiB for TYPICAL guests but is NOT an adversarial lower bound — a
    // crafted guest keeps anon to the image's page tables (tens of MiB for a multi-GiB image) while
    // ballooning the shm image, so crediting any anon floor is attacker-falsifiable and would SIGBUS.
    // Instead subtract a small poll-race margin so the 100 ms monitor SIGKILLs before a fast writer
    // can cross the last pages into a full tmpfs. x86-64-Linux ONLY — that is the sole target that
    // compiles SP1's native executor (and thus stages in /dev/shm); on linux-aarch64 or linux+profiling
    // the PORTABLE in-process executor runs, never touching /dev/shm, so clamping MEMORY_LIMIT from an
    // unrelated tmpfs there would needlessly shrink (or, with a tiny /dev/shm, wedge) the cap. Matches
    // the x86_64 gating of the paired /dev/shm sufficiency guard.
    if cfg!(target_arch = "x86_64") {
        if let Some(shm) = dev_shm_capacity_bytes() {
            cap = cap.min(shm.saturating_sub(SP1_DEV_SHM_POLL_MARGIN_BYTES));
        }
    }
    std::env::var("ZKMINER_SP1_MEASURE_PEAK_BYTES")
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .filter(|&n| n > 0)
        .map(|o| o.min(cap))
        .unwrap_or(cap)
}

/// Headroom kept BELOW the /dev/shm size when clamping `MEMORY_LIMIT` (finding H3). `MEMORY_LIMIT` is
/// a 100 ms-poll RSS monitor, so after it is crossed the executor can still dirty pages for up to one
/// interval before the SIGKILL lands; tmpfs-full SIGBUSes synchronously on the next page. This margin
/// (comfortably above a ~1 GiB/100 ms tmpfs write burst) ensures the monitor fires with room to spare,
/// regardless of how small the guest keeps its anon set. Credited as 0 anon = adversarially safe.
pub const SP1_DEV_SHM_POLL_MARGIN_BYTES: u64 = 2 * 1024 * 1024 * 1024;

/// `/proc/pressure/memory`'s `full avg10`, in percent, above which the host is genuinely stalling.
///
/// This is the SYSTEM-wide PSI file, not a cgroup's `memory.pressure`. `full` means all non-idle
/// tasks were stalled on memory at once — time the machine lost outright, which is the thing to
/// react to. It is a better signal than free-memory thresholds
/// because it measures the symptom (stalling) rather than a proxy for it. A `full avg10` of
/// 67.95% has been seen on a host that was effectively unusable.
pub const STALL_BRAKE_PERCENT: f64 = 10.0;

/// Above this, the host is losing real time; stop admitting and raise an alarm.
pub const STALL_CRITICAL_PERCENT: f64 = 30.0;

/// How long to let `busctl` take. It talks to the user bus, so it CAN block; this bounds how long
/// a worker spawn waits for the cap. Bounded rather than absent because the respawn path is
/// latency-sensitive — a wedged bus must cost one timeout, not the spawn.
const CAP_TIMEOUT: Duration = Duration::from_secs(5);

/// `MemAvailable` from `/proc/meminfo`, in bytes.
///
/// The kernel's own estimate of what can be allocated without swapping — NOT `MemFree`, which
/// excludes reclaimable page cache and on this box reads ~9 GB while 26 GB is actually available.
#[cfg(not(windows))]
pub fn mem_available_bytes() -> Option<u64> {
    parse_meminfo_kb(
        &std::fs::read_to_string("/proc/meminfo").ok()?,
        "MemAvailable",
    )
}

/// `MemTotal` from `/proc/meminfo`, in bytes.
#[cfg(not(windows))]
pub fn mem_total_bytes() -> Option<u64> {
    parse_meminfo_kb(&std::fs::read_to_string("/proc/meminfo").ok()?, "MemTotal")
}

/// Total capacity of the `/dev/shm` tmpfs, in bytes, or `None` if it cannot be stat'd.
///
/// The SP1 native executor (x86-64 Linux) stages its trace ring and memory image here. A tmpfs too
/// small to hold even the bounded ring — the classic 64 MiB Docker default is the usual culprit —
/// makes every execute SIGBUS the instant the ring is touched, so the measure-pool spawn consults
/// this to refuse to stand up workers that would only SIGBUS-loop. Total capacity, not free space:
/// this is a one-time "could this tmpfs ever hold the ring" misconfiguration guard, and transient
/// occupancy is the host-memory ledger's concern, not this check's.
#[cfg(target_os = "linux")]
pub fn dev_shm_capacity_bytes() -> Option<u64> {
    let path = std::ffi::CString::new("/dev/shm").ok()?;
    // SAFETY: `statvfs` only reads through `path` and writes the out-param, which it fully
    // initializes on success (rc == 0); we read the struct only in that case.
    let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statvfs(path.as_ptr(), &mut st) } != 0 {
        return None;
    }
    (st.f_blocks as u64).checked_mul(st.f_frsize as u64)
}

/// Non-Linux: there is no `/dev/shm` tmpfs and the portable executor runs in-process, so there is
/// nothing to size. `None` means "cannot tell", which the caller treats as "do not block".
#[cfg(not(target_os = "linux"))]
pub fn dev_shm_capacity_bytes() -> Option<u64> {
    None
}

/// Windows: free physical memory, which (like `MemAvailable`) counts the reclaimable standby list.
///
/// RAM only. Windows also charges every allocation to its COMMIT limit, which is admitted
/// separately (`commit_figures`): most of a CUDA prover's commit is VRAM that is never in RAM.
#[cfg(windows)]
pub fn mem_available_bytes() -> Option<u64> {
    win32::memory_status().map(|s| s.avail_phys)
}

/// Windows: physical memory.
#[cfg(windows)]
pub fn mem_total_bytes() -> Option<u64> {
    win32::memory_status().map(|s| s.total_phys)
}

/// The second measure Windows admits a proof against, besides RAM: COMMIT, in bytes.
///
/// Windows has no overcommit: every allocation is charged against the commit limit (RAM plus page
/// files) when it is made, touched or not. And under WDDM every byte of GPU memory a process
/// allocates is charged too, one for one, while its working set and free RAM do not move (measured
/// here for `cudaMalloc`, `cudaMallocAsync` and `cuMemCreate`; NVIDIA: it is Windows' doing, and
/// GeForce cards cannot leave WDDM). So an SP1 proof on an RTX 5090 commits 63 GB with 37 GB of it
/// in RAM, and an idle SP1 server keeps 22 GB of VRAM and so 22 GB of commit.
///
/// Running into the limit does not necessarily fail: a page file whose maximum is above its current
/// size (system-managed, the default) grows on demand, so ordinary allocations and GPU allocations
/// past the limit still succeed (measured). `growth` is how far the page files can still grow,
/// within the free space of their disks.
///
/// The one thing that does fail at the limit is PINNED host memory (`cudaMallocHost`, measured: it
/// does not wait for the page file to grow). `free_now`, the commit free without any growth, is
/// what the margin for it (`PINNED_COMMIT_MARGIN_BYTES`) is checked against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommitFigures {
    /// Free commit plus page-file growth: what proofs may still commit.
    pub available: u64,
    /// The commit limit plus page-file growth: the most that can ever be committed.
    pub total: u64,
    /// Free commit without growth.
    pub free_now: u64,
    /// The commit limit as it is now, without growth.
    pub limit: u64,
}

/// Windows: the commit figures (`CommitFigures`); `None` elsewhere, where admission is by RAM alone.
#[cfg(windows)]
pub fn commit_figures() -> Option<CommitFigures> {
    win32::memory_status_with_growth().map(|s| commit_figures_of(&s))
}

#[cfg(not(windows))]
pub fn commit_figures() -> Option<CommitFigures> {
    None
}

/// `CommitFigures` from what Windows reports.
pub fn commit_figures_of(s: &WindowsMemoryStatus) -> CommitFigures {
    CommitFigures {
        available: s.commit_free.saturating_add(s.commit_growth),
        total: s.commit_limit.saturating_add(s.commit_growth),
        free_now: s.commit_free,
        limit: s.commit_limit,
    }
}

/// Free commit (without page-file growth) that a proof must find before it starts, beyond what it
/// will take: pinned host allocations fail at the commit limit instead of waiting for the page file
/// to grow (measured: `cudaMallocHost` of 2 GiB failed in 16 ms with 1 GiB free and succeeded with
/// 6 GiB free). Windows grows a page file once commit reaches 90% of the limit, so normally far
/// more than this is free. On a small machine it is a twentieth of the limit
/// (`pinned_commit_margin`), which stays below the tenth Windows keeps free by growing.
pub const PINNED_COMMIT_MARGIN_BYTES: u64 = 4 * 1024 * 1024 * 1024;

/// The pinned margin (`PINNED_COMMIT_MARGIN_BYTES`) for a commit `limit`.
pub fn pinned_commit_margin(limit: u64) -> u64 {
    PINNED_COMMIT_MARGIN_BYTES.min(limit / 20)
}

/// How a proof's host part can start, by `WorkerPool::reserve_commit`'s rule: `host_need` (the RAM
/// the admitted proofs have still to take, plus the pinned margin) must be free commit without
/// growth. `Now` when it is; `AfterGrowing(n)` when the page file can grow by the `n` short
/// (grow it first, `grow_commit`, then check again); `No` when not even its growth covers it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostCommitStart {
    Now,
    AfterGrowing(u64),
    No,
}

/// See `HostCommitStart`.
pub fn host_commit_start(figures: &CommitFigures, host_need: u64) -> HostCommitStart {
    if figures.free_now >= host_need {
        HostCommitStart::Now
    } else if figures.available >= host_need {
        HostCommitStart::AfterGrowing(host_need - figures.free_now)
    } else {
        HostCommitStart::No
    }
}

/// Windows: make the page files grow now so that `bytes` more than is free can be committed, by
/// committing that much (untouched: it takes no RAM) and releasing it at once; whether it did.
///
/// A system-managed page file grows only when commit reaches the limit (measured: it did not grow
/// at 90%), so proofs that count on its growth run commit to the very edge, where pinned host
/// memory fails rather than wait (`PINNED_COMMIT_MARGIN_BYTES`). Grown ahead of a proof, it holds:
/// measured, the extension was still there 20 s after the commit that caused it was released (and
/// gone within a minute), and once the proof's own allocations use it, it cannot shrink below
/// them. The commit is at the limit only for the moment the growth takes (about 0.1 s for 8 GiB).
pub fn grow_commit(bytes: u64) -> bool {
    #[cfg(windows)]
    {
        let Some(status) = win32::memory_status() else {
            return false;
        };
        let Ok(n) = usize::try_from(status.commit_free.saturating_add(bytes)) else {
            return false;
        };
        win32::commit_and_release(n)
    }
    #[cfg(not(windows))]
    {
        let _ = bytes;
        false
    }
}

/// How far page files can still grow, in bytes: each one's maximum less its current size, within
/// the free space of its disk less `PAGE_FILE_DISK_MARGIN_BYTES` (Windows will not fill a disk).
/// `page_files` holds (current size, maximum size, free space of its disk if known); a page file on
/// a disk whose free space cannot be read is not counted on to grow.
pub fn page_file_growth(page_files: &[(u64, u64, Option<u64>)]) -> u64 {
    page_files
        .iter()
        .fold(0u64, |sum, &(current, maximum, disk_free)| {
            let room = disk_free.map_or(0, |d| d.saturating_sub(PAGE_FILE_DISK_MARGIN_BYTES));
            sum.saturating_add(maximum.saturating_sub(current).min(room))
        })
}

/// Free disk space a growing page file is not counted on to take.
pub const PAGE_FILE_DISK_MARGIN_BYTES: u64 = 4 * 1024 * 1024 * 1024;

/// Physical memory, in bytes (`mem_total_bytes`, read without the cgroup or commit question).
pub fn physical_total_bytes() -> Option<u64> {
    #[cfg(windows)]
    {
        win32::memory_status().map(|s| s.total_phys)
    }
    #[cfg(not(windows))]
    {
        mem_total_bytes()
    }
}

/// What the pressure check (`classify_pressure`) reads as available: `mem_available_bytes`, except
/// on Windows, where it is the smaller of free RAM and what proofs may still commit
/// (`CommitFigures::available`), each counting what IDLE workers hold of it as free (`idle_ram`,
/// `idle_commit`): a proof that needs it stops them (`WorkerPool::idle_reclaimable_host_bytes`), so
/// braking on it would stop the dispatch that gives it back.
pub fn pressure_available_bytes(idle_ram: u64, idle_commit: u64) -> Option<u64> {
    #[cfg(windows)]
    {
        let s = win32::memory_status_with_growth()?;
        let commit = commit_figures_of(&s).available.saturating_add(idle_commit);
        Some(s.avail_phys.saturating_add(idle_ram).min(commit))
    }
    #[cfg(not(windows))]
    {
        let _ = (idle_ram, idle_commit);
        mem_available_bytes()
    }
}

/// Windows: `(commit limit, free commit)`, in bytes: physical memory plus page files, and what of
/// that no process has committed yet. `None` elsewhere.
#[cfg(windows)]
pub fn commit_bytes() -> Option<(u64, u64)> {
    win32::memory_status().map(|s| (s.commit_limit, s.commit_free))
}

#[cfg(not(windows))]
pub fn commit_bytes() -> Option<(u64, u64)> {
    None
}

/// What Windows reports, in bytes: `GlobalMemoryStatusEx`, and how far the page files can grow
/// (`page_file_growth`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WindowsMemoryStatus {
    pub total_phys: u64,
    pub avail_phys: u64,
    /// Physical memory plus page files, as they are now: what all processes together may commit.
    pub commit_limit: u64,
    /// The commit limit less what is committed now.
    pub commit_free: u64,
    /// How much larger the page files can still grow (`page_file_growth`): 0 for a fixed one.
    pub commit_growth: u64,
}

/// What a process tree holds, in bytes (`tree_memory`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TreeMemory {
    /// Committed now (private commit charge, `PagefileUsage`), which on Windows includes the VRAM
    /// the processes allocated.
    pub commit: u64,
    /// In RAM now: the private working set (pinned memory included), not the pages shared with
    /// other processes.
    pub ram: u64,
}

/// Windows: what a process and every process it started (`process_tree`) hold now, summed
/// (`TreeMemory`). `None` when the root cannot be read (exited, or a different process with the
/// number).
#[cfg(windows)]
pub fn tree_memory(root: u32, root_started: Option<u64>) -> Option<TreeMemory> {
    let tree = process_tree(root, root_started);
    let (root_pid, _) = *tree.first()?;
    let mut sum = TreeMemory::default();
    let mut root_read = false;
    for (pid, started) in tree {
        let Some(process) = win32::open(
            pid,
            win32::PROCESS_QUERY_LIMITED_INFORMATION | win32::PROCESS_VM_READ,
        ) else {
            continue;
        };
        // The number may have been reused since the tree was walked.
        if process.creation_time() != Some(started) {
            continue;
        }
        let Some(m) = process.memory() else {
            continue;
        };
        root_read |= pid == root_pid;
        sum.commit = sum.commit.saturating_add(m.commit);
        sum.ram = sum.ram.saturating_add(m.ram);
    }
    root_read.then_some(sum)
}

/// Pull one `kB` field out of `/proc/meminfo` and return it in bytes.
///
/// Split out so the parse is testable without a particular host: the field order and the presence
/// of `MemAvailable` both vary by kernel version.
pub(crate) fn parse_meminfo_kb(text: &str, key: &str) -> Option<u64> {
    for line in text.lines() {
        let Some((name, rest)) = line.split_once(':') else {
            continue;
        };
        if name != key {
            continue;
        }
        let kb: u64 = rest.split_whitespace().next()?.parse().ok()?;
        return kb.checked_mul(1024);
    }
    None
}

/// `full avg10` from `/proc/pressure/memory`, as a percentage.
///
/// `None` when PSI is unavailable (`CONFIG_PSI` off, or an old kernel), in which case callers must
/// fall back to a free-memory floor rather than treating the absence as "no pressure".
pub fn memory_stall_percent() -> Option<f64> {
    parse_pressure_full_avg10(&std::fs::read_to_string("/proc/pressure/memory").ok()?)
}

pub(crate) fn parse_pressure_full_avg10(text: &str) -> Option<f64> {
    for line in text.lines() {
        if !line.starts_with("full ") {
            continue;
        }
        for field in line.split_whitespace() {
            if let Some(v) = field.strip_prefix("avg10=") {
                return v.parse().ok();
            }
        }
    }
    None
}

/// Cumulative count of processes in our cgroup subtree killed by ANY OOM killer.
///
/// This is the signal that makes a kill attributable, and getting it from the right place matters:
///
/// * A worker's own scope cgroup is destroyed the instant its last process exits (verified), so
///   reading the victim's own `memory.events` after the fact always loses the race.
/// * `memory.events` is HIERARCHICAL — an ancestor's counter includes its descendants' kills
///   (verified: `app.slice` went 2 -> 3 when a child scope was OOM-killed) — and the ancestor
///   persists. So we read an ancestor and compare across the worker's lifetime.
/// * cgroup v2 defines `oom_kill` as kills by any OOM killer, so this covers BOTH shapes we have
///   seen: a cgroup-limit kill and a global one.
pub fn oom_kill_count() -> Option<u64> {
    let events = std::fs::read_to_string(oom_events_path()?).ok()?;
    parse_oom_kill(&events)
}

pub(crate) fn parse_oom_kill(text: &str) -> Option<u64> {
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("oom_kill ") {
            return rest.trim().parse().ok();
        }
    }
    None
}

/// The ancestor cgroup whose `memory.events` we watch.
///
/// Our own cgroup is not enough: an adopted worker lives in a SIBLING scope under `app.slice`, not
/// under us. We walk up to a level that contains both.
fn oom_events_path() -> Option<std::path::PathBuf> {
    let own = std::fs::read_to_string("/proc/self/cgroup").ok()?;
    // cgroup v2: a single line, "0::/path".
    let rel = own
        .lines()
        .next()?
        .rsplit_once("::")
        .map(|(_, p)| p)?
        .trim();
    let mut dir = std::path::PathBuf::from("/sys/fs/cgroup").join(rel.trim_start_matches('/'));
    // Walk up until we find a level that has memory.events AND is high enough to contain the
    // transient scopes our workers are adopted into (those are siblings of our own scope).
    for _ in 0..6 {
        if !dir.pop() {
            break;
        }
        let candidate = dir.join("memory.events");
        if candidate.exists() {
            return Some(candidate);
        }
    }
    None
}

/// The ceiling to put on a single worker.
///
/// Deliberately generous: this layer's job is "no ONE worker can take the host down", not "the sum
/// of workers fits". Making it tight enough to guarantee the sum would refuse a lone proof that
/// would have fitted perfectly well — on this 28 GB box, dividing by two slots gives 12.5 GB and
/// would kill a single 17.6 GB SP1 proof that had the machine to itself. Keeping the workers from
/// summing past RAM is admission control's job, where it can be done with knowledge of what is
/// already in flight.
pub fn worker_memory_ceiling_bytes(reserve: u64) -> Option<u64> {
    // Physical memory, not Windows' commit limit (`mem_total_bytes` there): SP1 sizes pinned host
    // buffers from this, and pinned memory has to sit in RAM.
    let total = physical_total_bytes()?;
    total.checked_sub(reserve).filter(|c| *c > 0)
}

/// Put a kernel-enforced memory ceiling on an ALREADY-SPAWNED pid, best effort.
///
/// Adoption rather than a wrapper, and that is the whole point. `systemd-run --scope` FORKS: the
/// pid the caller holds is the wrapper's, not the worker's (verified — we spawned a `sleep` through
/// it and got two different pids). Every pid-keyed thing in this crate would break on that:
/// `child.id()`, the `waitid` exit probe, `exit_reason`, the `reaped` gate, the process-group sweep,
/// and `PR_SET_PDEATHSIG` (which would protect the wrapper, leaving the real worker unparented).
/// Handing systemd a pid we already own keeps all of it intact — the pid, the process group and the
/// parent relationship are untouched, and the cap still comes from the kernel.
///
/// `MemorySwapMax=0` is deliberate. Swap turns a kill into a stall, and for a prover that is the
/// worse outcome: a killed proof can be released and retried, whereas a thrashing one takes the
/// host's responsiveness with it — which is the failure this module exists to prevent. A cgroup
/// kill otherwise burns gigabytes of swap (4 GB, in one observed case) on its way down for no
/// benefit.
///
/// Best effort by design: no systemd user bus, no `busctl`, a different init, or a container
/// without delegation all mean no cap, and that must not stop a worker from starting. The
/// `oom_score_adj` layer still protects the host in that case.
///
/// Known limit, and it is wider than it looks: `StartTransientUnit` returns a systemd JOB, so the
/// pid is moved into the capped cgroup ASYNCHRONOUSLY — `Ok` means "systemd accepted the request",
/// not "the ceiling is in force". Between `spawn` and the job completing, a process that allocates
/// catastrophically can still escape the cap. Workers perform a handshake before doing any real
/// work, so the margin is wide in practice, but this is why the `oom_score_adj` layer is not
/// redundant: it is in effect from `exec` onwards with no window at all.
/// The transient-scope unit name for a worker, derived purely from `(unit_hint, pid)`.
///
/// Deterministic on purpose, so the readers that need to prove provenance — `peak_memory_of_pid`,
/// `current_memory_of_pid` — can reconstruct the expected name instead of the dispatcher having to
/// carry it in shared state. Those readers take no lock (avoiding the `bus_id_for_slot` deadlock),
/// so there is nowhere lock-free for a per-worker string to live.
pub fn cap_unit_name(unit_hint: &str, pid: u32) -> String {
    format!(
        "{CAP_UNIT_PREFIX}{}-{}.scope",
        sanitize_unit(unit_hint),
        pid
    )
}

/// Windows has no resident-memory ceiling that kills: a Job Object limits COMMITTED memory, which
/// for a CUDA process is no measure of what it holds (see the module docs), so a cap sized from RAM
/// could kill a proof that fits. Until one is measured against real provers there is none, and
/// admission control is the layer that keeps workers from summing past RAM.
#[cfg(windows)]
pub fn cap_process_memory(_pid: u32, _unit_hint: &str, _max_bytes: u64) -> Result<String, String> {
    Err("no per-worker memory ceiling on Windows".to_string())
}

#[cfg(not(windows))]
pub fn cap_process_memory(pid: u32, unit_hint: &str, max_bytes: u64) -> Result<String, String> {
    let unit = cap_unit_name(unit_hint, pid);
    let mut cmd = std::process::Command::new("busctl");
    cmd.args([
        "--user",
        "call",
        "org.freedesktop.systemd1",
        "/org/freedesktop/systemd1",
        "org.freedesktop.systemd1.Manager",
        "StartTransientUnit",
        "ssa(sv)a(sa(sv))",
        &unit,
        "fail",
        // FOUR properties. `CollectMode` is the fourth and it is not optional: systemd's default
        // (`inactive`) unloads a transient unit when it goes inactive but NOT when it FAILS, and a
        // worker that is SIGKILLed — by its own ceiling, by the 20-proof recycle, by a timeout, by
        // shutdown phase 3 — leaves a failed unit behind every single time (a scope can sit
        // `loaded failed` long after its process is gone). Nothing here ever calls StopUnit or
        // ResetFailed, so a long run accumulates one per spawn. Worse, the unit name embeds the pid
        // and the mode is `fail`, so a lingering unit whose pid gets reused makes StartTransientUnit
        // fail and that worker runs UNCAPPED, reported only as a warning.
        "4",
        "CollectMode",
        "s",
        "inactive-or-failed",
        "PIDs",
        "au",
        "1",
        &pid.to_string(),
        "MemoryMax",
        "t",
        &max_bytes.to_string(),
        "MemorySwapMax",
        "t",
        "0",
        "0",
    ]);
    match zkminer_prover_protocol::proc::output_with_timeout(&mut cmd, CAP_TIMEOUT, 16 * 1024) {
        zkminer_prover_protocol::proc::Outcome::Ran { success: true, .. } => Ok(unit),
        other => Err(other.describe()),
    }
}

/// systemd unit names accept a restricted character set; anything else must be replaced rather than
/// producing an unusable name (backend keys contain `:`, as in `risc0:cuda:0`).
pub(crate) fn sanitize_unit(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect()
}

/// Peak memory of a pid's whole cgroup SUBTREE, in bytes.
///
/// `memory.peak` is the right source and the only cheap one: it is a true high-water mark, it needs
/// no sampling, and it covers DESCENDANTS — verified at 319 MB while a grandchild held 300 MB, which
/// is what makes `sp1-gpu-server` (forked by the SDK, two levels down) visible at all.
///
/// Two caveats, both load-bearing:
///
/// * It must be read while the worker is ALIVE. A transient scope is destroyed with its last
///   process, taking the counter with it (verified). So the benchmark reads this before shutting a
///   worker down, not after.
/// * cgroup v2 does NOT migrate existing charges when a pid is adopted, so this counts only what was
///   allocated after the move. Workers are adopted within milliseconds of `spawn`, having allocated
///   almost nothing, so the undercount is negligible — but it is also why `cap_process_memory`'s
///   ceiling is not retroactive.
pub fn peak_memory_of_pid(pid: u32, expected_unit: Option<&str>) -> Option<u64> {
    let cg = std::fs::read_to_string(format!("/proc/{pid}/cgroup")).ok()?;
    let rel = cg.lines().next()?.rsplit_once("::").map(|(_, p)| p)?.trim();

    // ONLY the cgroup we created for THIS worker, matched by its exact unit name. Without a
    // provenance check the function silently measures whatever cgroup the pid happens to sit in, and
    // when the cap did not apply — a supported state, since it is best effort — that is the MINER'S
    // OWN cgroup. On this host the session scope's `memory.peak` reads 16.7 GB and the enclosing
    // `app.slice` 25.8 GB, both lifetime subtree high-water marks having nothing to do with one
    // proof. Such a figure would be persisted as the backend's expected peak and refuse every job
    // from then on.
    //
    // A prefix check like `leaf.starts_with("zkminer-")` is a NAME, not provenance, and is not
    // enough: a leftover `zkminer-gputest.scope` can be sitting in the hierarchy, and the natural
    // way to run a miner under a limit is `systemd-run --user --unit=zkminer-soak --scope`. In
    // either case a worker whose cap failed sits in a cgroup whose leaf matches the prefix, and a
    // prefix guard would wave through exactly the lifetime figure it is meant to reject. An exact
    // match against the unit `cap_process_memory` reported cannot be satisfied by an ancestor.
    let Some(unit) = expected_unit else {
        return None;
    };
    if rel.rsplit('/').next() != Some(unit) {
        return None;
    }

    let path = std::path::PathBuf::from("/sys/fs/cgroup")
        .join(rel.trim_start_matches('/'))
        .join("memory.peak");
    std::fs::read_to_string(path).ok()?.trim().parse().ok()
}

/// Bytes this worker's cgroup holds in ANONYMOUS memory right now.
///
/// Anonymous, not `memory.current`, and the distinction is the whole correctness of the credit this
/// feeds. `memory.current` charges the page cache too, and `MemAvailable` ALREADY counts reclaimable
/// page cache as available — so crediting `memory.current` against a proof's expected peak counts
/// those pages twice: once as headroom and once as a discount. On this box a single user slice
/// reads `anon 465 MiB` against `file 18.3 GiB`, so the over-credit is not marginal, it is most of
/// the number.
///
/// Left uncorrected, that compounds with an unfloored subtraction into the original freeze: once the
/// credit exceeds the expected peak the increment is zero, `fits_now` reduces to "is the host reserve
/// free", and four concurrent provers are admitted onto a box with 4 GiB left — the exact freeze
/// this guards against — and `can_admit` documents on `fits_now` why anon, unlike `memory.current`,
/// is safe to credit in full.
///
/// Anonymous pages are the right quantity on two counts: they are what a prover actually holds, and
/// with `MemorySwapMax=0` on the worker's scope they cannot be reclaimed, so `MemAvailable` genuinely
/// excludes them.
///
/// `None` on the same terms as `peak_memory_of_pid`, and for the same reason: a figure from a cgroup
/// we did not create describes something other than this worker.
#[cfg(unix)]
pub fn anon_memory_of_pid(pid: u32, expected_unit: Option<&str>) -> Option<u64> {
    let cg = std::fs::read_to_string(format!("/proc/{pid}/cgroup")).ok()?;
    let rel = cg.lines().next()?.rsplit_once("::").map(|(_, p)| p)?.trim();
    // Exact unit, for the reason given on `peak_memory_of_pid`.
    let unit = expected_unit?;
    if rel.rsplit('/').next() != Some(unit) {
        return None;
    }
    let path = std::path::PathBuf::from("/sys/fs/cgroup")
        .join(rel.trim_start_matches('/'))
        .join("memory.stat");
    parse_memory_stat_anon(&std::fs::read_to_string(path).ok()?)
}

/// The `anon` line of a cgroup v2 `memory.stat`, in bytes.
pub(crate) fn parse_memory_stat_anon(text: &str) -> Option<u64> {
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("anon ") {
            return rest.trim().parse().ok();
        }
    }
    None
}

/// Prefix of every transient scope this module creates, and the marker that tells a cgroup of ours
/// from one we merely happen to be sitting in.
pub(crate) const CAP_UNIT_PREFIX: &str = "zkminer-";

/// Fallback peak for a worker with no cgroup of its own: the sum of `VmHWM` across its process group.
///
/// Over-counts, because the members' peaks need not be simultaneous — which is the safe direction
/// for an admission decision. `proc_root` is a parameter so the arithmetic is testable against a
/// synthetic tree.
pub fn process_group_peak_bytes(proc_root: &std::path::Path, pgid: i32) -> Option<u64> {
    let entries = std::fs::read_dir(proc_root).ok()?;
    let mut total = 0u64;
    let mut found = false;
    for e in entries.flatten() {
        if e.file_name()
            .to_str()
            .and_then(|n| n.parse::<i32>().ok())
            .is_none()
        {
            continue;
        }
        // Group membership FIRST: `stat` is one short line, `status` is ~60, and on a busy host
        // most of `/proc` is not ours. Reading `status` for every pid and then discarding it would
        // be the wrong order.
        let Ok(stat) = std::fs::read_to_string(e.path().join("stat")) else {
            continue;
        };
        if group_of_stat(&stat) != Some(pgid) {
            continue;
        }
        let Ok(status) = std::fs::read_to_string(e.path().join("status")) else {
            continue;
        };
        if let Some(kb) = parse_status_kb(&status, "VmHWM") {
            total = total.saturating_add(kb);
            found = true;
        }
    }
    found.then_some(total)
}

/// Parent pid from a `/proc/<pid>/stat` line.
///
/// Field 4, read past the last `)` so a `comm` containing spaces and parentheses cannot shift the
/// offsets. Same technique as `group_of_stat`, which reads field 5 two positions further on.
#[cfg_attr(windows, allow(dead_code))] // Windows reads parents from a snapshot: `parent_pid`
pub(crate) fn parent_of_stat(stat: &str) -> Option<i32> {
    let rest = stat.get(stat.rfind(')')? + 1..)?;
    rest.split_whitespace().nth(1)?.parse().ok()
}

/// Kernel start time of a process, from field 22 of `/proc/<pid>/stat`, in clock ticks since boot.
///
/// The one field that makes a pid an identity rather than a number. Read past the last `)` so a
/// `comm` containing spaces and parentheses cannot shift the offsets.
pub(crate) fn starttime_of_stat(stat: &str) -> Option<u64> {
    let rest = stat.get(stat.rfind(')')? + 1..)?;
    rest.split_whitespace().nth(19)?.parse().ok()
}

/// `(pid, starttime)` for a live process, or `None` if it is gone.
///
/// Captured at spawn and re-checked before any signal: see `pid_is_our_worker`.
#[cfg(unix)]
pub fn pid_starttime(pid: u32) -> Option<u64> {
    starttime_of_stat(&std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?)
}

/// Is this pid still OUR worker, rather than a stranger that inherited the number?
///
/// The guard on every `kill` issued from a pid held in an `AtomicU32`. Loading that atomic and
/// signalling are not atomic with respect to the reap, and the existing design — zero the atomic
/// before every reap — only protects a signaller that loads AFTER the store. One that already
/// loaded is unprotected, and the window is as long as whatever runs in between: at the proving
/// watchdog's site that includes a `tracing::error!`, which under a contended file appender is
/// milliseconds. After the reap the kernel may hand the number to anything, and the next statement
/// is `kill(-pid, SIGKILL)` — a signal to an entire unrelated process GROUP, which on a developer's
/// box could be their login session. `may_signal_group`'s own-pgid refusal does not help: it screens
/// our group, not a stranger's.
///
/// Two facts settle it, both from one short read of `/proc/<pid>/stat`:
///
/// * **Parent.** Every worker is a direct child of this process. A recycled pid belongs to something
///   the kernel gave the number to, whose parent is not us. (An unreaped zombie of ours still reads
///   as our child, and signalling a zombie is a no-op — the safe direction.)
/// * **Group leader.** `pre_exec` calls `setpgid(0, 0)`, so a worker's pgid equals its pid. This is
///   what makes `kill(-pid, ..)` meaningful at all, and it rules out signalling the group of a
///   process that merely happens to be our child.
///
/// Cheaper than `pidfd_open` plumbing and needs no extra per-worker state, which matters because the
/// pid atomic is written from sixteen places. Unreadable `/proc` answers `false`: not signalling a
/// worker leaks a process, while signalling a stranger's group can take down the machine.
#[cfg(unix)]
pub fn pid_is_our_worker(pid: u32, expected_starttime: Option<u64>) -> bool {
    if pid == 0 {
        return false;
    }
    let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) else {
        return false;
    };
    let ours = std::process::id() as i32;
    if parent_of_stat(&stat) != Some(ours) || group_of_stat(&stat) != Some(pid as i32) {
        return false;
    }
    // The decisive check when we have it. Parent-and-group alone cannot distinguish our worker from
    // our NEXT worker: the likeliest recipient of a pid this process just freed is another worker
    // this same process forks seconds later, which satisfies both conditions — so the guard would
    // pass and the kill would land on a different, healthy, mid-proof worker's group. A start time
    // cannot be inherited, so pid plus start time is an identity.
    //
    // `None` means the caller never captured one, in which case parent-and-group is all we have; that
    // is still far better than the bare number, and it is the safe direction (we may fail to signal
    // a worker, rather than signal a stranger).
    match expected_starttime {
        Some(expected) => starttime_of_stat(&stat) == Some(expected),
        None => true,
    }
}

/// Windows: pid plus creation time is the identity, as pid plus start time is on Linux (Windows
/// has no process groups, and a worker's parent is not cheaply readable). Without a captured
/// creation time the answer is `false`: the safe direction, as on Linux.
#[cfg(windows)]
pub fn pid_is_our_worker(pid: u32, expected_starttime: Option<u64>) -> bool {
    match (pid, expected_starttime) {
        (0, _) | (_, None) => false,
        (pid, Some(expected)) => {
            win32::open(pid, win32::PROCESS_QUERY_LIMITED_INFORMATION)
                .and_then(|process| process.creation_time())
                == Some(expected)
        }
    }
}

/// Windows: the process's creation time (a FILETIME), which a recycled pid cannot share.
#[cfg(windows)]
pub fn pid_starttime(pid: u32) -> Option<u64> {
    win32::open(pid, win32::PROCESS_QUERY_LIMITED_INFORMATION)?.creation_time()
}

/// Windows: terminate `pid` if it is still our worker, which Unix does with `kill(-pid, SIGKILL)`
/// after `pid_is_our_worker`. One handle serves both the identity check and the kill, and an open
/// handle keeps its process's pid from being reused, so no other process can be hit in between.
/// Returns whether it was terminated.
#[cfg(windows)]
pub fn terminate_if_our_worker(pid: u32, expected_starttime: Option<u64>) -> bool {
    let Some(expected) = expected_starttime.filter(|_| pid != 0) else {
        return false;
    };
    let Some(process) = win32::open(
        pid,
        win32::PROCESS_QUERY_LIMITED_INFORMATION | win32::PROCESS_TERMINATE,
    ) else {
        return false;
    };
    process.creation_time() == Some(expected) && process.terminate()
}

/// Windows: `root` and every process it started, directly or not, each with its creation time:
/// what Linux finds by process group, which Windows does not have. A process counts as a child only
/// if it started after its recorded parent (a recorded parent pid may since belong to another
/// process), and one whose creation time cannot be read is left out, with what it started.
///
/// `root_started` is the root's own start time, when known: a live process with another start time
/// is a stranger given the number, and yields nothing. A root that has already exited is still the
/// parent its children recorded, so they are found from that start time.
#[cfg(windows)]
pub fn process_tree(root: u32, root_started: Option<u64>) -> Vec<(u32, u64)> {
    let Some(root_started) = tree_root_started(pid_starttime(root), root_started) else {
        return Vec::new();
    };
    tree_from(
        root,
        root_started,
        &win32::recorded_parents(),
        pid_starttime,
    )
}

/// The start time `process_tree` walks a tree from: the live root's (`now`), unless it is not the
/// `expected` one (a stranger given the number: no tree); else the expected one, for a root that
/// has exited; `None` when neither is known.
#[cfg_attr(not(windows), allow(dead_code))]
fn tree_root_started(now: Option<u64>, expected: Option<u64>) -> Option<u64> {
    match (now, expected) {
        (Some(now), Some(expected)) if now != expected => None,
        (Some(now), _) => Some(now),
        (None, Some(expected)) => Some(expected),
        (None, None) => None,
    }
}

/// `process_tree`'s walk: from `root`, started at `root_started`, every process whose recorded
/// parent (`parents`: pid, recorded parent pid) is in the tree and that started no earlier than
/// that parent (`starttime`), with its start time.
#[cfg_attr(not(windows), allow(dead_code))]
fn tree_from(
    root: u32,
    root_started: u64,
    parents: &[(u32, u32)],
    starttime: impl Fn(u32) -> Option<u64>,
) -> Vec<(u32, u64)> {
    let mut tree = vec![(root, root_started)];
    let mut next = 0;
    while next < tree.len() {
        let (parent, parent_started) = tree[next];
        next += 1;
        for &(pid, recorded) in parents {
            if recorded != parent || pid == parent || tree.iter().any(|(p, _)| *p == pid) {
                continue;
            }
            if let Some(started) = starttime(pid).filter(|s| *s >= parent_started) {
                tree.push((pid, started));
            }
        }
    }
    tree
}

/// Windows: the process that started `pid`, which Linux reads from `/proc/<pid>/stat`.
///
/// Windows records the parent's pid at creation and keeps it after the parent exits, by which time
/// the number may belong to another process. One that started after `pid` cannot be its parent, so
/// it is not returned; nor is one whose start time cannot be read, so a walk up the tree stops there
/// rather than guessing.
#[cfg(windows)]
pub fn parent_pid(pid: u32) -> Option<u32> {
    let parent = win32::recorded_parent(pid)?;
    let started = pid_starttime(pid)?;
    (parent != 0 && pid_starttime(parent)? <= started).then_some(parent)
}

#[cfg(windows)]
mod win32 {
    use std::ffi::c_void;

    pub const PROCESS_TERMINATE: u32 = 0x0001;
    pub const PROCESS_VM_READ: u32 = 0x0010;
    pub const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;

    #[repr(C)]
    #[derive(Default)]
    struct FileTime {
        low: u32,
        high: u32,
    }

    #[repr(C)]
    struct MemoryStatusEx {
        length: u32,
        memory_load: u32,
        total_phys: u64,
        avail_phys: u64,
        total_page_file: u64,
        avail_page_file: u64,
        total_virtual: u64,
        avail_virtual: u64,
        avail_extended_virtual: u64,
    }

    /// Physical memory and commit, in bytes.
    pub fn memory_status() -> Option<super::WindowsMemoryStatus> {
        let mut status = MemoryStatusEx {
            length: std::mem::size_of::<MemoryStatusEx>() as u32,
            memory_load: 0,
            total_phys: 0,
            avail_phys: 0,
            total_page_file: 0,
            avail_page_file: 0,
            total_virtual: 0,
            avail_virtual: 0,
            avail_extended_virtual: 0,
        };
        let ok = unsafe { GlobalMemoryStatusEx(&mut status) };
        (ok != 0).then_some(super::WindowsMemoryStatus {
            total_phys: status.total_phys,
            avail_phys: status.avail_phys,
            // `ullTotalPageFile`/`ullAvailPageFile` are, despite their names, the commit limit and
            // what is left of it.
            commit_limit: status.total_page_file,
            commit_free: status.avail_page_file,
            // Read only where it is needed (`memory_status_with_growth`): it asks for every page
            // file and the free space of its disk, and this runs every `LOW_WATER_SAMPLE`.
            commit_growth: 0,
        })
    }

    /// `memory_status`, with how far the page files can grow (`super::page_file_growth`). The
    /// growth is read at most every `GROWTH_REFRESH`: the claim gate asks per candidate job, and
    /// a page file's maximum and its disk's free space move slowly.
    pub fn memory_status_with_growth() -> Option<super::WindowsMemoryStatus> {
        const GROWTH_REFRESH: std::time::Duration = std::time::Duration::from_secs(2);
        let mut status = memory_status()?;
        let mut cached = GROWTH.lock().unwrap_or_else(|e| e.into_inner());
        status.commit_growth = match *cached {
            Some((at, growth)) if at.elapsed() < GROWTH_REFRESH => growth,
            _ => {
                let growth = super::page_file_growth(&page_files());
                *cached = Some((std::time::Instant::now(), growth));
                growth
            }
        };
        Some(status)
    }

    /// The last page-file growth read, and when (`memory_status_with_growth`).
    static GROWTH: std::sync::Mutex<Option<(std::time::Instant, u64)>> =
        std::sync::Mutex::new(None);

    const MEM_COMMIT: u32 = 0x1000;
    const MEM_RESERVE: u32 = 0x2000;
    const MEM_RELEASE: u32 = 0x8000;
    const PAGE_READWRITE: u32 = 0x04;

    /// Commit `bytes` (untouched) and release them; whether the commit succeeded.
    pub fn commit_and_release(bytes: usize) -> bool {
        let p = unsafe {
            VirtualAlloc(
                std::ptr::null_mut(),
                bytes,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            )
        };
        if p.is_null() {
            return false;
        }
        unsafe { VirtualFree(p, 0, MEM_RELEASE) };
        // The page file just grew: the growth left is less than the cached figure.
        *GROWTH.lock().unwrap_or_else(|e| e.into_inner()) = None;
        true
    }

    /// `SystemPageFileInformationEx`: one `SYSTEM_PAGEFILE_INFORMATION_EX` per page file.
    const SYSTEM_PAGE_FILE_INFORMATION_EX: u32 = 144;
    const STATUS_INFO_LENGTH_MISMATCH: i32 = 0xC000_0004_u32 as i32;
    /// The sizes `SYSTEM_PAGEFILE_INFORMATION_EX` reports are in pages of this size.
    const PAGE_FILE_PAGE: u64 = 4096;

    /// Every page file's (current size, maximum size, free space on its disk), in bytes, from
    /// `NtQuerySystemInformation(SystemPageFileInformationEx)`, which needs no privilege. Empty when
    /// it cannot be read: the page files are then not counted on to grow.
    pub fn page_files() -> Vec<(u64, u64, Option<u64>)> {
        // The layout read below is the 64-bit one.
        if cfg!(not(target_pointer_width = "64")) {
            return Vec::new();
        }
        let mut buf: Vec<u64> = vec![0; 512];
        let mut status = STATUS_INFO_LENGTH_MISMATCH;
        for _ in 0..4 {
            let mut returned = 0u32;
            status = unsafe {
                NtQuerySystemInformation(
                    SYSTEM_PAGE_FILE_INFORMATION_EX,
                    buf.as_mut_ptr().cast(),
                    (buf.len() * 8) as u32,
                    &mut returned,
                )
            };
            if status != STATUS_INFO_LENGTH_MISMATCH {
                break;
            }
            let len = buf.len() * 2;
            buf.resize(len, 0);
        }
        if status != 0 {
            return Vec::new();
        }
        let bytes: &[u8] =
            unsafe { std::slice::from_raw_parts(buf.as_ptr().cast(), buf.len() * 8) };
        let base = bytes.as_ptr() as usize;
        let u32_at = |off: usize| -> Option<u32> {
            Some(u32::from_ne_bytes(
                bytes.get(off..off + 4)?.try_into().ok()?,
            ))
        };
        let mut out = Vec::new();
        let mut seen: Vec<Option<String>> = Vec::new();
        let mut at = 0usize;
        // x64 `SYSTEM_PAGEFILE_INFORMATION_EX`: NextEntryOffset @0, TotalSize @4, TotalInUse @8,
        // PeakUsage @12, PageFileName (UNICODE_STRING: Length u16 @16, Buffer @24), MinimumSize
        // @32, MaximumSize @36; sizes in pages. An entry with TotalSize 0 means there is none.
        for _ in 0..64 {
            let (Some(next), Some(total), Some(maximum), Some(name_len)) = (
                u32_at(at),
                u32_at(at + 4),
                u32_at(at + 36),
                bytes
                    .get(at + 16..at + 18)
                    .map(|b| u16::from_ne_bytes([b[0], b[1]])),
            ) else {
                break;
            };
            if total == 0 {
                break;
            }
            let name_ptr = bytes
                .get(at + 24..at + 32)
                .map(|b| u64::from_ne_bytes(b.try_into().unwrap_or([0; 8])) as usize)
                .unwrap_or(0);
            // The name's buffer lies in the same output buffer; read it only from there.
            let name = name_ptr
                .checked_sub(base)
                .and_then(|off| bytes.get(off..off.checked_add(name_len as usize)?))
                .map(|b| {
                    String::from_utf16_lossy(
                        &b.chunks_exact(2)
                            .map(|c| u16::from_ne_bytes([c[0], c[1]]))
                            .collect::<Vec<_>>(),
                    )
                })
                .unwrap_or_default();
            // One disk's free space can be grown into once: a second page file on the same disk is
            // not counted on to grow.
            let drive = name
                .trim_start_matches(r"\??\")
                .get(..2)
                .map(str::to_ascii_uppercase);
            let disk = if drive.is_some() && seen.contains(&drive) {
                Some(0)
            } else {
                seen.push(drive);
                disk_free_of(&name)
            };
            out.push((
                u64::from(total) * PAGE_FILE_PAGE,
                u64::from(maximum) * PAGE_FILE_PAGE,
                disk,
            ));
            if next == 0 {
                break;
            }
            at += next as usize;
        }
        out
    }

    /// Free space on the disk a page file named like `\??\C:\pagefile.sys` is on.
    fn disk_free_of(name: &str) -> Option<u64> {
        let drive = name.trim_start_matches(r"\??\");
        let root: Vec<u16> = drive
            .get(..3)
            .filter(|r| r.as_bytes().get(1) == Some(&b':'))?
            .encode_utf16()
            .chain([0])
            .collect();
        let mut free = 0u64;
        let ok = unsafe {
            GetDiskFreeSpaceExW(
                root.as_ptr(),
                &mut free,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        (ok != 0).then_some(free)
    }

    /// `PROCESS_MEMORY_COUNTERS_EX2` (Windows 10 1809 and later).
    #[repr(C)]
    #[derive(Default)]
    struct ProcessMemoryCountersEx2 {
        cb: u32,
        page_fault_count: u32,
        peak_working_set_size: usize,
        working_set_size: usize,
        quota_peak_paged_pool_usage: usize,
        quota_paged_pool_usage: usize,
        quota_peak_non_paged_pool_usage: usize,
        quota_non_paged_pool_usage: usize,
        pagefile_usage: usize,
        peak_pagefile_usage: usize,
        private_usage: usize,
        private_working_set_size: usize,
        shared_commit_usage: u64,
    }

    const TH32CS_SNAPPROCESS: u32 = 0x0000_0002;

    #[repr(C)]
    struct ProcessEntry32W {
        size: u32,
        usage: u32,
        process_id: u32,
        default_heap_id: usize,
        module_id: u32,
        threads: u32,
        parent_process_id: u32,
        pri_class_base: i32,
        flags: u32,
        exe_file: [u16; 260],
    }

    /// Every process's `(pid, recorded parent pid)`, from one snapshot.
    pub fn recorded_parents() -> Vec<(u32, u32)> {
        let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
        if snapshot.is_null() || snapshot as isize == -1 {
            return Vec::new();
        }
        let snapshot = Process(snapshot);
        let mut entry = ProcessEntry32W {
            size: std::mem::size_of::<ProcessEntry32W>() as u32,
            usage: 0,
            process_id: 0,
            default_heap_id: 0,
            module_id: 0,
            threads: 0,
            parent_process_id: 0,
            pri_class_base: 0,
            flags: 0,
            exe_file: [0; 260],
        };
        let mut all = Vec::new();
        let mut more = unsafe { Process32FirstW(snapshot.0, &mut entry) } != 0;
        while more {
            all.push((entry.process_id, entry.parent_process_id));
            more = unsafe { Process32NextW(snapshot.0, &mut entry) } != 0;
        }
        all
    }

    /// The parent pid Windows recorded when `pid` was created, from a process snapshot.
    pub fn recorded_parent(pid: u32) -> Option<u32> {
        let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
        if snapshot.is_null() || snapshot as isize == -1 {
            return None;
        }
        let snapshot = Process(snapshot); // closed on drop, like a process handle
        let mut entry = ProcessEntry32W {
            size: std::mem::size_of::<ProcessEntry32W>() as u32,
            usage: 0,
            process_id: 0,
            default_heap_id: 0,
            module_id: 0,
            threads: 0,
            parent_process_id: 0,
            pri_class_base: 0,
            flags: 0,
            exe_file: [0; 260],
        };
        let mut more = unsafe { Process32FirstW(snapshot.0, &mut entry) } != 0;
        while more {
            if entry.process_id == pid {
                return Some(entry.parent_process_id);
            }
            more = unsafe { Process32NextW(snapshot.0, &mut entry) } != 0;
        }
        None
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn CreateToolhelp32Snapshot(flags: u32, pid: u32) -> *mut c_void;
        fn Process32FirstW(snapshot: *mut c_void, entry: *mut ProcessEntry32W) -> i32;
        fn Process32NextW(snapshot: *mut c_void, entry: *mut ProcessEntry32W) -> i32;
        fn GlobalMemoryStatusEx(status: *mut MemoryStatusEx) -> i32;
        fn OpenProcess(access: u32, inherit: i32, pid: u32) -> *mut c_void;
        fn CloseHandle(handle: *mut c_void) -> i32;
        fn TerminateProcess(handle: *mut c_void, exit_code: u32) -> i32;
        fn K32GetProcessMemoryInfo(
            handle: *mut c_void,
            counters: *mut ProcessMemoryCountersEx2,
            cb: u32,
        ) -> i32;
        fn VirtualAlloc(
            address: *mut c_void,
            size: usize,
            allocation_type: u32,
            protect: u32,
        ) -> *mut c_void;
        fn VirtualFree(address: *mut c_void, size: usize, free_type: u32) -> i32;
        fn GetDiskFreeSpaceExW(
            root: *const u16,
            free_to_caller: *mut u64,
            total: *mut u64,
            total_free: *mut u64,
        ) -> i32;
        fn GetProcessTimes(
            handle: *mut c_void,
            creation: *mut FileTime,
            exit: *mut FileTime,
            kernel: *mut FileTime,
            user: *mut FileTime,
        ) -> i32;
    }

    #[link(name = "ntdll")]
    extern "system" {
        fn NtQuerySystemInformation(
            class: u32,
            info: *mut c_void,
            length: u32,
            returned: *mut u32,
        ) -> i32;
    }

    /// An open process handle, closed on drop.
    pub struct Process(*mut c_void);

    pub fn open(pid: u32, access: u32) -> Option<Process> {
        let handle = unsafe { OpenProcess(access, 0, pid) };
        (!handle.is_null()).then_some(Process(handle))
    }

    impl Process {
        pub fn creation_time(&self) -> Option<u64> {
            let mut times: [FileTime; 4] = Default::default();
            let [creation, exit, kernel, user] = &mut times;
            let ok = unsafe { GetProcessTimes(self.0, creation, exit, kernel, user) };
            (ok != 0).then(|| (u64::from(times[0].high) << 32) | u64::from(times[0].low))
        }

        pub fn terminate(&self) -> bool {
            unsafe { TerminateProcess(self.0, 1) != 0 }
        }

        /// What the process holds now (`super::TreeMemory`): its private commit charge and its
        /// private working set, in bytes. Needs `PROCESS_QUERY_LIMITED_INFORMATION |
        /// PROCESS_VM_READ`.
        pub fn memory(&self) -> Option<super::TreeMemory> {
            let mut counters = ProcessMemoryCountersEx2 {
                cb: std::mem::size_of::<ProcessMemoryCountersEx2>() as u32,
                ..Default::default()
            };
            let ok = unsafe { K32GetProcessMemoryInfo(self.0, &mut counters, counters.cb) };
            // Before Windows 10 1809 the private working set reads 0: the whole one stands in, which
            // also counts shared pages, the safe direction for a charge.
            let ram = match counters.private_working_set_size {
                0 => counters.working_set_size,
                private => private,
            };
            (ok != 0).then_some(super::TreeMemory {
                commit: counters.pagefile_usage as u64,
                ram: ram as u64,
            })
        }
    }

    impl Drop for Process {
        fn drop(&mut self) {
            unsafe { CloseHandle(self.0) };
        }
    }
}

/// Neither Unix nor Windows: no identity to prove, so nothing is signalled.
#[cfg(not(any(unix, windows)))]
pub fn pid_is_our_worker(_pid: u32, _expected_starttime: Option<u64>) -> bool {
    false
}

#[cfg(not(any(unix, windows)))]
pub fn pid_starttime(_pid: u32) -> Option<u64> {
    None
}

pub(crate) fn group_of_stat(stat: &str) -> Option<i32> {
    let rest = stat.get(stat.rfind(')')? + 1..)?;
    rest.split_whitespace().nth(2)?.parse().ok()
}

pub(crate) fn parse_status_kb(text: &str, key: &str) -> Option<u64> {
    for line in text.lines() {
        let Some((name, rest)) = line.split_once(':') else {
            continue;
        };
        if name != key {
            continue;
        }
        return rest
            .split_whitespace()
            .next()?
            .parse::<u64>()
            .ok()?
            .checked_mul(1024);
    }
    None
}

/// Is there room to start a proof expected to peak at `expected_peak`?
///
/// The whole point of this layer, and the reason a per-worker ceiling is not enough on its own: a
/// ceiling stops ONE worker from taking the host down, but two workers each under their ceiling can
/// still sum past RAM. That is what froze this box — four concurrent provers, none of them
/// individually enormous.
///
/// `reserved` is what in-flight proofs have already claimed, so the decision accounts for work that
/// has started but not yet peaked. `reserve` is the slice kept for the OS. All in bytes; saturating
/// arithmetic so a pathological input refuses rather than wrapping into a yes.
pub fn can_admit(
    expected_peak: u64,
    resident: u64,
    reserved: u64,
    available: u64,
    total: u64,
    reserve: u64,
) -> bool {
    // TWO independent conditions, both of which must hold. Adding `reserved` to a figure already
    // net of it would be wrong — once an in-flight proof has actually allocated its pages, that
    // memory is both absent from `available` AND still counted in `reserved`, so every proof in
    // flight would shrink the apparent headroom twice. On this box that admits 2 proofs where 4
    // genuinely fit, quietly defeating the concurrency the rest of the design assumes.
    //
    // 1. LIVE headroom must cover the INCREMENT this proof adds: what is free right now, minus
    //    the OS slice. The increment, not the peak, because `resident` — what this slot's worker
    //    is already holding — has ALREADY been subtracted from `available`. Charging the full peak
    //    on top of it counts those pages twice.
    //
    //    Charging the full peak here wedges the miner permanently, and silently. The SP1 worker caches
    //    `CudaProver` and its proving keys deliberately, so after proof #1 `sp1-gpu-server` sits
    //    resident at ~17.6 GiB. Proof #2 on that same slot then asked for `18 + 3 <= 8.2` and was
    //    refused — and so was every risc0 proof, because the headroom really was gone. The result
    //    was a miner that earned nothing while `reserved_bytes()` read 0, PSI read 0.00%, and every
    //    slot and backend reported healthy. `resident` is 0 whenever we cannot read it, so an
    //    unreadable cgroup simply disables the credit, which is the conservative direction.
    //    The credit is NOT artificially capped, and that is a deliberate answer to a real
    //    objection: once the credit reaches the peak, `fits_now` reduces to "is the host reserve
    //    free", which sounds like no test at all. Two things make it sound anyway.
    //
    //    First, `resident` is ANONYMOUS memory only (`anon_memory_of_pid`), not `memory.current`.
    //    Crediting the page cache instead would be dangerous: `MemAvailable` already counts it as
    //    available — double-counting pages that are reclaimable anyway, and on
    //    this box that is most of the number (`anon 465 MiB` against `file 18.3 GiB` in one slice).
    //    With anon, every credited byte is a page the worker really holds, really cannot have
    //    reclaimed (its scope sets `MemorySwapMax=0`), and will really reuse. Crediting it in full
    //    is not optimism, it is arithmetic: `expected_peak` is a TOTAL footprint, so a worker
    //    already holding that footprint needs nothing more.
    //
    //    Second, concurrency is bounded by `fits_committed` below, which uses the ABSOLUTE peak and
    //    ignores the credit entirely. So the credit can only ever help the sequential case — the
    //    next proof on an already-warm slot — and can never wave through a second concurrent proof.
    //    Capping it at half would refuse exactly the case it exists for: a warm SP1 slot
    //    holding 17.6 GiB, where proof #2 genuinely needs 0.4 GiB more and a half-cap would demand 7.5.
    let fits_now = expected_peak
        .saturating_sub(resident)
        .saturating_add(reserve)
        <= available;
    // 2. TOTAL commitments must fit the machine: every outstanding claim plus this one. This is the
    //    condition that stops proofs being admitted one at a time, each fitting on its own, their
    //    sum exceeding RAM — the shape that froze this host.
    //
    //    The ABSOLUTE peak here, deliberately, not the increment: `resident` is a saving against
    //    live headroom only. Two SP1 workers each resident at 17.6 GiB must still be told that
    //    `18 + 18 + 3` does not fit in 28 GiB, and netting out `resident` here would wave them
    //    through one at a time — the exact failure this condition exists to catch.
    let fits_committed = reserved
        .saturating_add(expected_peak)
        .saturating_add(reserve)
        <= total;
    fits_now && fits_committed
}

/// Which IDLE workers of other backends to recycle so a proof `can_admit` refuses would fit; `None`
/// when recycling all of them would still not be enough, and empty when it fits already.
///
/// The case it exists for is this host's: `sp1-gpu-server` stays resident at ~23 GB between proofs,
/// deliberately, so the next SP1 proof is cheap. On a 28 GB box that leaves no room for a risc0 proof
/// on the other card, and nothing gives it back until SP1's worker is recycled for some other reason —
/// so risc0 jobs were neither claimed nor proved while SP1 sat warm. Recycling the idle SP1 worker
/// costs it a respawn and a cold proving-key cache on its next job; the alternative was a card idle.
///
/// What a recycle gives back is what the worker holds as anonymous memory (`anon_memory_of_pid`).
/// Those pages are all resident — the worker's scope sets `MemorySwapMax=0` — so `MemAvailable` gains
/// them when it exits. Largest first, so as few warm workers as possible are destroyed, and none
/// holding less than `min_holding`: a respawn is not worth that little.
///
/// `None` also when the refusal is not about live headroom at all: `fits_committed` does not depend
/// on `available`, so when every outstanding claim plus this one exceeds the machine, no recycle helps
/// and none is planned. Destroying a warm worker for a proof that is refused anyway is the outcome to
/// avoid.
#[allow(clippy::too_many_arguments)]
pub fn plan_host_room(
    expected_peak: u64,
    resident: u64,
    reserved: u64,
    available: u64,
    total: u64,
    reserve: u64,
    idle_others: &[(String, u64)],
    min_holding: u64,
) -> Option<Vec<String>> {
    let fits = |available| can_admit(expected_peak, resident, reserved, available, total, reserve);
    if fits(available) {
        return Some(Vec::new());
    }
    let mut candidates: Vec<&(String, u64)> = idle_others
        .iter()
        .filter(|(_, held)| *held >= min_holding)
        .collect();
    candidates.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    let mut freed = 0u64;
    let mut chosen = Vec::new();
    for (key, held) in candidates {
        freed = freed.saturating_add(*held);
        chosen.push(key.clone());
        if fits(available.saturating_add(freed)) {
            return Some(chosen);
        }
    }
    None
}

/// Choose the minimal set of in-flight pre-claim MEASUREMENTS to preempt so a COMMITTED proof of
/// `want` fits host RAM, biggest-first (fewest kills). The planner for `WorkerPool::
/// preempt_measures_for_host` (residual A), kept pure so the admission algebra is unit-testable
/// without live `/proc` readings — the same split as `plan_host_room`.
///
/// Returns:
///  - `Some(vec![])` — it already fits, kill nothing (room appeared since the caller's refusal);
///  - `Some(victims)` — the minimal biggest-first set whose preemption makes it fit;
///  - `None` — preempting EVERY measurement still would not fit, so the blocker is another bonded
///    PROOF, which must never be preempted; the caller refuses.
///
/// Unlike `plan_host_room`'s idle workers (whose charge was already released, so freeing them only
/// raises `available`), a live measurement HOLDS a ledger reservation — so killing it returns its
/// charge to BOTH `reserved` (its `MemoryReservation` drops) and `available` (its resident pages come
/// back). The credit to `available` is an upper bound (a CPU executor may hold less than its charge),
/// which is why the caller re-tests the real reservation after reclaim: an optimistic plan can only
/// under-reclaim and refuse, never over-admit.
pub fn plan_measure_preemption(
    want: u64,
    resident: u64,
    reserved: u64,
    available: u64,
    total: u64,
    reserve: u64,
    // (identifier, host_bytes reserved) per in-flight measurement, any order.
    measures: &[(String, u64)],
) -> Option<Vec<String>> {
    let fits = |reserved: u64, available: u64| {
        can_admit(want, resident, reserved, available, total, reserve)
    };
    if fits(reserved, available) {
        return Some(Vec::new());
    }
    let mut candidates: Vec<&(String, u64)> =
        measures.iter().filter(|(_, held)| *held > 0).collect();
    // Biggest-first, ties broken by key for a deterministic plan.
    candidates.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    let mut freed = 0u64;
    let mut chosen = Vec::new();
    for (key, held) in candidates {
        freed = freed.saturating_add(*held);
        chosen.push(key.clone());
        if fits(
            reserved.saturating_sub(freed),
            available.saturating_add(freed),
        ) {
            return Some(chosen);
        }
    }
    None
}

/// What to assume a proof costs in host RAM when nothing has measured it, PER BACKEND.
///
/// An unmeasured backend must look expensive, because assuming it is free is what permits the
/// unlimited concurrency that froze this box. But one blunt figure for every backend is its own
/// failure: charging risc0 the SP1 number means a host with less than ~21 GiB free admits nothing at
/// all and the miner silently stops mining, which is an availability outage dressed as safety.
///
/// Grounded in what this host has actually been observed to do, not invented:
/// * SP1 — `sp1-gpu-server` was OOM-killed at **17.6 GB** anon RSS.
/// * risc0 — the four provers that froze the box had 2-11 MB anon RSS EACH; their cost is driver,
///   pinned and file-backed pages, not heap. 6 GiB is well above anything observed per prover while
///   still letting a 28 GiB box run two of them.
/// * openvm — never observed here. It shares risc0's shape (a RISC-V zkVM with a modest memory
///   multiplier in `BACKEND_PROFILES`), so it gets risc0's figure rather than a guess of its own.
///
/// An UNKNOWN name is the one case that gets the expensive figure. It is not a backend we have
/// characterised, it could be any of them, and it is also what a malformed slot key degrades to —
/// in which case refusing work is the right failure.
///
/// Windows' figures are what was measured there, on an RTX 5090: a RISC Zero proof at po2 20 keeps
/// 2-6 GB in RAM, and an SP1 proof 37 GB at once (its server proves with the portable executor,
/// which runs inside it, and the Groth16 helper on the CPU took 12-16 GB of it). Until a proof on a
/// card has been measured (`learned_host_peak`), its backend is charged these. Commit is charged
/// separately (`unmeasured_commit_for`).
pub fn unmeasured_peak_for(backend: &str) -> u64 {
    const GIB: u64 = 1024 * 1024 * 1024;
    if cfg!(windows) {
        return match backend {
            "risc0" | "openvm" => 8 * GIB,
            "mock" => 64 * 1024 * 1024,
            _ => 40 * GIB,
        };
    }
    match backend {
        "risc0" | "openvm" => 6 * GIB,
        // `mock_worker` speaks the protocol and allocates nothing; `crates/zkminer-prover/src/bin/`
        // builds it and the integration tests register it as a backend. Charging it the
        // unknown-backend figure would make every such test demand more RAM than a standard CI runner
        // has (18 GiB committed on a 7-16 GB box), so the benchmark and prove paths would return
        // `HostMemoryShortage` and the tests would fail for a reason that had nothing to do with them.
        "mock" => 64 * 1024 * 1024,
        // SP1 and anything we do not recognise.
        _ => 18 * GIB,
    }
}

/// What to assume a proof COMMITS when nothing has measured it (Windows; `CommitFigures`), in bytes:
/// measured on an RTX 5090, a RISC Zero proof at po2 20 committed 28.4 GB, and an SP1 proof 63 GB at
/// once (server and Groth16 helper; 22 GB of it VRAM). Elsewhere commit is not admitted, and this is
/// `unmeasured_peak_for`.
pub fn unmeasured_commit_for(backend: &str) -> u64 {
    const GIB: u64 = 1024 * 1024 * 1024;
    if !cfg!(windows) {
        return unmeasured_peak_for(backend);
    }
    match backend {
        "risc0" | "openvm" => 30 * GIB,
        "mock" => 64 * 1024 * 1024,
        _ => 64 * GIB,
    }
}

/// Multiplier applied to a MEASURED peak before trusting it as a budget.
///
/// The measurement is taken on a strictly cheaper workload than the one it predicts, in two
/// independent ways:
///
/// * **Receipt kind.** The benchmark calls `prover.prove(..)` — the default COMPOSITE receipt. A
///   real proof calls `prove_with_opts(.., ProverOpts::groth16())`, adding lift/join and a Groth16
///   wrap. `zkminer-prove-risc0`'s own calibration comment says it plainly: *"It also under-reports
///   MEMORY pressure: po2=21 completes composite-only but OOMs on the real groth16 path, so a
///   composite-derived max_feasible_po2 is too optimistic."*
/// * **Segment size.** A figure is held at `BASELINE_PO2` (one measured at a card's smaller
///   benchmark size is scaled up to it, `peak_at_baseline`); a card proves jobs at its own po2, and
///   this project's own model has memory DOUBLING per po2 step.
///
/// So a measured figure is a lower bound, and using it raw is worse than using no measurement at
/// all: it REPLACES the conservative default and would license several times the real concurrency.
/// 2x does not close the gap in theory — nothing short of measuring the production workload does —
/// but it stops a single optimistic reading from authorising a freeze, and it is paired with
/// `MIN_TRUSTED_PEAK_BYTES` below.
pub const MEASUREMENT_SAFETY_FACTOR: u64 = 2;

/// A measured peak below this is not believed.
///
/// A GPU proof that appears to cost less than this did not measure the production workload — most
/// likely it measured a composite receipt at a small segment size, or the window before the cgroup
/// cap applied (charges made then stay with the miner's cgroup and never appear in the worker's
/// counter). Treating such a figure as the budget is how an accurate-looking number licenses
/// unlimited concurrency.
pub const MIN_TRUSTED_PEAK_BYTES: u64 = 2 * 1024 * 1024 * 1024;

/// The largest budget that can REALISTICALLY be admitted on a host with `total` bytes of RAM.
///
/// Two conditions have to be satisfiable, and they bind differently:
///
/// * `fits_committed` compares against `total`, a constant, so `total - reserve` is its hard bound.
///   A budget above that can never be admitted at any level of free memory — the permanent brick.
/// * `fits_now` compares against `MemAvailable`, which is never `total`: the kernel, the desktop and
///   everything else take their share. On this box an idle `MemAvailable` is ~92% of `MemTotal`. So a
///   budget of `total - reserve` satisfies the committed test and still fails the live one forever,
///   which is the same silent refusal wearing a different hat.
///
/// Hence the three-quarters bound as well. It says: one proof may budget at most three quarters of
/// the machine, because beyond that there is no realistic state in which the host admits it, and
/// reporting "cannot fit it right now" in perpetuity is worse than saying the box is too small.
pub fn max_admissible_budget(total: u64) -> u64 {
    // Both terms must leave room for the reserve ON TOP of the budget, because that is what
    // `can_admit` tests. Returning `min(¾·total, total − reserve)` and adding the reserve afterwards
    // would make the bound satisfiable only where `0.75·T + reserve <= 0.92·T`, i.e. `T >= 18 GiB` —
    // reintroducing the permanent silent refusal for every host smaller than this one. Subtracting
    // the reserve from both terms avoids that: a 16 GiB box bounds a budget at 9 GiB, which an idle
    // 14.7 GiB of `MemAvailable` can admit.
    let headroom = total.saturating_sub(DEFAULT_HOST_RESERVE_BYTES);
    let bound = (total / 4 * 3)
        .saturating_sub(DEFAULT_HOST_RESERVE_BYTES)
        .min(headroom.saturating_sub(DEFAULT_HOST_RESERVE_BYTES));
    // Never ZERO. A zero budget is not maximally safe, it is maximally unsafe: `can_admit`'s
    // committed term becomes `reserved + 0 + reserve <= total`, independent of the proof, so a host
    // too small to run anything would admit without limit. Floor it at the trust threshold, which is
    // the smallest figure anything else in this module is willing to believe — a host that cannot
    // satisfy even that will refuse on `fits_now` instead, which is the honest answer.
    bound.max(MIN_TRUSTED_PEAK_BYTES)
}

/// Baseline po2 that `unmeasured_peak_for` and every recorded benchmark measurement are held at.
///
/// `RISC0_DEFAULT_JOB_PO2`, which a benchmark proves at on every card of 14 GiB or more. A smaller
/// CUDA card's benchmark proves at its own smaller size (`benchmark::risc0_benchmark_po2`), and its
/// figure is scaled up to this one when recorded (`peak_at_baseline`). A card proves jobs at its
/// own po2, so any budget compared against a different po2 has to be scaled from here; below it
/// nothing is credited.
pub const BASELINE_PO2: u8 = zkminer_prover_protocol::RISC0_DEFAULT_JOB_PO2;

/// A host-memory figure measured at `measured_po2` (`None` = `BASELINE_PO2`), held at
/// `BASELINE_PO2`: doubled per step below it, as `peak_for_po2` doubles per step above. Never
/// lowered: a figure measured above the baseline stays as measured.
pub fn peak_at_baseline(peak: u64, measured_po2: Option<u8>) -> u64 {
    let steps = BASELINE_PO2.saturating_sub(measured_po2.unwrap_or(BASELINE_PO2));
    peak.saturating_mul(
        1u64.checked_shl(u32::from(steps.min(16)))
            .unwrap_or(u64::MAX),
    )
}

/// Scale a host-memory figure measured at `BASELINE_PO2` to the cost at `po2`.
///
/// Memory DOUBLES per po2 step in this project's own model (`estimate_po2_memory`), and every
/// host-memory budget in this module is keyed on the backend alone — not the segment size. So an
/// operator raising po2 from 20 to 22 in the TUI multiplies the real cost roughly fourfold while
/// every admission figure stays identical, and the `Critical` log line even advises lowering po2 as
/// the remedy for a number po2 does not affect.
///
/// Saturating, and clamped below at the baseline: a SMALLER po2 is cheaper, but a budget is not a
/// place to be optimistic, so going down buys nothing.
pub fn peak_for_po2(baseline_peak: u64, po2: u8) -> u64 {
    let steps = po2.saturating_sub(BASELINE_PO2);
    baseline_peak.saturating_mul(1u64.checked_shl(steps.min(16) as u32).unwrap_or(u64::MAX))
}

/// What the set of proofs a claim implies may need at once, in bytes: this one (`want`) and the
/// largest `slots - 1` of those outstanding (`same` of its own backend at `want` each, `other` of
/// other backends at `other_peak` each). `slots` is how many proofs can run at once: no more than
/// there are cards, nor than the miner's concurrency limit. Charging every outstanding job this
/// backend's peak, as the claim check did, refused an SP1 claim behind two RISC Zero jobs on a
/// two-card machine as 3 x 42 GiB, and charged a RISC Zero claim behind an SP1 job only its own
/// 5 GiB twice.
pub fn claim_set_bytes(want: u64, same: usize, other: usize, other_peak: u64, slots: usize) -> u64 {
    let mut peaks: Vec<u64> = std::iter::repeat_n(want, same)
        .chain(std::iter::repeat_n(other_peak, other))
        .collect();
    peaks.sort_unstable_by(|a, b| b.cmp(a));
    peaks
        .iter()
        .take(slots.max(1) - 1)
        .fold(want, |sum, p| sum.saturating_add(*p))
}

/// Whether a claim that will WAIT for a card fits (see `claim_set_bytes`): every card already has a
/// job ahead of it, so it starts only once one of those is done, and does not need room beside
/// the proofs running now. What it needs is that the set it will run in (`set`), with the OS slice
/// (`reserve`), fits what is free now (`available`) plus what our own proofs, idle workers and
/// measurements will have handed back by then (`returning`). That still counts memory held by
/// anything else, which the set's test against the total cannot see. Requiring the job to fit on
/// top of the running proofs instead refused a queued RISC Zero claim behind a running SP1 proof
/// it would never run beside.
pub fn queued_claim_fits(set: u64, reserve: u64, available: u64, returning: u64) -> bool {
    set.saturating_add(reserve) <= available.saturating_add(returning)
}

/// The host memory one card's real proofs have reached, by the po2 they proved at (`BASELINE_PO2`
/// for a proof given none), in bytes. Windows only: see `learned_host_peak`.
pub type LearnedPeaks = std::collections::BTreeMap<u8, u64>;

/// A learned peak is charged at this many eighths of itself: jobs differ, and the next one may
/// reach a little further than any so far.
pub const LEARNED_PEAK_MARGIN_EIGHTHS: u64 = 9;

/// Note that a proof at `po2` on a card peaked at `peak`; whether the card's figure for that po2
/// rose. A worker's peak is its lifetime high-water mark, so a later reading never describes less
/// than an earlier one of the same worker; a lower one comes from a respawned worker, and the
/// higher figure stands.
pub fn note_learned_peak(learned: &mut LearnedPeaks, po2: Option<u8>, peak: u64) -> bool {
    let slot = learned.entry(po2.unwrap_or(BASELINE_PO2)).or_insert(0);
    let rose = peak > *slot;
    *slot = (*slot).max(peak);
    rose
}

/// What a proof at `po2` is charged on a card whose real proofs reached `learned`, or `None` when
/// none of them says (no proof there yet at this po2 or above). A peak is what the worker and every
/// process it started held AT ONCE (`LowWater::tree_peak`), which is what the host must hold. It is
/// sampled, so a spike shorter than `LOW_WATER_SAMPLE` can be missed; the margin covers some of
/// that, and a proof that runs the host out drops the card's figure (`forget_learned_host_peak`).
/// The sum of each process's lifetime peak is no floor for it: SP1's Groth16 helper exits, taking
/// its peak along, and the sampled figure came in above that sum.
///
/// The figure of the smallest po2 at or above this one: a proof at a larger segment size bounds a
/// smaller one, while one at a smaller size says nothing about a larger. With the margin
/// (`LEARNED_PEAK_MARGIN_EIGHTHS`), never below what is believed at all (`MIN_TRUSTED_PEAK_BYTES`)
/// and never above what the host can admit (`max_admissible_budget`).
///
/// Unlike a benchmark measurement, this one may come in BELOW the blind default
/// (`unmeasured_peak_for`). The safety factor and the floor in `budget_from_measurement` exist
/// because a benchmark proves a cheaper workload than a job: a composite receipt, sometimes at a
/// smaller po2. This is the job itself, Groth16 wrap included, at the po2 it is charged for, on the
/// card it is charged on, in RAM or in commit as the caller learned it. Per card, because cards
/// of one backend differ: an RTX 4070 at po2 19 and an RTX 5090 at po2 20 are not one figure.
pub fn learned_host_peak(learned: &LearnedPeaks, po2: Option<u8>, host_total: u64) -> Option<u64> {
    let (_, &peak) = learned.range(po2.unwrap_or(BASELINE_PO2)..).next()?;
    Some(
        (peak / 8)
            .saturating_mul(LEARNED_PEAK_MARGIN_EIGHTHS)
            .max(MIN_TRUSTED_PEAK_BYTES)
            .min(max_admissible_budget(host_total)),
    )
}

/// The unmeasured default for `backend`, clamped to what this host can admit.
///
/// The clamp has to apply to the FALLBACK too, not only to the measured path. `budget_from_measurement`
/// clamps; `unmeasured_peak_for` does not, and `expected_host_peak_bytes` returns it raw on both of
/// its early returns. So on any host where `unmeasured_peak_for(backend) + reserve > total` — a 20 GiB
/// box with SP1's 18 GiB default, or any unrecognised backend name anywhere under ~24 GiB — the
/// committed condition would be unsatisfiable at every level of free memory, for the life of the
/// install: the same permanent silent refusal the measured path clamps to avoid.
///
/// It is worse than a proving outage, because the benchmark is charged the same figure: the one thing
/// that could lower it was refused using the number only it could lower. A deadlock, with no log line
/// to distinguish it from "not benchmarked yet".
pub fn admissible_unmeasured_peak_for(backend: &str, host_total: u64) -> u64 {
    unmeasured_peak_for(backend).min(max_admissible_budget(host_total))
}

/// Turn a raw measurement into a budget.
///
/// Three rules, each guarding a specific way of getting the budget wrong:
///
/// 1. **Refuse an implausibly small figure.** Below `MIN_TRUSTED_PEAK_BYTES` the benchmark did not
///    measure the production workload, and a believable-looking small number is how unlimited
///    concurrency gets authorised.
/// 2. **Never undercut the blind default.** Returning `measured * FACTOR` outright would let a
///    3 GiB SP1 reading — entirely plausible given the composite-receipt caveat above — produce a
///    6 GiB budget where knowing nothing would charge 18 GiB, licensing three concurrent
///    proofs of a workload observed at 17.6 GB each. It would also make the function non-monotonic
///    across the trust floor: 1.9 GiB gives 18 GiB and 2.0 GiB gives 4 GiB, so a SMALLER measurement
///    produces a LARGER charge. Taking the max prevents both.
/// 3. **Never exceed what the host can admit.** Unclamped, `measured * 2` above
///    `max_admissible_budget` permanently disables the backend — and on a 28 GiB box that threshold
///    is an 11.4 GiB measurement, below the 16.4 GiB SP1 figure observed on this hardware.
///    So the single act of running an ACCURATE benchmark would turn a working miner into one that
///    never claims again, silently, with no way back but deleting the cache. Clamping instead yields
///    one-proof-at-a-time, which is the truth about such a host, and leaves the per-worker ceiling
///    and `oom_score_adj` standing behind it. The caller logs when the clamp bites, because a
///    backend whose honest requirement exceeds the machine is something the operator must be told.
pub fn budget_from_measurement(measured: u64, backend: &str, host_total: u64) -> u64 {
    let base = if measured < MIN_TRUSTED_PEAK_BYTES {
        unmeasured_peak_for(backend)
    } else {
        measured
            .saturating_mul(MEASUREMENT_SAFETY_FACTOR)
            .max(unmeasured_peak_for(backend))
    };
    base.min(max_admissible_budget(host_total))
}

/// Running total of host memory that in-flight proofs have laid claim to.
///
/// Mirrors the collateral `in_flight` reservation the chain side already uses, and for the same
/// reason: a decision made against a free-memory reading alone double-spends, because a proof that
/// has started but not yet peaked is invisible in `MemAvailable`. Four such invisible proofs is
/// exactly what froze this host.
#[derive(Debug, Default)]
pub struct MemoryLedger {
    reserved: std::sync::atomic::AtomicU64,
    /// Admissions whose growth is tracked (`try_reserve_tracked`): id -> what was admitted.
    tracked: std::sync::Mutex<std::collections::HashMap<u64, Tracked>>,
    next_id: std::sync::atomic::AtomicU64,
}

/// One tracked admission: on `slot`, `increment` bytes beyond the `resident_at` its worker held
/// when admitted.
#[derive(Debug, Clone)]
struct Tracked {
    slot: String,
    increment: u64,
    resident_at: u64,
}

/// What admitted proofs have still to allocate: each one's increment, less what its worker has grown
/// by since (`holding_now` less `resident_at`; all of it when unreadable). Live headroom does not
/// show an allocation not made yet, so two proofs admitted a moment apart would otherwise each see
/// the other's share as free.
pub fn pending_growth(admitted: impl IntoIterator<Item = (u64, u64, Option<u64>)>) -> u64 {
    admitted
        .into_iter()
        .fold(0u64, |sum, (increment, resident_at, holding_now)| {
            let grown = holding_now.map_or(0, |h| h.saturating_sub(resident_at));
            sum.saturating_add(increment.saturating_sub(grown))
        })
}

/// A reservation held for as long as a proof is running. Releases on drop, including on panic or an
/// early return, so a failed proof cannot leak its claim and starve every later one.
pub struct MemoryReservation<'a> {
    ledger: &'a MemoryLedger,
    bytes: u64,
    /// Its entry in the ledger's tracked admissions, if it has one.
    tracked: Option<u64>,
    /// A reservation on another ledger held with this one (`pair`): Windows' commit beside RAM.
    paired: Option<Box<MemoryReservation<'a>>>,
    /// Released without waking the waiters (`release_quietly`).
    quiet: bool,
}

impl<'a> MemoryReservation<'a> {
    /// How many bytes this reservation holds against its ledger. Used by the dispatcher to record a
    /// measurement's charge so a committed proof's preemption knows how much each in-flight
    /// measurement would free.
    pub fn bytes(&self) -> u64 {
        self.bytes
    }

    /// Hold `other` (a reservation on another ledger) for as long as this one, and release both
    /// together.
    pub fn pair(mut self, other: MemoryReservation<'a>) -> Self {
        self.paired = Some(Box::new(other));
        self
    }

    /// Give the memory back without waking the proofs waiting for memory (`MEMORY_RELEASED`): for a
    /// reservation that never ran a proof, as when the commit beside its RAM was refused. Nothing
    /// the waiters were short of was freed, and waking them on it burned their waits in
    /// milliseconds, each one refused again by the same shortage.
    pub fn release_quietly(mut self) {
        self.quiet = true;
        if let Some(paired) = self.paired.as_mut() {
            paired.quiet = true;
        }
    }
}

impl Drop for MemoryReservation<'_> {
    fn drop(&mut self) {
        // The paired reservation first, so that the wake-up below finds both released: a waiter
        // woken while the other is still held would retry, fail, and sleep out its backoff.
        drop(self.paired.take());
        // SATURATING, to match the add. A plain `fetch_sub` that underflows wraps the counter to
        // ~u64::MAX, and `can_admit`'s committed term then refuses every proof for the life of the
        // process — a miner that never mines again, silently, from a single arithmetic mismatch.
        // Unreachable today (`try_reserve` refuses a reservation that would clamp the add), but the
        // failure mode is terminal and guarding against it costs nothing.
        let _ = self.ledger.reserved.fetch_update(
            std::sync::atomic::Ordering::AcqRel,
            std::sync::atomic::Ordering::Acquire,
            |v| Some(v.saturating_sub(self.bytes)),
        );
        if let Some(id) = self.tracked {
            self.ledger
                .tracked
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&id);
        }
        if !self.quiet {
            MEMORY_RELEASED.notify_waiters();
        }
    }
}

/// Signalled whenever any reservation (host RAM or `/dev/shm`) is given back, so a proof waiting for
/// memory can retry the moment some frees instead of on its next poll. A wake-up only: the waiter
/// still has to win the reservation, and waits with a timeout, since a release between its refusal
/// and its wait is not remembered.
pub static MEMORY_RELEASED: std::sync::LazyLock<tokio::sync::Notify> =
    std::sync::LazyLock::new(tokio::sync::Notify::new);

impl MemoryLedger {
    pub fn reserved_bytes(&self) -> u64 {
        self.reserved.load(std::sync::atomic::Ordering::Acquire)
    }

    /// Reserve `bytes` if the host can take it, else `None`.
    ///
    /// The check and the reservation are one atomic step (compare-and-swap, not read-then-add):
    /// two slots deciding concurrently would otherwise both see room and both take it, which is
    /// precisely the over-commit this is here to prevent.
    /// `resident` is what the slot's own worker is already holding and which `available` therefore
    /// already excludes — see `can_admit`. Pass 0 when it is unknown; that is the conservative
    /// reading, not a cheat.
    pub fn try_reserve(
        &self,
        bytes: u64,
        resident: u64,
        available: u64,
        total: u64,
        reserve: u64,
    ) -> Option<MemoryReservation<'_>> {
        let mut current = self.reserved_bytes();
        loop {
            if !can_admit(bytes, resident, current, available, total, reserve) {
                return None;
            }
            // Never let the add CLAMP. A clamped add paired with the release's subtraction would
            // leave the counter permanently wrong, so refuse instead — and a host with u64::MAX
            // bytes of outstanding claims has no business admitting another proof anyway.
            let Some(next) = current.checked_add(bytes) else {
                return None;
            };
            match self.reserved.compare_exchange_weak(
                current,
                next,
                std::sync::atomic::Ordering::AcqRel,
                std::sync::atomic::Ordering::Acquire,
            ) {
                Ok(_) => {
                    return Some(MemoryReservation {
                        ledger: self,
                        bytes,
                        tracked: None,
                        paired: None,
                        quiet: false,
                    })
                }
                Err(observed) => current = observed,
            }
        }
    }

    /// Whether an admission on `slot` is tracked.
    pub fn tracks(&self, slot: &str) -> bool {
        self.tracked
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .any(|t| t.slot == slot)
    }

    /// How many tracked admissions are held: proofs in flight, on Windows.
    pub fn tracked_count(&self) -> usize {
        self.tracked.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    /// What the tracked admissions have still to allocate (`pending_growth`), with `holding` reading
    /// what a slot's worker holds now.
    pub fn pending_growth(&self, holding: impl Fn(&str) -> Option<u64>) -> u64 {
        let tracked = self.tracked.lock().unwrap_or_else(|e| e.into_inner());
        pending_growth(
            tracked
                .values()
                .map(|t| (t.increment, t.resident_at, holding(&t.slot))),
        )
    }

    /// As `try_reserve`, for a proof on `slot` whose worker allocates as it goes: live headroom is
    /// taken net of what admissions already in flight have still to allocate (`pending_growth`),
    /// and this one is tracked until its reservation drops. Admissions through here are serialised,
    /// so two cannot each count the other's share as free.
    #[allow(clippy::too_many_arguments)]
    pub fn try_reserve_tracked(
        &self,
        bytes: u64,
        resident: u64,
        available: u64,
        total: u64,
        reserve: u64,
        slot: &str,
        holding: impl Fn(&str) -> Option<u64>,
    ) -> Option<MemoryReservation<'_>> {
        let mut tracked = self.tracked.lock().unwrap_or_else(|e| e.into_inner());
        let pending = pending_growth(
            tracked
                .values()
                .map(|t| (t.increment, t.resident_at, holding(&t.slot))),
        );
        let mut reservation = self.try_reserve(
            bytes,
            resident,
            available.saturating_sub(pending),
            total,
            reserve,
        )?;
        let id = self
            .next_id
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        tracked.insert(
            id,
            Tracked {
                slot: slot.to_string(),
                increment: bytes.saturating_sub(resident),
                resident_at: resident,
            },
        );
        reservation.tracked = Some(id);
        Some(reservation)
    }
}

/// How hard the host is struggling, and what to do about it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PressureState {
    /// Normal: admit work.
    Ok,
    /// Stop admitting new work, but let what is running finish.
    Brake,
    /// The host is losing real time to reclaim. Stop admitting, and say so loudly.
    ///
    /// NOTE, deliberately: nothing here automatically gives running work back. This differs from
    /// `Brake` in severity and in what it tells the operator, not yet in action. Releasing an
    /// in-flight job needs the deadline and collateral context that lives in the brain, and
    /// choosing the wrong victim strands collateral — so the selection is left to be designed
    /// rather than guessed at. Calling this `Sacrifice` would imply an action the system does not take.
    Critical,
}

/// Classify host memory pressure.
///
/// PSI is the primary signal because it measures the SYMPTOM — time the machine actually lost to
/// reclaim — rather than a proxy for it. A free-memory threshold cannot distinguish "26 GB of
/// reclaimable page cache" from "26 GB of headroom", and this box reads 9 GB "free" with 26 GB
/// available.
///
/// The free-memory floor is a backstop for hosts without PSI (`CONFIG_PSI=n`), where absence of a
/// reading must NOT be read as absence of pressure — the direction that froze the box.
pub fn classify_pressure(stall_pct: Option<f64>, available: u64, total: u64) -> PressureState {
    // A floor proportional to the machine, so it scales from this 28 GB box to a 512 GB one, with an
    // absolute minimum for small hosts.
    //
    // That minimum is `1.5 x` the admission reserve, not `0.5 x`. The brake is supposed to fire
    // BEFORE the gate starts refusing, so the operator sees the host struggling rather than a stream
    // of per-job refusals; a half-reserve minimum would let the free-memory backstop trigger only
    // once `available` was already well below the 3 GiB that admission insists on, i.e. after
    // everything had been silently refused. On a kernel without PSI — the only case this backstop
    // exists for — that would make this backstop effectively dead.
    let floor = (total / 10).max(DEFAULT_HOST_RESERVE_BYTES * 3 / 2);
    if let Some(p) = stall_pct {
        if p >= STALL_CRITICAL_PERCENT {
            return PressureState::Critical;
        }
        if p >= STALL_BRAKE_PERCENT {
            return PressureState::Brake;
        }
    }
    // Either PSI is quiet, or this kernel has none. Fall through to the free-memory floor in BOTH
    // cases: quiet-but-nearly-full means pressure has not been FELT yet only because nothing has
    // tried to allocate, and the next proof is what would; and a missing reading must never be
    // read as an absence of pressure, which is the direction that froze this box.
    // Critical at the reserve itself: below that, admission refuses everything anyway, so the host
    // is past braking and into losing time.
    if available <= DEFAULT_HOST_RESERVE_BYTES.max(floor / 2) {
        PressureState::Critical
    } else if available <= floor {
        PressureState::Brake
    } else {
        PressureState::Ok
    }
}

/// Free commit (`commit_bytes`) when it started, and the least while it was held, sampled every
/// `LOW_WATER_SAMPLE` on a thread of its own, plus whenever `sample` is called. Windows only, where
/// there is no OOM-kill counter to ask how a proof died (`windows_failure_is_host_shortage`);
/// elsewhere it samples nothing and answers `None`.
///
/// Commit, not `mem_available_bytes`: free physical memory running low makes Windows page, which
/// fails no allocation, so it says nothing about why a proof failed.
///
/// Given a worker (`tree`: its pid and start time), it also samples what the worker and every
/// process it started hold AT ONCE, committed and in RAM (`tree_peak`, `tree_ram_peak`): the
/// proof's real peaks. A process's own lifetime peaks are no substitute: SP1's Groth16 helper exits
/// with its own, and the processes' peaks need not coincide.
pub struct LowWater {
    start: Option<u64>,
    lowest: std::sync::Arc<std::sync::atomic::AtomicU64>,
    tree_peak: std::sync::Arc<std::sync::atomic::AtomicU64>,
    tree_ram_peak: std::sync::Arc<std::sync::atomic::AtomicU64>,
    tree: Option<(u32, u64)>,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

/// What the worker `tree` (pid, start time) and what it started hold now; Windows only.
fn tree_memory_now(tree: Option<(u32, u64)>) -> Option<TreeMemory> {
    #[cfg(windows)]
    {
        let (pid, started) = tree?;
        tree_memory(pid, Some(started))
    }
    #[cfg(not(windows))]
    {
        let _ = tree;
        None
    }
}

/// How often `LowWater` samples. Commit runs out over seconds as a proof allocates, not in one step.
pub const LOW_WATER_SAMPLE: Duration = Duration::from_millis(250);

impl LowWater {
    pub fn start(tree: Option<(u32, u64)>) -> Self {
        use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
        use std::sync::Arc;
        let tree = tree.filter(|(pid, started)| *pid != 0 && *started != 0);
        let watch = Self {
            start: commit_bytes().map(|(_, free)| free),
            lowest: Arc::new(AtomicU64::new(u64::MAX)),
            tree_peak: Arc::new(AtomicU64::new(0)),
            tree_ram_peak: Arc::new(AtomicU64::new(0)),
            tree,
            stop: Arc::new(AtomicBool::new(false)),
        };
        if cfg!(windows) {
            watch.sample();
            let (lowest, peak, ram_peak, stop) = (
                watch.lowest.clone(),
                watch.tree_peak.clone(),
                watch.tree_ram_peak.clone(),
                watch.stop.clone(),
            );
            let spawned = std::thread::Builder::new()
                .name("host-low-water".into())
                .spawn(move || {
                    while !stop.load(Ordering::Acquire) {
                        std::thread::sleep(LOW_WATER_SAMPLE);
                        if let Some((_, free)) = commit_bytes() {
                            lowest.fetch_min(free, Ordering::AcqRel);
                        }
                        if let Some(now) = tree_memory_now(tree) {
                            peak.fetch_max(now.commit, Ordering::AcqRel);
                            ram_peak.fetch_max(now.ram, Ordering::AcqRel);
                        }
                    }
                });
            if let Err(e) = spawned {
                tracing::debug!("host low-water sampler not started: {e}");
            }
        }
        watch
    }

    /// Sample now, as well as on the thread's schedule.
    pub fn sample(&self) {
        if let Some((_, free)) = commit_bytes() {
            self.lowest
                .fetch_min(free, std::sync::atomic::Ordering::AcqRel);
        }
        if let Some(now) = tree_memory_now(self.tree) {
            self.tree_peak
                .fetch_max(now.commit, std::sync::atomic::Ordering::AcqRel);
            self.tree_ram_peak
                .fetch_max(now.ram, std::sync::atomic::Ordering::AcqRel);
        }
    }

    /// The most the worker's tree COMMITTED at once, of the samples, or `None` if none was read.
    pub fn tree_peak(&self) -> Option<u64> {
        Some(self.tree_peak.load(std::sync::atomic::Ordering::Acquire)).filter(|v| *v != 0)
    }

    /// The most the worker's tree held in RAM at once, of the samples, or `None` if none was read.
    pub fn tree_ram_peak(&self) -> Option<u64> {
        Some(
            self.tree_ram_peak
                .load(std::sync::atomic::Ordering::Acquire),
        )
        .filter(|v| *v != 0)
    }

    /// Free commit when it started, or `None` if it was not read.
    pub fn started_at(&self) -> Option<u64> {
        self.start
    }

    /// The least seen, or `None` if nothing was read.
    pub fn lowest(&self) -> Option<u64> {
        Some(self.lowest.load(std::sync::atomic::Ordering::Acquire)).filter(|v| *v != u64::MAX)
    }
}

impl Drop for LowWater {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::Release);
    }
}

/// A proof that failed while no more than this much commit was free (`LowWater`) may have failed
/// for want of it, by `windows_failure_is_host_shortage`: the pinned margin. Above it, a page file
/// that can grow covers what is asked (only pinned memory does not wait for it), and Windows grows
/// it well before; free commit falling below it means the page file could not keep up, or is fixed.
pub const HOST_SHORT_LOW_WATER_BYTES: u64 = PINNED_COMMIT_MARGIN_BYTES;

/// ... and only if free commit FELL at least this much during the proof. A host that merely sits
/// low (idle workers keep what they committed, and admission lets a warm worker start with little
/// to spare) has not run out because of anything the proof did; a GPU out of memory there is the
/// card's.
pub const HOST_SHORT_FALL_BYTES: u64 = 2 * 1024 * 1024 * 1024;

/// Windows: did a proof fail because the HOST ran short of memory, rather than the card or the
/// prover? Then it is not the card's fault, and a retry should neither avoid the card nor shrink
/// what it proves at.
///
/// Linux reads its OOM-kill counter for this (`WorkerHandle::died_of_host_oom`). Windows kills
/// nothing: an allocation past the commit limit fails, and the process that asked dies of it or
/// reports it. A CUDA host allocation that fails says `cudaErrorMemoryAllocation: out of memory`,
/// word for word what a card out of memory says, so the text cannot tell them apart, and it may in
/// any case come from a job's guest program. Two facts can:
///
/// * the worker's exit code (`exit_code`, `None` while it lives) is one Windows gives a process that
///   could not get memory: `STATUS_COMMITMENT_LIMIT`, `STATUS_NO_MEMORY`,
///   `STATUS_INSUFFICIENT_RESOURCES`, or `ERROR_COMMITMENT_LIMIT` as a plain code;
/// * or free commit fell during the proof, by `HOST_SHORT_FALL_BYTES` or more from where it
///   started (`start`), to `HOST_SHORT_LOW_WATER_BYTES` or below (`lowest`).
///
/// Neither catches everything: a Rust allocation failure aborts with `0xC0000409`, which other
/// aborts share, and a single large request that fails leaves commit where it was. Those read as
/// the worker's failure, as before. The other error, a card out of memory while another proof
/// drained commit, costs the attempt and goes back to the same card at the same size (for SP1,
/// lowered on the next out-of-memory there); a host shortage read as the card's excludes a healthy
/// card from the job and, for SP1, lowers what the card proves at for good.
pub fn windows_failure_is_host_shortage(
    exit_code: Option<i32>,
    start: Option<u64>,
    lowest: Option<u64>,
) -> bool {
    const STATUS_NO_MEMORY: u32 = 0xC000_0017;
    const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;
    const STATUS_COMMITMENT_LIMIT: u32 = 0xC000_012D;
    const ERROR_COMMITMENT_LIMIT: u32 = 1455;
    let by_code = exit_code.is_some_and(|c| {
        matches!(
            c as u32,
            STATUS_NO_MEMORY
                | STATUS_INSUFFICIENT_RESOURCES
                | STATUS_COMMITMENT_LIMIT
                | ERROR_COMMITMENT_LIMIT
        )
    });
    let by_fall = match (start, lowest) {
        (Some(start), Some(lowest)) => {
            lowest <= HOST_SHORT_LOW_WATER_BYTES
                && start.saturating_sub(lowest) >= HOST_SHORT_FALL_BYTES
        }
        _ => false,
    };
    // `STATUS_IN_PAGE_ERROR`: a page could not be brought in, which is what a process gets when the
    // page file cannot back it. A host shortage when commit was at the low-water mark during the
    // proof, even if it started there (no fall to see): 9 of 9 such deaths on a 5090 came seconds
    // after a sibling worker was recycled with commit near the limit, and each excluded the card.
    const STATUS_IN_PAGE_ERROR: u32 = 0xC000_0006;
    let in_page = exit_code.is_some_and(|c| c as u32 == STATUS_IN_PAGE_ERROR)
        && lowest.is_some_and(|l| l <= HOST_SHORT_LOW_WATER_BYTES);
    by_code || by_fall || in_page
}

#[cfg(test)]
mod tests {
    use super::*;

    /// On this Linux host `/dev/shm` exists and has a real capacity, so the statvfs wrapper must
    /// return a plausible `Some`. Guards against a zeroed-struct / wrong-field-scaling regression
    /// (an all-zero or absurdly small answer would wrongly disable SP1 measuring).
    #[cfg(target_os = "linux")]
    #[test]
    fn dev_shm_capacity_is_a_plausible_nonzero_size() {
        let cap = dev_shm_capacity_bytes().expect("/dev/shm should stat on a Linux CI/dev host");
        // At least 1 MiB (even a locked-down tmpfs clears this) and sane (< 1 PiB).
        assert!(cap >= 1024 * 1024, "implausibly small /dev/shm: {cap} bytes");
        assert!(cap < 1u64 << 50, "implausibly large /dev/shm: {cap} bytes");
    }

    #[test]
    fn sp1_measure_cap_never_exceeds_any_of_its_bounds() {
        // cap = min(24 GiB default, admissible budget, /dev/shm − poll margin [Linux]). The /dev/shm
        // term is host-dependent, so assert the INVARIANTS that hold on any host, not a fixed value.
        let shm_bound =
            dev_shm_capacity_bytes().map(|s| s.saturating_sub(SP1_DEV_SHM_POLL_MARGIN_BYTES));
        for t in [8u64, 16, 24, 28, 36, 64, 256] {
            let total = t * 1024 * 1024 * 1024;
            let cap = sp1_measure_cap_bytes(total);
            assert!(cap > 0, "cap must be positive at {t} GiB");
            assert!(cap <= SP1_DEFAULT_MEMORY_LIMIT_BYTES, "cap above SP1 24 GiB default at {t} GiB");
            assert!(cap <= max_admissible_budget(total), "cap above admissible budget at {t} GiB");
            if let Some(shm_bound) = shm_bound {
                assert!(cap <= shm_bound, "cap above the /dev/shm bound at {t} GiB");
            }
        }
        // On a host whose /dev/shm comfortably clears the budget (its +5 GiB credit ≥ the budget), the
        // /dev/shm term never binds, so the cap is exactly min(24 GiB, budget) — the locked-#1 value.
        let total = 28u64 * 1024 * 1024 * 1024;
        let non_shm_cap = SP1_DEFAULT_MEMORY_LIMIT_BYTES.min(max_admissible_budget(total));
        if shm_bound.map_or(true, |b| b >= non_shm_cap) {
            assert_eq!(sp1_measure_cap_bytes(total), non_shm_cap);
        }
    }

    #[test]
    fn meminfo_is_parsed_in_bytes_and_by_exact_key() {
        let text = "MemTotal:       29493776 kB\nMemFree:         9000000 kB\n\
                    MemAvailable:   27184512 kB\nBuffers:          100 kB\n";
        assert_eq!(parse_meminfo_kb(text, "MemTotal"), Some(29_493_776 * 1024));
        assert_eq!(
            parse_meminfo_kb(text, "MemAvailable"),
            Some(27_184_512 * 1024)
        );
        // Exact key, not a prefix: `MemFree` must never answer a request for `MemAvailable`, and
        // `MemAvailable` must not be satisfied by `Mem`.
        assert_eq!(parse_meminfo_kb(text, "Mem"), None);
        // A kernel too old to report MemAvailable must yield None, not a wrong number.
        let old = "MemTotal:       29493776 kB\nMemFree:         9000000 kB\n";
        assert_eq!(parse_meminfo_kb(old, "MemAvailable"), None);
    }

    #[test]
    fn pressure_reads_full_not_some() {
        // `some` is any task stalled; `full` is ALL of them. Reading `some` would brake on a host
        // that is merely busy.
        let text = "some avg10=42.00 avg60=10.00 avg300=1.00 total=168325865\n\
                    full avg10=7.25 avg60=2.00 avg300=0.50 total=166823663\n";
        assert_eq!(parse_pressure_full_avg10(text), Some(7.25));
        assert_eq!(
            parse_pressure_full_avg10("some avg10=99.00 total=1\n"),
            None
        );
        assert_eq!(parse_pressure_full_avg10(""), None);
    }

    #[test]
    fn oom_kill_is_read_from_the_events_file() {
        let text = "low 0\nhigh 0\nmax 4\noom 2\noom_kill 3\noom_group_kill 0\n";
        assert_eq!(parse_oom_kill(text), Some(3));
        // `oom` and `oom_kill` are different counters; matching the wrong one under-reports.
        assert_eq!(parse_oom_kill("low 0\nhigh 0\noom 7\n"), None);
    }

    #[test]
    fn a_unit_name_survives_a_backend_key() {
        // Slot keys look like `risc0:cuda:0`, and `:` is not legal in a unit name.
        assert_eq!(sanitize_unit("risc0:cuda:0"), "risc0-cuda-0");
        assert_eq!(sanitize_unit("sp1:generic"), "sp1-generic");
    }

    #[test]
    fn the_ceiling_leaves_the_reserve_and_refuses_an_impossible_one() {
        // A reserve larger than the machine must yield None rather than a tiny or wrapped ceiling.
        // Physical memory (on Windows `mem_total_bytes` is the commit limit).
        let total = physical_total_bytes().expect("this host reports MemTotal");
        assert!(worker_memory_ceiling_bytes(total + 1).is_none());
        let c = worker_memory_ceiling_bytes(DEFAULT_HOST_RESERVE_BYTES)
            .expect("a 3 GiB reserve fits on any host that can prove");
        assert_eq!(c, total - DEFAULT_HOST_RESERVE_BYTES);
    }

    #[test]
    fn admission_accounts_for_work_already_in_flight() {
        let gib = 1024 * 1024 * 1024;
        let total = 28 * gib;
        let reserve = 3 * gib;

        // Nothing in flight, 26 GiB free: a 17 GiB proof fits on both tests.
        assert!(can_admit(17 * gib, 0, 0, 26 * gib, total, reserve));

        // One 17 GiB proof already running, so it is BOTH reserved and absent from `available`.
        // A second must be refused — this is the sum that froze the host.
        assert!(!can_admit(17 * gib, 0, 17 * gib, 9 * gib, total, reserve));

        // The double-count case. Two 6 GiB proofs in flight on a 28 GiB box: 12 GiB
        // reserved, ~13 GiB still free. A third genuinely fits and must be admitted. Adding
        // `reserved` to a figure already net of it would make this refuse, halving real concurrency
        // and quietly defeating the look-ahead the rest of the design assumes.
        assert!(can_admit(6 * gib, 0, 12 * gib, 13 * gib, total, reserve));

        // Four in flight: live headroom is gone, so refuse even though the committed total still
        // looks survivable. Either test failing is enough to refuse.
        assert!(!can_admit(6 * gib, 0, 24 * gib, 1 * gib, total, reserve));

        // And the committed test bites on its own: plenty free right now, but the outstanding
        // claims plus this one exceed the machine, so the proofs in flight would collide as they
        // grow into their peaks.
        assert!(!can_admit(6 * gib, 0, 22 * gib, 26 * gib, total, reserve));

        // Saturating, so an absurd expectation refuses rather than wrapping into a yes.
        assert!(!can_admit(u64::MAX, 0, u64::MAX, 26 * gib, total, reserve));
    }

    #[test]
    fn the_ledger_refuses_an_over_commit_and_releases_on_drop() {
        let gib = 1024 * 1024 * 1024;
        let ledger = MemoryLedger::default();
        let avail = 26 * gib;
        let reserve = 3 * gib;

        let total = 28 * gib;
        let first = ledger
            .try_reserve(17 * gib, 0, avail, total, reserve)
            .expect("the first proof fits");
        assert_eq!(ledger.reserved_bytes(), 17 * gib);

        // THE case that froze the box: the second proof also "fits" against free memory alone, and
        // must be refused because the first one's claim is already outstanding.
        assert!(
            ledger
                .try_reserve(17 * gib, 0, avail, total, reserve)
                .is_none(),
            "two 17 GiB proofs must not both be admitted on a 26 GiB host"
        );

        // A small one still fits alongside.
        let second = ledger
            .try_reserve(2 * gib, 0, avail, total, reserve)
            .expect("2 GiB fits");
        assert_eq!(ledger.reserved_bytes(), 19 * gib);
        drop(second);
        assert_eq!(ledger.reserved_bytes(), 17 * gib);

        // Dropping the first frees the whole claim, so a big proof is admissible again — the
        // property that stops a failed proof from starving every later one.
        drop(first);
        assert_eq!(ledger.reserved_bytes(), 0);
        assert!(ledger
            .try_reserve(17 * gib, 0, avail, total, reserve)
            .is_some());
    }

    #[test]
    fn concurrent_reservations_cannot_both_win() {
        // A BARRIER, so the threads genuinely collide. Without one they serialise — thread 1
        // reserves and holds before thread 8 is even spawned — and the test then passes against a
        // read-then-add ledger with no atomicity at all (verified: it did).
        //
        // Repeated, because losing a race is probabilistic: one round might not expose a
        // non-atomic implementation, twenty will.
        let gib = 1024 * 1024 * 1024;
        const THREADS: usize = 8;
        for round in 0..20 {
            let ledger = std::sync::Arc::new(MemoryLedger::default());
            let winners = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
            let barrier = std::sync::Arc::new(std::sync::Barrier::new(THREADS));
            let mut hs = Vec::new();
            for _ in 0..THREADS {
                let l = ledger.clone();
                let w = winners.clone();
                let b = barrier.clone();
                hs.push(std::thread::spawn(move || {
                    b.wait();
                    // BIND the reservation: testing `.is_some()` in an `if` condition drops the
                    // temporary before the body, which would release every claim instantly and let
                    // all eight "win" regardless of the ledger's behaviour.
                    // Room for exactly ONE: 10 GiB each, 1 GiB OS reserve, 20 GiB total. The first
                    // leaves 10+10+1 = 21 > 20 committed for any second, so the committed-total test
                    // is what binds. `available` is a fixed fixture figure here — the live-headroom
                    // test is covered by `admission_accounts_for_work_already_in_flight`.
                    let held = l.try_reserve(10 * gib, 0, 13 * gib, 20 * gib, gib);
                    if held.is_some() {
                        w.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
                        // Hold it long enough that the others must contend, not reuse a freed slot.
                        std::thread::sleep(Duration::from_millis(50));
                    }
                    drop(held);
                }));
            }
            for h in hs {
                h.join().unwrap();
            }
            assert_eq!(
                winners.load(std::sync::atomic::Ordering::Acquire),
                1,
                "round {round}: exactly one reservation may win when there is room for one. More \
                 than one means the check and the add are not a single atomic step, which is the \
                 over-commit this ledger exists to prevent."
            );
            assert_eq!(ledger.reserved_bytes(), 0, "round {round}: a claim leaked");
        }
    }

    #[test]
    fn pressure_brakes_on_stall_before_memory_runs_out() {
        let gib = 1024 * 1024 * 1024;
        let total = 28 * gib;
        // Quiet and roomy.
        assert_eq!(
            classify_pressure(Some(0.0), 26 * gib, total),
            PressureState::Ok
        );
        // Stalling, but memory still looks fine — PSI is why this is caught at all, because a
        // free-memory threshold would see nothing wrong here.
        assert_eq!(
            classify_pressure(Some(12.0), 26 * gib, total),
            PressureState::Brake
        );
        assert_eq!(
            classify_pressure(Some(45.0), 26 * gib, total),
            PressureState::Critical
        );
        // No PSI on this kernel: absence of a reading must not read as absence of pressure, so the
        // free-memory floor still brakes.
        assert_eq!(classify_pressure(None, 26 * gib, total), PressureState::Ok);
        // The floor now sits ABOVE the admission reserve, so the brake fires while the gate would
        // still admit — which is the point of a brake. 4 GiB free on a 28 GiB box: floor is 4.5 GiB.
        assert_eq!(
            classify_pressure(None, 4 * gib, total),
            PressureState::Brake
        );
        // And at or below the reserve itself the host is past braking: admission refuses everything
        // there anyway, so calling it Brake understated it.
        assert_eq!(
            classify_pressure(None, 2 * gib, total),
            PressureState::Critical
        );
        assert_eq!(
            classify_pressure(None, 512 * 1024 * 1024, total),
            PressureState::Critical
        );
        // What the free-memory arm is and is NOT. It cannot "fire before the gate refuses": the gate
        // refuses at `peak + reserve > available`, which for a 6 GiB risc0 proof means below 9 GiB
        // free — far above any sane floor. So on a PSI-capable kernel the gate always speaks first,
        // and this arm exists for the two cases the gate cannot cover: a kernel with no PSI at all,
        // and a host so short that even admission's own reserve is gone.
        let brake_floor = (total / 10).max(DEFAULT_HOST_RESERVE_BYTES * 3 / 2);
        assert!(
            !can_admit(
                unmeasured_peak_for("risc0"),
                0,
                0,
                brake_floor,
                total,
                DEFAULT_HOST_RESERVE_BYTES
            ),
            "the gate is expected to have refused long before the free-memory arm trips; if this \
             ever passes, the arm has become the primary signal and its thresholds need rethinking"
        );
        // PSI quiet but memory nearly gone: do not report Ok anyway. Nothing has stalled yet only
        // because nothing has tried to allocate; the next proof is what would. At 2 GiB — under
        // admission's own 3 GiB reserve — that is Critical, not merely Brake.
        assert_eq!(
            classify_pressure(Some(0.0), 2 * gib, total),
            PressureState::Critical
        );
        assert_eq!(
            classify_pressure(Some(0.0), 4 * gib, total),
            PressureState::Brake
        );
    }

    #[test]
    fn the_pressure_floor_scales_with_the_machine() {
        let gib = 1024 * 1024 * 1024;
        // On a big host the floor is PROPORTIONAL: 51.2 GiB on a 512 GiB box. So 60 GiB free is
        // fine, 30 GiB brakes, and 10 GiB — 2% of the machine — is already a sacrifice, even
        // though in absolute terms it would be comfortable on a small host.
        assert_eq!(
            classify_pressure(Some(0.0), 60 * gib, 512 * gib),
            PressureState::Ok
        );
        assert_eq!(
            classify_pressure(Some(0.0), 30 * gib, 512 * gib),
            PressureState::Brake
        );
        assert_eq!(
            classify_pressure(Some(0.0), 10 * gib, 512 * gib),
            PressureState::Critical
        );
        // On a small host the absolute minimum applies rather than a derisory 10%.
        assert_eq!(
            classify_pressure(Some(0.0), 8 * gib, 8 * gib),
            PressureState::Ok
        );
    }

    #[test]
    fn status_and_group_parsing_match_the_real_formats() {
        let status = "Name:\tpython3\nVmPeak:\t  400000 kB\nVmHWM:\t  307200 kB\n\
                      VmRSS:\t  307200 kB\n";
        assert_eq!(parse_status_kb(status, "VmHWM"), Some(307_200 * 1024));
        // Exact key: VmRSS must not answer a request for VmHWM, nor VmPeak (virtual, meaningless
        // for a CUDA process).
        assert_eq!(parse_status_kb(status, "VmHWMX"), None);
        assert_eq!(parse_status_kb("Name:\tx\n", "VmHWM"), None);
        // pgid is field 5, read past a comm that may contain spaces and parens.
        assert_eq!(
            group_of_stat("101 (sp1 gpu (server)) S 100 4242 4242 0 -1\n"),
            Some(4242)
        );
        assert_eq!(group_of_stat("garbage"), None);
    }

    /// The live signals must actually be present here, because every layer above depends on them.
    #[test]
    fn this_host_reports_the_signals_we_depend_on() {
        let total = mem_total_bytes().expect("MemTotal");
        let avail = mem_available_bytes().expect("MemAvailable");
        assert!(total > 1 << 30, "implausible MemTotal: {total}");
        assert!(
            avail <= total,
            "MemAvailable {avail} exceeds MemTotal {total}"
        );
        // PSI and the cgroup counter are optional by design; assert only that reading them does not
        // panic and that, when present, the values are sane.
        if let Some(p) = memory_stall_percent() {
            assert!((0.0..=100.0).contains(&p), "implausible PSI: {p}");
        }
        if let Some(k) = oom_kill_count() {
            // Cumulative counter; it can legitimately be any value including 0.
            assert!(k < u64::MAX);
        }
    }
}

/// Volunteer the CURRENT process as the kernel's first OOM victim.
///
/// `+800` of the `-1000..=1000` range, added to the heuristic score, makes a prover the first
/// choice essentially always. Raising is unprivileged; only lowering needs `CAP_SYS_RESOURCE`.
/// The value is INHERITED across `fork` and preserved across `exec`, which is the property that
/// really matters here: the SP1 SDK forks `sp1-gpu-server` itself, so we cannot set it on that
/// process directly, and inheritance is the only way it gets covered.
///
/// # Safety and placement
///
/// Written with raw syscalls, and deliberately so: this is called from a `pre_exec` closure,
/// between `fork` and `exec`, where only async-signal-safe calls are legal. `std::fs` allocates;
/// `open`/`write`/`close` do not. Nothing here allocates, locks, or panics.
///
/// Failure is ignored on purpose. A container with a read-only `/proc/self` must not be a reason
/// to refuse to prove — the host simply loses this one layer of the defence.
///
/// Lives here, rather than inline in `worker::spawn_on_this_thread`, so the test that checks the
/// value actually reaches the kernel exercises THIS code instead of a copy of it.
#[cfg(unix)]
pub(crate) fn volunteer_as_oom_victim() {
    const PATH: &[u8] = b"/proc/self/oom_score_adj\0";
    const VALUE: &[u8] = b"800\n";
    // SAFETY: `PATH` is a NUL-terminated literal; `write` is given a valid pointer and its own
    // length; the fd is closed on every path where it was opened. All three are
    // async-signal-safe, which is the requirement for running between fork and exec.
    unsafe {
        let fd = libc::open(PATH.as_ptr() as *const libc::c_char, libc::O_WRONLY);
        if fd >= 0 {
            let _ = libc::write(fd, VALUE.as_ptr() as *const libc::c_void, VALUE.len());
            libc::close(fd);
        }
    }
}

/// Does the protection actually reach the kernel? These spawn real processes and read `/proc`.
#[cfg(all(test, unix))]
mod live_tests {
    use super::*;

    /// A worker must volunteer as the OOM victim, and its CHILDREN must inherit that — the latter is
    /// the point, because `sp1-gpu-server` is forked by the SDK where we cannot reach it.
    #[test]
    fn oom_score_adj_is_raised_and_inherited() {
        use std::os::unix::process::CommandExt;
        use std::process::{Command, Stdio};

        let mut cmd = Command::new("/bin/sh");
        cmd.arg("-c")
            // Print our own, then a CHILD's, so inheritance is observable.
            .arg("cat /proc/self/oom_score_adj; sh -c 'cat /proc/self/oom_score_adj'")
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        // The PRODUCTION call, not a copy of it. Re-implementing the `pre_exec` body here would let
        // deleting the real one leave the test green.
        unsafe {
            cmd.pre_exec(|| {
                volunteer_as_oom_victim();
                Ok(())
            });
        }
        let out = cmd.output().expect("spawn /bin/sh");
        let text = String::from_utf8_lossy(&out.stdout);
        let vals: Vec<&str> = text.split_whitespace().collect();
        assert_eq!(
            vals.len(),
            2,
            "expected the worker's value and its child's, got {text:?}"
        );
        assert_eq!(
            vals[0], "800",
            "the worker did not raise its own oom_score_adj"
        );
        assert_eq!(
            vals[1], "800",
            "a forked child did not INHERIT it — that inheritance is the only way the SDK's \
             sp1-gpu-server gets covered"
        );
    }

    /// The pid guard every group kill passes through. Verified against real processes, because
    /// the whole point is that `/proc` agrees with us about who owns a number.
    #[test]
    fn only_our_own_group_leading_children_may_be_signalled() {
        use std::process::{Command, Stdio};

        // Our own pid: we are a child of the test harness, not of ourselves.
        assert!(
            !pid_is_our_worker(std::process::id(), None),
            "this process is not its own child"
        );
        // pid 1 is nobody's child here.
        assert!(!pid_is_our_worker(1, None));
        assert!(
            !pid_is_our_worker(0, None),
            "0 means no worker, and kill(0) is us"
        );

        // A child that does NOT lead its own group: our child, but signalling its group would
        // signal OURS. `may_signal_group` catches that case by pgid; this must too.
        let mut plain = Command::new("/bin/sh")
            .arg("-c")
            .arg("sleep 10")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn");
        assert!(
            !pid_is_our_worker(plain.id(), None),
            "a child that shares our process group must not be group-signalled"
        );
        let _ = plain.kill();
        let _ = plain.wait();

        // A child that leads its own group, exactly as `pre_exec`'s `setpgid(0, 0)` arranges.
        use std::os::unix::process::CommandExt;
        let mut cmd = Command::new("/bin/sh");
        cmd.arg("-c")
            .arg("sleep 10")
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        unsafe {
            cmd.pre_exec(|| {
                if libc::setpgid(0, 0) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut leader = cmd.spawn().expect("spawn group leader");
        let leader_pid = leader.id();
        let start = pid_starttime(leader_pid).expect("live child has a start time");
        assert!(
            pid_is_our_worker(leader_pid, Some(start)),
            "our own group-leading child IS signallable"
        );

        // The START TIME is what makes the pid an identity. Parent-and-group alone cannot tell this
        // worker from the NEXT worker this same process forks into the same recycled number — which
        // would satisfy both conditions and send SIGKILL to a healthy, mid-proof worker's group.
        assert!(
            !pid_is_our_worker(leader_pid, Some(start.wrapping_add(1))),
            "a different start time means a different process, whatever the pid says"
        );

        // And after the reap the number must stop being signallable — the whole hazard.
        let _ = leader.kill();
        let _ = leader.wait();
        assert!(
            !pid_is_our_worker(leader_pid, Some(start)),
            "a reaped pid must never be group-signalled: the kernel may have reused it"
        );
    }

    /// The call above proves the MECHANISM works. It cannot prove the mechanism is still WIRED IN,
    /// because it builds its own `Command` — delete the call from `worker::spawn_on_this_thread`
    /// and that test stays green.
    ///
    /// Reaching the real path means spawning a real worker binary that completes a handshake,
    /// which is not available in a unit test. So this checks the wiring the only other way
    /// available: in the source. A source assertion is a blunt instrument and normally the wrong
    /// one, but the alternative here is no coverage at all of the single line that stands between
    /// an OOM storm and the host's own processes, and that line is deletable in one keystroke.
    #[test]
    fn the_spawn_path_still_volunteers_the_worker() {
        let src = include_str!("worker.rs");
        let pre_exec = src
            .split_once("cmd.pre_exec(")
            .expect("worker spawn no longer installs a pre_exec hook")
            .1;
        assert!(
            pre_exec.contains("volunteer_as_oom_victim()"),
            "the worker spawn path no longer raises oom_score_adj. If this moved deliberately, \
             move this assertion with it — do not delete it: without that call the kernel picks \
             its OOM victim by size, and on this workload the biggest process is as likely to be \
             the user's desktop as the prover."
        );
    }

    /// The cap must land on the pid we already own, leaving its identity alone. If this ever starts
    /// reporting a different pid, every pid-keyed path in `worker.rs` is compromised.
    #[test]
    fn capping_preserves_pid_identity_and_applies_a_real_limit() {
        let mut child = std::process::Command::new("/bin/sh")
            .arg("-c")
            .arg("sleep 20")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("spawn");
        let pid = child.id();

        let applied = cap_process_memory(pid, "livetest:cuda:0", 2 * 1024 * 1024 * 1024);

        // The pid must not have changed, and it must still be OUR child.
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap_or_default();
        assert!(
            !stat.is_empty(),
            "pid {pid} vanished — identity was not preserved"
        );
        let ppid: i32 = stat
            .rsplit_once(')')
            .and_then(|(_, rest)| rest.split_whitespace().nth(1))
            .and_then(|v| v.parse().ok())
            .unwrap_or(-1);
        assert_eq!(
            ppid,
            std::process::id() as i32,
            "the capped process must still be a direct child of ours"
        );

        match applied {
            Ok(unit) => {
                // WAIT for it. `StartTransientUnit` returns a job, so the move is asynchronous —
                // reading the cgroup immediately is a race, and losing that race makes the read
                // fail intermittently. This is the same window the production code documents, and
                // is why `oom_score_adj` is the layer that has no window.
                let deadline = std::time::Instant::now() + Duration::from_secs(5);
                let mut max = String::new();
                let mut swap = String::new();
                let mut rel = String::new();
                while std::time::Instant::now() < deadline {
                    let cg =
                        std::fs::read_to_string(format!("/proc/{pid}/cgroup")).unwrap_or_default();
                    rel = cg
                        .lines()
                        .next()
                        .and_then(|l| l.rsplit_once("::").map(|(_, p)| p.to_string()))
                        .unwrap_or_default();
                    max = std::fs::read_to_string(format!("/sys/fs/cgroup{rel}/memory.max"))
                        .unwrap_or_default();
                    swap = std::fs::read_to_string(format!("/sys/fs/cgroup{rel}/memory.swap.max"))
                        .unwrap_or_default();
                    if max.trim() == "2147483648" {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(50));
                }
                assert_eq!(
                    max.trim(),
                    "2147483648",
                    "memory.max never took effect for unit {unit} (pid {pid} in cgroup {rel:?}, \
                     read {max:?})"
                );
                assert_eq!(
                    swap.trim(),
                    "0",
                    "swap must be disabled: swap turns a kill into a stall, and a stalling host is \
                     the failure this is preventing (unit {unit}, cgroup {rel:?})"
                );
            }
            Err(why) => {
                // No systemd user bus (CI, a container, a non-systemd init) is a supported state:
                // the cap is best effort and `oom_score_adj` still protects the host.
                eprintln!("cap unavailable here, which is allowed: {why}");
            }
        }

        let _ = child.kill();
        let _ = child.wait();
    }
}

/// Windows' identity check and terminate, against a real process.
#[cfg(all(test, windows))]
mod windows_pid_tests {
    use super::*;

    #[test]
    fn terminates_only_the_process_its_creation_time_names() {
        let mut child = std::process::Command::new("ping")
            .args(["-n", "60", "127.0.0.1"])
            .stdout(std::process::Stdio::null())
            .spawn()
            .expect("spawn ping");
        let pid = child.id();
        let start = pid_starttime(pid).expect("a live child has a creation time");

        assert!(!pid_is_our_worker(0, Some(start)), "pid 0 is never ours");
        assert!(
            !pid_is_our_worker(pid, None),
            "no creation time, no identity"
        );
        assert!(pid_is_our_worker(pid, Some(start)));

        // A different creation time is a different process: refused, and left running.
        assert!(!terminate_if_our_worker(pid, Some(start.wrapping_add(1))));
        assert!(child.try_wait().unwrap().is_none(), "still running");
        assert!(!terminate_if_our_worker(pid, None));

        assert!(terminate_if_our_worker(pid, Some(start)));
        child.wait().expect("terminated child is reaped");
    }

    /// A child's parent is us, and a pid that does not exist has none.
    #[test]
    fn a_child_names_its_parent() {
        let mut child = std::process::Command::new("ping")
            .args(["-n", "60", "127.0.0.1"])
            .stdout(std::process::Stdio::null())
            .spawn()
            .expect("spawn ping");
        assert_eq!(parent_pid(child.id()), Some(std::process::id()));
        child.kill().unwrap();
        child.wait().unwrap();
        assert_eq!(parent_pid(u32::MAX - 3), None);
    }
}

/// The measurement is optimistic by construction, so turning it into a budget is where the
/// freeze-or-not decision really lives.
#[cfg(test)]
mod budget_tests {
    use super::*;

    const GIB: u64 = 1024 * 1024 * 1024;

    /// The Linux blind default for `backend`, which the 28 GiB box these tests describe charges;
    /// on Windows the figures are commit, and larger.
    fn linux_default(backend: &str) -> u64 {
        if cfg!(windows) {
            match backend {
                "risc0" => 6 * GIB,
                _ => 18 * GIB,
            }
        } else {
            unmeasured_peak_for(backend)
        }
    }

    /// A raw measurement must never be used as the budget: it comes from a composite receipt at the
    /// default segment size, while production runs a Groth16 wrap at the resolved po2, and this
    /// project's own model has memory doubling per po2 step.
    ///
    /// Linux figures: on Windows the blind defaults (commit) are above these readings doubled, so
    /// the floor answers (`windows_commit_tests`).
    #[cfg(not(windows))]
    #[test]
    fn a_measurement_is_scaled_before_it_is_trusted() {
        let big = 512 * GIB; // a host large enough that the clamp is not what we are testing
        assert_eq!(budget_from_measurement(4 * GIB, "risc0", big), 8 * GIB);
        assert_eq!(budget_from_measurement(9 * GIB, "sp1", big), 18 * GIB);
        // The scenario this prevents: a 2 GiB reading on a 28 GiB box. Unscaled it licenses ~11
        // concurrent proofs; four was enough to require a power cycle.
        let unscaled_concurrency = (28 * GIB - 3 * GIB) / (2 * GIB);
        let scaled_concurrency =
            (28 * GIB - 3 * GIB) / budget_from_measurement(2 * GIB, "risc0", big);
        assert!(
            scaled_concurrency * 2 <= unscaled_concurrency,
            "scaling must materially reduce admitted concurrency: {scaled_concurrency} vs \
             {unscaled_concurrency}"
        );
    }

    /// An ACCURATE benchmark must not disable the backend. Unclamped, `measured * 2` above
    /// `total - reserve` would make `can_admit`'s committed condition unsatisfiable at any level of
    /// free memory — so measuring this box's real 16.4 GiB SP1 peak would retire SP1 permanently,
    /// silently, with no recovery but deleting the cache. One proof at a time is the truth about such
    /// a host.
    #[test]
    fn an_honest_measurement_cannot_brick_a_backend() {
        let total = 28 * GIB;
        let reserve = DEFAULT_HOST_RESERVE_BYTES;
        // The real observed SP1 figure: 17.6 GB ~= 16.4 GiB. 2x is 32.8 GiB, past the machine.
        let measured = 17_600 * 1024 * 1024;
        let budget = budget_from_measurement(measured, "sp1", total);
        assert!(
            budget <= max_admissible_budget(total),
            "a budget above {} can never be admitted: {budget}",
            max_admissible_budget(total)
        );
        // An idle host on this hardware reports ~92% of MemTotal as available. The clamped budget
        // must be admissible THERE, not merely against `total` — a bound that only satisfies the
        // committed condition is the same permanent refusal wearing a different hat.
        let idle_available = total / 100 * 92;
        assert!(
            can_admit(budget, 0, 0, idle_available, total, reserve),
            "the clamped budget must admit ONE proof on a realistically idle host: budget {budget}, \
             available {idle_available}"
        );
        // And it must still refuse a second.
        assert!(
            !can_admit(budget, 0, budget, idle_available, total, reserve),
            "one at a time, not two"
        );
    }

    /// Measuring must never buy MORE concurrency than knowing nothing would.
    ///
    /// Returning `measured * FACTOR` outright would let a 3 GiB SP1 reading — plausible, given
    /// that the benchmark proves a composite receipt at the default segment size — yield a 6 GiB
    /// budget against an 18 GiB blind default, and license three concurrent proofs of a workload
    /// observed at 17.6 GB each. It would also be non-monotonic across the trust floor: 1.9 GiB
    /// charging 18 GiB while 2.0 GiB charges 4 GiB.
    #[test]
    fn a_cheap_measurement_cannot_undercut_the_blind_default() {
        let big = 512 * GIB;
        assert_eq!(
            budget_from_measurement(3 * GIB, "sp1", big),
            unmeasured_peak_for("sp1"),
            "a 3 GiB SP1 reading must not license three concurrent 17.6 GB proofs"
        );
        // Monotonicity across the trust floor, in both directions.
        let just_below = budget_from_measurement(MIN_TRUSTED_PEAK_BYTES - 1, "sp1", big);
        let just_above = budget_from_measurement(MIN_TRUSTED_PEAK_BYTES, "sp1", big);
        assert!(
            just_above >= just_below,
            "a larger measurement must not produce a smaller charge: {just_below} -> {just_above}"
        );
    }

    /// An implausibly small reading is not a cheap proof, it is a failed measurement — most likely
    /// the composite path at a small segment size, or the window before the cgroup cap applied,
    /// whose charges stay with the miner's cgroup and never reach the worker's counter.
    #[test]
    fn an_implausible_measurement_is_rejected_not_scaled() {
        assert_eq!(
            budget_from_measurement(100 * 1024 * 1024, "risc0", 512 * GIB),
            unmeasured_peak_for("risc0"),
            "a 100 MiB 'GPU proof' is a failed measurement"
        );
        assert_eq!(
            budget_from_measurement(0, "sp1", 512 * GIB),
            unmeasured_peak_for("sp1"),
            "zero is not free, it is unmeasured"
        );
    }

    /// One blunt default for every backend is its own outage: charging risc0 the SP1 figure needs
    /// ~21 GiB free before anything is admitted, so a host with idle workers mines nothing and says
    /// only "cannot fit it right now".
    /// The Linux figures (resident memory); Windows charges commit, with its own defaults
    /// (`windows_commit_tests`).
    #[cfg(not(windows))]
    #[test]
    fn unmeasured_defaults_are_per_backend_and_let_this_box_work() {
        let total = 28 * GIB;
        let reserve = DEFAULT_HOST_RESERVE_BYTES;
        // SP1's default has to be big enough to REFUSE the configuration that actually killed
        // this box: ~17.6 GB resident with the rest of the system wanting its share. Asserting
        // the constant's value would just restate the constant, so assert the behaviour — a box
        // with 19 GiB free must not admit an unmeasured SP1 proof, because that is the case that
        // OOMed.
        assert!(
            !can_admit(unmeasured_peak_for("sp1"), 0, 0, 19 * GIB, total, reserve),
            "the unmeasured SP1 default is small enough to admit the proof that OOM-killed this \
             host at ~17.6 GB resident"
        );
        // risc0's must leave room for two on this box, or an unbenchmarked 2-GPU host idles.
        let risc0 = unmeasured_peak_for("risc0");
        assert!(
            can_admit(risc0, 0, risc0, total - 2 * risc0, total, reserve),
            "two unmeasured risc0 proofs must fit on a 28 GiB box, else an unbenchmarked host \
             never mines"
        );
        // And SP1 must still be admissible alone, or the backend is dead on this hardware.
        assert!(can_admit(
            unmeasured_peak_for("sp1"),
            0,
            0,
            25 * GIB,
            total,
            reserve
        ));
    }

    /// Why `resident` is an argument at all: a worker that keeps its allocations between
    /// proofs must not be charged for them twice.
    ///
    /// The SP1 worker caches `CudaProver` and its proving keys on purpose, so after proof #1
    /// `sp1-gpu-server` sits resident at its full working set. `MemAvailable` is down by that much
    /// ALREADY. Charging proof #2 the whole 18 GiB again would refuse it — and every risc0 proof too
    /// — on a host that genuinely had room, with the ledger reading 0 and every layer reporting
    /// healthy. A permanent earnings outage dressed as safety.
    #[test]
    fn a_resident_worker_is_not_charged_for_its_memory_twice() {
        let total = 28 * GIB;
        let reserve = DEFAULT_HOST_RESERVE_BYTES;
        let sp1 = linux_default("sp1");
        // Proof #1 on an idle box: admitted.
        assert!(can_admit(sp1, 0, 0, 25 * GIB, total, reserve));
        // sp1-gpu-server is now resident at ~17.6 GiB, so MemAvailable has fallen to ~7.4 GiB and
        // the reservation for proof #1 has been released.
        let resident = 17_600 * 1024 * 1024;
        let available = 25 * GIB - resident;
        // Without `resident` this is `18 + 3 <= 7.4` — refused forever.
        assert!(
            can_admit(sp1, resident, 0, available, total, reserve),
            "proof #2 on the same slot must be admitted: the pages it needs are already held"
        );
        // A risc0 proof on a DIFFERENT slot is still refused here, and correctly so: 7.4 GiB of
        // real headroom minus the 3 GiB host reserve leaves 4.4 GiB, and the proof wants 6. That
        // refusal is the gate working, not collateral damage — the bug was only ever the slot whose
        // own worker already holds the pages.
        let risc0 = linux_default("risc0");
        assert!(!can_admit(risc0, 0, 0, available, total, reserve));
        // Give it genuine room and it is admitted, which is what distinguishes the two cases.
        assert!(can_admit(risc0, 0, 0, 10 * GIB, total, reserve));
        // But `resident` must NOT buy a second concurrent SP1 proof: the committed condition is
        // tested on the ABSOLUTE peak, so two 18 GiB proofs still do not fit in 28 GiB.
        assert!(
            !can_admit(sp1, resident, sp1, available, total, reserve),
            "netting out `resident` must not wave through two concurrent SP1 proofs"
        );
    }

    /// The refusal above is right as far as `can_admit` goes, and it was permanent: nothing gave the
    /// idle SP1 worker's pages back. `plan_host_room` names the worker whose recycle makes it fit.
    #[test]
    fn an_idle_worker_of_another_backend_is_recycled_to_make_room() {
        let total = 28 * GIB;
        let reserve = DEFAULT_HOST_RESERVE_BYTES;
        let risc0 = linux_default("risc0");
        // An idle sp1-gpu-server has been observed holding 23.3 GB.
        let sp1_idle = 23_300_000_000;
        let available = total - sp1_idle - GIB;
        assert!(!can_admit(risc0, 0, 0, available, total, reserve));
        let idle = vec![("sp1:cuda:0".to_string(), sp1_idle)];
        assert_eq!(
            plan_host_room(risc0, 0, 0, available, total, reserve, &idle, GIB),
            Some(vec!["sp1:cuda:0".to_string()])
        );
        // Room already there: nothing is recycled.
        assert_eq!(
            plan_host_room(risc0, 0, 0, 20 * GIB, total, reserve, &idle, GIB),
            Some(Vec::new())
        );
    }

    #[test]
    fn as_few_warm_workers_as_possible_are_recycled() {
        let total = 28 * GIB;
        let reserve = DEFAULT_HOST_RESERVE_BYTES;
        let idle = vec![
            ("risc0:cuda:1".to_string(), 2 * GIB),
            ("sp1:cuda:0".to_string(), 20 * GIB),
            ("openvm:generic".to_string(), 3 * GIB),
        ];
        // 5 GiB short: the 20 GiB worker alone covers it, so it alone goes.
        assert_eq!(
            plan_host_room(6 * GIB, 0, 0, 4 * GIB, total, reserve, &idle, GIB),
            Some(vec!["sp1:cuda:0".to_string()])
        );
        // A holding below the floor is never chosen, even when it would be enough.
        let small = vec![("risc0:cuda:1".to_string(), 512 * 1024 * 1024)];
        assert_eq!(
            plan_host_room(
                6 * GIB,
                0,
                0,
                8 * GIB + 700 * 1024 * 1024,
                total,
                reserve,
                &small,
                GIB
            ),
            None
        );
    }

    /// No warm worker is destroyed for a proof that would be refused anyway.
    #[test]
    fn nothing_is_recycled_when_it_cannot_make_room() {
        let total = 28 * GIB;
        let reserve = DEFAULT_HOST_RESERVE_BYTES;
        let idle = vec![("sp1:cuda:0".to_string(), 4 * GIB)];
        // Live headroom: even with the 4 GiB back, 1 + 4 < 6 + 3.
        assert_eq!(
            plan_host_room(6 * GIB, 0, 0, GIB, total, reserve, &idle, GIB),
            None
        );
        // Commitments: 20 GiB already reserved by proofs in flight, plus 6, plus the 3 GiB reserve,
        // exceeds 28 GiB however much is free, so recycling cannot help.
        let big = vec![("sp1:cuda:0".to_string(), 23 * GIB)];
        assert_eq!(
            plan_host_room(6 * GIB, 0, 20 * GIB, 2 * GIB, total, reserve, &big, GIB),
            None
        );
    }

    // ---- plan_measure_preemption (residual A) ----

    /// The canonical marginal-box case: a 12 GiB SP1 MEASURE is in flight and an 18 GiB claimed
    /// PROVE cannot fit (12 + 18 + 3 > 28). Preempting the one measurement returns its 12 GiB charge
    /// to `reserved` AND its pages to `available`, and the prove fits — so the plan is exactly that
    /// one measurement.
    #[test]
    fn a_claimed_prove_preempts_the_measure_that_blocks_it() {
        let total = 28 * GIB;
        let reserve = DEFAULT_HOST_RESERVE_BYTES;
        // 12 GiB measure reserved; ~10 GiB available (the measure + OS hold the rest). The prove is
        // refused now (fits_committed 12 + 18 + 3 = 33 > 28), and freeing the measure's 12 GiB raises
        // reserved to 0 and available to 22, so 18 + 3 = 21 <= 22 and 18 + 3 <= 28 — it fits.
        let measures = vec![("sp1:measure:0".to_string(), 12 * GIB)];
        assert_eq!(
            plan_measure_preemption(18 * GIB, 0, 12 * GIB, 10 * GIB, total, reserve, &measures),
            Some(vec!["sp1:measure:0".to_string()]),
            "preempting the 12 GiB measure must let the 18 GiB prove fit"
        );
    }

    /// Already fits (room appeared since the caller's refusal): kill nothing.
    #[test]
    fn plan_measure_preemption_kills_nothing_when_it_already_fits() {
        let total = 28 * GIB;
        let reserve = DEFAULT_HOST_RESERVE_BYTES;
        let measures = vec![("sp1:measure:0".to_string(), 12 * GIB)];
        assert_eq!(
            plan_measure_preemption(6 * GIB, 0, 12 * GIB, 16 * GIB, total, reserve, &measures),
            Some(Vec::new()),
            "6 + 12 + 3 <= 28 and 6 <= 16 free: it fits, so preempt nothing"
        );
    }

    /// The blocker is another bonded PROOF, not a measurement: even preempting every measurement
    /// leaves `reserved` too high. `None` — the caller must never preempt a bonded proof.
    #[test]
    fn plan_measure_preemption_refuses_when_a_bonded_proof_is_the_blocker() {
        let total = 28 * GIB;
        let reserve = DEFAULT_HOST_RESERVE_BYTES;
        // 20 GiB held by an in-flight PROOF (not in `measures`) + a 2 GiB measure. Freeing the 2 GiB
        // measure still leaves 20 + 18 + 3 > 28.
        let measures = vec![("sp1:measure:0".to_string(), 2 * GIB)];
        assert_eq!(
            plan_measure_preemption(18 * GIB, 0, 22 * GIB, 2 * GIB, total, reserve, &measures),
            None,
            "a bonded proof holding the RAM must not be preempted — refuse"
        );
    }

    /// Biggest-first, minimal set: with two measures, prefer the one whose single preemption suffices
    /// rather than killing both.
    #[test]
    fn plan_measure_preemption_prefers_the_minimal_biggest_first_set() {
        let total = 28 * GIB;
        let reserve = DEFAULT_HOST_RESERVE_BYTES;
        let measures = vec![
            ("sp1:measure:0".to_string(), 4 * GIB),
            ("sp1:measure:1".to_string(), 10 * GIB),
        ];
        // Need to free ~10 GiB: reserved 14, want 10 -> 14 + 10 + 3 = 27... refuse at 28? 27 <= 28
        // fits_committed, but available 2 GiB blocks fits_now (10 - 0 + 3 = 13 > 2). Freeing the 10
        // GiB one: reserved 4, available 12 -> 10 + 3 = 13 > 12 still short; also free the 4 GiB one:
        // reserved 0, available 16 -> 13 <= 16. So both, biggest first.
        assert_eq!(
            plan_measure_preemption(10 * GIB, 0, 14 * GIB, 2 * GIB, total, reserve, &measures),
            Some(vec!["sp1:measure:1".to_string(), "sp1:measure:0".to_string()]),
        );
        // A looser case where freeing only the biggest suffices.
        let measures2 = vec![
            ("sp1:measure:0".to_string(), 4 * GIB),
            ("sp1:measure:1".to_string(), 10 * GIB),
        ];
        assert_eq!(
            plan_measure_preemption(10 * GIB, 0, 14 * GIB, 11 * GIB, total, reserve, &measures2),
            Some(vec!["sp1:measure:1".to_string()]),
            "freeing the 10 GiB measure alone makes it fit — do not also kill the 4 GiB one"
        );
    }

    /// Nothing is preemptible (empty registry) and it does not fit: `None`.
    #[test]
    fn plan_measure_preemption_with_no_measures_refuses() {
        let total = 28 * GIB;
        let reserve = DEFAULT_HOST_RESERVE_BYTES;
        assert_eq!(
            plan_measure_preemption(18 * GIB, 0, 20 * GIB, 2 * GIB, total, reserve, &[]),
            None
        );
    }
}

#[cfg(test)]
mod process_tree_tests {
    use super::{tree_from, tree_root_started};

    /// The root a retired worker's tree is walked from: the live process only if it is still the
    /// worker (same start time), the worker's recorded start when it has already exited.
    #[test]
    fn a_tree_is_walked_from_the_worker_itself_or_not_at_all() {
        assert_eq!(tree_root_started(Some(100), Some(100)), Some(100));
        assert_eq!(tree_root_started(Some(100), None), Some(100));
        // A stranger now has the number.
        assert_eq!(tree_root_started(Some(200), Some(100)), None);
        // The worker has exited: its children recorded it, and are found from its start.
        assert_eq!(tree_root_started(None, Some(100)), Some(100));
        assert_eq!(tree_root_started(None, None), None);
    }

    /// Children by recorded parent, each started no earlier than its parent (a recorded parent pid
    /// may since belong to another process), transitively; one whose start cannot be read is left
    /// out with what it started.
    #[test]
    fn a_tree_holds_what_the_worker_started_and_nothing_older() {
        // pid: start time.
        let started = |pid: u32| match pid {
            10 => Some(100),
            11 => Some(110), // the worker's server
            12 => Some(120), // started by the server
            13 => Some(90),  // records 10 as its parent, but is older: another process's child
            14 => None,      // gone, or unreadable
            15 => Some(150), // started by 14
            20 => Some(105), // somebody else's
            _ => None,
        };
        let parents = [
            (11, 10),
            (12, 11),
            (13, 10),
            (14, 10),
            (15, 14),
            (20, 1),
            (10, 1),
        ];
        let mut tree = tree_from(10, 100, &parents, started);
        tree.sort();
        assert_eq!(tree, vec![(10, 100), (11, 110), (12, 120)]);
        // From an exited worker's recorded start, its children are still found.
        let gone = |pid: u32| if pid == 10 { None } else { started(pid) };
        let mut tree = tree_from(10, 100, &parents, gone);
        tree.sort();
        assert_eq!(tree, vec![(10, 100), (11, 110), (12, 120)]);
        // A cycle in the recorded parents (reused numbers) ends.
        let cyclic = [(11, 10), (10, 11)];
        assert_eq!(tree_from(10, 100, &cyclic, started).len(), 2);
    }
}

#[cfg(test)]
mod windows_commit_tests {
    use super::*;
    use std::collections::HashMap;

    const GIB: u64 = 1024 * 1024 * 1024;

    /// RAM and commit are two measures: RAM is free physical memory, and commit is free commit
    /// plus how far the page files can grow. Figures from the machine this was measured on: 74 GB
    /// of RAM free while free commit fell to 40 GB during one SP1 proof, with a system-managed page
    /// file that can grow by 280 GB.
    #[test]
    fn commit_counts_what_the_page_file_can_still_grow() {
        let proving = WindowsMemoryStatus {
            total_phys: 94 * GIB,
            avail_phys: 74 * GIB,
            commit_limit: 100 * GIB,
            commit_free: 40 * GIB,
            commit_growth: 280 * GIB,
        };
        assert_eq!(
            commit_figures_of(&proving),
            CommitFigures {
                available: 320 * GIB,
                total: 380 * GIB,
                free_now: 40 * GIB,
                limit: 100 * GIB,
            }
        );
        // An SP1 proof committing 64 GiB fits, though free commit alone would not hold it.
        let c = commit_figures_of(&proving);
        assert!(can_admit(
            64 * GIB,
            0,
            0,
            c.available,
            c.total,
            DEFAULT_HOST_RESERVE_BYTES
        ));
        // A fixed page file cannot grow: commit is what is free, and it refuses.
        let fixed = commit_figures_of(&WindowsMemoryStatus {
            commit_growth: 0,
            ..proving
        });
        assert_eq!((fixed.available, fixed.total), (40 * GIB, 100 * GIB));
        assert!(!can_admit(
            64 * GIB,
            0,
            0,
            fixed.available,
            fixed.total,
            DEFAULT_HOST_RESERVE_BYTES
        ));
    }

    /// A page file grows to its maximum, within its disk's free space less a margin; one whose disk
    /// cannot be read, or a fixed one, does not.
    #[test]
    fn page_file_growth_is_bounded_by_its_maximum_and_its_disk() {
        assert_eq!(page_file_growth(&[]), 0);
        // System-managed on a roomy disk: up to its maximum.
        assert_eq!(
            page_file_growth(&[(7 * GIB, 288 * GIB, Some(2000 * GIB))]),
            281 * GIB
        );
        // Fixed: none.
        assert_eq!(
            page_file_growth(&[(40 * GIB, 40 * GIB, Some(2000 * GIB))]),
            0
        );
        // A nearly full disk: its free space less the margin.
        assert_eq!(
            page_file_growth(&[(7 * GIB, 288 * GIB, Some(10 * GIB))]),
            10 * GIB - PAGE_FILE_DISK_MARGIN_BYTES
        );
        assert_eq!(page_file_growth(&[(7 * GIB, 288 * GIB, Some(GIB))]), 0);
        // Unreadable disk: not counted on.
        assert_eq!(page_file_growth(&[(7 * GIB, 288 * GIB, None)]), 0);
        // Several: summed.
        assert_eq!(
            page_file_growth(&[
                (7 * GIB, 17 * GIB, Some(2000 * GIB)),
                (GIB, 6 * GIB, Some(2000 * GIB))
            ]),
            15 * GIB
        );
        // A second page file on a disk already counted (`page_files` gives it 0 free): none.
        assert_eq!(
            page_file_growth(&[
                (7 * GIB, 17 * GIB, Some(2000 * GIB)),
                (GIB, 6 * GIB, Some(0))
            ]),
            10 * GIB
        );
        // The pinned margin: 4 GiB, or a twentieth of a small limit.
        assert_eq!(pinned_commit_margin(100 * GIB), PINNED_COMMIT_MARGIN_BYTES);
        assert_eq!(pinned_commit_margin(40 * GIB), 2 * GIB);
    }

    /// Reservations on two ledgers, paired, are released together.
    #[test]
    fn a_paired_reservation_releases_both() {
        let ram = MemoryLedger::default();
        let commit = MemoryLedger::default();
        let reserve = DEFAULT_HOST_RESERVE_BYTES;
        let a = ram
            .try_reserve(10 * GIB, 0, 50 * GIB, 100 * GIB, reserve)
            .unwrap();
        let b = commit
            .try_reserve(30 * GIB, 0, 300 * GIB, 400 * GIB, reserve)
            .unwrap();
        let both = a.pair(b);
        assert_eq!(
            (ram.reserved_bytes(), commit.reserved_bytes()),
            (10 * GIB, 30 * GIB)
        );
        drop(both);
        assert_eq!((ram.reserved_bytes(), commit.reserved_bytes()), (0, 0));
    }

    /// A card's learned figure: the smallest po2 at or above the proof's, with the margin, inside
    /// what is believed and what the host can admit.
    #[test]
    fn a_card_is_charged_what_its_own_proofs_reached() {
        let total = 94 * GIB;
        let mut learned = LearnedPeaks::new();
        assert_eq!(learned_host_peak(&learned, Some(20), total), None);
        assert!(note_learned_peak(&mut learned, Some(20), 24 * GIB));
        // 24 GiB with an eighth on top.
        assert_eq!(learned_host_peak(&learned, Some(20), total), Some(27 * GIB));
        // A proof at a smaller po2 is bounded by one at a larger.
        assert_eq!(learned_host_peak(&learned, Some(19), total), Some(27 * GIB));
        // One at a larger po2 is not: nothing is known about it.
        assert_eq!(learned_host_peak(&learned, Some(21), total), None);
        // No po2 is the baseline.
        assert_eq!(learned_host_peak(&learned, None, total), Some(27 * GIB));
        // A lower reading (a respawned worker) leaves the higher one standing.
        assert!(!note_learned_peak(&mut learned, Some(20), 20 * GIB));
        assert_eq!(learned_host_peak(&learned, Some(20), total), Some(27 * GIB));
        // A higher one raises it.
        assert!(note_learned_peak(&mut learned, Some(20), 32 * GIB));
        assert_eq!(learned_host_peak(&learned, Some(20), total), Some(36 * GIB));
        // The nearest po2 at or above answers, not the largest.
        assert!(note_learned_peak(&mut learned, Some(22), 48 * GIB));
        assert_eq!(learned_host_peak(&learned, Some(20), total), Some(36 * GIB));
        assert_eq!(learned_host_peak(&learned, Some(21), total), Some(54 * GIB));
        // Never above what the host can admit, nor below what is believed at all.
        let mut huge = LearnedPeaks::new();
        note_learned_peak(&mut huge, Some(20), 90 * GIB);
        assert_eq!(
            learned_host_peak(&huge, Some(20), total),
            Some(max_admissible_budget(total))
        );
        let mut tiny = LearnedPeaks::new();
        note_learned_peak(&mut tiny, Some(20), 100 * 1024 * 1024);
        assert_eq!(
            learned_host_peak(&tiny, Some(20), total),
            Some(MIN_TRUSTED_PEAK_BYTES)
        );
    }

    /// A failure is the host's when the exit code says the process could not get memory, or when
    /// free commit fell during the proof to the low-water bound; otherwise it is not.
    #[test]
    fn a_failure_is_the_hosts_by_its_exit_code_or_a_fall_in_commit() {
        let plenty = (Some(40 * GIB), Some(40 * GIB));
        // NTSTATUS codes, as the negative numbers `ExitStatus::code` gives.
        for status in [0xC000_012Du32, 0xC000_0017, 0xC000_009A] {
            assert!(windows_failure_is_host_shortage(
                Some(status as i32),
                plenty.0,
                plenty.1
            ));
        }
        assert!(windows_failure_is_host_shortage(
            Some(1455),
            plenty.0,
            plenty.1
        ));
        // An access violation, a fast-fail abort, a plain error exit, an in-page error: not by
        // their code.
        for other in [0xC000_0005u32, 0xC000_0409, 1, 0xC000_0006] {
            assert!(!windows_failure_is_host_shortage(
                Some(other as i32),
                plenty.0,
                plenty.1
            ));
            assert!(!windows_failure_is_host_shortage(
                Some(other as i32),
                None,
                None
            ));
        }
        // By a fall to the low water, whatever the code, and with none (a worker that reported its
        // error).
        assert!(windows_failure_is_host_shortage(
            Some(0xC000_0409u32 as i32),
            Some(30 * GIB),
            Some(HOST_SHORT_LOW_WATER_BYTES)
        ));
        assert!(windows_failure_is_host_shortage(
            None,
            Some(30 * GIB),
            Some(GIB)
        ));
        // An in-page error with commit at the low water is the host's, even with no fall (it started
        // there); with commit above it, it is not.
        let in_page = Some(0xC000_0006u32 as i32);
        assert!(windows_failure_is_host_shortage(
            in_page,
            Some(GIB),
            Some(GIB)
        ));
        assert!(!windows_failure_is_host_shortage(
            in_page,
            Some(GIB),
            Some(HOST_SHORT_LOW_WATER_BYTES + GIB)
        ));
        // Not low enough.
        assert!(!windows_failure_is_host_shortage(
            None,
            Some(30 * GIB),
            Some(HOST_SHORT_LOW_WATER_BYTES + 1)
        ));
        // Low, but it was low already: the proof did not run the host out.
        assert!(!windows_failure_is_host_shortage(
            None,
            Some(5 * GIB),
            Some(4 * GIB)
        ));
        assert!(windows_failure_is_host_shortage(
            None,
            Some(5 * GIB),
            Some(3 * GIB)
        ));
        // Nothing read.
        assert!(!windows_failure_is_host_shortage(None, None, Some(GIB)));
        assert!(!windows_failure_is_host_shortage(None, None, None));
    }

    /// The sampler reads free commit on Windows, from where it started, and keeps the least;
    /// elsewhere it reads nothing.
    #[test]
    fn the_low_water_keeps_the_least_reading() {
        let watch = LowWater::start(None);
        if cfg!(windows) {
            let start = watch.started_at().expect("read at start");
            let first = watch.lowest().expect("sampled at start");
            assert!(first <= start + GIB);
            std::thread::sleep(LOW_WATER_SAMPLE * 3);
            watch.sample();
            assert!(watch.lowest().expect("still read") <= first);
            assert!(watch.lowest().unwrap() <= commit_bytes().unwrap().1 + GIB);
        } else {
            watch.sample();
            assert_eq!((watch.started_at(), watch.lowest()), (None, None));
        }
    }

    /// The real figures on this machine: RAM is physical memory; commit includes the page files'
    /// growth; a live process's RAM and commit are read, for its tree, only under its own start time.
    #[cfg(windows)]
    #[test]
    fn this_machines_ram_and_commit_are_read() {
        let (limit, free) = commit_bytes().expect("GlobalMemoryStatusEx");
        assert!(limit > 0 && free <= limit);
        let phys = physical_total_bytes().unwrap();
        assert_eq!(mem_total_bytes().unwrap(), phys);
        assert!(mem_available_bytes().unwrap() <= phys);
        let c = commit_figures().expect("commit figures");
        // Read a moment apart, so within a GiB (a page file may grow in between).
        assert!(c.free_now <= free + GIB && free <= c.free_now + GIB);
        assert!(c.available >= c.free_now && c.total >= c.limit);
        assert_eq!(
            c.total - c.limit,
            c.available - c.free_now,
            "one reading, one growth"
        );
        assert!(pinned_commit_margin(c.limit) <= PINNED_COMMIT_MARGIN_BYTES);
        // Each page file, if any, can grow to no less than its size, on a disk that is read.
        let files = win32::page_files();
        for (current, maximum, disk) in &files {
            assert!(maximum >= current, "{files:?}");
            assert!(disk.is_some(), "{files:?}");
        }

        let me = std::process::id();
        let started = pid_starttime(me).expect("own start time");
        // Hold a known amount, touched, so it is committed and in RAM.
        let held = vec![1u8; 256 * 1024 * 1024];
        let m = tree_memory(me, Some(started)).expect("own memory");
        assert!(m.commit >= 256 * 1024 * 1024, "{m:?}");
        assert!(m.ram >= 200 * 1024 * 1024, "{m:?}");
        drop(held);
        // Another start time is another process with the same number: nothing.
        assert_eq!(tree_memory(me, Some(started + 1)), None);
        // The pressure check reads free RAM here (commit, with the page file's growth, is far
        // larger), and counts what idle workers hold of it as free, no more.
        let p = pressure_available_bytes(0, 0).unwrap();
        assert!(p <= mem_available_bytes().unwrap() + GIB);
        let with_idle = pressure_available_bytes(5 * GIB, 0).unwrap();
        assert!(with_idle <= p + 6 * GIB && with_idle + GIB >= p + 5 * GIB.min(c.available));
    }

    /// The host part of a proof starts now when free commit holds it, after the page file grows
    /// when its growth covers it, and not at all otherwise.
    #[test]
    fn the_host_part_starts_now_after_growing_or_not() {
        let f = CommitFigures {
            available: 300 * GIB,
            total: 400 * GIB,
            free_now: 20 * GIB,
            limit: 100 * GIB,
        };
        assert_eq!(host_commit_start(&f, 20 * GIB), HostCommitStart::Now);
        assert_eq!(
            host_commit_start(&f, 30 * GIB),
            HostCommitStart::AfterGrowing(10 * GIB)
        );
        assert_eq!(host_commit_start(&f, 301 * GIB), HostCommitStart::No);
        // A fixed page file: no growth, so short is short.
        let fixed = CommitFigures {
            available: 20 * GIB,
            ..f
        };
        assert_eq!(host_commit_start(&fixed, 30 * GIB), HostCommitStart::No);
    }

    /// The ledger says whether a slot's admission is tracked, and forgets it on release.
    #[test]
    fn the_ledger_knows_which_slots_it_tracks() {
        let ledger = MemoryLedger::default();
        let holding = |_: &str| None;
        assert!(!ledger.tracks("a"));
        let r = ledger
            .try_reserve_tracked(GIB, 0, 50 * GIB, 100 * GIB, 0, "a", holding)
            .unwrap();
        assert!(ledger.tracks("a") && !ledger.tracks("b"));
        drop(r);
        assert!(!ledger.tracks("a"));
    }

    /// Growing the page file ahead: what can be committed rises by what was asked, and stays up
    /// once released. `#[ignore]`d: it runs this machine's commit to its limit for a moment.
    ///
    ///   cargo test -p zkminer-prover --lib -- --ignored the_page_file_is_grown_ahead
    #[cfg(windows)]
    #[test]
    #[ignore = "runs the machine's commit to its limit for a moment"]
    fn the_page_file_is_grown_ahead() {
        let before = commit_figures().unwrap();
        if before.available < before.free_now + 4 * GIB {
            eprintln!("skipped: this machine's page file cannot grow by 4 GiB");
            return;
        }
        assert!(grow_commit(2 * GIB));
        let after = commit_bytes().unwrap();
        let grew = after.0.saturating_sub(before.limit);
        assert!(grew >= GIB, "{before:?} -> {after:?}");
        // Released at once: free commit is what it was, plus the growth.
        assert!(
            after.1 + GIB >= before.free_now + grew && after.1 <= before.free_now + grew + GIB,
            "{before:?} -> {after:?}"
        );
    }

    /// A claim that waits for a card is charged against what will be free when it starts, not
    /// against room beside the proofs running now; memory held by anything else still counts.
    #[test]
    fn a_queued_claim_counts_what_running_proofs_hand_back() {
        let reserve = 4 * GIB;
        // Two cards busy: SP1 (42 GiB) and RISC Zero (5 GiB) running, 6 GiB free.
        let (running, free) = (47 * GIB, 6 * GIB);
        // A RISC Zero claim waits for a card; it will run beside one SP1 at most (47 GiB).
        let set = claim_set_bytes(5 * GIB, 1, 1, 42 * GIB, 2);
        assert_eq!(set, 47 * GIB);
        // Live headroom refuses it: 6 GiB free less the OS slice is not 5 GiB.
        assert!(!can_admit(5 * GIB, 0, running, free, 100 * GIB, reserve));
        // When it starts, the running proofs' 47 GiB is back: 6 + 47 covers 47 + 4.
        assert!(queued_claim_fits(set, reserve, free, running));
        // Another program holding 60 GiB: nothing our proofs return makes room for the set.
        assert!(!queued_claim_fits(set, reserve, 0, running - 10 * GIB));
    }

    /// The claim set: this proof and the largest of the outstanding, no more than the cards run.
    #[test]
    fn a_claim_is_charged_the_set_the_cards_can_run() {
        let (sp1, risc0) = (42 * GIB, 5 * GIB);
        // SP1 behind two RISC Zero jobs on two cards: SP1 and one RISC Zero, not 3 x SP1.
        assert_eq!(claim_set_bytes(sp1, 0, 2, risc0, 2), sp1 + risc0);
        // RISC Zero behind an SP1 job: the SP1 job's memory counts.
        assert_eq!(claim_set_bytes(risc0, 0, 1, sp1, 2), risc0 + sp1);
        // Nothing outstanding: this one.
        assert_eq!(claim_set_bytes(sp1, 0, 0, 0, 2), sp1);
        // More outstanding than cards: the largest that fit beside it.
        assert_eq!(claim_set_bytes(risc0, 2, 2, sp1, 3), risc0 + 2 * sp1);
        // One slot: this one alone.
        assert_eq!(claim_set_bytes(sp1, 3, 3, sp1, 1), sp1);
        assert_eq!(claim_set_bytes(sp1, 3, 3, sp1, 0), sp1);
    }

    /// Growth still to come: an admission's increment less what its worker has grown by since,
    /// all of it when unreadable.
    #[test]
    fn pending_growth_is_what_admitted_proofs_have_not_allocated_yet() {
        assert_eq!(pending_growth([]), 0);
        // Admitted for 20 GiB more than the 5 it held; it holds 12 now, so 13 is still to come.
        assert_eq!(
            pending_growth([(20 * GIB, 5 * GIB, Some(12 * GIB))]),
            13 * GIB
        );
        // Grown past its increment: nothing to come. Unreadable: all of it. Shrunk: all of it.
        assert_eq!(pending_growth([(20 * GIB, 5 * GIB, Some(30 * GIB))]), 0);
        assert_eq!(pending_growth([(20 * GIB, 5 * GIB, None)]), 20 * GIB);
        assert_eq!(pending_growth([(20 * GIB, 5 * GIB, Some(GIB))]), 20 * GIB);
        assert_eq!(
            pending_growth([(20 * GIB, 0, Some(5 * GIB)), (10 * GIB, 0, None)]),
            25 * GIB
        );
    }

    /// Two proofs admitted a moment apart: the second sees the first's share as taken, though live
    /// headroom does not show it yet; once the first has allocated, the headroom shows it instead,
    /// and once it ends, nothing is held for it.
    #[test]
    fn a_tracked_admission_holds_its_growth_until_it_is_made() {
        let ledger = MemoryLedger::default();
        let total = 100 * GIB;
        let reserve = DEFAULT_HOST_RESERVE_BYTES;
        let held = std::sync::Mutex::new(HashMap::from([("a".to_string(), 0u64)]));
        let holding = |slot: &str| held.lock().unwrap().get(slot).copied();
        // 40 GiB free: the first, wanting 30, fits.
        let first = ledger
            .try_reserve_tracked(30 * GIB, 0, 40 * GIB, total, reserve, "a", holding)
            .expect("fits");
        assert_eq!(ledger.pending_growth(holding), 30 * GIB);
        assert_eq!(ledger.tracked_count(), 1);
        // An untracked reservation is not counted as a proof in flight.
        let plain = ledger
            .try_reserve(GIB, 0, 100 * GIB, total, reserve)
            .unwrap();
        assert_eq!(ledger.tracked_count(), 1);
        drop(plain);
        // A second wanting 20, against the same 40 GiB reading: 30 of it is the first's.
        assert!(ledger
            .try_reserve_tracked(20 * GIB, 0, 40 * GIB, total, reserve, "b", holding)
            .is_none());
        // The first has allocated 25 of its 30: free commit reads 15, 5 is still to come.
        held.lock().unwrap().insert("a".to_string(), 25 * GIB);
        assert_eq!(ledger.pending_growth(holding), 5 * GIB);
        assert!(ledger
            .try_reserve_tracked(10 * GIB, 0, 15 * GIB, total, reserve, "b", holding)
            .is_none());
        let second = ledger
            .try_reserve_tracked(7 * GIB, 0, 15 * GIB, total, reserve, "b", holding)
            .expect("7 + 3 + 5 to come fits in 15");
        drop(first);
        drop(second);
        assert_eq!(ledger.pending_growth(holding), 0);
        assert_eq!(ledger.tracked_count(), 0);
        assert_eq!(ledger.reserved_bytes(), 0);
    }

    /// The Windows defaults are what was measured there, RAM and commit apart. On the host they
    /// were measured on (94 GiB of RAM, a system-managed page file), an SP1 proof and a RISC Zero
    /// one fit together on both measures; with the page file fixed at its current size, SP1 waits.
    #[cfg(windows)]
    #[test]
    fn windows_defaults_admit_one_of_each_on_the_measured_host() {
        let reserve = DEFAULT_HOST_RESERVE_BYTES;
        let (risc0, sp1) = (unmeasured_peak_for("risc0"), unmeasured_peak_for("sp1"));
        let (risc0_c, sp1_c) = (unmeasured_commit_for("risc0"), unmeasured_commit_for("sp1"));
        assert!(sp1 >= 37 * GIB && risc0 >= 6 * GIB);
        assert!(sp1_c >= 63 * GIB && risc0_c >= 28 * GIB);
        // RAM: 61 GiB free with a RISC Zero proof running.
        assert!(can_admit(sp1, 0, risc0, 61 * GIB, 94 * GIB, reserve));
        // Commit: 40 GiB free now, 280 GiB more as the page file grows.
        assert!(can_admit(sp1_c, 0, risc0_c, 320 * GIB, 380 * GIB, reserve));
        // A fixed page file at today's size: SP1 waits.
        assert!(!can_admit(sp1_c, 0, risc0_c, 40 * GIB, 100 * GIB, reserve));
        // A benchmark's reading, doubled, never undercuts the RAM default.
        let big = 512 * GIB;
        assert_eq!(budget_from_measurement(GIB * 3, "risc0", big), risc0);
        assert_eq!(budget_from_measurement(25 * GIB, "risc0", big), 50 * GIB);
        assert_eq!(budget_from_measurement(15 * GIB, "sp1", big), sp1);
        // A 32 GiB machine: each is clamped to what it can admit, and admitted alone.
        let small = 32 * GIB;
        for backend in ["risc0", "sp1"] {
            let want = admissible_unmeasured_peak_for(backend, small);
            assert!(can_admit(want, 0, 0, 28 * GIB, small, reserve), "{backend}");
        }
        let sp1_small = admissible_unmeasured_peak_for("sp1", small);
        assert!(!can_admit(
            sp1_small,
            0,
            sp1_small,
            28 * GIB,
            small,
            reserve
        ));
    }
}
