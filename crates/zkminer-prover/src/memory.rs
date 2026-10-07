//! Host memory: how much is left, how hard the box is stalling, and who the kernel should kill.
//!
//! WHY THIS EXISTS. On 2026-10-04 this host was hard-frozen by its own prover processes and had to
//! be power-cycled, then OOM-killed a prover again nine hours later. The two events looked nothing
//! alike, and between them they rule out most of the obvious defences:
//!
//! | | the freeze (06:23) | the cgroup kill (08:57) |
//! |---|---|---|
//! | victim | 4x `zkminer-prove-risc0` | `sp1-gpu-server` |
//! | `total_vm` | 54-72 GB each | **139 GB** |
//! | anon RSS | **2-11 MB each** | 17.6 GB |
//! | constraint | `global_oom` | `CONSTRAINT_MEMCG` |
//! | outcome | hard reboot | one failed test |
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
//!    one for the other has already cost real debugging time here.

use std::time::Duration;

/// Leave this much for the rest of the system when sizing a worker's ceiling.
///
/// The OS, the miner, the TUI, and the page cache the prover itself needs to read a 236 MB binary.
/// Too small and the cap does not prevent a freeze; too large and a legitimate proof is refused.
pub const DEFAULT_HOST_RESERVE_BYTES: u64 = 3 * 1024 * 1024 * 1024;

/// `/proc/pressure/memory`'s `full avg10`, in percent, above which the host is genuinely stalling.
///
/// This is the SYSTEM-wide PSI file, not a cgroup's `memory.pressure`. `full` means all non-idle
/// tasks were stalled on memory at once — time the machine lost outright, which is the thing to
/// react to. It is a better signal than free-memory thresholds
/// because it measures the symptom (stalling) rather than a proxy for it. An earlier session on
/// this box recorded `full avg10 = 67.95%` while it was unusable.
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
pub fn mem_available_bytes() -> Option<u64> {
    parse_meminfo_kb(
        &std::fs::read_to_string("/proc/meminfo").ok()?,
        "MemAvailable",
    )
}

/// `MemTotal` from `/proc/meminfo`, in bytes.
pub fn mem_total_bytes() -> Option<u64> {
    parse_meminfo_kb(&std::fs::read_to_string("/proc/meminfo").ok()?, "MemTotal")
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
    let total = mem_total_bytes()?;
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
/// host's responsiveness with it — which is the failure this module exists to prevent. The earlier
/// cgroup kill burned 4 GB of swap on its way down for no benefit.
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
/// carry it in shared state. Those readers take no lock (that is what fixed the `bus_id_for_slot`
/// deadlock), so there is nowhere lock-free for a per-worker string to live.
pub fn cap_unit_name(unit_hint: &str, pid: u32) -> String {
    format!(
        "{CAP_UNIT_PREFIX}{}-{}.scope",
        sanitize_unit(unit_hint),
        pid
    )
}

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
        // shutdown phase 3 — leaves a failed unit behind every single time. Verified on this box:
        // `zkminer-gputest.scope` was still `loaded failed` long after its process was gone. Nothing
        // here ever calls StopUnit or ResetFailed, so a soak accumulates one per spawn. Worse, the
        // unit name embeds the pid and the mode is `fail`, so a lingering unit whose pid gets reused
        // makes StartTransientUnit fail and that worker runs UNCAPPED, reported only as a warning.
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
    // OWN cgroup. Measured on this host: our session scope's `memory.peak` reads 16.7 GB and the
    // enclosing `app.slice` 25.8 GB, both lifetime subtree high-water marks having nothing to do
    // with one proof. That figure would be persisted as the backend's expected peak and refuse every
    // job from then on.
    //
    // The check used to be `leaf.starts_with("zkminer-")`, which is a NAME, not provenance. This box
    // has a `zkminer-gputest.scope` sitting in it right now from a capped test run, and the natural
    // way to run a miner under a limit is `systemd-run --user --unit=zkminer-soak --scope`. In
    // either case a worker whose cap failed sits in a cgroup whose leaf matches the prefix, and the
    // guard waves through exactly the lifetime figure it was written to reject. An exact match
    // against the unit `cap_process_memory` reported cannot be satisfied by an ancestor.
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
/// those pages twice: once as headroom and once as a discount. Measured on this box, a single user
/// slice reads `anon 465 MiB` against `file 18.3 GiB`, so the over-credit is not marginal, it is
/// most of the number.
///
/// Left uncorrected, that compounds with an unfloored subtraction into the original freeze: once the
/// credit exceeds the expected peak the increment is zero, `fits_now` reduces to "is the host reserve
/// free", and four concurrent provers are admitted onto a box with 4 GiB left — which is the 06:23
/// incident exactly — and `can_admit` documents on `fits_now` why anon, unlike `memory.current`,
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
        // most of `/proc` is not ours. Reading `status` for every pid and then discarding it was
        // the wrong order.
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

/// Non-unix: there is no `/proc` to prove identity with, and no process groups to signal, so the
/// signal sites this guards are themselves compiled out. Answering `false` keeps the surrounding
/// `if` well-typed without pretending to a check we cannot make.
#[cfg(not(unix))]
pub fn pid_is_our_worker(_pid: u32, _expected_starttime: Option<u64>) -> bool {
    false
}

/// Non-unix: no `/proc` to read a start time from. `None` is "unknown", which `publish_pid` already
/// stores as 0 and every reader treats as absent — the same thing an unreadable `/proc` means on Linux.
#[cfg(not(unix))]
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
    // TWO independent conditions, both of which must hold. The previous single test added
    // `reserved` to a figure already net of it — once an in-flight proof has actually allocated
    // its pages, that memory is both absent from `available` AND still counted in `reserved`, so
    // every proof in flight shrank the apparent headroom twice. On this box that admitted 2 proofs
    // where 4 genuinely fitted, quietly defeating the concurrency the rest of the design assumes.
    //
    // 1. LIVE headroom must cover the INCREMENT this proof adds: what is free right now, minus
    //    the OS slice. The increment, not the peak, because `resident` — what this slot's worker
    //    is already holding — has ALREADY been subtracted from `available`. Charging the full peak
    //    on top of it counts those pages twice.
    //
    //    That double-count wedged the miner permanently, and silently. The SP1 worker caches
    //    `CudaProver` and its proving keys deliberately, so after proof #1 `sp1-gpu-server` sits
    //    resident at ~17.6 GiB. Proof #2 on that same slot then asked for `18 + 3 <= 8.2` and was
    //    refused — and so was every risc0 proof, because the headroom really was gone. The result
    //    was a miner that earned nothing while `reserved_bytes()` read 0, PSI read 0.00%, and every
    //    slot and backend reported healthy. `resident` is 0 whenever we cannot read it, which is
    //    exactly the old behaviour, so an unreadable cgroup is no worse than before.
    //    The credit is NOT artificially capped, and that is a deliberate answer to a real
    //    objection: once the credit reaches the peak, `fits_now` reduces to "is the host reserve
    //    free", which sounds like no test at all. Two things make it sound anyway.
    //
    //    First, `resident` is ANONYMOUS memory only (`anon_memory_of_pid`), not `memory.current`.
    //    The version of this that was dangerous credited the page cache, which `MemAvailable`
    //    already counts as available — double-counting pages that are reclaimable anyway, and on
    //    this box that is most of the number (`anon 465 MiB` against `file 18.3 GiB` in one slice).
    //    With anon, every credited byte is a page the worker really holds, really cannot have
    //    reclaimed (its scope sets `MemorySwapMax=0`), and will really reuse. Crediting it in full
    //    is not optimism, it is arithmetic: `expected_peak` is a TOTAL footprint, so a worker
    //    already holding that footprint needs nothing more.
    //
    //    Second, concurrency is bounded by `fits_committed` below, which uses the ABSOLUTE peak and
    //    ignores the credit entirely. So the credit can only ever help the sequential case — the
    //    next proof on an already-warm slot — and can never wave through a second concurrent proof.
    //    Capping it at half instead refused exactly the case it was added for: a warm SP1 slot
    //    holding 17.6 GiB, where proof #2 genuinely needs 0.4 GiB more and the cap demanded 7.5.
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
pub fn unmeasured_peak_for(backend: &str) -> u64 {
    const GIB: u64 = 1024 * 1024 * 1024;
    match backend {
        "risc0" | "openvm" => 6 * GIB,
        // `mock_worker` speaks the protocol and allocates nothing; `crates/zkminer-prover/src/bin/`
        // builds it and the integration tests register it as a backend. Charging it the
        // unknown-backend figure made every such test demand more RAM than a standard CI runner has
        // (18 GiB committed on a 7-16 GB box), so the benchmark and prove paths returned
        // `HostMemoryShortage` and the tests failed for a reason that had nothing to do with them.
        "mock" => 64 * 1024 * 1024,
        // SP1 and anything we do not recognise.
        _ => 18 * GIB,
    }
}

/// Multiplier applied to a MEASURED peak before trusting it as a budget.
///
/// The measurement is taken on a strictly cheaper workload than the one it predicts, in two
/// independent ways, and the repo documents both:
///
/// * **Receipt kind.** The benchmark calls `prover.prove(..)` — the default COMPOSITE receipt. A
///   real proof calls `prove_with_opts(.., ProverOpts::groth16())`, adding lift/join and a Groth16
///   wrap. `zkminer-prove-risc0`'s own calibration comment says it plainly: *"It also under-reports
///   MEMORY pressure: po2=21 completes composite-only but OOMs on the real groth16 path, so a
///   composite-derived max_feasible_po2 is too optimistic."*
/// * **Segment size.** The benchmark runs at the SDK default po2; production sets the resolved po2,
///   and this project's own model has memory DOUBLING per po2 step.
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
    // `can_admit` tests. The first version returned `min(¾·total, total − reserve)` and added the
    // reserve afterwards, which made the bound satisfiable only where `0.75·T + reserve <= 0.92·T`,
    // i.e. `T >= 18 GiB` — so it reintroduced the permanent silent refusal it was written to remove,
    // for every host smaller than this one. Subtracting the reserve from both terms fixes it:
    // a 16 GiB box now bounds a budget at 9 GiB, which an idle 14.7 GiB of `MemAvailable` can admit.
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

/// Baseline po2 that `unmeasured_peak_for` and a benchmark measurement are taken at.
///
/// The SDK default segment size, which is what `benchmark_program` proves at. Production resolves its
/// own po2, so any budget compared against a different po2 has to be scaled from here.
pub const BASELINE_PO2: u8 = 21;

/// Scale a host-memory figure measured at `BASELINE_PO2` to the cost at `po2`.
///
/// Memory DOUBLES per po2 step in this project's own model (`estimate_po2_memory`), and every
/// host-memory budget in this module is keyed on the backend alone — not the segment size. So an
/// operator raising po2 from 21 to 24 in the TUI multiplies the real cost roughly eightfold while
/// every admission figure stays identical, and the `Critical` log line even advises lowering po2 as
/// the remedy for a number po2 does not affect.
///
/// Saturating, and clamped below at the baseline: a SMALLER po2 is cheaper, but a budget is not a
/// place to be optimistic, so going down buys nothing.
pub fn peak_for_po2(baseline_peak: u64, po2: u8) -> u64 {
    let steps = po2.saturating_sub(BASELINE_PO2);
    baseline_peak.saturating_mul(1u64.checked_shl(steps.min(16) as u32).unwrap_or(u64::MAX))
}

/// The unmeasured default for `backend`, clamped to what this host can admit.
///
/// The clamp has to apply to the FALLBACK too, not only to the measured path. `budget_from_measurement`
/// clamps; `unmeasured_peak_for` does not, and `expected_host_peak_bytes` returns it raw on both of
/// its early returns. So on any host where `unmeasured_peak_for(backend) + reserve > total` — a 20 GiB
/// box with SP1's 18 GiB default, or any unrecognised backend name anywhere under ~24 GiB — the
/// committed condition was unsatisfiable at every level of free memory, for the life of the install.
/// That is bit-for-bit the permanent silent refusal the measured path was fixed for.
///
/// It is worse than a proving outage, because the benchmark is charged the same figure: the one thing
/// that could lower it was refused using the number only it could lower. A deadlock, with no log line
/// to distinguish it from "not benchmarked yet".
pub fn admissible_unmeasured_peak_for(backend: &str, host_total: u64) -> u64 {
    unmeasured_peak_for(backend).min(max_admissible_budget(host_total))
}

/// Turn a raw measurement into a budget.
///
/// Three rules, each of which was a bug before it was a rule:
///
/// 1. **Refuse an implausibly small figure.** Below `MIN_TRUSTED_PEAK_BYTES` the benchmark did not
///    measure the production workload, and a believable-looking small number is how unlimited
///    concurrency gets authorised.
/// 2. **Never undercut the blind default.** The old code returned `measured * FACTOR` outright, so a
///    3 GiB SP1 reading — entirely plausible given the composite-receipt caveat above — produced a
///    6 GiB budget where knowing nothing would have charged 18 GiB, and licensed three concurrent
///    proofs of a workload observed at 17.6 GB each. It also made the function non-monotonic across
///    the trust floor: 1.9 GiB gave 18 GiB and 2.0 GiB gave 4 GiB, so a SMALLER measurement produced
///    a LARGER charge. Taking the max fixes both.
/// 3. **Never exceed what the host can admit.** Unclamped, `measured * 2` above
///    `max_admissible_budget` permanently disables the backend — and on a 28 GiB box that threshold
///    is an 11.4 GiB measurement, below the 16.4 GiB SP1 figure this project has actually observed.
///    So the single act of running an ACCURATE benchmark turned a working miner into one that never
///    claims again, silently, with no way back but deleting the cache. Clamping instead yields
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
}

/// A reservation held for as long as a proof is running. Releases on drop, including on panic or an
/// early return, so a failed proof cannot leak its claim and starve every later one.
pub struct MemoryReservation<'a> {
    ledger: &'a MemoryLedger,
    bytes: u64,
}

impl Drop for MemoryReservation<'_> {
    fn drop(&mut self) {
        // SATURATING, to match the add. A plain `fetch_sub` that underflows wraps the counter to
        // ~u64::MAX, and `can_admit`'s committed term then refuses every proof for the life of the
        // process — a miner that never mines again, silently, from a single arithmetic mismatch.
        // Unreachable today (`try_reserve` refuses a reservation that would clamp the add), but the
        // failure mode is terminal and the fix costs nothing.
        let _ = self.ledger.reserved.fetch_update(
            std::sync::atomic::Ordering::AcqRel,
            std::sync::atomic::Ordering::Acquire,
            |v| Some(v.saturating_sub(self.bytes)),
        );
    }
}

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
                    })
                }
                Err(observed) => current = observed,
            }
        }
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
    /// rather than guessed at. Calling this `Sacrifice` implied an action the system does not take.
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
    // of per-job refusals; with the old half-reserve minimum the free-memory backstop could only
    // trigger once `available` was already well below the 3 GiB that admission insists on, i.e. after
    // everything had been silently refused. On a kernel without PSI — the only case this backstop
    // exists for — that made layer 4 effectively dead.
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

#[cfg(test)]
mod tests {
    use super::*;

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
        let total = mem_total_bytes().expect("this host reports MemTotal");
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

        // THE double-count regression. Two 6 GiB proofs in flight on a 28 GiB box: 12 GiB
        // reserved, ~13 GiB still free. A third genuinely fits and must be admitted. Adding
        // `reserved` to a figure already net of it made this refuse, halving real concurrency and
        // quietly defeating the look-ahead the rest of the design assumes.
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
                    // temporary before the body, which released every claim instantly and let all
                    // eight "win" regardless of the ledger's behaviour.
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
        // The PRODUCTION call, not a copy of it. An earlier version of this test re-implemented
        // the `pre_exec` body, so deleting the real one would have left the test green.
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

    /// The pid guard every group kill now passes through. Verified against real processes, because
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
                // reading the cgroup immediately is a race, and losing it is what made the first
                // version of this test fail intermittently. The production doc now records the same
                // window, which is why `oom_score_adj` is the layer that has no window.
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

/// The measurement is optimistic by construction, so turning it into a budget is where the
/// freeze-or-not decision really lives.
#[cfg(test)]
mod budget_tests {
    use super::*;

    const GIB: u64 = 1024 * 1024 * 1024;

    /// A raw measurement must never be used as the budget: it comes from a composite receipt at the
    /// default segment size, while production runs a Groth16 wrap at the resolved po2, and this
    /// project's own model has memory doubling per po2 step.
    #[test]
    fn a_measurement_is_scaled_before_it_is_trusted() {
        let big = 512 * GIB; // a host large enough that the clamp is not what we are testing
        assert_eq!(budget_from_measurement(4 * GIB, "risc0", big), 8 * GIB);
        assert_eq!(budget_from_measurement(9 * GIB, "sp1", big), 18 * GIB);
        // THE scenario this prevents: a 2 GiB reading on a 28 GiB box. Unscaled it licenses ~11
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
    /// `total - reserve` made `can_admit`'s committed condition unsatisfiable at any level of free
    /// memory — so measuring this box's real 16.4 GiB SP1 peak retired SP1 permanently, silently,
    /// with no recovery but deleting the cache. One proof at a time is the truth about such a host.
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
    /// The old code returned `measured * FACTOR` outright, so a 3 GiB SP1 reading — plausible, given
    /// that the benchmark proves a composite receipt at the default segment size — yielded a 6 GiB
    /// budget against an 18 GiB blind default, and licensed three concurrent proofs of a workload
    /// observed at 17.6 GB each. It was also non-monotonic across the trust floor: 1.9 GiB charged
    /// 18 GiB while 2.0 GiB charged 4 GiB.
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

    /// The wedge that earned `resident` its argument: a worker that keeps its allocations between
    /// proofs must not be charged for them twice.
    ///
    /// The SP1 worker caches `CudaProver` and its proving keys on purpose, so after proof #1
    /// `sp1-gpu-server` sits resident at its full working set. `MemAvailable` is down by that much
    /// ALREADY. Charging proof #2 the whole 18 GiB again refused it — and every risc0 proof too —
    /// on a host that genuinely had room, with the ledger reading 0 and every layer reporting
    /// healthy. A permanent earnings outage dressed as safety.
    #[test]
    fn a_resident_worker_is_not_charged_for_its_memory_twice() {
        let total = 28 * GIB;
        let reserve = DEFAULT_HOST_RESERVE_BYTES;
        let sp1 = unmeasured_peak_for("sp1");
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
        let risc0 = unmeasured_peak_for("risc0");
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
}
