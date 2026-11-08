//! macOS observations and resources owned by one supervised worker.
use anyhow::{ensure, Context, Result};
use std::{
    collections::HashMap,
    path::PathBuf,
    process::Command,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};

unsafe extern "C" {
    fn mach_port_deallocate(
        task: libc::mach_port_t,
        name: libc::mach_port_t,
    ) -> libc::kern_return_t;
}

fn bsd_info(pid: u32) -> Option<libc::proc_bsdinfo> {
    if pid == 0 || pid > i32::MAX as u32 {
        return None;
    }
    let mut value = std::mem::MaybeUninit::<libc::proc_bsdinfo>::uninit();
    let size = std::mem::size_of::<libc::proc_bsdinfo>() as i32;
    let read = unsafe {
        libc::proc_pidinfo(
            pid as i32,
            libc::PROC_PIDTBSDINFO,
            0,
            value.as_mut_ptr().cast(),
            size,
        )
    };
    (read == size).then(|| unsafe { value.assume_init() })
}

pub fn start_time(pid: u32) -> Option<u64> {
    let info = bsd_info(pid)?;
    info.pbi_start_tvsec
        .checked_mul(1_000_000)?
        .checked_add(info.pbi_start_tvusec)
}

pub fn owned_group(pid: u32, expected: Option<u64>) -> bool {
    let Some(info) = bsd_info(pid) else {
        return false;
    };
    let time = info
        .pbi_start_tvsec
        .checked_mul(1_000_000)
        .and_then(|s| s.checked_add(info.pbi_start_tvusec));
    info.pbi_pid == pid
        && info.pbi_ppid == std::process::id()
        && info.pbi_pgid == pid
        && expected.is_some()
        && time == expected
}

/// Enumerate live descendants while the unreaped group leader pins its ID.
/// PROC_PGRP_ONLY is defined by the macOS SDK but not exported by libc.
pub fn group_members(pgid: i32) -> Option<Vec<(i32, String)>> {
    if pgid <= 0 {
        return None;
    }
    const PROC_PGRP_ONLY: u32 = 2;
    let bytes =
        unsafe { libc::proc_listpids(PROC_PGRP_ONLY, pgid as u32, std::ptr::null_mut(), 0) };
    if bytes < 0 {
        return None;
    }
    let mut capacity = (bytes as usize / std::mem::size_of::<i32>() + 32).max(64);
    for _ in 0..3 {
        if capacity > 262_144 {
            return None;
        }
        let mut pids = vec![0i32; capacity];
        let size = (pids.len() * std::mem::size_of::<i32>()) as i32;
        let read = unsafe {
            libc::proc_listpids(PROC_PGRP_ONLY, pgid as u32, pids.as_mut_ptr().cast(), size)
        };
        if read < 0 || read as usize % std::mem::size_of::<i32>() != 0 {
            return None;
        }
        if read >= size {
            capacity *= 2;
            continue;
        }
        let mut members = Vec::new();
        for pid in pids
            .into_iter()
            .take(read as usize / std::mem::size_of::<i32>())
        {
            if pid <= 0 || pid == pgid {
                continue;
            }
            let Some(info) = bsd_info(pid as u32) else {
                // Darwin can drop BSD info before a dying process disappears
                // from the group. Conservatively retain the kernel-enumerated
                // member until it is gone; only the owned group is signalled.
                let exists = unsafe { libc::kill(pid, 0) } == 0
                    || std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH);
                if exists {
                    members.push((pid, "<identity unavailable>".into()));
                }
                continue;
            };
            if info.pbi_pgid != pgid as u32 || info.pbi_status == libc::SZOMB as u32 {
                continue;
            }
            let name: Vec<u8> = info
                .pbi_comm
                .iter()
                .take_while(|c| **c != 0)
                .map(|c| *c as u8)
                .collect();
            members.push((pid, String::from_utf8_lossy(&name).into_owned()));
        }
        members.sort();
        return Some(members);
    }
    None
}

pub fn resident_bytes(pid: u32) -> Option<u64> {
    let mut value = std::mem::MaybeUninit::<libc::proc_taskinfo>::uninit();
    let size = std::mem::size_of::<libc::proc_taskinfo>() as i32;
    let read = unsafe {
        libc::proc_pidinfo(
            pid as i32,
            libc::PROC_PIDTASKINFO,
            0,
            value.as_mut_ptr().cast(),
            size,
        )
    };
    (read == size).then(|| unsafe { value.assume_init().pti_resident_size })
}

pub fn total_bytes() -> Option<u64> {
    let mut value = 0u64;
    let mut size = std::mem::size_of::<u64>();
    let status = unsafe {
        libc::sysctlbyname(
            c"hw.memsize".as_ptr(),
            (&mut value as *mut u64).cast(),
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    };
    (status == 0 && size == std::mem::size_of::<u64>()).then_some(value)
}

fn sysctl_u32(name: &std::ffi::CStr) -> Option<u32> {
    let mut value = 0u32;
    let mut size = std::mem::size_of_val(&value);
    let rc = unsafe {
        libc::sysctlbyname(
            name.as_ptr(),
            (&mut value as *mut u32).cast(),
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    };
    (rc == 0 && size == 4).then_some(value)
}

// XNU kern_memorystatus: normal=1, warning=2, critical=4.
pub fn pressure_level() -> Option<u32> {
    sysctl_u32(c"kern.memorystatus_vm_pressure_level").filter(|n| [1, 2, 4].contains(n))
}

fn parse_reserve(value: Option<&str>) -> Option<u64> {
    let gib = value.map(str::parse::<u64>).unwrap_or(Ok(8)).ok()?;
    if !(8..=64).contains(&gib) {
        return None;
    }
    gib.checked_mul(1024u64.pow(3))
}

pub fn reserve_bytes() -> u64 {
    // Invalid configuration refuses admission rather than reducing protection.
    parse_reserve(
        std::env::var("ZKMINER_MACOS_HOST_RESERVE_GIB")
            .ok()
            .as_deref(),
    )
    .unwrap_or(u64::MAX)
}

#[derive(Debug, serde::Serialize)]
pub struct ProcessMemory {
    pub rss_bytes: u64,
    pub footprint_bytes: u64,
    pub lifetime_peak_footprint_bytes: u64,
}

pub fn process_memory(pid: u32) -> Option<ProcessMemory> {
    let mut value = std::mem::MaybeUninit::<libc::rusage_info_v4>::uninit();
    let rc = unsafe {
        libc::proc_pid_rusage(pid as i32, libc::RUSAGE_INFO_V4, value.as_mut_ptr().cast())
    };
    if rc != 0 {
        return None;
    }
    let value = unsafe { value.assume_init() };
    Some(ProcessMemory {
        rss_bytes: value.ri_resident_size,
        footprint_bytes: value.ri_phys_footprint,
        lifetime_peak_footprint_bytes: value.ri_lifetime_max_phys_footprint,
    })
}

#[derive(Debug, serde::Serialize)]
pub struct GroupMemory {
    pub worker: ProcessMemory,
    pub helper_rss_bytes: u64,
    pub helper_footprint_bytes: u64,
    pub helper_count: usize,
}

pub fn group_memory(pid: u32) -> Option<GroupMemory> {
    let start = start_time(pid)?;
    if !owned_group(pid, Some(start)) {
        return None;
    }
    let mut result = GroupMemory {
        worker: process_memory(pid)?,
        helper_rss_bytes: 0,
        helper_footprint_bytes: 0,
        helper_count: 0,
    };
    for (member, _) in group_members(pid as i32)? {
        let Some(memory) = process_memory(member as u32) else {
            // A helper may finish between enumeration and its task observation.
            if bsd_info(member as u32).is_none_or(|info| info.pbi_status == libc::SZOMB as u32) {
                continue;
            }
            return None;
        };
        result.helper_count += 1;
        result.helper_rss_bytes = result.helper_rss_bytes.checked_add(memory.rss_bytes)?;
        result.helper_footprint_bytes = result
            .helper_footprint_bytes
            .checked_add(memory.footprint_bytes)?;
    }
    owned_group(pid, Some(start)).then_some(result)
}

pub fn observation(pid: u32) -> serde_json::Value {
    let guard = guard_samples(pid);
    serde_json::json!({"pressure_level":pressure_level(), "estimated_available_bytes":available_bytes(),
        "admission_available_bytes":admission_available_bytes(), "reserve_bytes":reserve_bytes(),
        "group":group_memory(pid), "guard_peak_footprint_bytes":peak_bytes(pid),
        "guard_min_estimated_available_bytes":guard.as_ref().and_then(|s| s.minimum_available),
        "guard_pressure_levels_seen":guard.map(|s| s.pressure_levels),
        "footprint_method":"proc_pid_rusage RUSAGE_INFO_V4"})
}

pub fn admission_available_bytes() -> Option<u64> {
    let available = available_bytes()?;
    Some(if pressure_level()? == 1 { available } else { 0 })
}

/// Translate a normal-pressure reading into the live headroom accepted by
/// the shared reservation ledger. `can_admit` then requires the VM estimate
/// to cover the reserve plus at most 8 GiB of additional owned footprint.
/// The ledger still bounds total commitments and the worker guard enforces
/// the 32 GiB owned-footprint ceiling during the proof.
fn policy_headroom(
    available: u64,
    pressure: Option<u32>,
    expected_peak: u64,
    resident: u64,
) -> Option<u64> {
    if pressure != Some(1) {
        return None;
    }
    let growth = expected_peak.saturating_sub(resident);
    Some(available.saturating_add(growth.saturating_sub(8 * 1024u64.pow(3))))
}

pub fn admission_headroom(
    available: u64,
    expected_peak: u64,
    resident: u64,
) -> Option<u64> {
    policy_headroom(available, pressure_level(), expected_peak, resident)
}

fn safe_to_continue(
    footprint: Option<u64>,
    _available: Option<u64>,
    pressure: Option<u32>,
    limit: u64,
) -> bool {
    footprint.is_some_and(|n| n <= limit)
        && matches!(pressure, Some(1 | 2))
}

pub fn available_bytes() -> Option<u64> {
    let mut value = std::mem::MaybeUninit::<libc::vm_statistics64>::uninit();
    let mut count = libc::HOST_VM_INFO64_COUNT;
    let host = unsafe { libc::mach_host_self() };
    let status = unsafe {
        libc::host_statistics64(
            host,
            libc::HOST_VM_INFO64,
            value.as_mut_ptr().cast(),
            &mut count,
        )
    };
    unsafe {
        mach_port_deallocate(libc::mach_task_self(), host);
    }
    if status != libc::KERN_SUCCESS || count != libc::HOST_VM_INFO64_COUNT {
        return None;
    }
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if page_size <= 0 {
        return None;
    }
    let stats = unsafe { value.assume_init() };
    // An admission estimate, NOT a guarantee of immediately allocatable RAM.
    // Bare free pages exclude the large filesystem cache after builds. Credit
    // only half the smaller of file-backed and inactive pages; do not add both
    // counters (they overlap), or credit compressed/anonymous pages separately.
    // The admission policy applies a separate reserve and pressure/floor gate.
    let reclaim_estimate = stats.external_page_count.min(stats.inactive_count) as u64 / 2;
    Some((stats.free_count as u64 + reclaim_estimate) * page_size as u64)
}

struct GuardSamples {
    peak: AtomicU64,
    minimum_available: AtomicU64,
    pressure_mask: AtomicU64,
}

type PeakRegistry = std::sync::Mutex<HashMap<u32, (u64, Arc<GuardSamples>)>>;
fn peaks() -> &'static PeakRegistry {
    static PEAKS: std::sync::OnceLock<PeakRegistry> = std::sync::OnceLock::new();
    PEAKS.get_or_init(|| std::sync::Mutex::new(HashMap::new()))
}

pub fn peak_bytes(pid: u32) -> Option<u64> {
    let (start, samples) = peaks().lock().ok()?.get(&pid)?.clone();
    owned_group(pid, Some(start))
        .then(|| samples.peak.load(Ordering::Acquire))
        .filter(|n| *n > 0)
}

struct GuardObservation {
    minimum_available: Option<u64>,
    pressure_levels: Vec<u32>,
}

fn guard_samples(pid: u32) -> Option<GuardObservation> {
    let (start, samples) = peaks().lock().ok()?.get(&pid)?.clone();
    if !owned_group(pid, Some(start)) {
        return None;
    }
    let minimum = samples.minimum_available.load(Ordering::Acquire);
    let mask = samples.pressure_mask.load(Ordering::Acquire);
    Some(GuardObservation {
        minimum_available: (minimum != u64::MAX).then_some(minimum),
        pressure_levels: [1u32, 2, 4]
            .into_iter()
            .filter(|level| mask & (*level as u64) != 0)
            .collect(),
    })
}

pub struct MemoryGuard {
    pid: u32,
    started: u64,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl MemoryGuard {
    pub fn new(pid: u32) -> Result<Self> {
        Self::with_limit(pid, 32 * 1024u64.pow(3))
    }

    fn with_limit(pid: u32, limit: u64) -> Result<Self> {
        let started = start_time(pid).context("cannot establish worker process identity")?;
        ensure!(
            owned_group(pid, Some(started)),
            "worker must be our process-group leader"
        );
        ensure!(
            available_bytes().is_some(),
            "cannot observe macOS free memory"
        );
        let stop = Arc::new(AtomicBool::new(false));
        let cancel = stop.clone();
        let samples = Arc::new(GuardSamples {
            peak: AtomicU64::new(0),
            minimum_available: AtomicU64::new(u64::MAX),
            pressure_mask: AtomicU64::new(0),
        });
        let tracked = samples.clone();
        let thread = std::thread::Builder::new().name("macos-memory-watch".into()).spawn(move || {
            while !cancel.load(Ordering::Acquire) {
                if !owned_group(pid, Some(started)) { return; }
                // A zombie may retain BSD identity after task info disappears.
                // Its already-buffered handshake error must remain readable.
                if bsd_info(pid).is_some_and(|info| info.pbi_status == libc::SZOMB as u32) { return; }
                let group = group_memory(pid);
                let footprint = group.as_ref().and_then(|g| g.worker.footprint_bytes.checked_add(g.helper_footprint_bytes));
                if let Some(bytes) = footprint { tracked.peak.fetch_max(bytes, Ordering::AcqRel); }
                let available = available_bytes();
                let pressure = pressure_level();
                if let Some(bytes) = available { tracked.minimum_available.fetch_min(bytes, Ordering::AcqRel); }
                if let Some(level) = pressure { tracked.pressure_mask.fetch_or(level as u64, Ordering::AcqRel); }
                let safe = safe_to_continue(footprint, available, pressure, limit);
                if !safe {
                    tracing::error!("macOS worker {pid}: group={group:?}, available={available:?}, pressure={pressure:?}; critical pressure, unreadable safety signal, or footprint limit reached");
                    if owned_group(pid, Some(started)) { unsafe { libc::kill(-(pid as i32), libc::SIGKILL); } }
                    return;
                }
                std::thread::sleep(Duration::from_secs(1));
            }
        })?;
        peaks().lock().unwrap().insert(pid, (started, samples));
        Ok(Self {
            pid,
            started,
            stop,
            thread: Some(thread),
        })
    }
}

impl Drop for MemoryGuard {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
        let mut registry = peaks().lock().unwrap();
        if registry
            .get(&self.pid)
            .is_some_and(|(start, _)| *start == self.started)
        {
            registry.remove(&self.pid);
        }
    }
}

pub struct HelperLease {
    context: Option<String>,
    name: String,
    directory: PathBuf,
}

impl HelperLease {
    pub fn configure(
        backend: &str,
        command: &mut Command,
        overrides: &HashMap<String, String>,
    ) -> Result<Option<Self>> {
        if backend.split(':').next() != Some("risc0")
            || std::path::Path::new(command.get_program())
                .file_name()
                .and_then(|s| s.to_str())
                != Some("zkminer-prove-risc0")
        {
            return Ok(None);
        }
        let setting = |key: &str| {
            overrides
                .get(key)
                .cloned()
                .or_else(|| std::env::var(key).ok())
                .with_context(|| format!("macOS worker requires {key}"))
        };
        let native = overrides
            .get("ZKMINER_RISC0_WRAP")
            .cloned()
            .or_else(|| std::env::var("ZKMINER_RISC0_WRAP").ok())
            .as_deref()
            == Some("native");
        let context = if native {
            command.env(
                "RISC0_GROTH16_NATIVE_DIR",
                setting("ZKMINER_RISC0_NATIVE_DIR")?,
            );
            None
        } else {
            Some(setting("ZKMINER_RISC0_DOCKER_CONTEXT")?)
        };
        let base = PathBuf::from(setting("ZKMINER_RISC0_WORK_ROOT")?).canonicalize()?;
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let name = format!(
            "zkminer-macos-{}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_nanos(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        );
        let directory = base.join(&name);
        std::fs::create_dir(&directory)?;
        command
            .env("RISC0_GROTH16_CONTAINER_NAME", &name)
            .env("RISC0_WORK_DIR", &directory);
        if let Some(context) = &context {
            command.env("ZKMINER_RISC0_DOCKER_CONTEXT", context);
        }
        Ok(Some(Self {
            context,
            name,
            directory,
        }))
    }
}

impl Drop for HelperLease {
    fn drop(&mut self) {
        if let Some(context) = &self.context {
            let status = zkminer_prover_protocol::proc::output_with_timeout(
                Command::new("docker").args(["--context", context, "rm", "-f", &self.name]),
                Duration::from_secs(10),
                16 * 1024,
            );
            tracing::debug!("owned helper {} cleanup: {}", self.name, status.describe());
        }
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::process::CommandExt;

    #[test]
    fn observations_and_process_identity() {
        assert!(total_bytes().unwrap() > 0);
        assert!(available_bytes().unwrap() <= total_bytes().unwrap());
        assert!(resident_bytes(std::process::id()).unwrap() > 0);
        assert!(process_memory(std::process::id()).unwrap().footprint_bytes > 0);
        assert!(pressure_level().is_some());
        assert!(!owned_group(
            std::process::id(),
            start_time(std::process::id())
        ));
        let mut child = Command::new("sleep")
            .arg("30")
            .process_group(0)
            .spawn()
            .unwrap();
        let pid = child.id();
        let time = start_time(pid).unwrap();
        assert!(owned_group(pid, Some(time)));
        assert!(!owned_group(pid, Some(time + 1)));
        assert!(!owned_group(pid, None));
        assert!(group_members(pid as i32).unwrap().is_empty());
        child.kill().unwrap();
        child.wait().unwrap();
        assert!(!owned_group(pid, Some(time)));
    }

    #[test]
    fn pressure_and_reserve_boundaries() {
        let gib = 1024u64.pow(3);
        assert_eq!(parse_reserve(None), Some(8 * gib));
        assert_eq!(parse_reserve(Some("32")), Some(32 * gib));
        for value in ["0", "7", "65", "no", "18446744073709551615"] {
            assert_eq!(parse_reserve(Some(value)), None);
        }
        assert!(safe_to_continue(
            Some(gib),
            Some(20 * gib),
            Some(1),
            32 * gib
        ));
        assert!(safe_to_continue(
            Some(gib),
            Some(20 * gib),
            Some(2),
            32 * gib
        ));
        assert!(!safe_to_continue(
            Some(gib),
            Some(20 * gib),
            Some(4),
            32 * gib
        ));
        assert!(!safe_to_continue(Some(gib), Some(20 * gib), None, 32 * gib));
        assert!(!safe_to_continue(
            Some(33 * gib),
            Some(20 * gib),
            Some(1),
            32 * gib
        ));
        assert!(safe_to_continue(
            Some(gib),
            Some(7 * gib),
            Some(1),
            32 * gib
        ));
        // A proof admitted at 16 GiB estimated must keep running if that
        // estimate falls to 3 GiB while owned memory and pressure stay safe.
        assert!(safe_to_continue(Some(20 * gib), Some(3 * gib), Some(1), 32 * gib));
        assert!(safe_to_continue(Some(20 * gib), None, Some(2), 32 * gib));
        assert!(!safe_to_continue(None, Some(20 * gib), Some(1), 32 * gib));
    }

    #[test]
    fn admission_uses_pressure_first_and_vm_estimate_as_a_floor() {
        let gib = 1024u64.pow(3);
        // A fresh 24 GiB budget no longer demands 24 + 16 GiB of the
        // conservative VM estimate; normal pressure and 16 GiB suffice.
        let fresh = |available| policy_headroom(available, Some(1), 24 * gib, 0).unwrap();
        assert!(crate::memory::can_admit(24 * gib, 0, 0, fresh(40 * gib), 128 * gib, 8 * gib));
        assert!(crate::memory::can_admit(24 * gib, 0, 0, fresh(16 * gib), 128 * gib, 8 * gib));
        assert!(!crate::memory::can_admit(24 * gib, 0, 0, fresh(15 * gib), 128 * gib, 8 * gib));
        // The actual owned footprint reduces expected growth. Warning,
        // critical or unreadable kernel pressure always refuses, then a
        // recovered normal reading permits the same request again.
        assert!(crate::memory::can_admit(24 * gib, 20 * gib, 0,
            policy_headroom(12 * gib, Some(1), 24 * gib, 20 * gib).unwrap(), 128 * gib, 8 * gib));
        assert_eq!(policy_headroom(40 * gib, Some(2), 24 * gib, 0), None);
        assert_eq!(policy_headroom(40 * gib, Some(4), 24 * gib, 0), None);
        assert_eq!(policy_headroom(40 * gib, None, 24 * gib, 0), None);
        assert!(policy_headroom(40 * gib, Some(1), 24 * gib, 0).is_some());
    }

    #[test]
    fn footprint_peak_is_scoped_to_the_live_guard() {
        let mut child = Command::new("sleep")
            .arg("30")
            .process_group(0)
            .spawn()
            .unwrap();
        let pid = child.id();
        let guard = MemoryGuard::new(pid).unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        while peak_bytes(pid).is_none() && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(peak_bytes(pid).unwrap() > 0);
        drop(guard);
        assert!(peak_bytes(pid).is_none());
        child.kill().unwrap();
        child.wait().unwrap();
    }

    #[test]
    fn bounded_allocation_stops_only_its_owned_group() {
        use std::io::{BufRead, BufReader};
        use std::process::Stdio;
        let mut child = Command::new("python3")
            .args(["-c", "import time; b=bytearray(64*1024**2); b[::4096]=bytes([1])*len(b[::4096]); print('ready',flush=True); time.sleep(30)"])
            .stdout(Stdio::piped()).process_group(0).spawn().unwrap();
        let mut ready = String::new();
        BufReader::new(child.stdout.take().unwrap())
            .read_line(&mut ready)
            .unwrap();
        assert_eq!(ready.trim(), "ready");
        assert!(group_memory(child.id()).unwrap().worker.footprint_bytes > 16 * 1024u64.pow(2));
        let _guard = MemoryGuard::with_limit(child.id(), 16 * 1024u64.pow(2)).unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                assert!(!status.success());
                break;
            }
            if std::time::Instant::now() > deadline {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!("footprint guard did not stop allocation");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn native_group_scan_finds_and_cleans_owned_descendants() {
        let mut child = Command::new("sh")
            .args(["-c", "sleep 30 & wait"])
            .process_group(0)
            .spawn()
            .unwrap();
        let pid = child.id();
        let started = start_time(pid).unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        let members = loop {
            let members = group_members(pid as i32).unwrap();
            if !members.is_empty() || std::time::Instant::now() > deadline {
                break members;
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        assert!(owned_group(pid, Some(started)));
        unsafe {
            libc::kill(-(pid as i32), libc::SIGKILL);
        }
        child.wait().unwrap();
        assert!(
            !members.is_empty(),
            "native scan missed the owned sleep process"
        );
    }
}
