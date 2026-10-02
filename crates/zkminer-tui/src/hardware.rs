//! Hardware monitoring via Linux sysfs / procfs.
//!
//! Reads CPU, memory, and GPU telemetry without any external dependencies
//! (AMD/Intel via sysfs, NVIDIA via NVML in-process library).
//! AMD GPUs are detected via the amdgpu driver sysfs interface.
//! NVIDIA GPUs are detected and monitored via NVML (no subprocess calls).
//! Intel GPUs are detected via the i915/xe kernel driver sysfs interface.

use std::fs;
use std::path::{Path, PathBuf};

use crate::nvml::nvml;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default)]
pub struct HardwareInfo {
    pub cpu: CpuInfo,
    pub memory: MemoryInfo,
    pub gpus: Vec<GpuInfo>,
}

#[derive(Debug, Clone, Default)]
pub struct CpuInfo {
    pub model: String,
    pub cores: u32,
    pub threads: u32,
    pub usage_percent: f64,
    pub load_avg: [f64; 3],
    pub freq_mhz: u32,
}

#[derive(Debug, Clone, Default)]
pub struct MemoryInfo {
    pub total_bytes: u64,
    pub used_bytes: u64,
    pub available_bytes: u64,
    pub swap_total_bytes: u64,
    pub swap_used_bytes: u64,
}

#[derive(Debug, Clone)]
pub struct GpuInfo {
    /// Display ordinal ONLY. Dense 0-based position in DRM card order across
    /// ALL vendors, with non-GPU DRM nodes excluded.
    ///
    /// This is NOT an NVML/CUDA index, NOT a DRM card number, and NOT a
    /// benchmark `gpuN` id. On a mixed-vendor box it agrees with none of them:
    /// a non-proving AMD card ahead of the NVIDIA cards in DRM order shifts
    /// every NVIDIA card by one. NEVER use it as a join key against benchmark
    /// rows or worker slots -- join on `pci_bus_id` instead.
    pub index: u32,
    pub name: String,
    pub vendor: GpuVendor,
    /// Vendor-local handle, NOT a PCI address: `nv:{nvml_index}` for NVIDIA,
    /// the sysfs device id for AMD/Intel. Correct for vendor-local lookups
    /// (`nvidia_smi_index`, `find_amd_card`); useless as a cross-crate key.
    pub pci_id: String,
    /// Canonical lowercase 4-digit-domain PCI address, e.g. `0000:06:1b.0`.
    /// The ONLY globally stable, vendor-neutral identity here, and the join
    /// key against prover-side benchmark rows and worker slots.
    pub pci_bus_id: String,
    pub gpu_clock_mhz: u32,
    pub mem_clock_mhz: u32,
    pub gpu_usage_percent: u32,
    pub mem_usage_percent: u32,
    pub vram_used_bytes: u64,
    pub vram_total_bytes: u64,
    pub temp_edge_c: Option<f64>,
    pub temp_junction_c: Option<f64>,
    pub temp_mem_c: Option<f64>,
    pub fan_rpm: u32,
    pub fan_max_rpm: u32,
    pub power_watts: f64,
    pub power_cap_watts: f64,
    pub voltage_mv: u32,
    pub pcie_speed: String,
    pub pcie_width: u32,
    pub vbios: String,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum GpuVendor {
    Amd,
    Nvidia,
    Intel,
    #[default]
    Unknown,
}

// ---------------------------------------------------------------------------
// CPU stat snapshot for usage% delta computation
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default)]
pub struct CpuStatSnapshot {
    pub idle: u64,
    pub total: u64,
}

/// Snapshot for computing Intel GPU power from energy counter deltas.
#[derive(Debug, Clone, Default)]
pub struct IntelGpuEnergySnapshot {
    pub energy_uj: u64,
    pub timestamp: Option<std::time::Instant>,
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// One-shot probe: detect hardware that won't change (CPU model, core count, GPU list).
/// Call once at startup.
pub fn probe_static() -> HardwareInfo {
    let mut info = HardwareInfo::default();

    // CPU static info
    if let Ok(cpuinfo) = fs::read_to_string("/proc/cpuinfo") {
        for line in cpuinfo.lines() {
            if line.starts_with("model name") {
                if let Some(val) = line.split(':').nth(1) {
                    info.cpu.model = shorten_cpu_name(val.trim());
                    break;
                }
            }
        }
    }
    // Count threads from /proc/cpuinfo "processor" entries, cores from unique "core id"
    if let Ok(cpuinfo) = fs::read_to_string("/proc/cpuinfo") {
        let mut thread_count: u32 = 0;
        let mut core_ids = std::collections::HashSet::new();
        for line in cpuinfo.lines() {
            if line.starts_with("processor") {
                thread_count += 1;
            } else if line.starts_with("core id") {
                if let Some(val) = line.split(':').nth(1) {
                    if let Ok(id) = val.trim().parse::<u32>() {
                        core_ids.insert(id);
                    }
                }
            }
        }
        info.cpu.threads = thread_count.max(1);
        info.cpu.cores = if core_ids.is_empty() {
            info.cpu.threads
        } else {
            core_ids.len() as u32
        };
    }

    // Detect GPUs
    info.gpus = detect_gpus();

    info
}

/// Refresh dynamic values in-place: CPU usage, load, memory, GPU telemetry.
/// Takes `&mut MinerState` to avoid split-borrow issues at call sites.
///
/// NOTE: This performs blocking I/O (sysfs reads, NVML calls). Prefer
/// [`collect_hw_snapshot`] + [`apply_hw_snapshot`] in async contexts to
/// avoid holding locks during I/O.
pub fn refresh_state(state: &mut crate::state::MinerState) {
    refresh_cpu(&mut state.hardware.cpu, &mut state.cpu_stat_snapshot);
    refresh_memory(&mut state.hardware.memory);
    for gpu in &mut state.hardware.gpus {
        let energy_snap = if gpu.vendor == GpuVendor::Intel {
            Some(
                state
                    .intel_gpu_energy
                    .entry(gpu.index)
                    .or_default(),
            )
        } else {
            None
        };
        refresh_gpu(gpu, energy_snap);
    }
}

/// Snapshot of mutable state needed for hardware refresh.
/// Clone this from MinerState under a brief read lock, then pass to
/// [`collect_hw_snapshot`] on a blocking thread.
#[derive(Clone)]
pub struct HwRefreshInput {
    pub hardware: HardwareInfo,
    pub cpu_stat_snapshot: CpuStatSnapshot,
    pub intel_gpu_energy: std::collections::HashMap<u32, IntelGpuEnergySnapshot>,
}

/// Result of hardware refresh — apply to MinerState under a brief write lock.
pub struct HwRefreshOutput {
    pub hardware: HardwareInfo,
    pub cpu_stat_snapshot: CpuStatSnapshot,
    pub intel_gpu_energy: std::collections::HashMap<u32, IntelGpuEnergySnapshot>,
}

/// Collect hardware telemetry snapshot. This performs all blocking I/O
/// (sysfs reads, NVML calls) and should be called from a blocking thread
/// via `tokio::task::spawn_blocking`. Does NOT require any locks.
pub fn collect_hw_snapshot(mut input: HwRefreshInput) -> HwRefreshOutput {
    refresh_cpu(&mut input.hardware.cpu, &mut input.cpu_stat_snapshot);
    refresh_memory(&mut input.hardware.memory);
    for gpu in &mut input.hardware.gpus {
        let energy_snap = if gpu.vendor == GpuVendor::Intel {
            Some(
                input
                    .intel_gpu_energy
                    .entry(gpu.index)
                    .or_default(),
            )
        } else {
            None
        };
        refresh_gpu(gpu, energy_snap);
    }
    HwRefreshOutput {
        hardware: input.hardware,
        cpu_stat_snapshot: input.cpu_stat_snapshot,
        intel_gpu_energy: input.intel_gpu_energy,
    }
}

/// Apply a hardware snapshot to MinerState. Call under a brief write lock.
pub fn apply_hw_snapshot(state: &mut crate::state::MinerState, output: HwRefreshOutput) {
    state.hardware = output.hardware;
    state.cpu_stat_snapshot = output.cpu_stat_snapshot;
    state.intel_gpu_energy = output.intel_gpu_energy;
}

// ---------------------------------------------------------------------------
// Dedicated hardware monitoring thread
// ---------------------------------------------------------------------------

/// A dedicated OS thread that polls hardware telemetry and sends snapshots
/// via a tokio channel. Completely isolated from the async runtime — even if
/// NVML hangs, no tokio resources are consumed.
///
/// NVML device handles are cached for the lifetime of the thread, reducing
/// per-refresh ioctl round-trips (no repeated `device_by_index()` calls).
pub struct HwMonitor {
    _stop: std::sync::mpsc::Sender<()>,
}

impl HwMonitor {
    /// Spawn the hardware monitor thread. Returns the monitor handle (drop to
    /// stop) and a tokio receiver for snapshots.
    pub fn spawn(
        initial: HwRefreshInput,
        poll_interval: std::time::Duration,
    ) -> (Self, tokio::sync::mpsc::Receiver<HwRefreshOutput>) {
        let (stop_tx, stop_rx) = std::sync::mpsc::channel::<()>();
        // Capacity 2: if the async side is slow, we drop stale samples
        // rather than blocking the monitor thread.
        let (tx, rx) = tokio::sync::mpsc::channel::<HwRefreshOutput>(2);

        std::thread::Builder::new()
            .name("hw-monitor".into())
            .spawn(move || {
                Self::run(initial, poll_interval, stop_rx, tx);
            })
            .expect("failed to spawn hw-monitor thread");

        (Self { _stop: stop_tx }, rx)
    }

    /// Maximum acceptable NVML refresh duration before we start throttling.
    const NVML_SLOW_THRESHOLD: std::time::Duration = std::time::Duration::from_millis(50);
    /// After this many consecutive slow cycles, reduce NVML polling to every Nth cycle.
    const NVML_SLOW_COUNT_THRESHOLD: u32 = 1;
    /// When throttled, poll NVML every Nth cycle (others skip NVIDIA and use stale data).
    const NVML_THROTTLE_DIVISOR: u32 = 10;

    fn run(
        mut state: HwRefreshInput,
        poll_interval: std::time::Duration,
        stop_rx: std::sync::mpsc::Receiver<()>,
        tx: tokio::sync::mpsc::Sender<HwRefreshOutput>,
    ) {
        // Cache NVML device handles — avoids a device_by_index() ioctl per refresh.
        let nvml_devices = cache_nvml_devices(&state.hardware);
        let has_nvidia = state.hardware.gpus.iter().any(|g| g.vendor == GpuVendor::Nvidia);

        let mut cycle: u32 = 0;
        let mut nvml_consecutive_slow: u32 = 0;
        let mut nvml_throttled = false;

        loop {
            // Wait for the next poll interval, or exit if stop signal received.
            match stop_rx.recv_timeout(poll_interval) {
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {} // normal
                _ => return, // stop signal or channel closed
            }

            cycle = cycle.wrapping_add(1);

            // Decide whether to poll NVIDIA this cycle.
            // When throttled, only poll every Nth cycle to reduce kernel driver contention.
            let poll_nvidia = has_nvidia
                && (!nvml_throttled || cycle % Self::NVML_THROTTLE_DIVISOR == 0);

            // All blocking I/O happens here on this dedicated thread.
            refresh_cpu(&mut state.hardware.cpu, &mut state.cpu_stat_snapshot);
            refresh_memory(&mut state.hardware.memory);

            let nvml_start = std::time::Instant::now();

            for gpu in &mut state.hardware.gpus {
                let energy_snap = if gpu.vendor == GpuVendor::Intel {
                    Some(state.intel_gpu_energy.entry(gpu.index).or_default())
                } else {
                    None
                };
                if gpu.vendor == GpuVendor::Nvidia {
                    if poll_nvidia {
                        if let Some(device) = nvml_devices.as_ref().and_then(|d| d.get(&gpu.index)) {
                            refresh_nvidia_gpu_cached(gpu, device);
                        }
                    }
                    // PCIe from sysfs is always fast
                    if let Some((base, _)) = find_drm_card_by_global_idx(gpu.index) {
                        if let Some(speed) = read_trimmed(&format!("{}/current_link_speed", base)) {
                            gpu.pcie_speed = speed;
                        }
                        gpu.pcie_width = read_u32(&format!("{}/current_link_width", base))
                            .unwrap_or(gpu.pcie_width);
                    }
                } else {
                    refresh_gpu(gpu, energy_snap);
                }
            }

            // Track NVML call duration and throttle if consistently slow.
            if poll_nvidia {
                let nvml_elapsed = nvml_start.elapsed();
                if nvml_elapsed > Self::NVML_SLOW_THRESHOLD {
                    nvml_consecutive_slow += 1;
                    if nvml_consecutive_slow >= Self::NVML_SLOW_COUNT_THRESHOLD && !nvml_throttled {
                        nvml_throttled = true;
                        tracing::warn!(
                            "NVML monitoring throttled — calls averaging {:?}, \
                             polling every {}th cycle",
                            nvml_elapsed,
                            Self::NVML_THROTTLE_DIVISOR,
                        );
                    }
                } else {
                    if nvml_throttled && nvml_consecutive_slow > 0 {
                        nvml_consecutive_slow -= 1;
                        if nvml_consecutive_slow == 0 {
                            nvml_throttled = false;
                            tracing::info!("NVML monitoring resumed — calls fast again");
                        }
                    } else {
                        nvml_consecutive_slow = 0;
                    }
                }
            }

            let output = HwRefreshOutput {
                hardware: state.hardware.clone(),
                cpu_stat_snapshot: state.cpu_stat_snapshot.clone(),
                intel_gpu_energy: state.intel_gpu_energy.clone(),
            };

            // try_send: drop stale sample if channel is full.
            if tx.try_send(output).is_err() && tx.is_closed() {
                return;
            }
        }
    }
}

/// Cache NVML Device objects keyed by global GPU index.
/// Returns None if NVML is unavailable.
fn cache_nvml_devices(
    hw: &HardwareInfo,
) -> Option<std::collections::HashMap<u32, nvml_wrapper::Device<'static>>> {
    let nvml = nvml()?;
    let mut map = std::collections::HashMap::new();
    for gpu in &hw.gpus {
        if gpu.vendor == GpuVendor::Nvidia {
            let nv_idx: u32 = gpu
                .pci_id
                .strip_prefix("nv:")
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
            if let Ok(device) = nvml.device_by_index(nv_idx) {
                map.insert(gpu.index, device);
            }
        }
    }
    Some(map)
}

/// Refresh NVIDIA GPU telemetry using a cached Device handle (no device_by_index ioctl).
fn refresh_nvidia_gpu_cached(gpu: &mut GpuInfo, device: &nvml_wrapper::Device) {
    if let Ok(util) = device.utilization_rates() {
        gpu.gpu_usage_percent = util.gpu;
        gpu.mem_usage_percent = util.memory;
    }
    if let Ok(mem) = device.memory_info() {
        gpu.vram_used_bytes = mem.used;
        gpu.vram_total_bytes = mem.total;
    }
    use nvml_wrapper::enum_wrappers::device::TemperatureSensor;
    gpu.temp_edge_c = device
        .temperature(TemperatureSensor::Gpu)
        .ok()
        .map(|t| t as f64);
    gpu.temp_junction_c = None;
    gpu.temp_mem_c = None;
    gpu.fan_rpm = device.fan_speed(0).unwrap_or(0);
    gpu.power_watts = device
        .power_usage()
        .map(|mw| mw as f64 / 1000.0)
        .unwrap_or(0.0);
    gpu.power_cap_watts = device
        .power_management_limit()
        .map(|mw| mw as f64 / 1000.0)
        .unwrap_or(gpu.power_cap_watts);
    use nvml_wrapper::enum_wrappers::device::Clock;
    gpu.gpu_clock_mhz = device.clock_info(Clock::Graphics).unwrap_or(0);
    gpu.mem_clock_mhz = device.clock_info(Clock::Memory).unwrap_or(0);
}

// ---------------------------------------------------------------------------
// CPU
// ---------------------------------------------------------------------------

fn refresh_cpu(cpu: &mut CpuInfo, prev: &mut CpuStatSnapshot) {
    // Load average
    if let Ok(la) = fs::read_to_string("/proc/loadavg") {
        let parts: Vec<&str> = la.split_whitespace().collect();
        if parts.len() >= 3 {
            cpu.load_avg[0] = parts[0].parse().unwrap_or(0.0);
            cpu.load_avg[1] = parts[1].parse().unwrap_or(0.0);
            cpu.load_avg[2] = parts[2].parse().unwrap_or(0.0);
        }
    }

    // CPU usage from /proc/stat
    if let Ok(stat) = fs::read_to_string("/proc/stat") {
        if let Some(line) = stat.lines().next() {
            let vals: Vec<u64> = line
                .split_whitespace()
                .skip(1) // skip "cpu"
                .filter_map(|v| v.parse().ok())
                .collect();
            if vals.len() >= 4 {
                let idle = vals[3] + vals.get(4).copied().unwrap_or(0); // idle + iowait
                let total: u64 = vals.iter().sum();

                if prev.total > 0 {
                    let d_total = total.saturating_sub(prev.total);
                    let d_idle = idle.saturating_sub(prev.idle);
                    if d_total > 0 {
                        cpu.usage_percent =
                            (1.0 - d_idle as f64 / d_total as f64) * 100.0;
                    }
                }
                prev.idle = idle;
                prev.total = total;
            }
        }
    }

    // CPU frequency — average of scaling_cur_freq across all cores
    let mut total_freq: u64 = 0;
    let mut count: u32 = 0;
    for i in 0..cpu.threads {
        let path = format!(
            "/sys/devices/system/cpu/cpu{}/cpufreq/scaling_cur_freq",
            i
        );
        if let Some(khz) = read_u64(&path) {
            total_freq += khz;
            count += 1;
        }
    }
    if count > 0 {
        cpu.freq_mhz = (total_freq / count as u64 / 1000) as u32;
    }
}

// ---------------------------------------------------------------------------
// Memory
// ---------------------------------------------------------------------------

fn refresh_memory(mem: &mut MemoryInfo) {
    if let Ok(mi) = fs::read_to_string("/proc/meminfo") {
        let mut total_kb: u64 = 0;
        let mut available_kb: u64 = 0;
        let mut free_kb: u64 = 0;
        let mut swap_total_kb: u64 = 0;
        let mut swap_free_kb: u64 = 0;
        let mut buffers_kb: u64 = 0;
        let mut cached_kb: u64 = 0;

        for line in mi.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                match parts[0] {
                    "MemTotal:" => total_kb = parts[1].parse().unwrap_or(0),
                    "MemAvailable:" => available_kb = parts[1].parse().unwrap_or(0),
                    "MemFree:" => free_kb = parts[1].parse().unwrap_or(0),
                    "Buffers:" => buffers_kb = parts[1].parse().unwrap_or(0),
                    "Cached:" => cached_kb = parts[1].parse().unwrap_or(0),
                    "SwapTotal:" => swap_total_kb = parts[1].parse().unwrap_or(0),
                    "SwapFree:" => swap_free_kb = parts[1].parse().unwrap_or(0),
                    _ => {}
                }
            }
        }

        mem.total_bytes = total_kb * 1024;
        // Use MemAvailable if present, else approximate
        mem.available_bytes = if available_kb > 0 {
            available_kb * 1024
        } else {
            (free_kb + buffers_kb + cached_kb) * 1024
        };
        mem.used_bytes = mem.total_bytes.saturating_sub(mem.available_bytes);
        mem.swap_total_bytes = swap_total_kb * 1024;
        mem.swap_used_bytes = swap_total_kb.saturating_sub(swap_free_kb) * 1024;
    }
}

// ---------------------------------------------------------------------------
// GPU detection
// ---------------------------------------------------------------------------

/// Known AMD PCI device IDs → marketing names.
fn amd_gpu_name(device_id: &str) -> String {
    match device_id {
        "0x7550" => "RX 9070 XT".to_string(),
        "0x7551" => "RX 9070".to_string(),
        "0x744c" => "RX 7900 XTX".to_string(),
        "0x7480" => "RX 7900 XT".to_string(),
        "0x7470" => "RX 7800 XT".to_string(),
        "0x7460" => "RX 7700 XT".to_string(),
        "0x73bf" => "RX 6900 XT".to_string(),
        "0x73af" => "RX 6800 XT".to_string(),
        "0x73a5" => "RX 6800".to_string(),
        "0x73df" => "RX 6700 XT".to_string(),
        "0x73ff" => "RX 6600 XT".to_string(),
        "0x15e7" => "Vega 10 (MI25)".to_string(),
        "0x66af" => "Radeon VII".to_string(),
        "0x740c" => "MI300X".to_string(),
        "0x740f" => "MI300A".to_string(),
        "0x7408" => "MI250X".to_string(),
        "0x740a" => "MI250".to_string(),
        "0x738c" => "MI100".to_string(),
        _ => format!("AMD GPU [{}]", device_id),
    }
}

/// Known Intel PCI device IDs → marketing names.
fn intel_gpu_name(device_id: &str) -> String {
    match device_id {
        // Arc Alchemist (DG2)
        "0x56a0" => "Arc A770".to_string(),
        "0x56a1" => "Arc A750".to_string(),
        "0x56a5" => "Arc A580".to_string(),
        "0x56a6" => "Arc A380".to_string(),
        "0x5690" => "Arc A770M".to_string(),
        "0x5691" => "Arc A730M".to_string(),
        "0x5692" => "Arc A550M".to_string(),
        "0x56b0" => "Data Center GPU Flex 170".to_string(),
        "0x56b1" => "Data Center GPU Flex 140".to_string(),
        // Arc Battlemage — BMG-G21 (small die)
        "0xe202" => "Arc BMG-G21".to_string(),
        "0xe209" => "Arc B580".to_string(),
        "0xe20b" => "Arc B580".to_string(),
        "0xe20c" => "Arc B570".to_string(),
        "0xe20d" => "Arc BMG-G21".to_string(),
        "0xe210" => "Arc BMG-G21".to_string(),
        "0xe211" => "Arc Pro B60".to_string(),
        "0xe212" => "Arc Pro B50".to_string(),
        "0xe216" => "Arc BMG-G21".to_string(),
        // Arc Battlemage — BMG-G31 (big die)
        "0xe220" => "Arc BMG-G31".to_string(),
        "0xe221" => "Arc BMG-G31".to_string(),
        "0xe222" => "Arc BMG-G31".to_string(),
        "0xe223" => "Arc Pro B70".to_string(),
        // Data Center GPU Max (Ponte Vecchio / PVC)
        "0x0bd5" => "Data Center GPU Max 1550".to_string(),
        "0x0bd6" => "Data Center GPU Max 1100".to_string(),
        "0x0bd9" => "Data Center GPU Max 1350".to_string(),
        "0x0bda" => "Data Center GPU Max 1100C".to_string(),
        "0x0bdb" => "Data Center GPU Max 1550VG".to_string(),
        _ => format!("Intel GPU [{}]", device_id),
    }
}

fn detect_gpus() -> Vec<GpuInfo> {
    let mut gpus = Vec::new();
    let mut idx = 0u32;

    // Pre-fetch NVIDIA GPU data keyed by PCI bus ID so we can merge it
    // into the DRM card scan below (preserving DRM card order).
    let nvml_data = query_nvml_gpus();

    // Single pass over DRM cards — all vendors in card-number order.
    for card_num in 0..16 {
        let base = format!("/sys/class/drm/card{}/device", card_num);
        let base_path = Path::new(&base);
        if !base_path.exists() {
            continue;
        }

        let vendor = read_trimmed(&format!("{}/vendor", base)).unwrap_or_default();

        if vendor == "0x1002" {
            // AMD GPU — check it has amdgpu telemetry files
            if !Path::new(&format!("{}/gpu_busy_percent", base)).exists() {
                continue;
            }

            let device_id = read_trimmed(&format!("{}/device", base)).unwrap_or_default();
            let name = amd_gpu_name(&device_id);
            let vbios = read_trimmed(&format!("{}/vbios_version", base)).unwrap_or_default();
            let pcie_speed = read_trimmed(&format!("{}/current_link_speed", base))
                .unwrap_or_default();
            let pcie_width =
                read_u32(&format!("{}/current_link_width", base)).unwrap_or(0);

            // Find hwmon path
            let hwmon = find_hwmon(&base);

            let vram_total =
                read_u64(&format!("{}/mem_info_vram_total", base)).unwrap_or(0);

            let mut gpu = GpuInfo {
                index: idx,
                name,
                vendor: GpuVendor::Amd,
                pci_id: device_id,
                pci_bus_id: read_pci_slot_from_uevent_path(&format!("{}/uevent", base))
                    .map(|id| normalize_pci_bus_id(&id))
                    .unwrap_or_default(),
                gpu_clock_mhz: 0,
                mem_clock_mhz: 0,
                gpu_usage_percent: 0,
                mem_usage_percent: 0,
                vram_used_bytes: 0,
                vram_total_bytes: vram_total,
                temp_edge_c: None,
                temp_junction_c: None,
                temp_mem_c: None,
                fan_rpm: 0,
                fan_max_rpm: read_u32_from_hwmon(&hwmon, "fan1_max").unwrap_or(0),
                power_watts: 0.0,
                power_cap_watts: read_u64_from_hwmon(&hwmon, "power1_cap")
                    .map(|v| v as f64 / 1_000_000.0)
                    .unwrap_or(0.0),
                voltage_mv: 0,
                pcie_speed,
                pcie_width,
                vbios,
            };

            gpu.gpu_clock_mhz = 0; // will be set in refresh
            refresh_amd_gpu(&mut gpu, &base, &hwmon);

            gpus.push(gpu);
            idx += 1;
        } else if vendor == "0x8086" {
            // Intel GPU — must have i915 or xe driver with discrete GPU indicators.
            if !is_intel_discrete_gpu(&base) {
                continue;
            }

            let device_id = read_trimmed(&format!("{}/device", base)).unwrap_or_default();
            let name = intel_gpu_name(&device_id);
            let hwmon = find_hwmon(&base);

            let vram_total = detect_intel_vram(&base);
            let pcie_speed = read_trimmed(&format!("{}/current_link_speed", base))
                .unwrap_or_default();
            let pcie_width =
                read_u32(&format!("{}/current_link_width", base)).unwrap_or(0);

            let mut gpu = GpuInfo {
                index: idx,
                name,
                vendor: GpuVendor::Intel,
                pci_id: device_id,
                pci_bus_id: read_pci_slot_from_uevent_path(&format!("{}/uevent", base))
                    .map(|id| normalize_pci_bus_id(&id))
                    .unwrap_or_default(),
                gpu_clock_mhz: 0,
                mem_clock_mhz: 0,
                gpu_usage_percent: 0,
                mem_usage_percent: 0,
                vram_used_bytes: 0,
                vram_total_bytes: vram_total,
                temp_edge_c: None,
                temp_junction_c: None,
                temp_mem_c: None,
                fan_rpm: 0,
                fan_max_rpm: read_u32_from_hwmon(&hwmon, "fan1_max").unwrap_or(0),
                power_watts: 0.0,
                power_cap_watts: read_u64_from_hwmon(&hwmon, "power1_cap")
                    .map(|v| v as f64 / 1_000_000.0)
                    .unwrap_or(0.0),
                voltage_mv: 0,
                pcie_speed,
                pcie_width,
                vbios: String::new(),
            };

            refresh_intel_gpu(&mut gpu, &base, &hwmon, None);
            gpus.push(gpu);
            idx += 1;
        } else if vendor == "0x10de" {
            // NVIDIA GPU — match against pre-fetched nvidia-smi data by PCI bus ID.
            let pci_bus_id = read_pci_slot_from_uevent_path(&format!("{}/uevent", base))
                .map(|id| normalize_pci_bus_id(&id))
                .unwrap_or_default();
            if pci_bus_id.is_empty() {
                continue;
            }

            let Some(nv) = nvml_data.get(&pci_bus_id) else {
                continue;
            };

            // Read negotiated PCIe speed from sysfs (current, not max)
            let pcie_speed = read_trimmed(&format!("{}/current_link_speed", base))
                .unwrap_or(nv.pcie_speed.clone());
            let pcie_width =
                read_u32(&format!("{}/current_link_width", base)).unwrap_or(nv.pcie_width);

            let mut gpu = GpuInfo {
                index: idx,
                name: nv.name.clone(),
                vendor: GpuVendor::Nvidia,
                pci_id: format!("nv:{}", nv.nv_index),
                pci_bus_id: pci_bus_id.clone(),
                gpu_clock_mhz: 0,
                mem_clock_mhz: 0,
                gpu_usage_percent: 0,
                mem_usage_percent: 0,
                vram_used_bytes: 0,
                vram_total_bytes: nv.vram_bytes,
                temp_edge_c: None,
                temp_junction_c: None,
                temp_mem_c: None,
                fan_rpm: 0,
                fan_max_rpm: 100, // NVIDIA reports fan as %, not RPM
                power_watts: 0.0,
                power_cap_watts: nv.power_cap,
                voltage_mv: 0,
                pcie_speed,
                pcie_width,
                vbios: nv.vbios.clone(),
            };

            refresh_nvidia_gpu(&mut gpu);
            gpus.push(gpu);
            idx += 1;
        }
    }

    // Fallback: if nvidia-smi found GPUs but none matched DRM cards
    // (e.g., no DRM device exposed), append them at the end.
    if !nvml_data.is_empty() {
        let matched: std::collections::HashSet<String> = gpus
            .iter()
            .filter(|g| g.vendor == GpuVendor::Nvidia)
            .filter_map(|g| {
                let nv_idx = g.pci_id.strip_prefix("nv:")?;
                nvml_data.values().find(|nv| nv.nv_index == nv_idx).map(|nv| nv.pci_bus_id.clone())
            })
            .collect();

        let mut unmatched: Vec<_> = nvml_data
            .iter()
            .filter(|(bus_id, _)| !matched.contains(*bus_id))
            .collect();
        // nv_index is a String, so the natural sort_by_key is LEXICOGRAPHIC: on a
        // 10+ GPU rig that orders 0,1,10,11,2,3 and GpuInfo.index stops matching
        // the NVML index even on a pure-NVIDIA box. Sort numerically, falling back
        // to the string form so unparseable values keep a deterministic order.
        unmatched.sort_by(|(_, a), (_, b)| {
            let na = a.nv_index.parse::<u32>().ok();
            let nb = b.nv_index.parse::<u32>().ok();
            match (na, nb) {
                (Some(x), Some(y)) => x.cmp(&y),
                _ => a.nv_index.cmp(&b.nv_index),
            }
        });

        for (_, nv) in unmatched {
            let mut gpu = GpuInfo {
                index: idx,
                name: nv.name.clone(),
                vendor: GpuVendor::Nvidia,
                pci_id: format!("nv:{}", nv.nv_index),
                pci_bus_id: normalize_pci_bus_id(&nv.pci_bus_id),
                gpu_clock_mhz: 0,
                mem_clock_mhz: 0,
                gpu_usage_percent: 0,
                mem_usage_percent: 0,
                vram_used_bytes: 0,
                vram_total_bytes: nv.vram_bytes,
                temp_edge_c: None,
                temp_junction_c: None,
                temp_mem_c: None,
                fan_rpm: 0,
                fan_max_rpm: 100,
                power_watts: 0.0,
                power_cap_watts: nv.power_cap,
                voltage_mv: 0,
                pcie_speed: nv.pcie_speed.clone(),
                pcie_width: nv.pcie_width,
                vbios: nv.vbios.clone(),
            };
            refresh_nvidia_gpu(&mut gpu);
            gpus.push(gpu);
            idx += 1;
        }
    }

    gpus
}

/// Pre-fetched NVIDIA GPU data from NVML, keyed by lowercase PCI bus ID.
struct NvmlGpuData {
    nv_index: String,
    name: String,
    vram_bytes: u64,
    pcie_speed: String,
    pcie_width: u32,
    power_cap: f64,
    vbios: String,
    pci_bus_id: String,
}

/// Query NVML once at startup and return GPU data keyed by lowercase PCI bus ID.
/// Falls back to empty map if NVML is unavailable (no NVIDIA driver).
fn query_nvml_gpus() -> std::collections::HashMap<String, NvmlGpuData> {
    let mut map = std::collections::HashMap::new();

    let Some(nvml) = nvml() else {
        return map;
    };

    let count = match nvml.device_count() {
        Ok(c) => c,
        Err(_) => return map,
    };

    for i in 0..count {
        let device = match nvml.device_by_index(i) {
            Ok(d) => d,
            Err(_) => continue,
        };

        let name = device
            .name()
            .unwrap_or_default()
            .strip_prefix("NVIDIA ")
            .unwrap_or(&device.name().unwrap_or_default())
            .to_string();

        let pci_info = device.pci_info().ok();
        let pci_bus_id = pci_info
            .as_ref()
            .map(|p| normalize_pci_bus_id(&p.bus_id))
            .unwrap_or_default();

        let vram_bytes = device
            .memory_info()
            .map(|m| m.total)
            .unwrap_or(0);

        let pcie_gen = device
            .max_pcie_link_gen()
            .unwrap_or(0);
        let pcie_width = device
            .max_pcie_link_width()
            .unwrap_or(0);
        let pcie_speed = if pcie_gen > 0 {
            format!("Gen{}", pcie_gen)
        } else {
            String::new()
        };

        let power_cap = device
            .power_management_limit()
            .map(|mw| mw as f64 / 1000.0)
            .unwrap_or(0.0);

        let vbios = device.vbios_version().unwrap_or_default();

        map.insert(pci_bus_id.clone(), NvmlGpuData {
            nv_index: i.to_string(),
            name,
            vram_bytes,
            pcie_speed,
            pcie_width,
            power_cap,
            vbios,
            pci_bus_id,
        });
    }

    map
}

/// Parse PCI_SLOT_NAME from a uevent file path string.
fn read_pci_slot_from_uevent_path(path: &str) -> Option<String> {
    let content = fs::read_to_string(path).ok()?;
    for line in content.lines() {
        if let Some(val) = line.strip_prefix("PCI_SLOT_NAME=") {
            return Some(val.trim().to_string());
        }
    }
    None
}

/// Normalize a PCI bus ID to a canonical lowercase form.
/// NVML uses 8-digit domain ("00000000:01:00.0") while sysfs uevent
/// uses 4-digit domain ("0000:01:00.0"). Normalize to 4-digit domain.
fn normalize_pci_bus_id(id: &str) -> String {
    let id = id.to_lowercase();
    // If domain is 8 digits (e.g. "00000000:01:00.0"), trim to 4
    if id.len() > 12 {
        if let Some(first_colon) = id.find(':') {
            let domain = &id[..first_colon];
            if domain.len() == 8 {
                return format!("{}{}", &domain[4..], &id[first_colon..]);
            }
        }
    }
    id
}

// ---------------------------------------------------------------------------
// GPU refresh
// ---------------------------------------------------------------------------

fn refresh_gpu(gpu: &mut GpuInfo, intel_energy: Option<&mut IntelGpuEnergySnapshot>) {
    match gpu.vendor {
        GpuVendor::Amd => {
            if let Some((base, hwmon)) = find_amd_card(gpu.index) {
                refresh_amd_gpu(gpu, &base, &hwmon);
            }
        }
        GpuVendor::Nvidia => {
            refresh_nvidia_gpu(gpu);
            // Refresh negotiated PCIe from sysfs (nvidia-smi doesn't report current link speed)
            if let Some((base, _vendor)) = find_drm_card_by_global_idx(gpu.index) {
                if let Some(speed) = read_trimmed(&format!("{}/current_link_speed", base)) {
                    gpu.pcie_speed = speed;
                }
                gpu.pcie_width = read_u32(&format!("{}/current_link_width", base))
                    .unwrap_or(gpu.pcie_width);
            }
        }
        GpuVendor::Intel => {
            if let Some((base, hwmon)) = find_intel_card(gpu.index) {
                refresh_intel_gpu(gpu, &base, &hwmon, intel_energy);
            }
        }
        _ => {}
    }
}

fn refresh_nvidia_gpu(gpu: &mut GpuInfo) {
    let nv_idx: u32 = gpu
        .pci_id
        .strip_prefix("nv:")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    let Some(nvml) = nvml() else {
        return;
    };
    let device = match nvml.device_by_index(nv_idx) {
        Ok(d) => d,
        Err(_) => return,
    };

    // Utilization
    if let Ok(util) = device.utilization_rates() {
        gpu.gpu_usage_percent = util.gpu;
        gpu.mem_usage_percent = util.memory;
    }

    // Memory
    if let Ok(mem) = device.memory_info() {
        gpu.vram_used_bytes = mem.used;
        gpu.vram_total_bytes = mem.total;
    }

    // Temperature
    use nvml_wrapper::enum_wrappers::device::TemperatureSensor;
    gpu.temp_edge_c = device
        .temperature(TemperatureSensor::Gpu)
        .ok()
        .map(|t| t as f64);
    gpu.temp_junction_c = None;
    gpu.temp_mem_c = None;

    // Fan (NVIDIA reports as percentage, stored in fan_rpm with max=100)
    gpu.fan_rpm = device.fan_speed(0).unwrap_or(0);

    // Power
    gpu.power_watts = device
        .power_usage()
        .map(|mw| mw as f64 / 1000.0)
        .unwrap_or(0.0);
    gpu.power_cap_watts = device
        .power_management_limit()
        .map(|mw| mw as f64 / 1000.0)
        .unwrap_or(gpu.power_cap_watts);

    // Clocks
    use nvml_wrapper::enum_wrappers::device::Clock;
    gpu.gpu_clock_mhz = device.clock_info(Clock::Graphics).unwrap_or(0);
    gpu.mem_clock_mhz = device.clock_info(Clock::Memory).unwrap_or(0);
}

pub(crate) fn find_amd_card(target_idx: u32) -> Option<(String, Option<PathBuf>)> {
    let (base, vendor) = find_drm_card_by_global_idx(target_idx)?;
    if vendor == "0x1002" && Path::new(&format!("{}/gpu_busy_percent", base)).exists() {
        let hwmon = find_hwmon(&base);
        Some((base, hwmon))
    } else {
        None
    }
}

/// Find a DRM card's sysfs device path by global GPU index.
/// Counts all discrete GPUs (AMD, Intel, NVIDIA) in DRM card order.
fn find_drm_card_by_global_idx(target_idx: u32) -> Option<(String, String)> {
    let mut idx = 0u32;
    for card_num in 0..16 {
        let base = format!("/sys/class/drm/card{}/device", card_num);
        if !Path::new(&base).exists() {
            continue;
        }
        let vendor = read_trimmed(&format!("{}/vendor", base)).unwrap_or_default();
        let is_gpu = match vendor.as_str() {
            "0x1002" => Path::new(&format!("{}/gpu_busy_percent", base)).exists(),
            "0x8086" => is_intel_discrete_gpu(&base),
            "0x10de" => true,
            _ => false,
        };
        if is_gpu {
            if idx == target_idx {
                return Some((base, vendor));
            }
            idx += 1;
        }
    }
    None
}

fn refresh_amd_gpu(gpu: &mut GpuInfo, base: &str, hwmon: &Option<PathBuf>) {
    gpu.gpu_usage_percent =
        read_u32(&format!("{}/gpu_busy_percent", base)).unwrap_or(0);
    gpu.mem_usage_percent =
        read_u32(&format!("{}/mem_busy_percent", base)).unwrap_or(0);
    gpu.vram_used_bytes =
        read_u64(&format!("{}/mem_info_vram_used", base)).unwrap_or(0);
    gpu.vram_total_bytes =
        read_u64(&format!("{}/mem_info_vram_total", base)).unwrap_or(gpu.vram_total_bytes);

    // Clocks from hwmon (Hz → MHz)
    if let Some(ref hwmon_path) = hwmon {
        gpu.gpu_clock_mhz = read_u64_from_hwmon_path(hwmon_path, "freq1_input")
            .map(|v| (v / 1_000_000) as u32)
            .unwrap_or(0);
        gpu.mem_clock_mhz = read_u64_from_hwmon_path(hwmon_path, "freq2_input")
            .map(|v| (v / 1_000_000) as u32)
            .unwrap_or(0);

        // Temperatures (millidegrees → degrees)
        gpu.temp_edge_c = read_u64_from_hwmon_path(hwmon_path, "temp1_input")
            .map(|v| v as f64 / 1000.0);
        gpu.temp_junction_c = read_u64_from_hwmon_path(hwmon_path, "temp2_input")
            .map(|v| v as f64 / 1000.0);
        gpu.temp_mem_c = read_u64_from_hwmon_path(hwmon_path, "temp3_input")
            .map(|v| v as f64 / 1000.0);

        // Fan
        gpu.fan_rpm = read_u32_from_hwmon_path(hwmon_path, "fan1_input").unwrap_or(0);
        gpu.fan_max_rpm = read_u32_from_hwmon_path(hwmon_path, "fan1_max")
            .unwrap_or(gpu.fan_max_rpm);

        // Power (microwatts → watts)
        gpu.power_watts = read_u64_from_hwmon_path(hwmon_path, "power1_average")
            .map(|v| v as f64 / 1_000_000.0)
            .unwrap_or(0.0);
        gpu.power_cap_watts = read_u64_from_hwmon_path(hwmon_path, "power1_cap")
            .map(|v| v as f64 / 1_000_000.0)
            .unwrap_or(gpu.power_cap_watts);

        // Voltage
        gpu.voltage_mv = read_u32_from_hwmon_path(hwmon_path, "in0_input").unwrap_or(0);
    }

    // PCIe (may change with power state)
    if let Some(speed) = read_trimmed(&format!("{}/current_link_speed", base)) {
        gpu.pcie_speed = speed;
    }
    gpu.pcie_width =
        read_u32(&format!("{}/current_link_width", base)).unwrap_or(gpu.pcie_width);
}

// ---------------------------------------------------------------------------
// Intel GPU detection & refresh
// ---------------------------------------------------------------------------

/// Check if an Intel PCI device at `base` is a discrete GPU (not an iGPU).
/// Discrete Intel GPUs (Arc, Data Center Max) have dedicated local memory.
fn is_intel_discrete_gpu(base: &str) -> bool {
    let base_path = Path::new(base);

    // xe driver: check for tile0 directory (discrete GPUs have tiles)
    if base_path.join("tile0").is_dir() {
        return true;
    }

    // i915 driver: check for local memory regions via resource file.
    // BAR2 (resource2) with non-zero size indicates dedicated VRAM.
    if let Ok(resource) = fs::read_to_string(format!("{}/resource", base)) {
        for (i, line) in resource.lines().enumerate() {
            // resource2 = BAR2 = local memory on DG2+
            if i == 2 {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    let start = u64::from_str_radix(
                        parts[0].trim_start_matches("0x"),
                        16,
                    )
                    .unwrap_or(0);
                    let end = u64::from_str_radix(
                        parts[1].trim_start_matches("0x"),
                        16,
                    )
                    .unwrap_or(0);
                    if end > start {
                        return true;
                    }
                }
                break;
            }
        }
    }

    // Fallback: check if the DRM driver is i915 or xe with a known discrete device ID.
    // The PCI class 0x030000 = VGA controller; discrete GPUs also show as 0x038000 (display)
    // but we rely on local memory checks above as the primary signal.
    false
}

/// Detect Intel GPU VRAM size. The xe driver exposes this via tile0/physical_vram_size_bytes
/// or the hwmon/i915 driver can expose it via other paths.
fn detect_intel_vram(base: &str) -> u64 {
    // xe driver: tile0/physical_vram_size_bytes
    if let Some(vram) = read_u64(&format!("{}/tile0/physical_vram_size_bytes", base)) {
        return vram;
    }

    // i915 driver: check resource2 (BAR2 = LMEM) size from PCI resource file
    if let Ok(resource) = fs::read_to_string(format!("{}/resource", base)) {
        for (i, line) in resource.lines().enumerate() {
            if i == 2 {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    let start = u64::from_str_radix(
                        parts[0].trim_start_matches("0x"),
                        16,
                    )
                    .unwrap_or(0);
                    let end = u64::from_str_radix(
                        parts[1].trim_start_matches("0x"),
                        16,
                    )
                    .unwrap_or(0);
                    if end > start {
                        return end - start + 1;
                    }
                }
                break;
            }
        }
    }

    0
}

/// Find the sysfs base path and hwmon for an Intel GPU by its global index.
pub(crate) fn find_intel_card(target_idx: u32) -> Option<(String, Option<PathBuf>)> {
    let (base, vendor) = find_drm_card_by_global_idx(target_idx)?;
    if vendor == "0x8086" && is_intel_discrete_gpu(&base) {
        let hwmon = find_hwmon(&base);
        Some((base, hwmon))
    } else {
        None
    }
}

/// Refresh dynamic telemetry for an Intel GPU via sysfs/hwmon.
/// The xe driver exposes temps/energy via hwmon and clocks via tile0/gt0/freq0/.
fn refresh_intel_gpu(
    gpu: &mut GpuInfo,
    base: &str,
    hwmon: &Option<PathBuf>,
    energy_snap: Option<&mut IntelGpuEnergySnapshot>,
) {
    // GPU clock — reading act_freq or cur_freq triggers a GuC firmware query
    // that wakes the GPU from C6 idle, causing a ~7 second kernel stall.
    // Only read frequency when the GPU is already active (gt-c0).
    let idle_status = read_trimmed(&format!("{}/tile0/gt0/gtidle/idle_status", base));
    let gpu_active = idle_status.as_deref() == Some("gt-c0");
    if gpu_active {
        gpu.gpu_clock_mhz = read_u32(&format!("{}/tile0/gt0/freq0/act_freq", base))
            .or_else(|| read_u32(&format!("{}/tile0/gt0/freq0/cur_freq", base)))
            .unwrap_or(0);
    } else {
        // GPU is idle (C6) — report 0 MHz, don't wake it.
        gpu.gpu_clock_mhz = 0;
    }

    // Memory clock — xe driver does not expose VRAM clock via sysfs.
    gpu.mem_clock_mhz = 0;

    if let Some(ref hwmon_path) = hwmon {
        // Temperatures (millidegrees → degrees)
        // The xe driver numbers vary (e.g. temp2=pkg, temp3=vram with no temp1).
        // Use labels to find the right sensors.
        gpu.temp_edge_c = None;
        gpu.temp_mem_c = None;
        gpu.temp_junction_c = None;
        for i in 1..=6 {
            let label = read_hwmon_str(hwmon_path, &format!("temp{}_label", i));
            let value = read_u64_from_hwmon_path(hwmon_path, &format!("temp{}_input", i))
                .map(|v| v as f64 / 1000.0);
            match label.as_deref() {
                Some("pkg") => gpu.temp_edge_c = value,
                Some("vram") => gpu.temp_mem_c = value,
                _ if gpu.temp_edge_c.is_none() && value.is_some() => {
                    // No label — use first available as package temp
                    gpu.temp_edge_c = value;
                }
                _ => {}
            }
        }

        // Fan
        gpu.fan_rpm = read_u32_from_hwmon_path(hwmon_path, "fan1_input").unwrap_or(0);
        gpu.fan_max_rpm = read_u32_from_hwmon_path(hwmon_path, "fan1_max")
            .unwrap_or(gpu.fan_max_rpm);

        // Power — xe driver exposes energy counters (microjoules), not instantaneous
        // power. Compute average watts from the delta since last refresh.
        // Look for the "card" labeled energy counter first, fall back to any.
        let energy_uj = find_labeled_energy(hwmon_path, "card")
            .or_else(|| read_u64_from_hwmon_path(hwmon_path, "energy1_input"));
        if let (Some(uj_now), Some(snap)) = (energy_uj, energy_snap) {
            if let Some(prev_ts) = snap.timestamp {
                let dt = prev_ts.elapsed().as_secs_f64();
                if dt > 0.1 && uj_now >= snap.energy_uj {
                    let delta_uj = uj_now - snap.energy_uj;
                    gpu.power_watts = delta_uj as f64 / (dt * 1_000_000.0);
                }
            }
            snap.energy_uj = uj_now;
            snap.timestamp = Some(std::time::Instant::now());
        }

        gpu.power_cap_watts = read_u64_from_hwmon_path(hwmon_path, "power1_cap")
            .map(|v| v as f64 / 1_000_000.0)
            .unwrap_or(gpu.power_cap_watts);

        // Voltage
        gpu.voltage_mv = read_u32_from_hwmon_path(hwmon_path, "in0_input").unwrap_or(0);
    }

    // VRAM total — ensure it's set even if detection missed it.
    // The xe driver may expose tile0/physical_vram_size_bytes on some cards;
    // fall back to BAR2 size from PCI resource file.
    if gpu.vram_total_bytes == 0 {
        gpu.vram_total_bytes = detect_intel_vram(base);
    }

    // PCIe (may change with power state)
    if let Some(speed) = read_trimmed(&format!("{}/current_link_speed", base)) {
        gpu.pcie_speed = speed;
    }
    gpu.pcie_width =
        read_u32(&format!("{}/current_link_width", base)).unwrap_or(gpu.pcie_width);
}

/// Find an energy counter by label (e.g. "card", "pkg").
/// Scans energy{1..4}_label / energy{1..4}_input.
fn find_labeled_energy(hwmon_path: &Path, target_label: &str) -> Option<u64> {
    for i in 1..=4 {
        if let Some(label) = read_hwmon_str(hwmon_path, &format!("energy{}_label", i)) {
            if label == target_label {
                return read_u64_from_hwmon_path(hwmon_path, &format!("energy{}_input", i));
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

pub(crate) fn read_trimmed(path: &str) -> Option<String> {
    fs::read_to_string(path).ok().map(|s| s.trim().to_string())
}

fn read_u32(path: &str) -> Option<u32> {
    read_trimmed(path).and_then(|s| s.parse().ok())
}

fn read_u64(path: &str) -> Option<u64> {
    read_trimmed(path).and_then(|s| s.parse().ok())
}

pub(crate) fn find_hwmon(device_base: &str) -> Option<PathBuf> {
    let hwmon_dir = format!("{}/hwmon", device_base);
    let entries = fs::read_dir(&hwmon_dir).ok()?;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            return Some(path);
        }
    }
    None
}

fn read_u32_from_hwmon(hwmon: &Option<PathBuf>, file: &str) -> Option<u32> {
    let path = hwmon.as_ref()?.join(file);
    fs::read_to_string(&path)
        .ok()
        .and_then(|s| s.trim().parse().ok())
}

fn read_u64_from_hwmon(hwmon: &Option<PathBuf>, file: &str) -> Option<u64> {
    let path = hwmon.as_ref()?.join(file);
    fs::read_to_string(&path)
        .ok()
        .and_then(|s| s.trim().parse().ok())
}

fn read_hwmon_str(hwmon_path: &Path, file: &str) -> Option<String> {
    let path = hwmon_path.join(file);
    fs::read_to_string(&path)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn read_u32_from_hwmon_path(hwmon_path: &Path, file: &str) -> Option<u32> {
    let path = hwmon_path.join(file);
    fs::read_to_string(&path)
        .ok()
        .and_then(|s| s.trim().parse().ok())
}

fn read_u64_from_hwmon_path(hwmon_path: &Path, file: &str) -> Option<u64> {
    let path = hwmon_path.join(file);
    fs::read_to_string(&path)
        .ok()
        .and_then(|s| s.trim().parse().ok())
}

/// Shorten a CPU model name for compact display.
fn shorten_cpu_name(name: &str) -> String {
    name.replace("AMD Ryzen Threadripper ", "TR ")
        .replace("AMD Ryzen 9 ", "R9 ")
        .replace("AMD Ryzen 7 ", "R7 ")
        .replace("AMD Ryzen 5 ", "R5 ")
        .replace("AMD EPYC ", "EPYC ")
        .replace("Intel(R) Core(TM) ", "")
        .replace("Intel(R) Xeon(R) ", "Xeon ")
        .replace(" Processor", "")
        .replace("-Core", " Core")
}

/// Format bytes into a compact human string: "1.2G", "512M", "3.4T"
pub fn fmt_bytes(bytes: u64) -> String {
    const TIB: f64 = 1024.0 * 1024.0 * 1024.0 * 1024.0;
    const GIB: f64 = 1024.0 * 1024.0 * 1024.0;
    const MIB: f64 = 1024.0 * 1024.0;
    let b = bytes as f64;
    if b >= TIB {
        format!("{:.1}T", b / TIB)
    } else if b >= GIB {
        format!("{:.1}G", b / GIB)
    } else if b >= MIB {
        format!("{:.0}M", b / MIB)
    } else {
        format!("{}B", bytes)
    }
}

/// Parse PCIe speed string like "32.0 GT/s PCIe" into a Gen label.
pub fn pcie_gen_label(speed: &str) -> &str {
    if speed.contains("32.0") || speed.contains("32 GT") {
        "Gen5"
    } else if speed.contains("16.0") || speed.contains("16 GT") {
        "Gen4"
    } else if speed.contains("8.0") || speed.contains("8 GT") {
        "Gen3"
    } else if speed.contains("5.0") || speed.contains("5 GT") {
        "Gen2"
    } else if speed.contains("2.5") {
        "Gen1"
    } else {
        speed.split_whitespace().next().unwrap_or("?")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_probe_detects_hardware() {
        let info = probe_static();
        // Should always detect CPU
        assert!(info.cpu.threads > 0, "should detect CPU threads");
        assert!(!info.cpu.model.is_empty(), "should detect CPU model");
        eprintln!("CPU: {} {}C/{}T", info.cpu.model, info.cpu.cores, info.cpu.threads);
        for gpu in &info.gpus {
            eprintln!(
                "GPU{}: {} | VRAM {}  | PCIe {} x{} | VBIOS {}",
                gpu.index,
                gpu.name,
                fmt_bytes(gpu.vram_total_bytes),
                pcie_gen_label(&gpu.pcie_speed),
                gpu.pcie_width,
                gpu.vbios,
            );
        }
    }

    #[test]
    fn test_fmt_bytes() {
        assert_eq!(fmt_bytes(0), "0B");
        assert_eq!(fmt_bytes(1024 * 1024), "1M");
        assert_eq!(fmt_bytes(17_095_983_104), "15.9G");
    }

    #[test]
    fn test_pcie_gen_label() {
        assert_eq!(pcie_gen_label("32.0 GT/s PCIe"), "Gen5");
        assert_eq!(pcie_gen_label("16.0 GT/s PCIe"), "Gen4");
        assert_eq!(pcie_gen_label("8.0 GT/s PCIe"), "Gen3");
    }

    #[test]
    fn test_shorten_cpu_name() {
        assert_eq!(
            shorten_cpu_name("AMD Ryzen Threadripper 3970X 32-Core Processor"),
            "TR 3970X 32 Core"
        );
        assert_eq!(
            shorten_cpu_name("AMD Ryzen 9 7950X 16-Core Processor"),
            "R9 7950X 16 Core"
        );
    }
}

impl GpuInfo {
    /// The benchmark `device_id` belonging to THIS physical card, or `None` when
    /// no benchmark row matches it.
    ///
    /// Resolution order:
    ///  1. `pci_bus_id` — the real identity, written by current prover builds.
    ///  2. GPU model name embedded in `device_label` — migrates caches written
    ///     before the bus id existed, and only when the match is unambiguous.
    ///
    /// `None` means "no data for this card", and callers MUST render that as
    /// blank rather than falling back to a positional guess. The bug this
    /// replaces was exactly such a guess: joining on `format!("gpu{}", index)`
    /// against rows keyed in the prover's per-vendor index space, so on a box
    /// with a non-proving AMD card first in DRM order the AMD row displayed the
    /// RTX 5090's throughput, the 5090 displayed the 4090's, and the 4090 --
    /// which had no row at that index -- displayed nothing.
    pub fn benchmark_device_id(
        &self,
        suite: &zkminer_prover::benchmark::BenchmarkSuite,
    ) -> Option<String> {
        let rows = &suite.device_benchmarks;

        // 1. Exact PCI bus id.
        if !self.pci_bus_id.is_empty() {
            if let Some(d) = rows
                .iter()
                .find(|d| !d.pci_bus_id.is_empty() && d.pci_bus_id == self.pci_bus_id)
            {
                return Some(d.device_id.clone());
            }
        }

        // 2. Legacy caches carry no bus id. Fall back to the model name in the
        //    label, but ONLY when exactly one legacy row matches: on a 2x4090 box
        //    the name is ambiguous, and guessing there is how the original bug
        //    silently showed one card's numbers against another.
        let want = normalize_gpu_name(&self.name);
        if want.is_empty() {
            return None;
        }
        let mut hits = rows
            .iter()
            .filter(|d| {
                d.pci_bus_id.is_empty()
                    && d.device_id.starts_with("gpu")
                    && normalize_gpu_name(&d.device_label).contains(&want)
            })
            .map(|d| d.device_id.clone())
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter();
        match (hits.next(), hits.next()) {
            (Some(id), None) => Some(id),
            _ => None,
        }
    }
}

/// Lowercase a GPU name and drop vendor prefixes and punctuation so the two
/// crates' spellings compare equal.
///
/// The TUI strips a leading `"NVIDIA "` during detection and the prover does
/// not, so `"GeForce RTX 5090"` and `"NVIDIA GeForce RTX 5090"` denote one card
/// and must match.
fn normalize_gpu_name(s: &str) -> String {
    s.to_lowercase()
        .replace("nvidia", " ")
        .replace("geforce", " ")
        .replace("advanced micro devices", " ")
        .replace("amd", " ")
        .replace("intel", " ")
        .replace(['(', ')', ',', '-', '_'], " ")
        .split_whitespace()
        .filter(|w| !w.chars().all(|c| c.is_ascii_digit()) || w.len() >= 3)
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod gpu_identity_tests {
    use super::*;
    use zkminer_prover::benchmark::{BenchmarkSuite, DeviceBenchmark};

    fn gpu(index: u32, name: &str, vendor: GpuVendor, bus: &str) -> GpuInfo {
        GpuInfo {
            index,
            name: name.to_string(),
            vendor,
            pci_id: String::new(),
            pci_bus_id: bus.to_string(),
            gpu_clock_mhz: 0,
            mem_clock_mhz: 0,
            gpu_usage_percent: 0,
            mem_usage_percent: 0,
            vram_used_bytes: 0,
            vram_total_bytes: 0,
            temp_edge_c: None,
            temp_junction_c: None,
            temp_mem_c: None,
            fan_rpm: 0,
            fan_max_rpm: 0,
            power_watts: 0.0,
            power_cap_watts: 0.0,
            voltage_mv: 0,
            pcie_speed: String::new(),
            pcie_width: 0,
            vbios: String::new(),
        }
    }

    fn row(device_id: &str, label: &str, bus: &str, tp: f64) -> DeviceBenchmark {
        DeviceBenchmark {
            device_id: device_id.to_string(),
            device_label: label.to_string(),
            prover_backend: "risc0".to_string(),
            throughput: tp,
            power_watts: 0.0,
            optimal_po2: 20,
            memory_usage_bytes: 0,
            max_feasible_po2: 20,
            program_throughputs: Default::default(),
            po2_samples: Vec::new(),
            pci_bus_id: bus.to_string(),
        }
    }

    fn suite(rows: Vec<DeviceBenchmark>) -> BenchmarkSuite {
        let mut s = BenchmarkSuite::default();
        s.device_benchmarks = rows;
        s
    }

    /// The exact reported bug: a non-proving AMD card first in DRM order shifted
    /// every NVIDIA card's benchmark row by one.
    #[test]
    fn non_proving_card_does_not_steal_a_neighbours_row() {
        let amd = gpu(0, "Radeon RX 7900 XTX", GpuVendor::Amd, "0000:06:10.0");
        let n5090 = gpu(1, "GeForce RTX 5090", GpuVendor::Nvidia, "0000:06:1b.0");
        let n4090 = gpu(2, "GeForce RTX 4090", GpuVendor::Nvidia, "0000:08:0d.0");

        // Benchmark rows exist ONLY for the two NVIDIA cards, keyed in the
        // prover's own index space -- exactly what this box has on disk.
        let s = suite(vec![
            row("gpu0", "GPU0 NVIDIA GeForce RTX 5090", "0000:06:1b.0", 2_287_871.9),
            row("gpu1", "GPU1 NVIDIA GeForce RTX 4090", "0000:08:0d.0", 1_504_981.0),
        ]);

        // The AMD card has no row and must resolve to nothing -- NOT to "gpu0",
        // which is the 5090's row and is what it used to display.
        assert_eq!(amd.benchmark_device_id(&s), None);
        assert_eq!(n5090.benchmark_device_id(&s).as_deref(), Some("gpu0"));
        assert_eq!(n4090.benchmark_device_id(&s).as_deref(), Some("gpu1"));
    }

    /// A legacy cache (written before pci_bus_id existed) still resolves, so the
    /// migration does not cost measured po2 calibration.
    #[test]
    fn legacy_rows_without_bus_id_match_on_name() {
        let n5090 = gpu(1, "GeForce RTX 5090", GpuVendor::Nvidia, "0000:06:1b.0");
        let s = suite(vec![
            row("gpu0", "GPU0 NVIDIA GeForce RTX 5090", "", 2_287_871.9),
            row("gpu1", "GPU1 NVIDIA GeForce RTX 4090", "", 1_504_981.0),
        ]);
        // "GeForce RTX 5090" vs "NVIDIA GeForce RTX 5090" must compare equal.
        assert_eq!(n5090.benchmark_device_id(&s).as_deref(), Some("gpu0"));
    }

    /// Two identical cards make a name match ambiguous. Resolve to None and show
    /// nothing rather than guessing -- guessing is the original bug.
    #[test]
    fn ambiguous_legacy_name_resolves_to_nothing() {
        let a = gpu(0, "GeForce RTX 4090", GpuVendor::Nvidia, "0000:01:00.0");
        let s = suite(vec![
            row("gpu0", "GPU0 NVIDIA GeForce RTX 4090", "", 1.0),
            row("gpu1", "GPU1 NVIDIA GeForce RTX 4090", "", 2.0),
        ]);
        assert_eq!(a.benchmark_device_id(&s), None);
    }

    /// Several backends for ONE card is the normal case and must not read as
    /// ambiguous -- otherwise every legacy row stops resolving.
    #[test]
    fn multiple_backends_for_one_card_are_not_ambiguous() {
        let a = gpu(0, "GeForce RTX 4090", GpuVendor::Nvidia, "0000:01:00.0");
        let mut r1 = row("gpu0", "GPU0 NVIDIA GeForce RTX 4090", "", 1.0);
        r1.prover_backend = "risc0".to_string();
        let mut r2 = row("gpu0", "GPU0 NVIDIA GeForce RTX 4090", "", 2.0);
        r2.prover_backend = "sp1".to_string();
        assert_eq!(a.benchmark_device_id(&suite(vec![r1, r2])).as_deref(), Some("gpu0"));
    }

    /// Bus id wins over a name that would match a different row.
    #[test]
    fn bus_id_takes_priority_over_name() {
        let g = gpu(0, "GeForce RTX 4090", GpuVendor::Nvidia, "0000:08:0d.0");
        let s = suite(vec![
            row("gpu0", "GPU0 NVIDIA GeForce RTX 4090", "0000:01:00.0", 1.0),
            row("gpu1", "GPU1 NVIDIA GeForce RTX 4090", "0000:08:0d.0", 2.0),
        ]);
        assert_eq!(g.benchmark_device_id(&s).as_deref(), Some("gpu1"));
    }

    /// Both crates must normalize a PCI address to the same string, or the join
    /// silently matches AMD (4-digit sysfs) and misses NVIDIA (8-digit smi).
    #[test]
    fn pci_normalization_agrees_across_crates() {
        for raw in ["00000000:06:1B.0", "0000:06:1b.0", "0000:06:1B.0"] {
            assert_eq!(
                normalize_pci_bus_id(raw),
                zkminer_prover::discovery::normalize_pci_bus_id(raw),
                "normalization disagreed for {raw}",
            );
            assert_eq!(normalize_pci_bus_id(raw), "0000:06:1b.0");
        }
    }
}
