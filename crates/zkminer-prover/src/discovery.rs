//! Worker binary discovery.
//!
//! Searches for prover worker binaries (`zkminer-prove-{backend}`) in a priority order:
//! 1. Explicit paths from config
//! 2. Configured search directories
//! 3. `~/.zkminer/provers/`
//! 4. Sibling directory of the main binary (finds cargo target dir during development)
//! 5. `$PATH`
//!
//! For each backend, GPU-suffixed variants are searched first:
//!   `zkminer-prove-{backend}-cuda`  → gpu_tag = "cuda"
//!   `zkminer-prove-{backend}-rocm`  → gpu_tag = "rocm"
//!   `zkminer-prove-{backend}`       → gpu_tag = "generic"
//!
//! GPU binaries are auto-expanded: one worker entry per detected physical GPU of that vendor.
//! For example, a `-cuda` binary with 2 NVIDIA GPUs produces two `DiscoveredWorker` entries.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use zkminer_prover_protocol::{BACKEND_OPENVM, BACKEND_RISC0, BACKEND_SP1};

/// All known backend names.
const ALL_BACKENDS: &[&str] = &[BACKEND_RISC0, BACKEND_SP1, BACKEND_OPENVM];

/// GPU variant suffixes to search, in order. "generic" means no suffix.
const GPU_TAGS: &[&str] = &["cuda", "rocm", "intel", "generic"];

/// A detected physical GPU.
#[derive(Debug, Clone)]
pub struct DetectedGpu {
    /// "cuda" or "rocm"
    pub gpu_tag: String,
    /// Sequential index within vendor (0, 1, ...)
    pub device_index: u32,
    /// PCI bus ID, e.g. "0000:01:00.0" — used for *_VISIBLE_DEVICES
    pub pci_bus_id: String,
    /// Human-readable GPU name
    pub name: String,
    /// CUDA compute capability as `(major, minor)`, e.g. `(12, 0)` for Blackwell, or `None` if it
    /// could not be read. Needed because some backends are broken on specific architectures in a way
    /// VRAM and model name cannot express — see `backend_broken_on_compute_cap`.
    pub compute_cap: Option<(u32, u32)>,
}

/// A discovered worker binary.
#[derive(Debug, Clone)]
pub struct DiscoveredWorker {
    pub backend: String,
    /// GPU variant: "cuda", "rocm", or "generic".
    pub gpu_tag: String,
    /// Device index within vendor (None for "generic" or explicit binaries).
    pub device_index: Option<u32>,
    /// PCI bus ID for GPU pinning (None for "generic" or explicit binaries).
    pub pci_bus_id: Option<String>,
    /// Human-readable GPU name (None for "generic" or explicit binaries).
    pub gpu_name: Option<String>,
    /// CUDA compute capability of the card, when known. Carried so the dispatcher can refuse a
    /// backend that is known to fault on this architecture — see `backend_broken_on_compute_cap` —
    /// or whose binary carries no GPU code this card can run — see `gpu_code_binary`.
    pub compute_cap: Option<(u32, u32)>,
    pub path: PathBuf,
}

/// Binary name for a given backend and GPU tag.
fn worker_binary_name(backend: &str, gpu_tag: &str) -> String {
    if gpu_tag == "generic" {
        format!("zkminer-prove-{backend}")
    } else {
        format!("zkminer-prove-{backend}-{gpu_tag}")
    }
}

/// Detect all physical GPUs (NVIDIA + AMD + Intel).
pub fn detect_all_gpus() -> Vec<DetectedGpu> {
    let mut gpus = Vec::new();

    let nvidia = detect_nvidia_gpus();
    if !nvidia.is_empty() {
        let names: Vec<_> = nvidia
            .iter()
            .map(|g| format!("[{}] {} ({})", g.device_index, g.name, g.pci_bus_id))
            .collect();
        tracing::info!(
            "Detected {} NVIDIA GPU(s): {}",
            nvidia.len(),
            names.join(", ")
        );
        gpus.extend(nvidia);
    }

    let amd = detect_amd_gpus();
    if !amd.is_empty() {
        let names: Vec<_> = amd
            .iter()
            .map(|g| format!("[{}] {} ({})", g.device_index, g.name, g.pci_bus_id))
            .collect();
        tracing::info!("Detected {} AMD GPU(s): {}", amd.len(), names.join(", "));
        gpus.extend(amd);
    }

    let intel = detect_intel_gpus();
    if !intel.is_empty() {
        let names: Vec<_> = intel
            .iter()
            .map(|g| format!("[{}] {} ({})", g.device_index, g.name, g.pci_bus_id))
            .collect();
        tracing::info!(
            "Detected {} Intel GPU(s): {}",
            intel.len(),
            names.join(", ")
        );
        gpus.extend(intel);
    }

    gpus
}

/// Detect NVIDIA GPUs via nvidia-smi, falling back to /proc/driver/nvidia/gpus/.
fn detect_nvidia_gpus() -> Vec<DetectedGpu> {
    // Primary: nvidia-smi
    if let Some(gpus) = detect_nvidia_via_smi() {
        return gpus;
    }
    // Fallback: /proc filesystem
    detect_nvidia_via_proc()
}

/// How long a GPU-tool query may take before we treat it as having no answer.
///
/// `nvidia-smi` and `rocm-smi` block in the driver — often in uninterruptible sleep — after an
/// Xid, a bus fall-off or an ECC remap, and `Command::output()` waits forever. Discovery runs at
/// startup, so an unbounded fork here hangs the miner before it has done anything, on exactly the
/// sick host the probes exist to characterise. (The benchmark-cache fingerprint has its own
/// budget, `NVIDIA_SMI_FINGERPRINT_TIMEOUT`, because a missing answer there costs a re-benchmark
/// rather than a delayed start.)
const GPU_TOOL_TIMEOUT: Duration = Duration::from_secs(5);

/// `detect_nvidia_via_smi`, for the live power check's skip gate.
///
/// The gate must distinguish "nvidia-smi reports cards" from "a GPU exists somehow", because the
/// /proc fallback answers the second and the test is about the first.
#[cfg(test)]
pub(crate) fn detect_nvidia_via_smi_for_test() -> Option<Vec<DetectedGpu>> {
    detect_nvidia_via_smi()
}

/// Parse nvidia-smi CSV output.
fn detect_nvidia_via_smi() -> Option<Vec<DetectedGpu>> {
    let (outcome, stdout) = zkminer_prover_protocol::proc::output_with_timeout_capturing_stdout(
        std::process::Command::new("nvidia-smi").args([
            "--query-gpu=index,name,pci.bus_id,compute_cap",
            "--format=csv,noheader,nounits",
        ]),
        GPU_TOOL_TIMEOUT,
        256 * 1024,
    );
    if !matches!(
        outcome,
        zkminer_prover_protocol::proc::Outcome::Ran { success: true, .. }
    ) {
        // The caller falls back to /proc, which is the whole reason that fallback exists: a
        // missing answer is not evidence that there is no GPU.
        tracing::warn!("nvidia-smi did not answer ({})", outcome.describe());
        return None;
    }
    let mut gpus = Vec::new();
    let mut saw_nonempty_line = false;

    for line in stdout.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        saw_nonempty_line = true;
        let parts: Vec<&str> = line.splitn(4, ',').map(|s| s.trim()).collect();
        if parts.len() < 3 {
            continue;
        }
        // `compute_cap` is appended last and is optional: an older nvidia-smi omits the column, and a
        // missing capability must not stop us detecting the card.
        let compute_cap = parts.get(3).and_then(|cc| {
            let (maj, min) = cc.split_once('.')?;
            Some((maj.trim().parse().ok()?, min.trim().parse().ok()?))
        });
        let index: u32 = match parts[0].parse() {
            Ok(i) => i,
            Err(_) => continue,
        };
        let name = parts[1].to_string();
        // Optional operator override to restrict which physical GPUs are used — e.g.
        // to isolate a single card for testing, or to exclude one in a bad driver
        // state. Case-insensitive substring match on the GPU name; unset = all GPUs.
        if let Ok(filter) = std::env::var("ZKMINER_GPU_NAME_FILTER") {
            if !filter.is_empty() && !name.to_lowercase().contains(&filter.to_lowercase()) {
                continue;
            }
        }
        // nvidia-smi outputs an 8-digit domain ("00000000:01:00.0"); sysfs uses 4.
        // Normalize so both sides of the cross-crate join produce the same string.
        let pci_bus_id = normalize_pci_bus_id(parts[2]);

        gpus.push(DetectedGpu {
            gpu_tag: "cuda".to_string(),
            device_index: index,
            pci_bus_id,
            name,
            compute_cap,
        });
    }

    warn_if_index_order_is_not_pci_order(&gpus);

    // If nvidia-smi ran but we couldn't parse a single GPU out of non-empty output
    // (e.g. a future column change or all-error lines), do NOT report "0 GPUs" —
    // that would silently skip the CUDA worker. Fall through to the /proc fallback.
    if gpus.is_empty() && saw_nonempty_line {
        tracing::warn!(
            "nvidia-smi produced output but no GPUs were parsed; falling back to /proc detection"
        );
        return None;
    }

    Some(gpus)
}

/// Enumerate /proc/driver/nvidia/gpus/*/information as fallback.
fn detect_nvidia_via_proc() -> Vec<DetectedGpu> {
    let base = Path::new("/proc/driver/nvidia/gpus");
    if !base.is_dir() {
        return Vec::new();
    }

    let mut gpus = Vec::new();
    let mut entries: Vec<_> = match std::fs::read_dir(base) {
        Ok(rd) => rd.filter_map(|e| e.ok()).collect(),
        Err(_) => return Vec::new(),
    };
    entries.sort_by_key(|e| e.file_name());

    for (idx, entry) in entries.iter().enumerate() {
        let info_path = entry.path().join("information");
        let content = match std::fs::read_to_string(&info_path) {
            Ok(c) => c,
            Err(_) => continue,
        };

        let mut model = String::new();
        let mut bus_location = String::new();

        for line in content.lines() {
            if let Some(val) = line.strip_prefix("Model:") {
                model = val.trim().to_string();
            } else if let Some(val) = line.strip_prefix("Bus Location:") {
                bus_location = val.trim().to_string();
            }
        }

        if bus_location.is_empty() {
            // Use directory name as PCI bus ID
            bus_location = entry.file_name().to_string_lossy().to_string();
        }

        gpus.push(DetectedGpu {
            gpu_tag: "cuda".to_string(),
            device_index: idx as u32,
            pci_bus_id: normalize_pci_bus_id(&bus_location),
            name: if model.is_empty() {
                "NVIDIA GPU".to_string()
            } else {
                model
            },
            // Not exposed by `/proc/driver/nvidia`. `None` means "cannot tell", and
            // `backend_broken_on_compute_cap` answers false for it — a card we cannot identify is not
            // assumed broken, and the worker declines on first use if it is.
            compute_cap: None,
        });
    }

    gpus
}

/// Detect Intel discrete GPUs via /sys/class/drm/card*/device/.
/// Filters out integrated GPUs by requiring local memory (tile0 or BAR2).
fn detect_intel_gpus() -> Vec<DetectedGpu> {
    let drm_base = Path::new("/sys/class/drm");
    if !drm_base.is_dir() {
        return Vec::new();
    }

    let mut entries: Vec<_> = match std::fs::read_dir(drm_base) {
        Ok(rd) => rd.filter_map(|e| e.ok()).collect(),
        Err(_) => return Vec::new(),
    };
    // Numeric cardN order (card10 must sort after card2, not before it).
    entries.sort_by_key(|e| card_number(&e.file_name().to_string_lossy()));

    let mut gpus = Vec::new();
    let mut device_index: u32 = 0;

    for entry in entries {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();

        // Only look at cardN entries (not card0-DP-1, renderD128, etc.)
        if !name_str.starts_with("card") || name_str.contains('-') {
            continue;
        }

        let device_dir = entry.path().join("device");

        // Check vendor is Intel (0x8086)
        let vendor_path = device_dir.join("vendor");
        let vendor = match std::fs::read_to_string(&vendor_path) {
            Ok(v) => v.trim().to_lowercase(),
            Err(_) => continue,
        };
        if vendor != "0x8086" {
            continue;
        }

        // Must be a discrete GPU: require local memory via tile0 or BAR2
        let has_tile0 = device_dir.join("tile0").is_dir();
        let has_lmem = device_dir.join("tile0/physical_vram_size_bytes").exists();
        if !has_tile0 && !has_lmem {
            // Check BAR2 in PCI resource file as fallback
            let has_bar2 = std::fs::read_to_string(device_dir.join("resource"))
                .ok()
                .and_then(|r| {
                    r.lines().nth(2).and_then(|line| {
                        let parts: Vec<&str> = line.split_whitespace().collect();
                        if parts.len() >= 2 {
                            let start = u64::from_str_radix(parts[0].trim_start_matches("0x"), 16)
                                .unwrap_or(0);
                            let end = u64::from_str_radix(parts[1].trim_start_matches("0x"), 16)
                                .unwrap_or(0);
                            if end > start {
                                Some(true)
                            } else {
                                None
                            }
                        } else {
                            None
                        }
                    })
                })
                .unwrap_or(false);
            if !has_bar2 {
                continue;
            }
        }

        // Read PCI bus ID from uevent
        let pci_bus_id = normalize_pci_bus_id(
            &read_pci_slot_from_uevent(&device_dir.join("uevent")).unwrap_or_default(),
        );
        if pci_bus_id.is_empty() {
            continue;
        }

        // Read device name
        let gpu_name = read_intel_gpu_name(&device_dir);

        gpus.push(DetectedGpu {
            gpu_tag: "intel".to_string(),
            device_index,
            pci_bus_id,
            name: gpu_name,
            // Not a CUDA device; CUDA compute capability does not apply.
            compute_cap: None,
        });
        device_index += 1;
    }

    gpus
}

/// Read Intel GPU name from sysfs, with fallbacks.
fn read_intel_gpu_name(device_dir: &Path) -> String {
    // Try product_name (available on some cards via xe driver)
    if let Ok(name) = std::fs::read_to_string(device_dir.join("product_name")) {
        let name = name.trim().to_string();
        if !name.is_empty() {
            return name;
        }
    }
    // Try label file (xe driver)
    if let Ok(name) = std::fs::read_to_string(device_dir.join("label")) {
        let name = name.trim().to_string();
        if !name.is_empty() {
            return name;
        }
    }
    // Fallback: PCI device ID → known name table
    if let Ok(device_id) = std::fs::read_to_string(device_dir.join("device")) {
        let device_id = device_id.trim().to_lowercase();
        if !device_id.is_empty() {
            return intel_gpu_name_from_id(&device_id);
        }
    }
    "Intel GPU".to_string()
}

/// Known Intel PCI device IDs → marketing names.
fn intel_gpu_name_from_id(device_id: &str) -> String {
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
        _ => format!("Intel GPU ({})", device_id),
    }
}

/// Detect AMD GPUs via /sys/class/drm/card*/device/.
fn detect_amd_gpus() -> Vec<DetectedGpu> {
    let drm_base = Path::new("/sys/class/drm");
    if !drm_base.is_dir() {
        return Vec::new();
    }

    // Query rocm-smi for proper product names AND the authoritative HIP device index.
    let rocm_info = query_rocm_smi_info();

    let mut entries: Vec<_> = match std::fs::read_dir(drm_base) {
        Ok(rd) => rd.filter_map(|e| e.ok()).collect(),
        Err(_) => return Vec::new(),
    };
    // Sort by the numeric cardN suffix, not lexically (else card10 < card2).
    entries.sort_by_key(|e| card_number(&e.file_name().to_string_lossy()));

    let mut gpus = Vec::new();
    // Fallback index counter, used only when rocm-smi can't provide a HIP index.
    let mut fallback_index: u32 = 0;

    for entry in entries {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();

        // Only look at cardN entries (not card0-DP-1 render nodes etc.)
        if !name_str.starts_with("card") || name_str.contains('-') {
            continue;
        }

        let device_dir = entry.path().join("device");

        // Check vendor is AMD (0x1002)
        let vendor_path = device_dir.join("vendor");
        let vendor = match std::fs::read_to_string(&vendor_path) {
            Ok(v) => v.trim().to_lowercase(),
            Err(_) => continue,
        };
        if vendor != "0x1002" {
            continue;
        }

        // Must have amdgpu driver (gpu_busy_percent exists)
        if !device_dir.join("gpu_busy_percent").exists() {
            continue;
        }

        // Filter out APU iGPUs: must have VRAM > 0
        let vram_path = device_dir.join("mem_info_vram_total");
        if let Ok(vram_str) = std::fs::read_to_string(&vram_path) {
            if let Ok(vram) = vram_str.trim().parse::<u64>() {
                if vram == 0 {
                    continue;
                }
            }
        } else {
            // No VRAM info — likely iGPU, skip
            continue;
        }

        // Read PCI bus ID from uevent
        let pci_bus_id = normalize_pci_bus_id(
            &read_pci_slot_from_uevent(&device_dir.join("uevent")).unwrap_or_default(),
        );
        if pci_bus_id.is_empty() {
            continue;
        }

        // Prefer rocm-smi name, fall back to sysfs
        let gpu_name = rocm_info
            .name_by_bus
            .get(&pci_bus_id)
            .cloned()
            .unwrap_or_else(|| read_amd_gpu_name(&device_dir));

        // HIP_VISIBLE_DEVICES must use the ROCm/HIP device index, which is what
        // rocm-smi's GPU[N] reports. The DRM cardN walk order need not match it
        // (an skipped iGPU or non-PCI ordering would shift the index and mis-pin
        // the worker onto the wrong AMD GPU — the same failure class as the CUDA
        // PCI-bus-id bug). Fall back to a positional counter only if rocm-smi
        // didn't give us an index for this bus.
        let device_index = rocm_info
            .index_by_bus
            .get(&pci_bus_id)
            .copied()
            .unwrap_or_else(|| {
                let i = fallback_index;
                fallback_index += 1;
                i
            });

        gpus.push(DetectedGpu {
            gpu_tag: "rocm".to_string(),
            device_index,
            pci_bus_id,
            name: gpu_name,
            // Not a CUDA device; CUDA compute capability does not apply.
            compute_cap: None,
        });
    }

    gpus
}

/// Parse the numeric suffix of a DRM node name like "card10" -> 10.
/// Non-cardN names sort last (u32::MAX) so they don't disturb ordering.
fn card_number(name: &str) -> u32 {
    name.strip_prefix("card")
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(u32::MAX)
}

/// Normalize a PCI bus id to the canonical lowercase 4-digit-domain form,
/// e.g. `0000:06:1b.0`.
///
/// This MUST agree byte-for-byte with `zkminer_tui::hardware::normalize_pci_bus_id`,
/// because the two are joined as strings across the crate boundary: the TUI matches
/// benchmark rows and worker slots to physical cards on this value.
///
/// The formats genuinely differ by source. `nvidia-smi` emits an 8-digit domain
/// (`00000000:06:1B.0`) while sysfs `uevent` emits 4 (`0000:06:10.0`). Lowercasing
/// alone -- which is all this did before -- leaves the two incomparable, so a
/// bus-id join would match every AMD card and silently miss every NVIDIA one.
pub fn normalize_pci_bus_id(id: &str) -> String {
    let id = id.trim().to_lowercase();
    let Some(first_colon) = id.find(':') else {
        return id;
    };
    let (domain, rest) = id.split_at(first_colon);
    // Trim an over-long domain to its last 4 hex digits ("00000000" -> "0000").
    if domain.len() > 4 {
        format!("{}{}", &domain[domain.len() - 4..], rest)
    } else {
        id
    }
}

/// Parse PCI_SLOT_NAME from a uevent file.
pub(crate) fn read_pci_slot_from_uevent(path: &Path) -> Option<String> {
    let content = std::fs::read_to_string(path).ok()?;
    for line in content.lines() {
        if let Some(val) = line.strip_prefix("PCI_SLOT_NAME=") {
            return Some(val.trim().to_string());
        }
    }
    None
}

/// Read AMD GPU name from sysfs, with fallbacks.
fn read_amd_gpu_name(device_dir: &Path) -> String {
    // Try product_name first (available on some cards)
    if let Ok(name) = std::fs::read_to_string(device_dir.join("product_name")) {
        let name = name.trim().to_string();
        if !name.is_empty() {
            return name;
        }
    }
    // Fallback: device ID
    if let Ok(device_id) = std::fs::read_to_string(device_dir.join("device")) {
        let device_id = device_id.trim().to_string();
        if !device_id.is_empty() {
            return format!("AMD GPU ({})", device_id);
        }
    }
    "AMD GPU".to_string()
}

/// rocm-smi enumeration info, keyed by lowercase PCI bus id.
#[derive(Default)]
struct RocmSmiInfo {
    /// PCI bus id -> Card Series name.
    name_by_bus: HashMap<String, String>,
    /// PCI bus id -> rocm-smi `GPU[N]` index. This index IS the ROCm/HIP device
    /// index, so it's the correct value for HIP_VISIBLE_DEVICES — unlike the DRM
    /// `cardN` walk order, which need not match HIP enumeration.
    index_by_bus: HashMap<String, u32>,
}

/// Query rocm-smi for GPU names and the authoritative HIP device index per PCI bus.
fn query_rocm_smi_info() -> RocmSmiInfo {
    let mut info = RocmSmiInfo::default();
    let (outcome, text) = zkminer_prover_protocol::proc::output_with_timeout_capturing_stdout(
        std::process::Command::new("rocm-smi").args(["--showproductname", "--showbus"]),
        GPU_TOOL_TIMEOUT,
        256 * 1024,
    );
    if !matches!(
        outcome,
        zkminer_prover_protocol::proc::Outcome::Ran { success: true, .. }
    ) {
        tracing::warn!("rocm-smi did not answer ({})", outcome.describe());
        return info;
    }

    // Parse GPU indices to PCI bus IDs and card series names
    let mut bus_ids: HashMap<String, String> = HashMap::new();
    let mut series: HashMap<String, String> = HashMap::new();

    for line in text.lines() {
        let line = line.trim();
        // "GPU[0]		: PCI Bus: 0000:00:10.0"
        if line.contains("PCI Bus:") {
            if let (Some(idx), Some(bus)) = (
                line.split('[').nth(1).and_then(|s| s.split(']').next()),
                line.split("PCI Bus:").nth(1),
            ) {
                bus_ids.insert(idx.trim().to_string(), bus.trim().to_lowercase());
            }
        }
        // "GPU[0]		: Card Series: 		AMD Radeon RX 9070 XT"
        if line.contains("Card Series:") {
            if let (Some(idx), Some(name)) = (
                line.split('[').nth(1).and_then(|s| s.split(']').next()),
                line.split("Card Series:").nth(1),
            ) {
                let name = name.trim().to_string();
                if !name.is_empty() {
                    series.insert(idx.trim().to_string(), name);
                }
            }
        }
    }

    // Map PCI bus ID -> card series name, and PCI bus ID -> HIP index.
    for (idx, bus_id) in &bus_ids {
        if let Some(name) = series.get(idx) {
            info.name_by_bus.insert(bus_id.clone(), name.clone());
        }
        if let Ok(i) = idx.parse::<u32>() {
            info.index_by_bus.insert(bus_id.clone(), i);
        }
    }
    info
}

/// Search for all available worker binaries.
///
/// `explicit_binaries`: backend -> exact path (highest priority, overrides all)
/// `search_dirs`: additional directories to search
///
/// GPU binaries are auto-expanded into one entry per detected physical GPU.
pub fn discover_workers(
    explicit_binaries: &HashMap<String, PathBuf>,
    search_dirs: &[PathBuf],
) -> Vec<DiscoveredWorker> {
    let gpus = detect_all_gpus();
    let mut found: Vec<DiscoveredWorker> = Vec::new();

    for backend in ALL_BACKENDS {
        // 1. Explicit path from config. Normally NOT auto-expanded, because the user controls GPU
        //    visibility through their own environment.
        //
        //    The exception is a backend that cannot take `CUDA_VISIBLE_DEVICES` at all. For SP1 the
        //    "user controls visibility" premise is simply false: whatever the operator sets, the SDK
        //    overrides it on the `sp1-gpu-server` child. So leaving the explicit path unexpanded did not
        //    hand control to the operator, it silently removed it — `sp1:generic` has no per-card lock,
        //    is absent from `proving_gpu_count`, maps to the CPU device id, and always lands on device
        //    0. Putting `worker_binaries = { sp1 = "..." }` in `config.toml`, the documented way to pin
        //    a binary, reverted every property this module exists to provide, without a warning.
        if let Some(path) = explicit_binaries.get(*backend) {
            if path.is_file() {
                let gpu_tag = infer_gpu_tag(path);
                let cuda_cards: Vec<&DetectedGpu> =
                    if gpu_tag == "generic" && drives_cuda_without_visibility_pin(backend) {
                        gpus.iter().filter(|g| g.gpu_tag == "cuda").collect()
                    } else {
                        Vec::new()
                    };
                if cuda_cards.is_empty() {
                    found.push(DiscoveredWorker {
                        backend: backend.to_string(),
                        gpu_tag,
                        device_index: None,
                        pci_bus_id: None,
                        gpu_name: None,
                        compute_cap: None,
                        path: path.clone(),
                    });
                } else {
                    for gpu in cuda_cards {
                        found.push(DiscoveredWorker {
                            backend: backend.to_string(),
                            gpu_tag: "cuda".to_string(),
                            device_index: Some(gpu.device_index),
                            pci_bus_id: Some(gpu.pci_bus_id.clone()),
                            gpu_name: Some(gpu.name.clone()),
                            compute_cap: gpu.compute_cap,
                            path: path.clone(),
                        });
                    }
                }
                continue;
            } else {
                tracing::warn!(
                    "Configured worker binary for {backend} not found at {}",
                    path.display()
                );
            }
        }

        // Build search directories list: configured -> ~/.zkminer/provers/ -> sibling of exe
        let mut all_dirs: Vec<PathBuf> = search_dirs.to_vec();
        if let Some(home_dir) = dirs::home_dir() {
            all_dirs.push(home_dir.join(".zkminer").join("provers"));
        }
        if let Ok(exe) = std::env::current_exe() {
            if let Some(parent) = exe.parent() {
                all_dirs.push(parent.to_path_buf());
            }
        }

        // Search for each GPU variant
        for gpu_tag in GPU_TAGS {
            let bin_name = worker_binary_name(backend, gpu_tag);

            let bin_path =
                search_in_dirs(&bin_name, &all_dirs).or_else(|| search_in_path(&bin_name));

            let Some(path) = bin_path else {
                continue;
            };

            // A backend that drives CUDA without being able to take the visibility pin is expanded
            // per-card like any CUDA worker, even though its binary name carries no `-cuda` suffix.
            // That is what buys it a per-card lock, a place in the capacity count, and a device it
            // can be routed to. See `drives_cuda_without_visibility_pin`.
            let cuda_tags: Vec<&DetectedGpu> =
                if *gpu_tag == "generic" && drives_cuda_without_visibility_pin(backend) {
                    gpus.iter().filter(|g| g.gpu_tag == "cuda").collect()
                } else {
                    Vec::new()
                };
            if !cuda_tags.is_empty() {
                for gpu in cuda_tags {
                    found.push(DiscoveredWorker {
                        backend: backend.to_string(),
                        // `cuda`, not `generic`: this is the occupancy fact, and every consumer of
                        // `gpu_tag` (`physical_gpu_id`, `gpu_device_id`, `proving_gpu_count`) wants
                        // it. The pin is withheld separately, in `gpu_env`.
                        gpu_tag: "cuda".to_string(),
                        device_index: Some(gpu.device_index),
                        pci_bus_id: Some(gpu.pci_bus_id.clone()),
                        gpu_name: Some(gpu.name.clone()),
                        compute_cap: gpu.compute_cap,
                        path: path.clone(),
                    });
                }
            } else if *gpu_tag == "generic" {
                // Generic binary: single entry, no GPU pinning
                found.push(DiscoveredWorker {
                    backend: backend.to_string(),
                    gpu_tag: gpu_tag.to_string(),
                    device_index: None,
                    pci_bus_id: None,
                    gpu_name: None,
                    compute_cap: None,
                    path,
                });
            } else {
                // GPU binary: expand into one entry per detected GPU of this vendor
                let vendor_gpus: Vec<&DetectedGpu> =
                    gpus.iter().filter(|g| g.gpu_tag == *gpu_tag).collect();

                if vendor_gpus.is_empty() {
                    // Binary exists but no GPUs of this vendor detected — skip silently
                    tracing::debug!(
                        "Found {} but no {} GPUs detected, skipping",
                        bin_name,
                        gpu_tag
                    );
                    continue;
                }

                for gpu in vendor_gpus {
                    found.push(DiscoveredWorker {
                        backend: backend.to_string(),
                        gpu_tag: gpu_tag.to_string(),
                        device_index: Some(gpu.device_index),
                        pci_bus_id: Some(gpu.pci_bus_id.clone()),
                        gpu_name: Some(gpu.name.clone()),
                        compute_cap: gpu.compute_cap,
                        path: path.clone(),
                    });
                }
            }
        }
    }

    found
}

/// Check the one assumption every device pin in this program rests on.
///
/// We take `device_index` from `nvidia-smi`'s own index column and hand it to CUDA under
/// `CUDA_DEVICE_ORDER=PCI_BUS_ID`, which orders devices by PCI bus id. Those two agree only because
/// NVML enumerates in PCI order — true on this box (index 0 = 06:10.0, index 1 = 06:1B.0, and sorting
/// the bus ids gives the same ranking) and true in general, but nowhere guaranteed by us.
///
/// If they ever disagreed, every pin in the program would name the wrong card: a proof would run on a
/// GPU other than the one whose per-card lock it holds, so SP1 and risc0 could double-book one card
/// while each believed it had its own, the VRAM floor would route large jobs to the small card, and
/// the dashboard would attribute work to the wrong row. All of it silent. Since the whole routing
/// guarantee hangs on it, say so loudly rather than assume it.
///
/// Warn-only: refusing to mine over a reordered enumeration would be worse than mining with a
/// warning, and the operator can set `ZKMINER_GPU_NAME_FILTER` to a single card to sidestep it.
/// Does `nvidia-smi`'s index order agree with PCI bus order? See the warner below for why it matters.
fn index_order_matches_pci_order(gpus: &[DetectedGpu]) -> bool {
    let mut by_bus: Vec<&DetectedGpu> = gpus.iter().collect();
    by_bus.sort_by(|a, b| a.pci_bus_id.cmp(&b.pci_bus_id));
    // Compare the indices against their own sorted ORDER, not against 0..n.
    //
    // `ZKMINER_GPU_NAME_FILTER` drops cards while deliberately keeping nvidia-smi's original index, so
    // filtering to the 4090 leaves a single GPU with `device_index == 1`. Against 0..n that reads as a
    // reordered enumeration and emitted an error advising the operator to set the very variable they
    // had just set — which teaches them to ignore the one alarm that means the routing guarantee is
    // void. What actually matters is whether index order and bus order AGREE, which is preserved by
    // filtering.
    by_bus
        .windows(2)
        .all(|w| w[0].device_index < w[1].device_index)
}

fn warn_if_index_order_is_not_pci_order(gpus: &[DetectedGpu]) {
    if index_order_matches_pci_order(gpus) {
        return;
    }
    let mut by_bus: Vec<&DetectedGpu> = gpus.iter().collect();
    by_bus.sort_by(|a, b| a.pci_bus_id.cmp(&b.pci_bus_id));
    for (rank, gpu) in by_bus.iter().enumerate() {
        if gpu.device_index as usize != rank {
            tracing::error!(
                "GPU enumeration does not match PCI bus order: {} reports index {} but is PCI rank \
                 {rank}. Every device pin in this miner assumes the two agree (we pass nvidia-smi's \
                 index to CUDA under CUDA_DEVICE_ORDER=PCI_BUS_ID), so proofs may run on a different \
                 card than the one whose VRAM lock they hold — two backends could double-book one \
                 card, and large jobs could be routed to the smaller one. Consider restricting to a \
                 single card with ZKMINER_GPU_NAME_FILTER until this is understood.",
                gpu.name,
                gpu.device_index,
            );
            return;
        }
    }
}

/// Does this backend drive a CUDA card while being unable to accept `CUDA_VISIBLE_DEVICES`?
///
/// SP1 is the case this exists for, and it is worth spelling out because the obvious fix is wrong.
///
/// `zkminer-prove-sp1` forks `sp1-gpu-server` (a 236 MB CUDA process measured holding 10.3 GB of
/// VRAM) yet carries no `-cuda` suffix, so `infer_gpu_tag` called it `generic`. A generic slot gets a
/// 2-part key, which cost three separate things: `physical_gpu_id` returned `None` so SP1 took no
/// per-card lock and could double-book a card with risc0; `proving_gpu_count` did not count it; and
/// no device could be chosen for it at all, so it silently always used CUDA device 0.
///
/// Re-tagging it `cuda` to earn those things was TRIED and REVERTED — `sp1:cuda:0` and `sp1:cuda:1`
/// both died with "process died (EOF)" in ~7s — and the cause is now understood, having first been
/// misdiagnosed as the visibility pin. It was not the pin. `sp1/crates/cuda/src/server.rs` does
/// `cmd.env("CUDA_VISIBLE_DEVICES", cuda_id.to_string())` on the server child, which OVERRIDES
/// whatever the worker had, and `cuda_id` comes from `CudaProver::new_with_id` — never from the
/// worker's environment. So our pin could not reach the server at all; it was useless, not harmful.
///
/// What actually broke was the SOCKET. Re-tagging produced two SP1 worker PROCESSES, and at the time
/// neither passed a device id, so both called `CudaClient::connect(0)`. The SDK's client cache is
/// process-local (`static CLIENT` in `crates/cuda/src/client.rs`), so the second process could not see
/// the first's server and started its own for device 0 — which unlinks and rebinds
/// `/tmp/sp1-cuda-0.sock`. Both clients then talked to one server on one card, double-booked its VRAM,
/// and died within seconds. On both keys, which is exactly what was observed.
///
/// So the fix is to give each worker a DISTINCT device id: distinct `cuda_id` means a distinct socket
/// and a distinct server, which is what makes two SP1 workers able to coexist. Occupancy — the
/// per-card lock, the capacity count, routing — comes from the per-device slot key, and the id is
/// carried in `types::CUDA_DEVICE_ID_ENV` so the worker can hand it to the SDK's own `with_device_id`
/// and let the SDK set `CUDA_VISIBLE_DEVICES` on its child the way it expects to.
pub fn drives_cuda_without_visibility_pin(backend: &str) -> bool {
    backend == "sp1"
}

/// Is this backend known to FAULT on a card of this compute capability, regardless of its size?
///
/// Currently NOTHING is. Kept because the mechanism earned its place and the next architecture may
/// need it, and because the history is worth not relearning.
///
/// SP1 did fault on `sm_120` (Blackwell): a 16,303 MiB RTX 5080 died within seconds in
/// `CudaRustError: misaligned address`, while a 24,564 MiB sm_89 4090 completed the same proof on the
/// same binary. It was never about VRAM. compute-sanitizer found FOUR distinct out-of-bounds bugs in
/// the fork's CUDA code, every one of them a latent bug on every architecture that only faulted on
/// Blackwell because local-memory layout and allocator slack differ there:
///
/// 1. `challenger.cuh` — `grind`'s thread-local `local_state[WIDTH + 2*RATE]` gave `output_buffer` only
///    RATE = 8 slots while `permute(in[WIDTH], out[WIDTH])` writes WIDTH = 16, overflowing by 8
///    elements on every duplexing.
/// 2. `grinding_challenger.rs` — `found_flag` was a 1-byte `DeviceBuffer<bool>` written with
///    `atomicExch((int*)found_flag, 1)`, a 4-byte atomic three bytes past the allocation.
/// 3. `jagged_sumcheck.cu` — `paddedHadamardFixAndSum` guarded the COMPUTATION with
///    `secondIdx < outputHeight` but stored at `secondIdx` unconditionally, writing one element past
///    both output buffers whenever `outputHeight` is odd.
/// 4. `poseidon2.cuh` — plain `F_t[...]` arrays were `reinterpret_cast` to `__align__(16) FDW_t` and
///    dereferenced as 128-bit vectors, which is only ever correct by luck of stack layout.
///
/// With all four fixed, both cards produce valid 356-byte Groth16 proofs (5080 in 51s, 4090 in 52s)
/// and compute-sanitizer reports no invalid accesses in the proving path at all.
///
/// `ZKMINER_ALLOW_BROKEN_GPU=1` still bypasses this, for reaching a card while debugging it.
pub fn backend_broken_on_compute_cap(backend: &str, cap: Option<(u32, u32)>) -> bool {
    if std::env::var("ZKMINER_ALLOW_BROKEN_GPU").is_ok() {
        return false;
    }
    let _ = (backend, cap);
    false
}

/// The binary holding a backend's CUDA device code, for `gpu_code::EmbeddedGpuCode` to read.
///
/// For most backends that is the worker itself. SP1's worker carries none: its proving runs in
/// `sp1-gpu-server`, so the server is the binary whose GPU code decides which cards SP1 can use.
/// `None` when that cannot be determined, which the caller must treat as "unknown", never as
/// "cannot run".
pub fn gpu_code_binary(backend: &str, worker: &Path) -> Option<PathBuf> {
    if backend != "sp1" {
        return Some(worker.to_path_buf());
    }
    let install = std::env::var(zkminer_prover_protocol::types::SP1_SERVER_INSTALL_ENV)
        .map_or(true, |v| v.trim() != "0");
    sp1_server_for(worker, install, dirs::home_dir().as_deref())
}

/// The `sp1-gpu-server` an SP1 worker at `worker` will run. Mirrors `zkminer-prove-sp1`'s
/// `bundled_server`, which at startup installs the server shipped beside the worker over
/// `~/.sp1/bin/sp1-gpu-server` unless `install` is off — so that shipped server, not the one
/// installed now, is the one the worker will use. Without either, the SDK downloads upstream's
/// build later, whose GPU code nothing here can see in advance.
fn sp1_server_for(worker: &Path, install: bool, home: Option<&Path>) -> Option<PathBuf> {
    const SERVER: &str = "sp1-gpu-server";
    if install {
        // The worker looks beside its own executable, which for a symlinked worker is the target's
        // directory; a wrapper script sits beside the binary it runs, so its own directory works too.
        let real = std::fs::canonicalize(worker).ok();
        let shipped = [real.as_deref().and_then(Path::parent), worker.parent()]
            .into_iter()
            .flatten()
            .map(|dir| dir.join(SERVER))
            .find(|path| path.is_file());
        if shipped.is_some() {
            return shipped;
        }
    }
    let installed = home?.join(".sp1").join("bin").join(SERVER);
    installed.is_file().then_some(installed)
}

/// Minimum VRAM a card must have for a backend to run on it at all, or `None` for no floor.
///
/// SP1 has a HARD one, enforced inside `sp1-gpu-server` before any proving starts, and it is a
/// capability check rather than an out-of-memory risk: the server refuses the device and panics.
///
/// **The figure depends on which server is installed**, which is the whole reason this constant has
/// moved. Measured on this box on 2026-10-05:
///
/// * The server the SDK downloads from `succinctlabs/sp1` releases — UPSTREAM, see
///   `crates/cuda/src/server.rs` — floors at 24 GB. Pinned to the 16,303 MiB RTX 5080 it printed
///   `Unsupported GPU memory: 20, must be at least 24GB` and the worker died on the SDK's own
///   `.expect("Failed to create the CUDA prover impl")` when the socket refused the connection.
/// * The fork this workspace actually pins (`hemilabs/sp1` @ 676290bb) floors at **16 GB** and carries
///   a dedicated 16 GB tier, added in `9c8a21cf4` (2026-03-20). The upstream binary predates it by a
///   month and could never contain it. Built from source and installed, so the floor is now 16 GB.
///
/// The number is 16 decimal GB, matched to the evidence rather than to the server's arithmetic — it
/// computes `ceil(vram / 1 GiB) + 4`, so the 5080 reports 20 and the 4090 reports 28, and neither is
/// a straight conversion. 16e9 separates the cards we have from anything genuinely too small.
///
/// Note the server's own guard has slack: `ceil(11.x) + 4 = 16` is not `< 16`, so a 12 GB card passes
/// it and then lands in the 16 GB tier. Our floor is the stricter of the two, deliberately.
///
/// If the upstream binary is ever restored — which happens silently if ours fails to exec, since an
/// empty `--version` reads as a version mismatch — this constant becomes too permissive and SP1 will
/// fail on the 5080 again. `strings ~/.sp1/bin/sp1-gpu-server | grep 'must be at least'` is the check;
/// `--version` cannot tell them apart, both print 6.0.2.
pub fn min_vram_bytes_for_backend(backend: &str) -> Option<u64> {
    match backend {
        "sp1" => Some(16_000_000_000),
        _ => None,
    }
}

/// Env override for [`min_available_vram_bytes_for_backend`], in MiB. `0` disables the check.
pub const MIN_AVAILABLE_VRAM_MB_ENV: &str = "ZKMINER_MIN_AVAILABLE_VRAM_MB";

/// How much VRAM must be FREE TO US on a card before this backend may be given work there, or `None`
/// for a backend with no such requirement.
///
/// This is [`min_vram_bytes_for_backend`] applied to what is available rather than to what is
/// installed, and the restatement is the whole point. That floor is already the figure below which
/// SP1's own prover refuses a device; a card with a desktop session on it has less VRAM free than it
/// has fitted, so the floor is the number that must clear after the display's share is subtracted.
///
/// Why it has to be checked at all: `sp1-gpu/crates/prover_components/src/builder.rs` picks its shard
/// element threshold from `cuda_memory_info().1` — the card's TOTAL. `cuda_memory_info` returns
/// `(free, total)`, so SP1 fetches the free figure and discards it. A card with 2 GiB held by a
/// compositor therefore sizes exactly as if it were empty, commits to that tier, and runs out of
/// device memory part-way through work we have already claimed and bonded collateral against. Nothing
/// inside SP1 can notice, because the sizing happens before its first allocation.
///
/// Why this, rather than a flat allowance for foreign VRAM, which is what this replaced: a flat
/// allowance refuses work the card could actually do. Measured on this box on 2026-10-05, SP1 peaks at
/// 15,092 MiB on the 134M-element tier and 17,766 MiB on the 268M tier. A 24,564 MiB 4090 with 6 GiB
/// held by a display still has 18 GiB free — plenty for the lower tier — and a 512 MiB allowance
/// refused it outright. Requiring the FLOOR to be free instead admits that card and leaves the sizing
/// to [`sp1_element_threshold_for_available_vram`], which steps the tier down to match. The floor
/// itself is the smaller tier's measured peak plus margin — 15,604 MiB — so a card that clears the
/// floor has room for the configuration it will actually be given.
///
/// risc0 and openvm have no floor here because they size per segment from `po2`, and that is a knob
/// the dispatcher sets per run: see `find_optimal_po2`, which is given the available figure rather
/// than the card's total so the segment shrinks instead of the work being refused.
pub fn min_available_vram_bytes_for_backend(backend: &str) -> Option<u64> {
    let default = match backend {
        // Derived from the MEASURED tier table rather than from the installed-VRAM floor, so this and
        // the tier the worker will actually be given cannot disagree about whether a card is usable.
        // They did in the first draft: a 16e9 floor admitted cards the tier function had no
        // configuration for.
        "sp1" => zkminer_prover_protocol::types::sp1_min_available_vram_bytes(),
        _ => return None,
    };
    match std::env::var(MIN_AVAILABLE_VRAM_MB_ENV) {
        // 0 is an explicit opt-out, for an operator who knows the other occupant of their card is
        // harmless and would rather risk the work than have it refused.
        Ok(v) => match v.trim().parse::<u64>() {
            Ok(0) => None,
            Ok(mb) => Some(mb * 1024 * 1024),
            Err(_) => {
                tracing::warn!(
                    "{MIN_AVAILABLE_VRAM_MB_ENV}={v:?} is not a number of MiB; using the default \
                     {:.1} GB for {backend}",
                    default as f64 / 1e9,
                );
                Some(default)
            }
        },
        Err(_) => Some(default),
    }
}

/// The sizing knob this backend should use on a card with `available` bytes of VRAM free, or `None`
/// for a backend that has no such knob.
///
/// Delegates to the shared arithmetic in `zkminer-prover-protocol` so the dispatcher and the worker
/// that actually applies it cannot drift apart: the dispatcher uses this to notice that a live worker
/// is sized for more VRAM than is now free, and the worker uses the same function to size itself.
pub fn vram_sizing_tier(backend: &str, available: u64) -> Option<u64> {
    match backend {
        "sp1" => {
            zkminer_prover_protocol::types::sp1_element_threshold_for_available_vram(available)
        }
        // risc0 and openvm size per segment from `po2`, which the dispatcher clamps per run in
        // `calibrate_slot_po2`; there is no spawn-time tier to go stale.
        _ => None,
    }
}

/// How much VRAM this backend needs free to run at sizing `tier` (a value [`vram_sizing_tier`]
/// returned), or `None` when that is unknown — a backend with no such knob, or a tier nothing has
/// measured.
///
/// What the dispatcher makes room for when our other workers share the card. `None` means the
/// requirement is unknown, and the dispatcher then makes all the room it can — recycling every idle
/// sibling holding at least `MIN_EVICTABLE_HOLDING` (see `RoomNeeded::Unknown`), because running
/// beside one that leaves too little kills the worker part-way through a claimed job — unless the
/// backend's floor cannot be reached even then, in which case nothing is recycled and the floor
/// refuses (see `room_needed`).
pub fn vram_required_for_tier(backend: &str, tier: u64) -> Option<u64> {
    match backend {
        "sp1" => zkminer_prover_protocol::types::sp1_vram_required_for_threshold(tier),
        // No spawn-time tier, so no figure: risc0's need depends on the segment size of the job in
        // hand, and nothing here has measured it per po2 yet. Unknown, so all the room is made.
        _ => None,
    }
}

/// Infer GPU tag from binary filename.
fn infer_gpu_tag(path: &Path) -> String {
    if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
        if name.ends_with("-cuda") {
            return "cuda".to_string();
        }
        if name.ends_with("-rocm") {
            return "rocm".to_string();
        }
        if name.ends_with("-intel") {
            return "intel".to_string();
        }
    }
    "generic".to_string()
}

fn search_in_dirs(bin_name: &str, dirs: &[PathBuf]) -> Option<PathBuf> {
    for dir in dirs {
        let candidate = dir.join(bin_name);
        if candidate.is_file() && is_executable(&candidate) {
            return Some(candidate);
        }
    }
    None
}

fn search_in_path(bin_name: &str) -> Option<PathBuf> {
    let path_var = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_var) {
        let candidate = dir.join(bin_name);
        if candidate.is_file() && is_executable(&candidate) {
            return Some(candidate);
        }
    }
    None
}

#[cfg(unix)]
fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    path.metadata()
        .map(|m| m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

#[cfg(not(unix))]
fn is_executable(path: &Path) -> bool {
    path.is_file()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn worker_binary_names() {
        assert_eq!(
            worker_binary_name("risc0", "generic"),
            "zkminer-prove-risc0"
        );
        assert_eq!(
            worker_binary_name("risc0", "cuda"),
            "zkminer-prove-risc0-cuda"
        );
        assert_eq!(
            worker_binary_name("risc0", "rocm"),
            "zkminer-prove-risc0-rocm"
        );
        assert_eq!(worker_binary_name("sp1", "generic"), "zkminer-prove-sp1");
    }

    /// The assumption every device pin rests on, pinned as a test.
    /// Nothing is currently excluded on architecture grounds — SP1's Blackwell fault was four
    /// out-of-bounds bugs in the fork's CUDA code, now fixed, and both cards prove. The mechanism stays
    /// for the next architecture that needs it; see `backend_broken_on_compute_cap`.
    #[test]
    fn no_backend_is_excluded_on_architecture_now() {
        for cap in [Some((12, 0)), Some((8, 9)), Some((13, 0)), None] {
            for backend in ["sp1", "risc0", "openvm"] {
                assert!(
                    !backend_broken_on_compute_cap(backend, cap),
                    "{backend} on {cap:?} should no longer be excluded"
                );
            }
        }
        // And the 5080 passes the VRAM floor, so nothing stops it being used.
        let floor = min_vram_bytes_for_backend("sp1").expect("sp1 has a floor");
        assert!(16_303u64 * 1024 * 1024 >= floor);
    }

    /// Which server's GPU code decides SP1's cards: the one the worker is about to install, not
    /// whatever is installed now.
    #[test]
    fn the_sp1_server_checked_is_the_one_the_worker_will_run() {
        let root = std::env::temp_dir().join(format!(
            "zk-sp1-server-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let (release, home) = (root.join("provers"), root.join("home"));
        let installed = home.join(".sp1").join("bin").join("sp1-gpu-server");
        std::fs::create_dir_all(installed.parent().unwrap()).unwrap();
        std::fs::create_dir_all(&release).unwrap();
        let worker = release.join("zkminer-prove-sp1");
        let shipped = release.join("sp1-gpu-server");
        for file in [&worker, &shipped, &installed] {
            std::fs::write(file, b"x").unwrap();
        }

        // The release layout: the shipped server will replace the installed one.
        assert_eq!(
            sp1_server_for(&worker, true, Some(&home)),
            Some(shipped.clone())
        );
        // `ZKMINER_SP1_SERVER_INSTALL=0`: the worker leaves the installed one in place.
        assert_eq!(
            sp1_server_for(&worker, false, Some(&home)),
            Some(installed.clone())
        );
        // A development build, with nothing shipped beside it.
        std::fs::remove_file(&shipped).unwrap();
        assert_eq!(
            sp1_server_for(&worker, true, Some(&home)),
            Some(installed.clone())
        );
        // Neither: the SDK will download upstream's, which cannot be read in advance.
        std::fs::remove_file(&installed).unwrap();
        assert_eq!(sp1_server_for(&worker, true, Some(&home)), None);
        assert_eq!(sp1_server_for(&worker, true, None), None);

        // Every other backend's GPU code is in the worker itself.
        assert_eq!(
            gpu_code_binary("risc0", Path::new("/opt/zk/zkminer-prove-risc0-cuda")),
            Some(PathBuf::from("/opt/zk/zkminer-prove-risc0-cuda"))
        );
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn index_order_matching_pci_order_is_checked_not_assumed() {
        let gpu = |idx: u32, bus: &str| DetectedGpu {
            gpu_tag: "cuda".to_string(),
            device_index: idx,
            pci_bus_id: bus.to_string(),
            name: format!("card{idx}"),
            compute_cap: None,
        };
        // This box's real layout: index order and PCI rank agree.
        let agreeing = vec![gpu(0, "0000:06:10.0"), gpu(1, "0000:06:1b.0")];
        assert!(index_order_matches_pci_order(&agreeing));
        // A reordered enumeration, which would make every pin name the wrong card.
        let disagreeing = vec![gpu(1, "0000:06:10.0"), gpu(0, "0000:06:1b.0")];
        assert!(!index_order_matches_pci_order(&disagreeing));
        // Single card and no cards are trivially consistent.
        assert!(index_order_matches_pci_order(&[gpu(0, "0000:06:10.0")]));
        assert!(index_order_matches_pci_order(&[]));
        // And a FILTERED list must not trip the alarm. `ZKMINER_GPU_NAME_FILTER=4090` keeps
        // nvidia-smi's original index, so the surviving card is index 1 with nothing at index 0 —
        // agreement is about ORDER, not about starting at zero. Firing here advised the operator to
        // set the variable they had just set.
        assert!(index_order_matches_pci_order(&[gpu(1, "0000:06:1b.0")]));
        assert!(index_order_matches_pci_order(&[
            gpu(1, "0000:06:10.0"),
            gpu(3, "0000:06:1b.0")
        ]));
    }

    /// SP1's VRAM floor is a hard capability check, not a tunable risk — and the figure tracks which
    /// `sp1-gpu-server` is installed.
    ///
    /// With the fork's server (built and installed 2026-10-05) the floor is 16 GB and BOTH cards here
    /// qualify. With the upstream binary the SDK downloads by default it is 24 GB and the 5080 is
    /// refused outright. The constant must match the installed server; see the doc on
    /// `min_vram_bytes_for_backend` for how to tell which one is in place.
    #[test]
    fn sp1_requires_a_card_its_server_will_accept() {
        let floor = min_vram_bytes_for_backend("sp1").expect("sp1 has a floor");
        // RTX 4090, 24564 MiB.
        assert!(24_564u64 * 1024 * 1024 >= floor, "the 4090 must qualify");
        // RTX 5080, 16303 MiB — qualifies against the FORK's 16 GB server, which is what is installed.
        assert!(
            16_303u64 * 1024 * 1024 >= floor,
            "the 5080 must qualify: the installed server's floor is 16 GB"
        );
        // But a genuinely small card must not. A 12 GB card slips past the server's OWN guard
        // (`ceil(11.x) + 4 = 16` is not `< 16`) and would then OOM in the 16 GB tier, so ours is
        // deliberately the stricter of the two.
        assert!(
            12_288u64 * 1024 * 1024 < floor,
            "a 12 GB card must be refused here even though the server would admit it"
        );
        // Nothing else has a floor: risc0 degrades by lowering po2 instead of refusing.
        assert_eq!(min_vram_bytes_for_backend("risc0"), None);
        assert_eq!(min_vram_bytes_for_backend("openvm"), None);
    }

    #[test]
    fn discover_with_empty_config() {
        // Should not panic, may find 0 workers
        let workers = discover_workers(&HashMap::new(), &[]);
        for w in &workers {
            assert!(ALL_BACKENDS.contains(&w.backend.as_str()));
            assert!(GPU_TAGS.contains(&w.gpu_tag.as_str()));
        }
    }

    /// SP1's binary name says `generic`, but SP1 drives a CUDA card. Discovery must expand it per
    /// card anyway, because a 2-part key is unguarded, uncounted and unaddressable — the three things
    /// that let SP1 silently sit on device 0 and double-book it with risc0.
    #[test]
    fn a_cuda_backend_without_a_cuda_suffix_is_still_expanded_per_card() {
        assert!(drives_cuda_without_visibility_pin("sp1"));
        assert!(!drives_cuda_without_visibility_pin("risc0"));
        assert!(!drives_cuda_without_visibility_pin("openvm"));
        // The tag inference is unchanged — the expansion is what differs, so that the SDK can still
        // be handed an unfiltered view of the devices.
        assert_eq!(
            infer_gpu_tag(Path::new("/x/zkminer-prove-sp1")),
            "generic",
            "the filename is still what it is; the per-card decision is made from the backend"
        );
    }

    #[test]
    fn infer_gpu_tag_from_path() {
        assert_eq!(
            infer_gpu_tag(Path::new("/usr/bin/zkminer-prove-risc0-cuda")),
            "cuda"
        );
        assert_eq!(
            infer_gpu_tag(Path::new("/usr/bin/zkminer-prove-risc0-rocm")),
            "rocm"
        );
        assert_eq!(
            infer_gpu_tag(Path::new("/usr/bin/zkminer-prove-risc0-intel")),
            "intel"
        );
        assert_eq!(
            infer_gpu_tag(Path::new("/usr/bin/zkminer-prove-risc0")),
            "generic"
        );
    }

    #[test]
    fn detected_gpu_struct() {
        let gpu = DetectedGpu {
            gpu_tag: "cuda".to_string(),
            device_index: 0,
            pci_bus_id: "0000:01:00.0".to_string(),
            name: "GeForce RTX 4090".to_string(),
            compute_cap: None,
        };
        assert_eq!(gpu.gpu_tag, "cuda");
        assert_eq!(gpu.device_index, 0);
    }

    #[test]
    fn discovered_worker_new_fields() {
        let w = DiscoveredWorker {
            backend: "risc0".to_string(),
            gpu_tag: "cuda".to_string(),
            device_index: Some(1),
            pci_bus_id: Some("0000:41:00.0".to_string()),
            gpu_name: Some("GeForce RTX 4090".to_string()),
            compute_cap: Some((8, 9)),
            path: PathBuf::from("/usr/bin/zkminer-prove-risc0-cuda"),
        };
        assert_eq!(w.device_index, Some(1));
        assert_eq!(w.pci_bus_id.as_deref(), Some("0000:41:00.0"));
    }

    #[test]
    fn nvidia_smi_parse() {
        // Test that parse logic handles nvidia-smi-like output
        let csv = "0, GeForce RTX 4090, 00000000:01:00.0\n1, GeForce RTX 4090, 00000000:41:00.0\n";
        let mut gpus = Vec::new();
        for line in csv.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let parts: Vec<&str> = line.splitn(3, ',').map(|s| s.trim()).collect();
            if parts.len() < 3 {
                continue;
            }
            let index: u32 = parts[0].parse().unwrap();
            let name = parts[1].to_string();
            // Use the REAL normalizer, not a bare lowercase. The production parser
            // canonicalizes nvidia-smi's 8-digit domain to 4 so the id compares equal to
            // the sysfs form the TUI reads; a test that lowercases only would keep passing
            // if that normalization were dropped, while every NVIDIA card silently stopped
            // matching its benchmark row.
            let pci_bus_id = normalize_pci_bus_id(parts[2]);
            gpus.push(DetectedGpu {
                gpu_tag: "cuda".to_string(),
                device_index: index,
                pci_bus_id,
                name,
                compute_cap: None,
            });
        }
        assert_eq!(gpus.len(), 2);
        assert_eq!(gpus[0].device_index, 0);
        assert_eq!(gpus[0].name, "GeForce RTX 4090");
        assert_eq!(gpus[1].device_index, 1);
        assert_eq!(gpus[1].pci_bus_id, "0000:41:00.0");
        assert_eq!(gpus[0].pci_bus_id, "0000:01:00.0");
        // And the canonical form must match what the TUI produces from sysfs.
        assert_eq!(normalize_pci_bus_id("0000:41:00.0"), gpus[1].pci_bus_id);
    }
}
