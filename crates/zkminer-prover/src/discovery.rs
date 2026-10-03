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
        tracing::info!(
            "Detected {} AMD GPU(s): {}",
            amd.len(),
            names.join(", ")
        );
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

/// Parse nvidia-smi CSV output.
fn detect_nvidia_via_smi() -> Option<Vec<DetectedGpu>> {
    let output = std::process::Command::new("nvidia-smi")
        .args([
            "--query-gpu=index,name,pci.bus_id",
            "--format=csv,noheader,nounits",
        ])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut gpus = Vec::new();
    let mut saw_nonempty_line = false;

    for line in stdout.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        saw_nonempty_line = true;
        let parts: Vec<&str> = line.splitn(3, ',').map(|s| s.trim()).collect();
        if parts.len() < 3 {
            continue;
        }
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
        });
    }

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
        let has_lmem = device_dir
            .join("tile0/physical_vram_size_bytes")
            .exists();
        if !has_tile0 && !has_lmem {
            // Check BAR2 in PCI resource file as fallback
            let has_bar2 = std::fs::read_to_string(device_dir.join("resource"))
                .ok()
                .and_then(|r| {
                    r.lines().nth(2).and_then(|line| {
                        let parts: Vec<&str> = line.split_whitespace().collect();
                        if parts.len() >= 2 {
                            let start =
                                u64::from_str_radix(parts[0].trim_start_matches("0x"), 16)
                                    .unwrap_or(0);
                            let end =
                                u64::from_str_radix(parts[1].trim_start_matches("0x"), 16)
                                    .unwrap_or(0);
                            if end > start { Some(true) } else { None }
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
    let output = match std::process::Command::new("rocm-smi")
        .args(["--showproductname", "--showbus"])
        .output()
    {
        Ok(o) if o.status.success() => o,
        _ => return info,
    };
    let text = String::from_utf8_lossy(&output.stdout);

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
        // 1. Explicit path from config — NOT auto-expanded (user controls GPU visibility)
        if let Some(path) = explicit_binaries.get(*backend) {
            if path.is_file() {
                let gpu_tag = infer_gpu_tag(path);
                found.push(DiscoveredWorker {
                    backend: backend.to_string(),
                    gpu_tag,
                    device_index: None,
                    pci_bus_id: None,
                    gpu_name: None,
                    path: path.clone(),
                });
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

            let bin_path = search_in_dirs(&bin_name, &all_dirs)
                .or_else(|| search_in_path(&bin_name));

            let Some(path) = bin_path else {
                continue;
            };

            if *gpu_tag == "generic" {
                // Generic binary: single entry, no GPU pinning
                found.push(DiscoveredWorker {
                    backend: backend.to_string(),
                    gpu_tag: gpu_tag.to_string(),
                    device_index: None,
                    pci_bus_id: None,
                    gpu_name: None,
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
                        path: path.clone(),
                    });
                }
            }
        }
    }

    found
}

// NOTE — why SP1 is left classified as "generic" even though it IS a CUDA prover.
//
// `zkminer-prove-sp1` forks `sp1-gpu-server` (a 236MB CUDA process, measured holding
// 10.3GB of VRAM) yet carries no `-cuda` suffix, so `infer_gpu_tag` returns "generic".
// A generic slot gets a 2-part key, which means `physical_gpu_id` returns None (no
// per-card lock, so SP1 and risc0 can double-book one card), `gpu_env` injects no
// `CUDA_VISIBLE_DEVICES` (no pin), and `proving_gpu_count` does not count it.
//
// Re-tagging it "cuda" to earn those three things was TRIED and REVERTED: it breaks SP1
// proving outright. Measured on 2026-10-03 -- `sp1:generic` proves bigint-mul in 64s,
// while `sp1:cuda:0` (16GB card) and `sp1:cuda:1` (24GB card) BOTH die with
// "Worker sp1 process died (EOF)" in ~7s. Identical on both cards, so it is not a VRAM
// shortfall: restricting `CUDA_VISIBLE_DEVICES` breaks the SDK's negotiation with its
// gpu-server child. Re-tagging also made SP1 share risc0's per-card lock, and because a
// single-key backend takes the `keys.len() == 1` shortcut in `prove_min_vram` it would
// then block on an unbounded `l.lock()` with no deadline check -- able to park a job past
// its own abort_at with collateral bonded, a loss path that does not exist today.
//
// A correct fix must therefore decouple "which card does this worker occupy" (for the
// lock and the capacity count) from "inject a visibility pin" (which SP1 cannot take).
// Until then the accounting gap is accepted, and the VRAM leak it caused is addressed
// instead in `WorkerHandle::drop`, which now reaps a forked helper unconditionally.

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
        assert_eq!(worker_binary_name("risc0", "generic"), "zkminer-prove-risc0");
        assert_eq!(worker_binary_name("risc0", "cuda"), "zkminer-prove-risc0-cuda");
        assert_eq!(worker_binary_name("risc0", "rocm"), "zkminer-prove-risc0-rocm");
        assert_eq!(worker_binary_name("sp1", "generic"), "zkminer-prove-sp1");
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

    #[test]
    fn infer_gpu_tag_from_path() {
        assert_eq!(infer_gpu_tag(Path::new("/usr/bin/zkminer-prove-risc0-cuda")), "cuda");
        assert_eq!(infer_gpu_tag(Path::new("/usr/bin/zkminer-prove-risc0-rocm")), "rocm");
        assert_eq!(infer_gpu_tag(Path::new("/usr/bin/zkminer-prove-risc0-intel")), "intel");
        assert_eq!(infer_gpu_tag(Path::new("/usr/bin/zkminer-prove-risc0")), "generic");
    }

    #[test]
    fn detected_gpu_struct() {
        let gpu = DetectedGpu {
            gpu_tag: "cuda".to_string(),
            device_index: 0,
            pci_bus_id: "0000:01:00.0".to_string(),
            name: "GeForce RTX 4090".to_string(),
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
