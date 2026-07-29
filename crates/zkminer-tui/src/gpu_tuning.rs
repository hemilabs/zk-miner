//! GPU tuning controls — power limits, clock offsets, fan speeds.
//!
//! NVIDIA GPUs use the NVML API (via `nvml-wrapper`) for clock offset control,
//! power limits, and fan control. No X11/Wayland or nvidia-settings required.
//!
//! AMD GPUs use sysfs writes (power_dpm_force_performance_level, pp_dpm_sclk, etc.).
//!
//! All GPU writes require root/sudo. If the miner isn't running as root,
//! writes will fail gracefully with a log message.

use std::fmt;
use std::fs;
use std::path::Path;

use anyhow::{Context, Result, anyhow};

use crate::hardware::{GpuVendor, HardwareInfo, find_amd_card, find_intel_card};
use crate::nvml::nvml;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// What tuning capabilities a GPU supports.
#[derive(Debug, Clone)]
pub struct GpuTuningCaps {
    pub device_id: String,
    pub vendor: GpuVendor,
    pub power: Option<PowerCaps>,
    pub perf_profile: Option<PerfProfileCaps>,
    pub core_clock: Option<ClockCaps>,
    pub mem_clock: Option<ClockCaps>,
    pub fan: Option<FanCaps>,
}

#[derive(Debug, Clone)]
pub struct PowerCaps {
    pub min_watts: f64,
    pub max_watts: f64,
    pub default_watts: f64,
}

/// AMD performance levels from power_dpm_force_performance_level.
#[derive(Debug, Clone)]
pub struct PerfProfileCaps {
    pub levels: Vec<PerfLevel>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PerfLevel {
    Auto,
    Low,
    High,
    Manual,
    ProfileStandard,
    ProfilePeak,
}

impl fmt::Display for PerfLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Auto => write!(f, "auto"),
            Self::Low => write!(f, "low"),
            Self::High => write!(f, "high"),
            Self::Manual => write!(f, "manual"),
            Self::ProfileStandard => write!(f, "profile_standard"),
            Self::ProfilePeak => write!(f, "profile_peak"),
        }
    }
}

impl PerfLevel {
    pub const ALL: &'static [PerfLevel] = &[
        PerfLevel::Auto,
        PerfLevel::Low,
        PerfLevel::High,
        PerfLevel::Manual,
        PerfLevel::ProfileStandard,
        PerfLevel::ProfilePeak,
    ];
}

/// Clock capabilities — varies by vendor and control mechanism.
#[derive(Debug, Clone)]
pub enum ClockCaps {
    /// AMD DPM levels: discrete freq steps selectable via pp_dpm_sclk/pp_dpm_mclk.
    DpmLevels(Vec<DpmLevel>),
    /// NVIDIA range: min/max MHz settable via nvidia-smi -lgc/-lmc (legacy).
    Range {
        min_mhz: u32,
        max_mhz: u32,
        default_mhz: u32,
    },
    /// NVIDIA clock offset: shifts the V/F curve by a delta in MHz.
    /// Positive = overclock, negative = underclock.
    Offset {
        min_offset_mhz: i32,
        max_offset_mhz: i32,
    },
}

#[derive(Debug, Clone)]
pub struct DpmLevel {
    pub index: u32,
    pub freq_mhz: u32,
    pub active: bool,
}

/// Fan control capabilities.
#[derive(Debug, Clone)]
pub struct FanCaps {
    pub num_fans: u32,
    pub min_percent: u32,
    pub max_percent: u32,
}

/// Fan speed setting.
#[derive(Debug, Clone, PartialEq)]
pub enum FanSetting {
    Auto,
    Fixed(u32),
}

// ---------------------------------------------------------------------------
// Per-GPU mutable state
// ---------------------------------------------------------------------------

/// Mutable tuning state for a single GPU.
#[derive(Debug, Clone)]
pub struct GpuTuningState {
    pub caps: GpuTuningCaps,
    /// Current user-set power limit (None = hardware default).
    pub power_limit_watts: Option<f64>,
    /// Current AMD perf level (None = auto).
    pub perf_level: Option<PerfLevel>,
    /// Core clock setting.
    pub core_clock: ClockSetting,
    /// Memory clock setting.
    pub mem_clock: ClockSetting,
    /// Fan speed setting.
    pub fan_speed: FanSetting,
    /// Whether the user has made changes that haven't been applied yet.
    pub dirty: bool,
}

impl GpuTuningState {
    pub fn new(caps: GpuTuningCaps) -> Self {
        Self {
            caps,
            power_limit_watts: None,
            perf_level: None,
            core_clock: ClockSetting::Default,
            mem_clock: ClockSetting::Default,
            fan_speed: FanSetting::Auto,
            dirty: false,
        }
    }

    /// Reset all tuning values to defaults.
    pub fn reset(&mut self) {
        self.power_limit_watts = None;
        self.perf_level = None;
        self.core_clock = ClockSetting::Default;
        self.mem_clock = ClockSetting::Default;
        self.fan_speed = FanSetting::Auto;
        self.dirty = false;
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum ClockSetting {
    Default,
    /// For NVIDIA: lock to specific MHz (legacy).
    Fixed(u32),
    /// For AMD DPM: force a specific level index.
    DpmLevel(u32),
    /// Clock offset in MHz (can be negative). Used by NVML.
    Offset(i32),
}

// ---------------------------------------------------------------------------
// Change enum (sent via PostKeyAction)
// ---------------------------------------------------------------------------

/// A single tuning change to apply to a GPU.
pub enum TuningChange {
    PowerLimit(f64),
    PerfLevel(PerfLevel),
    CoreClock(ClockSetting),
    MemClock(ClockSetting),
    FanSpeed(FanSetting),
    ResetAll,
}

// ---------------------------------------------------------------------------
// Capability probing
// ---------------------------------------------------------------------------

/// Probe tuning capabilities for all GPUs. Called once at startup.
pub fn probe_tuning_caps(hardware: &HardwareInfo) -> Vec<GpuTuningCaps> {
    hardware
        .gpus
        .iter()
        .map(|gpu| {
            let device_id = format!("gpu{}", gpu.index);
            match gpu.vendor {
                GpuVendor::Amd => probe_amd_caps(&device_id, gpu.index),
                GpuVendor::Nvidia => probe_nvidia_caps(&device_id, nvidia_smi_index(&gpu.pci_id)),
                GpuVendor::Intel => probe_intel_caps(&device_id, gpu.index),
                GpuVendor::Unknown => GpuTuningCaps {
                    device_id,
                    vendor: GpuVendor::Unknown,
                    power: None,
                    perf_profile: None,
                    core_clock: None,
                    mem_clock: None,
                    fan: None,
                },
            }
        })
        .collect()
}

fn probe_amd_caps(device_id: &str, gpu_index: u32) -> GpuTuningCaps {
    let mut caps = GpuTuningCaps {
        device_id: device_id.to_string(),
        vendor: GpuVendor::Amd,
        power: None,
        perf_profile: None,
        core_clock: None,
        mem_clock: None,
        fan: None,
    };

    let Some((base, hwmon)) = find_amd_card(gpu_index) else {
        return caps;
    };

    // Power caps from hwmon (microwatts -> watts)
    if let Some(ref hwmon_path) = hwmon {
        let read_uw = |file: &str| -> Option<f64> {
            let p = hwmon_path.join(file);
            fs::read_to_string(&p)
                .ok()
                .and_then(|s| s.trim().parse::<u64>().ok())
                .map(|v| v as f64 / 1_000_000.0)
        };

        let min = read_uw("power1_cap_min");
        let max = read_uw("power1_cap_max");
        let default = read_uw("power1_cap_default");

        if let (Some(min_w), Some(max_w), Some(def_w)) = (min, max, default) {
            caps.power = Some(PowerCaps {
                min_watts: min_w,
                max_watts: max_w,
                default_watts: def_w,
            });
        }
    }

    // Performance profile
    let perf_path = format!("{}/power_dpm_force_performance_level", base);
    if Path::new(&perf_path).exists() {
        let levels: Vec<PerfLevel> = PerfLevel::ALL.iter().copied().collect();
        caps.perf_profile = Some(PerfProfileCaps { levels });
    }

    // Core clock (pp_dpm_sclk)
    let sclk_path = format!("{}/pp_dpm_sclk", base);
    if let Some(levels) = parse_dpm_levels(&sclk_path) {
        if !levels.is_empty() {
            caps.core_clock = Some(ClockCaps::DpmLevels(levels));
        }
    }

    // Memory clock (pp_dpm_mclk)
    let mclk_path = format!("{}/pp_dpm_mclk", base);
    if let Some(levels) = parse_dpm_levels(&mclk_path) {
        if !levels.is_empty() {
            caps.mem_clock = Some(ClockCaps::DpmLevels(levels));
        }
    }

    caps
}

/// Parse AMD DPM level files. Each line: `N: XXXMhz [*]`
fn parse_dpm_levels(path: &str) -> Option<Vec<DpmLevel>> {
    let content = fs::read_to_string(path).ok()?;
    let mut levels = Vec::new();

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        // Format: "0: 500Mhz *" or "1: 1000Mhz"
        let active = line.contains('*');
        let parts: Vec<&str> = line.split(':').collect();
        if parts.len() < 2 {
            continue;
        }
        let index: u32 = match parts[0].trim().parse() {
            Ok(v) => v,
            Err(_) => continue,
        };
        // Extract MHz value from "500Mhz *" or " 500Mhz"
        let freq_str = parts[1].trim();
        let freq_mhz: u32 = freq_str
            .split(|c: char| !c.is_ascii_digit())
            .next()
            .unwrap_or("0")
            .parse()
            .unwrap_or(0);

        levels.push(DpmLevel {
            index,
            freq_mhz,
            active,
        });
    }

    Some(levels)
}

/// Extract the nvidia-smi device index from a pci_id like "nv:0".
fn nvidia_smi_index(pci_id: &str) -> u32 {
    pci_id
        .strip_prefix("nv:")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}

fn probe_nvidia_caps(device_id: &str, nv_index: u32) -> GpuTuningCaps {
    let mut caps = GpuTuningCaps {
        device_id: device_id.to_string(),
        vendor: GpuVendor::Nvidia,
        power: None,
        perf_profile: None,
        core_clock: None,
        mem_clock: None,
        fan: None,
    };

    let Some(nvml) = nvml() else {
        tracing::warn!("NVML unavailable, cannot probe NVIDIA tuning caps for {device_id}");
        return caps;
    };
    let device = match nvml.device_by_index(nv_index) {
        Ok(d) => d,
        Err(e) => {
            tracing::warn!("NVML device_by_index({nv_index}) failed: {e}");
            return caps;
        }
    };

    // Power limits (milliwatts -> watts)
    if let Ok(constraints) = device.power_management_limit_constraints() {
        let default_mw = device
            .power_management_limit_default()
            .unwrap_or(constraints.max_limit);
        caps.power = Some(PowerCaps {
            min_watts: constraints.min_limit as f64 / 1000.0,
            max_watts: constraints.max_limit as f64 / 1000.0,
            default_watts: default_mw as f64 / 1000.0,
        });
    }

    // Core clock offset range.
    // NVML doesn't expose min/max offset via a wrapped API, so we use safe defaults.
    // Values outside the range will be rejected by NVML at apply time.
    caps.core_clock = Some(ClockCaps::Offset {
        min_offset_mhz: -500,
        max_offset_mhz: 500,
    });

    // Memory clock offset range (raw NVML values — display will halve these).
    caps.mem_clock = Some(ClockCaps::Offset {
        min_offset_mhz: -2000,
        max_offset_mhz: 4000,
    });

    // Fan capabilities
    if let Ok(num_fans) = device.num_fans() {
        if num_fans > 0 {
            caps.fan = Some(FanCaps {
                num_fans,
                min_percent: 0,
                max_percent: 100,
            });
        }
    }

    caps
}

// ---------------------------------------------------------------------------
// Hardware writes
// ---------------------------------------------------------------------------

/// Apply a tuning change to a GPU. Returns a success message on Ok.
pub fn apply_tuning(
    device_id: &str,
    change: &TuningChange,
    hardware: &HardwareInfo,
) -> Result<String> {
    let gpu = hardware
        .gpus
        .iter()
        .find(|g| format!("gpu{}", g.index) == device_id)
        .ok_or_else(|| anyhow!("GPU not found: {device_id}"))?;

    match gpu.vendor {
        GpuVendor::Amd => apply_amd_tuning(device_id, gpu.index, change),
        GpuVendor::Nvidia => apply_nvidia_tuning(device_id, nvidia_smi_index(&gpu.pci_id), change),
        GpuVendor::Intel => apply_intel_tuning(device_id, gpu.index, change),
        GpuVendor::Unknown => Err(anyhow!("Unknown GPU vendor for {device_id}")),
    }
}

fn apply_amd_tuning(device_id: &str, gpu_index: u32, change: &TuningChange) -> Result<String> {
    let (base, hwmon) = find_amd_card(gpu_index)
        .ok_or_else(|| anyhow!("AMD GPU {device_id} sysfs path not found"))?;

    match change {
        TuningChange::PowerLimit(watts) => {
            let hwmon_path =
                hwmon.ok_or_else(|| anyhow!("No hwmon path for {device_id}"))?;
            let microwatts = (*watts * 1_000_000.0) as u64;
            write_sysfs(
                &hwmon_path.join("power1_cap"),
                &microwatts.to_string(),
            )?;
            Ok(format!("{device_id}: Power limit set to {watts:.0}W"))
        }
        TuningChange::PerfLevel(level) => {
            let path = format!("{}/power_dpm_force_performance_level", base);
            write_sysfs(Path::new(&path), &level.to_string())?;
            Ok(format!("{device_id}: Performance level set to {level}"))
        }
        TuningChange::CoreClock(setting) => match setting {
            ClockSetting::DpmLevel(idx) => {
                let path = format!("{}/pp_dpm_sclk", base);
                write_sysfs(Path::new(&path), &idx.to_string())?;
                Ok(format!("{device_id}: Core clock DPM level set to {idx}"))
            }
            ClockSetting::Default => {
                // Reset by setting perf level to auto
                let path = format!("{}/power_dpm_force_performance_level", base);
                write_sysfs(Path::new(&path), "auto")?;
                Ok(format!("{device_id}: Core clock reset to auto"))
            }
            ClockSetting::Fixed(_) | ClockSetting::Offset(_) => {
                Err(anyhow!("AMD GPUs use DPM levels, not fixed clocks or offsets"))
            }
        },
        TuningChange::MemClock(setting) => match setting {
            ClockSetting::DpmLevel(idx) => {
                let path = format!("{}/pp_dpm_mclk", base);
                write_sysfs(Path::new(&path), &idx.to_string())?;
                Ok(format!("{device_id}: Memory clock DPM level set to {idx}"))
            }
            ClockSetting::Default => {
                let path = format!("{}/power_dpm_force_performance_level", base);
                write_sysfs(Path::new(&path), "auto")?;
                Ok(format!("{device_id}: Memory clock reset to auto"))
            }
            ClockSetting::Fixed(_) | ClockSetting::Offset(_) => {
                Err(anyhow!("AMD GPUs use DPM levels, not fixed clocks or offsets"))
            }
        },
        TuningChange::FanSpeed(_) => {
            // TODO: AMD fan control via hwmon
            Err(anyhow!("AMD fan control not yet implemented"))
        }
        TuningChange::ResetAll => {
            // Reset perf level to auto
            let perf_path = format!("{}/power_dpm_force_performance_level", base);
            let _ = write_sysfs(Path::new(&perf_path), "auto");
            // Reset power to default
            if let Some(hwmon_path) = hwmon {
                if let Some(default_uw) = fs::read_to_string(hwmon_path.join("power1_cap_default"))
                    .ok()
                    .and_then(|s| s.trim().parse::<u64>().ok())
                {
                    let _ = write_sysfs(
                        &hwmon_path.join("power1_cap"),
                        &default_uw.to_string(),
                    );
                }
            }
            Ok(format!("{device_id}: All tuning reset to defaults"))
        }
    }
}

fn apply_nvidia_tuning(
    device_id: &str,
    nv_index: u32,
    change: &TuningChange,
) -> Result<String> {
    let nvml = nvml().ok_or_else(|| anyhow!("NVML not available"))?;
    let mut device = nvml
        .device_by_index(nv_index)
        .map_err(|e| anyhow!("NVML device {nv_index}: {e}"))?;

    match change {
        TuningChange::PowerLimit(watts) => {
            let limit_mw = (*watts * 1000.0) as u32;
            device
                .set_power_management_limit(limit_mw)
                .map_err(|e| anyhow!("set power limit: {e}"))?;
            Ok(format!("{device_id}: Power limit set to {watts:.0}W"))
        }
        TuningChange::PerfLevel(_) => {
            Err(anyhow!("NVIDIA GPUs don't support performance level profiles"))
        }
        TuningChange::CoreClock(setting) => match setting {
            ClockSetting::Offset(offset) => {
                device
                    .set_gpc_clock_vf_offset(*offset)
                    .map_err(|e| anyhow!("set core clock offset: {e}"))?;
                Ok(format!("{device_id}: Core clock offset set to {offset:+} MHz"))
            }
            ClockSetting::Fixed(mhz) => {
                use nvml_wrapper::enums::device::GpuLockedClocksSetting;
                device
                    .set_gpu_locked_clocks(GpuLockedClocksSetting::Numeric {
                        min_clock_mhz: *mhz,
                        max_clock_mhz: *mhz,
                    })
                    .map_err(|e| anyhow!("set core clock lock: {e}"))?;
                Ok(format!("{device_id}: Core clock locked to {mhz} MHz"))
            }
            ClockSetting::Default => {
                let _ = device.set_gpc_clock_vf_offset(0);
                let _ = device.reset_gpu_locked_clocks();
                Ok(format!("{device_id}: Core clock reset to default"))
            }
            ClockSetting::DpmLevel(_) => {
                Err(anyhow!("NVIDIA GPUs don't use DPM levels"))
            }
        },
        TuningChange::MemClock(setting) => match setting {
            ClockSetting::Offset(offset) => {
                device
                    .set_mem_clock_vf_offset(*offset)
                    .map_err(|e| anyhow!("set mem clock offset: {e}"))?;
                let display_offset = offset / 2;
                Ok(format!(
                    "{device_id}: Memory clock offset set to {display_offset:+} MHz (effective)"
                ))
            }
            ClockSetting::Default => {
                let _ = device.set_mem_clock_vf_offset(0);
                let _ = device.reset_mem_locked_clocks();
                Ok(format!("{device_id}: Memory clock reset to default"))
            }
            _ => Err(anyhow!("Unsupported memory clock setting for NVIDIA")),
        },
        TuningChange::FanSpeed(fan_setting) => match fan_setting {
            FanSetting::Fixed(pct) => {
                let num_fans = device.num_fans().unwrap_or(1);
                for fan_idx in 0..num_fans {
                    device
                        .set_fan_speed(fan_idx, *pct)
                        .map_err(|e| anyhow!("set fan {fan_idx} speed: {e}"))?;
                }
                Ok(format!("{device_id}: Fan speed set to {pct}%"))
            }
            FanSetting::Auto => {
                let num_fans = device.num_fans().unwrap_or(1);
                for fan_idx in 0..num_fans {
                    device
                        .set_default_fan_speed(fan_idx)
                        .map_err(|e| anyhow!("reset fan {fan_idx}: {e}"))?;
                }
                Ok(format!("{device_id}: Fan speed set to auto"))
            }
        },
        TuningChange::ResetAll => {
            let _ = device.set_gpc_clock_vf_offset(0);
            let _ = device.set_mem_clock_vf_offset(0);
            let _ = device.reset_gpu_locked_clocks();
            let _ = device.reset_mem_locked_clocks();
            // Reset power to default
            if let Ok(default_mw) = device.power_management_limit_default() {
                let _ = device.set_power_management_limit(default_mw);
            }
            // Reset fans to auto
            if let Ok(num_fans) = device.num_fans() {
                for fan_idx in 0..num_fans {
                    let _ = device.set_default_fan_speed(fan_idx);
                }
            }
            Ok(format!("{device_id}: All tuning reset to defaults"))
        }
    }
}

fn probe_intel_caps(device_id: &str, gpu_index: u32) -> GpuTuningCaps {
    let mut caps = GpuTuningCaps {
        device_id: device_id.to_string(),
        vendor: GpuVendor::Intel,
        power: None,
        perf_profile: None,
        core_clock: None,
        mem_clock: None,
        fan: None,
    };

    let Some((base, hwmon)) = find_intel_card(gpu_index) else {
        return caps;
    };

    // Power caps from hwmon (microwatts -> watts)
    // Intel xe driver exposes: power1_cap (current), power1_crit (max).
    // No power1_cap_min/max/default — derive from available files.
    if let Some(ref hwmon_path) = hwmon {
        let read_uw = |file: &str| -> Option<f64> {
            let p = hwmon_path.join(file);
            fs::read_to_string(&p)
                .ok()
                .and_then(|s| s.trim().parse::<u64>().ok())
                .map(|v| v as f64 / 1_000_000.0)
        };

        let current = read_uw("power1_cap");
        let min = read_uw("power1_cap_min");
        let max = read_uw("power1_cap_max").or_else(|| read_uw("power1_crit"));
        let default = read_uw("power1_cap_default").or(current);

        if let (Some(max_w), Some(def_w)) = (max, default) {
            caps.power = Some(PowerCaps {
                min_watts: min.unwrap_or(1.0),
                max_watts: max_w,
                default_watts: def_w,
            });
        }
    }

    // Performance profile — xe driver: tile0/gt0/freq0/power_profile
    // Format: "[base]    power_saving" (bracketed = active)
    let profile_path = format!("{}/tile0/gt0/freq0/power_profile", base);
    if Path::new(&profile_path).exists() {
        // Map Intel power profiles to PerfLevel enum:
        //   base → High, power_saving → Low, Auto → Auto (reset to default)
        caps.perf_profile = Some(PerfProfileCaps {
            levels: vec![PerfLevel::Auto, PerfLevel::Low, PerfLevel::High],
        });
    }

    // Core clock range — xe driver: tile0/gt0/freq0/{rpn_freq, rp0_freq, min_freq, max_freq}
    let freq_base = format!("{}/tile0/gt0/freq0", base);
    let rpn = read_intel_freq(&format!("{}/rpn_freq", freq_base)); // hardware minimum
    let rp0 = read_intel_freq(&format!("{}/rp0_freq", freq_base)); // hardware maximum
    let rpe = read_intel_freq(&format!("{}/rpe_freq", freq_base)); // efficient freq (default)
    if let (Some(min_mhz), Some(max_mhz)) = (rpn, rp0) {
        caps.core_clock = Some(ClockCaps::Range {
            min_mhz,
            max_mhz,
            default_mhz: rpe.unwrap_or(max_mhz),
        });
    }

    caps
}

/// Read an Intel xe freq value (already in MHz, plain integer).
fn read_intel_freq(path: &str) -> Option<u32> {
    fs::read_to_string(path)
        .ok()
        .and_then(|s| s.trim().parse().ok())
}


fn apply_intel_tuning(
    device_id: &str,
    gpu_index: u32,
    change: &TuningChange,
) -> Result<String> {
    let (base, hwmon) = find_intel_card(gpu_index)
        .ok_or_else(|| anyhow!("Intel GPU {device_id} sysfs path not found"))?;

    let freq_base = format!("{}/tile0/gt0/freq0", base);

    match change {
        TuningChange::PowerLimit(watts) => {
            let hwmon_path =
                hwmon.ok_or_else(|| anyhow!("No hwmon path for {device_id}"))?;
            let microwatts = (*watts * 1_000_000.0) as u64;
            write_sysfs(
                &hwmon_path.join("power1_cap"),
                &microwatts.to_string(),
            )?;
            Ok(format!("{device_id}: Power limit set to {watts:.0}W"))
        }
        TuningChange::PerfLevel(level) => {
            // Map PerfLevel to Intel xe power_profile values:
            //   Auto → reset min/max freq to hardware defaults
            //   Low → power_saving
            //   High → base (maximum performance)
            let profile_path = format!("{}/power_profile", freq_base);
            match level {
                PerfLevel::Auto => {
                    // Reset to default profile and restore hardware freq range
                    let _ = write_sysfs(Path::new(&profile_path), "base");
                    let rpn = read_intel_freq(&format!("{}/rpn_freq", freq_base));
                    let rp0 = read_intel_freq(&format!("{}/rp0_freq", freq_base));
                    if let Some(min) = rpn {
                        let _ = write_sysfs(
                            Path::new(&format!("{}/min_freq", freq_base)),
                            &min.to_string(),
                        );
                    }
                    if let Some(max) = rp0 {
                        let _ = write_sysfs(
                            Path::new(&format!("{}/max_freq", freq_base)),
                            &max.to_string(),
                        );
                    }
                    Ok(format!("{device_id}: Performance profile reset to auto"))
                }
                PerfLevel::Low => {
                    write_sysfs(Path::new(&profile_path), "power_saving")?;
                    Ok(format!("{device_id}: Performance profile set to power_saving"))
                }
                PerfLevel::High => {
                    write_sysfs(Path::new(&profile_path), "base")?;
                    Ok(format!("{device_id}: Performance profile set to base (max performance)"))
                }
                _ => Err(anyhow!(
                    "Intel GPUs support Auto, Low (power_saving), and High (base) profiles"
                )),
            }
        }
        TuningChange::CoreClock(setting) => match setting {
            ClockSetting::Fixed(mhz) => {
                // Lock clock by setting min = max = target
                let mhz_str = mhz.to_string();
                write_sysfs(
                    Path::new(&format!("{}/min_freq", freq_base)),
                    &mhz_str,
                )?;
                write_sysfs(
                    Path::new(&format!("{}/max_freq", freq_base)),
                    &mhz_str,
                )?;
                Ok(format!("{device_id}: Core clock locked to {mhz} MHz"))
            }
            ClockSetting::Default => {
                // Restore hardware min/max
                let rpn = read_intel_freq(&format!("{}/rpn_freq", freq_base))
                    .ok_or_else(|| anyhow!("Cannot read rpn_freq"))?;
                let rp0 = read_intel_freq(&format!("{}/rp0_freq", freq_base))
                    .ok_or_else(|| anyhow!("Cannot read rp0_freq"))?;
                write_sysfs(
                    Path::new(&format!("{}/min_freq", freq_base)),
                    &rpn.to_string(),
                )?;
                write_sysfs(
                    Path::new(&format!("{}/max_freq", freq_base)),
                    &rp0.to_string(),
                )?;
                Ok(format!("{device_id}: Core clock reset to default ({rpn}–{rp0} MHz)"))
            }
            ClockSetting::DpmLevel(_) => {
                Err(anyhow!("Intel GPUs don't use DPM levels — use Fixed clock instead"))
            }
            ClockSetting::Offset(_) => {
                Err(anyhow!("Intel GPUs don't support clock offsets — use Fixed clock instead"))
            }
        },
        TuningChange::MemClock(_) => {
            Err(anyhow!("Intel GPU memory clock is not user-adjustable"))
        }
        TuningChange::FanSpeed(_) => {
            Err(anyhow!("Intel GPU fan speed is not user-adjustable (read-only sensor)"))
        }
        TuningChange::ResetAll => {
            // Reset power to default
            if let Some(hwmon_path) = hwmon {
                if let Some(default_uw) = fs::read_to_string(hwmon_path.join("power1_cap_default"))
                    .ok()
                    .and_then(|s| s.trim().parse::<u64>().ok())
                {
                    let _ = write_sysfs(
                        &hwmon_path.join("power1_cap"),
                        &default_uw.to_string(),
                    );
                }
            }
            // Reset clock range to hardware defaults
            let rpn = read_intel_freq(&format!("{}/rpn_freq", freq_base));
            let rp0 = read_intel_freq(&format!("{}/rp0_freq", freq_base));
            if let Some(min) = rpn {
                let _ = write_sysfs(
                    Path::new(&format!("{}/min_freq", freq_base)),
                    &min.to_string(),
                );
            }
            if let Some(max) = rp0 {
                let _ = write_sysfs(
                    Path::new(&format!("{}/max_freq", freq_base)),
                    &max.to_string(),
                );
            }
            // Reset power profile
            let _ = write_sysfs(
                Path::new(&format!("{}/power_profile", freq_base)),
                "base",
            );
            Ok(format!("{device_id}: All tuning reset to defaults"))
        }
    }
}

/// Apply all non-default settings from a GpuTuningState.
/// Returns a list of results (one per setting applied).
pub fn apply_full_state(
    device_id: &str,
    ts: &GpuTuningState,
    hardware: &HardwareInfo,
) -> Vec<Result<String>> {
    let mut results = Vec::new();

    if let Some(watts) = ts.power_limit_watts {
        results.push(apply_tuning(device_id, &TuningChange::PowerLimit(watts), hardware));
    }
    if let Some(level) = ts.perf_level {
        results.push(apply_tuning(device_id, &TuningChange::PerfLevel(level), hardware));
    }
    if ts.core_clock != ClockSetting::Default {
        results.push(apply_tuning(
            device_id,
            &TuningChange::CoreClock(ts.core_clock.clone()),
            hardware,
        ));
    }
    if ts.mem_clock != ClockSetting::Default {
        results.push(apply_tuning(
            device_id,
            &TuningChange::MemClock(ts.mem_clock.clone()),
            hardware,
        ));
    }
    if ts.fan_speed != FanSetting::Auto {
        results.push(apply_tuning(
            device_id,
            &TuningChange::FanSpeed(ts.fan_speed.clone()),
            hardware,
        ));
    }

    if results.is_empty() {
        results.push(Ok(format!("{device_id}: No changes to apply")));
    }

    results
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn write_sysfs(path: &Path, value: &str) -> Result<()> {
    fs::write(path, value)
        .with_context(|| format!("Failed to write '{}' to {}", value, path.display()))
}

