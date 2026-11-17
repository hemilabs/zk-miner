//! Intel and AMD GPUs for the hardware panel on Windows, which has no sysfs to scan.
//!
//! They come from the prover's own discovery (`zkminer_prover::discovery`): the PnP display
//! devices for Intel, the HIP runtime for AMD. Only identity and VRAM size are known; the live
//! figures (clocks, temperature, power) stay empty, as the refresh path has nothing to read them
//! from here.

use crate::hardware::{GpuInfo, GpuVendor};

/// The Intel and AMD GPUs the prover would drive, numbered from `first_index` on.
pub(crate) fn intel_and_amd_gpus(first_index: u32) -> Vec<GpuInfo> {
    zkminer_prover::discovery::detect_all_gpus()
        .into_iter()
        .filter_map(|gpu| {
            let vendor = match gpu.gpu_tag.as_str() {
                "intel" => GpuVendor::Intel,
                "rocm" => GpuVendor::Amd,
                _ => return None,
            };
            let vram_total_bytes = match vendor {
                GpuVendor::Intel => {
                    zkminer_prover::discovery::intel_vram_bytes(gpu.device_index).unwrap_or(0)
                }
                _ => 0,
            };
            Some((vendor, gpu, vram_total_bytes))
        })
        .zip(first_index..)
        .map(|((vendor, gpu, vram_total_bytes), index)| GpuInfo {
            index,
            name: gpu.name,
            vendor,
            pci_id: format!("{}:{}", gpu.gpu_tag, gpu.device_index),
            pci_bus_id: gpu.pci_bus_id,
            gpu_clock_mhz: 0,
            mem_clock_mhz: 0,
            gpu_usage_percent: 0,
            mem_usage_percent: 0,
            vram_used_bytes: 0,
            vram_total_bytes,
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
            throttle_reasons: Vec::new(),
        })
        .collect()
}
