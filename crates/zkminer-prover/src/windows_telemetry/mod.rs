//! Live GPU telemetry on Windows from the vendors' driver libraries: Intel's IGCL
//! (`ControlLib.dll`) and AMD's ADLX (`amdadlx64.dll`). Both ship with the regular display
//! driver, so nothing extra is installed.
//!
//! Windows has no sysfs, so without these the hardware panel only knew each card's name and VRAM,
//! and the benchmark could not measure their power. They also report the PCIe link the card
//! actually negotiated with the slot: Windows' own device properties describe the link between the
//! GPU and the switch on its own board, which on Arc and Radeon cards is not the slot's.
//!
//! Cards are matched on their PCI address, the key the rest of the miner joins on. A library that
//! is missing or fails to start leaves its cards' figures as they were.

mod adlx;
mod igcl;

/// One card's figures, read into by [`WindowsTelemetry::refresh`]. A field the card's library
/// does not report keeps the value it had.
#[derive(Debug, Clone, Default)]
pub struct GpuTelemetry {
    /// Canonical lowercase PCI address, e.g. `0000:03:00.0`: which card to read.
    pub pci_bus_id: String,
    pub gpu_clock_mhz: u32,
    pub mem_clock_mhz: u32,
    pub gpu_usage_percent: u32,
    pub vram_used_bytes: u64,
    pub vram_total_bytes: u64,
    pub temp_edge_c: Option<f64>,
    pub temp_junction_c: Option<f64>,
    pub temp_mem_c: Option<f64>,
    pub fan_rpm: u32,
    /// Watts. 0 until known: Intel's comes from two readings of an energy counter.
    pub power_watts: f64,
    pub voltage_mv: u32,
    /// sysfs `current_link_speed` form, e.g. "32.0 GT/s PCIe".
    pub pcie_speed: String,
    pub pcie_width: u32,
    pub throttle_reasons: Vec<String>,
}

pub struct WindowsTelemetry {
    intel: Option<igcl::Igcl>,
    amd: Option<&'static std::sync::Mutex<adlx::Adlx>>,
}

impl WindowsTelemetry {
    /// Load the libraries of the vendors asked for.
    pub fn new(intel: bool, amd: bool) -> Self {
        let intel = if intel {
            igcl::Igcl::load()
                .inspect_err(|e| tracing::info!("Intel GPU telemetry unavailable: {e}"))
                .ok()
        } else {
            None
        };
        let amd = if amd {
            adlx::Adlx::shared()
                .inspect_err(|e| tracing::info!("AMD GPU telemetry unavailable: {e}"))
                .ok()
        } else {
            None
        };
        Self { intel, amd }
    }

    /// Reads the card at `gpu.pci_bus_id` into `gpu`, if a loaded library knows it.
    pub fn refresh(&mut self, gpu: &mut GpuTelemetry) {
        if let Some(intel) = self.intel.as_mut() {
            if intel.knows(&gpu.pci_bus_id) {
                intel.refresh(gpu);
                return;
            }
        }
        if let Some(amd) = self.amd {
            if let Ok(mut amd) = amd.lock() {
                amd.refresh(gpu);
            }
        }
    }
}

/// `pci_bus_id`'s form ("0000:03:00.0") for a bus/device/function.
fn bdf_key(bus: u32, device: u32, function: u32) -> String {
    format!("0000:{bus:02x}:{device:02x}.{function:x}")
}

/// A PCIe generation in sysfs' `current_link_speed` form, which `pcie_gen_label` reads.
pub fn pcie_speed_label(generation: u32) -> String {
    match generation {
        1 => "2.5 GT/s PCIe",
        2 => "5.0 GT/s PCIe",
        3 => "8.0 GT/s PCIe",
        4 => "16.0 GT/s PCIe",
        5 => "32.0 GT/s PCIe",
        6 => "64.0 GT/s PCIe",
        _ => return String::new(),
    }
    .to_string()
}

/// Power and utilization from two readings of the driver's monotonic counters.
#[derive(Debug, Default, Clone, Copy)]
struct CounterSample {
    /// Seconds, on the driver's clock.
    timestamp: f64,
    /// Joules.
    energy: Option<f64>,
    /// Seconds the GPU was busy.
    busy: Option<f64>,
}

impl CounterSample {
    /// `(watts, busy percent)` between `earlier` and `self`, where the counters moved forward.
    fn rates_since(&self, earlier: &CounterSample) -> (Option<f64>, Option<u32>) {
        let elapsed = self.timestamp - earlier.timestamp;
        if elapsed <= 0.0 {
            return (None, None);
        }
        let watts = match (self.energy, earlier.energy) {
            (Some(now), Some(then)) if now >= then => Some((now - then) / elapsed),
            _ => None,
        };
        let busy = match (self.busy, earlier.busy) {
            (Some(now), Some(then)) if now >= then => {
                Some(((now - then) / elapsed * 100.0).round().clamp(0.0, 100.0) as u32)
            }
            _ => None,
        };
        (watts, busy)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_match_the_hardware_panel_form() {
        assert_eq!(bdf_key(3, 0, 0), "0000:03:00.0");
        assert_eq!(bdf_key(0x22, 0x1f, 7), "0000:22:1f.7");
    }

    #[test]
    fn link_speeds_are_in_sysfs_form() {
        assert_eq!(pcie_speed_label(1), "2.5 GT/s PCIe");
        assert_eq!(pcie_speed_label(5), "32.0 GT/s PCIe");
        assert_eq!(pcie_speed_label(0), "");
    }

    #[test]
    fn rates_come_from_counter_deltas() {
        let then = CounterSample {
            timestamp: 1767.940,
            energy: Some(21265.352),
            busy: Some(20.349),
        };
        let now = CounterSample {
            timestamp: 1768.946,
            energy: Some(21400.904),
            busy: Some(21.353),
        };
        let (watts, busy) = now.rates_since(&then);
        assert!((watts.unwrap() - 134.7).abs() < 0.1, "{watts:?}");
        assert_eq!(busy, Some(100));
        // A counter that went backwards (driver reset) or a clock that did not move gives nothing.
        let reset = CounterSample {
            energy: Some(5.0),
            ..now
        };
        assert_eq!(reset.rates_since(&then).0, None);
        assert_eq!(then.rates_since(&then), (None, None));
    }

    /// Reads this machine's GPUs through the libraries, twice a second apart (Intel's power needs
    /// two). Run by hand: `cargo test -p zkminer-prover --lib live_telemetry -- --ignored --nocapture`.
    #[test]
    #[ignore = "reads the GPUs of the machine it runs on"]
    fn live_telemetry() {
        let mut telemetry = WindowsTelemetry::new(true, true);
        let mut cards: Vec<GpuTelemetry> = crate::discovery::detect_all_gpus()
            .into_iter()
            .map(|gpu| GpuTelemetry {
                pci_bus_id: gpu.pci_bus_id,
                ..Default::default()
            })
            .collect();
        for round in 0..2 {
            std::thread::sleep(std::time::Duration::from_secs(1));
            for card in &mut cards {
                telemetry.refresh(card);
                println!("round {round}: {card:?}");
            }
        }
    }
}
