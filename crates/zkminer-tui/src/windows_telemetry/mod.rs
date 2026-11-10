//! Live GPU telemetry on Windows from the vendors' driver libraries: Intel's IGCL
//! (`ControlLib.dll`) and AMD's ADLX (`amdadlx64.dll`). Both ship with the regular display
//! driver, so nothing extra is installed.
//!
//! Windows has no sysfs, so without these the hardware panel only knew each card's name and VRAM.
//! They also report the PCIe link the card actually negotiated with the slot: Windows' own device
//! properties describe the link between the GPU and the switch on its own board, which on Arc and
//! Radeon cards is not the slot's.
//!
//! Cards are matched on their PCI address, the key the rest of the TUI joins on. A library that
//! is missing or fails to start leaves its cards' figures empty, as before.

mod adlx;
mod igcl;

use crate::hardware::{GpuInfo, GpuVendor};

pub(crate) struct WindowsTelemetry {
    intel: Option<igcl::Igcl>,
    amd: Option<&'static std::sync::Mutex<adlx::Adlx>>,
}

impl WindowsTelemetry {
    /// Load the libraries for the vendors present in `gpus`.
    pub(crate) fn new(gpus: &[GpuInfo]) -> Self {
        let has = |vendor| gpus.iter().any(|g| g.vendor == vendor);
        let intel = if has(GpuVendor::Intel) {
            igcl::Igcl::load()
                .inspect_err(|e| tracing::info!("Intel GPU telemetry unavailable: {e}"))
                .ok()
        } else {
            None
        };
        let amd = if has(GpuVendor::Amd) {
            adlx::Adlx::shared()
                .inspect_err(|e| tracing::info!("AMD GPU telemetry unavailable: {e}"))
                .ok()
        } else {
            None
        };
        Self { intel, amd }
    }

    pub(crate) fn refresh(&mut self, gpu: &mut GpuInfo) {
        match gpu.vendor {
            GpuVendor::Intel => {
                if let Some(intel) = self.intel.as_mut() {
                    intel.refresh(gpu);
                }
            }
            GpuVendor::Amd => {
                if let Some(amd) = self.amd {
                    if let Ok(mut amd) = amd.lock() {
                        amd.refresh(gpu);
                    }
                }
            }
            _ => {}
        }
    }
}

/// `pci_bus_id`'s form ("0000:03:00.0") for a bus/device/function.
fn bdf_key(bus: u32, device: u32, function: u32) -> String {
    format!("0000:{bus:02x}:{device:02x}.{function:x}")
}

/// A PCIe generation in sysfs' `current_link_speed` form, which `pcie_gen_label` reads.
pub(crate) fn pcie_speed_label(generation: u32) -> String {
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
    fn link_speeds_read_back_as_their_generation() {
        for generation in 1..=5 {
            let label = crate::hardware::pcie_gen_label(&pcie_speed_label(generation)).to_string();
            assert_eq!(label, format!("Gen{generation}"));
        }
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

    /// Reads this machine's GPUs through the same path as the hardware panel. Run by hand:
    /// `cargo test -p zkminer-tui --lib live_telemetry -- --ignored --nocapture`.
    #[test]
    #[ignore = "reads the GPUs of the machine it runs on"]
    fn live_telemetry() {
        let mut gpus = crate::hardware::probe_static().gpus;
        let mut telemetry = WindowsTelemetry::new(&gpus);
        for round in 0..2 {
            std::thread::sleep(std::time::Duration::from_secs(1));
            for gpu in &mut gpus {
                telemetry.refresh(gpu);
                println!("round {round}: {gpu:#?}");
            }
        }
    }
}
