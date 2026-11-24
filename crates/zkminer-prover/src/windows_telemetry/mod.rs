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

/// The driver's library `name`, from System32 only, kept loaded for the life of the process.
///
/// System32 only: a bare name would also be looked for in the current directory and on `PATH`,
/// where anyone who can write there could put a library of that name in the miner. Never unloaded:
/// a vendor library may register event-tracing callbacks or leave work on the process's thread pool
/// that outlive a failed initialization (Intel's `ctlInit` does both); when the library was
/// unloaded under them, the next event or work item jumped into unmapped code and crashed the
/// miner, seconds or hours later. The module is also pinned, so no `FreeLibrary` anywhere in the
/// process can unload it, and the reference returned is leaked (the function pointers taken from it
/// point into it).
fn load_system_library(name: &str) -> anyhow::Result<&'static libloading::Library> {
    use libloading::os::windows::{Library, LOAD_LIBRARY_SEARCH_SYSTEM32};
    const GET_MODULE_HANDLE_EX_FLAG_PIN: u32 = 0x1;
    const GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS: u32 = 0x4;
    #[link(name = "kernel32")]
    extern "system" {
        fn GetModuleHandleExW(flags: u32, name: *const u16, module: *mut isize) -> i32;
    }
    // SAFETY: loading the driver's own library, whose initialization has no preconditions.
    let library = unsafe { Library::load_with_flags(name, LOAD_LIBRARY_SEARCH_SYSTEM32) }?;
    let module = library.into_raw();
    let mut pinned = 0isize;
    // SAFETY: `module` is the base address of a loaded module, which lies inside it; `pinned` is a
    // valid out pointer. Pinning takes no reference that needs giving back.
    let ok = unsafe {
        GetModuleHandleExW(
            GET_MODULE_HANDLE_EX_FLAG_PIN | GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
            module as *const u16,
            &mut pinned,
        )
    };
    if ok == 0 {
        // Still never unloaded by this process (leaked below); only another `FreeLibrary` could.
        tracing::debug!(
            "{name} could not be pinned: {}",
            std::io::Error::last_os_error()
        );
    }
    // SAFETY: `module` came from `into_raw` just above and is owned by nothing else.
    let library: libloading::Library = unsafe { Library::from_raw(module) }.into();
    Ok(Box::leak(Box::new(library)))
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

    /// A vendor library that loaded stays mapped, and a bare name is looked for in System32 only:
    /// a library of that name in the current directory is not loaded.
    #[test]
    fn vendor_libraries_come_from_system32_and_stay_loaded() {
        #[link(name = "kernel32")]
        extern "system" {
            fn GetModuleHandleW(name: *const u16) -> isize;
            fn FreeLibrary(module: isize) -> i32;
        }
        let wide = |s: &str| s.encode_utf16().chain([0]).collect::<Vec<u16>>();
        // A System32 library that every Windows has stands in for the vendors'.
        load_system_library("winmm.dll").expect("winmm.dll from System32");
        let name = wide("winmm.dll");
        // SAFETY: a NUL-terminated name.
        let module = unsafe { GetModuleHandleW(name.as_ptr()) };
        assert_ne!(module, 0);
        // A FreeLibrary from elsewhere in the process does not unload a pinned module.
        // SAFETY: drops one reference to a module this process loaded.
        unsafe { FreeLibrary(module) };
        // SAFETY: a NUL-terminated name.
        assert_ne!(unsafe { GetModuleHandleW(name.as_ptr()) }, 0, "unloaded");

        // Not System32: a library found only beside the program, where a plain load looks first,
        // is not loaded.
        let system = std::path::Path::new(&std::env::var_os("SystemRoot").unwrap())
            .join("System32")
            .join("winmm.dll");
        let name = format!("zkminer-not-system-{}.dll", std::process::id());
        let beside = std::env::current_exe().unwrap().with_file_name(&name);
        std::fs::copy(system, &beside).unwrap();
        let loaded = load_system_library(&name).is_ok();
        // The control: a plain load finds it there.
        // SAFETY: a copy of a System32 library.
        let plain = unsafe { libloading::Library::new(&name) }.is_ok();
        let _ = std::fs::remove_file(&beside);
        assert!(plain, "the control load failed");
        assert!(!loaded, "loaded from beside the program");
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
