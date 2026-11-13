//! Intel's Graphics Control Library (IGCL), `ControlLib.dll`.
//!
//! The structures mirror `igcl_api.h` (intel/drivers.gpu.control-library 1db55c36) field for
//! field; the size and offset assertions below are the values MSVC computes for that header.

use super::GpuTelemetry;
use super::{bdf_key, pcie_speed_label, CounterSample};
use std::collections::HashMap;
use std::ffi::c_void;
use std::mem::{offset_of, size_of};

type Handle = *mut c_void;
type CtlResult = u32;
const CTL_RESULT_SUCCESS: CtlResult = 0;
/// `CTL_MAKE_VERSION(1, 1)`, the header's `CTL_IMPL_VERSION`.
const CTL_IMPL_VERSION: u32 = (1 << 16) | 1;
/// The telemetry is read through Level Zero; without it the driver reports less.
const CTL_INIT_FLAG_USE_LEVEL_ZERO: u32 = 1;

#[repr(C)]
struct InitArgs {
    size: u32,
    version: u8,
    app_version: u32,
    flags: u32,
    supported_version: u32,
    application_uid: [u32; 4],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct AdapterBdf {
    bus: u8,
    device: u8,
    function: u8,
}

#[repr(C)]
struct AdapterProperties {
    size: u32,
    version: u8,
    device_id: *mut c_void,
    device_id_size: u32,
    device_type: i32,
    supported_subfunction_flags: u32,
    driver_version: u64,
    firmware_version: [u64; 3],
    pci_vendor_id: u32,
    pci_device_id: u32,
    rev_id: u32,
    num_eus_per_sub_slice: u32,
    num_sub_slices_per_slice: u32,
    num_slices: u32,
    name: [u8; 100],
    graphics_adapter_properties: u32,
    frequency: u32,
    pci_subsys_id: u16,
    pci_subsys_vendor_id: u16,
    adapter_bdf: AdapterBdf,
    num_xe_cores: u32,
    reserved: [u8; 108],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct PciSpeed {
    size: u32,
    version: u8,
    generation: i32,
    width: i32,
    max_bandwidth: i64,
}

#[repr(C)]
struct PciState {
    size: u32,
    version: u8,
    speed: PciSpeed,
}

/// One telemetry value: `value` holds a `ctl_data_value_t` union of the type in `data_type`.
#[repr(C)]
#[derive(Clone, Copy)]
/// `supported` and the `*_limited` flags are C `bool`s, read as bytes so no value is invalid.
struct Item {
    supported: u8,
    units: i32,
    data_type: i32,
    value: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct PsuInfo {
    supported: u8,
    psu_type: i32,
    energy_counter: Item,
    voltage: Item,
}

#[repr(C)]
struct PowerTelemetry {
    size: u32,
    version: u8,
    time_stamp: Item,
    gpu_energy_counter: Item,
    gpu_voltage: Item,
    gpu_current_clock_frequency: Item,
    gpu_current_temperature: Item,
    global_activity_counter: Item,
    render_compute_activity_counter: Item,
    media_activity_counter: Item,
    gpu_power_limited: u8,
    gpu_temperature_limited: u8,
    gpu_current_limited: u8,
    gpu_voltage_limited: u8,
    gpu_utilization_limited: u8,
    vram_energy_counter: Item,
    vram_voltage: Item,
    vram_current_clock_frequency: Item,
    vram_current_effective_frequency: Item,
    vram_read_bandwidth_counter: Item,
    vram_write_bandwidth_counter: Item,
    vram_current_temperature: Item,
    vram_power_limited: u8,
    vram_temperature_limited: u8,
    vram_current_limited: u8,
    vram_voltage_limited: u8,
    vram_utilization_limited: u8,
    total_card_energy_counter: Item,
    psu: [PsuInfo; 5],
    fan_speed: [Item; 5],
    gpu_vr_temp: Item,
    vram_vr_temp: Item,
    sa_vr_temp: Item,
    gpu_effective_clock: Item,
    gpu_over_voltage_percent: Item,
    gpu_power_percent: Item,
    gpu_temperature_percent: Item,
    vram_read_bandwidth: Item,
    vram_write_bandwidth: Item,
}

// What MSVC lays out for the header (printed by a C probe built against it).
const _: () = {
    assert!(size_of::<InitArgs>() == 36);
    assert!(size_of::<AdapterProperties>() == 320);
    assert!(offset_of!(AdapterProperties, name) == 88);
    assert!(offset_of!(AdapterProperties, adapter_bdf) == 200);
    assert!(size_of::<PciState>() == 32);
    assert!(size_of::<Item>() == 24);
    assert!(size_of::<PowerTelemetry>() == 1024);
    assert!(offset_of!(PowerTelemetry, gpu_energy_counter) == 32);
    assert!(offset_of!(PowerTelemetry, gpu_current_temperature) == 104);
    assert!(offset_of!(PowerTelemetry, vram_current_temperature) == 352);
    assert!(offset_of!(PowerTelemetry, total_card_energy_counter) == 384);
    assert!(offset_of!(PowerTelemetry, psu) == 408);
    assert!(offset_of!(PowerTelemetry, fan_speed) == 688);
    assert!(offset_of!(PowerTelemetry, gpu_vr_temp) == 808);
    assert!(offset_of!(PowerTelemetry, gpu_temperature_percent) == 952);
};

// `ctl_units_t`
const UNITS_VOLTAGE_VOLTS: i32 = 3;
const UNITS_ANGULAR_SPEED_RPM: i32 = 9;
const UNITS_VOLTAGE_MILLIVOLTS: i32 = 13;

impl Item {
    /// The value as a number, if the driver supplies it.
    fn get(&self) -> Option<f64> {
        if self.supported == 0 {
            return None;
        }
        let bits = self.value;
        // `ctl_data_type_t`: the union member is read from the low bytes of its 8.
        let value = match self.data_type {
            0 => bits as u8 as i8 as f64,
            1 => bits as u8 as f64,
            2 => bits as u16 as i16 as f64,
            3 => bits as u16 as f64,
            4 => bits as u32 as i32 as f64,
            5 => bits as u32 as f64,
            6 => bits as i64 as f64,
            7 => bits as f64,
            8 => f32::from_bits(bits as u32) as f64,
            9 => f64::from_bits(bits),
            _ => return None,
        };
        value.is_finite().then_some(value)
    }

    fn millivolts(&self) -> Option<u32> {
        let value = self.get()?;
        match self.units {
            UNITS_VOLTAGE_VOLTS => Some((value * 1000.0).round() as u32),
            UNITS_VOLTAGE_MILLIVOLTS => Some(value.round() as u32),
            _ => None,
        }
    }
}

type InitFn = unsafe extern "C" fn(*mut InitArgs, *mut Handle) -> CtlResult;
type CloseFn = unsafe extern "C" fn(Handle) -> CtlResult;
type EnumerateFn = unsafe extern "C" fn(Handle, *mut u32, *mut Handle) -> CtlResult;
type PropertiesFn = unsafe extern "C" fn(Handle, *mut AdapterProperties) -> CtlResult;
type PciStateFn = unsafe extern "C" fn(Handle, *mut PciState) -> CtlResult;
type TelemetryFn = unsafe extern "C" fn(Handle, *mut PowerTelemetry) -> CtlResult;

struct Device {
    handle: Handle,
    previous: Option<CounterSample>,
}

pub(super) struct Igcl {
    api: Handle,
    close: CloseFn,
    pci_state: PciStateFn,
    telemetry: TelemetryFn,
    /// Keyed by `pci_bus_id`.
    devices: HashMap<String, Device>,
}

// SAFETY: the handles are only used from the thread that owns this value; IGCL documents its calls
// as callable from any thread.
unsafe impl Send for Igcl {}

impl Igcl {
    pub(super) fn load() -> anyhow::Result<Self> {
        // SAFETY: loading the driver's own library, whose initialization has no preconditions.
        let library = unsafe { libloading::Library::new("ControlLib.dll") }?;
        // Never unloaded (the function pointers below point into it). ctlInit leaves work on the
        // process's thread pool that runs after it returns, failed or not: unloading the library
        // when it failed (as on a machine whose only GPUs are not Intel's: 0x40000001) made that
        // work jump into unmapped code and crash the miner, seconds later and only now and then.
        let library: &'static libloading::Library = Box::leak(Box::new(library));
        // SAFETY: the signatures are `igcl_api.h`'s; the pointers are kept with the library.
        let (init, close, enumerate, properties, pci_state, telemetry) = unsafe {
            (
                *library.get::<InitFn>(b"ctlInit\0")?,
                *library.get::<CloseFn>(b"ctlClose\0")?,
                *library.get::<EnumerateFn>(b"ctlEnumerateDevices\0")?,
                *library.get::<PropertiesFn>(b"ctlGetDeviceProperties\0")?,
                *library.get::<PciStateFn>(b"ctlPciGetState\0")?,
                *library.get::<TelemetryFn>(b"ctlPowerTelemetryGet\0")?,
            )
        };
        let mut args = InitArgs {
            size: size_of::<InitArgs>() as u32,
            version: 0,
            app_version: CTL_IMPL_VERSION,
            flags: CTL_INIT_FLAG_USE_LEVEL_ZERO,
            supported_version: 0,
            application_uid: [0; 4],
        };
        let mut api: Handle = std::ptr::null_mut();
        // SAFETY: both pointers are valid for the call.
        let result = unsafe { init(&mut args, &mut api) };
        anyhow::ensure!(result == CTL_RESULT_SUCCESS, "ctlInit returned {result:#x}");
        let mut igcl = Igcl {
            api,
            close,
            pci_state,
            telemetry,
            devices: HashMap::new(),
        };

        let mut count = 0u32;
        // SAFETY: a null array asks for the count.
        unsafe { enumerate(api, &mut count, std::ptr::null_mut()) };
        let mut handles = vec![std::ptr::null_mut(); count as usize];
        // SAFETY: `handles` holds `count` entries.
        let result = unsafe { enumerate(api, &mut count, handles.as_mut_ptr()) };
        anyhow::ensure!(
            result == CTL_RESULT_SUCCESS,
            "ctlEnumerateDevices returned {result:#x}"
        );
        handles.truncate(count as usize);
        for handle in handles {
            // SAFETY: all-zero is a valid value of this plain-data struct.
            let mut props: AdapterProperties = unsafe { std::mem::zeroed() };
            let mut luid = [0u8; 8];
            props.size = size_of::<AdapterProperties>() as u32;
            // Version 2 and up fill `adapter_bdf`.
            props.version = 2;
            props.device_id = luid.as_mut_ptr().cast();
            props.device_id_size = luid.len() as u32;
            // SAFETY: `props` and the LUID buffer it points to outlive the call.
            if unsafe { properties(handle, &mut props) } != CTL_RESULT_SUCCESS {
                continue;
            }
            let bdf = props.adapter_bdf;
            let key = bdf_key(bdf.bus.into(), bdf.device.into(), bdf.function.into());
            igcl.devices.insert(
                key,
                Device {
                    handle,
                    previous: None,
                },
            );
        }
        anyhow::ensure!(!igcl.devices.is_empty(), "no Intel adapters");
        Ok(igcl)
    }

    pub(super) fn knows(&self, pci_bus_id: &str) -> bool {
        self.devices.contains_key(pci_bus_id)
    }

    pub(super) fn refresh(&mut self, gpu: &mut GpuTelemetry) {
        let Some(device) = self.devices.get_mut(&gpu.pci_bus_id) else {
            return;
        };

        // SAFETY: all-zero is a valid value of this plain-data struct.
        let mut pci: PciState = unsafe { std::mem::zeroed() };
        pci.size = size_of::<PciState>() as u32;
        pci.speed.size = size_of::<PciSpeed>() as u32;
        // SAFETY: `pci` is valid for the call.
        if unsafe { (self.pci_state)(device.handle, &mut pci) } == CTL_RESULT_SUCCESS {
            if pci.speed.generation > 0 {
                gpu.pcie_speed = pcie_speed_label(pci.speed.generation as u32);
            }
            if pci.speed.width > 0 {
                gpu.pcie_width = pci.speed.width as u32;
            }
        }

        // SAFETY: all-zero is a valid value of this plain-data struct.
        let mut t: PowerTelemetry = unsafe { std::mem::zeroed() };
        t.size = size_of::<PowerTelemetry>() as u32;
        // Version 1 adds the fields after `fan_speed`.
        t.version = 1;
        // SAFETY: `t` is valid for the call.
        if unsafe { (self.telemetry)(device.handle, &mut t) } != CTL_RESULT_SUCCESS {
            return;
        }

        gpu.temp_edge_c = t.gpu_current_temperature.get();
        gpu.temp_mem_c = t.vram_current_temperature.get();
        gpu.temp_junction_c = None;
        gpu.gpu_clock_mhz = t
            .gpu_current_clock_frequency
            .get()
            .map_or(0, |v| v.round() as u32);
        gpu.mem_clock_mhz = t
            .vram_current_clock_frequency
            .get()
            .map_or(0, |v| v.round() as u32);
        gpu.voltage_mv = t.gpu_voltage.millivolts().unwrap_or(0);
        gpu.fan_rpm = match t.fan_speed[0] {
            fan if fan.units == UNITS_ANGULAR_SPEED_RPM => fan.get().map_or(0, |v| v as u32),
            _ => 0,
        };
        // Not `gpu_utilization_limited`: that is an idle card clocking down for want of work.
        gpu.throttle_reasons = [
            (t.gpu_power_limited != 0, "POWER"),
            (t.gpu_temperature_limited != 0, "THERMAL"),
            (t.gpu_current_limited != 0, "CURRENT"),
            (t.gpu_voltage_limited != 0, "VOLTAGE"),
        ]
        .into_iter()
        .filter(|&(limited, _)| limited)
        .map(|(_, reason)| reason.to_string())
        .collect();

        // The card total where the board reports one; this driver supports it but reads 0.
        let energy = t
            .total_card_energy_counter
            .get()
            .filter(|&joules| joules > 0.0)
            .or_else(|| t.gpu_energy_counter.get());
        let sample = t.time_stamp.get().map(|timestamp| CounterSample {
            timestamp,
            energy,
            busy: t.global_activity_counter.get(),
        });
        if let (Some(now), Some(then)) = (sample, device.previous) {
            let (watts, busy) = now.rates_since(&then);
            gpu.power_watts = watts.unwrap_or(0.0);
            gpu.gpu_usage_percent = busy.unwrap_or(0);
        }
        device.previous = sample;
    }
}

impl Drop for Igcl {
    fn drop(&mut self) {
        // SAFETY: `api` came from ctlInit, and the library is never unloaded.
        unsafe { (self.close)(self.api) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(data_type: i32, units: i32, value: u64) -> Item {
        Item {
            supported: 1,
            units,
            data_type,
            value,
        }
    }

    #[test]
    fn values_are_read_by_their_declared_type() {
        assert_eq!(item(9, 5, 64.0f64.to_bits()).get(), Some(64.0));
        assert_eq!(item(8, 5, 2.5f32.to_bits() as u64).get(), Some(2.5));
        assert_eq!(item(5, 9, 1302).get(), Some(1302.0));
        assert_eq!(item(4, 0, (-3i32) as u32 as u64).get(), Some(-3.0));
        assert_eq!(
            Item {
                supported: 0,
                ..item(9, 5, 1)
            }
            .get(),
            None
        );
        assert_eq!(item(42, 5, 1).get(), None);
    }

    #[test]
    fn voltage_comes_out_in_millivolts_whatever_the_units() {
        assert_eq!(
            item(9, UNITS_VOLTAGE_VOLTS, 1.03f64.to_bits()).millivolts(),
            Some(1030)
        );
        assert_eq!(
            item(9, UNITS_VOLTAGE_MILLIVOLTS, 875.0f64.to_bits()).millivolts(),
            Some(875)
        );
        assert_eq!(item(9, 5, 1.0f64.to_bits()).millivolts(), None);
    }
}
