//! The HIP devices this process sees, from the HIP runtime itself (ROCm builds).
//!
//! `--list-hip-devices` prints them for the host's GPU discovery on Windows, which has neither
//! `rocm-smi` nor sysfs: only the runtime knows its own device order, which is what
//! `HIP_VISIBLE_DEVICES` selects by, and which devices are integrated GPUs. And each device's
//! target (`gfx1201`), which the host checks this binary carries code for before advertising it.

use std::ffi::{c_char, c_int, CStr};

/// `hipDeviceAttributeIntegrated` (hip_runtime_api.h): in the CUDA-compatible block of
/// `hipDeviceAttribute_t`, whose values are fixed.
const HIP_DEVICE_ATTRIBUTE_INTEGRATED: c_int = 16;

/// `hipDeviceProp_tR0600` (hip_runtime_api.h, HIP 6.0 and later, what `hipGetDeviceProperties`
/// names there): 1472 bytes, with `char gcnArchName[256]` at byte 1160 (`offsetof` against the
/// HIP SDK 7.2 headers). Only that field is read, so the struct is not mirrored field by field;
/// the buffer is larger than the struct, so a runtime that wrote a longer one could not overrun it.
const HIP_DEVICE_PROP_R0600_SIZE: usize = 1472;
const HIP_DEVICE_PROP_R0600_GCN_ARCH_NAME: usize = 1160;

#[repr(C, align(8))]
struct DeviceProps([u8; 2 * HIP_DEVICE_PROP_R0600_SIZE]);

extern "C" {
    fn hipGetDeviceCount(count: *mut c_int) -> c_int;
    fn hipDeviceGetAttribute(value: *mut c_int, attr: c_int, device: c_int) -> c_int;
    fn hipDeviceGetPCIBusId(bus_id: *mut c_char, len: c_int, device: c_int) -> c_int;
    fn hipDeviceGetName(name: *mut c_char, len: c_int, device: c_int) -> c_int;
    fn hipDeviceTotalMem(bytes: *mut usize, device: c_int) -> c_int;
    fn hipGetDevicePropertiesR0600(props: *mut DeviceProps, device: c_int) -> c_int;
}

pub struct HipDevice {
    pub index: u32,
    /// "0000:03:00.0", lowercase.
    pub pci_bus_id: String,
    pub integrated: bool,
    pub total_mem: u64,
    pub name: String,
    /// `gcnArchName` as the runtime reports it, feature flags and all
    /// (`gfx1201`, `gfx90a:sramecc+:xnack-`); `None` if the properties could not be read.
    pub gcn_arch_name: Option<String>,
}

/// Device `device`'s `gcnArchName`, or `None` if the runtime would not report it.
///
/// # Safety
/// `device` must be a valid HIP device ordinal.
unsafe fn gcn_arch_name(device: c_int) -> Option<String> {
    let mut props = Box::new(DeviceProps([0; 2 * HIP_DEVICE_PROP_R0600_SIZE]));
    if hipGetDevicePropertiesR0600(&mut *props, device) != 0 {
        return None;
    }
    let field = &props.0[HIP_DEVICE_PROP_R0600_GCN_ARCH_NAME..][..256];
    let name = CStr::from_bytes_until_nul(field)
        .ok()?
        .to_str()
        .ok()?
        .trim();
    (!name.is_empty()).then(|| name.to_string())
}

/// The HIP devices in the runtime's order, or the HIP error that stopped the enumeration.
pub fn devices() -> Result<Vec<HipDevice>, String> {
    let mut count: c_int = 0;
    // SAFETY: plain HIP runtime queries into locals sized as each call is told.
    unsafe {
        let err = hipGetDeviceCount(&mut count);
        if err != 0 {
            return Err(format!("hipGetDeviceCount failed: {err}"));
        }
        let mut devices = Vec::with_capacity(count.max(0) as usize);
        for device in 0..count {
            let mut integrated: c_int = 0;
            let mut bus = [0 as c_char; 64];
            let mut name = [0 as c_char; 256];
            let mut total_mem: usize = 0;
            let errs = [
                hipDeviceGetAttribute(&mut integrated, HIP_DEVICE_ATTRIBUTE_INTEGRATED, device),
                hipDeviceGetPCIBusId(bus.as_mut_ptr(), bus.len() as c_int, device),
                hipDeviceGetName(name.as_mut_ptr(), name.len() as c_int, device),
                hipDeviceTotalMem(&mut total_mem, device),
            ];
            if let Some(err) = errs.iter().find(|&&e| e != 0) {
                return Err(format!("querying HIP device {device} failed: {err}"));
            }
            devices.push(HipDevice {
                index: device as u32,
                pci_bus_id: CStr::from_ptr(bus.as_ptr())
                    .to_string_lossy()
                    .to_lowercase(),
                integrated: integrated != 0,
                total_mem: total_mem as u64,
                name: CStr::from_ptr(name.as_ptr()).to_string_lossy().into_owned(),
                gcn_arch_name: gcn_arch_name(device),
            });
        }
        Ok(devices)
    }
}

/// Print `index|pci_bus_id|integrated|total_mem|name` per device on stdout (the format the
/// host's `parse_hip_device_list` reads), each followed by `arch|pci_bus_id|gcnArchName` where the
/// runtime reports the target (`parse_hip_arch_list`; a host that predates it skips the line, as
/// its first field is no index); exit non-zero if HIP cannot enumerate.
pub fn print_devices() {
    match devices() {
        Ok(devices) => {
            for d in devices {
                println!(
                    "{}|{}|{}|{}|{}",
                    d.index,
                    d.pci_bus_id,
                    u8::from(d.integrated),
                    d.total_mem,
                    d.name
                );
                if let Some(arch) = &d.gcn_arch_name {
                    println!("arch|{}|{arch}", d.pci_bus_id);
                }
            }
        }
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    }
}
