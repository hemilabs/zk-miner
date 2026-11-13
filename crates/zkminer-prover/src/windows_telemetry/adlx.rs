//! AMD's Device Library eXtra (ADLX), `amdadlx64.dll`.
//!
//! ADLX is a set of COM-style interfaces: each object starts with a pointer to its table of
//! methods, which take the object first and use `__stdcall`. The methods are called by their slot
//! in that table, numbered as in the SDK's C headers (GPUOpen-LibrariesAndSDKs/ADLX 32b5a740,
//! printed with `offsetof` by a C probe built against them).
//!
//! ADLX is started once per process and never stopped: it crashes when started again after
//! `ADLXTerminate`, so the one instance lives for the life of the process.

use super::GpuTelemetry;
use super::{bdf_key, pcie_speed_label};
use std::collections::HashMap;
use std::ffi::c_void;
use std::sync::{Mutex, OnceLock};

type Object = *mut c_void;
type AdlxResult = i32;
const ADLX_OK: AdlxResult = 0;
/// `ADLX_MAKE_FULL_VER(1, 0, 0, 0)`: the interfaces used here are all from ADLX 1.x, and asking
/// for no newer keeps older drivers in reach.
const ADLX_VERSION_1_0: u64 = 1 << 48;
/// `ADLX_GPU_TYPE::GPUTYPE_INTEGRATED`
const GPUTYPE_INTEGRATED: i32 = 1;
/// `ADLX_PCI_BUS_TYPE::PCIE`, generation 1; later generations follow in order.
const PCI_BUS_TYPE_PCIE: i32 = 3;

// Method slots.
const RELEASE: usize = 1;
const QUERY_INTERFACE: usize = 2;
const SYSTEM_GET_GPUS: usize = 1;
const SYSTEM_GET_PERFORMANCE_MONITORING_SERVICES: usize = 9;
const LIST_SIZE: usize = 3;
const GPU_LIST_AT: usize = 11;
const GPU_TYPE: usize = 5;
const GPU_TOTAL_VRAM: usize = 11;
const GPU1_PCI_BUS_TYPE: usize = 19;
const GPU1_PCI_BUS_LANE_WIDTH: usize = 20;
const PERF_GET_CURRENT_GPU_METRICS: usize = 18;
const METRICS_USAGE: usize = 4;
const METRICS_CLOCK_SPEED: usize = 5;
const METRICS_VRAM_CLOCK_SPEED: usize = 6;
const METRICS_TEMPERATURE: usize = 7;
const METRICS_HOTSPOT_TEMPERATURE: usize = 8;
const METRICS_POWER: usize = 9;
const METRICS_TOTAL_BOARD_POWER: usize = 10;
const METRICS_FAN_SPEED: usize = 11;
const METRICS_VRAM: usize = 12;
const METRICS_VOLTAGE: usize = 13;
const METRICS1_MEMORY_TEMPERATURE: usize = 15;
const MAPPING_BDF_FROM_GPU: usize = 2;

/// The method in `slot` of `object`'s table, as a function of type `F`.
///
/// # Safety
/// `object` must be a live ADLX object whose table has a method of type `F` in `slot`.
unsafe fn method<F: Copy>(object: Object, slot: usize) -> F {
    let table = *(object as *const *const *const c_void);
    std::mem::transmute_copy(&*table.add(slot))
}

/// Release one reference to `object`.
///
/// # Safety
/// `object` must be a live, reference-counted ADLX object the caller owns a reference to.
unsafe fn release(object: Object) {
    method::<unsafe extern "system" fn(Object) -> i32>(object, RELEASE)(object);
}

/// Ask `object` for another of its interfaces by name, e.g. `IADLXGPU1`.
///
/// # Safety
/// `object` must be a live ADLX object.
unsafe fn query_interface(object: Object, name: &str) -> Option<Object> {
    let wide: Vec<u16> = name.encode_utf16().chain([0]).collect();
    let mut out: Object = std::ptr::null_mut();
    let f: unsafe extern "system" fn(Object, *const u16, *mut Object) -> AdlxResult =
        method(object, QUERY_INTERFACE);
    (f(object, wide.as_ptr(), &mut out) == ADLX_OK && !out.is_null()).then_some(out)
}

/// Call a getter that writes one value of type `T`.
///
/// # Safety
/// `object` must be a live ADLX object with such a getter in `slot`.
unsafe fn get<T: Default>(object: Object, slot: usize) -> Option<T> {
    let mut value = T::default();
    let f: unsafe extern "system" fn(Object, *mut T) -> AdlxResult = method(object, slot);
    (f(object, &mut value) == ADLX_OK).then_some(value)
}

struct Gpu {
    /// `IADLXGPU`, one reference held.
    gpu: Object,
    /// `IADLXGPU1` (ADLX 1.1 and up), for the PCIe link; one reference held.
    gpu1: Option<Object>,
    vram_bytes: u64,
}

pub(super) struct Adlx {
    /// `IADLXPerformanceMonitoringServices`, one reference held.
    performance: Object,
    /// Keyed by `pci_bus_id`. Discrete GPUs only.
    gpus: HashMap<String, Gpu>,
}

// SAFETY: ADLX's objects may be used from any thread; the Mutex around the one instance keeps
// the calls from overlapping.
unsafe impl Send for Adlx {}

impl Adlx {
    /// The process's ADLX, started on first use.
    pub(super) fn shared() -> anyhow::Result<&'static Mutex<Adlx>> {
        static ADLX: OnceLock<Result<Mutex<Adlx>, String>> = OnceLock::new();
        ADLX.get_or_init(|| Adlx::start().map(Mutex::new).map_err(|e| format!("{e:#}")))
            .as_ref()
            .map_err(|e| anyhow::anyhow!("{e}"))
    }

    fn start() -> anyhow::Result<Self> {
        type Initialize2Fn = unsafe extern "C" fn(u64, *mut Object, *mut Object) -> AdlxResult;
        // SAFETY: loading the driver's own library, whose initialization has no preconditions.
        let library = unsafe { libloading::Library::new("amdadlx64.dll") }?;
        // Never unloaded, as `ControlLib.dll` (igcl.rs): a driver library may leave work on the
        // process's thread pool that outlives a failed initialization, and the objects below
        // point into it.
        let library: &'static libloading::Library = Box::leak(Box::new(library));
        // SAFETY: `ADLXInitialize2_Fn` from ADLX.h. Version 1.1 and later export it.
        let initialize = unsafe { *library.get::<Initialize2Fn>(b"ADLXInitialize2\0")? };
        let mut system: Object = std::ptr::null_mut();
        let mut mapping: Object = std::ptr::null_mut();
        // SAFETY: both out pointers are valid for the call.
        let result = unsafe { initialize(ADLX_VERSION_1_0, &mut system, &mut mapping) };
        anyhow::ensure!(
            result == ADLX_OK && !system.is_null() && !mapping.is_null(),
            "ADLXInitialize2 returned {result}"
        );

        // SAFETY: `system` and `mapping` are live; the slots and signatures are the headers'.
        unsafe {
            let mut performance: Object = std::ptr::null_mut();
            let f: unsafe extern "system" fn(Object, *mut Object) -> AdlxResult =
                method(system, SYSTEM_GET_PERFORMANCE_MONITORING_SERVICES);
            anyhow::ensure!(
                f(system, &mut performance) == ADLX_OK && !performance.is_null(),
                "no performance monitoring services"
            );

            let mut list: Object = std::ptr::null_mut();
            let f: unsafe extern "system" fn(Object, *mut Object) -> AdlxResult =
                method(system, SYSTEM_GET_GPUS);
            if f(system, &mut list) != ADLX_OK || list.is_null() {
                release(performance);
                anyhow::bail!("no GPU list");
            }
            let size: unsafe extern "system" fn(Object) -> u32 = method(list, LIST_SIZE);
            let at: unsafe extern "system" fn(Object, u32, *mut Object) -> AdlxResult =
                method(list, GPU_LIST_AT);
            let bdf_from_gpu: unsafe extern "system" fn(
                Object,
                Object,
                *mut i32,
                *mut i32,
                *mut i32,
            ) -> AdlxResult = method(mapping, MAPPING_BDF_FROM_GPU);

            let mut gpus = HashMap::new();
            for i in 0..size(list) {
                let mut gpu: Object = std::ptr::null_mut();
                if at(list, i, &mut gpu) != ADLX_OK || gpu.is_null() {
                    continue;
                }
                let (mut bus, mut device, mut function) = (0, 0, 0);
                let integrated = get::<i32>(gpu, GPU_TYPE) == Some(GPUTYPE_INTEGRATED);
                if integrated
                    || bdf_from_gpu(mapping, gpu, &mut bus, &mut device, &mut function) != ADLX_OK
                {
                    release(gpu);
                    continue;
                }
                let key = bdf_key(bus as u32, device as u32, function as u32);
                let vram_bytes =
                    get::<u32>(gpu, GPU_TOTAL_VRAM).map_or(0, |mb| u64::from(mb) << 20);
                let gpu1 = query_interface(gpu, "IADLXGPU1");
                gpus.insert(
                    key,
                    Gpu {
                        gpu,
                        gpu1,
                        vram_bytes,
                    },
                );
            }
            release(list);
            Ok(Adlx {
                performance,
                gpus,
            })
        }
    }

    pub(super) fn refresh(&mut self, gpu: &mut GpuTelemetry) {
        let Some(card) = self.gpus.get(&gpu.pci_bus_id) else {
            return;
        };
        if gpu.vram_total_bytes == 0 {
            gpu.vram_total_bytes = card.vram_bytes;
        }
        // SAFETY: every object here is live and held; the slots and signatures are the headers'.
        unsafe {
            if let Some(gpu1) = card.gpu1 {
                if let Some(bus) = get::<i32>(gpu1, GPU1_PCI_BUS_TYPE) {
                    if bus >= PCI_BUS_TYPE_PCIE {
                        gpu.pcie_speed = pcie_speed_label((bus - PCI_BUS_TYPE_PCIE + 1) as u32);
                    }
                }
                if let Some(lanes) = get::<u32>(gpu1, GPU1_PCI_BUS_LANE_WIDTH) {
                    gpu.pcie_width = lanes;
                }
            }

            let mut metrics: Object = std::ptr::null_mut();
            let f: unsafe extern "system" fn(Object, Object, *mut Object) -> AdlxResult =
                method(self.performance, PERF_GET_CURRENT_GPU_METRICS);
            if f(self.performance, card.gpu, &mut metrics) != ADLX_OK || metrics.is_null() {
                return;
            }
            gpu.gpu_usage_percent = get::<f64>(metrics, METRICS_USAGE)
                .map_or(0, |p| p.round().clamp(0.0, 100.0) as u32);
            gpu.gpu_clock_mhz =
                get::<i32>(metrics, METRICS_CLOCK_SPEED).map_or(0, |v| v.max(0) as u32);
            gpu.mem_clock_mhz =
                get::<i32>(metrics, METRICS_VRAM_CLOCK_SPEED).map_or(0, |v| v.max(0) as u32);
            gpu.temp_edge_c = get::<f64>(metrics, METRICS_TEMPERATURE);
            gpu.temp_junction_c = get::<f64>(metrics, METRICS_HOTSPOT_TEMPERATURE);
            gpu.temp_mem_c = query_interface(metrics, "IADLXGPUMetrics1").and_then(|metrics1| {
                let temp = get::<f64>(metrics1, METRICS1_MEMORY_TEMPERATURE);
                release(metrics1);
                temp
            });
            // The whole board where the card reports it (RDNA 3 and later), else the chip.
            gpu.power_watts = get::<f64>(metrics, METRICS_TOTAL_BOARD_POWER)
                .or_else(|| get::<f64>(metrics, METRICS_POWER))
                .unwrap_or(0.0);
            gpu.fan_rpm = get::<i32>(metrics, METRICS_FAN_SPEED).map_or(0, |v| v.max(0) as u32);
            gpu.vram_used_bytes =
                get::<i32>(metrics, METRICS_VRAM).map_or(0, |mb| (mb.max(0) as u64) << 20);
            gpu.voltage_mv = get::<i32>(metrics, METRICS_VOLTAGE).map_or(0, |v| v.max(0) as u32);
            release(metrics);
        }
    }
}
