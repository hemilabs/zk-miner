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
//!   `zkminer-prove-{backend}-intel` → gpu_tag = "intel"
//!   `zkminer-prove-{backend}-metal` → gpu_tag = "metal" (macOS, Apple silicon)
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
const GPU_TAGS: &[&str] = &["cuda", "rocm", "intel", "metal", "generic"];

/// A detected physical GPU.
#[derive(Debug, Clone)]
pub struct DetectedGpu {
    /// "cuda", "rocm", "intel" or "metal"
    pub gpu_tag: String,
    /// Sequential index within vendor (0, 1, ...)
    pub device_index: u32,
    /// PCI bus ID, e.g. "0000:01:00.0" — used for *_VISIBLE_DEVICES. An Apple GPU is not on PCI
    /// and gets the stable pseudo id [`APPLE_GPU_PSEUDO_BUS_ID`].
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
    /// GPU variant: "cuda", "rocm", "intel", "metal", or "generic".
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

/// Detect all physical GPUs (NVIDIA + AMD + Intel, and Apple on macOS).
pub fn detect_all_gpus() -> Vec<DetectedGpu> {
    detect_all_gpus_with(&HashMap::new(), &[], &|_| {})
}

/// `detect_all_gpus`, also looking for the HIP probe (see `detect_amd_gpus_windows`) where
/// `discover_workers` looks for worker binaries: `explicit_binaries` and `search_dirs`. `report` is
/// told which vendor it is checking.
fn detect_all_gpus_with(
    explicit_binaries: &HashMap<String, PathBuf>,
    search_dirs: &[PathBuf],
    report: &dyn Fn(&str),
) -> Vec<DetectedGpu> {
    let mut gpus = Vec::new();

    report("Looking for NVIDIA GPUs");
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

    report("Looking for AMD GPUs");
    #[cfg(windows)]
    let amd = detect_amd_gpus_windows(explicit_binaries, search_dirs);
    #[cfg(not(windows))]
    let amd = {
        let _ = (explicit_binaries, search_dirs);
        detect_amd_gpus()
    };
    if !amd.is_empty() {
        let names: Vec<_> = amd
            .iter()
            .map(|g| format!("[{}] {} ({})", g.device_index, g.name, g.pci_bus_id))
            .collect();
        tracing::info!("Detected {} AMD GPU(s): {}", amd.len(), names.join(", "));
        warn_if_inaccessible(&[Path::new("/dev/kfd")], "AMD");
        gpus.extend(amd);
    }

    report("Looking for Intel GPUs");
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
        let render_nodes: Vec<PathBuf> = std::fs::read_dir("/dev/dri")
            .into_iter()
            .flatten()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().starts_with("renderD"))
            .map(|e| e.path())
            .collect();
        let render_nodes: Vec<&Path> = render_nodes.iter().map(PathBuf::as_path).collect();
        warn_if_inaccessible(&render_nodes, "Intel");
        gpus.extend(intel);
    }

    #[cfg(target_os = "macos")]
    {
        let apple = detect_apple_gpus();
        if !apple.is_empty() {
            let names: Vec<_> = apple
                .iter()
                .map(|g| format!("[{}] {} ({})", g.device_index, g.name, g.pci_bus_id))
                .collect();
            tracing::info!(
                "Detected {} Apple GPU(s): {}",
                apple.len(),
                names.join(", ")
            );
            gpus.extend(apple);
        }
    }

    gpus
}

/// The pseudo PCI bus id of the Apple GPU. Apple silicon's GPU sits on the SoC, not on PCI, but
/// everything downstream (benchmark rows' `pci_bus_id`, cache migration, the dashboard) keys a card
/// by this string, so it must be non-empty and stable across runs. It contains no `:`, so
/// `normalize_pci_bus_id` leaves it alone and it can never equal a real bus id.
pub const APPLE_GPU_PSEUDO_BUS_ID: &str = "apple-gpu0";

/// Detect the Apple silicon GPU on macOS: exactly one, device index 0, which is the device
/// `MTLCreateSystemDefaultDevice` returns and the only one the risc0 Metal HAL drives.
///
/// `system_profiler SPDisplaysDataType -json` names it (bounded by `GPU_TOOL_TIMEOUT` like
/// `nvidia-smi` and `rocm-smi`; it took 0.16 s on an M5 Max). If that does not answer, the SoC's
/// brand string (`sysctl machdep.cpu.brand_string`, e.g. "Apple M5 Max") is the same name, since the
/// GPU is part of the chip. An Intel Mac reports neither as Apple and gets no entry: the Metal port
/// targets Apple silicon only. No compute capability: that is a CUDA notion.
#[cfg(target_os = "macos")]
fn detect_apple_gpus() -> Vec<DetectedGpu> {
    let (outcome, stdout) = zkminer_prover_protocol::proc::output_with_timeout_capturing_stdout(
        std::process::Command::new("system_profiler").args(["SPDisplaysDataType", "-json"]),
        GPU_TOOL_TIMEOUT,
        1024 * 1024,
    );
    let from_profiler = if matches!(
        outcome,
        zkminer_prover_protocol::proc::Outcome::Ran { success: true, .. }
    ) {
        if let Some(cores) = apple_gpu_cores_from_profiler_json(&stdout) {
            let _ = APPLE_GPU_CORES.set(cores);
        }
        apple_gpu_name_from_profiler_json(&stdout)
    } else {
        tracing::warn!(
            "system_profiler did not answer ({}); naming the Apple GPU after the chip",
            outcome.describe()
        );
        None
    };
    let name = from_profiler.or_else(|| {
        crate::memory::sysctl_string("machdep.cpu.brand_string").filter(|b| b.starts_with("Apple"))
    });
    match name {
        Some(name) => vec![apple_gpu(name)],
        None => Vec::new(),
    }
}

/// Where the owner-activity reading comes from (W7-M10), so the tier logic can be tested with a
/// fake one. [`MacOwnerSource`] is the real one.
pub trait OwnerSource {
    /// Time since the last keyboard, mouse or trackpad input.
    fn hid_idle(&self) -> Option<std::time::Duration>;
    /// Whether the main display is asleep.
    fn display_asleep(&self) -> Option<bool>;
    /// On battery power.
    fn on_battery(&self) -> Option<bool>;
    /// Low Power Mode.
    fn low_power_mode(&self) -> Option<bool>;
}

/// One owner reading from `source`.
pub fn read_owner(source: &dyn OwnerSource) -> crate::metal_sizing::OwnerReading {
    crate::metal_sizing::OwnerReading {
        hid_idle: source.hid_idle(),
        display_asleep: source.display_asleep(),
        on_battery: source.on_battery(),
        low_power_mode: source.low_power_mode(),
    }
}

/// The owner reading of this Mac now ([`MacOwnerSource`]); all `None` off macOS.
pub fn owner_reading() -> crate::metal_sizing::OwnerReading {
    read_owner(&MacOwnerSource)
}

/// W7-M11: this host's power state now, in the form a worker's benchmark entry carries it
/// (`BenchmarkEntry::power_state`): Low Power Mode, battery, `NSProcessInfo.thermalState`. All
/// `None` off macOS. `benchmark::load_cached_benchmark` compares it with a cached suite's marks.
pub fn host_power_state() -> zkminer_prover_protocol::BenchPowerState {
    #[cfg(target_os = "macos")]
    {
        zkminer_prover_protocol::BenchPowerState {
            low_power_mode: mac_owner::low_power_mode(),
            on_battery: mac_owner::on_battery(),
            thermal: mac_owner::thermal_state(),
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        zkminer_prover_protocol::BenchPowerState::default()
    }
}

/// The real owner-activity source. Every probe works as an ordinary user, with no entitlement and
/// no sudo:
/// - IOKit `IOHIDSystem`'s `HIDIdleTime` (nanoseconds since the last HID event; what `ioreg -c
///   IOHIDSystem` prints);
/// - CoreGraphics `CGDisplayIsAsleep(CGMainDisplayID())`;
/// - IOKit's power-source type ("Battery Power"), as M9's worker power guard reads it;
/// - `NSProcessInfo.isLowPowerModeEnabled` (macOS 12+), as M9's power guard reads it.
pub struct MacOwnerSource;

#[cfg(not(target_os = "macos"))]
impl OwnerSource for MacOwnerSource {
    fn hid_idle(&self) -> Option<std::time::Duration> {
        None
    }
    fn display_asleep(&self) -> Option<bool> {
        None
    }
    fn on_battery(&self) -> Option<bool> {
        None
    }
    fn low_power_mode(&self) -> Option<bool> {
        None
    }
}

#[cfg(target_os = "macos")]
mod mac_owner {
    use std::ffi::{c_char, c_void, CStr};

    type CFTypeRef = *const c_void;

    #[link(name = "IOKit", kind = "framework")]
    extern "C" {
        fn IOServiceMatching(name: *const c_char) -> *mut c_void;
        fn IOServiceGetMatchingService(main_port: u32, matching: *mut c_void) -> u32;
        fn IORegistryEntryCreateCFProperty(
            entry: u32,
            key: CFTypeRef,
            allocator: CFTypeRef,
            options: u32,
        ) -> CFTypeRef;
        fn IOObjectRelease(object: u32) -> i32;
        fn IOPSCopyPowerSourcesInfo() -> CFTypeRef;
        fn IOPSGetProvidingPowerSourceType(blob: CFTypeRef) -> CFTypeRef;
    }
    #[link(name = "CoreFoundation", kind = "framework")]
    extern "C" {
        fn CFStringCreateWithCString(alloc: CFTypeRef, s: *const c_char, enc: u32) -> CFTypeRef;
        fn CFStringGetCString(s: CFTypeRef, buf: *mut c_char, size: isize, enc: u32) -> u8;
        fn CFRelease(cf: CFTypeRef);
        fn CFGetTypeID(cf: CFTypeRef) -> usize;
        fn CFNumberGetTypeID() -> usize;
        fn CFDataGetTypeID() -> usize;
        fn CFNumberGetValue(number: CFTypeRef, the_type: isize, out: *mut c_void) -> u8;
        fn CFDataGetLength(data: CFTypeRef) -> isize;
        fn CFDataGetBytePtr(data: CFTypeRef) -> *const u8;
    }
    #[link(name = "CoreGraphics", kind = "framework")]
    extern "C" {
        fn CGMainDisplayID() -> u32;
        fn CGDisplayIsAsleep(display: u32) -> u32;
    }
    #[link(name = "Foundation", kind = "framework")]
    extern "C" {
        // Referenced so Foundation (NSProcessInfo) is linked and loaded.
        static NSFoundationVersionNumber: f64;
    }
    #[link(name = "objc")]
    extern "C" {
        fn objc_getClass(name: *const c_char) -> *mut c_void;
        fn sel_registerName(name: *const c_char) -> *mut c_void;
        fn objc_msgSend();
    }

    const UTF8: u32 = 0x0800_0100;
    const K_CF_NUMBER_SINT64: isize = 4;

    /// `HIDIdleTime` of IOHIDSystem, in nanoseconds.
    pub fn hid_idle_ns() -> Option<u64> {
        // SAFETY: IOKit registry API. `IOServiceGetMatchingService` consumes the matching dict;
        // the service and the property are released here (Create/Copy rule).
        unsafe {
            let matching = IOServiceMatching(c"IOHIDSystem".as_ptr());
            if matching.is_null() {
                return None;
            }
            let service = IOServiceGetMatchingService(0, matching);
            if service == 0 {
                return None;
            }
            let key = CFStringCreateWithCString(std::ptr::null(), c"HIDIdleTime".as_ptr(), UTF8);
            let prop = if key.is_null() {
                std::ptr::null()
            } else {
                IORegistryEntryCreateCFProperty(service, key, std::ptr::null(), 0)
            };
            if !key.is_null() {
                CFRelease(key);
            }
            IOObjectRelease(service);
            if prop.is_null() {
                return None;
            }
            let ty = CFGetTypeID(prop);
            let mut ns: Option<u64> = None;
            if ty == CFNumberGetTypeID() {
                let mut v: i64 = 0;
                if CFNumberGetValue(prop, K_CF_NUMBER_SINT64, (&mut v as *mut i64).cast()) != 0 {
                    ns = u64::try_from(v).ok();
                }
            } else if ty == CFDataGetTypeID() && CFDataGetLength(prop) == 8 {
                let p = CFDataGetBytePtr(prop);
                if !p.is_null() {
                    ns = Some(u64::from_ne_bytes(
                        std::slice::from_raw_parts(p, 8).try_into().ok()?,
                    ));
                }
            }
            CFRelease(prop);
            ns
        }
    }

    /// Whether the main display is asleep; `None` on a Mac with no display.
    pub fn display_asleep() -> Option<bool> {
        // SAFETY: plain CoreGraphics queries.
        unsafe {
            let d = CGMainDisplayID();
            (d != 0).then(|| CGDisplayIsAsleep(d) != 0)
        }
    }

    /// The providing power source is the battery.
    pub fn on_battery() -> Option<bool> {
        // SAFETY: IOKit power-source API; the blob is released after use, and the source-type
        // string is owned by the blob (Get rule), read before the release.
        unsafe {
            let blob = IOPSCopyPowerSourcesInfo();
            if blob.is_null() {
                return None;
            }
            let ty = IOPSGetProvidingPowerSourceType(blob);
            let mut buf = [0 as c_char; 64];
            let ok = !ty.is_null()
                && CFStringGetCString(ty, buf.as_mut_ptr(), buf.len() as isize, UTF8) != 0;
            let text = ok.then(|| CStr::from_ptr(buf.as_ptr()).to_string_lossy().into_owned());
            CFRelease(blob);
            text.map(|t| t == "Battery Power")
        }
    }

    /// `[[NSProcessInfo processInfo] thermalState]` (0 nominal .. 3 critical).
    pub fn thermal_state() -> Option<u8> {
        type MsgId = unsafe extern "C" fn(*mut c_void, *mut c_void) -> *mut c_void;
        type MsgInt = unsafe extern "C" fn(*mut c_void, *mut c_void) -> isize;
        // SAFETY: as in `low_power_mode`: `objc_msgSend` through each message's real signature;
        // `thermalState` (macOS 10.10.3+) returns an NSInteger; the shared instance is not owned.
        unsafe {
            if NSFoundationVersionNumber <= 0.0 {
                return None;
            }
            let class = objc_getClass(c"NSProcessInfo".as_ptr());
            if class.is_null() {
                return None;
            }
            let send = objc_msgSend as unsafe extern "C" fn();
            let id: MsgId = std::mem::transmute(send);
            let int: MsgInt = std::mem::transmute(send);
            let info = id(class, sel_registerName(c"processInfo".as_ptr()));
            if info.is_null() {
                return None;
            }
            let t = int(info, sel_registerName(c"thermalState".as_ptr()));
            (0..=3).contains(&t).then_some(t as u8)
        }
    }

    /// `[[NSProcessInfo processInfo] isLowPowerModeEnabled]`, when the OS has it.
    pub fn low_power_mode() -> Option<bool> {
        type MsgId = unsafe extern "C" fn(*mut c_void, *mut c_void) -> *mut c_void;
        type MsgBool = unsafe extern "C" fn(*mut c_void, *mut c_void) -> bool;
        type MsgRespond = unsafe extern "C" fn(*mut c_void, *mut c_void, *mut c_void) -> bool;
        // SAFETY: `objc_msgSend` is called through the function type of each message's real
        // signature (arm64 requires the cast); the shared NSProcessInfo instance is not owned.
        unsafe {
            if NSFoundationVersionNumber <= 0.0 {
                return None;
            }
            let class = objc_getClass(c"NSProcessInfo".as_ptr());
            if class.is_null() {
                return None;
            }
            let send = objc_msgSend as unsafe extern "C" fn();
            let id: MsgId = std::mem::transmute(send);
            let boolean: MsgBool = std::mem::transmute(send);
            let respond: MsgRespond = std::mem::transmute(send);
            let info = id(class, sel_registerName(c"processInfo".as_ptr()));
            if info.is_null() {
                return None;
            }
            let lpm = sel_registerName(c"isLowPowerModeEnabled".as_ptr());
            if !respond(info, sel_registerName(c"respondsToSelector:".as_ptr()), lpm) {
                return None;
            }
            Some(boolean(info, lpm))
        }
    }
}

#[cfg(target_os = "macos")]
impl OwnerSource for MacOwnerSource {
    fn hid_idle(&self) -> Option<std::time::Duration> {
        mac_owner::hid_idle_ns().map(std::time::Duration::from_nanos)
    }
    fn display_asleep(&self) -> Option<bool> {
        mac_owner::display_asleep()
    }
    fn on_battery(&self) -> Option<bool> {
        mac_owner::on_battery()
    }
    fn low_power_mode(&self) -> Option<bool> {
        mac_owner::low_power_mode()
    }
}

/// The Apple GPU's core count (`sppci_cores`), recorded when discovery ran `system_profiler`.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
static APPLE_GPU_CORES: std::sync::OnceLock<u32> = std::sync::OnceLock::new();

/// This Mac's GPU core count, if discovery read it (macOS only; `None` elsewhere or before
/// discovery). Read at runtime, never assumed: the dev machine reports 32, the minimum tier 7-10
/// (PLAN 9.1). Used to scale the Metal benchmark's deadline (`dispatcher::metal_benchmark_timeout`).
pub fn apple_gpu_cores() -> Option<u32> {
    APPLE_GPU_CORES.get().copied()
}

/// `sppci_cores` of the first Apple GPU in `system_profiler SPDisplaysDataType -json` output.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn apple_gpu_cores_from_profiler_json(json: &str) -> Option<u32> {
    let v: serde_json::Value = serde_json::from_str(json).ok()?;
    v.get("SPDisplaysDataType")?
        .as_array()?
        .iter()
        .filter(|gpu| {
            gpu.get("spdisplays_vendor")
                .and_then(|x| x.as_str())
                .is_some_and(|v| v.to_ascii_lowercase().contains("apple"))
                || gpu
                    .get("sppci_model")
                    .and_then(|x| x.as_str())
                    .is_some_and(|m| m.starts_with("Apple"))
        })
        .find_map(|gpu| gpu.get("sppci_cores")?.as_str()?.trim().parse::<u32>().ok())
        .filter(|&c| c > 0)
}

/// The single Apple GPU entry, given its name.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn apple_gpu(name: String) -> DetectedGpu {
    DetectedGpu {
        gpu_tag: "metal".to_string(),
        device_index: 0,
        pci_bus_id: APPLE_GPU_PSEUDO_BUS_ID.to_string(),
        name,
        compute_cap: None,
    }
}

/// The name of the first Apple-made GPU in `system_profiler SPDisplaysDataType -json` output, or
/// `None` when there is none (an Intel Mac's AMD or Intel GPU is skipped) or the JSON is not the
/// expected shape. Split out so the parse is testable without a Mac.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn apple_gpu_name_from_profiler_json(json: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(json).ok()?;
    v.get("SPDisplaysDataType")?
        .as_array()?
        .iter()
        .filter(|gpu| {
            let vendor = gpu.get("spdisplays_vendor").and_then(|x| x.as_str());
            let model = gpu.get("sppci_model").and_then(|x| x.as_str());
            vendor.is_some_and(|v| v.to_ascii_lowercase().contains("apple"))
                || model.is_some_and(|m| m.starts_with("Apple"))
        })
        .find_map(|gpu| {
            ["sppci_model", "_name"]
                .iter()
                .filter_map(|k| gpu.get(*k).and_then(|x| x.as_str()))
                .map(str::trim)
                .find(|n| !n.is_empty())
                .map(str::to_string)
        })
}

/// Says so, once, when this user cannot open the device nodes an AMD (`/dev/kfd`) or Intel
/// (`/dev/dri/renderD*`) worker needs. They are `root:render`, mode 0660: a desktop session's user
/// is let in by its seat, but a service, a cron job or an SSH session needs the user in `render`,
/// and without it every worker on those cards fails to start, with only the runtime's own error.
#[cfg(unix)]
fn warn_if_inaccessible(nodes: &[&Path], vendor: &str) {
    use std::os::unix::ffi::OsStrExt;
    let denied: Vec<String> = nodes
        .iter()
        .filter(|node| {
            let Ok(path) = std::ffi::CString::new(node.as_os_str().as_bytes()) else {
                return false;
            };
            // access(2) checks the real user and all its groups, as opening the node would.
            let status = unsafe { libc::access(path.as_ptr(), libc::R_OK | libc::W_OK) };
            status != 0
        })
        .map(|node| node.display().to_string())
        .collect();
    if !denied.is_empty() && denied.len() == nodes.len() {
        tracing::warn!(
            "{vendor} GPU(s) found, but this user cannot open {}: their workers will fail to \
             start. Add the user to the `render` group (`sudo usermod -aG render $USER`, then log \
             in again): a desktop session is let in, a service or SSH session is not.",
            denied.join(", ")
        );
    }
}

#[cfg(not(unix))]
fn warn_if_inaccessible(_nodes: &[&Path], _vendor: &str) {}

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
    // Cards `ZKMINER_GPU_NAME_FILTER` left out: an empty list because of them is the operator's
    // choice, not an unparseable probe, and must not fall back to /proc (which would bring them back).
    let mut filtered_out = 0usize;

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
        if !passes_gpu_name_filter(&name) {
            filtered_out += 1;
            continue;
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
    if gpus.is_empty() && saw_nonempty_line && filtered_out == 0 {
        tracing::warn!(
            "nvidia-smi produced output but no GPUs were parsed; falling back to /proc detection"
        );
        return None;
    }

    Some(gpus)
}

/// `ZKMINER_GPU_NAME_FILTER` (a case-insensitive substring of the GPU name; unset or empty keeps every
/// card): whether an NVIDIA card named `name` is kept.
fn passes_gpu_name_filter(name: &str) -> bool {
    match std::env::var("ZKMINER_GPU_NAME_FILTER") {
        Ok(filter) if !filter.is_empty() => name.to_lowercase().contains(&filter.to_lowercase()),
        _ => true,
    }
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
        // The same filter as the nvidia-smi path, which this one stands in for. The index stays the
        // card's position among them all, as there.
        if !model.is_empty() && !passes_gpu_name_filter(&model) {
            continue;
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

/// Detect Intel discrete GPUs: from sysfs on Linux, from the PnP display devices on Windows.
fn detect_intel_gpus() -> Vec<DetectedGpu> {
    #[cfg(windows)]
    {
        detect_intel_gpus_windows()
    }
    #[cfg(not(windows))]
    {
        detect_intel_gpus_sysfs()
    }
}

/// PowerShell that lists the PnP display devices as `name|PNPDeviceID|location|memory` lines:
/// the location is `DEVPKEY_Device_LocationInfo` ("PCI bus 3, device 0, function 0"), the memory
/// the adapter's `HardwareInformation.qwMemorySize` from its driver key (bytes; empty if absent).
/// (WMI's `AdapterRAM` is a 32-bit field, capped at 4 GiB.)
#[cfg(any(windows, test))]
const WINDOWS_DISPLAY_DEVICES_PS: &str = r#"Get-CimInstance Win32_PnPEntity -Filter "PNPClass='Display'" | ForEach-Object { $loc = (Get-PnpDeviceProperty -InstanceId $_.PNPDeviceID -KeyName DEVPKEY_Device_LocationInfo -ErrorAction SilentlyContinue).Data; $drv = (Get-PnpDeviceProperty -InstanceId $_.PNPDeviceID -KeyName DEVPKEY_Device_Driver -ErrorAction SilentlyContinue).Data; $mem = ''; if ($drv) { $mem = (Get-ItemProperty ('HKLM:\SYSTEM\CurrentControlSet\Control\Class\' + $drv) -ErrorAction SilentlyContinue).'HardwareInformation.qwMemorySize' }; '{0}|{1}|{2}|{3}' -f $_.Name, $_.PNPDeviceID, $loc, $mem }"#;

/// Detect Intel discrete GPUs on Windows, which has no sysfs: list the PnP display devices
/// through PowerShell and keep Intel's discrete parts (see `parse_windows_intel_gpus`).
#[cfg(windows)]
fn detect_intel_gpus_windows() -> Vec<DetectedGpu> {
    query_windows_intel_gpus()
        .into_iter()
        .map(|(gpu, _)| gpu)
        .collect()
}

/// The VRAM of Intel GPU `device_index` (as numbered by `detect_intel_gpus`), where the platform
/// reports it: on Windows, from the adapter's driver key. `None` elsewhere or if unknown.
pub fn intel_vram_bytes(device_index: u32) -> Option<u64> {
    #[cfg(windows)]
    {
        query_windows_intel_gpus()
            .into_iter()
            .find(|(gpu, _)| gpu.device_index == device_index)
            .and_then(|(_, vram)| vram)
    }
    #[cfg(not(windows))]
    {
        let _ = device_index;
        None
    }
}

/// The Intel discrete GPUs on Windows with their VRAM (see `WINDOWS_DISPLAY_DEVICES_PS`).
#[cfg(windows)]
fn query_windows_intel_gpus() -> Vec<(DetectedGpu, Option<u64>)> {
    run_windows_display_devices_ps("Intel GPUs")
        .map(|stdout| parse_windows_intel_gpus_with_vram(&stdout))
        .unwrap_or_default()
}

/// The output of `WINDOWS_DISPLAY_DEVICES_PS`, or `None` (logged, as listing them for `what`) if
/// it failed or timed out.
#[cfg(windows)]
fn run_windows_display_devices_ps(what: &str) -> Option<String> {
    // PowerShell's own start-up takes a second or so: allow it more than a GPU tool.
    let (outcome, stdout) = zkminer_prover_protocol::proc::output_with_timeout_capturing_stdout(
        std::process::Command::new("powershell").args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            WINDOWS_DISPLAY_DEVICES_PS,
        ]),
        GPU_TOOL_TIMEOUT * 4,
        256 * 1024,
    );
    if !matches!(
        outcome,
        zkminer_prover_protocol::proc::Outcome::Ran { success: true, .. }
    ) {
        tracing::warn!(
            "listing display devices for {what} failed ({})",
            outcome.describe()
        );
        return None;
    }
    Some(stdout)
}

/// Whether an Intel PCI device ID is a discrete GPU: Arc Alchemist / Flex (DG2, 0x56xx), Arc
/// Battlemage (BMG, 0xe2xx) and Data Center GPU Max (PVC, 0x0bd5-0x0bdb). Integrated GPUs share
/// the vendor ID, and on Windows there is no local-memory attribute to tell them apart by.
#[cfg(any(windows, test))]
fn is_discrete_intel_device_id(device_id: u16) -> bool {
    matches!(device_id >> 8, 0x56 | 0xe2) || (0x0bd5..=0x0bdb).contains(&device_id)
}

/// Parse `name|PNPDeviceID|location[|memory]` lines (`WINDOWS_DISPLAY_DEVICES_PS`) into Intel
/// discrete GPUs, ordered by PCI bus ID. `device_index` follows that order, which is the order
/// Level Zero enumerates them in (the index `ZE_AFFINITY_MASK` selects by).
#[cfg(test)]
fn parse_windows_intel_gpus(output: &str) -> Vec<DetectedGpu> {
    parse_windows_intel_gpus_with_vram(output)
        .into_iter()
        .map(|(gpu, _)| gpu)
        .collect()
}

/// `parse_windows_intel_gpus`, with each GPU's VRAM in bytes where the line reports it.
#[cfg(any(windows, test))]
fn parse_windows_intel_gpus_with_vram(output: &str) -> Vec<(DetectedGpu, Option<u64>)> {
    let mut gpus: Vec<(DetectedGpu, Option<u64>)> = output
        .lines()
        .filter_map(|line| {
            let mut parts = line.trim().splitn(4, '|');
            let name = parts.next()?.trim();
            let pnp_id = parts.next()?.trim().to_uppercase();
            let location = parts.next().unwrap_or("").trim();
            let vram = parts
                .next()
                .and_then(|m| m.trim().parse::<u64>().ok())
                .filter(|&m| m > 0);
            let ids = pnp_id.strip_prefix("PCI\\VEN_8086&DEV_")?;
            let device_id = u16::from_str_radix(ids.get(..4)?, 16).ok()?;
            if !is_discrete_intel_device_id(device_id) {
                return None;
            }
            let pci_bus_id = pci_bus_id_from_location_info(location)?;
            let name = if name.is_empty() {
                intel_gpu_name_from_id(&format!("0x{device_id:04x}"))
            } else {
                name.to_string()
            };
            Some((
                DetectedGpu {
                    gpu_tag: "intel".to_string(),
                    device_index: 0,
                    pci_bus_id,
                    name,
                    // Not a CUDA device; CUDA compute capability does not apply.
                    compute_cap: None,
                },
                vram,
            ))
        })
        .collect();
    gpus.sort_by(|a, b| a.0.pci_bus_id.cmp(&b.0.pci_bus_id));
    for (i, (gpu, _)) in gpus.iter_mut().enumerate() {
        gpu.device_index = i as u32;
    }
    gpus
}

/// "PCI bus 3, device 0, function 0" (Windows' `DEVPKEY_Device_LocationInfo`, decimal) ->
/// "0000:03:00.0".
#[cfg(any(windows, test))]
fn pci_bus_id_from_location_info(location: &str) -> Option<String> {
    let mut nums = location
        .split(|c: char| !c.is_ascii_digit())
        .filter(|s| !s.is_empty())
        .map(|s| s.parse::<u32>());
    let (bus, device, function) = (nums.next()?.ok()?, nums.next()?.ok()?, nums.next()?.ok()?);
    if !location.to_ascii_lowercase().starts_with("pci bus") || device > 31 || function > 7 {
        return None;
    }
    Some(format!("0000:{bus:02x}:{device:02x}.{function:x}"))
}

/// Detect Intel discrete GPUs via /sys/class/drm/card*/device/.
/// Filters out integrated GPUs by requiring local memory (tile0 or BAR2).
#[cfg_attr(windows, allow(dead_code))]
fn detect_intel_gpus_sysfs() -> Vec<DetectedGpu> {
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

/// An Intel discrete card's device memory as its driver reports it: `(total, used)` in bytes over its
/// VRAM regions.
///
/// sysfs has no answer on current xe kernels (`tile0/physical_vram_size_bytes` is gone, and BAR2 is the
/// aperture, not the memory: 16 GiB on a 12 GB Arc B580), and none on i915, so this asks the driver
/// directly on the card's render node, which any user that may compute on the card can open: xe's
/// `DRM_XE_DEVICE_QUERY_MEM_REGIONS` (Battlemage and later), or i915's `DRM_I915_QUERY_MEMORY_REGIONS`
/// (Alchemist, e.g. the Arc A770, which kernels still give to i915). `None` for another driver, a card
/// with no render node, or a query that fails.
#[cfg(target_os = "linux")]
pub fn intel_vram(pci_bus_id: &str) -> Option<(u64, u64)> {
    let dev = Path::new("/sys/bus/pci/devices").join(pci_bus_id.to_ascii_lowercase());
    let driver = std::fs::read_link(dev.join("driver")).ok()?;
    let driver = driver.file_name()?.to_str()?.to_string();
    if driver != "xe" && driver != "i915" {
        return None;
    }
    let render = std::fs::read_dir(dev.join("drm"))
        .ok()?
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .find(|n| n.starts_with("renderD"))?;
    let node = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(Path::new("/dev/dri").join(render))
        .ok()?;
    if driver == "xe" {
        xe_vram(&node)
    } else {
        i915_vram(&node)
    }
}

/// `intel_vram` on an xe card: `DRM_IOCTL_XE_DEVICE_QUERY` / `DRM_XE_DEVICE_QUERY_MEM_REGIONS`.
#[cfg(target_os = "linux")]
fn xe_vram(node: &std::fs::File) -> Option<(u64, u64)> {
    use std::os::fd::AsRawFd;

    /// `struct drm_xe_device_query` (uapi/drm/xe_drm.h).
    #[repr(C)]
    struct DeviceQuery {
        extensions: u64,
        query: u32,
        size: u32,
        data: u64,
        reserved: [u64; 2],
    }
    // _IOWR('d', DRM_COMMAND_BASE + DRM_XE_DEVICE_QUERY, struct drm_xe_device_query)
    const DRM_IOCTL_XE_DEVICE_QUERY: u64 = (3 << 30) | (40 << 16) | ((b'd' as u64) << 8) | 0x40;
    const DRM_XE_DEVICE_QUERY_MEM_REGIONS: u32 = 1;
    const _: () = assert!(std::mem::size_of::<DeviceQuery>() == 40);

    let mut q = DeviceQuery {
        extensions: 0,
        query: DRM_XE_DEVICE_QUERY_MEM_REGIONS,
        size: 0,
        data: 0,
        reserved: [0; 2],
    };
    // SAFETY: `q` is a live, correctly laid out `drm_xe_device_query`; with `size == 0` the driver
    // only writes the size it needs into it.
    if unsafe { libc::ioctl(node.as_raw_fd(), DRM_IOCTL_XE_DEVICE_QUERY as _, &mut q) } != 0 {
        return None;
    }
    if q.size == 0 || q.size > 1 << 16 {
        return None;
    }
    let mut buf = vec![0u64; (q.size as usize).div_ceil(8)];
    q.data = buf.as_mut_ptr() as u64;
    // SAFETY: `data` points at `buf`, which holds at least the `size` bytes the driver asked for.
    if unsafe { libc::ioctl(node.as_raw_fd(), DRM_IOCTL_XE_DEVICE_QUERY as _, &mut q) } != 0 {
        return None;
    }
    // SAFETY: `buf` is `size.div_ceil(8) * 8 >= size` initialized bytes.
    let bytes = unsafe { std::slice::from_raw_parts(buf.as_ptr().cast::<u8>(), q.size as usize) };
    parse_xe_mem_regions(bytes)
}

/// `intel_vram` on an i915 card: `DRM_IOCTL_I915_QUERY` / `DRM_I915_QUERY_MEMORY_REGIONS`. Without
/// `CAP_PERFMON` the driver reports each region's unallocated size as its probed size, so the used
/// figure is then 0 (`card_occupancy` also counts what each process holds); the total is exact.
#[cfg(target_os = "linux")]
fn i915_vram(node: &std::fs::File) -> Option<(u64, u64)> {
    use std::os::fd::AsRawFd;

    /// `struct drm_i915_query_item` (uapi/drm/i915_drm.h).
    #[repr(C)]
    struct QueryItem {
        query_id: u64,
        length: i32,
        flags: u32,
        data_ptr: u64,
    }
    /// `struct drm_i915_query`.
    #[repr(C)]
    struct Query {
        num_items: u32,
        flags: u32,
        items_ptr: u64,
    }
    // _IOWR('d', DRM_COMMAND_BASE + DRM_I915_QUERY, struct drm_i915_query)
    const DRM_IOCTL_I915_QUERY: u64 = (3 << 30) | (16 << 16) | ((b'd' as u64) << 8) | (0x40 + 0x39);
    const DRM_I915_QUERY_MEMORY_REGIONS: u64 = 4;
    const _: () = assert!(std::mem::size_of::<QueryItem>() == 24);
    const _: () = assert!(std::mem::size_of::<Query>() == 16);

    let mut item = QueryItem {
        query_id: DRM_I915_QUERY_MEMORY_REGIONS,
        length: 0,
        flags: 0,
        data_ptr: 0,
    };
    let mut q = Query {
        num_items: 1,
        flags: 0,
        items_ptr: std::ptr::addr_of_mut!(item) as u64,
    };
    // SAFETY: `q` names one live, correctly laid out `drm_i915_query_item`; with `length == 0` the
    // driver only writes the length it needs into it (or a negative error code).
    if unsafe { libc::ioctl(node.as_raw_fd(), DRM_IOCTL_I915_QUERY as _, &mut q) } != 0 {
        return None;
    }
    if item.length <= 0 || item.length > 1 << 16 {
        return None;
    }
    let len = item.length as usize;
    let mut buf = vec![0u64; len.div_ceil(8)];
    item.data_ptr = buf.as_mut_ptr() as u64;
    q.items_ptr = std::ptr::addr_of_mut!(item) as u64;
    // SAFETY: `data_ptr` points at `buf`, which holds at least the `length` bytes the driver asked for.
    if unsafe { libc::ioctl(node.as_raw_fd(), DRM_IOCTL_I915_QUERY as _, &mut q) } != 0 {
        return None;
    }
    if item.length <= 0 || item.length as usize > len {
        return None;
    }
    // SAFETY: `buf` is `len.div_ceil(8) * 8 >= item.length` initialized bytes.
    let bytes =
        unsafe { std::slice::from_raw_parts(buf.as_ptr().cast::<u8>(), item.length as usize) };
    parse_i915_mem_regions(bytes)
}

#[cfg(not(target_os = "linux"))]
pub fn intel_vram(_pci_bus_id: &str) -> Option<(u64, u64)> {
    None
}

/// `(total, used)` over the VRAM regions of a `struct drm_xe_query_mem_regions`: a `u32` count and a
/// `u32` pad, then that many 88-byte `struct drm_xe_mem_region` (`u16 mem_class`, `u16 instance`,
/// `u32 min_page_size`, `u64 total_size`, `u64 used`, ...). `None` when it is cut short or has no VRAM.
fn parse_xe_mem_regions(b: &[u8]) -> Option<(u64, u64)> {
    const REGION: usize = 88;
    const DRM_XE_MEM_REGION_CLASS_VRAM: u16 = 1;
    let n = u32::from_ne_bytes(b.get(0..4)?.try_into().ok()?) as usize;
    let (mut total, mut used) = (0u64, 0u64);
    for i in 0..n {
        let r = b.get(8 + i * REGION..8 + (i + 1) * REGION)?;
        if u16::from_ne_bytes(r[0..2].try_into().ok()?) == DRM_XE_MEM_REGION_CLASS_VRAM {
            total += u64::from_ne_bytes(r[8..16].try_into().ok()?);
            used += u64::from_ne_bytes(r[16..24].try_into().ok()?);
        }
    }
    (total > 0).then_some((total, used))
}

/// `(total, used)` over the device-memory regions of a `struct drm_i915_query_memory_regions`: a `u32`
/// count and three reserved `u32`, then that many 88-byte `struct drm_i915_memory_region_info`
/// (`u16 memory_class`, `u16 memory_instance`, `u32` reserved, `u64 probed_size`,
/// `u64 unallocated_size`, ...); used is probed less unallocated. `None` when it is cut short or has no
/// device memory.
fn parse_i915_mem_regions(b: &[u8]) -> Option<(u64, u64)> {
    const HEADER: usize = 16;
    const REGION: usize = 88;
    const I915_MEMORY_CLASS_DEVICE: u16 = 1;
    let n = u32::from_ne_bytes(b.get(0..4)?.try_into().ok()?) as usize;
    let (mut total, mut used) = (0u64, 0u64);
    for i in 0..n {
        let r = b.get(HEADER + i * REGION..HEADER + (i + 1) * REGION)?;
        if u16::from_ne_bytes(r[0..2].try_into().ok()?) == I915_MEMORY_CLASS_DEVICE {
            let probed = u64::from_ne_bytes(r[8..16].try_into().ok()?);
            let unallocated = u64::from_ne_bytes(r[16..24].try_into().ok()?);
            total += probed;
            used += probed.saturating_sub(unallocated);
        }
    }
    (total > 0).then_some((total, used))
}

/// Whether the Intel card at `pci_bus_id` is an Alchemist (Xe-HPG: Arc A-series, Arc Pro A, Flex)
/// part, by its PCI device id (`0x56xx`). False where sysfs has no answer (not Linux, or no such card).
pub fn intel_is_alchemist(pci_bus_id: &str) -> bool {
    let dev = Path::new("/sys/bus/pci/devices").join(pci_bus_id.to_ascii_lowercase());
    let read = |f: &str| std::fs::read_to_string(dev.join(f)).ok();
    let hex = |s: String| u32::from_str_radix(s.trim().trim_start_matches("0x"), 16).ok();
    read("vendor").and_then(hex) == Some(0x8086)
        && read("device")
            .and_then(hex)
            .is_some_and(is_alchemist_device_id)
}

/// Alchemist's PCI device ids, `0x5690`..=`0x56ff` (Arc A770 `0x56a0`, A750 `0x56a1`, A380 `0x56a5`, ...).
fn is_alchemist_device_id(id: u32) -> bool {
    (0x5690..=0x56ff).contains(&id)
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

/// Detect AMD discrete GPUs on Windows, which has neither sysfs nor rocm-smi, from the HIP runtime
/// itself: run a ROCm worker binary's `--list-hip-devices` (see `parse_hip_device_list`). Only
/// the runtime knows its own device order, which is what `HIP_VISIBLE_DEVICES` selects by (an
/// integrated GPU, which it lists too, can sit anywhere in it), and which devices are integrated.
/// No ROCm worker binary, no AMD GPU: there would be nothing to run on it.
#[cfg(windows)]
fn detect_amd_gpus_windows(
    explicit_binaries: &HashMap<String, PathBuf>,
    search_dirs: &[PathBuf],
) -> Vec<DetectedGpu> {
    let Some(probe) = find_hip_probe(explicit_binaries, search_dirs) else {
        return Vec::new();
    };
    // The probe must see every device, whatever this process was started with.
    let mut cmd = std::process::Command::new(&probe);
    cmd.arg("--list-hip-devices")
        .env_remove("HIP_VISIBLE_DEVICES")
        .env_remove("ROCR_VISIBLE_DEVICES")
        .env_remove("CUDA_VISIBLE_DEVICES")
        .env("RUST_LOG", "error");
    // A worker's start-up (a large binary, the HIP runtime) takes longer than a GPU tool's.
    let (outcome, stdout) = zkminer_prover_protocol::proc::output_with_timeout_capturing_stdout(
        &mut cmd,
        GPU_TOOL_TIMEOUT * 4,
        256 * 1024,
    );
    if !matches!(
        outcome,
        zkminer_prover_protocol::proc::Outcome::Ran { success: true, .. }
    ) {
        tracing::warn!(
            "listing HIP devices with {} failed ({})",
            probe.display(),
            outcome.describe()
        );
        return Vec::new();
    }
    let gpus = parse_hip_device_list_with_vram(&stdout);
    if let Ok(mut known) = AMD_HIP_GFX.lock() {
        known
            .get_or_insert_with(HashMap::new)
            .extend(parse_hip_arch_list(&stdout));
    }
    if let Ok(mut known) = AMD_HIP_VRAM.lock() {
        let known = known.get_or_insert_with(HashMap::new);
        for (gpu, vram) in &gpus {
            if let Some(vram) = vram {
                known.insert(gpu.pci_bus_id.clone(), *vram);
            }
        }
    }
    gpus.into_iter().map(|(gpu, _)| gpu).collect()
}

/// Each discrete AMD GPU's memory as the HIP runtime reported it to the last
/// `detect_amd_gpus_windows`, by PCI bus id. Windows has no amdgpu sysfs to read it from.
#[cfg(windows)]
static AMD_HIP_VRAM: std::sync::Mutex<Option<HashMap<String, u64>>> = std::sync::Mutex::new(None);

/// Each AMD GPU's target (`gfx1201`) as the HIP runtime reported it to the last
/// `detect_amd_gpus_windows`, by PCI bus id. Windows has no KFD topology to read it from.
#[cfg(windows)]
static AMD_HIP_GFX: std::sync::Mutex<Option<HashMap<String, String>>> = std::sync::Mutex::new(None);

/// The target of the AMD GPU at `pci_bus_id` as the HIP runtime reported it at discovery
/// (`--list-hip-devices`, on Windows). `None` elsewhere, before discovery, from a worker that
/// predates reporting it, or if unknown.
fn amd_hip_gfx_target(pci_bus_id: &str) -> Option<String> {
    #[cfg(windows)]
    {
        AMD_HIP_GFX.lock().ok()?.as_ref()?.get(pci_bus_id).cloned()
    }
    #[cfg(not(windows))]
    {
        let _ = pci_bus_id;
        None
    }
}

/// Parse the `arch|pci_bus_id|gcnArchName` lines of a ROCm worker's `--list-hip-devices` into
/// each device's target by PCI bus id (see `gfx_target_from_gcn_arch_name`).
#[cfg(any(windows, test))]
fn parse_hip_arch_list(output: &str) -> HashMap<String, String> {
    output
        .lines()
        .filter_map(|line| {
            let mut parts = line.trim().splitn(3, '|');
            if parts.next()?.trim() != "arch" {
                return None;
            }
            let pci_bus_id = normalize_pci_bus_id(parts.next()?);
            let gfx = gfx_target_from_gcn_arch_name(parts.next()?)?;
            (!pci_bus_id.is_empty()).then_some((pci_bus_id, gfx))
        })
        .collect()
}

/// The target a HIP `gcnArchName` names, without its feature flags: `gfx90a:sramecc+:xnack-` ->
/// `gfx90a`, as a HIP binary's code objects are listed (`gpu_code::EmbeddedHipCode`). `None`
/// for anything that is not a `gfx` target.
#[cfg(any(windows, test))]
fn gfx_target_from_gcn_arch_name(name: &str) -> Option<String> {
    let target = name.trim().split(':').next()?.trim().to_ascii_lowercase();
    let suffix = target.strip_prefix("gfx")?;
    (!suffix.is_empty() && suffix.chars().all(|c| c.is_ascii_alphanumeric())).then_some(target)
}

/// The memory of the AMD GPU at `pci_bus_id`, where the platform reports it without sysfs: on
/// Windows, what the HIP runtime said at discovery (`--list-hip-devices`). `None` elsewhere, before
/// discovery, or if unknown.
pub fn amd_hip_vram_bytes(pci_bus_id: &str) -> Option<u64> {
    #[cfg(windows)]
    {
        let key = normalize_pci_bus_id(pci_bus_id);
        AMD_HIP_VRAM.lock().ok()?.as_ref()?.get(&key).copied()
    }
    #[cfg(not(windows))]
    {
        let _ = pci_bus_id;
        None
    }
}

/// The ROCm worker binary to list HIP devices with: an explicitly configured one, else the first
/// `zkminer-prove-<backend>-rocm` where `discover_workers` searches.
#[cfg(windows)]
fn find_hip_probe(
    explicit_binaries: &HashMap<String, PathBuf>,
    search_dirs: &[PathBuf],
) -> Option<PathBuf> {
    for backend in ALL_BACKENDS {
        if let Some(path) = explicit_binaries.get(*backend) {
            if path.is_file() && infer_gpu_tag(path) == "rocm" {
                return Some(path.clone());
            }
        }
    }
    let dirs = worker_search_dirs(search_dirs);
    ALL_BACKENDS.iter().find_map(|backend| {
        let bin_name = worker_binary_name(backend, "rocm");
        search_in_dirs(&bin_name, &dirs).or_else(|| search_in_path(&bin_name))
    })
}

/// Parse `index|pci_bus_id|integrated|total_mem|name` lines (a ROCm worker's
/// `--list-hip-devices`) into the discrete AMD GPUs, keeping HIP's own index.
#[cfg(test)]
fn parse_hip_device_list(output: &str) -> Vec<DetectedGpu> {
    parse_hip_device_list_with_vram(output)
        .into_iter()
        .map(|(gpu, _)| gpu)
        .collect()
}

/// [`parse_hip_device_list`], with each GPU's memory in bytes as HIP reports it (`total_mem`).
#[cfg(any(windows, test))]
fn parse_hip_device_list_with_vram(output: &str) -> Vec<(DetectedGpu, Option<u64>)> {
    output
        .lines()
        .filter_map(|line| {
            let mut parts = line.trim().splitn(5, '|');
            let device_index = parts.next()?.trim().parse::<u32>().ok()?;
            let pci_bus_id = normalize_pci_bus_id(parts.next()?);
            let integrated = parts.next()?.trim() != "0";
            let total_mem = parts.next()?.trim().parse::<u64>().ok().filter(|b| *b > 0);
            let name = parts.next()?.trim().to_string();
            if integrated {
                tracing::debug!("Skipping integrated AMD GPU [{device_index}] {name}");
                return None;
            }
            if pci_bus_id.is_empty() {
                return None;
            }
            let gpu = DetectedGpu {
                gpu_tag: "rocm".to_string(),
                device_index,
                pci_bus_id,
                name,
                // Not a CUDA device; CUDA compute capability does not apply.
                compute_cap: None,
            };
            Some((gpu, total_mem))
        })
        .collect()
}

/// Detect AMD GPUs via /sys/class/drm/card*/device/.
#[cfg_attr(windows, allow(dead_code))]
fn detect_amd_gpus() -> Vec<DetectedGpu> {
    let drm_base = Path::new("/sys/class/drm");
    if !drm_base.is_dir() {
        return Vec::new();
    }

    // HIP device indices from the kernel's KFD topology, which needs no ROCm install; rocm-smi's
    // where that cannot be read (and product names, where rocm-smi is installed).
    let kfd_index = kfd_hip_indices(Path::new("/sys/class/kfd/kfd/topology"));
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

        // HIP_VISIBLE_DEVICES must use the ROCm/HIP device index: KFD's GPU order, which
        // rocm-smi's GPU[N] also reports. The DRM cardN walk order need not match it
        // (an skipped iGPU or non-PCI ordering would shift the index and mis-pin
        // the worker onto the wrong AMD GPU — the same failure class as the CUDA
        // PCI-bus-id bug). Fall back to a positional counter only if neither
        // gave us an index for this bus.
        let device_index = kfd_index
            .get(&pci_bus_id)
            .or_else(|| rocm_info.index_by_bus.get(&pci_bus_id))
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

/// The GPU nodes of the kernel's KFD topology (`<topology>/nodes/<n>/properties`), which a host
/// with only the amdgpu driver has, in node order: each one's PCI bus id and target (`gfx1100`).
/// CPU nodes, which have no SIMDs, are left out. A node's `location_id` is its PCI address,
/// `bus << 8 | device << 3 | function`, in PCI domain `domain`; its `gfx_target_version` is
/// `major * 10000 + minor * 100 + stepping`, the target named `gfx<major><minor:x><stepping:x>`.
///
/// `None` when the topology cannot be read whole: a GPU node missing from the list would shift
/// every later HIP index, and pin a worker onto the wrong card.
fn kfd_gpu_nodes(topology: &Path) -> Option<Vec<(String, Option<String>)>> {
    let mut nodes: Vec<(u32, PathBuf)> = std::fs::read_dir(topology.join("nodes"))
        .ok()?
        .filter_map(|e| e.ok())
        .filter_map(|e| Some((e.file_name().to_str()?.parse().ok()?, e.path())))
        .collect();
    nodes.sort();
    let mut gpus = Vec::new();
    for (_, dir) in nodes {
        let properties = std::fs::read_to_string(dir.join("properties")).ok()?;
        let value = |key: &str| {
            properties.lines().find_map(|line| {
                let (k, v) = line.split_once(' ')?;
                (k == key).then(|| v.trim().parse::<u64>().ok()).flatten()
            })
        };
        if value("simd_count").unwrap_or(0) == 0 {
            continue;
        }
        let (location, domain) = (value("location_id")?, value("domain")?);
        let bus = format!(
            "{domain:04x}:{:02x}:{:02x}.{:x}",
            (location >> 8) & 0xff,
            (location >> 3) & 0x1f,
            location & 0x7
        );
        let gfx = value("gfx_target_version")
            .filter(|v| *v > 0)
            .map(|v| format!("gfx{}{:x}{:x}", v / 10_000, (v / 100) % 100, v % 100));
        gpus.push((normalize_pci_bus_id(&bus), gfx));
    }
    Some(gpus)
}

/// Each AMD GPU's HIP device index, by PCI bus id: HIP numbers the GPUs in the order of their KFD
/// nodes, counting every GPU node (an APU's too). Empty when the topology cannot be read whole.
fn kfd_hip_indices(topology: &Path) -> HashMap<String, u32> {
    kfd_gpu_nodes(topology)
        .unwrap_or_default()
        .into_iter()
        .enumerate()
        .map(|(index, (bus, _))| (bus, index as u32))
        .collect()
}

/// The target of the AMD GPU at `pci_bus_id` (`gfx1100` for an RX 7900 XTX), for checking a HIP
/// binary carries code for it (`gpu_code::EmbeddedHipCode`). From the first source that knows it:
/// the kernel's KFD topology (Linux), what the HIP runtime reported at discovery (Windows, which
/// has no KFD), then the card's PCI device id (`amd_gfx_target_for_device_id`), for a worker that
/// does not report its runtime's target.
pub fn amd_gfx_target(pci_bus_id: &str) -> Option<String> {
    let bus = normalize_pci_bus_id(pci_bus_id);
    first_gfx_target(
        &bus,
        &[
            ("the KFD topology", &kfd_gfx_target),
            ("the HIP runtime", &amd_hip_gfx_target),
            ("its PCI device id", &pci_id_gfx_target),
        ],
    )
}

/// A source of AMD GPU targets, by PCI bus id, and what to call it in the log.
type GfxTargetSource<'a> = (&'a str, &'a dyn Fn(&str) -> Option<String>);

/// The target the first of `sources` that knows one gives for the card at `bus`.
fn first_gfx_target(bus: &str, sources: &[GfxTargetSource]) -> Option<String> {
    sources.iter().find_map(|(what, source)| {
        let gfx = source(bus)?;
        tracing::debug!("AMD GPU {bus} is {gfx}, from {what}");
        Some(gfx)
    })
}

/// The target of the AMD GPU at `bus` in the kernel's KFD topology, which a Linux host with the
/// amdgpu driver has.
fn kfd_gfx_target(bus: &str) -> Option<String> {
    kfd_gpu_nodes(Path::new("/sys/class/kfd/kfd/topology"))?
        .into_iter()
        .find(|(b, _)| b == bus)?
        .1
}

/// The target of the AMD GPU at `bus` from its PCI device id, which Windows lists with the display
/// devices (`WINDOWS_DISPLAY_DEVICES_PS`; read once). `None` elsewhere: a Linux host has the KFD
/// topology.
fn pci_id_gfx_target(bus: &str) -> Option<String> {
    #[cfg(windows)]
    {
        static DEVICE_IDS: std::sync::OnceLock<HashMap<String, u16>> = std::sync::OnceLock::new();
        let ids = DEVICE_IDS.get_or_init(|| {
            run_windows_display_devices_ps("AMD GPU device ids")
                .map(|out| parse_windows_amd_device_ids(&out))
                .unwrap_or_default()
        });
        amd_gfx_target_for_device_id(*ids.get(bus)?).map(str::to_string)
    }
    #[cfg(not(windows))]
    {
        let _ = bus;
        None
    }
}

/// Parse `name|PNPDeviceID|location[|memory]` lines (`WINDOWS_DISPLAY_DEVICES_PS`) into each AMD
/// display device's PCI device id, by PCI bus id.
#[cfg(any(windows, test))]
fn parse_windows_amd_device_ids(output: &str) -> HashMap<String, u16> {
    output
        .lines()
        .filter_map(|line| {
            let mut parts = line.trim().splitn(4, '|');
            let _name = parts.next()?;
            let pnp_id = parts.next()?.trim().to_uppercase();
            let location = parts.next().unwrap_or("").trim();
            let ids = pnp_id.strip_prefix("PCI\\VEN_1002&DEV_")?;
            let device_id = u16::from_str_radix(ids.get(..4)?, 16).ok()?;
            Some((pci_bus_id_from_location_info(location)?, device_id))
        })
        .collect()
}

/// The HIP target of an AMD (vendor 0x1002) GPU by PCI device id, for the RDNA 2, 3 and 4 parts;
/// `None` for any other, which is then not checked.
///
/// The ids are the amdgpu driver's for its RDNA 2 dies (Linux `drivers/gpu/drm/amd/amdgpu/
/// amdgpu_drv.c` `pciidlist`: SIENNA_CICHLID = Navi 21, NAVY_FLOUNDER = Navi 22,
/// DIMGREY_CAVEFISH = Navi 23, BEIGE_GOBY = Navi 24, YELLOW_CARP = Rembrandt). The driver matches
/// newer dies by class and reads their IP versions instead, so for those, and for Van Gogh and
/// Raphael, the ids are the PCI ID Repository's (pci-ids.ucw.cz, vendor 1002) for each die. The
/// target is the one the kernel's KFD reports for the die's GC IP version
/// (`drivers/gpu/drm/amd/amdkfd/kfd_device.c`, `gfx_target_version`), which is what the HIP
/// runtime names it: Navi 31 (GC 11.0.0) gfx1100, Navi 32 (11.0.3) gfx1101, Navi 33 (11.0.2)
/// gfx1102, Phoenix and Hawk Point (11.0.1, 11.0.4) gfx1103, Strix (11.5.0) gfx1150, Strix Halo
/// (11.5.1) gfx1151, Krackan (11.5.2) gfx1152, Navi 44 (12.0.0) gfx1200, Navi 48 (12.0.1)
/// gfx1201; Mendocino (10.3.7) is reported as gfx1036, as Raphael is.
#[cfg(any(windows, test))]
fn amd_gfx_target_for_device_id(device_id: u16) -> Option<&'static str> {
    Some(match device_id {
        // Navi 21: RX 6800 / 6800 XT / 6900 XT / 6950 XT, PRO W6800, V620.
        0x73a0..=0x73a3 | 0x73a5 | 0x73a8 | 0x73a9 | 0x73ab..=0x73af | 0x73bf => "gfx1030",
        // Navi 22: RX 6700 / 6700 XT / 6750 XT, 6800M.
        0x73c0 | 0x73c1 | 0x73c3 | 0x73da..=0x73df => "gfx1031",
        // Navi 23: RX 6600 / 6600 XT / 6650 XT, PRO W6600.
        0x73e0..=0x73e3 | 0x73e8..=0x73ed | 0x73ef | 0x73ff => "gfx1032",
        // Van Gogh (Steam Deck).
        0x163f => "gfx1033",
        // Navi 24: RX 6400 / 6500 XT, PRO W6400.
        0x7420..=0x7424 | 0x743f => "gfx1034",
        // Rembrandt: Radeon 660M / 680M.
        0x164d | 0x1681 => "gfx1035",
        // Raphael, Granite Ridge, Mendocino: Radeon 610M.
        0x164e | 0x13c0 | 0x1506 => "gfx1036",
        // Navi 31: RX 7900 XT / XTX / GRE, PRO W7800 / W7900.
        0x7448..=0x744c | 0x745e => "gfx1100",
        // Navi 32: RX 7700 XT / 7800 XT, PRO W7700, V710.
        0x7460 | 0x7461 | 0x7470 | 0x747e => "gfx1101",
        // Navi 33: RX 7600 / 7600 XT / 7500 / 7400, PRO W7600 / W7500.
        0x73f0 | 0x7480 | 0x7481 | 0x7483 | 0x7487 | 0x7489 | 0x748b | 0x7499 | 0x749f => "gfx1102",
        // Phoenix, Hawk Point: Radeon 740M / 760M / 780M.
        0x15bf | 0x15c8 | 0x164f | 0x1900 | 0x1901 => "gfx1103",
        // Strix: Radeon 880M / 890M.
        0x150e => "gfx1150",
        // Strix Halo: Radeon 8050S / 8060S.
        0x1586 => "gfx1151",
        // Krackan: Radeon 840M / 860M.
        0x1114 => "gfx1152",
        // Navi 44: RX 9060 XT.
        0x7590 => "gfx1200",
        // Navi 48: RX 9070 / 9070 XT / 9070 GRE, AI PRO R9700.
        0x7550 | 0x7551 => "gfx1201",
        _ => return None,
    })
}

/// The binary holding a backend's HIP device code, for `gpu_code::EmbeddedHipCode` to read: the
/// risc0 worker itself, or the SP1 HIP server the SP1 worker will run.
pub fn hip_code_binary(backend: &str, worker: &Path) -> Option<PathBuf> {
    if backend != "sp1" {
        return Some(worker.to_path_buf());
    }
    let install = std::env::var(zkminer_prover_protocol::types::SP1_SERVER_INSTALL_ENV)
        .map_or(true, |v| v.trim() != "0");
    sp1_named_server_for(
        sp1_server_name("rocm")?,
        worker,
        install,
        dirs::home_dir().as_deref(),
    )
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
    let read = |file: &str| {
        std::fs::read_to_string(device_dir.join(file))
            .map(|s| s.trim().to_string())
            .unwrap_or_default()
    };
    let (device_id, revision) = (read("device"), read("revision"));
    // The marketing name from libdrm's table, which Mesa installs (libdrm-common): a host with only
    // the GPU driver has no rocm-smi to ask.
    if let Some(name) = [
        "/usr/share/libdrm/amdgpu.ids",
        "/usr/local/share/libdrm/amdgpu.ids",
    ]
    .iter()
    .filter_map(|path| std::fs::read_to_string(path).ok())
    .find_map(|ids| amdgpu_ids_name(&ids, &device_id, &revision))
    {
        return name;
    }
    // Fallback: device ID
    if !device_id.is_empty() {
        return format!("AMD GPU ({})", device_id);
    }
    "AMD GPU".to_string()
}

/// The product name libdrm's `amdgpu.ids` gives a device id and revision (sysfs's `0x744c` and
/// `0xc8`), from its `744C,\tC8,\tAMD Radeon RX 7900 XTX` lines.
fn amdgpu_ids_name(ids: &str, device_id: &str, revision: &str) -> Option<String> {
    let hex = |s: &str| u32::from_str_radix(s.trim().trim_start_matches("0x"), 16).ok();
    let (device, revision) = (hex(device_id)?, hex(revision)?);
    ids.lines().find_map(|line| {
        let mut fields = line.splitn(3, ',');
        let (d, r, name) = (fields.next()?, fields.next()?, fields.next()?);
        (hex(d)? == device && hex(r)? == revision).then(|| name.trim().to_string())
    })
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
    discover_workers_reporting(explicit_binaries, search_dirs, &|_| {})
}

/// `discover_workers`, telling `report` which GPU vendor it is checking, for a startup display.
pub fn discover_workers_reporting(
    explicit_binaries: &HashMap<String, PathBuf>,
    search_dirs: &[PathBuf],
    report: &dyn Fn(&str),
) -> Vec<DiscoveredWorker> {
    survey_workers(explicit_binaries, search_dirs, report).workers
}

/// What worker discovery found: the GPUs, a worker for each card a binary was found for, and the
/// directories it searched.
#[derive(Debug, Clone, Default)]
pub struct DiscoverySurvey {
    pub gpus: Vec<DetectedGpu>,
    pub workers: Vec<DiscoveredWorker>,
    /// Searched in this order, then `PATH`.
    pub searched: Vec<PathBuf>,
}

/// The directories searched for worker binaries, in order (then `PATH`): the configured ones,
/// `~/.zkminer/provers`, and the directory of the running executable.
pub fn worker_search_dirs(search_dirs: &[PathBuf]) -> Vec<PathBuf> {
    let mut all_dirs: Vec<PathBuf> = search_dirs.to_vec();
    if let Some(home_dir) = dirs::home_dir() {
        all_dirs.push(home_dir.join(".zkminer").join("provers"));
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            all_dirs.push(parent.to_path_buf());
        }
    }
    all_dirs
}

/// The file names a `backend` worker for `gpu_tag` cards is looked for under: the vendor's own,
/// then the generic one.
pub fn worker_file_names(backend: &str, gpu_tag: &str) -> Vec<String> {
    let mut names = vec![worker_file_name(&worker_binary_name(backend, gpu_tag))];
    if gpu_tag != "generic" {
        names.push(worker_file_name(&worker_binary_name(backend, "generic")));
    }
    names
}

/// Files in `dirs` named like a `backend` worker for `gpu_tag` cards that discovery skips because
/// they are not executable (on unix; elsewhere, none).
pub fn non_executable_workers(backend: &str, gpu_tag: &str, dirs: &[PathBuf]) -> Vec<PathBuf> {
    worker_file_names(backend, gpu_tag)
        .iter()
        .flat_map(|name| dirs.iter().map(move |d| d.join(name)))
        .filter(|p| p.is_file() && !is_executable(p))
        .collect()
}

/// [`discover_workers_reporting`], keeping the GPUs it detected and where it looked.
pub fn survey_workers(
    explicit_binaries: &HashMap<String, PathBuf>,
    search_dirs: &[PathBuf],
    report: &dyn Fn(&str),
) -> DiscoverySurvey {
    let gpus = detect_all_gpus_with(explicit_binaries, search_dirs, report);
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
                        gpus.iter()
                            .filter(|g| sp1_serves_card(&g.gpu_tag, path))
                            .collect()
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
                            gpu_tag: gpu.gpu_tag.clone(),
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
        let all_dirs = worker_search_dirs(search_dirs);

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
                    gpus.iter()
                        .filter(|g| sp1_serves_card(&g.gpu_tag, &path))
                        .collect()
                } else {
                    Vec::new()
                };
            if !cuda_tags.is_empty() {
                for gpu in cuda_tags {
                    found.push(DiscoveredWorker {
                        backend: backend.to_string(),
                        // The card's vendor, not `generic`: this is the occupancy fact, and every
                        // consumer of `gpu_tag` (`physical_gpu_id`, `gpu_device_id`,
                        // `proving_gpu_count`) wants it. The pin is withheld separately, in `gpu_env`.
                        gpu_tag: gpu.gpu_tag.clone(),
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

    DiscoverySurvey {
        gpus,
        workers: found,
        searched: worker_search_dirs(search_dirs),
    }
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
    sp1_named_server_for("sp1-gpu-server", worker, install, home)
}

/// The `sp1-gpu-server` build an SP1 worker runs on a card of `gpu_tag`, or `None` for a card no
/// SP1 build drives. The CUDA build keeps the SDK's default name; hemilabs/sp1's HIP and SYCL builds
/// (#19) are installed beside it under their own names and chosen with `SP1_GPU_SERVER_NAME`.
pub fn sp1_server_name(gpu_tag: &str) -> Option<&'static str> {
    match gpu_tag {
        "cuda" => Some("sp1-gpu-server"),
        "rocm" => Some("sp1-gpu-server-hip"),
        "intel" => Some("sp1-gpu-server-sycl"),
        _ => None,
    }
}

/// Whether the SP1 worker at `worker` can drive a card of `gpu_tag`: always a CUDA card (the SDK
/// downloads a CUDA server when none is shipped); an AMD or Intel card only when its vendor's server
/// is shipped beside the worker or installed in `~/.sp1/bin`, since nothing downloads those.
fn sp1_serves_card(gpu_tag: &str, worker: &Path) -> bool {
    match gpu_tag {
        "cuda" => true,
        "rocm" | "intel" => {
            let install = std::env::var(zkminer_prover_protocol::types::SP1_SERVER_INSTALL_ENV)
                .map_or(true, |v| v.trim() != "0");
            sp1_server_name(gpu_tag).is_some_and(|name| {
                sp1_named_server_for(name, worker, install, dirs::home_dir().as_deref()).is_some()
            })
        }
        _ => false,
    }
}

fn sp1_named_server_for(
    server: &str,
    worker: &Path,
    install: bool,
    home: Option<&Path>,
) -> Option<PathBuf> {
    // `.exe` on Windows.
    let server = worker_file_name(server);
    if install {
        // The worker looks beside its own executable, which for a symlinked worker is the target's
        // directory; a wrapper script sits beside the binary it runs, so its own directory works too.
        let real = std::fs::canonicalize(worker).ok().map(strip_verbatim);
        let shipped = [real.as_deref().and_then(Path::parent), worker.parent()]
            .into_iter()
            .flatten()
            .map(|dir| dir.join(&server))
            .find(|path| path.is_file());
        if shipped.is_some() {
            return shipped;
        }
    }
    let installed = home?.join(".sp1").join("bin").join(&server);
    installed.is_file().then_some(installed)
}

/// `path` without the `\\?\` that `canonicalize` puts before a Windows drive path, so a canonical
/// path compares and prints as the ordinary spelling of the same file. Anything else is unchanged.
fn strip_verbatim(path: PathBuf) -> PathBuf {
    match path.to_str().and_then(|s| s.strip_prefix(r"\\?\")) {
        Some(rest) if rest.as_bytes().get(1) == Some(&b':') => PathBuf::from(rest),
        _ => path,
    }
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
///
/// **hemilabs/sp1 #19 (6.8.1):** its server, on every backend, refuses only below
/// `ceil(GiB) + 4 = 16`, so a 12 GB card (11.x GiB) runs, in the same element tier as a 16 GB one; an
/// RTX 4070 and an Arc B580 proved SP1 Groth16 fibonacci on it. The floor is therefore the server's
/// own: more than 11 GiB (an 11,264 MiB card is `11 + 4 = 15` and refused), in bytes as the card
/// totals are read. Whether a card has ROOM for a job is still [`min_available_vram_bytes_for_backend`]'s
/// measured question, answered for 12-16 GB CUDA cards from an RTX 4070's peaks (2026-11-16).
pub fn min_vram_bytes_for_backend(backend: &str) -> Option<u64> {
    match backend {
        "sp1" => Some(11 * 1024 * 1024 * 1024 + 1),
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
/// allowance refuses work the card could actually do. SP1 proves in anything from about 10 GiB free
/// (134M lean on a 24 GB CUDA card) to 22 (268M full on a 32 GB one), see `sp1_measured_configs`; a
/// 24,564 MiB 4090 with 6 GiB held by a display still has 18 GiB free — room for 268M lean — and a
/// 512 MiB allowance refused it outright. Requiring the FLOOR to be free instead admits that card and
/// leaves the sizing to `sp1_config_for_available_vram`, which steps the configuration down to match.
/// The floor itself is the smallest configuration's measured need plus margin on that card — 10,344
/// MiB on a 24 GB CUDA card, 9,167 on one of 16 GiB or less, 15,604 on a card nothing has measured —
/// so a card that clears the floor has room for the configuration it will actually be given.
///
/// risc0 and openvm have no floor here: a risc0 card proves jobs at its own segment size
/// (`benchmark::risc0_job_po2`), and one too small for any proves none. A risc0 PROOF has one of
/// its own, by its segment size: [`risc0_proof_vram_bytes`].
///
/// `gpu_tag` and `total` (the card's capacity, `None` when unknown) pick SP1's measured table, as do
/// the operator's savers in the miner's environment, which the workers inherit (`sp1_operator_lean`).
pub fn min_available_vram_bytes_for_backend(
    backend: &str,
    gpu_tag: &str,
    total: Option<u64>,
) -> Option<u64> {
    use zkminer_prover_protocol::types as t;
    let default = match backend {
        // Derived from the MEASURED tier table rather than from the installed-VRAM floor, so this and
        // the tier the worker will actually be given cannot disagree about whether a card is usable.
        // They did in the first draft: a 16e9 floor admitted cards the tier function had no
        // configuration for.
        "sp1" => {
            let gpu = t::Sp1Gpu::from_gpu_tag(gpu_tag);
            t::sp1_min_available_vram_bytes(
                gpu,
                total,
                t::sp1_operator_lean(crate::env::var, gpu, total),
            )
        }
        _ => return None,
    };
    if free_vram_checks_off() {
        return None;
    }
    match crate::env::var(MIN_AVAILABLE_VRAM_MB_ENV) {
        // 0 is an explicit opt-out, for an operator who knows the other occupant of their card is
        // harmless and would rather risk the work than have it refused.
        Some(v) => match v.trim().parse::<u64>() {
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
        None => Some(default),
    }
}

/// Whether the operator turned the free-VRAM checks off: [`MIN_AVAILABLE_VRAM_MB_ENV`] set to 0.
pub fn free_vram_checks_off() -> bool {
    crate::env::var(MIN_AVAILABLE_VRAM_MB_ENV).is_some_and(|v| v.trim().parse::<u64>() == Ok(0))
}

/// What a risc0 proof at segment size `po2` takes on a CUDA card of `total` bytes, as measured
/// (`benchmark::RISC0_GPU_MEASURED_PEAK_MIB`), plus the Groth16 prover and SRS a worker keeps on a
/// card of 20 GiB or more ([`RISC0_RESIDENT_GROTH16_BYTES`]): the room a proof must have before it
/// starts, or it spills into system memory (Windows) or runs out (Linux). Not a margin: a proof
/// that fits is never refused.
///
/// `None`, no requirement, for a size nothing measured (16 and 17, whose peaks are only bounded by
/// 18's; 21 and up, which are extrapolated), another vendor's card, a card of unknown size or one
/// that could never hold it (a refusal there would release every job such a card claims, where
/// today it proves them slowly; the planner prices that, see
/// `benchmark::risc0_largest_fitting_po2`), and with the checks off (`free_vram_checks_off`).
pub fn risc0_proof_vram_bytes(po2: u8, gpu_tag: &str, total: Option<u64>) -> Option<u64> {
    const MIB: u64 = 1024 * 1024;
    if gpu_tag != "cuda" || free_vram_checks_off() {
        return None;
    }
    let total = total?;
    let peak = crate::benchmark::RISC0_GPU_MEASURED_PEAK_MIB
        .iter()
        .find(|(p, _)| *p == po2)
        .map(|(_, mib)| mib * MIB)?;
    let resident = if total >= RISC0_KEEPS_GROTH16_FROM_BYTES {
        RISC0_RESIDENT_GROTH16_BYTES
    } else {
        0
    };
    let need = peak.saturating_add(resident);
    (need <= total).then_some(need)
}

/// The card size from which a CUDA risc0 worker keeps its Groth16 prover and SRS on the card
/// between proofs (`RELEASE_GROTH16_CACHE_BELOW_BYTES` in `zkminer-prove-risc0`).
pub const RISC0_KEEPS_GROTH16_FROM_BYTES: u64 = 20 * 1024 * 1024 * 1024;

/// What the kept Groth16 cache adds to a risc0 proof's peak: 15,834 MiB at po2 20 with it kept,
/// against 12,436 with it released (both on a 16 GB RTX 5080).
pub const RISC0_RESIDENT_GROTH16_BYTES: u64 = (15_834 - 12_436) * 1024 * 1024;

/// Whether this backend sizes its workers from the VRAM free when they start — SP1, by
/// `sp1_worker_sizing` — so that a live worker can be sized for more than is free now.
///
/// risc0 and openvm size per segment from `po2`, which the dispatcher picks per proof
/// (`risc0_size_that_fits`); there is no spawn-time configuration to go stale.
pub fn sizes_from_vram(backend: &str) -> bool {
    backend == "sp1"
}

/// Infer GPU tag from binary filename.
fn infer_gpu_tag(path: &Path) -> String {
    if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
        let name = name
            .strip_suffix(std::env::consts::EXE_SUFFIX)
            .unwrap_or(name);
        if name.ends_with("-cuda") {
            return "cuda".to_string();
        }
        if name.ends_with("-rocm") {
            return "rocm".to_string();
        }
        if name.ends_with("-intel") {
            return "intel".to_string();
        }
        if name.ends_with("-metal") {
            return "metal".to_string();
        }
    }
    "generic".to_string()
}

/// The file a worker binary is installed as: `bin_name` plus the platform's
/// executable suffix (`.exe` on Windows, nothing elsewhere).
fn worker_file_name(bin_name: &str) -> String {
    format!("{bin_name}{}", std::env::consts::EXE_SUFFIX)
}

fn search_in_dirs(bin_name: &str, dirs: &[PathBuf]) -> Option<PathBuf> {
    for dir in dirs {
        let candidate = dir.join(worker_file_name(bin_name));
        if candidate.is_file() && is_executable(&candidate) {
            return Some(candidate);
        }
    }
    None
}

fn search_in_path(bin_name: &str) -> Option<PathBuf> {
    let path_var = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_var) {
        let candidate = dir.join(worker_file_name(bin_name));
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
    fn amd_names_come_from_libdrm_without_rocm() {
        let ids = "# comment\n1.0.0\n744C,\tC8,\tAMD Radeon RX 7900 XTX\n744C,\tCC,\tAMD Radeon RX 7900 XT\n7550,\tC0,\tAMD Radeon RX 9070 XT\n";
        assert_eq!(
            amdgpu_ids_name(ids, "0x744c", "0xc8").as_deref(),
            Some("AMD Radeon RX 7900 XTX")
        );
        assert_eq!(
            amdgpu_ids_name(ids, "0x7550", "0xc0").as_deref(),
            Some("AMD Radeon RX 9070 XT")
        );
        assert_eq!(amdgpu_ids_name(ids, "0x744c", "0xff"), None);
        assert_eq!(amdgpu_ids_name(ids, "", "0xc8"), None);
    }

    #[test]
    fn gfx_targets_are_named_from_their_version() {
        let root = std::env::temp_dir().join(format!("zkminer-kfd-gfx-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        for (n, version) in [(1, 110001), (2, 120001), (3, 90010), (4, 90402)] {
            let dir = root.join(format!("nodes/{n}"));
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(
                dir.join("properties"),
                format!(
                    "simd_count 64\nlocation_id {}\ndomain 0\ngfx_target_version {version}\n",
                    n << 8
                ),
            )
            .unwrap();
        }
        let gfx: Vec<String> = kfd_gpu_nodes(&root)
            .unwrap()
            .into_iter()
            .filter_map(|g| g.1)
            .collect();
        assert_eq!(gfx, ["gfx1101", "gfx1201", "gfx90a", "gfx942"]);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn hip_indices_follow_the_kfd_topology_without_rocm() {
        let root = std::env::temp_dir().join(format!("zkminer-kfd-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let node = |n: u32, properties: &str| {
            let dir = root.join(format!("nodes/{n}"));
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join("properties"), properties).unwrap();
        };
        // A CPU node, an APU, then two discrete cards, listed out of order (node 10 after 2).
        node(
            0,
            "cpu_cores_count 16\nsimd_count 0\nlocation_id 0\ndomain 0\n",
        );
        node(1, "simd_count 24\nlocation_id 1280\ndomain 0\n");
        node(10, "simd_count 128\nlocation_id 49152\ndomain 1\n");
        node(
            2,
            "simd_count 192\nlocation_id 2168\ndomain 0\ngfx_target_version 110000\n",
        );

        let gpus = kfd_gpu_nodes(&root).unwrap();
        assert_eq!(
            gpus[1],
            ("0000:08:0f.0".to_string(), Some("gfx1100".to_string()))
        );
        assert_eq!(gpus[0].1, None, "a node without its target version");
        let indices = kfd_hip_indices(&root);
        // 1280 = 0x500: 05:00.0; 2168 = 0x878: 08:0f.0; 49152 = 0xc000: c0:00.0.
        assert_eq!(indices.get("0000:05:00.0"), Some(&0), "the APU counts");
        assert_eq!(indices.get("0000:08:0f.0"), Some(&1));
        assert_eq!(
            indices.get("0001:c0:00.0"),
            Some(&2),
            "node 10 sorts after node 2"
        );
        assert_eq!(indices.len(), 3);

        // A GPU node without its address: no index is trusted.
        node(11, "simd_count 64\n");
        assert!(kfd_hip_indices(&root).is_empty());
        assert!(kfd_hip_indices(&root.join("missing")).is_empty());
        let _ = std::fs::remove_dir_all(&root);
    }

    /// The layout an Arc B580 returned on xe (kernel 7.0): system memory, then one VRAM region.
    #[test]
    fn xe_mem_regions_sum_only_vram() {
        fn region(class: u16, instance: u16, total: u64, used: u64) -> Vec<u8> {
            let mut r = Vec::new();
            r.extend(class.to_ne_bytes());
            r.extend(instance.to_ne_bytes());
            r.extend(4096u32.to_ne_bytes());
            r.extend(total.to_ne_bytes());
            r.extend(used.to_ne_bytes());
            r.extend([0u8; 88 - 24]);
            r
        }
        let mut b = Vec::new();
        b.extend(2u32.to_ne_bytes());
        b.extend(0u32.to_ne_bytes());
        b.extend(region(0, 0, 98_776_000_000, 0));
        b.extend(region(1, 1, 12_809_404_416, 20 << 20));
        assert_eq!(b.len(), 184);
        assert_eq!(parse_xe_mem_regions(&b), Some((12_809_404_416, 20 << 20)));
        // Cut short: no answer rather than a partial sum.
        assert_eq!(parse_xe_mem_regions(&b[..100]), None);
        // System memory only (an integrated GPU): no VRAM, no answer.
        let mut igpu = Vec::new();
        igpu.extend(1u32.to_ne_bytes());
        igpu.extend(0u32.to_ne_bytes());
        igpu.extend(region(0, 0, 1 << 34, 0));
        assert_eq!(parse_xe_mem_regions(&igpu), None);
    }

    #[test]
    fn alchemist_device_ids() {
        for id in [0x5690, 0x56a0, 0x56a1, 0x56a5, 0x56b0, 0x56c0] {
            assert!(is_alchemist_device_id(id), "{id:#x}");
        }
        // Battlemage (Arc B580 0xe20b), Lunar Lake (0x64a0), DG1 (0x4905): not Alchemist.
        for id in [0xe20b, 0xe211, 0x64a0, 0x4905, 0x568f] {
            assert!(!is_alchemist_device_id(id), "{id:#x}");
        }
    }

    /// The layout an Arc A770 (i915) answers with, as measured: system memory, then 15.9 GiB of device
    /// memory, reported unallocated in full to a user without `CAP_PERFMON`.
    #[test]
    fn i915_mem_regions_sum_only_device_memory() {
        fn region(class: u16, probed: u64, unallocated: u64) -> Vec<u8> {
            let mut r = Vec::new();
            r.extend(class.to_ne_bytes());
            r.extend(0u16.to_ne_bytes());
            r.extend(0u32.to_ne_bytes());
            r.extend(probed.to_ne_bytes());
            r.extend(unallocated.to_ne_bytes());
            r.extend([0u8; 88 - 24]);
            r
        }
        let mut b = Vec::new();
        b.extend(2u32.to_ne_bytes());
        b.extend([0u8; 12]);
        b.extend(region(0, 64_952_971_264, 64_952_971_264));
        b.extend(region(1, 17_079_205_888, 17_079_205_888));
        assert_eq!(b.len(), 192);
        assert_eq!(parse_i915_mem_regions(&b), Some((17_079_205_888, 0)));
        // With CAP_PERFMON the unallocated size is real.
        let mut p = b.clone();
        p[16 + 88 + 16..16 + 88 + 24]
            .copy_from_slice(&(17_079_205_888u64 - (3 << 30)).to_ne_bytes());
        assert_eq!(parse_i915_mem_regions(&p), Some((17_079_205_888, 3 << 30)));
        assert_eq!(parse_i915_mem_regions(&b[..120]), None);
        let mut igpu = Vec::new();
        igpu.extend(1u32.to_ne_bytes());
        igpu.extend([0u8; 12]);
        igpu.extend(region(0, 1 << 34, 1 << 34));
        assert_eq!(parse_i915_mem_regions(&igpu), None);
    }

    #[test]
    fn parse_hip_device_list_keeps_discrete_gpus_with_hip_index() {
        // A Ryzen host with an RX 9070 XT: the iGPU is HIP device 1 here, but could be any index.
        let out = "0|0000:03:00.0|0|17095983104|AMD Radeon RX 9070 XT
                   1|0000:16:00.0|1|62477336576|AMD Radeon(TM) Graphics
                   2|00000000:2d:00.0|0|25753026560|AMD Radeon RX 7900 XTX
                   garbage line
";
        let gpus = parse_hip_device_list(out);
        assert_eq!(gpus.len(), 2);
        assert_eq!(gpus[0].device_index, 0);
        assert_eq!(gpus[0].pci_bus_id, "0000:03:00.0");
        assert_eq!(gpus[0].name, "AMD Radeon RX 9070 XT");
        assert_eq!(gpus[0].gpu_tag, "rocm");
        // The index is HIP's, not the position among discrete GPUs.
        assert_eq!(gpus[1].device_index, 2);
        assert_eq!(gpus[1].pci_bus_id, "0000:2d:00.0");
        let with_vram = parse_hip_device_list_with_vram(out);
        assert_eq!(with_vram[0].1, Some(17_095_983_104));
        assert_eq!(with_vram[1].1, Some(25_753_026_560));
        // An unreadable or zero size is unknown, not zero.
        let odd = parse_hip_device_list_with_vram("0|0000:03:00.0|0|?|X\n1|0000:04:00.0|0|0|Y");
        assert_eq!(
            odd.iter().map(|(_, v)| *v).collect::<Vec<_>>(),
            [None, None]
        );
    }

    #[test]
    fn hip_arch_lines_give_each_card_its_target_and_old_hosts_skip_them() {
        // A worker's `--list-hip-devices`: each device line followed by its runtime's target.
        let out = "0|0000:03:00.0|0|17095983104|AMD Radeon RX 9070 XT
                   arch|0000:03:00.0|gfx1201
                   1|0000:16:00.0|1|62477336576|AMD Radeon(TM) Graphics
                   arch|0000:16:00.0|gfx1036
                   2|00000000:2D:00.0|0|68702699520|AMD Instinct MI210
                   arch|00000000:2D:00.0|gfx90a:sramecc+:xnack-
                   arch|0000:2e:00.0|not-a-target
                   arch|0000:2f:00.0
";
        let gfx = parse_hip_arch_list(out);
        assert_eq!(gfx.len(), 3, "{gfx:?}");
        assert_eq!(gfx["0000:03:00.0"], "gfx1201");
        assert_eq!(gfx["0000:16:00.0"], "gfx1036");
        // Keyed as the device lines are, and without the feature flags.
        assert_eq!(gfx["0000:2d:00.0"], "gfx90a");
        // The device list a host that predates the arch lines reads is unchanged by them.
        let gpus = parse_hip_device_list(out);
        assert_eq!(gpus.len(), 2);
        assert_eq!(gpus[0].name, "AMD Radeon RX 9070 XT");
        assert_eq!(gpus[1].pci_bus_id, "0000:2d:00.0");
        // And a worker that predates them gives no targets.
        assert!(
            parse_hip_arch_list("0|0000:03:00.0|0|17095983104|AMD Radeon RX 9070 XT").is_empty()
        );
    }

    #[test]
    fn gcn_arch_names_lose_their_feature_flags() {
        for (name, want) in [
            ("gfx1201", Some("gfx1201")),
            ("gfx1030", Some("gfx1030")),
            (" gfx90a:sramecc+:xnack- ", Some("gfx90a")),
            ("gfx942:sramecc-:xnack+", Some("gfx942")),
            ("GFX1100", Some("gfx1100")),
            ("gfx", None),
            ("gfx11-generic", None),
            ("sm_89", None),
            ("", None),
            (":xnack-", None),
        ] {
            assert_eq!(
                gfx_target_from_gcn_arch_name(name).as_deref(),
                want,
                "{name:?}"
            );
        }
    }

    #[test]
    fn amd_pci_device_ids_map_to_their_targets() {
        for (id, want) in [
            // RDNA 2: RX 6950 XT, 6900 XT, 6800 XT, 6700 XT, 6600 XT, 6500 XT, iGPUs.
            (0x73a5, Some("gfx1030")),
            (0x73af, Some("gfx1030")),
            (0x73bf, Some("gfx1030")),
            (0x73df, Some("gfx1031")),
            (0x73ff, Some("gfx1032")),
            (0x73ef, Some("gfx1032")),
            (0x743f, Some("gfx1034")),
            (0x1681, Some("gfx1035")),
            (0x13c0, Some("gfx1036")),
            (0x164e, Some("gfx1036")),
            // RDNA 3: RX 7900 XTX, 7800 XT, 7600 (and the 7600M XT's 0x73f0), Phoenix, Strix.
            (0x744c, Some("gfx1100")),
            (0x747e, Some("gfx1101")),
            (0x7480, Some("gfx1102")),
            (0x73f0, Some("gfx1102")),
            (0x15bf, Some("gfx1103")),
            (0x150e, Some("gfx1150")),
            (0x1586, Some("gfx1151")),
            (0x1114, Some("gfx1152")),
            // RDNA 4: RX 9060 XT, 9070 XT, AI PRO R9700.
            (0x7590, Some("gfx1200")),
            (0x7550, Some("gfx1201")),
            (0x7551, Some("gfx1201")),
            // Unknown, and not a gap in a range: no target, so the card is not checked.
            (0x73a4, None), // Navi 21's USB controller
            (0x731f, None), // RDNA 1, which no build targets
            (0x74a1, None), // MI300X
            (0xffff, None),
        ] {
            assert_eq!(amd_gfx_target_for_device_id(id), want, "{id:#06x}");
        }
    }

    #[test]
    fn windows_display_devices_give_amd_device_ids_by_bus() {
        let out = [
            r"AMD Radeon RX 9070 XT|PCI\VEN_1002&DEV_7550&SUBSYS_24161EAE&REV_C0\6&2BA1C4D7&0&00000019|PCI bus 3, device 0, function 0|17095983104",
            r"AMD Radeon(TM) Graphics|PCI\VEN_1002&DEV_13C0&SUBSYS_D0001458&REV_C9\4&16012499&0&0041|PCI bus 19, device 0, function 0",
            r"AMD Radeon RX 6950 XT|pci\ven_1002&dev_73a5&subsys_0e3a1002&rev_c0\6&1&0&0|PCI bus 45, device 0, function 0|",
            r"Intel(R) Arc(TM) Pro B70 Graphics|PCI\VEN_8086&DEV_E223&SUBSYS_60251849&REV_00\6&81E8C03&0&00080009|PCI bus 4, device 0, function 0|34359738368",
            r"AMD Radeon RX 7900 XTX|PCI\VEN_1002&DEV_744C&SUBSYS_0E3B1002&REV_C8\6&3&0&0|",
        ]
        .join("\n");
        let ids = parse_windows_amd_device_ids(&out);
        assert_eq!(ids.len(), 3, "{ids:?}");
        assert_eq!(ids["0000:03:00.0"], 0x7550);
        assert_eq!(ids["0000:13:00.0"], 0x13c0);
        assert_eq!(ids["0000:2d:00.0"], 0x73a5);
        assert_eq!(
            amd_gfx_target_for_device_id(ids["0000:03:00.0"]),
            Some("gfx1201")
        );
        assert_eq!(
            amd_gfx_target_for_device_id(ids["0000:2d:00.0"]),
            Some("gfx1030")
        );
    }

    #[test]
    fn gfx_target_comes_from_the_first_source_that_knows_it() {
        use std::cell::RefCell;
        let asked = RefCell::new(Vec::new());
        let source = |name: &'static str, gfx: Option<&'static str>| {
            let asked = &asked;
            move |bus: &str| {
                asked.borrow_mut().push((name, bus.to_string()));
                gfx.map(str::to_string)
            }
        };
        let (kfd, hip, pci) = (
            source("kfd", Some("gfx1100")),
            source("hip", Some("gfx1201")),
            source("pci", Some("gfx1030")),
        );
        let (no_kfd, no_hip, no_pci) = (
            source("kfd", None),
            source("hip", None),
            source("pci", None),
        );
        let bus = "0000:03:00.0";
        let names = |asked: &RefCell<Vec<(&'static str, String)>>| -> Vec<&'static str> {
            asked.borrow_mut().drain(..).map(|(n, _)| n).collect()
        };

        // KFD (Linux) wins, and nothing after it is asked.
        let got = first_gfx_target(bus, &[("kfd", &kfd), ("hip", &hip), ("pci", &pci)]);
        assert_eq!(got.as_deref(), Some("gfx1100"));
        assert_eq!(names(&asked), ["kfd"]);
        // No KFD (Windows): the HIP runtime's.
        let got = first_gfx_target(bus, &[("kfd", &no_kfd), ("hip", &hip), ("pci", &pci)]);
        assert_eq!(got.as_deref(), Some("gfx1201"));
        assert_eq!(names(&asked), ["kfd", "hip"]);
        // A worker that does not report its runtime's target: the PCI device id's.
        let got = first_gfx_target(bus, &[("kfd", &no_kfd), ("hip", &no_hip), ("pci", &pci)]);
        assert_eq!(got.as_deref(), Some("gfx1030"));
        assert_eq!(names(&asked), ["kfd", "hip", "pci"]);
        // None knows: unknown, which the spawn gate does not refuse.
        let got = first_gfx_target(bus, &[("kfd", &no_kfd), ("hip", &no_hip), ("pci", &no_pci)]);
        assert_eq!(got, None);
        assert_eq!(names(&asked), ["kfd", "hip", "pci"]);
        // Each is asked for the card's bus id as given.
        first_gfx_target(bus, &[("kfd", &no_kfd)]);
        assert_eq!(asked.borrow().as_slice(), [("kfd", bus.to_string())]);
    }

    #[test]
    fn amd_gfx_target_without_kfd_or_discovery_is_unknown_off_windows() {
        // This host's sources: on Linux the KFD topology, which a CI runner has no AMD GPU in;
        // nothing reported a HIP target, and no PCI id is read off Windows.
        if cfg!(windows) || Path::new("/sys/class/kfd/kfd/topology").exists() {
            return;
        }
        assert_eq!(amd_gfx_target("0000:03:00.0"), None);
    }

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
        // Canonical, because `sp1_named_server_for` canonicalizes the worker's path: on macOS the
        // temp dir is `/var/folders/...`, a symlink into `/private/var/folders/...`.
        let tmp =
            std::fs::canonicalize(std::env::temp_dir()).unwrap_or_else(|_| std::env::temp_dir());
        let root = tmp.join(format!(
            "zk-sp1-server-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        // In its canonical spelling, as `sp1_server_for` returns paths: a temp dir can be spelled
        // otherwise (a Windows runner's TEMP is `C:\Users\RUNNER~1\...`, 8.3 for `runneradmin`).
        std::fs::create_dir_all(&root).unwrap();
        let root = strip_verbatim(std::fs::canonicalize(&root).unwrap());
        let (release, home) = (root.join("provers"), root.join("home"));
        let server = worker_file_name("sp1-gpu-server");
        let installed = home.join(".sp1").join("bin").join(&server);
        std::fs::create_dir_all(installed.parent().unwrap()).unwrap();
        std::fs::create_dir_all(&release).unwrap();
        let worker = release.join(worker_file_name("zkminer-prove-sp1"));
        let shipped = release.join(&server);
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
    /// With the fork's server as first built (2026-10-05) the floor was 16 GB (it is now more than
    /// 11 GiB, see `min_vram_bytes_for_backend`) and BOTH cards here
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
        // A 12 GB card runs on hemilabs/sp1 #19's server (an RTX 4070 and an Arc B580 proved on it);
        // whether it has room for a job is the available-VRAM floor's question.
        assert!(
            12_288u64 * 1024 * 1024 >= floor,
            "a 12 GB card must qualify: #19's server admits it"
        );
        // But a genuinely small card must not: below `ceil(GiB) + 4 = 16` the server refuses it.
        assert!(
            10_240u64 * 1024 * 1024 < floor,
            "a 10 GB card must be refused, as the server refuses it"
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

    /// Windows installs workers as `<name>.exe`: discovery must find them under that
    /// name, and an explicitly configured `...-cuda.exe` is still a CUDA worker.
    #[test]
    #[cfg(windows)]
    fn windows_worker_names_carry_exe() {
        assert_eq!(
            worker_file_name("zkminer-prove-risc0-cuda"),
            "zkminer-prove-risc0-cuda.exe"
        );
        assert_eq!(
            infer_gpu_tag(Path::new(r"C:\zk\zkminer-prove-risc0-cuda.exe")),
            "cuda"
        );
        let dir = std::env::temp_dir().join(format!("zkminer-disc-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("zkminer-prove-risc0-cuda.exe"), b"").unwrap();
        let found = search_in_dirs("zkminer-prove-risc0-cuda", std::slice::from_ref(&dir));
        std::fs::remove_dir_all(&dir).unwrap();
        assert_eq!(found, Some(dir.join("zkminer-prove-risc0-cuda.exe")));
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

    #[test]
    fn metal_is_a_gpu_tag_with_a_suffixed_binary() {
        assert!(GPU_TAGS.contains(&"metal"));
        // Searched before the generic name, like every other vendor suffix.
        let metal = GPU_TAGS.iter().position(|t| *t == "metal").unwrap();
        let generic = GPU_TAGS.iter().position(|t| *t == "generic").unwrap();
        assert!(metal < generic);
        assert_eq!(
            worker_binary_name("risc0", "metal"),
            "zkminer-prove-risc0-metal"
        );
        assert_eq!(
            infer_gpu_tag(Path::new(
                "/Users/x/.zkminer/provers/zkminer-prove-risc0-metal"
            )),
            "metal"
        );
        // Only a suffix counts.
        assert_eq!(
            infer_gpu_tag(Path::new("/x/zkminer-prove-risc0-metal-old")),
            "generic"
        );
        // No SP1 build drives an Apple GPU, so SP1 is never expanded onto one.
        assert_eq!(sp1_server_name("metal"), None);
        assert!(!sp1_serves_card(
            "metal",
            Path::new("/nonexistent/zkminer-prove-sp1")
        ));
    }

    #[test]
    fn apple_gpu_is_named_from_system_profiler() {
        // Trimmed from `system_profiler SPDisplaysDataType -json` on an M5 Max (macOS 27.2).
        let m5 = r#"{
          "SPDisplaysDataType" : [
            {
              "_name" : "Apple M5 Max",
              "spdisplays_mtlgpufamilysupport" : "spdisplays_metal4",
              "spdisplays_ndrvs" : [ { "_name" : "Some Display" } ],
              "spdisplays_vendor" : "sppci_vendor_Apple",
              "sppci_bus" : "spdisplays_builtin",
              "sppci_cores" : "32",
              "sppci_device_type" : "spdisplays_gpu",
              "sppci_model" : "Apple M5 Max"
            }
          ]
        }"#;
        assert_eq!(
            apple_gpu_name_from_profiler_json(m5).as_deref(),
            Some("Apple M5 Max")
        );
        // An Intel Mac's discrete AMD GPU is not an Apple GPU: no entry.
        let intel_mac = r#"{"SPDisplaysDataType":[{"_name":"AMD Radeon Pro 5500M",
            "spdisplays_vendor":"sppci_vendor_amd","sppci_model":"AMD Radeon Pro 5500M"}]}"#;
        assert_eq!(apple_gpu_name_from_profiler_json(intel_mac), None);
        // Falls back to `_name` when the model is missing.
        let no_model = r#"{"SPDisplaysDataType":[{"_name":"Apple M1",
            "spdisplays_vendor":"sppci_vendor_Apple"}]}"#;
        assert_eq!(
            apple_gpu_name_from_profiler_json(no_model).as_deref(),
            Some("Apple M1")
        );
        assert_eq!(apple_gpu_name_from_profiler_json(""), None);
        assert_eq!(apple_gpu_name_from_profiler_json("{}"), None);
        assert_eq!(apple_gpu_name_from_profiler_json("not json"), None);
        // The core count, for the Metal benchmark deadline (M6).
        assert_eq!(apple_gpu_cores_from_profiler_json(m5), Some(32));
        assert_eq!(apple_gpu_cores_from_profiler_json(intel_mac), None);
        assert_eq!(apple_gpu_cores_from_profiler_json(no_model), None);

        let gpu = apple_gpu("Apple M5 Max".into());
        assert_eq!(gpu.gpu_tag, "metal");
        assert_eq!(gpu.device_index, 0);
        assert_eq!(gpu.pci_bus_id, APPLE_GPU_PSEUDO_BUS_ID);
        assert_eq!(gpu.compute_cap, None);
        // The pseudo id must survive normalisation unchanged, or rows keyed by it would not join.
        assert_eq!(normalize_pci_bus_id(APPLE_GPU_PSEUDO_BUS_ID), "apple-gpu0");
    }

    /// On an Apple silicon Mac, discovery reports exactly one Apple GPU.
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    #[test]
    fn this_mac_reports_one_apple_gpu() {
        let apple = detect_apple_gpus();
        assert_eq!(apple.len(), 1, "{apple:?}");
        assert!(apple[0].name.starts_with("Apple"), "{apple:?}");
        assert_eq!(apple[0].gpu_tag, "metal");
        assert_eq!(apple[0].device_index, 0);
        assert_eq!(apple[0].pci_bus_id, "apple-gpu0");
        let all = detect_all_gpus();
        assert_eq!(all.iter().filter(|g| g.gpu_tag == "metal").count(), 1);
    }

    /// W7-M10: a fake owner source drives the reading and, through it, the tier.
    #[test]
    fn a_fake_owner_source_drives_the_tier() {
        use crate::metal_sizing::{OwnerForce, OwnerTier, OwnerTierState};
        use std::cell::Cell;
        use std::time::Duration;
        struct Fake {
            idle: Cell<Option<u64>>,
            asleep: Cell<Option<bool>>,
            battery: Option<bool>,
            lpm: Option<bool>,
        }
        impl OwnerSource for Fake {
            fn hid_idle(&self) -> Option<Duration> {
                self.idle.get().map(Duration::from_secs)
            }
            fn display_asleep(&self) -> Option<bool> {
                self.asleep.get()
            }
            fn on_battery(&self) -> Option<bool> {
                self.battery
            }
            fn low_power_mode(&self) -> Option<bool> {
                self.lpm
            }
        }
        let fake = Fake {
            idle: Cell::new(Some(4)),
            asleep: Cell::new(Some(false)),
            battery: Some(false),
            lpm: None,
        };
        let r = read_owner(&fake);
        assert_eq!(r.hid_idle, Some(Duration::from_secs(4)));
        assert_eq!(
            (r.display_asleep, r.on_battery, r.low_power_mode),
            (Some(false), Some(false), None)
        );
        assert!(r.describe().contains("input idle 4 s"), "{}", r.describe());
        let t = Duration::from_secs(300);
        let mut s = OwnerTierState::default();
        assert_eq!(
            s.update(&read_owner(&fake), t, OwnerForce::Auto),
            OwnerTier::Active
        );
        fake.idle.set(Some(400));
        assert_eq!(
            s.update(&read_owner(&fake), t, OwnerForce::Auto),
            OwnerTier::Active
        );
        fake.asleep.set(Some(true));
        assert_eq!(
            s.update(&read_owner(&fake), t, OwnerForce::Auto),
            OwnerTier::Idle
        );
        // An unreadable source (every probe None): no change.
        let none = Fake {
            idle: Cell::new(None),
            asleep: Cell::new(None),
            battery: None,
            lpm: None,
        };
        assert_eq!(
            s.update(&read_owner(&none), t, OwnerForce::Auto),
            OwnerTier::Idle
        );
    }

    /// The real probes answer on this Mac, as an ordinary user (no sudo).
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    #[test]
    fn this_macs_owner_probes_answer() {
        let r = owner_reading();
        eprintln!("owner reading: {}", r.describe());
        assert!(r.hid_idle.is_some(), "{r:?}");
        assert!(r.low_power_mode.is_some(), "{r:?}");
        assert!(r.on_battery.is_some(), "{r:?}");
        // What a reading costs (the dispatcher reads at every Metal job start and claim-side
        // sizing read).
        let t = std::time::Instant::now();
        for _ in 0..100 {
            assert!(owner_reading().hid_idle.is_some());
        }
        eprintln!("one owner reading: {:.1} us", t.elapsed().as_secs_f64() * 1e4);
    }

    /// W7-M11: the host's power state answers here too (a Mac Studio on mains power, thermal
    /// nominal or fair at rest), and is full power, so a marked cached suite would get re-benchmark
    /// advice.
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    #[test]
    fn this_macs_power_state_answers_and_is_full() {
        let p = host_power_state();
        eprintln!("host power state: {p:?}");
        assert!(p.low_power_mode.is_some() && p.thermal.is_some(), "{p:?}");
        assert_eq!(p.on_battery, owner_reading().on_battery);
        if p.thermal.unwrap() < zkminer_prover_protocol::THERMAL_THROTTLED {
            assert_eq!(p.reduced(), None, "{p:?}");
        }
    }

    #[test]
        fn parses_windows_intel_display_devices() {
        // As listed on a Windows box with an Arc Pro B70 and a Ryzen iGPU, plus an Intel iGPU
        // (Meteor Lake, 0x7d55) and a second B70 on a lower bus, to check filtering and order.
        let out = [
            r"AMD Radeon(TM) Graphics|PCI\VEN_1002&DEV_13C0&SUBSYS_D0001458&REV_C9\4&16012499&0&0041|PCI bus 19, device 0, function 0",
            r"Intel(R) Arc(TM) Pro B70 Graphics|PCI\VEN_8086&DEV_E223&SUBSYS_60251849&REV_00\6&81E8C03&0&00080009|PCI bus 3, device 0, function 0|34359738368",
            r"Intel(R) Graphics|PCI\VEN_8086&DEV_7D55&SUBSYS_00000000&REV_08\3&11583659&0&10|PCI bus 0, device 2, function 0",
            r"|PCI\VEN_8086&DEV_E223&SUBSYS_60251849&REV_00\6&1&0&0|PCI bus 2, device 0, function 0",
            // No location: dropped, as it couldn't be matched to a device.
            r"Intel(R) Arc(TM) A770|PCI\VEN_8086&DEV_56A0&SUBSYS_1020172F&REV_08\6&2&0&0|",
        ]
        .join("\r\n");
        let out = out.as_str();
        let gpus = parse_windows_intel_gpus(out);
        assert_eq!(gpus.len(), 2, "{gpus:?}");
        assert_eq!(gpus[0].pci_bus_id, "0000:02:00.0");
        assert_eq!(gpus[0].name, "Arc Pro B70");
        assert_eq!(gpus[0].device_index, 0);
        assert_eq!(gpus[1].pci_bus_id, "0000:03:00.0");
        assert_eq!(gpus[1].name, "Intel(R) Arc(TM) Pro B70 Graphics");
        assert_eq!(gpus[1].device_index, 1);
        assert!(gpus.iter().all(|g| g.gpu_tag == "intel" && g.compute_cap.is_none()));
        let vram: Vec<Option<u64>> = parse_windows_intel_gpus_with_vram(out)
            .into_iter()
            .map(|(_, v)| v)
            .collect();
        assert_eq!(vram, vec![None, Some(34359738368)]);
    }

    #[test]
    fn pci_location_info_to_bus_id() {
        assert_eq!(
            pci_bus_id_from_location_info("PCI bus 3, device 0, function 0").as_deref(),
            Some("0000:03:00.0")
        );
        assert_eq!(
            pci_bus_id_from_location_info("PCI bus 129, device 31, function 7").as_deref(),
            Some("0000:81:1f.7")
        );
        assert_eq!(pci_bus_id_from_location_info(""), None);
        assert_eq!(pci_bus_id_from_location_info("Internal"), None);
        assert!(is_discrete_intel_device_id(0xe223));
        assert!(is_discrete_intel_device_id(0x56a0));
        assert!(is_discrete_intel_device_id(0x0bd5));
        assert!(!is_discrete_intel_device_id(0x7d55));
        assert!(!is_discrete_intel_device_id(0xa7a0));
    }
}
