//! Metal worker start-up (item M9): what a fresh worker process does before its first job so that
//! job runs at warm speed, the scheduling class its proving threads run at, and the power state of
//! the Mac it proves on.
//!
//! - [`prewarm_first_job`]: beyond the pipeline states ([`crate::metal_host::warm_up_pipelines`])
//!   and M7's Groth16 witness graph, two pieces of warm state that a long-lived worker otherwise
//!   only builds during its first job: the rv32im `eval_check` pipeline specialized for this Mac's
//!   segment po2 (risc0 R20 / Z16) and identity_p254's committed ctrl group (risc0 C13 / C16).
//! - [`apply_proving_qos`]: the worker's proving threads run at user-initiated QoS, and a worker
//!   started with the Darwin background policy (`taskpolicy -b`, a launchd `Background` job) leaves
//!   it, which otherwise confines it to the efficiency cores and the lowest I/O and GPU priority.
//! - [`PowerState`]: Low Power Mode, battery power and the thermal state, logged at start and with
//!   every benchmark, because each of them slows proving and a benchmark taken under one of them
//!   does not show what this Mac proves at full speed.

// `objc`'s `msg_send!` expands `cfg(feature = ...)` checks of its own.
#![allow(unexpected_cfgs)]

use std::sync::OnceLock;
use std::time::Instant;

/// Revert knob for [`prewarm_first_job`]: `0`, `off` or `false` leaves the specialized eval pipeline
/// and the identity_p254 ctrl group to the first job, as before M9. risc0's own knobs still apply
/// underneath: `RISC0_METAL_RV32IM_EVAL_FC=0` (no specialized pipelines) and
/// `RISC0_METAL_REC_P254_PREWARM=0` (no ctrl prewarm).
pub const PREWARM_ENV: &str = "ZKMINER_METAL_PREWARM";

/// Revert knob for [`apply_proving_qos`]: `0`, `off` or `false` leaves the process's scheduling as
/// it was started.
pub const QOS_ENV: &str = "ZKMINER_WORKER_QOS";

fn knob_off(var: &str) -> bool {
    std::env::var(var).is_ok_and(|v| value_is_off(&v))
}

/// Whether a knob value means "off" (`0`, `off` or `false`, surrounding spaces ignored).
fn value_is_off(v: &str) -> bool {
    matches!(v.trim(), "0" | "off" | "false")
}

/// Builds, once per process, the warm state the first job of a worker would otherwise build itself,
/// and returns (and logs) what it did:
///
/// 1. every circuit's pipeline states ([`crate::metal_host::warm_up_pipelines`]);
/// 2. the rv32im `eval_check` pipeline specialized for `segment_po2`
///    (`risc0_circuit_rv32im::prove::metal_prewarm_segment_po2`, waiting for it). With a warm OS
///    shader cache it is an archive hit (~20 ms); with a cold one Metal specializes the function
///    first (~6.5 s, Z16 note), and until it is ready every segment of that size runs the plain
///    kernel (~41 ms slower per po2 20 segment, BASELINES 5c.3);
/// 3. identity_p254's ctrl group, committed on a temporary prover and kept as C13's host copy
///    (`risc0_circuit_recursion::prove::prewarm_p254_ctrl`), so the first Groth16 wrap restores it
///    instead of committing it (~150-170 ms). risc0 gates it on the working-set budget (512 MiB of
///    device headroom) and on C13's host cap, and it holds the process-wide GPU lock for ~0.25 s:
///    it runs while the step-2 build is still going, before any job.
///
/// Later callers get the first call's summary. Never fails: each step logs its own failure.
pub fn prewarm_first_job(segment_po2: u8) -> &'static str {
    static DONE: OnceLock<String> = OnceLock::new();
    DONE.get_or_init(|| {
        let pipelines = crate::metal_host::warm_up_pipelines();
        if knob_off(PREWARM_ENV) {
            let s = format!("{pipelines}; first-job prewarm off ({PREWARM_ENV})");
            tracing::info!("{s}");
            return s;
        }
        let started = Instant::now();
        let (segment, ctrl) = std::thread::scope(|s| {
            let segment = s.spawn(|| {
                let t = Instant::now();
                let ready = risc0_circuit_rv32im::prove::metal_prewarm_segment_po2(
                    segment_po2 as usize,
                    true,
                );
                (ready, t.elapsed())
            });
            let t = Instant::now();
            let ctrl =
                risc0_circuit_recursion::prove::prewarm_p254_ctrl(risc0_zkvm::RECURSION_PO2);
            let ctrl = (ctrl, t.elapsed());
            (segment.join().unwrap_or((false, Default::default())), ctrl)
        });
        use risc0_circuit_recursion::prove::P254Prewarm;
        let ctrl_text = match &ctrl.0 {
            Ok(P254Prewarm::Kept { ms, bytes }) => {
                format!("identity_p254 ctrl kept ({:.0} MiB) in {ms:.0} ms", *bytes as f64 / (1u64 << 20) as f64)
            }
            Ok(P254Prewarm::AlreadyKept) => "identity_p254 ctrl already kept".to_string(),
            Ok(P254Prewarm::Skipped(why)) => format!("identity_p254 ctrl not prewarmed: {why}"),
            Ok(other) => format!("identity_p254 ctrl: {other:?}"),
            Err(e) => format!("identity_p254 ctrl prewarm failed: {e:#}"),
        };
        let s = format!(
            "{pipelines}; first-job prewarm {:.2} s: po2 {segment_po2} eval pipeline {} in {:.2} s, \
             {ctrl_text} ({:.2} s)",
            started.elapsed().as_secs_f64(),
            if segment.0 { "ready" } else { "not specialized" },
            segment.1.as_secs_f64(),
            ctrl.1.as_secs_f64(),
        );
        tracing::info!("{s}");
        s
    })
}

/// Runs [`prewarm_first_job`] on a background thread (worker start in IPC mode: the dispatcher's
/// first command may be a Prove, and a respawned worker gets no Warmup). A Prove that arrives
/// meanwhile shares the pipeline builds (they are process-wide) and waits at most for the ctrl
/// commit's ~0.25 s hold of the GPU lock.
pub fn start_first_job_prewarm(segment_po2: u8) {
    if let Err(e) = std::thread::Builder::new()
        .name("metal-first-job-prewarm".into())
        .spawn(move || {
            prewarm_first_job(segment_po2);
        })
    {
        tracing::warn!("could not start the first-job prewarm: {e}");
    }
}

// <pthread/qos.h>
const QOS_CLASS_USER_INITIATED: u32 = 0x19;
const QOS_CLASS_DEFAULT: u32 = 0x15;
extern "C" {
    fn pthread_set_qos_class_self_np(qos_class: u32, relative_priority: libc::c_int)
        -> libc::c_int;
    fn qos_class_self() -> u32;
}

/// Sets the calling thread's QoS class to user-initiated; returns whether it took.
pub fn set_thread_user_initiated() -> bool {
    // SAFETY: no pointers; sets the calling thread's own QoS.
    unsafe { pthread_set_qos_class_self_np(QOS_CLASS_USER_INITIATED, 0) == 0 }
}

/// What [`apply_proving_qos`] found and changed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QosReport {
    /// The process was started with the Darwin background policy.
    pub was_background: bool,
    /// The background policy was cleared.
    pub cleared_background: bool,
    /// The main thread's QoS class before (raw `qos_class_t`).
    pub main_qos_before: u32,
    /// The main thread now runs at user-initiated.
    pub main_user_initiated: bool,
    /// rayon's global pool (risc0's CPU work) was built with user-initiated threads.
    pub rayon_user_initiated: bool,
}

/// Call first thing in `main`, before any thread exists. Threads on macOS do not inherit their
/// creator's QoS class (a `pthread_create`d thread starts at the default class whatever its creator
/// runs at), so this sets the main thread (which proves in IPC mode and drives the benchmark) and
/// builds rayon's global pool, where risc0 does its CPU work (preflight, witness generation, the
/// Groth16 witness), with a start handler that does the same per worker thread. A process started
/// with the Darwin background policy is taken out of it first: under it every thread is confined
/// to the efficiency cores with throttled I/O and GPU priority (measured 0.66 s against 0.50 s for an
/// 8-thread CPU loop under `taskpolicy -b`, M9 note). A QoS clamp set from outside
/// (`taskpolicy -c`) cannot be lifted from inside and stays. `ZKMINER_WORKER_QOS=0` skips all of it.
pub fn apply_proving_qos() -> Option<QosReport> {
    if knob_off(QOS_ENV) {
        return None;
    }
    // SAFETY: `getpriority`/`setpriority` on this process; no pointers.
    let was_background = unsafe { libc::getpriority(libc::PRIO_DARWIN_PROCESS, 0) } > 0;
    let cleared_background =
        was_background && unsafe { libc::setpriority(libc::PRIO_DARWIN_PROCESS, 0, 0) } == 0;
    // SAFETY: reads the calling thread's QoS class.
    let main_qos_before = unsafe { qos_class_self() };
    let main_user_initiated = set_thread_user_initiated();
    let rayon_user_initiated = rayon::ThreadPoolBuilder::new()
        .start_handler(|_| {
            set_thread_user_initiated();
        })
        .build_global()
        .is_ok();
    Some(QosReport {
        was_background,
        cleared_background,
        main_qos_before,
        main_user_initiated,
        rayon_user_initiated,
    })
}

/// Log [`apply_proving_qos`]'s report (once logging is set up).
pub fn log_qos(report: &Option<QosReport>) {
    match report {
        None => tracing::info!("proving-thread QoS left as started ({QOS_ENV}=0)"),
        Some(r) => {
            if r.main_qos_before != 0 && r.main_qos_before < QOS_CLASS_DEFAULT && !r.was_background
            {
                tracing::warn!(
                    "this worker was started at a low QoS class (0x{:x}, utility or background, e.g. \
                     `taskpolicy -c`); a clamp set that way cannot be lifted from inside and may \
                     keep proving off the performance cores",
                    r.main_qos_before
                );
            }
            if r.was_background && !r.cleared_background {
                tracing::warn!(
                    "this worker was started with the background scheduling policy and could not \
                     leave it: proving is confined to the efficiency cores"
                );
            } else if r.was_background {
                tracing::warn!(
                    "this worker was started with the background scheduling policy (efficiency \
                     cores only); cleared it"
                );
            }
            tracing::info!(
                "proving-thread QoS: main thread user-initiated {} (was 0x{:x}), rayon pool \
                 user-initiated {}",
                r.main_user_initiated,
                r.main_qos_before,
                r.rayon_user_initiated
            );
        }
    }
}

/// `NSProcessInfoThermalState`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Thermal {
    Nominal,
    Fair,
    Serious,
    Critical,
}

impl Thermal {
    fn from_raw(v: i64) -> Option<Self> {
        Some(match v {
            0 => Self::Nominal,
            1 => Self::Fair,
            2 => Self::Serious,
            3 => Self::Critical,
            _ => return None,
        })
    }
}

/// The Mac's power and thermal state now. `None` fields could not be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PowerState {
    /// Low Power Mode (`NSProcessInfo.isLowPowerModeEnabled`, macOS 12+).
    pub low_power_mode: Option<bool>,
    /// Running on battery (`IOPSGetProvidingPowerSourceType` is "Battery Power").
    pub on_battery: Option<bool>,
    /// `NSProcessInfo.thermalState`.
    pub thermal: Option<Thermal>,
}

impl PowerState {
    /// Why proving here is likely slower than this Mac's full speed, or `None` when nothing says so.
    /// Fair thermal state is normal under sustained load and is not counted.
    pub fn reduced(&self) -> Option<String> {
        let mut why = Vec::new();
        if self.low_power_mode == Some(true) {
            why.push("Low Power Mode is on");
        }
        if self.on_battery == Some(true) {
            why.push("running on battery");
        }
        match self.thermal {
            Some(Thermal::Serious) => why.push("thermal state serious (throttling)"),
            Some(Thermal::Critical) => why.push("thermal state critical (throttling)"),
            _ => {}
        }
        (!why.is_empty()).then(|| why.join(", "))
    }

    /// The protocol's form of this reading (`BenchmarkEntry::power_state`, v12).
    pub fn to_bench(&self) -> zkminer_prover_protocol::BenchPowerState {
        zkminer_prover_protocol::BenchPowerState {
            low_power_mode: self.low_power_mode,
            on_battery: self.on_battery,
            thermal: self.thermal.map(|t| match t {
                Thermal::Nominal => 0,
                Thermal::Fair => 1,
                Thermal::Serious => 2,
                Thermal::Critical => 3,
            }),
        }
    }

    /// One line for logs and the benchmark's device line.
    pub fn describe(&self) -> String {
        let b = |v: Option<bool>| match v {
            Some(true) => "yes",
            Some(false) => "no",
            None => "unknown",
        };
        format!(
            "Low Power Mode {}, on battery {}, thermal {}",
            b(self.low_power_mode),
            b(self.on_battery),
            match self.thermal {
                Some(Thermal::Nominal) => "nominal",
                Some(Thermal::Fair) => "fair",
                Some(Thermal::Serious) => "serious",
                Some(Thermal::Critical) => "critical",
                None => "unknown",
            }
        )
    }
}

#[link(name = "IOKit", kind = "framework")]
extern "C" {
    fn IOPSCopyPowerSourcesInfo() -> *const std::ffi::c_void;
    fn IOPSGetProvidingPowerSourceType(blob: *const std::ffi::c_void) -> *const std::ffi::c_void;
}
#[link(name = "CoreFoundation", kind = "framework")]
extern "C" {
    fn CFRelease(cf: *const std::ffi::c_void);
    fn CFStringGetCString(
        s: *const std::ffi::c_void,
        buf: *mut libc::c_char,
        size: libc::c_long,
        encoding: u32,
    ) -> u8;
}
const K_CF_STRING_ENCODING_UTF8: u32 = 0x0800_0100;

fn on_battery() -> Option<bool> {
    // SAFETY: IOKit power-source API; the blob is released after use, and the source-type string is
    // owned by the blob (Get rule), read before the release.
    unsafe {
        let blob = IOPSCopyPowerSourcesInfo();
        if blob.is_null() {
            return None;
        }
        let ty = IOPSGetProvidingPowerSourceType(blob);
        let mut buf = [0 as libc::c_char; 64];
        let ok = !ty.is_null()
            && CFStringGetCString(
                ty,
                buf.as_mut_ptr(),
                buf.len() as _,
                K_CF_STRING_ENCODING_UTF8,
            ) != 0;
        let text = ok.then(|| {
            std::ffi::CStr::from_ptr(buf.as_ptr())
                .to_string_lossy()
                .into_owned()
        });
        CFRelease(blob);
        text.map(|t| t == "Battery Power")
    }
}

/// Reads the power state now (cheap: two Objective-C calls and one IOKit query).
pub fn power_state() -> PowerState {
    use metal::objc::runtime::{Object, BOOL, NO};
    use metal::objc::{class, msg_send, sel, sel_impl};
    // SAFETY: `+[NSProcessInfo processInfo]` returns the shared instance (not owned);
    // `isLowPowerModeEnabled` is only sent when the instance responds to it (macOS 12+).
    let (low_power_mode, thermal) = unsafe {
        let info: *mut Object = msg_send![class!(NSProcessInfo), processInfo];
        if info.is_null() {
            (None, None)
        } else {
            let responds: BOOL = msg_send![info, respondsToSelector: sel!(isLowPowerModeEnabled)];
            let lpm = if responds != NO {
                let v: BOOL = msg_send![info, isLowPowerModeEnabled];
                Some(v != NO)
            } else {
                None
            };
            let t: i64 = msg_send![info, thermalState];
            (lpm, Thermal::from_raw(t))
        }
    };
    PowerState {
        low_power_mode,
        on_battery: on_battery(),
        thermal,
    }
}

/// Logs the power state (`warn` when it slows proving) and returns it.
pub fn log_power_state(at: &str) -> PowerState {
    let p = power_state();
    match p.reduced() {
        Some(why) => tracing::warn!(
            "power state at {at}: {} -- proving is slower than this Mac's full speed ({why}); a \
             benchmark taken now underestimates it",
            p.describe()
        ),
        None => tracing::info!("power state at {at}: {}", p.describe()),
    }
    p
}

// ---- W7-M11: packaged offline (AOT) Metal binary archives ----

/// Revert knob for [`apply_packaged_aot_dir`]: `0`, `off` or `false` leaves `RISC0_METAL_AOT_DIR` as
/// the worker was started with (unset: no offline archives).
pub const AOT_ENV: &str = "ZKMINER_METAL_AOT";

/// The directory beside the installed worker that the installer copies risc0 W7-Z1's offline
/// archives into (`make -f Makefile.mac mac-install-worker AOT_SRC=...`,
/// `scripts/mac/install-metal-aot.sh`): `~/.zkminer/provers/metal-aot`.
pub const AOT_DIR_NAME: &str = "metal-aot";

/// risc0's variable for the offline archive directory (`risc0_zkp::hal::metal::archive::AOT_DIR_ENV`).
pub const RISC0_AOT_DIR_ENV: &str = "RISC0_METAL_AOT_DIR";

/// What [`apply_packaged_aot_dir`] decided, for the start-up log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AotDecision {
    /// `RISC0_METAL_AOT_DIR` was set to the packaged directory.
    Set(std::path::PathBuf),
    /// The operator set `RISC0_METAL_AOT_DIR` already: left alone.
    Operator(std::ffi::OsString),
    /// [`AOT_ENV`] is off.
    Off,
    /// No packaged directory with archives beside the worker.
    Absent,
}

/// The packaged directory for a worker at `exe`, when it holds at least one `.binarchive`.
pub fn packaged_aot_dir(exe: &std::path::Path) -> Option<std::path::PathBuf> {
    let dir = exe.parent()?.join(AOT_DIR_NAME);
    let has_archive = std::fs::read_dir(&dir)
        .ok()?
        .flatten()
        .any(|e| e.path().extension().is_some_and(|x| x == "binarchive"));
    has_archive.then_some(dir)
}

/// [`apply_packaged_aot_dir`]'s decision as a pure function of its inputs.
pub fn aot_decision(
    knob: Option<&str>,
    current: Option<std::ffi::OsString>,
    packaged: Option<std::path::PathBuf>,
) -> AotDecision {
    if knob.is_some_and(value_is_off) {
        return AotDecision::Off;
    }
    if let Some(cur) = current.filter(|c| !c.is_empty()) {
        return AotDecision::Operator(cur);
    }
    match packaged {
        Some(dir) => AotDecision::Set(dir),
        None => AotDecision::Absent,
    }
}

/// W7-M11: when the installer packaged risc0 W7-Z1's offline archives beside this binary
/// ([`AOT_DIR_NAME`]), points `RISC0_METAL_AOT_DIR` at them, so a first install (cold OS shader
/// cache, no runtime archives) loads its pipelines from them instead of compiling them (65-85 s,
/// BASELINES 6.2). On a warm start risc0 opens the offline file only after its runtime archive
/// misses (W7-Z1), so keeping it set costs nothing there. Call first thing in `main`, before any
/// thread reads the environment or opens a Metal library. Logged by [`log_aot_decision`].
pub fn apply_packaged_aot_dir() -> &'static AotDecision {
    static DONE: OnceLock<AotDecision> = OnceLock::new();
    DONE.get_or_init(|| {
        let packaged = std::env::current_exe()
            .ok()
            .and_then(|exe| packaged_aot_dir(&exe));
        let decision = aot_decision(
            std::env::var(AOT_ENV).ok().as_deref(),
            std::env::var_os(RISC0_AOT_DIR_ENV),
            packaged,
        );
        if let AotDecision::Set(dir) = &decision {
            std::env::set_var(RISC0_AOT_DIR_ENV, dir);
        }
        decision
    })
}

/// Logs [`apply_packaged_aot_dir`]'s decision (once tracing is up).
pub fn log_aot_decision() {
    match apply_packaged_aot_dir() {
        AotDecision::Set(dir) => tracing::info!(
            "offline Metal archives: {RISC0_AOT_DIR_ENV}={} (packaged beside the worker; {AOT_ENV}=0 \
             turns this off)",
            dir.display()
        ),
        AotDecision::Operator(dir) => tracing::info!(
            "offline Metal archives: {RISC0_AOT_DIR_ENV}={} (set by the operator)",
            dir.to_string_lossy()
        ),
        AotDecision::Off => tracing::info!("offline Metal archives: off ({AOT_ENV}=0)"),
        AotDecision::Absent => tracing::debug!("offline Metal archives: none packaged"),
    }
}

/// This Mac's GPU architecture name (`MTLDevice.architecture.name`, e.g. `applegpu_g17s`), which
/// names the offline archive set it can use; `--metal-arch` prints it for the installer.
pub fn gpu_architecture() -> Option<String> {
    let device = metal::Device::system_default()?;
    risc0_zkp::hal::metal::archive::gpu_architecture(&device)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reduced_power_names_each_cause_and_ignores_fair() {
        let full = PowerState {
            low_power_mode: Some(false),
            on_battery: Some(false),
            thermal: Some(Thermal::Fair),
        };
        assert_eq!(full.reduced(), None);
        assert_eq!(
            PowerState::default().reduced(),
            None,
            "unknown is not reduced"
        );
        let lpm = PowerState {
            low_power_mode: Some(true),
            ..full
        };
        assert_eq!(lpm.reduced().as_deref(), Some("Low Power Mode is on"));
        let all = PowerState {
            low_power_mode: Some(true),
            on_battery: Some(true),
            thermal: Some(Thermal::Critical),
        };
        let why = all.reduced().unwrap();
        assert!(why.contains("battery") && why.contains("critical"), "{why}");
        // The protocol form agrees about what is reduced (W7-M11).
        assert_eq!(full.to_bench().reduced(), None);
        assert_eq!(full.to_bench().thermal, Some(1));
        assert!(lpm.to_bench().reduced().is_some());
        assert_eq!(all.to_bench().thermal, Some(3));
        assert!(all.to_bench().reduced().unwrap().contains("critical"));
        let serious = PowerState {
            thermal: Some(Thermal::Serious),
            ..full
        };
        assert_eq!(
            serious.reduced().is_some(),
            serious.to_bench().reduced().is_some()
        );
        assert_eq!(PowerState::default().to_bench().reduced(), None);
        assert!(full.describe().contains("thermal fair"));
    }

    /// The dev machine is a Mac Studio on mains power: the probes answer, and say so.
    #[test]
    fn this_macs_power_state_is_readable() {
        let p = power_state();
        assert!(p.low_power_mode.is_some(), "{p:?}");
        assert!(p.thermal.is_some(), "{p:?}");
        eprintln!("{}", p.describe());
    }

    #[test]
    fn the_calling_thread_can_take_user_initiated() {
        std::thread::spawn(|| {
            assert!(set_thread_user_initiated());
            // SAFETY: reads the calling thread's QoS class.
            assert_eq!(unsafe { qos_class_self() }, QOS_CLASS_USER_INITIATED);
        })
        .join()
        .unwrap();
    }

    #[test]
    fn the_packaged_aot_dir_is_used_only_when_it_holds_archives_and_nobody_chose() {
        let tmp = std::env::temp_dir().join(format!("w7m11-aot-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(tmp.join(AOT_DIR_NAME)).unwrap();
        let exe = tmp.join("zkminer-prove-risc0-metal");
        // An empty directory is not a packaged set.
        assert_eq!(packaged_aot_dir(&exe), None);
        std::fs::write(tmp.join(AOT_DIR_NAME).join("SHA256SUMS"), b"").unwrap();
        assert_eq!(packaged_aot_dir(&exe), None);
        std::fs::write(
            tmp.join(AOT_DIR_NAME)
                .join("zkp-0123-applegpu_g17s-macos27-ab.binarchive"),
            b"x",
        )
        .unwrap();
        let dir = packaged_aot_dir(&exe).unwrap();
        assert_eq!(dir, tmp.join(AOT_DIR_NAME));
        // Not beside another binary.
        assert_eq!(
            packaged_aot_dir(&std::env::temp_dir().join("nowhere/x")),
            None
        );
        let p = Some(dir.clone());
        assert_eq!(
            aot_decision(None, None, p.clone()),
            AotDecision::Set(dir.clone())
        );
        assert_eq!(
            aot_decision(Some("1"), None, p.clone()),
            AotDecision::Set(dir.clone())
        );
        assert_eq!(aot_decision(Some("0"), None, p.clone()), AotDecision::Off);
        assert_eq!(
            aot_decision(Some(" off "), None, p.clone()),
            AotDecision::Off
        );
        let op = std::ffi::OsString::from("/elsewhere");
        assert_eq!(
            aot_decision(None, Some(op.clone()), p.clone()),
            AotDecision::Operator(op)
        );
        // An empty variable counts as unset (risc0 reads it so too).
        assert_eq!(
            aot_decision(None, Some(std::ffi::OsString::new()), p),
            AotDecision::Set(dir)
        );
        assert_eq!(aot_decision(None, None, None), AotDecision::Absent);
        std::fs::remove_dir_all(&tmp).unwrap();
    }

    #[test]
    fn this_macs_gpu_architecture_is_readable() {
        let arch = gpu_architecture().expect("MTLDevice.architecture");
        assert!(arch.starts_with("applegpu_"), "{arch}");
    }

    #[test]
    fn the_prewarm_knob_parses_off_values() {
        // A pure parse: no process-wide env mutation under the parallel harness (PLAN 8.7).
        for (v, off) in [
            ("0", true),
            ("off", true),
            (" false ", true),
            ("1", false),
            ("", false),
        ] {
            assert_eq!(value_is_off(v), off, "{v:?}");
        }
        assert!(!knob_off("ZKMINER_M9_TEST_KNOB_NEVER_SET"));
    }
}
