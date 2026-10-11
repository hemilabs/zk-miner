//! Regression test: two backends on ONE card make room for each other.
//!
//! risc0 and SP1 share a per-card guard, so they never prove at the same time — but the guard says
//! nothing about what an IDLE worker keeps. Measured on 2026-10-07 after a `fibonacci` proof: an idle
//! risc0 worker holds 1,806 MiB of the RTX 5080 and 7,134 MiB of the RTX 4090 (which keeps its Groth16
//! SRS cache resident); an idle SP1 worker holds 15,124 MiB of the 5080 and 15,302 MiB of the 4090,
//! still 30 s after its proof. The VRAM gate credited every process of ours as free, so it read the
//! 5080 beside an idle risc0 worker as 16,301 MiB available, admitted SP1's 15,604 MiB tier, and the
//! proof ran out of device memory and was killed by the 600 s watchdog: "Worker sp1 process died
//! (EOF)". In the other direction, a risc0 worker respawned 0.7 s after the SP1 worker was recycled
//! by hand still died on its first 8 MiB allocation, because the memory was not back yet.
//!
//! The fix reads the card per slot, recycles the other backend's idle worker when it stands in the way,
//! and waits for its memory to actually come back. This test runs the production interleaving on one
//! card — risc0, then SP1, then risc0 again — and requires all three to prove, the first switch to have
//! recycled the idle risc0 worker, and the second to have recycled the idle SP1 worker whenever that
//! still held at least 1 GiB of its own — so a run where nothing needed recycling cannot pass
//! vacuously.
//!
//! A card with more room than that is first made to look like a 16 GB one: a separate process, not
//! ours, holds device memory until what is allocatable is SP1's floor plus 1.5 GiB (or
//! `ZKMINER_TEST_VRAM_TARGET_MIB`), whatever else the card already carries. To the miner it is
//! foreign, like a display or another program, so nothing can reclaim it; on a 32 GB card the idle risc0
//! worker would otherwise never stand in SP1's way and the run could not exercise the fix. A card
//! already that tight is used as it is: on the 5080 SP1's smallest tier leaves only 276 MiB to spare
//! (15,880 MiB allocatable against 15,604), so there a desktop session fails the SP1 step for reasons
//! that have nothing to do with this fix. The 4090 step assumes a host budget that allows the 268M
//! tier (at least 21⅓ GiB, two thirds of the 32 GiB reference), which is what makes its idle risc0
//! worker stand in the way.
//!
//! `#[ignore]`d — real GPU proofs. `ZKMINER_TEST_CARD` picks the card (default 0); both backends must
//! have a slot on it. Run with:
//!   ZKMINER_TEST_CARD=0 cargo test --release -p zkminer-prover --test cross_backend_vram \
//!     -- --ignored --test-threads=1 --nocapture

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use zkminer_prover::dispatcher::WorkerPool;

fn compute_app_mib(pid: u32) -> Option<u64> {
    let out = std::process::Command::new("nvidia-smi")
        .args([
            "--query-compute-apps=pid,used_gpu_memory",
            "--format=csv,noheader,nounits",
        ])
        .output()
        .ok()?;
    String::from_utf8_lossy(&out.stdout).lines().find_map(|l| {
        let (p, m) = l.split_once(',')?;
        (p.trim().parse::<u32>().ok()? == pid)
            .then(|| m.trim().parse().ok())
            .flatten()
    })
}

#[test]
#[ignore = "real GPU proofs"]
fn risc0_and_sp1_alternate_on_one_card() {
    let _ = tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .try_init();

    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let risc0_elf = root.join(
        "target/riscv-guest/zkminer-prove-risc0/fibonacci/riscv32im-risc0-zkvm-elf/release/\
         fibonacci.bin",
    );
    let sp1_elf = root.join(
        "crates/zkminer-prover/guests/sp1/fibonacci/target/elf-compilation/\
         riscv64im-succinct-zkvm-elf/release/fibonacci-sp1-guest",
    );
    let (Ok(risc0_elf), Ok(sp1_elf)) = (std::fs::read(&risc0_elf), std::fs::read(&sp1_elf)) else {
        eprintln!("SKIP: build the risc0 and SP1 fibonacci guests first");
        return;
    };

    let card = std::env::var("ZKMINER_TEST_CARD").unwrap_or_else(|_| "0".into());
    let (risc0, sp1) = (format!("risc0:cuda:{card}"), format!("sp1:cuda:{card}"));

    // Before any worker exists, so each is sized for the card as it will be.
    let floor_mib = zkminer_prover::discovery::min_available_vram_bytes_for_backend("sp1")
        .expect("sp1 must require free VRAM for this test to mean anything")
        >> 20;
    let target_mib = std::env::var("ZKMINER_TEST_VRAM_TARGET_MIB")
        .ok()
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(floor_mib + 1536);
    let _ballast = match allocatable_mib(&card) {
        Some(allocatable) if allocatable >= target_mib + 1024 => {
            let ballast = Ballast::start(&card, allocatable - target_mib);
            eprintln!(
                "RESULT card {card}: {allocatable} MiB allocatable; ballast holds {} MiB of it, \
                 leaving ~{} MiB against SP1's {floor_mib} MiB floor",
                ballast.held_mib,
                allocatable - ballast.held_mib
            );
            Some(ballast)
        }
        allocatable => {
            eprintln!("RESULT card {card}: {allocatable:?} MiB allocatable; no ballast");
            None
        }
    };

    let mut pool = WorkerPool::new(HashMap::new(), vec![], Some(Duration::from_secs(900)));
    let connected = pool.discover_and_spawn();
    if !connected.contains(&risc0) || !connected.contains(&sp1) {
        eprintln!("SKIP: need both {risc0} and {sp1} (connected: {connected:?})");
        pool.shutdown_all();
        return;
    }

    let input = 100u32.to_le_bytes();
    let budget = Some(Duration::from_secs(600));
    let prove = |key: &str, elf: &[u8]| {
        let t = Instant::now();
        let r = pool.prove(key, elf, &input, None, budget, None);
        eprintln!(
            "RESULT {key}: {} in {:.1}s",
            match &r {
                Ok(p) => format!("PROVED, seal {} bytes", p.seal.len()),
                Err(e) => format!("FAILED {e:#}"),
            },
            t.elapsed().as_secs_f64()
        );
        r
    };

    // risc0 first, leaving its worker idle on the card.
    let first = prove(&risc0, &risc0_elf);
    let risc0_pid = pool.worker_pid(&risc0).unwrap_or(0);
    eprintln!(
        "RESULT idle {risc0} worker (pid {risc0_pid}) holds {:?} MiB",
        compute_app_mib(risc0_pid)
    );
    let before_sp1 = pool.vram_budget_for_slot(&sp1);
    eprintln!("RESULT {sp1} before admission: {before_sp1:?}");

    // SP1 must make room.
    let second = prove(&sp1, &sp1_elf);
    let risc0_after = pool.worker_pid(&risc0).unwrap_or(0);
    eprintln!(
        "RESULT {risc0} worker after the SP1 admission: {}",
        if risc0_after == risc0_pid {
            format!("kept (pid {risc0_after})")
        } else {
            format!("recycled (pid {risc0_pid} -> {risc0_after})")
        }
    );

    // The reverse direction. Does the idle SP1 worker give its arena back by itself? Watched for
    // 30 s and reported; the fix must not depend on the answer.
    // SP1's OWN holding: what the card has in use less what SP1's slot sees as held elsewhere. Not
    // risc0's view, which would count a desktop session as SP1's.
    let sp1_holds = || {
        pool.vram_budget_for_slot(&sp1)
            .map_or(0, |b| b.used.saturating_sub(b.held_elsewhere))
    };
    let t = Instant::now();
    let held_by_sp1 = loop {
        let held = sp1_holds();
        if held < 1 << 30 || t.elapsed() >= Duration::from_secs(30) {
            break held;
        }
        std::thread::sleep(Duration::from_secs(1));
    };
    eprintln!(
        "RESULT idle {sp1} worker, {:.0}s after its proof, holds {} MiB of the card",
        t.elapsed().as_secs_f64(),
        held_by_sp1 >> 20
    );
    let sp1_pid = pool.worker_pid(&sp1).unwrap_or(0);

    // risc0 must make room in turn, and its recycled worker must come back.
    let third = prove(&risc0, &risc0_elf);
    let sp1_after = pool.worker_pid(&sp1).unwrap_or(0);
    eprintln!(
        "RESULT {sp1} worker after the risc0 admission: {}",
        if sp1_after == sp1_pid {
            format!("kept (pid {sp1_after})")
        } else {
            format!("recycled (pid {sp1_pid} -> {sp1_after})")
        }
    );
    pool.shutdown_all();

    first.expect("the first risc0 proof must succeed on an otherwise idle card");
    let proof = second.unwrap_or_else(|e| {
        panic!(
            "SP1 could not prove on {sp1} after risc0 had proved there: {e:#}. The other backend's \
             idle worker must be recycled when it stands between SP1 and its tier."
        )
    });
    assert!(!proof.seal.is_empty());
    // Non-vacuity. On both cards here the idle risc0 worker leaves less than SP1's tier needs
    // (5080: 14,072 MiB against 15,604; 4090: 16,973 against 18,278 — see the header for what that
    // assumes), so a pass without a recycle means this run did not exercise the fix.
    assert_ne!(
        risc0_after, risc0_pid,
        "SP1 proved but the idle risc0 worker was never recycled: this run did not exercise making \
         room for SP1"
    );
    third.unwrap_or_else(|e| {
        panic!(
            "risc0 could not prove on {risc0} after SP1 had proved there: {e:#}. The recycled risc0 \
             worker must come back, and the idle SP1 worker's arena must be given back first."
        )
    });
    if held_by_sp1 >= 1 << 30 {
        assert_ne!(
            sp1_after, sp1_pid,
            "risc0 proved beside {} MiB of an idle SP1 worker without recycling it: this run did not \
             exercise making room for risc0",
            held_by_sp1 >> 20
        );
    }
}

/// What the card has free to allocate, in MiB: its capacity less the driver's reservation and
/// everything in use.
fn allocatable_mib(card: &str) -> Option<u64> {
    let out = std::process::Command::new("nvidia-smi")
        .args([
            "-i",
            card,
            "--query-gpu=memory.total,memory.reserved,memory.used",
            "--format=csv,noheader,nounits",
        ])
        .output()
        .ok()?;
    let row = String::from_utf8_lossy(&out.stdout);
    let mut f = row.trim().split(',').map(|v| v.trim().parse::<u64>().ok());
    let (total, reserved, used) = (f.next()??, f.next()?.unwrap_or(0), f.next()??);
    Some(total.saturating_sub(reserved).saturating_sub(used))
}

const BALLAST_MIB_ENV: &str = "ZKMINER_TEST_VRAM_BALLAST_MIB";
const BALLAST_CARD_ENV: &str = "ZKMINER_TEST_VRAM_BALLAST_CARD";
const BALLAST_REPORT_ENV: &str = "ZKMINER_TEST_VRAM_BALLAST_REPORT";

/// Device memory held by a process that is not ours, for as long as this lives.
///
/// Started detached, so it is not a descendant of the test process: one of ours would be credited to
/// us (`attribute_pid`), and what this stands in for is memory the miner cannot reclaim. It runs this
/// test binary's `vram_ballast_process`.
struct Ballast {
    pid: u32,
    held_mib: u64,
}

impl Ballast {
    fn start(card: &str, mib: u64) -> Self {
        let report =
            std::env::temp_dir().join(format!("zkminer-vram-ballast-{}", std::process::id()));
        let _ = std::fs::remove_file(&report);
        let exe = std::env::current_exe().unwrap();
        let args = [
            "--exact",
            "vram_ballast_process",
            "--ignored",
            "--test-threads=1",
        ];
        #[cfg(windows)]
        let mut launcher = {
            let mut c = std::process::Command::new("cmd");
            c.args(["/C", "start", "", "/B"]).arg(&exe).args(args);
            c
        };
        #[cfg(unix)]
        let mut launcher = {
            let mut c = std::process::Command::new("sh");
            c.args(["-c", r#""$0" "$@" >/dev/null 2>&1 &"#])
                .arg(&exe)
                .args(args);
            c
        };
        let status = launcher
            .env(BALLAST_MIB_ENV, mib.to_string())
            .env(BALLAST_CARD_ENV, card)
            .env(BALLAST_REPORT_ENV, &report)
            // CUDA ordinals in nvidia-smi's order, and every card visible to it.
            .env("CUDA_DEVICE_ORDER", "PCI_BUS_ID")
            .env_remove("CUDA_VISIBLE_DEVICES")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .expect("launch the VRAM ballast");
        assert!(status.success(), "VRAM ballast launcher: {status}");

        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            if let Some((pid, held_mib)) = std::fs::read_to_string(&report).ok().and_then(|r| {
                let (pid, held) = r.trim().split_once(' ')?;
                Some((pid.parse().ok()?, held.parse().ok()?))
            }) {
                let _ = std::fs::remove_file(&report);
                return Ballast { pid, held_mib };
            }
            assert!(
                Instant::now() < deadline,
                "the VRAM ballast never reported holding its memory"
            );
            std::thread::sleep(Duration::from_millis(200));
        }
    }
}

impl Drop for Ballast {
    fn drop(&mut self) {
        #[cfg(windows)]
        let _ = std::process::Command::new("taskkill")
            .args(["/F", "/PID", &self.pid.to_string()])
            .stdout(std::process::Stdio::null())
            .status();
        #[cfg(unix)]
        unsafe {
            libc::kill(self.pid as i32, libc::SIGKILL);
        }
    }
}

/// The ballast itself: holds the asked-for device memory, reports it, and waits to be killed. Exits
/// on its own after 30 minutes in case its owner died first. Does nothing when run any other way.
#[test]
#[ignore = "helper process for risc0_and_sp1_alternate_on_one_card"]
fn vram_ballast_process() {
    let (Some(mib), Some(card), Some(report)) = (
        std::env::var(BALLAST_MIB_ENV)
            .ok()
            .and_then(|v| v.parse::<u64>().ok()),
        std::env::var(BALLAST_CARD_ENV)
            .ok()
            .and_then(|v| v.parse::<i32>().ok()),
        std::env::var_os(BALLAST_REPORT_ENV),
    ) else {
        return;
    };
    let held = cuda_driver::hold(card, mib).expect("hold device memory");
    std::fs::write(report, format!("{} {held}", std::process::id())).unwrap();
    std::thread::sleep(Duration::from_secs(30 * 60));
}

/// Just enough of the CUDA driver API, loaded at run time, to hold device memory.
mod cuda_driver {
    use std::ffi::c_void;

    type CuInit = unsafe extern "system" fn(u32) -> i32;
    type CuDeviceGet = unsafe extern "system" fn(*mut i32, i32) -> i32;
    type CuCtxCreate = unsafe extern "system" fn(*mut *mut c_void, u32, i32) -> i32;
    type CuMemAlloc = unsafe extern "system" fn(*mut u64, usize) -> i32;
    type CuMemsetD8 = unsafe extern "system" fn(u64, u8, usize) -> i32;

    #[cfg(windows)]
    fn symbol(name: &str) -> Option<*mut c_void> {
        #[link(name = "kernel32")]
        extern "system" {
            fn LoadLibraryA(name: *const u8) -> *mut c_void;
            fn GetProcAddress(module: *mut c_void, name: *const u8) -> *mut c_void;
        }
        let lib = unsafe { LoadLibraryA(b"nvcuda.dll\0".as_ptr()) };
        let name = format!("{name}\0");
        let f = (!lib.is_null()).then(|| unsafe { GetProcAddress(lib, name.as_ptr()) })?;
        (!f.is_null()).then_some(f)
    }

    #[cfg(unix)]
    fn symbol(name: &str) -> Option<*mut c_void> {
        let lib = unsafe { libc::dlopen(c"libcuda.so.1".as_ptr(), libc::RTLD_NOW) };
        let name = std::ffi::CString::new(name).ok()?;
        let f = (!lib.is_null()).then(|| unsafe { libc::dlsym(lib, name.as_ptr()) })?;
        (!f.is_null()).then_some(f)
    }

    /// Allocates up to `mib` MiB on device `ordinal` in 256 MiB pieces and writes to all of it, so it
    /// is resident and in `memory.used`. Returns how much it holds; it stays held until the process
    /// exits.
    pub fn hold(ordinal: i32, mib: u64) -> Result<u64, String> {
        const PIECE_MIB: u64 = 256;
        let get = |name| symbol(name).ok_or_else(|| format!("CUDA driver has no {name}"));
        unsafe {
            let init: CuInit = std::mem::transmute(get("cuInit")?);
            let device_get: CuDeviceGet = std::mem::transmute(get("cuDeviceGet")?);
            let ctx_create: CuCtxCreate = std::mem::transmute(get("cuCtxCreate_v2")?);
            let mem_alloc: CuMemAlloc = std::mem::transmute(get("cuMemAlloc_v2")?);
            let memset: CuMemsetD8 = std::mem::transmute(get("cuMemsetD8_v2")?);
            let check = |what: &str, r: i32| {
                (r == 0)
                    .then_some(())
                    .ok_or_else(|| format!("{what}: CUDA error {r}"))
            };
            check("cuInit", init(0))?;
            let mut device = 0;
            check("cuDeviceGet", device_get(&mut device, ordinal))?;
            let mut ctx = std::ptr::null_mut();
            check("cuCtxCreate", ctx_create(&mut ctx, 0, device))?;
            let mut held = 0;
            while held + PIECE_MIB <= mib {
                let bytes = (PIECE_MIB << 20) as usize;
                let mut ptr = 0u64;
                if mem_alloc(&mut ptr, bytes) != 0 {
                    break;
                }
                check("cuMemsetD8", memset(ptr, 0xa5, bytes))?;
                held += PIECE_MIB;
            }
            Ok(held)
        }
    }
}
