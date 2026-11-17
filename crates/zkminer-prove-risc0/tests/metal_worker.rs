//! The Metal worker over its IPC protocol, as the dispatcher drives it: Hello, Capabilities, Warmup
//! (pipelines + one verified Groth16 proof), one Prove, Shutdown. Needs an Apple Silicon Mac and the
//! `risc0-groth16` component (Warmup installs it), so it is ignored by default:
//!
//!   cargo test --release -p zkminer-prove-risc0 --features metal --test metal_worker --no-run
//!   gpu-run --tag <who> -- <that test binary> --ignored --nocapture --test-threads=1
//!
//! MEMORY: each test spawns a full Metal worker that sizes itself to the whole GPU budget and peaks
//! at ~13-14 GB of footprint; risc0's GPU lock only serializes within one process. Three at once
//! would exceed a 36 GB Mac's RAM (the kernel-panic pattern seen during the port). So every GPU
//! test here takes [`GPU_TEST_LOCK`] for its whole run (one worker at a time even under the default
//! parallel harness), the doc lines pass `--test-threads=1` as well, and the run belongs under the
//! exclusive (heavy) `gpu-run` lock so no other agent's prover overlaps it.
#![cfg(feature = "metal")]

use std::io::{BufReader, BufWriter, Write};
use std::process::{Command, Stdio};
use std::time::Instant;

use zkminer_prover_protocol::{read_message, write_message, WorkerCommand, WorkerResponse};

/// Held by every GPU test for its whole run: at most one Metal worker alive per test process.
static GPU_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn gpu_test_lock() -> std::sync::MutexGuard<'static, ()> {
    // A failed test poisons the lock; the next one may still run on its own.
    GPU_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

#[test]
#[ignore = "proves on the Apple GPU; run with --ignored"]
fn the_metal_worker_warms_up_and_proves_over_ipc() {
    let _gpu = gpu_test_lock();
    let mut child = Command::new(env!("CARGO_BIN_EXE_zkminer-prove-risc0-metal"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn the worker");
    let mut to = BufWriter::new(child.stdin.take().unwrap());
    let mut from = BufReader::new(child.stdout.take().unwrap());
    let mut ask = |cmd: &WorkerCommand| -> WorkerResponse {
        write_message(&mut to, cmd).unwrap();
        to.flush().unwrap();
        loop {
            match read_message(&mut from).unwrap() {
                WorkerResponse::Progress { .. } => continue,
                other => return other,
            }
        }
    };

    match ask(&WorkerCommand::Capabilities) {
        WorkerResponse::CapabilitiesReport {
            gpu_available,
            gpu_name,
            ..
        } => {
            assert!(gpu_available);
            assert!(gpu_name.unwrap().starts_with("Apple"));
        }
        other => panic!("unexpected {other:?}"),
    }

    let t = Instant::now();
    match ask(&WorkerCommand::Warmup { request_id: 1 }) {
        WorkerResponse::WarmupDone { summary, .. } => {
            eprintln!("warm-up ({:.1} s): {summary}", t.elapsed().as_secs_f64());
            assert!(summary.contains("built the Metal pipelines"), "{summary}");
            assert!(summary.contains("verified a Groth16 proof"), "{summary}");
        }
        other => panic!("unexpected {other:?}"),
    }

    let dir = tempfile::tempdir().unwrap();
    let guest = dir.path().join("fibonacci.elf");
    let out = Command::new(env!("CARGO_BIN_EXE_zkminer-prove-risc0-metal"))
        .arg("--export-guest")
        .arg("fibonacci")
        .arg(&guest)
        .output()
        .unwrap();
    assert!(out.status.success());
    let t = Instant::now();
    match ask(&WorkerCommand::Prove {
        request_id: 2,
        elf: std::fs::read(&guest).unwrap(),
        input_data: 1000u32.to_le_bytes().to_vec(),
        po2: None,
        program_id: None,
    }) {
        WorkerResponse::ProofResult { seal, cycles, .. } => {
            eprintln!(
                "proof: {cycles} cycles, {} seal bytes, {:.1} s",
                seal.len(),
                t.elapsed().as_secs_f64()
            );
            assert!(!seal.is_empty());
        }
        other => panic!("unexpected {other:?}"),
    }

    write_message(&mut to, &WorkerCommand::Shutdown).unwrap();
    to.flush().unwrap();
    assert!(child.wait().unwrap().success());
}

/// M7: the first Prove of a fresh worker, with no Warmup before it (which would build the Groth16
/// witness graph itself), the case the worker-start graph preload is for. Prints the proof's wall
/// time; the worker's own log (stderr, `RISC0_VERBOSE=1`) has the wrap breakdown and peaks. For the
/// A/B, `ZKMINER_M7_WORKER` runs another worker binary, `ZKMINER_M7_FIB_ITERS` sizes the proof
/// (default 400000 fibonacci iterations, a few million cycles) and `ZKMINER_M7_IDLE_MS` lets the
/// worker sit idle that long before the Prove arrives, as a worker waiting for its first job does.
///
///   cargo test --release -p zkminer-prove-risc0 --features metal --test metal_worker -- --ignored --nocapture --test-threads=1 a_first_prove
#[test]
#[ignore = "proves on the Apple GPU; run with --ignored"]
fn a_first_prove_without_warmup_proves() {
    let _gpu = gpu_test_lock();
    let worker = std::env::var("ZKMINER_M7_WORKER")
        .unwrap_or_else(|_| env!("CARGO_BIN_EXE_zkminer-prove-risc0-metal").to_string());
    let iters: u32 = std::env::var("ZKMINER_M7_FIB_ITERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(400_000);
    let dir = tempfile::tempdir().unwrap();
    let guest = dir.path().join("fibonacci.elf");
    let out = Command::new(&worker)
        .arg("--export-guest")
        .arg("fibonacci")
        .arg(&guest)
        .output()
        .unwrap();
    assert!(out.status.success());

    let started = Instant::now();
    let mut child = Command::new(&worker)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn the worker");
    let mut to = BufWriter::new(child.stdin.take().unwrap());
    let mut from = BufReader::new(child.stdout.take().unwrap());
    if let Some(ms) = std::env::var("ZKMINER_M7_IDLE_MS")
        .ok()
        .and_then(|v| v.parse().ok())
    {
        std::thread::sleep(std::time::Duration::from_millis(ms));
    }
    let t = Instant::now();
    write_message(
        &mut to,
        &WorkerCommand::Prove {
            request_id: 1,
            elf: std::fs::read(&guest).unwrap(),
            input_data: iters.to_le_bytes().to_vec(),
            po2: None,
            program_id: None,
        },
    )
    .unwrap();
    to.flush().unwrap();
    loop {
        match read_message(&mut from).unwrap() {
            WorkerResponse::Progress { .. } => continue,
            WorkerResponse::ProofResult { seal, cycles, .. } => {
                eprintln!(
                    "M7 first prove: {cycles} cycles, {} seal bytes, {:.2} s (worker spawned {:.2} s \
                     before the answer)",
                    seal.len(),
                    t.elapsed().as_secs_f64(),
                    started.elapsed().as_secs_f64()
                );
                assert!(!seal.is_empty());
                break;
            }
            other => panic!("unexpected {other:?}"),
        }
    }
    write_message(&mut to, &WorkerCommand::Shutdown).unwrap();
    to.flush().unwrap();
    assert!(child.wait().unwrap().success());
}

/// The fork's `multi_test` guest (risc0-zkvm-methods), which `MultiTestSpec::KeccakUnion(n)` makes
/// request keccak proofs (the keccak circuit on the GPU, then its lift and join into the receipt).
/// zk-miner's own guests use no keccak precompile. Built by the fork's zkvm test build; override with
/// `ZKMINER_B9_KECCAK_ELF`.
const FORK_MULTI_TEST_BIN: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../deps/risc0-3.1/target/riscv-guest/risc0-zkvm-methods/risc0-zkvm-methods-guest/",
    "riscv32im-risc0-zkvm-elf/release/multi_test.bin"
);

/// `MultiTestSpec::KeccakUnion(1)` in risc0's serde words: variant 16 (the enum's 17th, counted in
/// risc0/zkvm/methods/src/multi_test.rs), then its `usize` as a u64 (two words; serde serializes
/// usize as u64 on every target).
const KECCAK_UNION_1_WORDS: [u32; 3] = [16, 1, 0];

/// B9-ZK: one worker at a tight budget (default the 4 GiB tier; `ZKMINER_B9_BUDGET` = bytes for
/// another tier below 20 GiB) through the job order that used to break the 4 GiB tier (P31-14 /
/// P31-19): Warmup (every pipeline, keccak's included, then a verified Groth16 proof), fibonacci,
/// a keccak job, an rv32im job (memory-merkle) and fibonacci again, each wrapped in Groth16 (the
/// worker verifies every receipt before answering). Below 20 GiB the worker releases the Groth16 key
/// after every proof; its stderr must show one release per wrap, each freeing a whole prover of the
/// layout the tier needs (4 GiB: split_h + tw_lent; 8 GiB: whole), back to the pipelines alone.
///
///   cargo test --release -p zkminer-prove-risc0 --features metal --test metal_worker --no-run
///   gpu-run --tag <who> -- <that test binary> --ignored --nocapture --test-threads=1 a_tight_worker
#[test]
#[ignore = "proves on the Apple GPU; run with --ignored"]
fn a_tight_worker_wraps_after_keccak_and_releases_the_key_between_jobs() {
    use std::io::BufRead;
    use std::sync::{Arc, Mutex};
    let _gpu = gpu_test_lock();
    const GIB: u64 = 1 << 30;
    let budget: u64 = std::env::var("ZKMINER_B9_BUDGET")
        .ok()
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(4 * GIB);
    assert!(
        budget < 20 * GIB,
        "the key is kept from 20 GiB up: nothing to release"
    );
    // `ZKMINER_B9_WORKER`: another worker binary (e.g. one built before B9-ZK, which proves the same
    // jobs but does not log its releases; the release checks are then skipped).
    let other_worker = std::env::var("ZKMINER_B9_WORKER").ok();
    let worker: &str = other_worker
        .as_deref()
        .unwrap_or(env!("CARGO_BIN_EXE_zkminer-prove-risc0-metal"));
    let keccak_path =
        std::env::var("ZKMINER_B9_KECCAK_ELF").unwrap_or_else(|_| FORK_MULTI_TEST_BIN.to_string());
    let keccak_elf = std::fs::read(&keccak_path).unwrap_or_else(|e| {
        panic!(
            "the keccak guest {keccak_path}: {e}. Build the fork's risc0-zkvm-methods (any risc0-zkvm \
             test build does) or point ZKMINER_B9_KECCAK_ELF at a multi_test .bin"
        )
    });
    let dir = tempfile::tempdir().unwrap();
    let export = |name: &str| -> Vec<u8> {
        let path = dir.path().join(format!("{name}.elf"));
        // This build's worker: one built before B9-ZK exports only fibonacci.
        let out = Command::new(env!("CARGO_BIN_EXE_zkminer-prove-risc0-metal"))
            .arg("--export-guest")
            .arg(name)
            .arg(&path)
            .output()
            .unwrap();
        assert!(out.status.success(), "export {name}");
        std::fs::read(&path).unwrap()
    };
    let fibonacci = export("fibonacci");
    let merkle = export("memory-merkle");

    let mut child = Command::new(worker)
        .env("RISC0_METAL_MAX_WORKING_SET_BYTES", budget.to_string())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn the worker");
    // The worker's log, echoed and kept for the checks below.
    let log: Arc<Mutex<Vec<String>>> = Arc::default();
    let tee = {
        let log = log.clone();
        let err = BufReader::new(child.stderr.take().unwrap());
        std::thread::spawn(move || {
            for line in err.lines().map_while(Result::ok) {
                eprintln!("{line}");
                log.lock().unwrap().push(line);
            }
        })
    };
    let mut to = BufWriter::new(child.stdin.take().unwrap());
    let mut from = BufReader::new(child.stdout.take().unwrap());
    let mut ask = |cmd: &WorkerCommand| -> WorkerResponse {
        write_message(&mut to, cmd).unwrap();
        to.flush().unwrap();
        loop {
            match read_message(&mut from).unwrap() {
                WorkerResponse::Progress { .. } => continue,
                other => return other,
            }
        }
    };

    let t = Instant::now();
    match ask(&WorkerCommand::Warmup { request_id: 1 }) {
        WorkerResponse::WarmupDone { summary, .. } => {
            eprintln!("B9 warm-up ({:.1} s): {summary}", t.elapsed().as_secs_f64());
            assert!(summary.contains("verified a Groth16 proof"), "{summary}");
        }
        other => panic!("warm-up: unexpected {other:?}"),
    }
    let keccak_input: Vec<u8> = KECCAK_UNION_1_WORDS
        .iter()
        .flat_map(|w| w.to_le_bytes())
        .collect();
    let jobs: [(&str, &[u8], Vec<u8>); 4] = [
        ("fibonacci", &fibonacci, 100_000u32.to_le_bytes().to_vec()),
        ("keccak", &keccak_elf, keccak_input),
        (
            "rv32im (memory-merkle)",
            &merkle,
            64u32.to_le_bytes().to_vec(),
        ),
        (
            "fibonacci again",
            &fibonacci,
            1_000u32.to_le_bytes().to_vec(),
        ),
    ];
    for (i, (name, elf, input)) in jobs.iter().enumerate() {
        let t = Instant::now();
        match ask(&WorkerCommand::Prove {
            request_id: 10 + i as u64,
            elf: elf.to_vec(),
            input_data: input.clone(),
            po2: None,
            program_id: None,
        }) {
            WorkerResponse::ProofResult { seal, cycles, .. } => {
                eprintln!(
                    "B9 job {name}: {cycles} cycles, {} seal bytes, {:.2} s",
                    seal.len(),
                    t.elapsed().as_secs_f64()
                );
                assert_eq!(seal.len(), 256, "{name}: a Groth16 proof");
            }
            other => panic!("{name}: unexpected {other:?}"),
        }
    }
    write_message(&mut to, &WorkerCommand::Shutdown).unwrap();
    to.flush().unwrap();
    assert!(child.wait().unwrap().success());
    tee.join().unwrap();

    // One release per wrap (the warm-up's and the four jobs'), each a whole prover.
    let log = log.lock().unwrap();
    let releases: Vec<&String> = log
        .iter()
        .filter(|l| l.contains("Groth16 proving key released:"))
        .collect();
    if releases.is_empty() && other_worker.is_some() {
        eprintln!("B9: {worker} logs no releases: release checks skipped");
        return;
    }
    assert_eq!(releases.len(), 1 + jobs.len(), "{releases:#?}");
    let want = if budget <= 5 * GIB {
        "prover layout split_h + tw_lent"
    } else {
        "prover layout whole"
    };
    let number_before = |l: &str, tail: &str| -> f64 {
        let head = &l[..l.find(tail).unwrap_or_else(|| panic!("{tail:?} in {l}"))];
        head.rsplit(' ').next().unwrap().parse().unwrap()
    };
    for l in &releases {
        assert!(l.contains(want), "expected {want}: {l}");
        let freed = number_before(l, " MiB of device memory freed");
        assert!(freed > 3800.0, "a whole Groth16 prover is freed: {l}");
        let now: f64 = l
            .split("device allocation now ")
            .nth(1)
            .and_then(|t| t.split(' ').next())
            .and_then(|n| n.parse().ok())
            .unwrap_or_else(|| panic!("no allocation in {l}"));
        assert!(now < 256.0, "back to the pipelines after the release: {l}");
    }
}

/// `phys_footprint` (now, lifetime peak) of a child process, in bytes.
fn footprint(pid: u32) -> Option<(u64, u64)> {
    // SAFETY: plain old data; `proc_pid_rusage` fills at most one `rusage_info_v4`.
    let mut ri: libc::rusage_info_v4 = unsafe { std::mem::zeroed() };
    let rc = unsafe {
        libc::proc_pid_rusage(
            pid as libc::c_int,
            libc::RUSAGE_INFO_V4,
            (&mut ri as *mut libc::rusage_info_v4).cast(),
        )
    };
    (rc == 0).then_some((ri.ri_phys_footprint, ri.ri_lifetime_max_phys_footprint))
}

/// M9: many Proves in one worker process, as the dispatcher sends them between recycles. Prints
/// each proof's wall time and the worker's idle footprint after it, which is what the Metal
/// recycle policy (and its memory-growth safety net) is sized from. `ZKMINER_M9_WORKER` runs another
/// worker binary, `ZKMINER_M9_PROOFS` (default 10) and `ZKMINER_M9_FIB_ITERS` (default 400000) size
/// the run, `ZKMINER_M9_WARMUP=1` sends a Warmup first and `ZKMINER_M9_IDLE_MS` waits that long
/// after the worker starts (or after the Warmup) before the first Prove. `ZKMINER_M9_GAP_MS` waits
/// between proofs. `ZKMINER_M9_HOLD_MS` keeps the worker alive and idle that long after the last proof, for `footprint -p <pid>`.
///
///   cargo test --release -p zkminer-prove-risc0 --features metal --test metal_worker -- --ignored --nocapture --test-threads=1 m9_proofs
#[test]
#[ignore = "proves on the Apple GPU; run with --ignored"]
fn m9_proofs_in_one_worker() {
    let _gpu = gpu_test_lock();
    let env_num = |k: &str, d: u64| -> u64 {
        std::env::var(k)
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(d)
    };
    let worker = std::env::var("ZKMINER_M9_WORKER")
        .unwrap_or_else(|_| env!("CARGO_BIN_EXE_zkminer-prove-risc0-metal").to_string());
    let proofs = env_num("ZKMINER_M9_PROOFS", 10);
    let iters = env_num("ZKMINER_M9_FIB_ITERS", 400_000) as u32;
    let dir = tempfile::tempdir().unwrap();
    let guest = dir.path().join("fibonacci.elf");
    let out = Command::new(&worker)
        .arg("--export-guest")
        .arg("fibonacci")
        .arg(&guest)
        .output()
        .unwrap();
    assert!(out.status.success());
    let elf = std::fs::read(&guest).unwrap();

    let started = Instant::now();
    let mut child = Command::new(&worker)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn the worker");
    let pid = child.id();
    let mut to = BufWriter::new(child.stdin.take().unwrap());
    let mut from = BufReader::new(child.stdout.take().unwrap());
    let mut ask = |cmd: &WorkerCommand| -> WorkerResponse {
        write_message(&mut to, cmd).unwrap();
        to.flush().unwrap();
        loop {
            match read_message(&mut from).unwrap() {
                WorkerResponse::Progress { .. } => continue,
                other => return other,
            }
        }
    };
    let mib = |b: u64| b >> 20;
    if std::env::var("ZKMINER_M9_WARMUP").is_ok_and(|v| v == "1") {
        let t = Instant::now();
        match ask(&WorkerCommand::Warmup { request_id: 1 }) {
            WorkerResponse::WarmupDone { summary, .. } => {
                eprintln!("M9 warm-up {:.2} s: {summary}", t.elapsed().as_secs_f64())
            }
            other => panic!("unexpected {other:?}"),
        }
    }
    let idle = env_num("ZKMINER_M9_IDLE_MS", 0);
    if idle > 0 {
        std::thread::sleep(std::time::Duration::from_millis(idle));
    }
    if let Some((now, peak)) = footprint(pid) {
        eprintln!(
            "M9 before proof 1: footprint {} MiB, lifetime peak {} MiB ({:.2} s after spawn)",
            mib(now),
            mib(peak),
            started.elapsed().as_secs_f64()
        );
    }
    let gap = env_num("ZKMINER_M9_GAP_MS", 0);
    for i in 1..=proofs {
        if i > 1 && gap > 0 {
            std::thread::sleep(std::time::Duration::from_millis(gap));
        }
        let t = Instant::now();
        match ask(&WorkerCommand::Prove {
            request_id: 100 + i,
            elf: elf.clone(),
            input_data: iters.to_le_bytes().to_vec(),
            po2: None,
            program_id: None,
        }) {
            WorkerResponse::ProofResult { seal, cycles, .. } => {
                assert!(!seal.is_empty());
                let wall = t.elapsed().as_secs_f64();
                let (now, peak) = footprint(pid).unwrap_or_default();
                eprintln!(
                    "M9 proof {i}: {cycles} cycles, {wall:.3} s, idle footprint {} MiB, lifetime \
                     peak {} MiB",
                    mib(now),
                    mib(peak)
                );
                // The reclaim profile the growth net's settle constants are sized from: the idle
                // footprint every 20 ms for `ZKMINER_M9_TRACE_MS` after the proof.
                let trace = env_num("ZKMINER_M9_TRACE_MS", 0);
                if trace > 0 {
                    let t0 = Instant::now();
                    let mut line = String::new();
                    let mut last = u64::MAX;
                    while t0.elapsed().as_millis() < trace as u128 {
                        let (cur, _) = footprint(pid).unwrap_or_default();
                        if mib(cur) != last {
                            line += &format!(" {}ms:{}", t0.elapsed().as_millis(), mib(cur));
                            last = mib(cur);
                        }
                        std::thread::sleep(std::time::Duration::from_millis(20));
                    }
                    eprintln!("M9 trace after proof {i} (MiB):{line}");
                }
            }
            other => panic!("unexpected {other:?}"),
        }
    }
    // Lets `footprint -p <pid>` look at the idle worker.
    let hold = env_num("ZKMINER_M9_HOLD_MS", 0);
    if hold > 0 {
        eprintln!("M9 holding the idle worker (pid {pid}) for {hold} ms");
        std::thread::sleep(std::time::Duration::from_millis(hold));
    }
    write_message(&mut to, &WorkerCommand::Shutdown).unwrap();
    to.flush().unwrap();
    assert!(child.wait().unwrap().success());
}

/// M9's memory-growth net against a REAL leaking Metal worker, driven by the dispatcher: the
/// worker (built with the test-only `testing` feature) leaks `ZKMINER_M9_LEAK_MIB` (default 128)
/// MiB of host memory per proof, at a 4 GiB working-set budget (margin `clamp(4 GiB / 4, 1 GiB,
/// 2 GiB)` = 1 GiB), with the proofs arriving back to back, after a 2.5 s idle gap and 0.6 s
/// after the previous one (mid-reclaim), in turn. The dispatcher must recycle the worker
/// gracefully (every proof succeeds, no failure counted, one respawn) near the predicted proof.
/// The baseline is the maximum settled level of the first 10 proofs (up to the net's 256 MiB
/// tolerance below it), so the settled level passes baseline + margin about margin / g proofs
/// after proof 10, where g is the settled growth per proof. g is measured here from the settled
/// readings after the idle gaps: the leak plus the caches' own growth (~45 MiB a proof beyond a
/// 128 MiB leak in the fix-round-3 runs), so a prediction from the leak alone came out 3 late.
///
///   cargo test --release -p zkminer-prove-risc0 --features metal,testing --test metal_worker --no-run
///   gpu-run --tag <who> --budget 4G -- <that test binary> --ignored --nocapture --test-threads=1 a_leaking
#[cfg(feature = "testing")]
#[test]
#[ignore = "proves on the Apple GPU; run with --ignored"]
fn a_leaking_metal_worker_is_recycled_by_the_dispatcher() {
    use std::collections::HashMap;
    use std::time::Duration;
    let _gpu = gpu_test_lock();
    let _ = tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .try_init();
    let env_num = |k: &str, d: u64| -> u64 {
        std::env::var(k)
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(d)
    };
    let leak_mib = env_num("ZKMINER_M9_LEAK_MIB", 128);
    let iters = env_num("ZKMINER_M9_FIB_ITERS", 100_000) as u32;
    let worker = env!("CARGO_BIN_EXE_zkminer-prove-risc0-metal");
    let dir = tempfile::tempdir().unwrap();
    let guest = dir.path().join("fibonacci.elf");
    let out = Command::new(worker)
        .arg("--export-guest")
        .arg("fibonacci")
        .arg(&guest)
        .output()
        .unwrap();
    assert!(out.status.success());
    let elf = std::fs::read(&guest).unwrap();

    const GIB: u64 = 1 << 30;
    let budget = 4 * GIB;
    let margin_mib: u64 = 1024;
    let mut env = HashMap::new();
    env.insert(
        "RISC0_METAL_MAX_WORKING_SET_BYTES".to_string(),
        budget.to_string(),
    );
    env.insert(
        "ZKMINER_TEST_LEAK_MIB_PER_PROOF".to_string(),
        leak_mib.to_string(),
    );
    let key = "risc0:metal";
    let mut pool = zkminer_prover::dispatcher::WorkerPool::new(HashMap::new(), Vec::new(), None);
    pool.insert_test_worker(key, "risc0", worker.into(), env)
        .expect("spawn the Metal worker");
    pool.test_set_gpu_tag(key, "metal");
    let first_pid = pool.test_pid(key).unwrap();
    let predicted = 10 + margin_mib.div_ceil(leak_mib) as u32;
    let gap = |i: u32| match i % 4 {
        0 => Duration::from_millis(2_500),
        2 => Duration::from_millis(600),
        _ => Duration::ZERO,
    };
    let mib = |b: u64| b >> 20;
    let mut recycled_after = None;
    // (completed proofs, settled MiB) of the first worker, read after each idle gap.
    let mut settled: Vec<(u32, u64)> = Vec::new();
    let started = Instant::now();
    for i in 1..=predicted + 8 {
        std::thread::sleep(gap(i));
        let pid_before = pool.test_pid(key).unwrap();
        let fp_before = footprint(pid_before).map_or(0, |f| mib(f.0));
        if gap(i) >= Duration::from_secs(2) && pid_before == first_pid && i > 1 {
            settled.push((i - 1, fp_before));
        }
        let t = Instant::now();
        let proof = pool
            .prove(
                "risc0",
                &elf,
                &iters.to_le_bytes(),
                None,
                Some(Duration::from_secs(300)),
                None,
            )
            .unwrap_or_else(|e| panic!("proof {i}: {e:#}"));
        assert!(!proof.seal.is_empty(), "proof {i}: empty seal");
        let pid = pool.test_pid(key).unwrap();
        eprintln!(
            "M9 leak proof {i}: {:.2} s after a {:?} gap, pid {pid}, footprint before {fp_before} MiB, \
             after {} MiB ({:.0} s in)",
            t.elapsed().as_secs_f64(),
            gap(i),
            footprint(pid).map_or(0, |f| mib(f.0)),
            started.elapsed().as_secs_f64()
        );
        if pid != first_pid && recycled_after.is_none() {
            // Recycled before proof i: after i - 1 completed proofs.
            recycled_after = Some(i - 1);
        }
        if recycled_after.is_some_and(|n| i >= n + 2) {
            break;
        }
    }
    let n = recycled_after.unwrap_or_else(|| {
        panic!(
            "not recycled within {} proofs (predicted {predicted})",
            predicted + 8
        )
    });
    // The settled growth per proof, from the first and last idle-gap readings of the first worker.
    let (&(n0, s0), &(n1, s1)) = (settled.first().unwrap(), settled.last().unwrap());
    assert!(n1 > n0, "too few settled readings: {settled:?}");
    let g = (s1.saturating_sub(s0) as f64 / f64::from(n1 - n0)).max(1.0);
    assert!(
        g >= 0.9 * leak_mib as f64,
        "settled growth {g:.0} MiB/proof, below the {leak_mib} MiB/proof leak: {settled:?}"
    );
    let earliest = 10 + ((margin_mib - 256) as f64 / g).floor() as u32 - 1;
    let latest = 10 + (margin_mib as f64 / g).ceil() as u32 + 2;
    eprintln!(
        "M9 leak: recycled after {n} proofs; settled growth {g:.0} MiB/proof {settled:?}, \
         predicted {earliest}..={latest} ({leak_mib} MiB/proof leak alone: {predicted})"
    );
    assert!(
        (earliest..=latest).contains(&n),
        "recycled after {n} proofs, predicted {earliest}..={latest}"
    );
    assert_eq!(
        pool.test_consecutive_failures(key),
        Some(0),
        "a graceful recycle"
    );
}
