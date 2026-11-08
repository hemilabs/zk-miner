//! Explicit local acceptance: real WorkerPool, real proofs, unchanged external verifier.
#![cfg(target_os = "macos")]
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeSet, HashMap},
    fs::{self, OpenOptions},
    io::{BufRead, Write},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use zkminer_prover::{dispatcher::WorkerPool, worker::WorkerHandle};
use zkminer_prover_protocol::{WorkerCommand, WorkerResponse, PROTOCOL_VERSION};

const KEY: &str = "risc0:generic";

#[test]
#[ignore = "source-bound native worker process-launch handshake timing"]
fn native_worker_handshake_timing() {
    let binary = required("ZKMINER_MACOS_WORKER");
    let evidence = required("ZKMINER_MACOS_EVIDENCE_DIR");
    fs::create_dir_all(&evidence).unwrap();
    let mut rows = Vec::new();
    for index in 0..3 {
        let started = Instant::now();
        let worker = WorkerHandle::spawn("risc0", &binary, &HashMap::new()).unwrap();
        let pid = worker.pid();
        rows.push(json!({"index":index,"worker_pid":pid,
            "spawn_to_handshake_ms":worker.spawn_to_handshake_ms,
            "pool_call_ms":started.elapsed().as_secs_f64()*1000.0}));
        drop(worker);
        assert_group_gone(pid);
    }
    assert!(helpers().is_empty());
    fs::write(evidence.join("complete.json"), serde_json::to_vec_pretty(&json!({
        "status":"handshake_timing_passed","rows":rows,
        "span":"Command::spawn start through HelloAck, including parent supervision setup",
    })).unwrap()).unwrap();
}

#[test]
#[ignore = "fresh-user Metal driver cache reading with one complete verified proof"]
fn native_worker_cold_timing() {
    let binary = required("ZKMINER_MACOS_WORKER");
    let program = required("ZKMINER_MACOS_PROGRAM");
    let input = required("ZKMINER_MACOS_INPUT");
    let verifier = required("ZKMINER_MACOS_VERIFIER");
    let evidence = required("ZKMINER_MACOS_EVIDENCE_DIR");
    fs::create_dir_all(&evidence).unwrap();
    assert!(helpers().is_empty());
    let elf = fs::read(&program).unwrap();
    let workload = Workload::from_environment(&elf);
    assert_eq!(fs::read(&input).unwrap(), workload.input);
    let before = sidecar_paths();
    let mut worker = WorkerHandle::spawn("risc0", &binary, &HashMap::new()).unwrap();
    let pid = worker.pid();
    let spawn_to_handshake_ms = worker.spawn_to_handshake_ms;
    let handshake = Instant::now();
    let request_epoch_ns = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64;
    let handshake_to_request_ms = elapsed_ms(handshake);
    worker.send(&WorkerCommand::Prove {
        request_id: 1, elf, input_data: workload.input.clone(), po2: Some(workload.po2),
        program_id: None,
    }).unwrap();
    let response = worker.recv_proof(1, &None).unwrap();
    let proof = match response {
        WorkerResponse::ProofResult { request_id: 1, journal, seal, duration_secs, cycles } =>
            zkminer_prover::engine::ProofOutput {
                journal, seal, duration: Duration::from_secs_f64(duration_secs), cycles,
            },
        other => panic!("cold-reading proof failed: {other:?}"),
    };
    let (_, record) = require_sidecar(&before);
    let dispatch_epoch_ns = record["observed_stages"]["rv32im_metal"]
        ["first_completed_gpu_dispatch_epoch_ns"].as_u64().unwrap();
    assert!(dispatch_epoch_ns >= request_epoch_ns);
    let request_to_first_completed_gpu_dispatch_ms =
        (dispatch_epoch_ns - request_epoch_ns) as f64 / 1_000_000.0;
    let external_verifier_ms = verify(&verifier, &program, &input,
        &evidence.join("proof-0"), proof, &record, &workload);
    drop(worker);
    assert_group_gone(pid);
    assert!(helpers().is_empty());
    fs::write(evidence.join("complete.json"), serde_json::to_vec_pretty(&json!({
        "status":"cold_timing_verified", "worker_pid":pid,
        "spawn_to_handshake_ms":spawn_to_handshake_ms,
        "handshake_to_request_ms":handshake_to_request_ms,
        "request_to_first_completed_gpu_dispatch_ms":request_to_first_completed_gpu_dispatch_ms,
        "request_epoch_ns":request_epoch_ns,"dispatch_epoch_ns":dispatch_epoch_ns,
        "external_verifier_ms":external_verifier_ms,"tamper_rejections":3,
        "scope":"one WorkerHandle launch and one direct proof request; no discovery spawn, execute validation, or harness warmup in the three spans",
    })).unwrap()).unwrap();
}

#[test]
#[ignore = "corrupt native bundle must fail after handshake and before helper spawn"]
fn native_bundle_corrupt_hash_rejected() {
    let binary = required("ZKMINER_MACOS_WORKER");
    let evidence = required("ZKMINER_MACOS_EVIDENCE_DIR");
    fs::create_dir_all(&evidence).unwrap();
    let source = required("ZKMINER_RISC0_NATIVE_DIR");
    let corrupt = evidence.join("corrupt-bundle");
    fs::create_dir(&corrupt).unwrap();
    for name in ["prover", "stark_verify.cs", "stark_verify_final.pk.dmp", "stark_verify_graph.bin"] {
        assert!(Command::new("cp").arg("-c").arg(source.join(name))
            .arg(corrupt.join(name)).status().unwrap().success());
    }
    fs::copy(source.join("manifest.json"), corrupt.join("manifest.json")).unwrap();
    let mut bytes = fs::read(corrupt.join("prover")).unwrap();
    bytes[8] ^= 1; // Preserve the Mach-O header so the asynchronous hash catches the change.
    fs::write(corrupt.join("prover"), bytes).unwrap();
    let overrides = HashMap::from([("ZKMINER_RISC0_NATIVE_DIR".into(),
        corrupt.to_string_lossy().into_owned())]);
    let mut worker = WorkerHandle::spawn("risc0", &binary, &overrides).unwrap();
    let pid = worker.pid();
    worker.send(&WorkerCommand::Prove { request_id: 1,
        elf: fs::read(required("ZKMINER_MACOS_PROGRAM")).unwrap(),
        input_data: fs::read(required("ZKMINER_MACOS_INPUT")).unwrap(),
        po2: Some(14),
        program_id: None,
    }).unwrap();
    let response = worker.recv_proof(1, &None).unwrap();
    let error = match response {
        WorkerResponse::Error { request_id: 1, message, .. } => message,
        other => panic!("corrupt bundle was not refused: {other:?}"),
    };
    assert!(error.contains("native artifact hash mismatch: prover"), "{error}");
    drop(worker);
    assert_group_gone(pid);
    assert!(helpers().is_empty());
    fs::write(evidence.join("complete.json"), serde_json::to_vec_pretty(&json!({
        "status":"corrupt_bundle_rejected","error":error,"worker_pid":pid,
        "handshake_succeeded":true,"proof_failed_before_helper":true,
    })).unwrap()).unwrap();
}

#[test]
#[ignore = "child process for the opt-in held-memory admission case"]
fn held_memory_child() {
    unsafe extern "C" {
        fn arc4random_buf(buf: *mut libc::c_void, n: libc::size_t);
    }
    let gib: usize = std::env::var("ZKMINER_MACOS_HELD_MEMORY_GIB")
        .unwrap().parse().unwrap();
    assert!((1..=100).contains(&gib));
    const SLAB: usize = 256 * 1024 * 1024;
    let mut slabs = Vec::with_capacity(gib * 4);
    for _ in 0..gib * 4 {
        let mut bytes = vec![0u8; SLAB];
        // Fill every page with incompressible data so the requested amount is
        // actually held by this sibling rather than collapsed by VM compression.
        unsafe { arc4random_buf(bytes.as_mut_ptr().cast(), bytes.len()); }
        slabs.push(bytes);
    }
    let ready = required("ZKMINER_MACOS_HELD_READY_PATH");
    fs::write(&ready, serde_json::to_vec_pretty(&json!({
        "pid":std::process::id(), "held_gib":gib, "slabs":slabs.len(),
        "bytes_written":gib as u64 * 1024u64.pow(3),
    })).unwrap()).unwrap();
    let mut release = String::new();
    std::io::stdin().lock().read_line(&mut release).unwrap();
    assert_eq!(release.trim(), "release");
    std::hint::black_box(&slabs);
}

#[test]
#[ignore = "real native worker workload-limit controls; no proof success is claimed"]
fn native_workload_limit_controls() {
    use zkminer_prover_protocol::ErrorKind;
    let binary = required("ZKMINER_MACOS_WORKER");
    let evidence = required("ZKMINER_MACOS_EVIDENCE_DIR");
    fs::create_dir(&evidence).unwrap();
    let elf = fs::read(required("ZKMINER_MACOS_PROGRAM")).unwrap();
    let mut cases = Vec::new();
    for value in ["0", "67108865", "-1", "invalid", "18446744073709551615"] {
        let overrides = HashMap::from([("ZKMINER_RISC0_MAX_GUEST_CYCLES".into(), value.into())]);
        let error = match WorkerHandle::spawn("risc0", &binary, &overrides) {
            Ok(_) => panic!("invalid session limit admitted"),
            Err(error) => format!("{error:#}"),
        };
        assert!(error.contains("ZKMINER_RISC0_MAX_GUEST_CYCLES"), "{error}");
        cases.push(json!({"limit":value,"outcome":"startup_rejected"}));
    }
    let overrides = HashMap::from([("ZKMINER_RISC0_MAX_GUEST_CYCLES".into(), "1000".into())]);
    let mut worker = WorkerHandle::spawn("risc0", &binary, &overrides).unwrap();
    let input = fs::read(required("ZKMINER_MACOS_INPUT")).unwrap();
    worker.send(&WorkerCommand::Execute { request_id:1, elf:elf.clone(), input_data:input.clone(),
        program_id:None, po2:Some(14) }).unwrap();
    match worker.recv().unwrap() {
        WorkerResponse::Error { kind:ErrorKind::InvalidInput, message, .. } => assert!(message.contains("Session limit exceeded")),
        other => panic!("expected execution cycle-limit rejection, got {other:?}"),
    }
    cases.push(json!({"operation":"execute","outcome":"guest_cycle_limit_rejected"}));
    for (id, po2) in [(2, 13), (3, 22), (4, 20)] {
        worker.send(&WorkerCommand::Prove {request_id:id,elf:elf.clone(),input_data:input.clone(),po2:Some(po2),program_id:None}).unwrap();
        loop {
            match worker.recv().unwrap() {
                WorkerResponse::Progress {request_id,..} => assert_eq!(request_id,id),
                WorkerResponse::Error {request_id,kind:ErrorKind::InvalidInput,message} => {
                    assert_eq!(request_id,id);
                    assert!(message.contains(if po2 == 20 {"Session limit exceeded"} else {"po2 value"}), "{message}");
                    break;
                }
                other => panic!("expected proof input rejection, got {other:?}"),
            }
        }
        cases.push(json!({"operation":"prove","po2":po2,"outcome":"input_rejected"}));
    }
    drop(worker);
    assert!(helpers().is_empty());
    fs::write(evidence.join("complete.json"), serde_json::to_vec_pretty(&json!({
        "status":"workload_limit_controls_passed","verified_proofs":0,"cases":cases,"shutdown":true,
    })).unwrap()).unwrap();
}

fn required(name: &str) -> PathBuf {
    PathBuf::from(
        std::env::var_os(name)
            .unwrap_or_else(|| panic!("set {name}; acceptance cannot skip missing prerequisites")),
    )
}
fn mode() -> String {
    std::env::var("ZKMINER_RISC0_MODE").unwrap_or_else(|_| "cpu".into())
}
fn observed_mode() -> String {
    std::env::var("ZKMINER_MACOS_EXPECT_MODE").unwrap_or_else(|_| "cpu".into())
}
fn worker_kind() -> String {
    std::env::var("ZKMINER_MACOS_WORKER_KIND").unwrap_or_else(|_| "cpu".into())
}
fn proof_timeout() -> Duration {
    let seconds = std::env::var("ZKMINER_MACOS_PROOF_TIMEOUT_SECS")
        .unwrap_or_else(|_| "600".into()).parse().unwrap();
    assert!((30..=3600).contains(&seconds));
    Duration::from_secs(seconds)
}
#[derive(Clone)]
struct Workload {
    name: String,
    input: Vec<u8>,
    expected: Vec<u8>,
    expected_hex: String,
    elf_sha256: String,
    po2: u8,
    min_segments: u64,
}

impl Workload {
    fn from_environment(elf: &[u8]) -> Self {
        const KEYS: [&str; 5] = [
            "ZKMINER_MACOS_WORKLOAD",
            "ZKMINER_MACOS_INPUT",
            "ZKMINER_MACOS_EXPECTED_JOURNAL_HEX",
            "ZKMINER_MACOS_PO2",
            "ZKMINER_MACOS_MIN_SEGMENTS",
        ];
        let supplied = KEYS
            .iter()
            .filter(|key| std::env::var_os(key).is_some())
            .count();
        assert!(
            supplied == 0 || supplied == KEYS.len(),
            "supply all five workload settings together"
        );
        let (name, input, expected, po2, min_segments) = if supplied == 0 {
            (
                "fibonacci".to_owned(),
                20u32.to_le_bytes().to_vec(),
                6765u64.to_le_bytes().to_vec(),
                18,
                1,
            )
        } else {
            let name = std::env::var(KEYS[0]).unwrap();
            assert!(
                ["fibonacci", "sha256-chain", "segment-boundary"].contains(&name.as_str()),
                "unsupported acceptance workload"
            );
            let input_path = required(KEYS[1]);
            assert!(
                (1..=65536).contains(&fs::metadata(&input_path).unwrap().len()),
                "acceptance input must be 1..65536 bytes"
            );
            (
                name,
                fs::read(input_path).unwrap(),
                hex::decode(std::env::var(KEYS[2]).unwrap()).expect("invalid expected journal hex"),
                std::env::var(KEYS[3])
                    .unwrap()
                    .parse()
                    .expect("invalid acceptance po2"),
                std::env::var(KEYS[4])
                    .unwrap()
                    .parse()
                    .expect("invalid minimum segment count"),
            )
        };
        assert!(
            (14..=21).contains(&po2),
            "acceptance po2 must be in 14..=21"
        );
        assert!(
            (1..=256).contains(&min_segments),
            "minimum segment count must be in 1..=256"
        );
        assert!(
            (1..=4096).contains(&expected.len()),
            "expected journal must be 1..4096 bytes"
        );
        Self {
            name,
            input,
            expected_hex: hex::encode(&expected),
            expected,
            elf_sha256: hash(elf),
            po2,
            min_segments,
        }
    }
}

fn elapsed_ms(started: Instant) -> f64 {
    let value = started.elapsed().as_secs_f64() * 1000.0;
    assert!(value.is_finite() && value >= 0.0);
    value
}

fn hash(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Serial proofs in separately configured warm workers; no thread environment
/// is mutated after a worker starts. Testing hooks reuse real WorkerPool admission.
#[cfg(feature = "testing")]
#[test]
#[ignore = "requires sealed native worker, original verifier, and explicit fixtures"]
fn native_thread_comparison() {
    let program = required("ZKMINER_MACOS_PROGRAM");
    let elf = fs::read(&program).unwrap();
    let workload = Workload::from_environment(&elf);
    let evidence = required("ZKMINER_MACOS_EVIDENCE_DIR");
    fs::create_dir(&evidence).unwrap();
    let input = evidence.join("input.bin");
    fs::write(&input, &workload.input).unwrap();
    let settings: Vec<(usize, usize)> = std::env::var("ZKMINER_MACOS_THREAD_CASES")
        .unwrap()
        .split(',')
        .map(|s| {
            let (a, b) = s.split_once(':').unwrap();
            (a.parse().unwrap(), b.parse().unwrap())
        })
        .collect();
    assert!((2..=3).contains(&settings.len()));
    assert!(settings
        .iter()
        .all(|(a, b)| (1..=18).contains(a) && (1..=18).contains(b)));
    let recursion_cases: Option<Vec<String>> = std::env::var("ZKMINER_MACOS_RECURSION_CASES")
        .ok().map(|s| s.split(',').map(str::to_owned).collect());
    if let Some(cases) = &recursion_cases {
        assert_eq!(cases.len(), settings.len());
        assert!(cases.iter().all(|s| s == "cpu" || s == "metal"));
    }
    let samples: usize = std::env::var("ZKMINER_MACOS_THREAD_SAMPLES")
        .unwrap()
        .parse()
        .unwrap();
    assert!((1..=5).contains(&samples));
    let binaries: Option<Vec<PathBuf>> = std::env::var("ZKMINER_MACOS_WORKER_BINARIES")
        .ok().map(|s| serde_json::from_str(&s).unwrap());
    let segment_cases: Option<Vec<String>> = std::env::var("ZKMINER_MACOS_SEGMENT_CASES")
        .ok().map(|s| s.split(',').map(str::to_owned).collect());
    let po2_cases: Option<Vec<u8>> = std::env::var("ZKMINER_MACOS_PO2_CASES")
        .ok().map(|s| s.split(',').map(|value| value.parse().unwrap()).collect());
    if let Some(cases) = &po2_cases {
        assert_eq!(cases.len(), settings.len());
        assert!(cases.iter().all(|po2| (14..=21).contains(po2)));
        assert!(segment_cases.is_some(), "per-arm po2 requires paired segment cases");
    }
    let pipeline_cases: Option<Vec<String>> = std::env::var("ZKMINER_MACOS_PIPELINE_CASES")
        .ok().map(|s| s.split(',').map(str::to_owned).collect());
    if let Some(cases) = &pipeline_cases {
        assert_eq!(cases.len(), settings.len());
        assert!(cases.iter().all(|value| value == "0" || value == "1"));
        assert!(segment_cases.is_some(), "per-arm pipeline requires paired segment cases");
    }
    if let Some(cases) = &segment_cases {
        assert!(cases == &["cpu", "metal"] || cases == &["metal", "metal"]);
        assert_eq!(cases.len(), settings.len());
        assert_eq!(binaries.as_ref().unwrap().len(), settings.len());
    }
    let mut pools = Vec::new();
    for (index, &(rayon, go)) in settings.iter().enumerate() {
        let mut pool = WorkerPool::new(HashMap::new(), vec![], Some(proof_timeout()));
        let mut overrides = HashMap::from([
            ("ZKMINER_RISC0_CPU_THREADS".to_owned(), rayon.to_string()),
            ("RISC0_GROTH16_NATIVE_THREADS".to_owned(), go.to_string()),
        ]);
        if let Some(cases) = &recursion_cases {
            overrides.insert("RISC0_RECURSION_HAL".into(), cases[index].clone());
        }
        if let Some(cases) = &segment_cases {
            overrides.insert("RISC0_SEGMENT_HAL".into(), cases[index].clone());
        }
        if let Some(cases) = &pipeline_cases {
            overrides.insert("RISC0_SEGMENT_PIPELINE".into(), cases[index].clone());
        }
        if index == 0 && std::env::var("ZKMINER_MACOS_LEGACY_BASELINE_PROTOCOL")
            .ok().as_deref() == Some("5") {
            assert!(segment_cases.is_some(), "legacy worker is only for sealed pairs");
            overrides.insert("ZKMINER_TEST_LEGACY_PROTOCOL".into(), "5".into());
        }
        let binary = binaries.as_ref().map(|v| v[index].clone())
            .unwrap_or_else(|| required("ZKMINER_MACOS_WORKER"));
        eprintln!("paired worker insert index={index} binary={}", binary.display());
        pool.insert_test_worker(KEY, "risc0", binary.clone(), overrides).unwrap();
        let pid = pool.worker_pid(KEY).unwrap();
        let status = Command::new("ps").args(["-o", "pid=,ni=,pri=,comm=", "-p", &pid.to_string()])
            .output().expect("read actual worker process priority");
        assert!(status.status.success(), "worker process priority unavailable");
        ledger(&evidence, &json!({"event":"worker_started","case":index,
            "worker_pid":pid,"binary":binary,
            "rayon_threads":rayon,"gomaxprocs":go,
            "process_priority":String::from_utf8_lossy(&status.stdout).trim(),
            "process_priority_columns":"pid nice priority command; ps cannot report thread QoS on this macOS"}));
        pools.push(pool);
    }
    let mut rows = Vec::new();
    let first_case: usize = std::env::var("ZKMINER_MACOS_PAIRED_START_CASE")
        .unwrap_or_else(|_| "0".into())
        .parse()
        .unwrap();
    assert!(first_case < settings.len());
    for round in 0..=samples {
        let mut order: Vec<_> = (0..settings.len()).collect();
        if (round + first_case) % 2 == 1 {
            order.reverse();
        }
        for index in order {
            let mut case_workload = workload.clone();
            if let Some(cases) = &po2_cases {
                case_workload.po2 = cases[index];
            }
            let before = sidecar_paths();
            let mut admission_wait_ms = 0.0;
            let (outcome, mut resources) = loop {
                let attempt = Instant::now();
                let worker_pid = pools[index].worker_pid(KEY);
                let (result, resources) = measured_prove(&pools[index], &elf, &case_workload);
                match result {
                    Ok(outcome) => break (outcome, resources),
                    Err(error) if error.downcast_ref::<zkminer_prover_protocol::types::HostMemoryShortage>().is_some() => {
                        // No request was dispatched. Retain both warm workers,
                        // keep the production policy intact, and record the wait
                        // separately from successful prove-call timing.
                        assert_eq!(sidecar_paths(), before, "admission refusal dispatched work");
                        assert_eq!(pools[index].worker_pid(KEY), worker_pid,
                            "admission refusal changed the warm worker identity");
                        if admission_wait_ms == 0.0 {
                            ledger(&evidence, &json!({"event":"admission_wait_started",
                                "round":round,"case":index,"worker_pid":worker_pid,
                                "error":format!("{error:#}")}));
                        }
                        assert!(admission_wait_ms < 600_000.0,
                            "host admission remained unavailable for ten minutes: {error:#}");
                        std::thread::sleep(Duration::from_secs(5));
                        admission_wait_ms += attempt.elapsed().as_secs_f64() * 1000.0;
                    }
                    Err(error) => panic!("proof failed without retry: {error:#}"),
                }
            };
            if admission_wait_ms > 0.0 {
                ledger(&evidence, &json!({"event":"admission_wait_finished",
                    "round":round,"case":index,"admission_wait_ms":admission_wait_ms}));
            }
            let directory = evidence.join(format!("round-{round}-case-{index}"));
            let (_, record) = require_sidecar(&before);
            assert_eq!(record["rayon_threads"], settings[index].0);
            assert_eq!(record["gomaxprocs"], settings[index].1);
            assert_eq!(record["po2"], case_workload.po2);
            assert_eq!(record["helper_arch"], "darwin/arm64");
            if let Some(cases) = &segment_cases {
                assert_eq!(record["segment_hal"].as_str().unwrap_or("cpu"), cases[index]);
                assert_eq!(record["observed_mode"], cases[index]);
            }
            if let Some(cases) = &recursion_cases {
                assert_eq!(record["recursion_hal"], cases[index]);
            }
            let external = verify(
                &required("ZKMINER_MACOS_VERIFIER"),
                &program,
                &input,
                &directory,
                outcome,
                &record,
                &case_workload,
            );
            finish_resources(&directory, &record, &mut resources);
            let timing = save_proof_timing(&directory, &record, &resources, external);
            let thermal = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../target/macos/benchmark-tools/thermal");
            let thermal = Command::new(thermal)
                .output()
                .ok()
                .filter(|o| o.status.success())
                .map(|o| String::from_utf8_lossy(&o.stdout).into_owned());
            let row = json!({"round":round,"warmup":round==0,"case":index,"rayon_threads":settings[index].0,
                "gomaxprocs":settings[index].1,"admission_wait_ms":admission_wait_ms,"worker":record,"resources":resources,"timings":timing,"thermal":thermal});
            ledger(&evidence, &row);
            rows.push(row);
        }
    }
    for mut pool in pools {
        pool.shutdown_all();
    }
    assert!(helpers().is_empty());
    fs::write(
        evidence.join("complete.json"),
        serde_json::to_vec_pretty(&json!({"status":"complete_independently_verified",
        "samples_per_case":samples,"settings":settings,"recursion_cases":recursion_cases,"segment_cases":segment_cases,"po2_cases":po2_cases,"pipeline_cases":pipeline_cases,"worker_binaries":binaries,"rows":rows}))
        .unwrap(),
    )
    .unwrap();
}
fn bounded_output(command: &mut Command) -> String {
    let (status, stdout) = zkminer_prover_protocol::proc::output_with_timeout_capturing_stdout(
        command,
        Duration::from_secs(10),
        1024 * 1024,
    );
    assert!(
        matches!(
            status,
            zkminer_prover_protocol::proc::Outcome::Ran { success: true, .. }
        ),
        "observation command failed: {}",
        status.describe()
    );
    stdout
}
fn native_helpers() -> Vec<String> {
    let executable = required("ZKMINER_RISC0_NATIVE_DIR").join("prover");
    let executable = executable.to_str().unwrap();
    bounded_output(Command::new("ps").args(["-axo", "args="]))
        .lines()
        .filter(|line| line.trim_start().starts_with(executable))
        .map(str::to_owned)
        .collect()
}
fn helpers() -> Vec<String> {
    if worker_kind() == "native" {
        let prefix = format!("zkminer-macos-{}-", std::process::id());
        return native_helpers()
            .into_iter()
            .filter(|line| line.contains(&prefix))
            .collect();
    }
    bounded_output(Command::new("docker").args([
        "--context",
        &std::env::var("ZKMINER_RISC0_DOCKER_CONTEXT").unwrap(),
        "ps",
        "-a",
        "--filter",
        "name=zkminer-macos-",
        "--format",
        "{{.Names}}",
    ]))
    .lines()
    .map(str::to_owned)
    .collect()
}
fn helper_running(name: &str) -> bool {
    if worker_kind() == "native" {
        return native_helpers().iter().any(|line| line.contains(name));
    }
    assert!(
        name.starts_with(&format!("zkminer-macos-{}-", std::process::id())),
        "not this test's helper"
    );
    let names = bounded_output(Command::new("docker").args([
        "--context",
        &std::env::var("ZKMINER_RISC0_DOCKER_CONTEXT").unwrap(),
        "ps",
        "--filter",
        "status=running",
        "--format",
        "{{.Names}}",
    ]));
    names.lines().any(|value| value == name)
}
fn assert_group_gone(pid: u32) {
    let processes = bounded_output(Command::new("ps").args(["-axo", "pid=,pgid=,stat="]));
    for line in processes.lines() {
        let fields: Vec<_> = line.split_whitespace().collect();
        assert_eq!(fields.len(), 3, "invalid process observation");
        assert!(
            !(fields[1].parse::<u32>().unwrap() == pid && !fields[2].starts_with('Z')),
            "owned worker group still has live member: {line}"
        );
    }
}
fn sidecar_paths() -> BTreeSet<PathBuf> {
    fs::read_dir(required("ZKMINER_RISC0_EVIDENCE_DIR"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|s| s == "json"))
        .collect()
}
fn new_sidecar(before: &BTreeSet<PathBuf>) -> Option<(PathBuf, Value)> {
    let paths = sidecar_paths();
    let new: Vec<_> = paths.difference(before).collect();
    assert!(
        new.len() <= 1,
        "more than one request active in the single worker slot"
    );
    new.first().map(|path| {
        (
            (*path).clone(),
            serde_json::from_slice(&fs::read(path).unwrap()).unwrap(),
        )
    })
}
fn require_sidecar(before: &BTreeSet<PathBuf>) -> (PathBuf, Value) {
    new_sidecar(before).expect("worker returned without persistent request evidence")
}
fn positive(value: &Value, field: &str) -> u64 {
    value[field]
        .as_u64()
        .filter(|n| *n > 0)
        .unwrap_or_else(|| panic!("missing positive {field}: {value}"))
}
fn validate_stage(record: &Value, workload: &Workload) {
    let observed = if std::env::var_os("ZKMINER_MACOS_SEGMENT_CASES").is_some() {
        // The paired test independently checks this against each configured
        // worker's case before calling the common cryptographic verifier.
        if record["segment_hal"] == "metal" { "metal".to_owned() } else { "cpu".to_owned() }
    } else { observed_mode() };
    assert_eq!(record["schema_version"], 1);
    assert_eq!(record["operation"], "prove");
    assert_eq!(record["requested_mode"], mode());
    assert_eq!(record["observed_mode"], observed.clone());
    assert_eq!(record["elf_sha256"], workload.elf_sha256);
    assert_eq!(record["input_sha256"], hash(&workload.input));
    if record["phase"] == "complete" {
        assert_eq!(record["journal_hex"], workload.expected_hex);
        assert_eq!(record["journal_sha256"], hash(&workload.expected));
    }
    assert_eq!(record["po2"], workload.po2);
    let count = positive(&record["stats"], "segments");
    let recursion = if let Ok(cases) = std::env::var("ZKMINER_MACOS_RECURSION_CASES") {
        let actual = record["recursion_hal"].as_str().unwrap();
        assert!(cases.split(',').any(|s| s == actual));
        Ok(actual.to_owned())
    } else { std::env::var("RISC0_RECURSION_HAL") };
    if let Ok(recursion) = recursion {
        assert_eq!(record["recursion_hal"], recursion);
        if recursion == "metal" {
            let stage = &record["observed_stages"]["recursion_metal"];
            assert!(positive(stage, "completed_constraint_checks") >= 2 * count - 1);
            assert!(positive(stage, "evaluation_points") > 0);
            assert_eq!(stage["kernel_source_sha256"].as_str().unwrap().len(), 64);
            if std::env::var("RISC0_RECURSION_METAL_CHECK_CPU").as_deref() == Ok("1") {
                assert_eq!(stage["cpu_differential_checks"], stage["completed_constraint_checks"]);
            }
            let cpu_identity = record["observed_stages"]["identity"] == "cpu";
            if cpu_identity {
                // WP8 pairs a sealed pre-WP8 worker with the candidate. The
                // paired collector binds the CPU identity to arm 0 only.
                assert_eq!(std::env::var("ZKMINER_MACOS_PAIRED_ALLOW_CPU_IDENTITY").as_deref(), Ok("1"));
                assert!(record["recursion_cpu_stages"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|stage| stage == "identity_p254"));
            } else {
                assert_eq!(record["observed_stages"]["identity"], "metal");
                assert!(!record["recursion_cpu_stages"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|stage| stage == "identity_p254"));
            }
            if record["phase"] == "complete" && !cpu_identity {
                let identity = &record["observed_stages"]["identity_metal"];
                assert!(positive(identity, "completed_constraint_checks") > 0);
                assert!(positive(identity, "evaluation_points") > 0);
                if record["segment_hal"] == "metal" {
                    for kernel in ["recursion/poseidon254_rows", "recursion/poseidon254_fold"] {
                        assert!(positive(&identity["gpu_kernels"][kernel], "commands") > 0);
                    }
                }
            }
        } else {
            assert_eq!(record["observed_stages"]["identity"], "cpu");
        }
    }
    let minimum: u64 = std::env::var("ZKMINER_MACOS_MIN_GUEST_CYCLES")
        .unwrap_or_else(|_| "1".into()).parse().unwrap();
    assert!(positive(&record["stats"], "user_cycles") >= minimum);
    assert_eq!(record["stats"]["total_cycles"].as_u64().unwrap(),
        ["user_cycles", "paging_cycles", "reserved_cycles"].iter()
            .map(|k| record["stats"][k].as_u64().unwrap()).sum::<u64>());
    assert!(
        count >= workload.min_segments,
        "workload did not cover the required segment count"
    );
    let stage = &record["observed_stages"]["metal_stage"];
    if record["segment_hal"] == "metal" {
        assert_eq!(observed.clone(), "metal");
        assert_eq!(record["observed_stages"]["segment"], "metal");
        assert_eq!(record["observed_stages"]["other_segment_operations"], "metal_shared_buffers");
        let rv = &record["observed_stages"]["rv32im_metal"];
        assert_eq!(positive(rv, "completed_constraint_checks"), count);
        assert_eq!(positive(rv, "cpu_witness_calls"), count);
        assert_eq!(positive(rv, "cpu_accumulation_calls"), count);
        assert_eq!(rv["cpu_differential_checks"], if std::env::var("RISC0_RV32IM_METAL_CHECK_CPU").as_deref() == Ok("1") { count } else { 0 });
        assert!(positive(rv, "evaluation_points") >= count * (1 << 16));
        assert!(positive(rv, "completed_dispatches") > count);
        assert!(rv["threads_per_threadgroup"] == 32 || rv["threads_per_threadgroup"] == 256);
        assert_eq!(rv["normalization"], "period_four_table");
        for key in ["kernel_source_sha256", "hal_kernel_source_sha256"] { assert_eq!(rv[key].as_str().unwrap().len(), 64); }
        assert!(stage.is_null(), "resident segment mode unexpectedly used the legacy fold-only path");
        return;
    }
    if observed.clone() == "cpu" {
        assert!(stage.is_null(), "CPU segment mode unexpectedly executed a Metal fold");
        return;
    }
    panic!("fold-only Metal proof validation is retired");
}
fn ledger(evidence: &Path, value: &Value) {
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(evidence.join("requests.jsonl"))
        .unwrap();
    writeln!(file, "{value}").unwrap();
}
// Observation only: this never allocates a synthetic workload or changes the worker.
fn rss_observation(pid: u32, expected_start: Option<u64>, started: Instant, phase: &str) -> Value {
    let host_available = zkminer_prover::memory::mem_available_bytes();
    let host_total = zkminer_prover::memory::mem_total_bytes();
    let mut sample = json!({"worker_pid":pid,"elapsed_ms":started.elapsed().as_secs_f64()*1000.0,"phase":phase,
        "host_available_bytes":host_available,"host_total_bytes":host_total});
    if host_available.is_none() || host_total.is_none() {
        sample["host_memory_unavailable_reason"] =
            json!("production host memory observation unavailable; unknown values are null");
    }
    sample["native_memory"] = zkminer_prover::memory::native_memory_observation(pid);
    let identity = zkminer_prover::memory::pid_starttime(pid);
    if pid == 0 || identity.is_none() {
        sample["unavailable_reason"] = json!("no live worker start identity");
        return sample;
    }
    let identity = identity.unwrap();
    sample["worker_start_time_us"] = json!(identity);
    if expected_start.is_some_and(|value| value != identity)
        || !zkminer_prover::memory::pid_is_our_worker(pid, Some(identity))
    {
        sample["unavailable_reason"] =
            json!("worker identity or parent/group ownership changed before RSS observation");
        return sample;
    }
    let (status, stdout) = zkminer_prover_protocol::proc::output_with_timeout_capturing_stdout(
        Command::new("ps").args(["-o", "rss=", "-p", &pid.to_string()]),
        Duration::from_secs(2),
        4096,
    );
    if !matches!(
        status,
        zkminer_prover_protocol::proc::Outcome::Ran { success: true, .. }
    ) {
        sample["unavailable_reason"] =
            json!(format!("ps observation failed: {}", status.describe()));
        return sample;
    }
    if zkminer_prover::memory::pid_starttime(pid) != Some(identity)
        || !zkminer_prover::memory::pid_is_our_worker(pid, Some(identity))
    {
        sample["unavailable_reason"] =
            json!("worker identity or parent/group ownership changed during RSS observation");
        return sample;
    }
    match stdout
        .trim()
        .parse::<u64>()
        .ok()
        .and_then(|value| value.checked_mul(1024))
        .filter(|value| *value > 0)
    {
        Some(bytes) => sample["rss_bytes"] = json!(bytes),
        None => {
            sample["unavailable_reason"] = json!("ps did not return a positive bounded RSS value")
        }
    }
    sample
}

fn measured_prove(
    pool: &WorkerPool,
    elf: &[u8],
    workload: &Workload,
) -> (anyhow::Result<zkminer_prover::engine::ProofOutput>, Value) {
    let started = Instant::now();
    let baseline = rss_observation(
        pool.worker_pid(KEY).unwrap_or(0),
        None,
        started,
        "before_prove_call",
    );
    let done = Arc::new(AtomicBool::new(false));
    let (result, mut observations, prove_call_ms, request_epoch_ns) = std::thread::scope(|scope| {
        let stop = done.clone();
        let observer = scope.spawn(move || {
            let mut samples = Vec::new();
            while !stop.load(Ordering::Acquire) {
                samples.push(rss_observation(
                    pool.worker_pid(KEY).unwrap_or(0),
                    None,
                    started,
                    "periodic_during_prove_call",
                ));
                // One-second cadence, interruptible so joining does not add a full second.
                for _ in 0..10 {
                    if stop.load(Ordering::Acquire) {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(100));
                }
            }
            samples
        });
        let prove_started = Instant::now();
        let request_epoch_ns = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64;
        let result = pool.prove(
            "risc0",
            elf,
            &workload.input,
            Some(workload.po2),
            Some(proof_timeout()),
            None,
        );
        let prove_call_ms = elapsed_ms(prove_started);
        done.store(true, Ordering::Release);
        (result, observer.join().unwrap(), prove_call_ms, request_epoch_ns)
    });
    observations.insert(0, baseline.clone());
    observations.push(rss_observation(
        pool.worker_pid(KEY).unwrap_or(0),
        None,
        started,
        "after_prove_call",
    ));
    (
        result,
        json!({"schema_version":1,
        "method":"ps -o rss=, converted from KiB; PID start identity and parent/process-group ownership checked before and after each observation",
        "scope":"native worker process RSS only; excludes helper VM and is not a Metal driver allocation peak",
        "observation_window":"immediately before WorkerPool::prove through its return; post-verification idle observation is separate",
        "host_memory_method":"production Darwin available-memory estimate (free pages plus conservative reclaim credit); includes all host pressure and is not added to worker RSS or treated as an allocation guarantee",
        "sampling_interval_ms":1000,"request_elapsed_ms":started.elapsed().as_secs_f64()*1000.0,
        "prove_call_ms":prove_call_ms,"proof_request_epoch_ns":request_epoch_ns,
        "prove_call_scope":"immediately around WorkerPool::prove; includes admission, any policy-driven worker replacement, IPC and completed proof response; excludes RSS baseline and sampler join",
        "baseline_before_prove_call":baseline,"observations":observations}),
    )
}

fn finish_resources(dir: &Path, record: &Value, resources: &mut Value) {
    let pid = record["worker_pid"].as_u64().unwrap();
    let observations = resources["observations"].as_array().unwrap();
    let identity = observations
        .iter()
        .rev()
        .find(|sample| sample["worker_pid"] == pid && sample["rss_bytes"].as_u64().is_some())
        .and_then(|sample| sample["worker_start_time_us"].as_u64())
        .expect("no identity-checked RSS observation for the worker that produced this proof");
    let samples: Vec<_> = observations
        .iter()
        .filter(|sample| {
            sample["worker_pid"] == pid
                && sample["worker_start_time_us"] == identity
                && sample["rss_bytes"].as_u64().is_some()
        })
        .cloned()
        .collect();
    let periodic = samples
        .iter()
        .filter(|sample| sample["phase"] == "periodic_during_prove_call")
        .count();
    assert!(
        periodic > 0,
        "no periodic RSS observation during the real proving request"
    );
    let peak = samples
        .iter()
        .map(|sample| sample["rss_bytes"].as_u64().unwrap())
        .max()
        .unwrap();
    assert!(
        peak <= 32 * 1024u64.pow(3),
        "sampled native request RSS exceeded the worker bound"
    );
    let identities: BTreeSet<_> = observations
        .iter()
        .filter(|sample| sample["rss_bytes"].as_u64().is_some())
        .filter_map(|sample| {
            Some((
                sample["worker_pid"].as_u64()?,
                sample["worker_start_time_us"].as_u64()?,
            ))
        })
        .collect();
    resources["observed_worker_identities"] = json!(identities.into_iter().map(|(worker_pid, worker_start_time_us)|
        json!({"worker_pid":worker_pid,"worker_start_time_us":worker_start_time_us})).collect::<Vec<_>>());
    resources["worker_pid"] = json!(pid);
    resources["worker_start_time_us"] = json!(identity);
    resources["sample_count"] = json!(samples.len());
    resources["periodic_sample_count"] = json!(periodic);
    resources["peak_rss_bytes"] = json!(peak);
    resources["first_sample"] = samples.first().unwrap().clone();
    resources["last_sample"] = samples.last().unwrap().clone();
    resources["baseline_matches_request_worker"] = json!(
        resources["baseline_before_prove_call"]["worker_pid"] == pid
            && resources["baseline_before_prove_call"]["worker_start_time_us"] == identity
            && resources["baseline_before_prove_call"]["rss_bytes"]
                .as_u64()
                .is_some()
    );
    resources["idle_settle_ms"] = json!(1000);
    let idle_started = Instant::now();
    std::thread::sleep(Duration::from_secs(1));
    let mut idle = rss_observation(
        pid as u32,
        Some(identity),
        idle_started,
        "after_independent_verification_and_settle",
    );
    idle["elapsed_ms_reference"] =
        json!("time since the post-verification settling interval began");
    resources["idle_after_verification_and_settle"] = idle;
    fs::write(
        dir.join("resource.json"),
        serde_json::to_vec_pretty(resources).unwrap(),
    )
    .unwrap();
}

fn admission_pressure(pool: &WorkerPool, elf: &[u8], workload: &Workload, evidence: &Path) {
    const STEP: u64 = 1024 * 1024 * 1024;
    let total =
        zkminer_prover::memory::mem_total_bytes().expect("cannot observe real host total memory");
    let available = zkminer_prover::memory::mem_available_bytes()
        .expect("cannot observe real host available memory");
    let reserve = zkminer_prover::memory::host_reserve_bytes();
    let needed = pool.expected_host_peak_at_po2("risc0", Some(workload.po2));
    assert!(
        available >= STEP + reserve,
        "insufficient live headroom for the logical reservation test prerequisite"
    );
    assert_eq!(
        pool.reserved_host_memory(),
        0,
        "reservation test requires an idle ledger"
    );
    let before = sidecar_paths();
    assert!(helpers().is_empty());
    let pid_before = pool.worker_pid(KEY).unwrap_or(0);
    ledger(
        evidence,
        &json!({"case":"admission-pressure","status":"started", "kind":"in_flight_reservation_admission",
        "physical_memory_pressure":false,"host_total_bytes":total,"host_available_bytes":available}),
    );
    // These are the real production ledger guards. They reserve accounting only;
    // no corresponding host/GPU pages are allocated or touched by this test.
    let mut guards = Vec::new();
    let limit = total / STEP + 1;
    assert!(limit <= 4096, "logical reservation test bound exceeded");
    while pool
        .reserved_host_memory()
        .saturating_add(needed)
        .saturating_add(reserve)
        <= total
    {
        assert!(
            (guards.len() as u64) < limit,
            "logical reservation loop exceeded its host-derived bound"
        );
        guards.push(pool.reserve_host_memory(STEP, KEY)
            .expect("live host headroom changed before the intended committed-reservation condition; prerequisite failure"));
    }
    let held = pool.reserved_host_memory();
    let refusal = pool
        .prove(
            "risc0",
            elf,
            &workload.input,
            Some(workload.po2),
            Some(Duration::from_secs(30)),
            None,
        )
        .expect_err("proof unexpectedly ran while real in-flight reservations exhausted admission");
    let shortage = refusal
        .downcast_ref::<zkminer_prover_protocol::types::HostMemoryShortage>()
        .expect("admission case did not return typed HostMemoryShortage");
    assert!(
        !shortage.attempted,
        "admission case unexpectedly attempted a proof"
    );
    assert_eq!(shortage.slot_key, KEY);
    assert_eq!(shortage.needed, needed);
    assert_eq!(shortage.reserved, held);
    assert_eq!(
        sidecar_paths(),
        before,
        "admission refusal started a worker request"
    );
    let helper_count_after = helpers().len();
    assert_eq!(
        helper_count_after, 0,
        "admission refusal started or leaked a helper"
    );
    let mut report = json!({"kind":"in_flight_reservation_admission","physical_memory_pressure":false,"attempted":false,
        "reserved_before_bytes":0,"reserved_held_bytes":held,"needed_bytes":needed,"host_total_bytes":total,
        "host_available_bytes":available,"host_available_at_refusal_bytes":shortage.available,"host_reserve_bytes":reserve,
        "reservation_count":guards.len(),"step_bytes":STEP,"sidecar_count_before":before.len(),"sidecar_count_after":sidecar_paths().len(),
        "helper_count_after":helper_count_after,"worker_pid_before":pid_before,"worker_pid_after":pool.worker_pid(KEY).unwrap_or(0),
        "error":format!("{refusal:#}")});
    drop(guards);
    assert_eq!(
        pool.reserved_host_memory(),
        0,
        "logical reservations were not released"
    );
    report["reserved_after_bytes"] = json!(pool.reserved_host_memory());
    fs::write(
        evidence.join("pressure.json"),
        serde_json::to_vec_pretty(&report).unwrap(),
    )
    .unwrap();
    ledger(
        evidence,
        &json!({"case":"admission-pressure","status":"expected_admission_refusal","pressure":report}),
    );
    // The normal proof loop immediately following this case must produce and
    // independently verify a genuine full proof after releasing the guards.
}

fn kernel_pressure_level() -> Option<u32> {
    let output = Command::new("/usr/sbin/sysctl")
        .args(["-n", "kern.memorystatus_vm_pressure_level"])
        .output()
        .ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().parse().ok())
        .flatten()
}

struct HeldMemory {
    child: Child,
    ready: Value,
    ready_ms: f64,
}

impl Drop for HeldMemory {
    fn drop(&mut self) {
        if let Some(mut input) = self.child.stdin.take() {
            let _ = input.write_all(b"release\n");
        }
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if self.child.try_wait().ok().flatten().is_some() {
                return;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn start_held_memory(evidence: &Path, gib: usize) -> HeldMemory {
    let ready = evidence.join("held-memory-ready.json");
    let log = fs::File::create(evidence.join("held-memory-child.log")).unwrap();
    let child = Command::new(std::env::current_exe().unwrap())
        .args(["held_memory_child", "--exact", "--ignored", "--nocapture"])
        .env("ZKMINER_MACOS_HELD_READY_PATH", &ready)
        .env("ZKMINER_MACOS_HELD_MEMORY_GIB", gib.to_string())
        .stdin(Stdio::piped())
        .stdout(Stdio::from(log.try_clone().unwrap()))
        .stderr(Stdio::from(log))
        .spawn()
        .expect("cannot start held-memory sibling");
    let mut held = HeldMemory { child, ready: Value::Null, ready_ms: 0.0 };
    let started = Instant::now();
    while !ready.exists() {
        assert!(started.elapsed() < Duration::from_secs(180),
            "held-memory sibling did not finish writing every page within 180 seconds");
        assert!(held.child.try_wait().unwrap().is_none(),
            "held-memory sibling exited before signaling readiness");
        std::thread::sleep(Duration::from_millis(200));
    }
    held.ready_ms = started.elapsed().as_secs_f64() * 1000.0;
    held.ready = serde_json::from_slice(&fs::read(ready).unwrap()).unwrap();
    assert_eq!(held.ready["held_gib"], gib);
    assert_eq!(held.ready["pid"], held.child.id());
    held
}

fn kernel_pressure(pool: &WorkerPool, elf: &[u8], workload: &Workload, evidence: &Path) {
    struct PressureChild(Child);
    impl Drop for PressureChild {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    assert_eq!(kernel_pressure_level(), Some(1));
    let before = sidecar_paths();
    assert!(helpers().is_empty());
    let log = fs::File::create(evidence.join("kernel-pressure.log")).unwrap();
    let child = Command::new("/usr/bin/memory_pressure")
        .args(["-l", "warn", "-s", "30"])
        .stdout(Stdio::from(log.try_clone().unwrap()))
        .stderr(Stdio::from(log))
        .spawn()
        .expect("cannot start real memory-pressure allocator");
    let mut allocator = PressureChild(child);
    let started = Instant::now();
    let warned = loop {
        let pressure = kernel_pressure_level();
        if matches!(pressure, Some(2 | 4)) {
            break pressure.unwrap();
        }
        assert!(
            started.elapsed() < Duration::from_secs(60),
            "real allocator did not raise kernel pressure within 60 seconds"
        );
        assert!(
            allocator.0.try_wait().unwrap().is_none(),
            "real allocator exited before kernel pressure changed"
        );
        std::thread::sleep(Duration::from_millis(200));
    };
    let warning_ms = started.elapsed().as_secs_f64() * 1000.0;
    let needed = pool.expected_host_peak_at_po2("risc0", Some(workload.po2));
    let refused_at = Instant::now();
    let refusal = pool
        .prove(
            "risc0",
            elf,
            &workload.input,
            Some(workload.po2),
            Some(Duration::from_secs(30)),
            None,
        )
        .expect_err("proof dispatched under warning or critical kernel pressure");
    let refusal_ms = refused_at.elapsed().as_secs_f64() * 1000.0;
    let shortage = refusal
        .downcast_ref::<zkminer_prover_protocol::types::HostMemoryShortage>()
        .expect("kernel pressure did not return typed HostMemoryShortage");
    assert!(!shortage.attempted, "pressure refusal attempted a proof");
    assert_eq!(shortage.slot_key, KEY);
    assert_eq!(shortage.needed, needed);
    assert!(shortage.available > 0, "typed shortage lost the raw VM estimate");
    let label = if warned == 2 { "warning" } else { "critical" };
    assert!(format!("{refusal:#}").contains(&format!(
        "kernel memory pressure is {label} (level {warned}); refused before dispatch"
    )));
    assert_eq!(sidecar_paths(), before, "pressure refusal started a worker request");
    assert!(helpers().is_empty(), "pressure refusal started a helper");
    drop(allocator);
    let release_started = Instant::now();
    while kernel_pressure_level() != Some(1) {
        assert!(
            release_started.elapsed() < Duration::from_secs(30),
            "kernel pressure did not recover after allocator exit"
        );
        std::thread::sleep(Duration::from_millis(200));
    }
    let report = json!({
        "kind":"real_allocation_kernel_pressure", "allocator_command":"memory_pressure -l warn -s 30",
        "warning_level":warned, "time_to_warning_ms":warning_ms,
        "refusal_ms":refusal_ms, "attempted":shortage.attempted,
        "host_reserve_bytes":zkminer_prover::memory::host_reserve_bytes(),
        "sidecar_count_before":before.len(), "sidecar_count_after":sidecar_paths().len(),
        "helper_count_after":helpers().len(), "recovered_level":1,
        "recovery_ms":release_started.elapsed().as_secs_f64()*1000.0,
        "error":format!("{refusal:#}"),
    });
    fs::write(
        evidence.join("kernel-pressure.json"),
        serde_json::to_vec_pretty(&report).unwrap(),
    )
    .unwrap();
    ledger(evidence, &json!({"case":"kernel-pressure","status":"refused_then_recovered","pressure":report}));
    // The normal proof loop then proves and independently verifies recovery.
}

fn verify(
    verifier: &Path,
    program: &Path,
    input: &Path,
    dir: &Path,
    proof: zkminer_prover::engine::ProofOutput,
    record: &Value,
    workload: &Workload,
) -> f64 {
    fs::create_dir(dir).unwrap();
    assert_eq!(proof.journal, workload.expected);
    assert_eq!(proof.seal.len(), 256);
    assert!(proof.cycles > 0);
    assert_eq!(Some(proof.cycles), record["stats"]["total_cycles"].as_u64());
    assert_eq!(record["phase"], "complete");
    assert_eq!(record["proof_kind"], "groth16");
    assert_eq!(record["seal_sha256"], hash(&proof.seal));
    validate_stage(record, workload);
    fs::write(
        dir.join("worker.json"),
        serde_json::to_vec_pretty(record).unwrap(),
    )
    .unwrap();
    fs::write(dir.join("journal.bin"), &proof.journal).unwrap();
    fs::write(dir.join("seal.bin"), &proof.seal).unwrap();
    let verifier_started = Instant::now();
    let output = Command::new(verifier)
        .arg("verify-seal")
        .arg(program)
        .arg(input)
        .arg(&workload.expected_hex)
        .arg(dir)
        .arg(workload.po2.to_string())
        .output()
        .unwrap();
    let external_verifier_ms = elapsed_ms(verifier_started);
    fs::write(dir.join("verifier.stdout"), &output.stdout).unwrap();
    fs::write(dir.join("verifier.stderr"), &output.stderr).unwrap();
    assert!(
        output.status.success(),
        "independent verification failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let verification: Value =
        serde_json::from_slice(&fs::read(dir.join("verification.json")).unwrap()).unwrap();
    assert_eq!(verification["image_id"], record["image_id"]);
    assert_eq!(verification["verification"], "passed");
    assert_eq!(verification["journal_hex"], workload.expected_hex);
    assert_eq!(verification["elf_sha256"], workload.elf_sha256);
    assert_eq!(
        verification["negative_tests"],
        json!(["wrong_image", "modified_journal", "corrupt_seal"])
    );
    eprintln!(
        "independently verified {} ({} cycles, {:.3}s, mode={})",
        dir.display(),
        proof.cycles,
        proof.duration.as_secs_f64(),
        record["observed_mode"].as_str().unwrap()
    );
    external_verifier_ms
}

fn save_proof_timing(
    dir: &Path,
    record: &Value,
    resources: &Value,
    external_verifier_ms: f64,
) -> Value {
    let prove_call_ms = resources["prove_call_ms"].as_f64().unwrap();
    assert!(prove_call_ms.is_finite() && prove_call_ms >= 0.0);
    assert!(external_verifier_ms.is_finite() && external_verifier_ms >= 0.0);
    let timing = json!({
        "schema_version":1,"method":"monotonic std::time::Instant elapsed wall time",
        "prove_call_ms":prove_call_ms,"external_verifier_ms":external_verifier_ms,
        "prove_call_scope":resources["prove_call_scope"],
        "external_verifier_scope":"external unchanged verifier Command::output, including process startup, positive verification and all three negative checks; excludes evidence file writes",
        "worker_pid":record["worker_pid"],"worker_start_time_us":resources["worker_start_time_us"],
        "request_id":record["request_id"],
        "proof_request_epoch_ns":resources["proof_request_epoch_ns"],
        "first_completed_gpu_dispatch_epoch_ns":record["observed_stages"]["rv32im_metal"]["first_completed_gpu_dispatch_epoch_ns"],
        "request_to_first_completed_gpu_dispatch_ms":match (
            resources["proof_request_epoch_ns"].as_u64(),
            record["observed_stages"]["rv32im_metal"]["first_completed_gpu_dispatch_epoch_ns"].as_u64(),
        ) {
            (Some(request), Some(dispatch)) if dispatch >= request => json!((dispatch-request) as f64 / 1_000_000.0),
            _ => Value::Null,
        },
        "worker_pid_before_prove":resources["baseline_before_prove_call"]["worker_pid"],
        "worker_start_time_us_before_prove":resources["baseline_before_prove_call"]["worker_start_time_us"],
        "same_worker_as_before_prove":resources["baseline_matches_request_worker"],
    });
    fs::write(
        dir.join("timing.json"),
        serde_json::to_vec_pretty(&timing).unwrap(),
    )
    .unwrap();
    timing
}

#[test]
#[ignore = "requires the real native worker and dedicated local helper VM"]
fn native_worker_mode_preflight() {
    let binary = required("ZKMINER_MACOS_WORKER");
    for (requested, expected) in [
        ("cpu", "cpu"),
        (
            "auto",
            if worker_kind() == "metal" {
                "metal"
            } else {
                "cpu"
            },
        ),
    ] {
        let overrides = HashMap::from([("ZKMINER_RISC0_MODE".into(), requested.into())]);
        let mut handle = WorkerHandle::spawn("risc0", &binary, &overrides).unwrap();
        handle
            .send(&WorkerCommand::Warmup { request_id: 17 })
            .unwrap();
        match handle.recv().unwrap() {
            WorkerResponse::WarmupDone {
                request_id,
                summary,
                groth16_helper,
            } => {
                assert_eq!(request_id, 17);
                assert!(summary.to_lowercase().contains(expected), "{summary}");
                assert!(groth16_helper);
            }
            other => panic!("unexpected warmup response: {other:?}"),
        }
    }
    for (key, value, expected) in [
        (
            "ZKMINER_RISC0_MODE",
            "invalid-mode",
            "unknown ZKMINER_RISC0_MODE",
        ),
        ("RISC0_DEV_MODE", "1", "unset RISC0_DEV_MODE"),
        ("RISC0_SKIP_VERIFY", "1", "unset RISC0_SKIP_VERIFY"),
        (
            "ZKMINER_RISC0_METAL_STAGING_BYTES",
            "bad",
            "invalid ZKMINER_RISC0_METAL_STAGING_BYTES",
        ),
        (
            "ZKMINER_RISC0_METAL_STAGING_BYTES",
            "4095",
            "Metal staging budget",
        ),
        (
            "ZKMINER_RISC0_METAL_STAGING_BYTES",
            "16777217",
            "Metal staging budget",
        ),
    ] {
        let overrides = HashMap::from([(key.into(), value.into())]);
        let error = match WorkerHandle::spawn("risc0", &binary, &overrides) {
            Ok(_) => panic!("invalid startup admitted"),
            Err(error) => format!("{error:#}"),
        };
        assert!(error.contains(expected), "{error}");
    }
    if worker_kind() == "cpu" {
        let overrides = HashMap::from([("ZKMINER_RISC0_MODE".into(), "metal".into())]);
        assert!(
            WorkerHandle::spawn("risc0", &binary, &overrides).is_err(),
            "CPU-only worker admitted forced Metal"
        );
    }
}

#[test]
#[ignore = "explicit local Groth16 acceptance; requires built worker, guest, unchanged verifier, and dedicated helper VM"]
fn native_worker_proofs_failure_restart_and_shutdown() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("info")
        .with_writer(std::io::stderr)
        .try_init();
    let binary = required("ZKMINER_MACOS_WORKER");
    let program = required("ZKMINER_MACOS_PROGRAM");
    let verifier = required("ZKMINER_MACOS_VERIFIER");
    let evidence = required("ZKMINER_MACOS_EVIDENCE_DIR");
    fs::create_dir(&evidence).expect("use a fresh evidence directory");
    assert!(helpers().is_empty(), "use an idle dedicated VM");
    let input = evidence.join("input.bin");
    let elf = fs::read(&program).unwrap();
    let workload = Workload::from_environment(&elf);
    fs::write(&input, &workload.input).unwrap();
    fs::write(evidence.join("workload.json"), serde_json::to_vec_pretty(&json!({
        "name":workload.name,"input_sha256":hash(&workload.input),"elf_sha256":workload.elf_sha256,
        "expected_journal_hex":workload.expected_hex,"po2":workload.po2,"min_segments":workload.min_segments,
    })).unwrap()).unwrap();
    let repeats: usize = std::env::var("ZKMINER_MACOS_REPEAT")
        .unwrap_or_else(|_| "3".into())
        .parse()
        .unwrap();
    assert!((1..=100).contains(&repeats));
    let lifecycle = std::env::var("ZKMINER_MACOS_LIFECYCLE").unwrap_or_else(|_| "1".into()) == "1";
    assert!(
        !lifecycle || repeats >= 3,
        "lifecycle acceptance needs at least three complete repeat proofs"
    );
    let overrides = HashMap::from([(
        if worker_kind() == "native" {
            "ZKMINER_RISC0_NATIVE_DIR"
        } else {
            "ZKMINER_RISC0_DOCKER_CONTEXT"
        }
        .into(),
        "hemi-deliberately-missing-context".into(),
    )]);
    assert!(
        WorkerHandle::spawn("risc0", &binary, &overrides).is_err(),
        "missing helper context admitted"
    );
    let mut handle = WorkerHandle::spawn("risc0", &binary, &HashMap::new()).unwrap();
    handle.send(&WorkerCommand::Capabilities).unwrap();
    match handle.recv().unwrap() {
        WorkerResponse::CapabilitiesReport {
            backend,
            gpu_available,
            gpu_name,
            supported_benchmarks,
            ..
        } => {
            assert_eq!(backend, "risc0");
            let gpu = observed_mode() == "metal" || std::env::var("RISC0_RECURSION_HAL").as_deref() == Ok("metal");
            assert_eq!(gpu_available, gpu);
            assert_eq!(gpu_name.is_some(), gpu);
            assert_eq!(supported_benchmarks, ["fibonacci", "sha256-chain"]);
        }
        other => panic!("unexpected capabilities: {other:?}"),
    }
    handle
        .send(&WorkerCommand::Hello {
            protocol_version: PROTOCOL_VERSION + 1,
        })
        .unwrap();
    assert!(matches!(
        handle.recv().unwrap(),
        WorkerResponse::Error { .. }
    ));
    drop(handle);
    let setup_started = Instant::now();
    let phase_started = Instant::now();
    let mut pool = WorkerPool::new(
        HashMap::from([("risc0".into(), binary)]),
        vec![],
        Some(proof_timeout()),
    );
    let pool_new_ms = elapsed_ms(phase_started);
    let phase_started = Instant::now();
    assert_eq!(pool.discover_and_spawn(), [KEY]);
    let pool_discover_and_spawn_ms = elapsed_ms(phase_started);
    let spawned_worker_pid = pool.worker_pid(KEY).unwrap();
    let spawned_worker_start = zkminer_prover::memory::pid_starttime(spawned_worker_pid)
        .expect("discovered worker has no live start identity");
    assert!(zkminer_prover::memory::pid_is_our_worker(
        spawned_worker_pid,
        Some(spawned_worker_start)
    ));
    let phase_started = Instant::now();
    assert!(pool
        .warm_up("risc0", Duration::from_secs(15))
        .unwrap()
        .contains("helper"));
    let worker_warmup_ms = elapsed_ms(phase_started);
    let phase_started = Instant::now();
    let executed_cycles = pool.execute_cycles(
            "risc0",
            &elf,
            &workload.input,
            Some(Duration::from_secs(30)),
            None,
            Some(workload.po2),
        )
        .unwrap().cycles;
    assert!(executed_cycles > 0);
    let valid_execute_cycles_ms = elapsed_ms(phase_started);
    let phase_started = Instant::now();
    assert!(pool
        .execute_cycles(
            "risc0",
            b"invalid guest",
            &[],
            Some(Duration::from_secs(10)),
            None,
            Some(workload.po2),
        )
        .is_err());
    let invalid_execute_cycles_ms = elapsed_ms(phase_started);
    let setup_total_ms = elapsed_ms(setup_started);
    let setup_worker_pid = pool.worker_pid(KEY).unwrap();
    let setup_worker_start = zkminer_prover::memory::pid_starttime(setup_worker_pid);
    if let Some(start) = setup_worker_start {
        assert!(zkminer_prover::memory::pid_is_our_worker(
            setup_worker_pid,
            Some(start)
        ));
    }
    let mut run_timing = json!({
        "schema_version":1,"method":"monotonic std::time::Instant elapsed wall time",
        "setup_scope":"fresh WorkerPool initialization, discovery/startup, warmup and valid/invalid execute-cycle validation; excludes preceding mode/protocol preflight; no proof has been requested; the validation worker may be retired before proving",
        "setup":{
            "pool_new_ms":pool_new_ms,"pool_discover_and_spawn_ms":pool_discover_and_spawn_ms,
            "worker_warmup_ms":worker_warmup_ms,"valid_execute_cycles_ms":valid_execute_cycles_ms,
            "valid_execute_total_cycles":executed_cycles,
            "invalid_execute_cycles_ms":invalid_execute_cycles_ms,"total_ms":setup_total_ms,
            "spawned_worker_pid":spawned_worker_pid,"spawned_worker_start_time_us":spawned_worker_start,
            "worker_pid":setup_worker_pid,"worker_start_time_us":setup_worker_start,
            "identity_scope":"spawned identity immediately after discovery; worker identity after valid/invalid execution validation; null start identity denotes no live worker",
        },
        "cleanup":null,
    });
    fs::write(
        evidence.join("timing.json"),
        serde_json::to_vec_pretty(&run_timing).unwrap(),
    )
    .unwrap();
    let pressure = match std::env::var("ZKMINER_MACOS_ADMISSION_PRESSURE")
        .as_deref()
        .unwrap_or("0")
    {
        "0" => false,
        "1" => true,
        _ => panic!("admission pressure must be 0 or 1"),
    };
    let real_pressure = match std::env::var("ZKMINER_MACOS_KERNEL_PRESSURE")
        .as_deref()
        .unwrap_or("0")
    {
        "0" => false,
        "1" => true,
        _ => panic!("kernel pressure must be 0 or 1"),
    };
    assert!(
        !(pressure || real_pressure) || !lifecycle,
        "admission pressure cases require proof-only acceptance"
    );
    if let Some(path) = std::env::var_os("ZKMINER_MACOS_CALIBRATION") {
        use zkminer_prover::benchmark::{BenchmarkSuite, DeviceBenchmark};
        assert_eq!(worker_kind(), "native");
        let bytes = fs::read(path).unwrap();
        let profile: DeviceBenchmark = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(profile.device_id, "cpu");
        assert_eq!(profile.prover_backend, "risc0");
        let peak = profile.host_peak_bytes.filter(|n| *n > 0).unwrap();
        let mut suite = BenchmarkSuite::default();
        suite.host_peaks.insert("risc0".into(), peak);
        suite.device_benchmarks.push(profile);
        pool.set_expected_host_peaks(&suite);
        let budget = pool.expected_host_peak_at_po2("risc0", Some(workload.po2));
        assert_eq!(budget, suite.expected_host_peak_bytes("risc0"));
        assert!(budget >= peak);
        fs::write(evidence.join("calibration.json"), serde_json::to_vec_pretty(&json!({
            "profile_sha256":hash(&bytes),"measured_peak_bytes":peak,
            "expected_host_budget_bytes":budget,"requested_po2":workload.po2,
        })).unwrap()).unwrap();
    }
    if pressure {
        admission_pressure(&pool, &elf, &workload, &evidence);
    }
    if real_pressure {
        kernel_pressure(&pool, &elf, &workload, &evidence);
    }
    let held_gib = std::env::var("ZKMINER_MACOS_HELD_MEMORY_GIB")
        .ok().map(|value| value.parse::<usize>().unwrap());
    if let Some(gib) = held_gib {
        assert!((1..=100).contains(&gib) && !lifecycle && repeats == 1,
            "held-memory case requires 1..100 GiB and one proof-only request");
    }
    let held = held_gib.map(|gib| start_held_memory(&evidence, gib));
    let mut request_identities = BTreeSet::new();
    let warmups: usize = std::env::var("ZKMINER_MACOS_WARMUP_COUNT")
        .unwrap_or_else(|_| "0".into()).parse().unwrap();
    assert!(warmups <= 1 && warmups < repeats);
    for index in 0..repeats {
        let before = sidecar_paths();
        ledger(
            &evidence,
            &json!({"case":format!("proof-{index}"),"status":"started"}),
        );
        let held_admission = held.as_ref().map(|sibling| {
            let estimate = zkminer_prover::memory::mem_available_bytes().unwrap();
            let level = kernel_pressure_level();
            let report = json!({"held_gib":sibling.ready["held_gib"],
                "sibling_pid":sibling.ready["pid"],"bytes_written":sibling.ready["bytes_written"],
                "time_to_ready_ms":sibling.ready_ms,
                "estimated_available_bytes_at_admission":estimate,
                "pressure_level_at_admission":level});
            fs::write(evidence.join("held-memory-admission.json"),
                serde_json::to_vec_pretty(&report).unwrap()).unwrap();
            assert_eq!(level, Some(1), "held-memory admission requires normal kernel pressure");
            assert!((20 * 1024u64.pow(3)..=30 * 1024u64.pow(3)).contains(&estimate),
                "held-memory admission estimate must be 20..30 GiB; adjust --held-memory-gib");
            report
        });
        let (result, mut resources) = measured_prove(&pool, &elf, &workload);
        fs::write(
            evidence.join(format!("proof-{index}-resource-observations.json")),
            serde_json::to_vec_pretty(&resources).unwrap(),
        )
        .unwrap();
        if let Err(error) = &result {
            ledger(
                &evidence,
                &json!({"case":format!("proof-{index}"),"status":"failed","error":format!("{error:#}"),"resources":resources}),
            );
        }
        let proof = result.unwrap();
        let (_, record) = require_sidecar(&before);
        if workload.po2 == 20 {
            assert_eq!(record["stats"]["total_cycles"], executed_cycles,
                "execution sizing and proof cycle accounting disagree");
        }
        assert!(
            request_identities.insert((
                record["worker_pid"].as_u64().unwrap(),
                record["request_id"].as_u64().unwrap()
            )),
            "duplicate completed request identity"
        );
        let external_verifier_ms = verify(
            &verifier,
            &program,
            &input,
            &evidence.join(format!("proof-{index}")),
            proof,
            &record,
            &workload,
        );
        finish_resources(
            &evidence.join(format!("proof-{index}")),
            &record,
            &mut resources,
        );
        if let Some(admission) = held_admission {
            let worker_pid = record["worker_pid"].as_u64().unwrap() as u32;
            let guard = zkminer_prover::memory::native_memory_observation(worker_pid);
            let periodic: Vec<&Value> = resources["observations"].as_array().unwrap().iter()
                .filter(|sample| sample["phase"] == "periodic_during_prove_call")
                .collect();
            let minimum_periodic_estimate = periodic.iter()
                .filter_map(|sample| sample["native_memory"]["estimated_available_bytes"].as_u64())
                .min().expect("no periodic VM estimate during held-memory proof");
            let report = json!({"admission":admission,
                "minimum_periodic_estimated_available_bytes":minimum_periodic_estimate,
                "guard_min_estimated_available_bytes":guard["guard_min_estimated_available_bytes"],
                "guard_pressure_levels_seen":guard["guard_pressure_levels_seen"],
                "worker_peak_footprint_bytes":guard["guard_peak_footprint_bytes"],
                "worker_pid":worker_pid,"proof_verified":true,"tamper_rejections":3,
                "sibling_held_through_verification":true});
            assert!(report["worker_peak_footprint_bytes"].as_u64().unwrap() > 0);
            fs::write(evidence.join("held-memory.json"),
                serde_json::to_vec_pretty(&report).unwrap()).unwrap();
        }
        let timings = save_proof_timing(
            &evidence.join(format!("proof-{index}")),
            &record,
            &resources,
            external_verifier_ms,
        );
        ledger(
            &evidence,
            &json!({"case":format!("proof-{index}"),"status":"complete_independently_verified","warmup":index < warmups,"worker":record,"resources":resources,"timings":timings}),
        );
        assert!(helpers().is_empty(), "helper survived a successful proof");
    }
    drop(held);
    let pipeline_cancel = std::env::var("ZKMINER_MACOS_PIPELINE_CANCEL").as_deref() == Ok("1");
    if pipeline_cancel {
        assert!(!lifecycle && workload.po2 == 20 && observed_mode() == "metal");
        let before = sidecar_paths();
        let test_log = evidence.parent().unwrap().join("test.log");
        let log_before = fs::metadata(&test_log).unwrap().len() as usize;
        ledger(&evidence, &json!({"case":"segment-pipeline-cancel","status":"started"}));
        let mut observed = None;
        let failure = std::thread::scope(|scope| {
            let task = scope.spawn(|| {
                pool.prove(
                    "risc0",
                    &elf,
                    &workload.input,
                    Some(workload.po2),
                    Some(proof_timeout()),
                    None,
                )
            });
            let deadline = Instant::now() + Duration::from_secs(240);
            while !task.is_finished() && Instant::now() < deadline {
                if let Some((_, record)) = new_sidecar(&before) {
                    let log = fs::read_to_string(&test_log).unwrap();
                    if let Some(recent) = log.get(log_before..) {
                        if let Some(marker) = recent.lines().rev().find(|line| {
                            line.contains("[metal_pipeline] cpu_begin set=")
                                && line.contains("gpu_owned_set=Some(")
                        }) {
                            pool.cancel(KEY, record["request_id"].as_u64().unwrap())
                                .unwrap();
                            observed = Some((record, marker.to_owned()));
                            break;
                        }
                    }
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            if observed.is_none() && !task.is_finished() {
                pool.cancel(KEY, 0).unwrap();
            }
            task.join().unwrap()
        });
        ledger(&evidence, &json!({
            "case":"segment-pipeline-cancel",
            "status":if failure.is_err() && observed.is_some() {"expected_failure"} else {"failed"},
            "error":failure.as_ref().err().map(|error|format!("{error:#}")),
            "observed_overlap":observed,
        }));
        assert!(failure.is_err(), "cancelled pipeline request unexpectedly completed");
        let (record, _) = observed.expect("cancellation did not observe overlapping segments");
        assert!(helpers().is_empty(), "owned helper survived pipeline cancellation");
        assert_group_gone(record["worker_pid"].as_u64().unwrap() as u32);
    }
    if lifecycle {
        // Trigger real parent cancellation only after this request's helper is running.
        let before = sidecar_paths();
        ledger(
            &evidence,
            &json!({"case":"helper-cancel","status":"started"}),
        );
        let mut observed = None;
        let failure = std::thread::scope(|scope| {
            let task = scope.spawn(|| {
                pool.prove(
                    "risc0",
                    &elf,
                    &workload.input,
                    Some(workload.po2),
                    Some(proof_timeout()),
                    None,
                )
            });
            let deadline = Instant::now() + Duration::from_secs(240);
            while !task.is_finished() && Instant::now() < deadline {
                if let Some((_, record)) = new_sidecar(&before) {
                    if record["phase"] == "wrapping" {
                        let name = record["helper_container"]
                            .as_str()
                            .expect("missing helper lease identity");
                        if helper_running(name) {
                            validate_stage(&record, &workload);
                            pool.cancel(KEY, record["request_id"].as_u64().unwrap())
                                .unwrap();
                            observed = Some(record);
                            break;
                        }
                    }
                }
                std::thread::sleep(Duration::from_millis(250));
            }
            if observed.is_none() && !task.is_finished() {
                pool.cancel(KEY, 0).unwrap();
            }
            task.join().unwrap()
        });
        ledger(
            &evidence,
            &json!({"case":"helper-cancel","status":if failure.is_err() && observed.is_some() {"expected_failure"} else {"failed"},"error":failure.as_ref().err().map(|e|format!("{e:#}")),"observed_running_helper":observed}),
        );
        assert!(failure.is_err(), "cancelled request unexpectedly completed");
        let observed =
            observed.expect("cancellation did not observe this request's running helper");
        assert!(helpers().is_empty(), "owned helper survived cancellation");
        assert_group_gone(observed["worker_pid"].as_u64().unwrap() as u32);

        // Keep the production watchdog test separate from explicit cancellation.
        let before = sidecar_paths();
        let seen = Arc::new(Mutex::new(None));
        let done = Arc::new(AtomicBool::new(false));
        let (capture, stop) = (seen.clone(), done.clone());
        let monitor = std::thread::spawn(move || {
            while !stop.load(Ordering::Acquire) {
                if let Some((_, record)) = new_sidecar(&before) {
                    if worker_kind() == "native"
                        || (record["phase"] == "wrapping"
                            && helper_running(record["helper_container"].as_str().unwrap()))
                    {
                        *capture.lock().unwrap() = Some(record);
                    }
                }
                std::thread::sleep(Duration::from_millis(500));
            }
        });
        let seconds: u64 = std::env::var("ZKMINER_MACOS_FAILURE_TIMEOUT_SECS")
            .unwrap_or_else(|_| {
                if worker_kind() == "native" {
                    "10".into()
                } else {
                    "70".into()
                }
            })
            .parse()
            .unwrap();
        assert!((1..=300).contains(&seconds));
        ledger(
            &evidence,
            &json!({"case":"helper-timeout","status":"started","timeout_seconds":seconds}),
        );
        let timeout_started = Instant::now();
        let failure = pool.prove(
            "risc0",
            &elf,
            &workload.input,
            Some(workload.po2),
            Some(Duration::from_secs(seconds)),
            None,
        );
        let timeout_elapsed = timeout_started.elapsed().as_secs_f64();
        done.store(true, Ordering::Release);
        monitor.join().unwrap();
        let observed = seen.lock().unwrap().clone();
        ledger(
            &evidence,
            &json!({"case":"helper-timeout","status":if failure.is_err() && observed.is_some() && timeout_elapsed >= seconds as f64 {"expected_failure"} else {"failed"},"timeout_seconds":seconds,"elapsed_seconds":timeout_elapsed,"error":failure.as_ref().err().map(|e|format!("{e:#}")),"observed_running_helper":observed}),
        );
        assert!(failure.is_err(), "deadline should stop a real proof");
        assert!(
            timeout_elapsed >= seconds as f64,
            "request failed before the configured watchdog deadline"
        );
        let observed = observed.expect("watchdog did not reach this request's running helper");
        // The watchdog may stop a proof before recursion or constraint stages
        // write their completed counters. This is an in-flight sidecar, not a
        // completed proof record.
        assert_eq!(observed["schema_version"], 1);
        assert_eq!(observed["operation"], "prove");
        assert_eq!(observed["po2"], workload.po2);
        assert_eq!(observed["requested_mode"], mode());
        let timeout_worker_pid = positive(&observed, "worker_pid") as u32;
        assert!(helpers().is_empty(), "owned helper survived watchdog");
        assert_group_gone(timeout_worker_pid);
        assert_group_gone(observed["worker_pid"].as_u64().unwrap() as u32);

        let before = sidecar_paths();
        ledger(
            &evidence,
            &json!({"case":"proof-after-restart","status":"started"}),
        );
        let (proof, mut resources) = measured_prove(&pool, &elf, &workload);
        fs::write(
            evidence.join("proof-after-restart-resource-observations.json"),
            serde_json::to_vec_pretty(&resources).unwrap(),
        )
        .unwrap();
        if let Err(error) = &proof {
            ledger(
                &evidence,
                &json!({"case":"proof-after-restart","status":"failed","error":format!("{error:#}"),"resources":resources}),
            );
        }
        let proof = proof.unwrap();
        let (_, record) = require_sidecar(&before);
        assert!(
            request_identities.insert((
                record["worker_pid"].as_u64().unwrap(),
                record["request_id"].as_u64().unwrap()
            )),
            "duplicate completed request identity"
        );
        let external_verifier_ms = verify(
            &verifier,
            &program,
            &input,
            &evidence.join("proof-after-restart"),
            proof,
            &record,
            &workload,
        );
        finish_resources(
            &evidence.join("proof-after-restart"),
            &record,
            &mut resources,
        );
        let timings = save_proof_timing(
            &evidence.join("proof-after-restart"),
            &record,
            &resources,
            external_verifier_ms,
        );
        ledger(
            &evidence,
            &json!({"case":"proof-after-restart","status":"complete_independently_verified","worker":record,"resources":resources,"timings":timings}),
        );
    }
    let cleanup_started = Instant::now();
    let pid = pool.worker_pid(KEY).unwrap();
    let cleanup_worker_start = zkminer_prover::memory::pid_starttime(pid);
    let phase_started = Instant::now();
    pool.shutdown_all();
    let shutdown_all_ms = elapsed_ms(phase_started);
    let phase_started = Instant::now();
    drop(pool);
    let drop_pool_ms = elapsed_ms(phase_started);
    let phase_started = Instant::now();
    assert!(helpers().is_empty(), "helper survived shutdown");
    if pid != 0 {
        assert_group_gone(pid);
    }
    let post_cleanup_checks_ms = elapsed_ms(phase_started);
    run_timing["cleanup"] = json!({
        "shutdown_all_ms":shutdown_all_ms,"drop_pool_ms":drop_pool_ms,
        "post_cleanup_checks_ms":post_cleanup_checks_ms,"total_ms":elapsed_ms(cleanup_started),
        "worker_pid":pid,"worker_start_time_us":cleanup_worker_start,
        "scope":"WorkerPool shutdown and drop followed by helper absence and process-group checks",
    });
    fs::write(
        evidence.join("timing.json"),
        serde_json::to_vec_pretty(&run_timing).unwrap(),
    )
    .unwrap();
    fs::write(evidence.join("complete.json"), serde_json::to_vec_pretty(&json!({
        "status":"complete_independently_verified", "requested_mode":mode(),"observed_mode":observed_mode(),
        "verified_proofs":repeats + usize::from(lifecycle), "helper_cancel":lifecycle,"helper_timeout":lifecycle && worker_kind() != "native","worker_timeout":lifecycle,
        "restart":lifecycle,"shutdown":true,"pipeline_cancel":pipeline_cancel,"workload":workload.name,"po2":workload.po2,
        "min_segments":workload.min_segments,"expected_journal_hex":workload.expected_hex,
        "admission_pressure":pressure,"kernel_pressure":real_pressure,"held_memory_gib":held_gib,"unique_completed_requests":request_identities.len(),
    })).unwrap()).unwrap();
}
