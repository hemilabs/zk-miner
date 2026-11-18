//! Mock worker binary for integration tests.
//!
//! Speaks the worker IPC protocol (Hello/HelloAck handshake, Benchmark, Prove, Warmup, and canned
//! answers to Execute and CalibrateSegmentLimit)
//! and can be configured via environment variables:
//!
//! - `MOCK_HANG_ON`: `"benchmark"`, `"prove"`, `"execute"`, `"both"` or `"warmup"` — hangs (sleeps
//!   forever) on the specified command type. `"both"` covers benchmark + prove + execute. Unset or
//!   empty = respond normally. `"execute"` holds a measurement in flight until it is SIGKILLed.
//! - `MOCK_CRASH_ON`: `"benchmark"`, `"prove"`, `"execute"`, `"both"` or `"warmup"` — exits
//!   immediately with code 1 on the specified command type, simulating a worker crash.
//! - `MOCK_CRASH_CODE`: the exit code for `MOCK_CRASH_ON` on `"prove"` and `"benchmark"`. Default: 1.
//! - `MOCK_SERVER_OOM`: set to anything to have a child, standing in for a prover's server, allocate
//!   until the kernel kills it, before `MOCK_CRASH_ON` applies on `"prove"`: a host OOM killing a
//!   server and not the worker. First lowers this worker's own cgroup limit to 256 MiB, and exits 99
//!   if it cannot, so the child can never eat the host.
//! - `MOCK_HOLD_SHM`: a `/dev/shm` name to create and map before hanging on an Execute, as SP1's native
//!   executor stages a guest there, and leaves it behind if killed.
//! - `MOCK_BACKEND`: backend name for the HelloAck response. Default: `"mock"`.
//! - `MOCK_JOURNAL_HEX` / `MOCK_SEAL_HEX`: replay a fixed receipt. Execute reports the journal, and
//!   Prove returns the journal and the seal, whatever the ELF and input. With a real receipt (the
//!   contract suite's RISC Zero fixture), the miner can claim and fulfil on a chain whose verifier
//!   accepts it, without proving (crates/zkminer-cli/tests/localnet.rs). Unset = an empty journal
//!   and seal.
//! - `MOCK_PROVE_DELAY_SECS`: how long a Prove takes (default 0), so a test can act while a lock
//!   is held.
//! - `MOCK_HOST_ENTROPY_READS`: what an Execute reports as `host_entropy_reads`: a number, or
//!   `unknown` for `None`. Default: 0.
//! - `MOCK_PROTOCOL_VERSION`: the protocol version HelloAck reports. Default: this build's.
//! - `MOCK_PROVE_ERROR_KIND`: answer every Prove with a `WorkerResponse::Error` of this kind
//!   (`resource_exhausted`, `proof_failed` or `invalid_input`), and `MOCK_PROVE_ERROR_MESSAGE` as
//!   its message.
//! - `MOCK_OOM_UNLESS_CAP_AT_MOST`: answer a Prove, and a Benchmark, with a `ResourceExhausted`
//!   error unless `ZKMINER_SP1_ELEMENT_THRESHOLD_CAP` (the SP1 shard-size cap the dispatcher spawns
//!   a worker with) is set to at most this: a program, or a card, that fits only at the smaller size.
//! - `MOCK_RECORD_TO`: a file each Benchmark and Prove appends a line to, saying what it was sent
//!   (`benchmark po2=<po2>`) or what it ran with (`prove cap=<ZKMINER_SP1_ELEMENT_THRESHOLD_CAP>`).
//! - `MOCK_SETUP_SECS`: a one-time setup of this many seconds (default 0), paid by the first
//!   Warmup, Execute or ProgramId, as SP1's measure worker builds its CPU prover on first use.
//! - `MOCK_WARMUP_LOG`: a file each Warmup appends a line to, so a test can count them.

use std::io::{self, BufReader, BufWriter};
use std::time::Duration;

use zkminer_prover_protocol::types::ErrorKind;
use zkminer_prover_protocol::{
    read_message, write_message, FrameError, WorkerCommand, WorkerResponse, PROTOCOL_VERSION,
};

fn main() {
    if std::env::var_os("MOCK_BE_MEMORY_HOG").is_some() {
        let mut held: Vec<Vec<u8>> = Vec::new();
        loop {
            held.push(vec![1u8; 16 * 1024 * 1024]);
        }
    }
    let hang_on = std::env::var("MOCK_HANG_ON").unwrap_or_default();
    let crash_on = std::env::var("MOCK_CRASH_ON").unwrap_or_default();
    let crash_code: i32 = std::env::var("MOCK_CRASH_CODE")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1);
    let backend = std::env::var("MOCK_BACKEND").unwrap_or_else(|_| "mock".to_string());
    let journal = hex_env("MOCK_JOURNAL_HEX");
    let seal = hex_env("MOCK_SEAL_HEX");
    let record = |line: String| {
        if let Some(path) = std::env::var_os("MOCK_RECORD_TO") {
            use std::io::Write as _;
            let mut file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .expect("MOCK_RECORD_TO");
            writeln!(file, "{line}").expect("MOCK_RECORD_TO");
        }
    };
    let cap = std::env::var("ZKMINER_SP1_ELEMENT_THRESHOLD_CAP").ok();
    // `MOCK_OOM_UNLESS_CAP_AT_MOST`: runs out of memory at this worker's cap.
    let oom_at_cap = std::env::var("MOCK_OOM_UNLESS_CAP_AT_MOST")
        .ok()
        .map(|most| {
            most.trim()
                .parse::<u64>()
                .expect("MOCK_OOM_UNLESS_CAP_AT_MOST")
        })
        .is_some_and(|most| {
            cap.as_deref()
                .and_then(|c| c.trim().parse::<u64>().ok())
                .is_none_or(|c| c > most)
        });
    let prove_delay = Duration::from_secs(
        std::env::var("MOCK_PROVE_DELAY_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0),
    );
    let mut setup = Some(Duration::from_secs(
        std::env::var("MOCK_SETUP_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0),
    ));
    // Pays the one-time setup if it has not been paid yet.
    let mut set_up = move || {
        if let Some(d) = setup.take() {
            std::thread::sleep(d);
        }
    };

    let mut stdin = BufReader::new(io::stdin().lock());
    let mut stdout = BufWriter::new(io::stdout().lock());

    loop {
        let cmd: WorkerCommand = match read_message(&mut stdin) {
            Ok(cmd) => cmd,
            Err(FrameError::UnexpectedEof) => break,
            Err(_) => break,
        };

        match cmd {
            WorkerCommand::Hello {
                protocol_version: _,
            } => {
                let resp = WorkerResponse::HelloAck {
                    protocol_version: std::env::var("MOCK_PROTOCOL_VERSION")
                        .ok()
                        .map(|v| v.trim().parse().expect("MOCK_PROTOCOL_VERSION"))
                        .unwrap_or(PROTOCOL_VERSION),
                    backend: backend.clone(),
                    sdk_version: "mock 0.1.0".to_string(),
                    worker_version: "0.1.0".to_string(),
                };
                write_message(&mut stdout, &resp).unwrap();
            }

            WorkerCommand::Capabilities => {
                let resp = WorkerResponse::CapabilitiesReport {
                    backend: backend.clone(),
                    version: "0.1.0".to_string(),
                    supported_benchmarks: vec![],
                    gpu_available: false,
                    gpu_name: None,
                };
                write_message(&mut stdout, &resp).unwrap();
            }

            WorkerCommand::Benchmark { po2, .. } => {
                record(format!("benchmark po2={po2:?}"));
                if crash_on == "benchmark" || crash_on == "both" {
                    std::process::exit(crash_code);
                }
                if hang_on == "benchmark" || hang_on == "both" {
                    // Hang forever — the watchdog will SIGKILL us
                    loop {
                        std::thread::sleep(Duration::from_secs(3600));
                    }
                }
                let resp = if oom_at_cap {
                    WorkerResponse::Error {
                        request_id: 0,
                        kind: ErrorKind::ResourceExhausted,
                        message: "mock: an SP1 benchmark ran out of GPU memory at this shard size"
                            .to_string(),
                    }
                } else {
                    WorkerResponse::BenchmarkResult { results: vec![] }
                };
                write_message(&mut stdout, &resp).unwrap();
            }

            WorkerCommand::Prove {
                request_id,
                elf: _,
                input_data: _,
                po2,
                program_id: _,
            } => {
                if std::env::var_os("MOCK_SERVER_OOM").is_some() {
                    if limit_own_cgroup_memory(256 * 1024 * 1024).is_err() {
                        std::process::exit(99);
                    }
                    let _ = std::process::Command::new(std::env::current_exe().unwrap())
                        .env("MOCK_BE_MEMORY_HOG", "1")
                        .stdout(std::process::Stdio::null())
                        .status();
                }
                if crash_on == "prove" || crash_on == "both" {
                    std::process::exit(crash_code);
                }
                if hang_on == "prove" || hang_on == "both" {
                    loop {
                        std::thread::sleep(Duration::from_secs(3600));
                    }
                }
                std::thread::sleep(prove_delay);
                record(format!("prove cap={}", cap.as_deref().unwrap_or("none")));
                let oom = oom_at_cap;
                let error_kind = match std::env::var("MOCK_PROVE_ERROR_KIND").as_deref() {
                    Ok("resource_exhausted") => Some(ErrorKind::ResourceExhausted),
                    Ok("proof_failed") => Some(ErrorKind::ProofFailed),
                    Ok("invalid_input") => Some(ErrorKind::InvalidInput),
                    Ok(other) => panic!("MOCK_PROVE_ERROR_KIND={other}"),
                    Err(_) => oom.then_some(ErrorKind::ResourceExhausted),
                };
                if let Some(kind) = error_kind {
                    let resp = WorkerResponse::Error {
                        request_id,
                        kind,
                        message: std::env::var("MOCK_PROVE_ERROR_MESSAGE")
                            .unwrap_or_else(|_| "mock: out of GPU memory".to_string()),
                    };
                    write_message(&mut stdout, &resp).unwrap();
                    continue;
                }
                // 1,000 cycles, plus the segment size asked for, so a test can see which arrived.
                let resp = WorkerResponse::ProofResult {
                    request_id,
                    journal: journal.clone(),
                    seal: seal.clone(),
                    duration_secs: 0.01,
                    cycles: 1000 + u64::from(po2.unwrap_or(0)),
                };
                write_message(&mut stdout, &resp).unwrap();
            }

            // Measures nothing: answers like a guest of 1,000 cycles (plus the segment size asked
            // for, so a test can see which arrived) that commits `journal`, so a caller sees a
            // well-formed reply rather than a hang.
            WorkerCommand::Execute {
                request_id, po2, ..
            } => {
                if crash_on == "execute" || crash_on == "both" {
                    std::process::exit(1);
                }
                set_up();
                #[cfg(unix)]
                if let Ok(name) = std::env::var("MOCK_HOLD_SHM") {
                    hold_shm(&name);
                }
                if hang_on == "execute" || hang_on == "both" {
                    // Hang forever — simulating an in-flight measurement that holds its slot and its
                    // ledger reservations until it is SIGKILLed (by the measure watchdog, or by a
                    // committed proof preempting it). Lets a test hold a measurement in flight
                    // deterministically. The sleep loop is interruptible only by the signal.
                    loop {
                        std::thread::sleep(Duration::from_secs(3600));
                    }
                }
                let resp = WorkerResponse::ExecuteResult {
                    request_id,
                    cycles: 1000 + u64::from(po2.unwrap_or(0)),
                    duration_secs: 0.01,
                    journal_len: journal.len() as u64,
                    peak_host_bytes: 0,
                    journal: Some(journal.clone()),
                    host_entropy_reads: match std::env::var("MOCK_HOST_ENTROPY_READS") {
                        Ok(v) if v == "unknown" => None,
                        Ok(v) => Some(v.trim().parse().expect("MOCK_HOST_ENTROPY_READS")),
                        Err(_) => Some(0),
                    },
                    user_cycles: Some(1000),
                    keccak_cycles: Some(0),
                };
                write_message(&mut stdout, &resp).unwrap();
            }

            // Measures nothing either: one segment of 1,000 cycles at whatever po2 was asked for.
            WorkerCommand::CalibrateSegmentLimit { request_id, po2 } => {
                let resp = WorkerResponse::CalibrationResult {
                    request_id,
                    po2,
                    segment_count: 1,
                    total_cycles: 1000,
                    prove_duration_secs: 0.01,
                };
                write_message(&mut stdout, &resp).unwrap();
            }

            WorkerCommand::Cancel { request_id } => {
                let resp = WorkerResponse::Cancelled { request_id };
                write_message(&mut stdout, &resp).unwrap();
            }

            WorkerCommand::Warmup { request_id } => {
                if crash_on == "warmup" {
                    std::process::exit(1);
                }
                if let Some(log) = std::env::var_os("MOCK_WARMUP_LOG") {
                    use std::io::Write;
                    let mut f = std::fs::OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open(log)
                        .unwrap();
                    writeln!(f, "{}", std::process::id()).unwrap();
                }
                if hang_on == "warmup" {
                    // Hang forever — the watchdog will SIGKILL us
                    loop {
                        std::thread::sleep(Duration::from_secs(3600));
                    }
                }
                set_up();
                let resp = WorkerResponse::WarmupDone {
                    request_id,
                    summary: "nothing to warm up".to_string(),
                    groth16_helper: false,
                };
                write_message(&mut stdout, &resp).unwrap();
            }

            // Derives nothing: answers keccak256 of the ELF, so a test can tell ELFs apart and serve a
            // matching (or deliberately mismatching) programId. `MOCK_PROGRAM_ID_FAIL=1` refuses the
            // ELF, as a worker does one its SDK cannot parse.
            WorkerCommand::ProgramId { request_id, elf } => {
                if crash_on == "program_id" {
                    std::process::exit(1);
                }
                if hang_on == "program_id" {
                    loop {
                        std::thread::sleep(Duration::from_secs(3600));
                    }
                }
                set_up();
                let resp = if std::env::var_os("MOCK_PROGRAM_ID_FAIL").is_some() {
                    WorkerResponse::Error {
                        request_id,
                        kind: zkminer_prover_protocol::types::ErrorKind::InvalidInput,
                        message: "mock: this ELF does not parse".to_string(),
                    }
                } else {
                    WorkerResponse::ProgramIdResult {
                        request_id,
                        program_id: alloy_primitives::keccak256(&elf).0,
                        duration_secs: 0.01,
                    }
                };
                write_message(&mut stdout, &resp).unwrap();
            }

            WorkerCommand::Shutdown => break,
        }
    }
}

/// Map a new `/dev/shm/<name>` shared, touch it, and keep it mapped for good. Named only once it is
/// mapped, so that a test that sees the name knows a kill will find the mapping.
#[cfg(unix)]
fn hold_shm(name: &str) {
    use std::os::fd::AsRawFd;
    const LEN: usize = 1024 * 1024;
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .read(true)
        .write(true)
        .open(format!("/dev/shm/{name}.partial"))
        .expect("create the /dev/shm file");
    file.set_len(LEN as u64).expect("size the /dev/shm file");
    let mapped = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            LEN,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            file.as_raw_fd(),
            0,
        )
    };
    assert_ne!(mapped, libc::MAP_FAILED, "map the /dev/shm file");
    unsafe { std::ptr::write_bytes(mapped as *mut u8, 1, LEN) };
    std::fs::rename(
        format!("/dev/shm/{name}.partial"),
        format!("/dev/shm/{name}"),
    )
    .expect("name the /dev/shm file");
}

/// Lower `memory.max` of the cgroup this process is in, and read it back.
fn limit_own_cgroup_memory(bytes: u64) -> io::Result<()> {
    let own = std::fs::read_to_string("/proc/self/cgroup")?;
    let relative = own
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .ok_or(io::ErrorKind::NotFound)?;
    let file = format!("/sys/fs/cgroup{}/memory.max", relative.trim());
    std::fs::write(&file, bytes.to_string())?;
    if std::fs::read_to_string(&file)?.trim() != bytes.to_string() {
        return Err(io::ErrorKind::Other.into());
    }
    Ok(())
}

/// The bytes of a hex environment variable (an optional `0x` prefix allowed); empty when unset.
fn hex_env(name: &str) -> Vec<u8> {
    let Ok(v) = std::env::var(name) else {
        return Vec::new();
    };
    let v = v.trim().trim_start_matches("0x");
    assert!(v.len() % 2 == 0, "{name} has an odd number of hex digits");
    (0..v.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&v[i..i + 2], 16).unwrap_or_else(|_| panic!("{name} is not hex"))
        })
        .collect()
}
