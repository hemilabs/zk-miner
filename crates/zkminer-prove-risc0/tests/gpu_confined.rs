//! A GPU worker proves while confined (`zkminer_witness_sandbox::confine`): a real Groth16 proof of
//! the fibonacci guest through the `Prove` command, on whichever card the environment pins, with the
//! worker checked from outside (every thread in seccomp filter mode, no socket but the CUDA driver's
//! own listener) and its confinement report in its log.
//!
//! Built with the CPU feature (cheap), it drives the GPU worker named by `ZKMINER_GPU_WORKER`:
//!
//! ```text
//! CUDA_DEVICE_ORDER=PCI_BUS_ID ZKMINER_GPU_WORKER=target/release/zkminer-prove-risc0-cuda \
//!     cargo test -p zkminer-prove-risc0 --features cpu --test gpu_confined -- --ignored \
//!     --nocapture --test-threads=1
//! ```
//!
//! The worker inherits this process's environment (device pinning: `CUDA_VISIBLE_DEVICES`,
//! `HIP_VISIBLE_DEVICES`, `ZE_AFFINITY_MASK`, `ONEAPI_DEVICE_SELECTOR`), with a fresh `HOME`.
//! `RISC0_HOME` must name an rzup home holding the `risc0-groth16` component (it is only read), and
//! `XDG_CACHE_HOME` the GPU caches to use (an Intel card compiles its kernels into it on first use).
#![cfg(all(feature = "cpu", target_os = "linux"))]

use std::io::{BufReader, Read};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use zkminer_prover_protocol::{
    read_message, write_message, WorkerCommand, WorkerResponse, PROTOCOL_VERSION,
};

struct Worker {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    log: Arc<Mutex<String>>,
}

impl Worker {
    fn recv(&mut self) -> WorkerResponse {
        read_message(&mut self.stdout).unwrap_or_else(|e| panic!("{e}; log:\n{}", self.log()))
    }

    fn log(&self) -> String {
        self.log.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }

    /// The answer past progress messages.
    fn answer(&mut self, cmd: &WorkerCommand) -> WorkerResponse {
        write_message(&mut self.stdin, cmd).unwrap();
        loop {
            match self.recv() {
                WorkerResponse::Progress { .. } | WorkerResponse::SetupProgress { .. } => {}
                other => return other,
            }
        }
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn status_field(status: &str, name: &str) -> String {
    status
        .lines()
        .find_map(|l| l.strip_prefix(name))
        .map(|v| v.trim().to_string())
        .unwrap_or_default()
}

/// `(socket inode, listening?)` of the worker's sockets, from `/proc/<pid>/fd` and `/proc/net/unix`
/// (`Flags` 00010000 is `__SO_ACCEPTCON`).
fn sockets(pid: u32) -> Vec<(u64, String)> {
    let unix = std::fs::read_to_string(format!("/proc/{pid}/net/unix")).unwrap_or_default();
    std::fs::read_dir(format!("/proc/{pid}/fd"))
        .unwrap()
        .filter_map(|fd| std::fs::read_link(fd.ok()?.path()).ok())
        .filter_map(|t| {
            t.to_str()?
                .strip_prefix("socket:[")?
                .strip_suffix(']')?
                .parse::<u64>()
                .ok()
        })
        .map(|inode| {
            let line = unix
                .lines()
                .find(|l| l.split_whitespace().nth(6) == Some(&inode.to_string()))
                .unwrap_or("not a unix socket")
                .to_string();
            (inode, line)
        })
        .collect()
}

#[test]
#[ignore = "needs a GPU worker (ZKMINER_GPU_WORKER) and its card"]
fn a_confined_gpu_worker_proves() {
    let worker_path = std::env::var("ZKMINER_GPU_WORKER").expect("ZKMINER_GPU_WORKER");
    let home = tempfile::tempdir().unwrap();
    // The guest and its image id, from the worker itself.
    let elf_path = home.path().join("fibonacci.elf");
    let out = Command::new(&worker_path)
        .args(["--export-guest", "fibonacci"])
        .arg(&elf_path)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let hex = String::from_utf8(out.stdout).unwrap();
    let hex = hex.trim().trim_start_matches("0x");
    let image_id: [u8; 32] = (0..64)
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect::<Vec<u8>>()
        .try_into()
        .unwrap();
    let elf = std::fs::read(&elf_path).unwrap();

    let mut child = Command::new(&worker_path)
        .env("HOME", home.path())
        .env(
            "RUST_LOG",
            std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()),
        )
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let pid = child.id();
    let stdin = child.stdin.take().unwrap();
    let stdout = BufReader::new(child.stdout.take().unwrap());
    let mut stderr = child.stderr.take().unwrap();
    let log = Arc::new(Mutex::new(String::new()));
    let sink = log.clone();
    std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        while let Ok(n) = stderr.read(&mut buf) {
            if n == 0 {
                break;
            }
            let text = String::from_utf8_lossy(&buf[..n]).into_owned();
            eprint!("{text}");
            sink.lock()
                .unwrap_or_else(|e| e.into_inner())
                .push_str(&text);
        }
    });
    let mut w = Worker {
        child,
        stdin,
        stdout,
        log,
    };
    match w.answer(&WorkerCommand::Hello {
        protocol_version: PROTOCOL_VERSION,
    }) {
        WorkerResponse::HelloAck { .. } => {}
        other => panic!("{other:?}"),
    }
    // The one-time setup (the component is installed; an Intel card proves once, confined).
    let started = Instant::now();
    match w.answer(&WorkerCommand::Warmup { request_id: 1 }) {
        WorkerResponse::WarmupDone { summary, .. } => {
            eprintln!("WARMUP {:.0}s: {summary}", started.elapsed().as_secs_f64())
        }
        other => panic!("{other:?}\n{}", w.log()),
    }

    // A measurement, then a real proof, both after the confinement.
    let input = 1000u32.to_le_bytes().to_vec();
    let po2 = std::env::var("ZKMINER_GPU_PO2")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(20u8);
    match w.answer(&WorkerCommand::Execute {
        request_id: 2,
        elf: elf.clone(),
        input_data: input.clone(),
        program_id: Some(image_id),
        po2: Some(po2),
    }) {
        WorkerResponse::ExecuteResult {
            cycles, journal, ..
        } => {
            eprintln!("EXECUTE {cycles} cycles, journal {journal:?}")
        }
        other => panic!("{other:?}\n{}", w.log()),
    }
    let started = Instant::now();
    let (journal, seal) = match w.answer(&WorkerCommand::Prove {
        request_id: 3,
        elf: elf.clone(),
        input_data: input,
        po2: Some(po2),
        program_id: Some(image_id),
        witness: None,
    }) {
        WorkerResponse::ProofResult {
            journal,
            seal,
            duration_secs,
            cycles,
            ..
        } => {
            eprintln!(
                "PROOF {cycles} cycles in {duration_secs:.1}s ({:.1}s with the round trip), \
                 journal {} bytes, Groth16 seal {} bytes",
                started.elapsed().as_secs_f64(),
                journal.len(),
                seal.len()
            );
            (journal, seal)
        }
        other => panic!("{other:?}\n{}", w.log()),
    };
    // fib(1000) mod 2^64, as the guest commits it; the worker verified the receipt itself.
    let (mut a, mut b) = (0u64, 1u64);
    for _ in 0..1000 {
        let c = a.wrapping_add(b);
        a = b;
        b = c;
    }
    assert_eq!(journal, a.to_le_bytes());
    assert_eq!(seal.len(), 256, "a Groth16 seal");

    // From outside: every thread filtered, no new privileges, no socket but an inert listener.
    let mut threads = 0;
    for task in std::fs::read_dir(format!("/proc/{pid}/task")).unwrap() {
        let task = task.unwrap();
        let Ok(status) = std::fs::read_to_string(task.path().join("status")) else {
            continue;
        };
        threads += 1;
        assert_eq!(
            (
                status_field(&status, "Seccomp:"),
                status_field(&status, "NoNewPrivs:")
            ),
            ("2".to_string(), "1".to_string()),
            "thread {:?}",
            task.file_name()
        );
    }
    eprintln!("THREADS {threads} all in seccomp filter mode with no_new_privs");
    for (inode, line) in sockets(pid) {
        eprintln!("SOCKET {inode}: {line}");
        // Flags 00010000: a listener (the CUDA driver's), which can accept nothing.
        assert!(line.split_whitespace().nth(3) == Some("00010000"), "{line}");
    }
    let log = w.log();
    let report = log
        .lines()
        .find(|l| l.contains("worker confined:"))
        .unwrap_or_else(|| panic!("no confinement report:\n{log}"));
    eprintln!("REPORT {report}");
    for promise in [
        "seccomp: no sockets",
        "socket() refused",
        "filesystem restricted",
        "parent unreachable by signal",
    ] {
        assert!(report.contains(promise), "{promise}");
    }
    // The miner (here, the test) can still signal its worker.
    assert_eq!(unsafe { libc::kill(pid as i32, 0) }, 0);
}
