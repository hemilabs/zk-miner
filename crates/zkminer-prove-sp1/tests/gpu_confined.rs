//! A real SP1 Groth16 proof with the worker and its `sp1-gpu-server` confined: the worker keeps only
//! its connection to its own server, and the server runs under its supervisor (Landlock, no socket
//! after its first connection, never `connect`). Checked from outside: every thread of the worker,
//! the shim and the server in seccomp filter mode, the server's parent the shim, the sockets each
//! holds; and the worker's confinement report in its log.
//!
//! ```text
//! CUDA_DEVICE_ORDER=PCI_BUS_ID cargo test --release -p zkminer-prove-sp1 --test gpu_confined -- \
//!     --ignored --nocapture --test-threads=1
//! ```
//!
//! The worker inherits this process's environment (`ZKMINER_CUDA_DEVICE_ID`,
//! `ZKMINER_SP1_CUDA_RUNTIME_DIR`, `SP1_GPU_SERVER_NAME`, ...) with `HOME` set to
//! `ZKMINER_GPU_TEST_HOME`: a home of its own, whose `.sp1` holds (or links to) the server and the
//! Groth16 circuit artifacts. Nothing is written there but the shim's link in `.sp1/bin`.

use std::io::{BufReader, Read};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use zkminer_prover_protocol::{
    read_message, write_message, WorkerCommand, WorkerResponse, PROTOCOL_VERSION,
};

const WORKER: &str = env!("CARGO_BIN_EXE_zkminer-prove-sp1");

struct Worker {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    log: Arc<Mutex<String>>,
}

impl Worker {
    fn answer(&mut self, cmd: &WorkerCommand) -> WorkerResponse {
        write_message(&mut self.stdin, cmd).unwrap();
        loop {
            match read_message(&mut self.stdout).unwrap_or_else(|e| {
                let log = self.log.lock().unwrap_or_else(|p| p.into_inner()).clone();
                panic!("{e}; log:\n{log}")
            }) {
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

fn read(path: String) -> String {
    std::fs::read_to_string(path).unwrap_or_default()
}

fn field(status: &str, name: &str) -> String {
    status
        .lines()
        .find_map(|l| l.strip_prefix(name))
        .map(|v| v.trim().to_string())
        .unwrap_or_default()
}

fn children(pid: u32) -> Vec<u32> {
    read(format!("/proc/{pid}/task/{pid}/children"))
        .split_whitespace()
        .filter_map(|p| p.parse().ok())
        .collect()
}

/// Every thread of `pid` in seccomp filter mode with no new privileges: the thread count.
fn all_filtered(pid: u32, what: &str) -> usize {
    let mut n = 0;
    for task in std::fs::read_dir(format!("/proc/{pid}/task")).unwrap() {
        let status = read(format!("{}/status", task.unwrap().path().display()));
        if status.is_empty() {
            continue;
        }
        n += 1;
        assert_eq!(
            (field(&status, "Seccomp:"), field(&status, "NoNewPrivs:")),
            ("2".to_string(), "1".to_string()),
            "{what} {pid}"
        );
    }
    n
}

/// The `/proc/net/unix` lines of `pid`'s sockets.
fn sockets(pid: u32) -> Vec<String> {
    let unix = read(format!("/proc/{pid}/net/unix"));
    std::fs::read_dir(format!("/proc/{pid}/fd"))
        .map(|d| {
            d.filter_map(|fd| std::fs::read_link(fd.ok()?.path()).ok())
                .filter_map(|t| {
                    let inode = t
                        .to_str()?
                        .strip_prefix("socket:[")?
                        .strip_suffix(']')?
                        .to_string();
                    Some(
                        unix.lines()
                            .find(|l| l.split_whitespace().nth(6) == Some(inode.as_str()))
                            .map(str::to_string)
                            .unwrap_or_else(|| format!("socket:[{inode}] (not a unix socket)")),
                    )
                })
                .collect()
        })
        .unwrap_or_default()
}

#[test]
#[ignore = "a real SP1 Groth16 proof on a GPU"]
fn a_confined_worker_and_server_prove() {
    let home = std::env::var("ZKMINER_GPU_TEST_HOME").expect("ZKMINER_GPU_TEST_HOME");
    let dir = tempfile::tempdir().unwrap();
    let elf_path = dir.path().join("fibonacci.elf");
    let out = Command::new(WORKER)
        .args(["--export-guest", "fibonacci"])
        .arg(&elf_path)
        .env("HOME", &home)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let hex = String::from_utf8(out.stdout).unwrap();
    let hex = hex.trim().trim_start_matches("0x");
    let vkey: [u8; 32] = (0..64)
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect::<Vec<u8>>()
        .try_into()
        .unwrap();
    let elf = std::fs::read(&elf_path).unwrap();

    let mut child = Command::new(WORKER)
        .env("HOME", &home)
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
        log: log.clone(),
    };
    match w.answer(&WorkerCommand::Hello {
        protocol_version: PROTOCOL_VERSION,
    }) {
        WorkerResponse::HelloAck { .. } => {}
        other => panic!("{other:?}"),
    }
    match w.answer(&WorkerCommand::Warmup { request_id: 1 }) {
        WorkerResponse::WarmupDone { summary, .. } => eprintln!("WARMUP {summary}"),
        other => panic!("{other:?}"),
    }
    let n = 300u32;
    let started = Instant::now();
    let (journal, seal) = match w.answer(&WorkerCommand::Prove {
        request_id: 2,
        elf: elf.clone(),
        input_data: n.to_le_bytes().to_vec(),
        po2: None,
        program_id: Some(vkey),
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
        other => panic!(
            "{other:?}\n{}",
            log.lock().unwrap_or_else(|p| p.into_inner()).clone()
        ),
    };
    let (mut a, mut b) = (0u64, 1u64);
    for _ in 0..n {
        let c = a.wrapping_add(b);
        a = b;
        b = c;
    }
    assert_eq!(journal, a.to_le_bytes(), "fib({n})");
    assert!(!seal.is_empty());
    eprintln!("SEAL selector {:02x?}", &seal[..4.min(seal.len())]);

    // The worker: confined, keeping only its server connection (and the inert listeners).
    let threads = all_filtered(pid, "worker");
    eprintln!("WORKER {pid}: {threads} threads filtered");
    for s in sockets(pid) {
        eprintln!("WORKER SOCKET {s}");
    }
    let report = log
        .lock()
        .unwrap()
        .lines()
        .find(|l| l.contains("worker confined:"))
        .map(str::to_string)
        .expect("a confinement report");
    eprintln!("REPORT {report}");
    assert!(
        report.contains("keeps connections to its own children"),
        "{report}"
    );
    assert!(report.contains("filesystem restricted"), "{report}");
    // The shim (the worker's child) and the server (the shim's child).
    let shim = children(pid)
        .into_iter()
        .find(|c| read(format!("/proc/{c}/comm")).starts_with("zkminer-confine"))
        .expect("the shim, a child of the worker");
    let server = children(shim)
        .into_iter()
        .find(|c| read(format!("/proc/{c}/comm")).starts_with("sp1-gpu-server"))
        .expect("the server, a child of the shim");
    let threads = all_filtered(server, "server");
    eprintln!("SERVER {server} (parent {shim}): {threads} threads filtered");
    for s in sockets(server) {
        eprintln!("SERVER SOCKET {s}");
    }
    let shim_status = read(format!("/proc/{shim}/status"));
    eprintln!(
        "SUPERVISOR {shim}: Seccomp {}, NoNewPrivs {}",
        field(&shim_status, "Seccomp:"),
        field(&shim_status, "NoNewPrivs:")
    );
    assert_eq!(
        read(format!("/proc/{server}/fd/0")),
        "",
        "stdin is /dev/null"
    );
    assert_eq!(
        std::fs::read_link(format!("/proc/{server}/fd/0")).unwrap(),
        std::path::Path::new("/dev/null")
    );
    // Shut down: the server goes with the worker.
    drop(w);
    let deadline = Instant::now() + std::time::Duration::from_secs(30);
    while std::path::Path::new(&format!("/proc/{server}")).exists() && Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    let gone = read(format!("/proc/{server}/stat"));
    assert!(
        gone.is_empty()
            || gone
                .rsplit_once(')')
                .is_some_and(|(_, r)| r.trim_start().starts_with('Z')),
        "the server outlived its worker"
    );
}
