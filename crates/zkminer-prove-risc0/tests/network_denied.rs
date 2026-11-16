//! The CPU worker has the network until it runs a requester's guest, and never after: its first
//! `Execute` installs the network filter (`zkminer_witness_sandbox::netdeny`) on every thread, with no
//! network socket left open, and a `Warmup` after it refuses to download rather than try.
//!
//! `cargo test -p zkminer-prove-risc0 --features cpu --test network_denied`. CPU only: the guest is
//! executed, never proven, and nothing is downloaded.
#![cfg(all(feature = "cpu", target_os = "linux"))]

use std::collections::HashSet;
use std::io::{BufReader, Read};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::{Arc, Mutex};

use zkminer_prover_protocol::{
    read_message, sys_rand, write_message, WorkerCommand, WorkerResponse, PROTOCOL_VERSION,
};

const WORKER: &str = env!("CARGO_BIN_EXE_zkminer-prove-risc0-cpu");

/// A worker over its pipes, with its stderr collected.
struct Worker {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    log: Arc<Mutex<String>>,
    _home: tempfile::TempDir,
}

impl Worker {
    fn start() -> Worker {
        let home = tempfile::tempdir().unwrap();
        let mut cmd = Command::new(WORKER);
        cmd.env_clear()
            // A key of the test's own, so nothing reads or creates ~/.zkminer.
            .env(
                sys_rand::SYS_RAND_KEY_ENV,
                sys_rand::encode_key(&[0x5a; 32]),
            )
            .env("HOME", home.path())
            // An empty rzup home: no risc0-groth16 component, so a warm-up would have to download it.
            .env("RISC0_HOME", home.path().join("risc0"))
            .env("RUST_LOG", "info")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if let Some(path) = std::env::var_os("PATH") {
            cmd.env("PATH", path);
        }
        let mut child = cmd.spawn().unwrap();
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
                sink.lock()
                    .unwrap()
                    .push_str(&String::from_utf8_lossy(&buf[..n]));
            }
        });
        let mut w = Worker {
            child,
            stdin,
            stdout,
            log,
            _home: home,
        };
        w.send(&WorkerCommand::Hello {
            protocol_version: PROTOCOL_VERSION,
        });
        match w.recv() {
            WorkerResponse::HelloAck { .. } => {}
            other => panic!("{other:?}"),
        }
        w
    }

    fn send(&mut self, cmd: &WorkerCommand) {
        write_message(&mut self.stdin, cmd).unwrap();
    }

    fn recv(&mut self) -> WorkerResponse {
        read_message(&mut self.stdout).unwrap_or_else(|e| panic!("{e}; log:\n{}", self.log()))
    }

    fn log(&self) -> String {
        self.log.lock().unwrap().clone()
    }

    fn pid(&self) -> u32 {
        self.child.id()
    }

    fn execute(&mut self, request_id: u64) -> WorkerResponse {
        let (elf, program_id) = fibonacci();
        self.send(&WorkerCommand::Execute {
            request_id,
            elf: elf.clone(),
            input_data: 10u32.to_le_bytes().to_vec(),
            program_id: Some(*program_id),
            po2: Some(20),
        });
        self.recv()
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn fibonacci() -> &'static (Vec<u8>, [u8; 32]) {
    static GUEST: std::sync::OnceLock<(Vec<u8>, [u8; 32])> = std::sync::OnceLock::new();
    GUEST.get_or_init(|| {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fibonacci.elf");
        let out = Command::new(WORKER)
            .args(["--export-guest", "fibonacci"])
            .arg(&path)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let printed = String::from_utf8(out.stdout).unwrap();
        let hex = printed.trim().trim_start_matches("0x");
        let id: Vec<u8> = (0..64)
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect();
        (std::fs::read(&path).unwrap(), id.try_into().unwrap())
    })
}

/// `(tid, Seccomp, NoNewPrivs)` of every thread of `pid`, from `/proc/<pid>/task/*/status`.
fn thread_modes(pid: u32) -> Vec<(String, String, String)> {
    let mut out = Vec::new();
    for task in std::fs::read_dir(format!("/proc/{pid}/task")).unwrap() {
        let task = task.unwrap();
        let Ok(status) = std::fs::read_to_string(task.path().join("status")) else {
            continue; // exited meanwhile
        };
        let field = |name: &str| {
            status
                .lines()
                .find_map(|l| l.strip_prefix(name))
                .map(|v| v.trim().to_string())
                .unwrap_or_default()
        };
        out.push((
            task.file_name().to_string_lossy().into_owned(),
            field("Seccomp:"),
            field("NoNewPrivs:"),
        ));
    }
    out
}

/// The inodes of `pid`'s open sockets that are network sockets: those of its `/proc/<pid>/fd`
/// links (`socket:[inode]`) that its network namespace lists as TCP, UDP, raw, ICMP or packet
/// sockets.
fn network_socket_inodes(pid: u32) -> Vec<u64> {
    let mut held = HashSet::new();
    for fd in std::fs::read_dir(format!("/proc/{pid}/fd")).unwrap() {
        let Ok(target) = std::fs::read_link(fd.unwrap().path()) else {
            continue;
        };
        if let Some(inode) = target
            .to_str()
            .and_then(|t| t.strip_prefix("socket:["))
            .and_then(|t| t.strip_suffix(']'))
            .and_then(|t| t.parse::<u64>().ok())
        {
            held.insert(inode);
        }
    }
    let mut network = Vec::new();
    for table in [
        "tcp", "tcp6", "udp", "udp6", "udplite", "udplite6", "raw", "raw6", "icmp", "icmp6",
    ] {
        let Ok(text) = std::fs::read_to_string(format!("/proc/{pid}/net/{table}")) else {
            continue; // not in this kernel
        };
        // `sl local rem st tx_queue:rx_queue tr:tm->when retrnsmt uid timeout inode ...`
        for line in text.lines().skip(1) {
            if let Some(inode) = line
                .split_whitespace()
                .nth(9)
                .and_then(|i| i.parse::<u64>().ok())
            {
                if held.contains(&inode) {
                    network.push(inode);
                }
            }
        }
    }
    if let Ok(text) = std::fs::read_to_string(format!("/proc/{pid}/net/packet")) {
        // `sk RefCnt Type Proto Iface R Rmem User Inode`
        for line in text.lines().skip(1) {
            if let Some(inode) = line
                .split_whitespace()
                .nth(8)
                .and_then(|i| i.parse::<u64>().ok())
            {
                if held.contains(&inode) {
                    network.push(inode);
                }
            }
        }
    }
    network
}

#[test]
fn the_first_execute_takes_the_network_away_for_good() {
    let mut worker = Worker::start();
    let pid = worker.pid();

    // The handshake and a capabilities query run no guest: the network is still there (a warm-up
    // would need it).
    worker.send(&WorkerCommand::Capabilities);
    assert!(matches!(
        worker.recv(),
        WorkerResponse::CapabilitiesReport { .. }
    ));
    for (tid, seccomp, _) in thread_modes(pid) {
        assert_eq!(seccomp, "0", "thread {tid} before any guest");
    }

    match worker.execute(1) {
        WorkerResponse::ExecuteResult {
            cycles, journal, ..
        } => {
            assert!(cycles > 0);
            assert_eq!(journal.as_deref(), Some(&55u64.to_le_bytes()[..]));
        }
        other => panic!("{other:?}\n{}", worker.log()),
    }
    // Every thread, the ones the executor started included, is in filter mode with no new
    // privileges. The worker checked for itself that `socket(AF_INET)` and `socket(AF_INET6)` fail
    // with EPERM before it ran the guest, or it would have answered an error.
    let modes = thread_modes(pid);
    assert!(!modes.is_empty());
    for (tid, seccomp, nnp) in &modes {
        assert_eq!(
            (seccomp.as_str(), nnp.as_str()),
            ("2", "1"),
            "thread {tid} after the first execute"
        );
    }
    assert_eq!(
        network_socket_inodes(pid),
        Vec::<u64>::new(),
        "no network socket is open in the worker"
    );

    // The warm-up's download is refused in words, not attempted.
    worker.send(&WorkerCommand::Warmup { request_id: 2 });
    let message = loop {
        match worker.recv() {
            WorkerResponse::SetupProgress { status, .. } => {
                assert!(!status.contains("Downloading"), "{status}")
            }
            WorkerResponse::Error { message, .. } => break message,
            other => panic!("{other:?}\n{}", worker.log()),
        }
    };
    assert!(
        message.contains("cannot download it") && message.contains("no network"),
        "{message}"
    );

    // Later guests run as before; the filter is installed once.
    assert!(matches!(
        worker.execute(3),
        WorkerResponse::ExecuteResult { .. }
    ));
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap();
    if let Some(n) = status
        .lines()
        .find_map(|l| l.strip_prefix("Seccomp_filters:"))
    {
        let n: u32 = n.trim().parse().unwrap();
        assert!(n <= 2, "{n} filters: one install, not one per command");
    }
    assert!(!worker.log().contains("could not deny"), "{}", worker.log());
}

/// A program-id derivation parses the requester's ELF: the same filter goes on first.
#[test]
fn a_program_id_derivation_takes_the_network_away_too() {
    let mut worker = Worker::start();
    let pid = worker.pid();
    worker.send(&WorkerCommand::ProgramId {
        request_id: 1,
        elf: fibonacci().0.clone(),
    });
    match worker.recv() {
        WorkerResponse::ProgramIdResult { program_id, .. } => {
            assert_eq!(program_id, fibonacci().1)
        }
        other => panic!("{other:?}\n{}", worker.log()),
    }
    for (tid, seccomp, nnp) in thread_modes(pid) {
        assert_eq!((seccomp.as_str(), nnp.as_str()), ("2", "1"), "thread {tid}");
    }
}
