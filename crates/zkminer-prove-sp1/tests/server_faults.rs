//! What the real worker does when its `sp1-gpu-server` misbehaves, with a stand-in for the server.
//!
//! No GPU. This binary is also the server: the worker starts it from `~/.sp1/bin`, under a server's
//! name, and `FAKE_SERVER_MODE` makes it speak the server's wire format and fail in a chosen way.
//!
//!   cargo test --release -p zkminer-prove-sp1 --test server_faults [-- <substring of a scenario>]
//!
//! In release: the benchmark scenarios execute every guest, and a debug build of the executor takes
//! minutes over that.
//!
//! The worker's reaper kills ANY orphaned `sp1-gpu-server` on the machine, which is what it is for, so
//! do not run this while a server you care about has lost its worker.
//!
//! `-- --gpu` instead runs the one scenario a stand-in cannot, on a real server and card: forcing key
//! evictions, then checking that real proofs carry their own input's journal. `HOME` must hold the
//! server and Groth16 artifacts, or set `SP1_GROTH16_CIRCUIT_PATH`.

use std::io::{Read, Write};
use std::os::unix::net::UnixListener;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::time::{Duration, Instant};

use zkminer_prover_protocol::types::{ErrorKind, WORKER_EXIT_SERVER_LOST};
use zkminer_prover_protocol::{
    read_message, write_message, WorkerCommand, WorkerResponse, PROTOCOL_VERSION,
};

const WORKER: &str = env!("CARGO_BIN_EXE_zkminer-prove-sp1");
/// A card number nothing else uses, so the sockets here cannot be anyone's.
const DEVICE: u32 = 6;
const CUDA_SERVER: &str = "sp1-gpu-server";
const HIP_SERVER: &str = "sp1-gpu-server-hip";

// ---- The stand-in server ----

/// The server's `Response`, by position: bincode encodes an enum as its index.
const RESPONSE_OK: u32 = 0;
const RESPONSE_INTERNAL_ERROR: u32 = 4;

fn fake_server(mode: &str) {
    if std::env::args().any(|a| a == "--version") {
        println!("{}", sp1_primitives::SP1_CRATE_VERSION);
        return;
    }
    let name = std::env::var("SP1_GPU_SERVER_NAME").unwrap_or_default();
    let base = if name.is_empty() { "sp1-cuda" } else { &name };
    let device = std::env::var("CUDA_VISIBLE_DEVICES").expect("the SDK sets this");
    let path = format!("/tmp/{base}-{device}.sock");
    // About as long as a real one takes, which is what lets a client beat it to the socket.
    std::thread::sleep(Duration::from_millis(450));
    let _ = std::fs::remove_file(&path);
    let listener = UnixListener::bind(&path).expect("bind");
    if let Ok(log) = std::env::var("FAKE_SERVER_LOG") {
        std::fs::write(log, "reached\n").unwrap_or_default();
    }
    for stream in listener.incoming() {
        let mut stream = stream.expect("accept");
        loop {
            let mut len = [0u8; 4];
            if stream.read_exact(&mut len).is_err() {
                break;
            }
            let mut request = vec![0u8; u32::from_le_bytes(len) as usize];
            if stream.read_exact(&mut request).is_err() {
                break;
            }
            let mut reply = Vec::new();
            match mode.split_once(':').unwrap_or((mode, "")) {
                ("err", text) => {
                    reply.extend(RESPONSE_INTERNAL_ERROR.to_le_bytes());
                    reply.extend((text.len() as u64).to_le_bytes());
                    reply.extend(text.as_bytes());
                }
                ("ok", _) => reply.extend(RESPONSE_OK.to_le_bytes()),
                ("close", _) => break,
                ("die", _) => unsafe {
                    libc::kill(libc::getpid(), libc::SIGKILL);
                },
                (other, _) => panic!("unknown mode {other}"),
            }
            let _ = stream.write_all(&(reply.len() as u32).to_le_bytes());
            let _ = stream.write_all(&reply);
        }
    }
}

// ---- The rig ----

/// A directory, HOME and server for one scenario.
struct Rig {
    dir: PathBuf,
    env: Vec<(String, String)>,
}

impl Rig {
    fn new(name: &str, server: &str, mode: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "zkminer-server-faults-{}-{name}",
            std::process::id()
        ));
        let bin = dir.join(".sp1/bin");
        std::fs::create_dir_all(&bin).unwrap();
        // A link keeps this quick: what runs is named by its path, and that is what its `comm` is.
        std::os::unix::fs::symlink(std::env::current_exe().unwrap(), bin.join(server)).unwrap();
        let mut env = vec![
            (
                "PATH".to_string(),
                std::env::var("PATH").unwrap_or_default(),
            ),
            ("HOME".to_string(), dir.display().to_string()),
            ("RUST_LOG".to_string(), "info".to_string()),
            ("ZKMINER_CUDA_DEVICE_ID".to_string(), DEVICE.to_string()),
            ("ZKMINER_SP1_SERVER_INSTALL".to_string(), "0".to_string()),
            ("FAKE_SERVER_MODE".to_string(), mode.to_string()),
            (
                "FAKE_SERVER_LOG".to_string(),
                dir.join("reached").display().to_string(),
            ),
        ];
        if server != CUDA_SERVER {
            env.push(("SP1_GPU_SERVER_NAME".to_string(), server.to_string()));
        }
        Self { dir, env }
    }

    fn log(&self) -> String {
        std::fs::read_to_string(self.dir.join("worker.log")).unwrap_or_default()
    }

    fn command(&self) -> Command {
        let mut command = Command::new(WORKER);
        command
            .env_clear()
            .envs(self.env.iter().map(|(k, v)| (k, v)));
        command.current_dir(&self.dir);
        let log = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.dir.join("worker.log"))
            .unwrap();
        command.stderr(log);
        command
    }

    fn start(&self) -> Worker {
        let mut child = self
            .command()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .process_group(0)
            .spawn()
            .unwrap();
        let stdin = child.stdin.take().unwrap();
        let stdout = child.stdout.take().unwrap();
        let mut worker = Worker {
            child,
            stdin,
            stdout: Some(stdout),
        };
        worker.send(&WorkerCommand::Hello {
            protocol_version: PROTOCOL_VERSION,
        });
        match worker.answer() {
            Some(WorkerResponse::HelloAck { .. }) => worker,
            other => panic!("no HelloAck: {other:?}"),
        }
    }

    fn benchmark_by_hand(&self) -> i32 {
        let status = self
            .command()
            .arg("--benchmark")
            .stdout(Stdio::null())
            .status()
            .unwrap();
        status.code().unwrap_or(-1)
    }

    fn no_panic(&self) -> Result<(), String> {
        match self.log().lines().find(|l| l.contains("panicked")) {
            Some(line) => Err(format!("the worker panicked: {line}")),
            None => Ok(()),
        }
    }

    fn server_was_reached(&self) -> bool {
        self.dir.join("reached").exists()
    }
}

impl Drop for Rig {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
        // A killed server leaves its socket, as a real one does.
        for socket in [
            format!("/tmp/sp1-cuda-{DEVICE}.sock"),
            format!("/tmp/{HIP_SERVER}-{DEVICE}.sock"),
            format!("/tmp/{HIP_SERVER}-3.sock"),
        ] {
            let _ = std::fs::remove_file(socket);
        }
    }
}

struct Worker {
    child: Child,
    stdin: ChildStdin,
    stdout: Option<ChildStdout>,
}

impl Worker {
    fn send(&mut self, command: &WorkerCommand) {
        let _ = write_message(&mut self.stdin, command);
    }

    /// The next answer that is not progress. `None` is EOF.
    fn answer(&mut self) -> Option<WorkerResponse> {
        loop {
            match read_message(self.stdout.as_mut().unwrap()) {
                Ok(WorkerResponse::Progress { .. }) => continue,
                Ok(answer) => return Some(answer),
                Err(_) => return None,
            }
        }
    }

    fn prove(
        &mut self,
        elf: &[u8],
        input: u32,
        program_id: Option<[u8; 32]>,
    ) -> Option<WorkerResponse> {
        self.send(&WorkerCommand::Prove {
            request_id: 1,
            elf: elf.to_vec(),
            input_data: input.to_le_bytes().to_vec(),
            po2: None,
            program_id,
        });
        self.answer()
    }

    fn benchmark(&mut self) -> Option<WorkerResponse> {
        self.send(&WorkerCommand::Benchmark);
        self.answer()
    }

    fn exit_code(&mut self) -> i32 {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                return status.code().unwrap_or(-1);
            }
            assert!(Instant::now() < deadline, "the worker did not exit");
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    fn shutdown(&mut self) -> i32 {
        self.send(&WorkerCommand::Shutdown);
        self.exit_code()
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        unsafe { libc::kill(-(self.child.id() as i32), libc::SIGKILL) };
        let _ = self.child.wait();
    }
}

/// Stand-in servers still running, found by the variable only they have.
fn fake_servers() -> Vec<i32> {
    let mut found = Vec::new();
    for entry in std::fs::read_dir("/proc").unwrap().flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|s| s.parse::<i32>().ok())
        else {
            continue;
        };
        let environ = std::fs::read(format!("/proc/{pid}/environ")).unwrap_or_default();
        let comm = std::fs::read_to_string(format!("/proc/{pid}/comm")).unwrap_or_default();
        if comm.starts_with("sp1-gpu-server")
            && environ.windows(16).any(|w| w == b"FAKE_SERVER_MODE")
        {
            found.push(pid);
        }
    }
    found
}

/// None left, allowing for one that is on its way out.
fn no_server_left() -> Result<(), String> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let left = fake_servers();
        if left.is_empty() {
            return Ok(());
        }
        if Instant::now() > deadline {
            return Err(format!("left running: {left:?}"));
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn expect(ok: bool, what: impl std::fmt::Display) -> Result<(), String> {
    if ok {
        Ok(())
    } else {
        Err(what.to_string())
    }
}

/// A process of `gb` touched gigabytes named as a server, with the environment the SDK gives a real
/// one, listening at `socket`, whose parent is gone. Returns its pid once it is ready.
fn orphan(dir: &Path, server: &str, device: u32, socket: &str, gb: usize) -> i32 {
    let ready = dir.join(format!("orphan-{device}.ready"));
    let link = dir.join(server);
    std::os::unix::fs::symlink(std::env::current_exe().unwrap(), &link).unwrap();
    // Started in the background by a shell that then exits, which leaves it an orphan.
    let mut script = Command::new("sh");
    script
        .arg("-c")
        .arg("\"$0\" &")
        .arg(&link)
        .env("FAKE_ORPHAN_SOCKET", socket)
        .env("FAKE_ORPHAN_GB", gb.to_string())
        .env("FAKE_ORPHAN_READY", &ready)
        .env("CUDA_VISIBLE_DEVICES", device.to_string())
        .env("FAKE_SERVER_MODE", "orphan");
    if server != CUDA_SERVER {
        script.env("SP1_GPU_SERVER_NAME", server);
    }
    script
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        if let Ok(text) = std::fs::read_to_string(&ready) {
            if let Ok(pid) = text.trim().parse() {
                return pid;
            }
        }
        assert!(Instant::now() < deadline, "the orphan never came up");
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// `orphan`'s body, in the process it started.
fn be_orphan() {
    let socket = std::env::var("FAKE_ORPHAN_SOCKET").unwrap();
    let gb: usize = std::env::var("FAKE_ORPHAN_GB").unwrap().parse().unwrap();
    let held = vec![1u8; gb << 30];
    let _ = std::fs::remove_file(&socket);
    let listener = UnixListener::bind(&socket).unwrap();
    std::fs::write(
        std::env::var("FAKE_ORPHAN_READY").unwrap(),
        std::process::id().to_string(),
    )
    .unwrap();
    // Accepting, as a dying server's socket goes on doing: a client that gets here is lost.
    for stream in listener.incoming() {
        std::mem::forget(stream);
    }
    drop(held);
}

// ---- The scenarios ----

const FORGED: [&str; 3] = [
    "CudaClientError: Failed to read the response: Custom { kind: UnexpectedEof }",
    "CudaClientError: Failed to write the request: Os { code: 32 }",
    "CudaClientError: The server returned an unexpected response: \"Ok\"",
];

fn prove_error_keeps_the_worker(elf: &[u8]) -> Result<(), String> {
    let rig = Rig::new("prove-error", CUDA_SERVER, "err:boom");
    let mut worker = rig.start();
    for _ in 0..2 {
        match worker.prove(elf, 10, None) {
            Some(WorkerResponse::Error {
                kind: ErrorKind::ProofFailed,
                message,
                ..
            }) if message.contains("boom") => {}
            other => return Err(format!("answered {other:?}")),
        }
    }
    let code = worker.shutdown();
    expect(code == 0, format!("exit {code}"))?;
    rig.no_panic()?;
    no_server_left()
}

/// A guest's text can reach the server's errors, and must not be able to end a worker.
fn forged_text_keeps_the_worker(elf: &[u8]) -> Result<(), String> {
    for (i, text) in FORGED.iter().enumerate() {
        let rig = Rig::new(&format!("forged-{i}"), CUDA_SERVER, &format!("err:{text}"));
        let mut worker = rig.start();
        match worker.prove(elf, 10, None) {
            Some(WorkerResponse::Error {
                kind: ErrorKind::ProofFailed,
                ..
            }) => {}
            other => return Err(format!("{text}: answered {other:?}")),
        }
        expect(
            worker.child.try_wait().unwrap().is_none(),
            format!("{text}: the worker exited"),
        )?;
    }
    Ok(())
}

fn a_lost_server_ends_the_worker(elf: &[u8]) -> Result<(), String> {
    for mode in ["close", "die", "ok"] {
        let rig = Rig::new(&format!("lost-{mode}"), CUDA_SERVER, mode);
        let mut worker = rig.start();
        let answer = worker.prove(elf, 10, None);
        expect(
            answer.is_none(),
            format!("{mode}: answered {answer:?} instead of exiting"),
        )?;
        let code = worker.exit_code();
        expect(
            code == WORKER_EXIT_SERVER_LOST,
            format!("{mode}: exit {code}"),
        )?;
        rig.no_panic()?;
        expect(
            rig.log().contains("lost the connection to sp1-gpu-server"),
            format!("{mode}: no reason logged"),
        )?;
        // Closing the connection leaves the server alive, and the worker must end it.
        no_server_left().map_err(|e| format!("{mode}: {e}"))?;
    }
    Ok(())
}

fn an_undelivered_answer_does_not_panic(elf: &[u8]) -> Result<(), String> {
    let rig = Rig::new("host-gone", CUDA_SERVER, "err:boom");
    let mut worker = rig.start();
    worker.prove(elf, 10, None);
    worker.send(&WorkerCommand::Prove {
        request_id: 2,
        elf: elf.to_vec(),
        input_data: 10u32.to_le_bytes().to_vec(),
        po2: None,
        program_id: None,
    });
    // The miner gone: this worker's next write fails, and `?` leaves its loop.
    drop(worker.stdout.take());
    let code = worker.exit_code();
    expect(code == 1, format!("exit {code}"))?;
    rig.no_panic()?;
    no_server_left()
}

fn an_ipc_benchmark_with_no_rows_is_an_error() -> Result<(), String> {
    let rig = Rig::new("ipc-bench", CUDA_SERVER, "err:boom");
    let mut worker = rig.start();
    match worker.benchmark() {
        Some(WorkerResponse::Error {
            kind: ErrorKind::Internal,
            message,
            ..
        }) if message.contains("no SP1 benchmark completed") && message.contains("boom") => {}
        other => return Err(format!("answered {other:?}")),
    }
    let code = worker.shutdown();
    expect(code == 0, format!("exit {code}"))?;
    rig.no_panic()?;
    no_server_left()
}

fn an_ipc_benchmark_that_loses_its_server_answers_and_exits() -> Result<(), String> {
    let rig = Rig::new("ipc-bench-lost", CUDA_SERVER, "close");
    let mut worker = rig.start();
    match worker.benchmark() {
        Some(WorkerResponse::Error { message, .. }) if message.contains("lost the connection") => {}
        other => return Err(format!("answered {other:?}")),
    }
    let code = worker.exit_code();
    expect(code == WORKER_EXIT_SERVER_LOST, format!("exit {code}"))?;
    rig.no_panic()?;
    no_server_left()
}

/// Where the panic this file exists for was: `--benchmark` dropping its prover outside a runtime.
fn benchmark_by_hand_reports_and_cleans_up() -> Result<(), String> {
    for (mode, want) in [
        ("err:boom", 1),
        ("close", WORKER_EXIT_SERVER_LOST),
        ("die", WORKER_EXIT_SERVER_LOST),
    ] {
        let rig = Rig::new(
            &format!("by-hand-{}", mode.replace(':', "-")),
            CUDA_SERVER,
            mode,
        );
        let code = rig.benchmark_by_hand();
        expect(code == want, format!("{mode}: exit {code}, wanted {want}"))?;
        rig.no_panic()?;
        expect(
            rig.log().contains("FAILED"),
            format!("{mode}: nothing said what failed"),
        )?;
        no_server_left().map_err(|e| format!("{mode}: {e}"))?;
    }
    Ok(())
}

/// The race: an orphan's socket goes on accepting while it frees its memory, so without the wait the
/// worker's client gets there before the new server has bound, and never reconnects.
fn an_orphan_is_waited_for(elf: &[u8]) -> Result<(), String> {
    for server in [CUDA_SERVER, HIP_SERVER] {
        let rig = Rig::new(&format!("orphan-{server}"), server, "err:boom");
        let base = if server == CUDA_SERVER {
            "sp1-cuda"
        } else {
            server
        };
        let socket = format!("/tmp/{base}-{DEVICE}.sock");
        orphan(&rig.dir, server, DEVICE, &socket, 8);
        let started = Instant::now();
        let mut worker = rig.start();
        let handshake = started.elapsed();
        match worker.prove(elf, 10, None) {
            Some(WorkerResponse::Error { message, .. }) if message.contains("boom") => {}
            other => return Err(format!("{server}: answered {other:?}")),
        }
        expect(
            rig.server_was_reached(),
            format!("{server}: the new server was never reached"),
        )?;
        expect(
            handshake < Duration::from_secs(5),
            format!("{server}: the handshake took {handshake:?}"),
        )?;
        rig.no_panic()?;
    }
    Ok(())
}

/// The reaper removes an orphan's socket whichever vendor's build it was, and only that.
fn only_an_orphans_socket_is_removed() -> Result<(), String> {
    let rig = Rig::new("sockets", CUDA_SERVER, "err:boom");
    let theirs = format!("/tmp/{HIP_SERVER}-3.sock");
    orphan(&rig.dir, HIP_SERVER, 3, &theirs, 0);
    expect(Path::new(&theirs).exists(), "the orphan has no socket")?;
    let bystander = format!("/tmp/{HIP_SERVER}-4.sock");
    std::fs::write(&bystander, "").map_err(|e| e.to_string())?;
    let worker = rig.start();
    let removed = !Path::new(&theirs).exists();
    let spared = Path::new(&bystander).exists();
    drop(worker);
    let _ = std::fs::remove_file(&bystander);
    expect(removed, "the orphan's socket is still there")?;
    expect(spared, "another card's socket was removed")
}

// ---- On a real server ----

/// Many evictions, cheaply: a job whose programId matches nothing runs setup, evicts the cached key,
/// and is refused before proving. Real proofs after that must still carry their own input's journal.
fn gpu_evictions() -> Result<(), String> {
    let dir =
        std::env::temp_dir().join(format!("zkminer-server-faults-{}-gpu", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let fibonacci = export_guest("fibonacci", &dir);
    let other = export_guest("bigint-mul", &dir);
    let mut command = Command::new(WORKER);
    command
        .env("ZKMINER_SP1_PK_CACHE_MAX", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .process_group(0);
    let mut child = command.spawn().unwrap();
    let stdin = child.stdin.take().unwrap();
    let stdout = child.stdout.take().unwrap();
    let mut worker = Worker {
        child,
        stdin,
        stdout: Some(stdout),
    };
    worker.send(&WorkerCommand::Hello {
        protocol_version: PROTOCOL_VERSION,
    });
    worker.answer();
    for i in 0..40 {
        let elf = if i % 2 == 0 { &other } else { &fibonacci };
        match worker.prove(elf, 1, Some([0x11; 32])) {
            Some(WorkerResponse::Error {
                kind: ErrorKind::ProgramMismatch,
                ..
            }) => {}
            other => return Err(format!("decoy {i}: answered {other:?}")),
        }
    }
    for n in [1000u32, 2000, 3000] {
        worker.send(&WorkerCommand::Execute {
            request_id: 9,
            elf: fibonacci.clone(),
            input_data: n.to_le_bytes().to_vec(),
            program_id: None,
            po2: None,
        });
        let Some(WorkerResponse::ExecuteResult {
            journal: Some(want),
            ..
        }) = worker.answer()
        else {
            return Err("no execution result".to_string());
        };
        match worker.prove(&fibonacci, n, None) {
            Some(WorkerResponse::ProofResult { journal, .. }) if journal == want => {}
            Some(WorkerResponse::ProofResult { .. }) => {
                return Err(format!("fib({n}): the journal of another input"));
            }
            other => return Err(format!("fib({n}): answered {other:?}")),
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

fn export_guest(name: &str, dir: &Path) -> Vec<u8> {
    let path = dir.join(format!("{name}.elf"));
    let status = Command::new(WORKER)
        .arg("--export-guest")
        .arg(name)
        .arg(&path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(status.success(), "--export-guest {name}");
    std::fs::read(&path).unwrap()
}

fn main() {
    if let Ok(mode) = std::env::var("FAKE_SERVER_MODE") {
        if mode == "orphan" {
            return be_orphan();
        }
        return fake_server(&mode);
    }
    let args: Vec<String> = std::env::args()
        .skip(1)
        .filter(|a| !a.starts_with("--") || a == "--gpu")
        .collect();
    if args.iter().any(|a| a == "--gpu") {
        match gpu_evictions() {
            Ok(()) => println!("ok: every eviction answered, every journal its own"),
            Err(e) => {
                println!("FAILED: {e}");
                std::process::exit(1);
            }
        }
        return;
    }
    let dir = std::env::temp_dir().join(format!("zkminer-server-faults-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let elf = export_guest("fibonacci", &dir);
    let _ = std::fs::remove_dir_all(&dir);
    type Run<'a> = Box<dyn Fn() -> Result<(), String> + 'a>;
    let scenarios: Vec<(&str, Run)> = vec![
        (
            "an ordinary server error keeps the worker",
            Box::new(|| prove_error_keeps_the_worker(&elf)),
        ),
        (
            "a guest's text cannot end the worker",
            Box::new(|| forged_text_keeps_the_worker(&elf)),
        ),
        (
            "a lost server ends the worker, with no panic and no server left",
            Box::new(|| a_lost_server_ends_the_worker(&elf)),
        ),
        (
            "an answer that cannot be delivered does not panic",
            Box::new(|| an_undelivered_answer_does_not_panic(&elf)),
        ),
        (
            "an IPC benchmark with no rows is an error",
            Box::new(an_ipc_benchmark_with_no_rows_is_an_error),
        ),
        (
            "an IPC benchmark that loses its server answers, then exits",
            Box::new(an_ipc_benchmark_that_loses_its_server_answers_and_exits),
        ),
        (
            "--benchmark reports, cleans up, and does not panic",
            Box::new(benchmark_by_hand_reports_and_cleans_up),
        ),
        (
            "an orphan is waited for, outside the handshake",
            Box::new(|| an_orphan_is_waited_for(&elf)),
        ),
        (
            "only an orphan's socket is removed",
            Box::new(only_an_orphans_socket_is_removed),
        ),
    ];
    let mut failed = 0;
    for (name, run) in &scenarios {
        if !args.is_empty() && !args.iter().any(|a| name.contains(a.as_str())) {
            continue;
        }
        let started = Instant::now();
        match run() {
            Ok(()) => println!("test {name} ... ok ({:.1?})", started.elapsed()),
            Err(e) => {
                failed += 1;
                println!("test {name} ... FAILED: {e}");
            }
        }
    }
    if failed > 0 {
        println!("\n{failed} failed");
        std::process::exit(1);
    }
}
