//! The real runner binary under the real sandbox: spawned through the sandbox launcher
//! (`prepare_command`: job cgroup, fd map, NO_NEW_PRIVS, PDEATHSIG), restricting itself first
//! (`restrict_self(BuilderRunner)`), running the SDK's example builder against a broker on its fd 5.
//! While the runner waits on its first fetch, the test checks from outside that it is restricted.
//!
//! Needs a delegated cgroup:
//!
//! ```text
//! systemd-run --user --scope -q -p Delegate=yes -- \
//!     env ZKMINER_SANDBOX_TESTS_REQUIRED=1 cargo test -p zkminer-witness-builder --test sandboxed
//! ```
//!
//! Elsewhere it prints `SKIPPED` to stderr and returns (or fails, with ZKMINER_SANDBOX_TESTS_REQUIRED).

use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsFd, FromRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::OnceLock;
use std::thread;

use zkminer_witness::context::{build_context, encode_context, DescriptorFields};
use zkminer_witness::envelope::{encode_evm_rpc_config, Capability, Limits, CLASS_EVM_RPC_V1, METHOD_SET_STATE_READ};
use zkminer_witness::ipc::{self, decode_summary_pipe, exit, BuilderSummary, FetchStatus};
use zkminer_witness::WitnessJobV1;
use zkminer_witness_sandbox::{
    delegated_root, landlock_abi, prepare_command, Cgroup, CgroupSpec, SandboxError, MIN_LANDLOCK_ABI,
};

const RUNNER: &str = env!("CARGO_BIN_EXE_zkminer-witness-builder");
const HASH: &str = "0x9b83c12c69edb74f6c8dd5d052765c1adf940e320bd1291696e6fa07829eee71";

fn skip(test: &str, reason: &str) {
    if std::env::var_os("ZKMINER_SANDBOX_TESTS_REQUIRED").is_some() {
        panic!("{test}: sandbox unavailable: {reason}");
    }
    let _ = writeln!(std::io::stderr(), "SKIPPED {test}: {reason}");
}

fn delegated(test: &str) -> Option<PathBuf> {
    let abi = landlock_abi();
    if abi < MIN_LANDLOCK_ABI {
        skip(test, &format!("Landlock ABI {abi} < {MIN_LANDLOCK_ABI}"));
        return None;
    }
    match delegated_root() {
        Ok(root) => Some(root),
        Err(e @ SandboxError::NotDelegated { .. }) => {
            skip(test, &e.to_string());
            None
        }
        Err(e) => panic!("{test}: delegated_root: {e}"),
    }
}

fn example_wasm() -> &'static [u8] {
    static WASM: OnceLock<Vec<u8>> = OnceLock::new();
    WASM.get_or_init(|| {
        let sdk = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../sdk").canonicalize().unwrap();
        let target = Path::new(env!("CARGO_TARGET_TMPDIR")).join("sdk-target-sandboxed");
        let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
        let out = Command::new(cargo)
            .current_dir(&sdk)
            .args(["build", "--locked", "--release", "--target", "wasm32-unknown-unknown", "-p", "latest-block"])
            .arg("--target-dir")
            .arg(&target)
            .env_remove("RUSTFLAGS")
            .env_remove("CARGO_ENCODED_RUSTFLAGS")
            .env_remove("CARGO_BUILD_RUSTFLAGS")
            .env_remove("CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUSTFLAGS")
            .env_remove("CARGO_BUILD_TARGET")
            .env_remove("CARGO_TARGET_DIR")
            .output()
            .expect("cargo runs");
        assert!(out.status.success(), "building the example failed:\n{}", String::from_utf8_lossy(&out.stderr));
        std::fs::read(target.join("wasm32-unknown-unknown/release/latest_block.wasm")).unwrap()
    })
}

fn context() -> Vec<u8> {
    let job = WitnessJobV1 {
        builderType: 1,
        builderId: [0x11; 32].into(),
        builderURIs: vec![],
        builderParams: vec![1, 2, 3].into(),
        sources: vec![Capability {
            class: CLASS_EVM_RPC_V1,
            config: encode_evm_rpc_config(8453, true, METHOD_SET_STATE_READ, 300).into(),
        }],
        limits: Limits {
            maxFetches: 100,
            maxFetchBytes: 1 << 24,
            maxRequestBytes: 65_536,
            maxResponseBytes: 1 << 22,
            maxBuilderFuel: 1 << 32,
            maxBuilderMemoryBytes: 1 << 28,
            maxBuilderSeconds: 60,
            maxWitnessBytes: 1 << 24,
            maxGuestCycles: 1 << 28,
        },
    };
    let d = DescriptorFields {
        program_id: [1; 32].into(),
        proof_system_id: [2; 32].into(),
        expected_journal_hash: [3; 32].into(),
        journal_fields: [4; 32].into(),
    };
    encode_context(&build_context(743_111, [5; 20].into(), &d, &job))
}

fn block_response() -> Vec<u8> {
    format!(r#"{{"jsonrpc":"2.0","id":1,"result":{{"hash":"{HASH}","number":"0x1406f40"}}}}"#).into_bytes()
}

/// A sealed memfd holding `bytes`.
fn sealed_memfd(name: &str, bytes: &[u8]) -> OwnedFd {
    let cname = std::ffi::CString::new(name).unwrap();
    // SAFETY: plain syscalls on a fd we own.
    unsafe {
        let fd = libc::memfd_create(cname.as_ptr(), libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING);
        assert!(fd >= 0, "memfd_create: {}", std::io::Error::last_os_error());
        let mut f = File::from_raw_fd(fd);
        f.write_all(bytes).unwrap();
        let seals = libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE;
        assert_eq!(libc::fcntl(fd, libc::F_ADD_SEALS, seals), 0);
        OwnedFd::from(f)
    }
}

fn pipe() -> (File, OwnedFd) {
    let mut fds = [0; 2];
    // SAFETY: pipe2 fills two fds we then own.
    assert_eq!(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
    unsafe { (File::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) }
}

fn status_field(pid: u32, field: &str) -> String {
    let s = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap();
    s.lines()
        .find_map(|l| l.strip_prefix(field).map(|v| v.trim().to_string()))
        .unwrap_or_else(|| panic!("{field} missing from /proc/{pid}/status"))
}

struct Run {
    code: Option<i32>,
    w: Vec<u8>,
    /// The started marker came first on the summary pipe.
    started: bool,
    summary: Option<BuilderSummary>,
    log: String,
    requests: Vec<(u32, Vec<u8>)>,
}

/// Spawns the runner in a fresh job cgroup; `on_fetch(pid, cgroup)` runs while the runner is blocked
/// on each fetch, then `reply` answers it.
fn run_sandboxed(
    root: &Path,
    pids_max: u32,
    module: &[u8],
    argv: &[&str],
    reply: Vec<u8>,
    on_fetch: impl Fn(u32, &Cgroup) + Send + 'static,
) -> Run {
    static N: AtomicU32 = AtomicU32::new(0);
    let name = format!("runner-test-{}-{}", std::process::id(), N.fetch_add(1, Ordering::SeqCst));
    let cg = Cgroup::create(
        root,
        &CgroupSpec { name, memory_max: 512 << 20, pids_max, cpu_max: None, cpu_weight: 10 },
    )
    .unwrap();
    let (mut w_read, w_write) = pipe();
    let (mut sum_read, sum_write) = pipe();
    let (mut log_read, log_write) = pipe();
    let (broker_child, mut broker) = UnixStream::pair().unwrap();
    let module_fd = sealed_memfd("module", module);
    let context_fd = sealed_memfd("context", &context());

    let mut cmd = Command::new(RUNNER);
    cmd.args(argv).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::from(log_write));
    prepare_command(
        &mut cmd,
        &cg,
        &[
            (w_write.as_fd(), 3),
            (sum_write.as_fd(), 4),
            (broker_child.as_fd(), 5),
            (module_fd.as_fd(), 6),
            (context_fd.as_fd(), 7),
        ],
    )
    .unwrap();
    let mut child = cmd.spawn().unwrap();
    // The child holds its own copies now: close ours so the readers see EOF.
    drop((w_write, sum_write, broker_child, module_fd, context_fd));
    drop(cmd);

    let pid = child.id();
    let cg_path = cg.path().to_path_buf();
    let broker_thread = thread::spawn(move || {
        let cg = cg;
        let mut requests = Vec::new();
        while let Ok((kind, payload)) = ipc::read_frame(&mut broker, ipc::fetch_frame_max(65_536)) {
            assert_eq!(kind, ipc::KIND_FETCH);
            let (cap, req) = ipc::decode_fetch(&payload).unwrap();
            requests.push((cap, req.to_vec()));
            on_fetch(pid, &cg);
            ipc::write_frame(&mut broker, ipc::KIND_FETCH_RESULT, &ipc::encode_fetch_result(FetchStatus::Ok, &reply))
                .unwrap();
        }
        (requests, cg)
    });
    let w_thread = thread::spawn(move || {
        let mut w = Vec::new();
        w_read.read_to_end(&mut w).unwrap();
        w
    });
    let mut summary = Vec::new();
    sum_read.read_to_end(&mut summary).unwrap();
    let mut log = Vec::new();
    log_read.read_to_end(&mut log).unwrap();
    let status = child.wait().unwrap();
    let w = w_thread.join().unwrap();
    let (requests, cg) = broker_thread.join().unwrap();
    assert!(cg_path.exists());
    cg.remove().unwrap();
    let (started, summary) = decode_summary_pipe(&summary);
    Run { code: status.code(), w, started, summary, log: String::from_utf8_lossy(&log).into_owned(), requests }
}

const ARGV: &[&str] = &[
    "--fuel", "100000000", "--memory-bytes", "67108864", "--wall-ms", "20000", "--max-witness-bytes", "1048576",
    "--max-request-bytes", "65536", "--max-response-bytes", "4194304",
];

#[test]
fn the_example_runs_under_the_sandbox() {
    let Some(root) = delegated("the_example_runs_under_the_sandbox") else { return };
    let r = run_sandboxed(&root, 8, example_wasm(), ARGV, block_response(), |pid, cg| {
        // The runner is blocked in `fetch`: check it from outside.
        assert_eq!(status_field(pid, "Seccomp:"), "2", "seccomp filter mode");
        assert_eq!(status_field(pid, "NoNewPrivs:"), "1");
        let procs = std::fs::read_to_string(cg.path().join("cgroup.procs")).unwrap();
        assert!(procs.lines().any(|l| l.trim() == pid.to_string()), "runner {pid} not in its job cgroup: {procs}");
        // Non-dumpable: even its own uid cannot read its environment.
        assert!(std::fs::read(format!("/proc/{pid}/environ")).is_err(), "environ readable");
        let threads = status_field(pid, "Threads:").parse::<u32>().unwrap();
        assert!(threads <= 4, "{threads} threads");
    });
    assert_eq!(r.code, Some(exit::OK), "log: {}", r.log);
    assert!(r.started, "the marker precedes the summary");
    let s = r.summary.expect("a summary");
    assert_eq!(s.exit_code, exit::OK);
    assert_eq!(s.fetches, 1);
    let mut want = 0x1406f40u64.to_be_bytes().to_vec();
    want.extend_from_slice(&hex::decode(&HASH[2..]).unwrap());
    assert_eq!(r.w, want);
    assert_eq!(r.requests.len(), 1);
    assert_eq!(r.requests[0].0, 0);
    assert!(r.log.contains("latest-block: block 21000000"), "{}", r.log);
}

#[test]
fn exit_classes_propagate_from_the_sandbox() {
    let Some(root) = delegated("exit_classes_propagate_from_the_sandbox") else { return };
    // An infinite loop: out of fuel, reported as FUEL in both the exit status and the summary.
    let spin = wat::parse_str(
        r#"(module (memory (export "memory") 1) (func (export "run") (result i32) (loop $l (br $l)) (i32.const 0)))"#,
    )
    .unwrap();
    let argv: Vec<&str> =
        ARGV.iter().map(|a| if *a == "100000000" { "1000000" } else { *a }).collect();
    let r = run_sandboxed(&root, 8, &spin, &argv, vec![], |_, _| {});
    assert_eq!(r.code, Some(exit::FUEL), "log: {}", r.log);
    assert!(r.started);
    assert_eq!(r.summary.unwrap().exit_code, exit::FUEL);
    assert!(r.w.is_empty());
    // An import outside the ABI: UNKNOWN_IMPORT, before anything runs.
    let bad = wat::parse_str(
        r#"(module (import "wasi_snapshot_preview1" "fd_write" (func (param i32 i32 i32 i32) (result i32)))
                   (memory (export "memory") 1) (func (export "run") (result i32) (i32.const 0)))"#,
    )
    .unwrap();
    let r = run_sandboxed(&root, 8, &bad, ARGV, vec![], |_, _| {});
    assert_eq!(r.code, Some(exit::UNKNOWN_IMPORT), "log: {}", r.log);
    assert!(!r.started, "refused before instantiation");
    assert_eq!(r.summary.unwrap().exit_code, exit::UNKNOWN_IMPORT);
}

#[test]
fn fewer_than_three_pids_fail_before_compiling() {
    let Some(root) = delegated("fewer_than_three_pids_fail_before_compiling") else { return };
    // Accepted by the pre-pass but slow to compile (~1.8 s in a release build, far longer in this
    // debug one): 4,096 locals read inside 58 nested loops.
    let reads: String = (0..4_096).map(|i| format!("(drop (local.get {i})) ")).collect();
    let slow = wat::parse_str(format!(
        r#"(module (memory (export "memory") 1) (func (export "run") (result i32) (i32.const 0))
            (func (local {}) {} {reads} {}))"#,
        "i32 ".repeat(4_096),
        "(loop ".repeat(58),
        ")".repeat(58)
    ))
    .unwrap();
    // pids.max = 2: the main and execution threads fit; the epoch watchdog, started before
    // compilation, does not.
    let t = std::time::Instant::now();
    let r = run_sandboxed(&root, 2, &slow, ARGV, vec![], |_, _| {});
    assert_eq!(r.code, Some(exit::INTERNAL), "log: {}", r.log);
    assert!(r.log.contains("[runner] internal: watchdog thread"), "{}", r.log);
    assert!(!r.started);
    assert_eq!(r.summary.unwrap().exit_code, exit::INTERNAL);
    assert!(t.elapsed() < std::time::Duration::from_secs(3), "failed only after compiling: {:?}", t.elapsed());
    // Three are enough.
    let quick =
        wat::parse_str(r#"(module (memory (export "memory") 1) (func (export "run") (result i32) (i32.const 0)))"#)
            .unwrap();
    let r = run_sandboxed(&root, 3, &quick, ARGV, vec![], |_, _| {});
    assert_eq!(r.code, Some(exit::OK), "log: {}", r.log);
    assert!(r.started);
}
