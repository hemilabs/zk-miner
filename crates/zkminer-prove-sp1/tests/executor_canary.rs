//! A measuring worker whose executor cannot share memory with its runner once confined gives SP1 up
//! before it runs any requester's guest. With `memfd_create` refused (as a strict seccomp profile
//! refuses it) and no `/dev/shm` (the confinement gives none, which leaves the executor's fallback
//! nowhere to go), the first `Execute` meets the executor canary, and the worker exits
//! `WORKER_EXIT_DECLINED` without an answer. Unrefused, the same request is measured.
//!
//! No GPU, no server.
//!
//! ```text
//! cargo test --release -p zkminer-prove-sp1 --test executor_canary
//! ```
//!
//! In release: a debug build of SP1's CPU executor takes minutes to build its prover.
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use std::io::BufReader;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use zkminer_prover_protocol::types::{SP1_MEASURE_ONLY_ENV, WORKER_EXIT_DECLINED};
use zkminer_prover_protocol::{
    read_message, write_message, FrameError, WorkerCommand, WorkerResponse, PROTOCOL_VERSION,
};

const WORKER: &str = env!("CARGO_BIN_EXE_zkminer-prove-sp1");
const FIBONACCI: &[u8] = include_bytes!(env!("SP1_ELF_fibonacci-sp1-guest"));

/// Makes `memfd_create` fail with EPERM in this process from now on, and in what it executes.
/// Async-signal-safe: no allocation, for `pre_exec`.
fn deny_memfd_create() -> std::io::Result<()> {
    // A classic BPF program: load the syscall number; memfd_create returns EPERM, the rest runs.
    const LD_W_ABS: u16 = 0x20;
    const JEQ_K: u16 = 0x15;
    const RET_K: u16 = 0x06;
    const RET_ERRNO: u32 = 0x0005_0000;
    const RET_ALLOW: u32 = 0x7fff_0000;
    let mut filter = [
        libc::sock_filter {
            code: LD_W_ABS,
            jt: 0,
            jf: 0,
            k: 0,
        },
        libc::sock_filter {
            code: JEQ_K,
            jt: 0,
            jf: 1,
            k: libc::SYS_memfd_create as u32,
        },
        libc::sock_filter {
            code: RET_K,
            jt: 0,
            jf: 0,
            k: RET_ERRNO | libc::EPERM as u32,
        },
        libc::sock_filter {
            code: RET_K,
            jt: 0,
            jf: 0,
            k: RET_ALLOW,
        },
    ];
    let prog = libc::sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_mut_ptr(),
    };
    // SAFETY: prctl with valid arguments; the filter outlives the call, which copies it.
    unsafe {
        if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0
            || libc::prctl(libc::PR_SET_SECCOMP, libc::SECCOMP_MODE_FILTER, &prog) != 0
        {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

/// What a measuring worker does with one `Execute` of fibonacci(300): its answer, or `None` and its
/// exit status if it exited without one.
fn measure(memfd_refused: bool) -> (Option<WorkerResponse>, Option<std::process::ExitStatus>) {
    let home = tempfile::tempdir().unwrap();
    let mut command = Command::new(WORKER);
    command
        .env(SP1_MEASURE_ONLY_ENV, "1")
        .env("HOME", home.path())
        .env("RUST_LOG", "info")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    if memfd_refused {
        // SAFETY: `deny_memfd_create` only makes system calls.
        unsafe { command.pre_exec(deny_memfd_create) };
    }
    let mut child = command.spawn().unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    write_message(
        &mut stdin,
        &WorkerCommand::Hello {
            protocol_version: PROTOCOL_VERSION,
        },
    )
    .unwrap();
    match read_message(&mut stdout).unwrap() {
        WorkerResponse::HelloAck { .. } => {}
        other => panic!("the measuring worker did not take the handshake: {other:?}"),
    }
    write_message(
        &mut stdin,
        &WorkerCommand::Execute {
            request_id: 1,
            elf: FIBONACCI.to_vec(),
            input_data: 300u32.to_le_bytes().to_vec(),
            program_id: None,
            po2: None,
        },
    )
    .unwrap();
    let answer: Result<WorkerResponse, _> = read_message(&mut stdout);
    let answer = match answer {
        Ok(answer) => Some(answer),
        Err(FrameError::UnexpectedEof) => None,
        Err(e) => panic!("{e}"),
    };
    let deadline = Instant::now() + Duration::from_secs(60);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break Some(status);
        }
        if answer.is_some() || Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            break None;
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    (answer, status)
}

#[test]
fn a_worker_whose_executor_cannot_share_memory_declines_before_any_guest() {
    if FIBONACCI.is_empty() {
        eprintln!("skipping: the guests are stubbed (SP1_SKIP_PROGRAM_BUILD)");
        return;
    }
    let (answer, status) = measure(true);
    assert!(
        answer.is_none(),
        "a worker whose canary failed answered: {answer:?}"
    );
    let status = status.expect("the worker exits");
    assert_eq!(
        status.code(),
        Some(WORKER_EXIT_DECLINED),
        "it exits declined ({status:?}, signal {:?})",
        status.signal()
    );

    // The control: the same worker and request with memfd_create allowed is measured.
    match measure(false).0 {
        Some(WorkerResponse::ExecuteResult { cycles, .. }) => assert!(cycles > 0),
        other => panic!("an unrefused worker did not measure: {other:?}"),
    }
}
