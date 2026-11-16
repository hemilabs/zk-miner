//! The binary's argv/fd contract: `main_with_fds` in-process with explicit fds, and in a child
//! process with real pipes, memfds and a socket placed at fds 2–7.
//!
//! The child is this test binary re-executed on `child_entry` (the runner binary itself calls
//! `restrict_self` first, which this branch does not implement). Only this test binary reads the
//! variable that selects child mode; the runner binary has no such switch.

mod common;

use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::thread;
use std::time::Instant;

use common::*;
use zkminer_witness::ipc::{exit, BuilderSummary, FetchStatus, BUILDER_SUMMARY_BYTES};
use zkminer_witness_builder::{main_with_fds, parse_args, Args, RunnerFds};

const CHILD_ENV: &str = "ZKMINER_WITNESS_BUILDER_TEST_CHILD_ARGS";

fn args(s: &str) -> Vec<String> {
    s.split_whitespace().map(String::from).collect()
}

const GOOD_ARGS: &str = "--fuel 50000000 --memory-bytes 16777216 --wall-ms 20000 --max-witness-bytes 1048576 \
                         --max-request-bytes 1024 --max-response-bytes 1048576";

#[test]
fn parse_args_requires_every_flag_once_as_a_plain_number() {
    assert_eq!(
        parse_args(&args(GOOD_ARGS)).unwrap(),
        Args {
            fuel: 50_000_000,
            memory_bytes: 16 << 20,
            wall_ms: 20_000,
            max_witness_bytes: 1 << 20,
            max_request_bytes: 1024,
            max_response_bytes: 1 << 20
        }
    );
    // Order does not matter.
    let mut rev: Vec<String> = args(GOOD_ARGS).chunks(2).rev().flatten().cloned().collect();
    assert!(parse_args(&rev).is_ok());
    rev.truncate(10);
    assert!(parse_args(&rev).unwrap_err().contains("required"));
    for bad in [
        format!("{GOOD_ARGS} --fuel 1"),
        format!("{GOOD_ARGS} --extra 1"),
        format!("{GOOD_ARGS} --fuel"),
        GOOD_ARGS.replace("--fuel 50000000", "--fuel +5"),
        GOOD_ARGS.replace("--fuel 50000000", "--fuel -5"),
        GOOD_ARGS.replace("--fuel 50000000", "--fuel 0x10"),
        GOOD_ARGS.replace("--fuel 50000000", "--fuel 18446744073709551616"),
        GOOD_ARGS.replace("--max-request-bytes 1024", "--max-request-bytes 4294967296"),
        GOOD_ARGS.replace("--wall-ms 20000", "--wall-ms=20000"),
        format!("{GOOD_ARGS} positional"),
    ] {
        assert!(parse_args(&args(&bad)).is_err(), "{bad}");
    }
}

fn memfd(bytes: &[u8]) -> OwnedFd {
    // SAFETY: plain syscalls on fds this function owns.
    unsafe {
        let fd = libc::memfd_create(c"zkminer-test".as_ptr(), libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING);
        assert!(fd >= 0);
        let fd = OwnedFd::from_raw_fd(fd);
        File::from(fd.try_clone().unwrap()).write_all(bytes).unwrap();
        let seals = libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE;
        assert_eq!(libc::fcntl(fd.as_raw_fd(), libc::F_ADD_SEALS, seals), 0);
        fd
    }
}

/// A pipe whose read end is drained by a thread; returns (write end, join handle for the bytes).
fn drained_pipe() -> (OwnedFd, thread::JoinHandle<Vec<u8>>) {
    let (mut r, w) = std::io::pipe().unwrap();
    let h = thread::spawn(move || {
        let mut v = Vec::new();
        r.read_to_end(&mut v).unwrap();
        v
    });
    (OwnedFd::from(w), h)
}

/// Copies the context to W, logs, fetches once and copies the response to W.
fn echo_module() -> Vec<u8> {
    module(
        r#"(data (i32.const 0) "hi from the guest")
        (func (export "run") (result i32) (local $n i32)
          (local.set $n (call $input_read (i32.const 0) (i32.const 1024) (i32.const 4096)))
          (drop (call $witness_write (i32.const 1024) (local.get $n)))
          (call $log (i32.const 0) (i32.const 17))
          (drop (call $fetch (i32.const 0) (i32.const 0) (i32.const 2)))
          (local.set $n (call $response_read (i32.const 0) (i32.const 8192) (i32.const 4096)))
          (drop (call $witness_write (i32.const 8192) (local.get $n)))
          (i32.const 0))"#,
    )
}

struct Captured {
    code: i32,
    summary: Vec<u8>,
    w: Vec<u8>,
    log: Vec<u8>,
    requests: Vec<(u32, Vec<u8>)>,
}

/// Runs `main_with_fds` in this process with fresh fds.
fn in_process(argv: &str, module: OwnedFd, context: OwnedFd, replies: Vec<Reply>) -> Captured {
    let (w, w_out) = drained_pipe();
    let (summary, summary_out) = drained_pipe();
    let (log, log_out) = drained_pipe();
    let (broker, fake) = FakeBroker::spawn(replies);
    let fds = RunnerFds { witness: w, summary, broker: broker.into(), module, context, log };
    let code = main_with_fds(&args(argv), fds, Instant::now());
    Captured {
        code,
        summary: summary_out.join().unwrap(),
        w: w_out.join().unwrap(),
        log: log_out.join().unwrap(),
        requests: fake.finish(),
    }
}

#[test]
fn main_with_fds_in_process() {
    let c = in_process(
        GOOD_ARGS,
        memfd(&echo_module()),
        memfd(b"the context"),
        vec![Reply::Result(FetchStatus::Ok, b"the response".to_vec())],
    );
    assert_eq!(c.code, exit::OK);
    let s = BuilderSummary::decode(&c.summary).expect("a 48-byte summary");
    assert_eq!(s.exit_code, exit::OK);
    assert_eq!((s.fetches, s.fetch_bytes, s.witness_bytes), (1, 12, 23));
    assert_eq!(c.w, b"the contextthe response");
    assert_eq!(c.log, b"hi from the guest");
    assert_eq!(c.requests, vec![(0, b"hi".to_vec())]);
}

#[test]
fn main_with_fds_reads_pipes_too() {
    let pipe_with = |bytes: Vec<u8>| {
        let (r, mut w) = std::io::pipe().unwrap();
        thread::spawn(move || w.write_all(&bytes).unwrap());
        OwnedFd::from(r)
    };
    let c = in_process(
        GOOD_ARGS,
        pipe_with(echo_module()),
        pipe_with(b"ctx".to_vec()),
        vec![Reply::Result(FetchStatus::Ok, vec![])],
    );
    assert_eq!(c.code, exit::OK);
    assert_eq!(c.w, b"ctx");
}

#[test]
fn main_with_fds_writes_a_summary_for_bad_args_and_bad_modules() {
    let c = in_process("--fuel 1", memfd(&echo_module()), memfd(b""), vec![]);
    assert_eq!(c.code, exit::INTERNAL);
    assert_eq!(BuilderSummary::decode(&c.summary).unwrap().exit_code, exit::INTERNAL);
    assert!(String::from_utf8_lossy(&c.log).contains("is required"));

    let c = in_process(GOOD_ARGS, memfd(b"\0asm\x01\0\0\0\x05"), memfd(b""), vec![]);
    assert_eq!(c.code, exit::INVALID_MODULE);
    assert_eq!(c.summary.len(), BUILDER_SUMMARY_BYTES);

    let too_big = vec![0u8; zkminer_witness_builder::prepass::MAX_MODULE_BYTES + 1];
    let c = in_process(GOOD_ARGS, memfd(&too_big), memfd(b""), vec![]);
    assert_eq!(c.code, exit::INVALID_MODULE);
    assert!(String::from_utf8_lossy(&c.log).contains("more than"));
}

/// Child mode: when this test binary is re-executed with `CHILD_ENV` set, it acts as the runner
/// binary minus `restrict_self`. Otherwise this test does nothing.
#[test]
fn child_entry() {
    let Ok(argv) = std::env::var(CHILD_ENV) else { return };
    let start = Instant::now();
    // SAFETY: the parent placed fds 2–7 for this process.
    let fds = unsafe { RunnerFds::from_standard_fds() };
    std::process::exit(main_with_fds(&args(&argv), fds, start));
}

fn dup_high(fd: RawFd) -> OwnedFd {
    // SAFETY: duplicates an fd this process owns; the copy has CLOEXEC, so only the dup2'd targets
    // survive exec.
    unsafe {
        let d = libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 100);
        assert!(d >= 100);
        OwnedFd::from_raw_fd(d)
    }
}

#[test]
fn main_with_fds_in_a_child_with_fds_2_to_7() {
    let (w, w_out) = drained_pipe();
    let (summary, summary_out) = drained_pipe();
    let (log, log_out) = drained_pipe();
    let (broker, fake) = FakeBroker::spawn(vec![Reply::Result(FetchStatus::Ok, b"from the broker".to_vec())]);
    let module = memfd(&echo_module());
    let context = memfd(b"child context");
    // fd number in the child <- source fd here (moved high so no source sits on a target number).
    let plan: Vec<(RawFd, OwnedFd)> = vec![
        (2, dup_high(log.as_raw_fd())),
        (3, dup_high(w.as_raw_fd())),
        (4, dup_high(summary.as_raw_fd())),
        (5, dup_high(broker.as_raw_fd())),
        (6, dup_high(module.as_raw_fd())),
        (7, dup_high(context.as_raw_fd())),
    ];
    let pairs: Vec<(RawFd, RawFd)> = plan.iter().map(|(t, s)| (*t, s.as_raw_fd())).collect();
    let mut cmd = Command::new(std::env::current_exe().unwrap());
    cmd.args(["--exact", "child_entry", "--test-threads=1", "--nocapture"])
        .env(CHILD_ENV, GOOD_ARGS)
        .stdin(Stdio::null())
        .stdout(Stdio::null());
    // SAFETY: only dup2, which is async-signal-safe, between fork and exec.
    unsafe {
        cmd.pre_exec(move || {
            for &(target, source) in &pairs {
                if libc::dup2(source, target) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
    let mut child = cmd.spawn().unwrap();
    // Close the parent's copies, so the drains see EOF when the child exits.
    drop((plan, w, summary, log, broker, module, context));
    let status = child.wait().unwrap();

    let summary = BuilderSummary::decode(&summary_out.join().unwrap()).expect("a 48-byte summary on fd 4");
    assert_eq!(summary.exit_code, exit::OK);
    assert_eq!(status.code(), Some(exit::OK), "the exit status is the summary's exit code");
    assert_eq!(w_out.join().unwrap(), b"child contextfrom the broker");
    let log = log_out.join().unwrap();
    assert!(String::from_utf8_lossy(&log).contains("hi from the guest"), "{}", String::from_utf8_lossy(&log));
    assert_eq!(fake.finish(), vec![(0, b"hi".to_vec())]);
    assert_eq!((summary.fetches, summary.witness_bytes), (1, 28));
}

#[test]
fn a_child_exits_with_the_summary_code() {
    // A trapping module: exit status 12 (TRAP), with the same code in the summary.
    let (w, _w_out) = drained_pipe();
    let (summary, summary_out) = drained_pipe();
    let (log, _log_out) = drained_pipe();
    let (broker, fake) = FakeBroker::spawn(vec![]);
    let module = memfd(&module(r#"(func (export "run") (result i32) unreachable)"#));
    let context = memfd(b"");
    let plan: Vec<(RawFd, OwnedFd)> =
        [(2, &log), (3, &w), (4, &summary), (5, &broker.into()), (6, &module), (7, &context)]
            .into_iter()
            .map(|(t, s): (RawFd, &OwnedFd)| (t, dup_high(s.as_raw_fd())))
            .collect();
    let pairs: Vec<(RawFd, RawFd)> = plan.iter().map(|(t, s)| (*t, s.as_raw_fd())).collect();
    let mut cmd = Command::new(std::env::current_exe().unwrap());
    cmd.args(["--exact", "child_entry", "--test-threads=1"]).env(CHILD_ENV, GOOD_ARGS).stdout(Stdio::null());
    // SAFETY: only dup2 between fork and exec.
    unsafe {
        cmd.pre_exec(move || {
            for &(target, source) in &pairs {
                if libc::dup2(source, target) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
    let mut child = cmd.spawn().unwrap();
    drop((plan, w, summary, log, module, context));
    let status = child.wait().unwrap();
    assert_eq!(status.code(), Some(exit::TRAP));
    assert_eq!(BuilderSummary::decode(&summary_out.join().unwrap()).unwrap().exit_code, exit::TRAP);
    fake.finish();
}
