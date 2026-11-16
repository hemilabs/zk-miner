//! The binary's contract: argv and fds (plan §10.1).
//!
//! ```text
//! zkminer-witness-builder --fuel N --memory-bytes N --wall-ms N \
//!     --max-witness-bytes N --max-request-bytes N --max-response-bytes N
//! ```
//!
//! Every flag is required, appears once, and takes a plain decimal number; nothing else is accepted
//! (no secrets travel on argv). `--wall-ms` counts from process start.
//!
//! | fd | direction | content |
//! |---|---|---|
//! | 2 | write | diagnostics ([`RunnerIo::log`]) |
//! | 3 | write | `W`, raw, in pieces of ≤ `W_CHUNK_BYTES` |
//! | 4 | write | the 48-byte [`BuilderSummary`], written once, last |
//! | 5 | read/write | the job's `SOCK_STREAM` socket to the broker (`ipc` fetch frames) |
//! | 6 | read | the module bytes (a sealed memfd; read with `pread` from offset 0) |
//! | 7 | read | `abi.encode(BuilderContextV1)` (a sealed memfd; same) |
//!
//! The process exit status is the summary's exit code.

use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::FileExt;
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

use zkminer_witness::abi;
use zkminer_witness::ipc::{exit, BuilderSummary};

use crate::prepass::MAX_MODULE_BYTES;
use crate::{run, RunnerConfig, RunnerIo};

/// Largest context the runner reads (a real one is a few KiB: the envelope body is ≤ 28,480 bytes).
pub const MAX_CONTEXT_BYTES: usize = 1 << 20;

/// The limits passed on argv.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Args {
    pub fuel: u64,
    pub memory_bytes: u64,
    pub wall_ms: u64,
    pub max_witness_bytes: u64,
    pub max_request_bytes: u32,
    pub max_response_bytes: u32,
}

impl Args {
    /// The run's configuration, with the deadline `wall_ms` after `process_start`.
    pub fn config(&self, process_start: Instant) -> RunnerConfig {
        RunnerConfig {
            fuel: self.fuel,
            memory_bytes: self.memory_bytes,
            deadline: process_start + Duration::from_millis(self.wall_ms),
            max_witness_bytes: self.max_witness_bytes,
            max_request_bytes: self.max_request_bytes,
            max_response_bytes: self.max_response_bytes,
        }
    }
}

const FLAGS: [&str; 6] =
    ["--fuel", "--memory-bytes", "--wall-ms", "--max-witness-bytes", "--max-request-bytes", "--max-response-bytes"];

/// Parses argv (without `argv[0]`).
pub fn parse_args(args: &[String]) -> Result<Args, String> {
    let mut values: [Option<u64>; 6] = [None; 6];
    let mut it = args.iter();
    while let Some(flag) = it.next() {
        let i = FLAGS.iter().position(|f| f == flag).ok_or_else(|| format!("unknown argument {flag:?}"))?;
        let v = it.next().ok_or_else(|| format!("{flag} needs a value"))?;
        if v.is_empty() || !v.bytes().all(|b| b.is_ascii_digit()) {
            return Err(format!("{flag}: not a decimal number"));
        }
        let n: u64 = v.parse().map_err(|_| format!("{flag}: out of range"))?;
        if values[i].replace(n).is_some() {
            return Err(format!("{flag} given twice"));
        }
    }
    let get = |i: usize| values[i].ok_or_else(|| format!("{} is required", FLAGS[i]));
    let u32_of =
        |i: usize| -> Result<u32, String> { u32::try_from(get(i)?).map_err(|_| format!("{}: out of range", FLAGS[i])) };
    Ok(Args {
        fuel: get(0)?,
        memory_bytes: get(1)?,
        wall_ms: get(2)?,
        max_witness_bytes: get(3)?,
        max_request_bytes: u32_of(4)?,
        max_response_bytes: u32_of(5)?,
    })
}

/// The runner's fds, owned. The binary builds this from the fixed numbers in [`abi::fd`]; tests
/// pass any fds.
#[derive(Debug)]
pub struct RunnerFds {
    pub witness: OwnedFd,
    pub summary: OwnedFd,
    pub broker: OwnedFd,
    pub module: OwnedFd,
    pub context: OwnedFd,
    pub log: OwnedFd,
}

impl RunnerFds {
    /// Takes ownership of fds 2–7.
    ///
    /// # Safety
    /// Fds 2–7 must be open and not owned by anything else in the process (true at the top of the
    /// binary's `main`, where the miner placed them).
    pub unsafe fn from_standard_fds() -> Self {
        // SAFETY: per this function's contract.
        unsafe {
            Self {
                witness: OwnedFd::from_raw_fd(abi::fd::W),
                summary: OwnedFd::from_raw_fd(abi::fd::SUMMARY),
                broker: OwnedFd::from_raw_fd(abi::fd::BROKER),
                module: OwnedFd::from_raw_fd(abi::fd::MODULE),
                context: OwnedFd::from_raw_fd(abi::fd::CONTEXT),
                log: OwnedFd::from_raw_fd(abi::fd::LOG),
            }
        }
    }
}

/// Reads a whole fd with `pread` from offset 0 (the miner may hand a memfd whose offset is at its
/// end), falling back to `read` for a pipe. `None` if it holds more than `max` bytes.
fn read_input(fd: OwnedFd, max: usize) -> io::Result<Option<Vec<u8>>> {
    let file = File::from(fd);
    let mut buf = Vec::new();
    let mut chunk = vec![0u8; 64 << 10];
    let mut offset = 0u64;
    loop {
        let n = match file.read_at(&mut chunk, offset) {
            Ok(n) => n,
            Err(e) if e.raw_os_error() == Some(libc::ESPIPE) && offset == 0 => {
                let mut rest = Vec::new();
                (&file).take(max as u64 + 1).read_to_end(&mut rest)?;
                return Ok((rest.len() <= max).then_some(rest));
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        if n == 0 {
            return Ok(Some(buf));
        }
        if buf.len() + n > max {
            return Ok(None);
        }
        buf.extend_from_slice(&chunk[..n]);
        offset += n as u64;
    }
}

/// Everything the binary does after `restrict_self`: reads the inputs, runs the builder, writes the
/// summary to the summary fd, and returns the exit code. `process_start` is when `main` began; the
/// wall clock counts from it.
pub fn main_with_fds(args: &[String], fds: RunnerFds, process_start: Instant) -> i32 {
    let RunnerFds { witness, summary: summary_fd, broker, module, context, log } = fds;
    let mut log = File::from(log);
    let summary = (|| {
        let internal = BuilderSummary { exit_code: exit::INTERNAL, ..Default::default() };
        let args = match parse_args(args) {
            Ok(a) => a,
            Err(e) => {
                let _ = writeln!(log, "[runner] {e}");
                return internal;
            }
        };
        let module = match read_input(module, MAX_MODULE_BYTES) {
            Ok(Some(m)) => m,
            Ok(None) => {
                let _ = writeln!(log, "[runner] invalid module: more than {MAX_MODULE_BYTES} bytes");
                return BuilderSummary { exit_code: exit::INVALID_MODULE, ..Default::default() };
            }
            Err(e) => {
                let _ = writeln!(log, "[runner] module fd: {e}");
                return internal;
            }
        };
        let context = match read_input(context, MAX_CONTEXT_BYTES) {
            Ok(Some(c)) => c,
            Ok(None) => {
                let _ = writeln!(log, "[runner] context of more than {MAX_CONTEXT_BYTES} bytes");
                return internal;
            }
            Err(e) => {
                let _ = writeln!(log, "[runner] context fd: {e}");
                return internal;
            }
        };
        let run_log = match log.try_clone() {
            Ok(l) => l,
            Err(e) => {
                let _ = writeln!(log, "[runner] log fd: {e}");
                return internal;
            }
        };
        let io = RunnerIo { witness: File::from(witness), broker: UnixStream::from(broker), log: run_log };
        run(&module, &context, &args.config(process_start), io)
    })();
    let mut out = File::from(summary_fd);
    if let Err(e) = out.write_all(&summary.encode()) {
        let _ = writeln!(log, "[runner] summary fd {}: {e}", out.as_raw_fd());
    }
    summary.exit_code
}
