//! Store data, the resource limiter and the six ABI v1 host functions (plan §9.2).
//!
//! Every host function:
//! - charges [`FUEL_PER_HOST_CALL`] on entry;
//! - checks `len` against its per-call cap before touching guest memory (`fetch`: the request cap,
//!   a trap; `witness_write`: the bytes left under `maxWitnessBytes`, result 1; `log`: the bytes left
//!   in the per-job log budget, the rest dropped; `input_read`/`response_read`: the bytes available
//!   from `offset`);
//! - bounds-checks exactly the guest range it then copies, with checked `u32` arithmetic, and traps
//!   when it is out of bounds;
//! - charges [`FUEL_PER_BYTE`] for every byte it copies, before copying.
//!
//! Pointers, lengths and offsets are the guest's `i32`s reinterpreted as `u32` (wasm32 addresses).

use std::io::{self, Read, Write};
use std::ops::Range;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use wasmtime::{Caller, Extern, Linker, Memory, ResourceLimiter};
use zkminer_witness::{abi, ipc};

use crate::prepass::MAX_TABLE_ELEMENTS;
use crate::BrokerChannel;

/// Fuel charged per byte a host function copies between guest memory and the host (in either
/// direction). wasmtime meters one unit per wasm operator, so a guest-side copy loop costs at least
/// one unit per 8 bytes; one unit per byte keeps host copies from being a cheaper way to move data
/// than wasm itself, while a 32 MiB witness still costs only ~3.4e7 units.
pub const FUEL_PER_BYTE: u64 = 1;
/// Fuel charged on entry to every host function, for the call itself (a host call costs about as
/// much CPU as tens of wasm operators). Time blocked in `fetch` is not charged.
pub const FUEL_PER_HOST_CALL: u64 = 64;

/// Counters shared with the waiting thread, so a summary can be written even if the execution
/// thread is stuck past the deadline.
#[derive(Debug, Default)]
pub(crate) struct Progress {
    pub fetches: AtomicU32,
    pub fetch_bytes: AtomicU64,
    pub witness_bytes: AtomicU64,
    pub transient: AtomicBool,
}

/// A host-side reason to stop the guest. Returned from host functions as the `wasmtime::Error`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub(crate) enum Fault {
    #[error("out-of-bounds guest pointer")]
    OutOfBounds,
    #[error("request of {0} bytes is over the request cap")]
    RequestTooLarge(u32),
    #[error("out of fuel in a host function")]
    Fuel,
    #[error("wall clock expired during a fetch")]
    WallClock,
    #[error("module has no `memory` export")]
    NoMemory,
    #[error("runner: {0}")]
    Internal(String),
}

/// Records a denied or failed memory growth, so a later trap classifies as MEMORY.
#[derive(Debug)]
pub(crate) struct Limiter {
    pub memory_bytes: usize,
    pub memory_denied: bool,
}

impl ResourceLimiter for Limiter {
    fn memory_growing(&mut self, _current: usize, desired: usize, maximum: Option<usize>) -> wasmtime::Result<bool> {
        let allow = desired <= self.memory_bytes && maximum.is_none_or(|max| desired <= max);
        if !allow {
            self.memory_denied = true;
        }
        Ok(allow)
    }

    fn memory_grow_failed(&mut self, _error: wasmtime::Error) -> wasmtime::Result<()> {
        self.memory_denied = true;
        Ok(())
    }

    fn table_growing(&mut self, _current: usize, desired: usize, maximum: Option<usize>) -> wasmtime::Result<bool> {
        Ok(desired as u64 <= MAX_TABLE_ELEMENTS && maximum.is_none_or(|max| desired <= max))
    }

    fn instances(&self) -> usize {
        1
    }

    fn tables(&self) -> usize {
        1
    }

    fn memories(&self) -> usize {
        1
    }
}

/// The store's data.
pub(crate) struct HostState {
    pub limiter: Limiter,
    pub context: Vec<u8>,
    /// The response of the latest `fetch`; replaced by every fetch.
    pub response: Vec<u8>,
    pub witness: Box<dyn Write + Send>,
    pub broker: Box<dyn BrokerChannel>,
    pub log: Box<dyn Write + Send>,
    pub log_remaining: usize,
    pub witness_written: u64,
    pub witness_over_limit: bool,
    pub max_witness_bytes: u64,
    pub max_request_bytes: u32,
    pub max_response_bytes: u32,
    pub deadline: Instant,
    pub progress: Arc<Progress>,
}

fn fault(f: Fault) -> wasmtime::Error {
    wasmtime::Error::new(f)
}

fn charge(caller: &mut Caller<'_, HostState>, units: u64) -> wasmtime::Result<()> {
    let left = caller.get_fuel()?;
    if left < units {
        caller.set_fuel(0)?;
        return Err(fault(Fault::Fuel));
    }
    caller.set_fuel(left - units)
}

fn memory(caller: &mut Caller<'_, HostState>) -> wasmtime::Result<Memory> {
    match caller.get_export(abi::EXPORT_MEMORY) {
        Some(Extern::Memory(m)) => Ok(m),
        _ => Err(fault(Fault::NoMemory)),
    }
}

/// `[ptr, ptr + len)` if it lies inside a memory of `size` bytes.
fn guest_range(ptr: u32, len: u32, size: usize) -> Result<Range<usize>, wasmtime::Error> {
    let end = ptr.checked_add(len).ok_or_else(|| fault(Fault::OutOfBounds))?;
    if end as usize > size {
        return Err(fault(Fault::OutOfBounds));
    }
    Ok(ptr as usize..end as usize)
}

/// `input_read` / `response_read`: copies up to `len` bytes from `offset` of a host buffer; 0 when
/// `offset` is at or past its end (nothing is checked or touched then).
fn read_into_guest(
    caller: &mut Caller<'_, HostState>,
    which: fn(&HostState) -> &[u8],
    offset: u32,
    ptr: u32,
    len: u32,
) -> wasmtime::Result<i32> {
    charge(caller, FUEL_PER_HOST_CALL)?;
    let avail = which(caller.data()).len();
    let offset = offset as usize;
    if offset >= avail {
        return Ok(0);
    }
    // Never more than the buffer holds from `offset`, nor more than an i32 result can report.
    let n = (len as usize).min(avail - offset).min(i32::MAX as usize) as u32;
    let mem = memory(caller)?;
    let range = guest_range(ptr, n, mem.data_size(&*caller))?;
    charge(caller, u64::from(n) * FUEL_PER_BYTE)?;
    let (data, state) = mem.data_and_store_mut(&mut *caller);
    data[range].copy_from_slice(&which(state)[offset..offset + n as usize]);
    Ok(n as i32)
}

fn witness_write(caller: &mut Caller<'_, HostState>, ptr: u32, len: u32) -> wasmtime::Result<i32> {
    charge(caller, FUEL_PER_HOST_CALL)?;
    let state = caller.data_mut();
    // Checked before guest memory is touched. Once over, every later write is refused too.
    if state.witness_over_limit || u64::from(len) > state.max_witness_bytes - state.witness_written {
        state.witness_over_limit = true;
        return Ok(abi::WITNESS_WRITE_OVER_LIMIT);
    }
    let mem = memory(caller)?;
    let range = guest_range(ptr, len, mem.data_size(&*caller))?;
    charge(caller, u64::from(len) * FUEL_PER_BYTE)?;
    let (data, state) = mem.data_and_store_mut(&mut *caller);
    for chunk in data[range].chunks(abi::W_CHUNK_BYTES) {
        state.witness.write_all(chunk).map_err(|e| fault(Fault::Internal(format!("W sink: {e}"))))?;
    }
    state.witness_written += u64::from(len);
    state.progress.witness_bytes.store(state.witness_written, Ordering::Relaxed);
    Ok(abi::WITNESS_WRITE_OK)
}

fn log(caller: &mut Caller<'_, HostState>, ptr: u32, len: u32) -> wasmtime::Result<()> {
    charge(caller, FUEL_PER_HOST_CALL)?;
    let n = (len as usize).min(caller.data().log_remaining) as u32;
    if n == 0 {
        return Ok(()); // over the per-job budget: dropped without touching guest memory
    }
    let mem = memory(caller)?;
    let range = guest_range(ptr, n, mem.data_size(&*caller))?;
    charge(caller, u64::from(n) * FUEL_PER_BYTE)?;
    let (data, state) = mem.data_and_store_mut(&mut *caller);
    state.log_remaining -= n as usize;
    // Diagnostics only: a failing log sink does not fail the run.
    let _ = state.log.write_all(&data[range]);
    Ok(())
}

/// Reads and writes on the broker channel, each bounded by the time left until the deadline.
struct DeadlineIo<'a> {
    ch: &'a mut dyn BrokerChannel,
    deadline: Instant,
}

impl DeadlineIo<'_> {
    fn remaining(&self) -> io::Result<Duration> {
        let left = self.deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(io::ErrorKind::TimedOut.into());
        }
        Ok(left)
    }

    fn retry<T>(&mut self, mut op: impl FnMut(&mut dyn BrokerChannel, Duration) -> io::Result<T>) -> io::Result<T> {
        loop {
            let left = self.remaining()?;
            match op(&mut *self.ch, left) {
                // SO_RCVTIMEO/SO_SNDTIMEO can fire a little before our own clock says the deadline
                // has passed; only `remaining` decides that.
                Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) => continue,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                r => return r,
            }
        }
    }
}

impl Read for DeadlineIo<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.retry(|ch, left| {
            ch.set_read_timeout(Some(left))?;
            ch.read(buf)
        })
    }
}

impl Write for DeadlineIo<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.retry(|ch, left| {
            ch.set_write_timeout(Some(left))?;
            ch.write(buf)
        })
    }

    fn flush(&mut self) -> io::Result<()> {
        self.retry(|ch, _| ch.flush())
    }
}

fn io_fault(e: io::Error) -> wasmtime::Error {
    if e.kind() == io::ErrorKind::TimedOut {
        fault(Fault::WallClock)
    } else {
        fault(Fault::Internal(format!("broker channel: {e}")))
    }
}

fn fetch(caller: &mut Caller<'_, HostState>, cap: u32, req_ptr: u32, req_len: u32) -> wasmtime::Result<i64> {
    charge(caller, FUEL_PER_HOST_CALL)?;
    if req_len > caller.data().max_request_bytes {
        // Before guest memory is touched; the broker never sees it.
        return Err(fault(Fault::RequestTooLarge(req_len)));
    }
    let mem = memory(caller)?;
    let range = guest_range(req_ptr, req_len, mem.data_size(&*caller))?;
    charge(caller, u64::from(req_len) * FUEL_PER_BYTE)?;
    let (data, state) = mem.data_and_store_mut(&mut *caller);
    let frame = ipc::encode_fetch(cap, &data[range]);
    // A new fetch replaces the held response, whatever its outcome.
    state.response = Vec::new();
    let max_result = ipc::fetch_result_frame_max(state.max_response_bytes);
    let mut io = DeadlineIo { ch: &mut *state.broker, deadline: state.deadline };
    ipc::write_frame(&mut io, ipc::KIND_FETCH, &frame).map_err(io_fault)?;
    state.progress.fetches.fetch_add(1, Ordering::Relaxed);
    let (kind, mut payload) = match ipc::read_frame(&mut io, max_result) {
        Ok(f) => f,
        Err(ipc::FrameError::Io(e)) => return Err(io_fault(e)),
        Err(e) => return Err(fault(Fault::Internal(format!("broker frame: {e}")))),
    };
    if kind != ipc::KIND_FETCH_RESULT {
        return Err(fault(Fault::Internal(format!("broker frame kind {kind:#x}"))));
    }
    let status = match ipc::decode_fetch_result(&payload) {
        Ok((status, _)) => status,
        Err(e) => return Err(fault(Fault::Internal(format!("broker result: {e}")))),
    };
    payload.remove(0);
    let len = payload.len() as u32; // ≤ max_response_bytes, by the frame cap
    state.progress.fetch_bytes.fetch_add(u64::from(len), Ordering::Relaxed);
    if status == ipc::FetchStatus::Failed {
        state.progress.transient.store(true, Ordering::Relaxed);
    }
    state.response = payload;
    Ok(abi::pack_fetch(status as u8, len))
}

/// A linker with exactly the six ABI v1 functions.
pub(crate) fn linker(engine: &wasmtime::Engine) -> wasmtime::Result<Linker<HostState>> {
    let mut l = Linker::new(engine);
    l.func_wrap(abi::MODULE, abi::IMPORT_INPUT_LEN, |mut caller: Caller<'_, HostState>| -> wasmtime::Result<i32> {
        charge(&mut caller, FUEL_PER_HOST_CALL)?;
        Ok(caller.data().context.len() as i32)
    })?;
    l.func_wrap(
        abi::MODULE,
        abi::IMPORT_INPUT_READ,
        |mut caller: Caller<'_, HostState>, offset: i32, ptr: i32, len: i32| {
            read_into_guest(&mut caller, |s| &s.context, offset as u32, ptr as u32, len as u32)
        },
    )?;
    l.func_wrap(abi::MODULE, abi::IMPORT_FETCH, |mut caller: Caller<'_, HostState>, cap: i32, ptr: i32, len: i32| {
        fetch(&mut caller, cap as u32, ptr as u32, len as u32)
    })?;
    l.func_wrap(
        abi::MODULE,
        abi::IMPORT_RESPONSE_READ,
        |mut caller: Caller<'_, HostState>, offset: i32, ptr: i32, len: i32| {
            read_into_guest(&mut caller, |s| &s.response, offset as u32, ptr as u32, len as u32)
        },
    )?;
    l.func_wrap(abi::MODULE, abi::IMPORT_WITNESS_WRITE, |mut caller: Caller<'_, HostState>, ptr: i32, len: i32| {
        witness_write(&mut caller, ptr as u32, len as u32)
    })?;
    l.func_wrap(abi::MODULE, abi::IMPORT_LOG, |mut caller: Caller<'_, HostState>, ptr: i32, len: i32| {
        log(&mut caller, ptr as u32, len as u32)
    })?;
    Ok(l)
}
