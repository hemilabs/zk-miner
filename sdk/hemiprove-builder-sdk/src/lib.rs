//! Safe wrappers for HemiProve witness builders: WASM modules (builder type 1, ABI v1) that a
//! zkminer runs before it claims a job, to fetch data through the job's declared capabilities and
//! write the witness `W` its guest proves over (zkminer docs/witness-construction-jobs.md §9, §12).
//!
//! ```ignore
//! use hemiprove_builder_sdk as sdk;
//!
//! sdk::entry!(build);
//!
//! fn build() -> Result<(), sdk::Error> {
//!     let ctx = sdk::context()?;
//!     let response = sdk::fetch(0, br#"{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}"#)?;
//!     sdk::write_witness(sdk::json::rpc_result(&response)?)?;
//!     Ok(())
//! }
//! ```
//!
//! What the runner gives a builder: its context (no job id, no prover address), `fetch` through the
//! envelope's capabilities, an append-only `W`, and a capped diagnostic log. Nothing else: no clock,
//! no randomness, no file system. A panic traps (the crate is built with `panic = "abort"`; the panic
//! message goes to the log first), and the run then fails.
//!
//! Build with this workspace's `.cargo/config.toml`, which pins the WASM profile's target features
//! (see README.md for the reproducible build).

use core::fmt;

pub mod context;
#[cfg(feature = "eth")]
pub mod eth;
pub mod json;
pub mod rpc;
pub mod sys;

pub use context::{Capability, Context, DecodeError, EvmRpcConfig, Limits};
pub use json::JsonError;

const fn hex32(s: &str) -> [u8; 32] {
    let b = s.as_bytes();
    assert!(b.len() == 64);
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        let hi = (b[2 * i] as char).to_digit(16).unwrap() as u8;
        let lo = (b[2 * i + 1] as char).to_digit(16).unwrap() as u8;
        out[i] = (hi << 4) | lo;
        i += 1;
    }
    out
}

/// `keccak256("evm-rpc/v1")`: a capability whose `fetch` requests are JSON-RPC (§11.2).
pub const CLASS_EVM_RPC_V1: [u8; 32] = hex32("74d47797fc541e361442d98a5b45ff3d5e54bfb28cbbbc97f128ed9b98308d91");
/// `keccak256("blob/v1")`: a capability whose `fetch` request is a 32-byte sha256 (§11.3).
pub const CLASS_BLOB_V1: [u8; 32] = hex32("6b2b59f84c5ad9614227bf40d627bbae33351c7888e565b81c40a3fe7a3d1aff");
/// `keccak256("state-read")`: the `evm-rpc/v1` method set.
pub const METHOD_SET_STATE_READ: [u8; 32] = hex32("443f50d27406b101b4b4af812d91df11e0ebaaf1d24dae2f29b85a5324437205");

/// Why a `fetch` returned no response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FetchError {
    /// Status 1: the request is outside what the capability allows (or the capability index is
    /// unknown). Permanent for the job.
    Denied,
    /// Status 2: the data source failed. The run is then transient: the miner may retry once.
    Failed,
    /// Status 3: the job's own fetch budget is spent.
    Exhausted,
}

impl fmt::Display for FetchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Denied => "fetch denied",
            Self::Failed => "fetch failed",
            Self::Exhausted => "fetch budget exhausted",
        })
    }
}

/// `W` would exceed `maxWitnessBytes`; nothing of that write was appended, and the run fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WitnessTooLarge;

impl fmt::Display for WitnessTooLarge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("witness over maxWitnessBytes")
    }
}

/// Every SDK error, for builders that use `?` throughout.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    Context(DecodeError),
    Fetch(FetchError),
    WitnessTooLarge,
    Json(JsonError),
    Other(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Context(e) => write!(f, "context: {e}"),
            Self::Fetch(e) => e.fmt(f),
            Self::WitnessTooLarge => WitnessTooLarge.fmt(f),
            Self::Json(e) => e.fmt(f),
            Self::Other(s) => f.write_str(s),
        }
    }
}

impl From<DecodeError> for Error {
    fn from(e: DecodeError) -> Self {
        Self::Context(e)
    }
}
impl From<FetchError> for Error {
    fn from(e: FetchError) -> Self {
        Self::Fetch(e)
    }
}
impl From<WitnessTooLarge> for Error {
    fn from(_: WitnessTooLarge) -> Self {
        Self::WitnessTooLarge
    }
}
impl From<JsonError> for Error {
    fn from(e: JsonError) -> Self {
        Self::Json(e)
    }
}

/// The raw context bytes, `abi.encode(BuilderContextV1)`.
pub fn input() -> Vec<u8> {
    // SAFETY: the host copies at most the requested length into the buffer it is given.
    let len = unsafe { sys::input_len() } as u32 as usize;
    let mut buf = vec![0u8; len];
    let mut off = 0;
    while off < len {
        let got = unsafe { sys::input_read(off as i32, buf[off..].as_mut_ptr(), (len - off) as i32) };
        if got <= 0 {
            break;
        }
        off += got as usize;
    }
    buf.truncate(off);
    buf
}

/// The decoded context.
pub fn context() -> Result<Context, DecodeError> {
    Context::decode(&input())
}

/// Sends `request` through capability `cap` (an index into [`Context::sources`]) and returns the
/// whole response. Blocks; time spent waiting costs no fuel, but does count against the job's wall
/// clock. Each call replaces the previous response.
pub fn fetch(cap: u32, request: &[u8]) -> Result<Vec<u8>, FetchError> {
    // SAFETY: the host reads `request.len()` bytes from `request`.
    let packed = unsafe { sys::fetch(cap as i32, request.as_ptr(), request.len() as i32) } as u64;
    assert!((packed >> 32) & 0x00ff_ffff == 0, "the host returned a malformed fetch result");
    let len = packed as u32 as usize;
    match (packed >> 56) as u8 {
        0 => {}
        1 => return Err(FetchError::Denied),
        2 => return Err(FetchError::Failed),
        3 => return Err(FetchError::Exhausted),
        s => panic!("the host returned fetch status {s}"),
    }
    let mut buf = vec![0u8; len];
    let mut off = 0;
    while off < len {
        // SAFETY: the host copies at most the requested length into the buffer it is given.
        let got = unsafe { sys::response_read(off as i32, buf[off..].as_mut_ptr(), (len - off) as i32) };
        assert!(got > 0, "the host returned a short response");
        off += got as usize;
    }
    Ok(buf)
}

/// Appends `bytes` to `W`. The miner keeps `W` only if `run` returns 0.
pub fn write_witness(bytes: &[u8]) -> Result<(), WitnessTooLarge> {
    // SAFETY: the host reads `bytes.len()` bytes from `bytes`.
    match unsafe { sys::witness_write(bytes.as_ptr(), bytes.len() as i32) } {
        0 => Ok(()),
        _ => Err(WitnessTooLarge),
    }
}

/// Writes raw bytes to the diagnostic log (64 KiB per job in total; the rest is dropped). The miner
/// sanitizes it; it is for the requester's dry runs, not for data.
pub fn log_bytes(bytes: &[u8]) {
    // SAFETY: the host reads `bytes.len()` bytes from `bytes`.
    unsafe { sys::log(bytes.as_ptr(), bytes.len() as i32) }
}

/// Writes a message to the diagnostic log.
pub fn log(msg: &str) {
    log_bytes(msg.as_bytes());
}

/// Defines the module's `run` export around `f: fn() -> Result<(), E>` (any `E: Display`): `run`
/// returns 0 on `Ok`, and on `Err` logs the error and returns 1 (the miner's NONZERO_RETURN). A panic
/// is logged and then traps.
#[macro_export]
macro_rules! entry {
    ($f:path) => {
        #[unsafe(no_mangle)]
        pub extern "C" fn run() -> i32 {
            $crate::__run($f)
        }
    };
}

#[doc(hidden)]
pub fn __run<E: fmt::Display>(f: impl FnOnce() -> Result<(), E>) -> i32 {
    std::panic::set_hook(Box::new(|info| log(&format!("panic: {info}\n"))));
    match f() {
        Ok(()) => 0,
        Err(e) => {
            log(&format!("builder failed: {e}\n"));
            1
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn class_constants() {
        assert_eq!(super::CLASS_EVM_RPC_V1[..4], [0x74, 0xd4, 0x77, 0x97]);
        assert_eq!(super::CLASS_BLOB_V1[31], 0xff);
        assert_eq!(super::METHOD_SET_STATE_READ[0], 0x44);
    }
}
