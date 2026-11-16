//! Builder ABI v1 constants (plan §9.2), shared by the runner and the SDK's host-side tests.

/// The only import module a v1 builder may use. ABI v2 is a new module name.
pub const MODULE: &str = "hemiprove_builder_v1";

/// The imports, with their wasm signatures (params → results).
pub const IMPORT_INPUT_LEN: &str = "input_len"; // () -> i32
pub const IMPORT_INPUT_READ: &str = "input_read"; // (offset: i32, ptr: i32, len: i32) -> i32
pub const IMPORT_FETCH: &str = "fetch"; // (cap: i32, req_ptr: i32, req_len: i32) -> i64
pub const IMPORT_RESPONSE_READ: &str = "response_read"; // (offset: i32, ptr: i32, len: i32) -> i32
pub const IMPORT_WITNESS_WRITE: &str = "witness_write"; // (ptr: i32, len: i32) -> i32
pub const IMPORT_LOG: &str = "log"; // (ptr: i32, len: i32) -> ()
pub const IMPORTS: [&str; 6] =
    [IMPORT_INPUT_LEN, IMPORT_INPUT_READ, IMPORT_FETCH, IMPORT_RESPONSE_READ, IMPORT_WITNESS_WRITE, IMPORT_LOG];

/// The exports: exactly one 32-bit memory and `run() -> i32`.
pub const EXPORT_MEMORY: &str = "memory";
pub const EXPORT_RUN: &str = "run";

/// The diagnostic sink's total per job; the rest is dropped.
pub const LOG_CAP_BYTES: usize = 64 * 1024;
/// `W` reaches the miner as a raw byte stream on the runner's W pipe (fd 3), written in pieces of at
/// most this size; the miner counts it against `maxWitnessBytes` and keeps it only on exit 0.
pub const W_CHUNK_BYTES: usize = 1 << 20;

/// `witness_write` results.
pub const WITNESS_WRITE_OK: i32 = 0;
pub const WITNESS_WRITE_OVER_LIMIT: i32 = 1;

/// Runner fd numbers (the miner places them with the sandbox launcher's fd map).
pub mod fd {
    /// Write end of the W pipe.
    pub const W: i32 = 3;
    /// Write end of the summary pipe (`BuilderSummary`, 48 bytes).
    pub const SUMMARY: i32 = 4;
    /// The job's socket to the broker (fetch frames).
    pub const BROKER: i32 = 5;
    /// Sealed memfd holding the module bytes.
    pub const MODULE: i32 = 6;
    /// Sealed memfd holding `abi.encode(BuilderContextV1)`.
    pub const CONTEXT: i32 = 7;
    /// The diagnostic sink (sanitized by the miner).
    pub const LOG: i32 = 2;
}

/// Packs `fetch`'s result: bits 63–56 the status, bits 55–32 zero, bits 31–0 the response length.
pub fn pack_fetch(status: u8, len: u32) -> i64 {
    ((u64::from(status) << 56) | u64::from(len)) as i64
}

/// Unpacks `fetch`'s result; `None` if bits 55–32 are not zero.
pub fn unpack_fetch(v: i64) -> Option<(u8, u32)> {
    let v = v as u64;
    if (v >> 32) & 0x00ff_ffff != 0 {
        return None;
    }
    Some(((v >> 56) as u8, v as u32))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fetch_packing() {
        for (s, l) in [(0u8, 0u32), (1, 7), (2, u32::MAX), (3, 1 << 20)] {
            assert_eq!(unpack_fetch(pack_fetch(s, l)), Some((s, l)));
        }
        assert!(pack_fetch(3, 0) > 0, "status 3 keeps the sign bit clear");
        assert_eq!(unpack_fetch(1 << 40), None);
    }
}
