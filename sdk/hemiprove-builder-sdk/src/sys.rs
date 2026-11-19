//! The raw builder ABI v1 imports (zkminer docs/witness-construction-jobs.md §9.2). Use the safe
//! wrappers in the crate root instead.
//!
//! Pointers and lengths are wasm32 `i32`s; the host reads them as `u32`.

#[cfg(target_arch = "wasm32")]
#[link(wasm_import_module = "hemiprove_builder_v1")]
extern "C" {
    /// Length of the encoded context.
    pub fn input_len() -> i32;
    /// Copies up to `len` context bytes from `offset` to `ptr`; returns the count (0 past the end).
    pub fn input_read(offset: i32, ptr: *mut u8, len: i32) -> i32;
    /// Sends `req` to capability `cap`; bits 63–56 of the result are the status (0 ok, 1 denied,
    /// 2 failed, 3 exhausted), bits 31–0 the response length. Replaces the held response.
    pub fn fetch(cap: i32, req_ptr: *const u8, req_len: i32) -> i64;
    /// Copies up to `len` bytes of the held response from `offset` to `ptr`; returns the count.
    pub fn response_read(offset: i32, ptr: *mut u8, len: i32) -> i32;
    /// Appends to W; 0 ok, 1 over `maxWitnessBytes` (the run then fails).
    pub fn witness_write(ptr: *const u8, len: i32) -> i32;
    /// Writes to the diagnostic sink (64 KiB per job in total, the rest dropped).
    pub fn log(ptr: *const u8, len: i32);
}

// Off wasm32 (the SDK's own host-side unit tests) there is no host to call: every stub panics, so
// none has a safety contract of its own.
#[cfg(not(target_arch = "wasm32"))]
#[allow(clippy::missing_safety_doc)]
mod native {
    const MSG: &str = "the builder ABI is only available in wasm32 builders";
    pub unsafe fn input_len() -> i32 {
        unimplemented!("{MSG}")
    }
    pub unsafe fn input_read(_: i32, _: *mut u8, _: i32) -> i32 {
        unimplemented!("{MSG}")
    }
    pub unsafe fn fetch(_: i32, _: *const u8, _: i32) -> i64 {
        unimplemented!("{MSG}")
    }
    pub unsafe fn response_read(_: i32, _: *mut u8, _: i32) -> i32 {
        unimplemented!("{MSG}")
    }
    pub unsafe fn witness_write(_: *const u8, _: i32) -> i32 {
        unimplemented!("{MSG}")
    }
    pub unsafe fn log(_: *const u8, _: i32) {
        unimplemented!("{MSG}")
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub use native::*;
