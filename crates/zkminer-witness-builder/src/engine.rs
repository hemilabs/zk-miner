//! The wasmtime configuration (plan §9.1). wasmtime is built with `default-features = false` and
//! only `runtime` + `cranelift`, which also fixes three properties at compile time:
//! - **no compiled-code cache** (`cache` is off) and no `Module::deserialize` anywhere in the runner;
//! - **serial compilation**: `parallel-compilation` (rayon) is not compiled in, so
//!   `Config::parallel_compilation` does not exist and compilation runs on the calling thread;
//! - **no coredumps**: `coredump` is off, so `Config::coredump_on_trap` does not exist.
//!
//! The `gc` feature is off too, which keeps `externref` and every GC type out at wasmtime's own
//! validation (the pre-pass rejects them first).

use wasmtime::{Config, Engine, InstanceAllocationStrategy, OptLevel, Strategy, WasmFeatures};

use crate::prepass::PROFILE_FEATURES;

/// `max_wasm_stack`: the native stack wasm frames may use. Execution runs on a thread with
/// [`EXEC_THREAD_STACK_BYTES`] of stack, so host functions keep plenty.
pub const MAX_WASM_STACK_BYTES: usize = 1 << 20;
/// Stack of the thread that compiles, instantiates and runs the module.
pub const EXEC_THREAD_STACK_BYTES: usize = 8 << 20;

/// The exact configuration every builder runs under.
pub fn engine_config() -> Config {
    let mut c = Config::new();
    c.strategy(Strategy::Cranelift);
    c.cranelift_opt_level(OptLevel::None);
    // Both armed on the store before instantiation, since start functions run during it.
    c.consume_fuel(true);
    c.epoch_interruption(true);
    // One instance per process: no pooling. Guard regions and the reservation stay at wasmtime's
    // defaults (bounds checks elided behind a 4 GiB reservation and guard pages on 64-bit hosts).
    c.allocation_strategy(InstanceAllocationStrategy::OnDemand);
    // Copy data segments in at instantiation instead of mapping a copy-on-write memfd image: no
    // `memfd_create` in the sandbox, and nothing to gain for a single instance.
    c.memory_init_cow(false);
    // SAFETY: both are standard Cranelift settings that wasmtime itself defaults to `true` and
    // accepts as compatible with its runtime; enabling them explicitly only pins that default.
    unsafe {
        c.cranelift_flag_enable("enable_heap_access_spectre_mitigation");
        c.cranelift_flag_enable("enable_table_access_spectre_mitigation");
    }
    c.max_wasm_stack(MAX_WASM_STACK_BYTES);
    // `wasm_backtrace(false)`, in the form wasmtime 48 spells it (the old method is deprecated).
    c.wasm_backtrace_max_frames(None);
    c.cranelift_nan_canonicalization(true);

    // Every proposal outside the profile, explicitly off (several of these have no `wasm_*` method
    // in this build because their cargo feature is off; `wasm_features` reaches them all).
    c.wasm_simd(false);
    c.wasm_relaxed_simd(false);
    c.wasm_multi_memory(false);
    c.wasm_memory64(false);
    c.wasm_tail_call(false);
    c.wasm_gc(false);
    c.wasm_extended_const(false);
    c.wasm_custom_page_sizes(false);
    c.wasm_wide_arithmetic(false);
    c.wasm_stack_switching(false);
    c.wasm_shared_everything_threads(false);
    c.wasm_branch_hinting(false);
    c.wasm_features(
        WasmFeatures::THREADS
            | WasmFeatures::EXCEPTIONS
            | WasmFeatures::LEGACY_EXCEPTIONS
            | WasmFeatures::COMPONENT_MODEL
            | WasmFeatures::FUNCTION_REFERENCES
            | WasmFeatures::GC_TYPES,
        false,
    );
    // And the rest of the flag space, so the engine's set is exactly the profile.
    c.wasm_features(WasmFeatures::all().difference(PROFILE_FEATURES), false);
    c.wasm_features(PROFILE_FEATURES, true);
    c
}

/// An engine with [`engine_config`].
pub fn engine() -> wasmtime::Result<Engine> {
    Engine::new(&engine_config())
}
