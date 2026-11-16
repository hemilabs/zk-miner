//! The WASM witness-builder runner (plan §9, §10.1): runs a requester's ABI v1 builder module under
//! the frozen WASM profile and returns a [`BuilderSummary`] whose exit code the miner turns into a
//! local verdict (§16).
//!
//! # Pipeline
//! 1. **Pre-pass** ([`prepass`]): a streaming wasmparser pass, before any compilation, validates the
//!    module against exactly [`PROFILE_FEATURES`] and rejects oversized or over-numerous parts and
//!    modules over the compile-cost budget ([`cost`]) (INVALID_MODULE), and any import other than
//!    `hemiprove_builder_v1`'s six functions with their exact signatures (UNKNOWN_IMPORT). The module
//!    must export `memory` (32-bit) and `run: () -> i32` (INVALID_MODULE otherwise). **Other exports
//!    are tolerated and ignored**: Rust's wasm32 cdylibs export the globals `__heap_base` and
//!    `__data_end`, and the runner never calls anything but `run`.
//! 2. **The epoch watchdog** starts, then **compilation** with [`engine::engine_config`],
//!    single-threaded, at `OptLevel::None`, on the execution thread; the wall clock is already
//!    running. A compile error is INVALID_MODULE.
//! 3. **The started marker** ([`zkminer_witness::abi::MODULE_STARTED_MARKER`]) goes to the summary
//!    pipe, then **instantiation and `run()`**, with fuel and the epoch deadline armed on the store
//!    before instantiation (a start function runs inside it), a [`wasmtime::ResourceLimiter`] that
//!    allows one memory, one table and one instance, at most 65,536 table elements and the memory
//!    clamp, and that records a denied growth.
//!
//! # Exit classification ([`zkminer_witness::ipc::exit`])
//! | Outcome | Exit |
//! |---|---|
//! | `run()` returned 0 | OK |
//! | `run()` returned anything else | NONZERO_RETURN |
//! | a trap (wasm or a host function's bounds/request-cap trap) | TRAP, or MEMORY if a memory growth was denied earlier |
//! | fuel exhausted (in wasm or charged by a host function) | FUEL |
//! | the epoch deadline; the deadline passing during a `fetch`, or before a `witness_write` or `log`; `run()` returning after the deadline | WALL_CLOCK |
//! | `witness_write` returned 1 at any point (overrides the above) | WITNESS_TOO_LARGE |
//! | rejected by the pre-pass, or by compilation | INVALID_MODULE / UNKNOWN_IMPORT |
//! | runner, sink or broker-channel failure | INTERNAL |
//!
//! The runner never reports a signal; a runner killed by one (an OOM kill, the miner's own timeout,
//! or a crash) is the miner's to classify.
//!
//! # Threads
//! Exactly three once the pre-pass has passed: the caller (main), the execution thread (8 MiB stack)
//! and the epoch watchdog, started before compilation. This build of wasmtime starts none
//! (no `parallel-compilation`, `async`, `cache`, `profiling`, pooling allocator or userfaultfd). The
//! job cgroup's `pids.max` must be at least 3; with less, the run ends INTERNAL before compiling.

pub mod cli;
pub mod cost;
pub mod engine;
mod host;
pub mod prepass;
mod runner;

pub use cli::{main_with_fds, parse_args, Args, RunnerFds, MAX_CONTEXT_BYTES};
pub use host::{FUEL_PER_BYTE, FUEL_PER_FETCH, FUEL_PER_HOST_CALL};
pub use prepass::{prepass, prepass_with_caps, CompileCost, CostCaps, ModuleInfo, PrepassError, PROFILE_FEATURES};
pub use runner::{run, BrokerChannel, RunnerConfig, RunnerIo, DEADLINE_GRACE};
pub use zkminer_witness::ipc::BuilderSummary;
