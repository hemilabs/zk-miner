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
//! 2. **Compilation** with [`engine::engine_config`], single-threaded, at `OptLevel::None`, on the
//!    execution thread; the wall clock is already running.
//! 3. **Instantiation and `run()`**, with fuel and the epoch deadline armed on the store before
//!    instantiation (a start function runs inside it), a [`wasmtime::ResourceLimiter`] that allows one
//!    memory, one table and one instance, at most 65,536 table elements and the memory clamp, and that
//!    records a denied growth.
//!
//! # Exit classification ([`zkminer_witness::ipc::exit`])
//! | Outcome | Exit |
//! |---|---|
//! | `run()` returned 0 | OK |
//! | `run()` returned anything else | NONZERO_RETURN |
//! | a trap (wasm or a host function's bounds/request-cap trap) | TRAP, or MEMORY if a memory growth was denied earlier |
//! | fuel exhausted (in wasm or charged by a host function) | FUEL |
//! | the epoch deadline, or the deadline passing during a `fetch` | WALL_CLOCK |
//! | `witness_write` returned 1 at any point (overrides the above) | WITNESS_TOO_LARGE |
//! | rejected by the pre-pass | INVALID_MODULE / UNKNOWN_IMPORT |
//! | runner, sink or broker-channel failure | INTERNAL |
//!
//! # Threads
//! At most three: the caller (main), the execution thread (8 MiB stack) and the epoch watchdog. This
//! build of wasmtime starts none (no `parallel-compilation`, `async`, `cache`, `profiling`, pooling
//! allocator or userfaultfd).

pub mod cli;
pub mod cost;
pub mod engine;
mod host;
pub mod prepass;
mod runner;

pub use cli::{main_with_fds, parse_args, Args, RunnerFds, MAX_CONTEXT_BYTES};
pub use host::{FUEL_PER_BYTE, FUEL_PER_HOST_CALL};
pub use prepass::{prepass, prepass_with_caps, CompileCost, CostCaps, ModuleInfo, PrepassError, PROFILE_FEATURES};
pub use runner::{run, BrokerChannel, RunnerConfig, RunnerIo, DEADLINE_GRACE};
pub use zkminer_witness::ipc::BuilderSummary;
