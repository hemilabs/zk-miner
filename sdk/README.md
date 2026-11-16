# HemiProve witness-builder SDK

A witness builder is a WASM module (builder type 1, ABI v1) that a zkminer runs before it claims a
witness job: it reads the job's context, fetches data through the job's declared capabilities, and
writes the witness `W` the job's guest proves over. The design is in zkminer
`docs/witness-construction-jobs.md` §9 (ABI and WASM profile), §11 (capabilities) and §12 (a
worked example). The runner that executes builders is `crates/zkminer-witness-builder`.

This directory is its own Cargo workspace (excluded from the zkminer workspace):

| Path | What |
|---|---|
| `hemiprove-builder-sdk/` | the SDK: `context()`, `fetch()`, `write_witness()`, `log()`, `entry!`, a `BuilderContextV1` decoder, minimal JSON extraction |
| `examples/latest-block/` | example builder: `W = blockNumber (u64 BE) ‖ blockHash` of the finalized block behind capability 0 |
| `test-builders/faults/` | a builder that panics or exhausts memory on request, for the runner's tests |
| `test-builders/receipts-proof/`, `test-builders/storage-proof/` | realistic builders with heavy dependencies (serde_json, alloy-rlp, alloy-primitives, alloy-trie, alloy-sol-types, tiny-keccak, sha2) that calibrate and test the runner's compile-cost budget; built at `opt-level = 3` |
| `.cargo/config.toml` | the pinned target-feature list (the WASM profile) |
| `rust-toolchain.toml` | the pinned toolchain (1.97.1, with the wasm32-unknown-unknown target) |
| `build-reproducible.sh` | the reproducible build, which also runs the runner's pre-pass on what it built |

## Writing a builder

```rust
use hemiprove_builder_sdk::{self as sdk, json, Error};

sdk::entry!(build);

fn build() -> Result<(), Error> {
    let ctx = sdk::context()?;                       // BuilderContextV1: sources, limits, builderParams, …
    let response = sdk::fetch(0, br#"{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}"#)?;
    let number = json::quantity_u64(json::as_str(json::rpc_result(&response)?)?)?;
    sdk::write_witness(&number.to_be_bytes())?;
    Ok(())
}
```

- The crate is a `cdylib` for `wasm32-unknown-unknown`. `entry!` defines the `run` export: `Ok` → 0
  (the run succeeds), `Err` → the error is logged and `run` returns 1 (the miner's NONZERO_RETURN).
- `fetch(cap, request)` returns the whole response, or `FetchError::{Denied, Failed, Exhausted}`
  (statuses 1–3). `Failed` makes the run transient (one retry elsewhere); the others are permanent.
- `write_witness` appends to `W`; over `maxWitnessBytes` it returns `WitnessTooLarge` and the run
  fails whatever `run` returns.
- `log` goes to a sanitized diagnostic sink, 64 KiB per job in total.
- A panic is logged, then traps (`panic = "abort"`): the run fails with TRAP. Running out of memory
  (the clamp refuses `memory.grow`, the allocator aborts) fails it with MEMORY.
- There is no clock, no randomness, no file system and no job identity. The builder does not have
  to be deterministic or correct: the miner proves the `W` it persisted, and the guest must check
  everything it reads from `W`.
- Besides `memory` and `run`, a module may export anything (the runner ignores other exports, such
  as the `__heap_base` and `__data_end` globals some Rust builds emit); it may import only the six
  `hemiprove_builder_v1` functions.

## The WASM profile

The runner accepts exactly: MVP with floats, mutable globals, sign extension, saturating
float-to-int, bulk memory, multi-value, and reference types for `funcref` only. Everything else
(SIMD, relaxed SIMD, threads and atomics, multi-memory, memory64, exceptions, tail calls, GC and
`externref`, function references, extended-const, the component model) is rejected before
compilation (INVALID_MODULE). `.cargo/config.toml` pins the matching `-C target-cpu=mvp` plus the
explicit `+`/`-` feature list, so a newer rustc's default CPU cannot add a feature. The precompiled
`std` for the target uses only features inside the profile; the runner's test
`the_example_passes_the_prepass_under_exactly_the_profile` builds the example and validates it
against exactly the profile, and `the_example_imports_only_hemiprove_builder_v1_functions` checks
its imports.

`RUSTFLAGS` (or `CARGO_ENCODED_RUSTFLAGS`) **replaces** the config's target rustflags, so never set
it when building a builder. `build-reproducible.sh` sets `CARGO_ENCODED_RUSTFLAGS` itself, to the
complete list: the config's target features followed by its path remapping (a test keeps the two
lists equal).

## Building reproducibly

The job's `builderId` is the sha256 of the module bytes, so anyone must be able to rebuild a
published builder from source and get the same bytes:

```sh
cd sdk
./build-reproducible.sh -p latest-block
sha256sum target/wasm32-unknown-unknown/release/latest_block.wasm
```

The script runs `cargo build --locked --release --target wasm32-unknown-unknown` from this directory
(so `.cargo/config.toml` and `rust-toolchain.toml` apply), after it:

- **pins the toolchain:** unsets `RUSTUP_TOOLCHAIN`, `RUSTC`, `CARGO_BUILD_RUSTC*` and sets
  `RUSTC_WRAPPER` and `RUSTC_WORKSPACE_WRAPPER` empty (which also overrides a wrapper in a cargo
  config file); checks that `rustc -vV` is the release `rust-toolchain.toml` names and the commit
  hash the script records, and that `cargo -V` is the same release; then points `RUSTC` at exactly
  that rustc;
- **pins the profile:** unsets every `CARGO_PROFILE_*`, `CARGO_INCREMENTAL` and
  `CARGO_BUILD_INCREMENTAL`, so the release profile in `Cargo.toml` applies: `panic = "abort"`,
  `opt-level = "s"`, `lto = true`, `codegen-units = 1`, no debug info, `strip = true`, no
  incremental compilation;
- **pins the flags:** unsets `RUSTFLAGS`, `CARGO_BUILD_RUSTFLAGS` and the target's own
  `RUSTFLAGS`/`LINKER` variables, and passes the complete list in `CARGO_ENCODED_RUSTFLAGS`, which
  replaces rustflags from every other source, config files included: the profile's target features,
  then `--remap-path-prefix` for every host path that can reach the module through panic locations:
  the toolchain's `rust-src` directory → `/rustc/<commit-hash>` (without this, inlined `core` code
  records `~/.rustup/toolchains/…/library/core/src/…` when the `rust-src` component is installed,
  and `/rustc/<commit-hash>/…` when it is not), `$CARGO_HOME` → `/cargo` (registry dependencies),
  and this directory → `/sdk`;
- uses `--locked`: exactly the dependency versions in `Cargo.lock`.

Then it puts every module it built through the runner's own pre-pass (`zkminer-builder-check`: the
profile, the imports and exports, the structural limits and the compile-cost budget), printing each
one's compile-cost estimate, and fails if any is refused. Inside the zkminer repository it builds
the checker itself; elsewhere, point `ZKMINER_BUILDER_CHECK` at a `zkminer-builder-check` binary.
The runner's test `the_script_rebuilds_the_published_example` runs the script, with hostile values in
all of those variables, and checks the hash below.

A builder with its own repository should copy `.cargo/config.toml`, `rust-toolchain.toml`, the
release profile and the script, and commit its `Cargo.lock`.

### Recorded on this host (2026-11-16)

Toolchain `rustc 1.97.1 (8bab26f4f 2026-07-14)`, LLVM 22.1.6, x86_64-unknown-linux-gnu.

| Build | sha256 of `latest_block.wasm` (31,317 bytes) |
|---|---|
| `./build-reproducible.sh -p latest-block`, clean target dir #1 | `ec41c077833f209353a019615fb11a45cd6147d7ce079b47f8c8130162a4f64e` |
| same, clean target dir #2 | `ec41c077833f209353a019615fb11a45cd6147d7ce079b47f8c8130162a4f64e` |
| same, from a copy of `sdk/` in another directory | `ec41c077833f209353a019615fb11a45cd6147d7ce079b47f8c8130162a4f64e` |

A plain `cargo build --locked --release --target wasm32-unknown-unknown -p latest-block` (no
remapping) was also identical across two clean target dirs and the copy, at
`a2325169cbc2dab544948c4b3f3a29c68e8f36e931e35bac29149a98eaa82fb6` (31,353 bytes), but that module
embeds this host's `rust-src` path; the script's bytes are the ones to publish.

The module has 17 initial memory pages (1.06 MiB, mostly Rust's 1 MiB shadow stack), so it needs
`maxBuilderMemoryBytes` ≥ 1,114,112 to pass the runner's pre-pass.

## Testing

- `cargo test` here runs the SDK's host-side unit tests (the context decoder and the JSON
  extraction; the ABI imports exist only on wasm32).
- `cargo test -p zkminer-witness-builder` from the zkminer root builds every builder here for wasm32
  with this configuration and runs them through the runner against a fake broker; checks that
  `receipts-proof` and `storage-proof` pass the pre-pass with at least 10× headroom under every
  compile-cost cap; and rebuilds `latest-block` with `build-reproducible.sh` against the hash above.
