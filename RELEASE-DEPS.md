# Release dependencies (macOS / Metal, risc0 3.1)

What a zk-miner build on this branch takes from outside the repository, how it is pinned, and how
to build it on a clean macOS machine (a CI runner) or against a local risc0 checkout. Item B9-DEP;
evidence in `docs/metal-port-notes/B9-DEP.md`. The pin moved to `28b4bef33` when GitHub main was merged
into the macOS beta (W10-INT, `docs/metal-port-notes/W10-INT.md`), then to `37b434755`, which gates the
fork's non-Metal changes to Metal builds (W10-GATE; W10-PIN, `docs/metal-port-notes/W10-PIN.md`).

## The pins

| what | source | pin |
|---|---|---|
| 17 risc0 crates (`risc0-zkvm`, `-zkp`, `-sys`, `-build`, `-build-kernel`, `-groth16`, `-groth16-sys`, `-circuit-{rv32im,recursion,keccak}` and their `-sys`, `-core`, `-binfmt`, `-zkos-v1compat`, `-zkvm-platform`) | `https://github.com/hemilabs/risc0`, branch **`zkminer/metal-3.1`** | `rev = "37b434755ce77dd1354d957a7b61912aa4359423"` (`Cargo.toml` `[patch.crates-io]`) |
| `rzup` (risc0-build's toolchain lookup) | same rev, through risc0-build | (follows the rev) |
| `risc0-circuit-recursion-zkrs`, `risc0-circuit-recursion-control-zkrs` | crates.io | `=4.1.0` (`Cargo.toml` `[patch."https://github.com/hemilabs/risc0"]`); `Cargo.lock` checksums `667665b4…6fb5d` and `bc7f8b26…f1667` |
| sppark | `hemilabs/risc0-sppark` | rev `5f68eb3e…` (unchanged) |
| SP1 crates | `hemilabs/sp1` | rev `a4df7c8f7…` (`zkminer/windows-server-connect`, from GitHub main; was `9a0de746…`) |
| guest crates (`crates/zkminer-prover/guests/risc0/*`) | crates.io (`risc0-zkvm` 3.0.5) and the RustCrypto risc0 forks on GitHub | each guest's own `Cargo.lock` (unchanged) |

`37b434755` is `/Users/user/zkminer/deps/risc0-3.1` after the Wave 10 phase-2 merge
(`Merge metal/W10-GATE`). Its first parent `28b4bef33` (the phase-1 merge, `Merge metal/W10-R0`) is the
Wave 9 beta pin `d94ef6501` (the release-3.1 port of Wave 8, the 3.1 security fixes of B9-SEC, merge
`abea7c97c`, and the 4 GiB Groth16 wrap, B9-G1 `afb524d8e` and B9-4G `d94ef6501`) merged with upstream
hemilabs `release-3.1` @ `5beab26b5`, which GitHub main pinned until W10-INT
(`git merge-base --is-ancestor 5beab26b5 37b434755` holds). The two commits that release-3.1 had and the
beta pin lacked are the ROCm evalfast `eval_check` regeneration for the 3.1 circuit (4 files, ROCm only).
W10-GATE (`404ae8dcf`, merged as `37b434755`) adds no Metal behaviour change: the five metallibs are
byte-identical and its interleaved worker A/B is inside A-vs-A at the default and 4 GiB budgets.
**The branch has to be pushed to hemilabs/risc0 unchanged as `zkminer/metal-3.1`** before anyone outside
this Mac can build: until then `https://github.com/hemilabs/risc0` has no commit `37b434755`. If the
branch is rebased or amended before the push, the rev in `Cargo.toml` and the 18 `source = "git+…"`
lines in `Cargo.lock` must be updated to the pushed sha.

**What the Metal fork changes on the other platforms: nothing by default.** W10-R0's audit (the fork
note `docs/metal-port/notes/W10-R0.md` in the risc0 repository) found six fork changes active off Metal.
W10-GATE (`docs/metal-port/notes/W10-GATE.md`, table "The changes") gates each of them to Metal builds,
`cfg!(all(feature = "metal", any(target_os = "macos", target_os = "ios")))`, so a CUDA, ROCm, Intel or
CPU build behaves like upstream release-3.1 unless a knob opts in. Each knob keeps its "off" spelling,
and any other value turns the change on, on every build:

| change | default on Metal | default elsewhere (= release-3.1) | knob |
|---|---|---|---|
| keccak requests right-sized to the smallest po2 that holds their inputs (control ids stay under `KECCAK_CONTROL_ROOT`) | on | off: the session's keccak max po2 | `RISC0_KECCAK_RIGHTSIZE_PO2` (`0` = off) |
| per-process zkr program cache | on | off: a program is built per call | `RISC0_METAL_REC_ZKR_CACHE` (`0`/`off`/`false` = off) |
| recursion ZK noise drawn on a helper thread (same RNG and draws) | on | off: drawn on the proving thread | `RISC0_RECURSION_NOISE_OVERLAP` (`0` = off) |
| rv32im data witness dropped after `step_accum` at every po2 | on | off: po2 >= 22 only | `RISC0_METAL_DROP_DATA_EARLY` (`0` = off) |
| Groth16 graph build memoized, digest overlapped (`fast.rs`, also compiled for Intel) | on | off | `RISC0_G16_GRAPH_MEMO` (`0` = off) |
| `RISC0_REC_HOST_CHAIN_MIN_LEN` read | yes (default 16) | not read: CUDA/ROCm use 16 | Metal only |

`risc0_circuit_recursion::prove::zkr::get_zkr` has upstream's signature again on every platform,
`fn(&str, usize) -> Result<Program>` (the Metal path calls the new `get_zkr_shared`); zk-miner calls
neither. The CPU recursion witgen runs on the caller's trace off Metal, as upstream. The remaining
differences off Metal are additive public items (`verify_seal`, `prewarm_p254_ctrl`, `get_zkr_shared`,
`Hal` methods whose defaults keep the old sequence), test-only helpers and log/error wording; on macOS
without `metal`, `risc0_zkp::hal::metal` is no longer compiled and zkvm's `metal` feature refuses
non-macOS targets (zk-miner enables `metal` only for the macOS worker).

Evidence: the CPU-only suites on this Mac assert the upstream defaults, and `cargo check --target
x86_64-unknown-linux-gnu --tests` with `prove`, `cuda`, `rocm` and `intel` type-checks the gated code
(W10-GATE's stand-in compilers; nothing is compiled for a GPU or linked). No CUDA/HIP/SYCL compile and no
non-Metal GPU run was possible here: a Linux/Windows CI run of the fork is still needed before GitHub main
relies on this pin for those platforms.

Do not `cargo update` the risc0 crates: a rev is used, not a branch, so that a moved branch head can
never change the build without a review (the same rule as for sppark and SP1).

### Why the zkrs crates come from crates.io

In git, `risc0/circuit/recursion-zkrs/src/zkrs.tar.xz` and `recursion-control-zkrs/src/zkrs.tar.xz`
are Git LFS objects. Cargo's git checkout never runs LFS (also not with
`CARGO_NET_GIT_FETCH_WITH_CLI`), so it leaves the 132-byte pointer files, and the crates' build
scripts refuse them (`src/zkrs.tar.xz is a git-lfs pointer, not the tarball … depend on this crate
from crates.io`). The crates.io 4.1.0 packages are byte-identical to the fork's: the same `build.rs`
and `src/`, and the tarballs' sha256 (`53388c58…26c2` lift, `202fd7e7…187f` control) equal the
fork's LFS oids. Nothing else that a zk-miner build reads is stored in LFS. (The other LFS file,
`groth16_proof/groth16/stark_verify.circom`, is only read by risc0's `xtask setup_groth16`.)

### Build inputs outside the crate directories

A git dependency is a checkout of the whole repository at the rev, so the risc0 build scripts find
everything they read outside their own crate (the Metal kernels and shared headers under
`risc0/build_kernel/kernels/metal`, `risc0/sys/kernels`, …), exactly as in a local checkout. Every such
file is tracked in git (`git status --ignored` of the fork shows nothing untracked but an unrelated
lockfile). The cuda2metal headers are compiled into `risc0-build-kernel` (`include_str!`). The offline
(AOT) archive tooling, `tools/metal_aot`, is not a build input: `make -f Makefile.mac mac-build-aot`
uses it from cargo's checkout (see below).

## Building on a clean macOS machine (CI)

CI does this with the repository's scripts, each pinned and checked (`docs/ci-macos.md` has the jobs,
the runner and every pin; `.github/workflows/build-macos.yml` runs them). On a clean Apple Silicon Mac
(Command Line Tools or Xcode, python3; no sudo and no Homebrew needed), from a checkout:

```sh
# 1. The validated Metal compiler: Metal Toolchain 27B47 (`Apple metal version 32023.922`), downloaded
#    from Apple's CDN, SHA-256 checked twice, mounted read-only (no Xcode, Apple ID or sudo). Never the
#    runner's own Xcode compiler for a release: another compiler build is unvalidated GPU code
#    (docs/macos-beta.md, "Metal compiler"). In a workflow it writes METAL_TC to $GITHUB_ENV;
#    elsewhere it prints the export line: run that line before step 3.
scripts/ci/macos-metal-toolchain.sh "$TMPDIR/metal-tc" pinned

# 2. rustup 1.29.3 (rustup-init, SHA-256 pinned) and the toolchain rust-toolchain.toml names (1.97.1);
#    rzup built --locked from the hemilabs/risc0 rev Cargo.toml pins, then the RISC Zero Rust guest
#    toolchain 1.97.0 through it (risc0-build compiles the 13 benchmark guests; 1.97.0 is what they were
#    built and measured with); protoc 36.2 (the official zip, SHA-256 pinned) for risc0-groth16's
#    circom-witnesscalc build script. No C++ guest toolchain and no Docker. Prints the PATH and
#    PROTOC lines to export outside a workflow.
scripts/ci/macos-toolchains.sh "$TMPDIR/tools"

# 3. The kit (RISC0_SRC=git, the rev Cargo.toml pins): Makefile.mac mac-build-worker with the kit's
#    settings (minimum macOS 26.0, the compiler wrapper), its checks, the package and
#    check-macos-release.sh. AOT_ARCHES=none: the release kit has no offline archives.
AOT_ARCHES=none scripts/ci/assemble-macos.sh dist/macos
#    mac-build-worker = cargo build --locked --release -p zkminer-prove-risc0 --features metal --bin zkminer-prove-risc0-metal
#                       cargo build --locked --release -p zkminer-cli
```

The workflow splits step 3 (`ASSEMBLE_BUILD_ONLY=1`, prune, then `ASSEMBLE_SKIP_BUILD=1 AOT_ARCHES=none`)
to fit the runner's 14 GB disk, and runs `scripts/ci/macos-cpu-tests.sh` in a second job.

Notes:

- `NVCC=off HIPCC=off` and `-j >= 4` are set by Makefile.mac. When cargo is called directly, set them
  yourself (`-j 1..3` can deadlock the -sys build scripts on cargo's jobserver).
- Never set `RISC0_SKIP_BUILD`: it embeds empty guest ELFs.
- risc0-build strips every `CARGO*` variable from the guest builds, so the guests' crates go to
  `$HOME/.cargo`, not `$CARGO_HOME`. Cache both on CI.
- The guest image ids depend on the build host's `$HOME`, because cargo registry paths end up in
  the guests' panic messages. A build under a different `HOME` gives different benchmark-guest
  image ids, for example `05bd9ebe…5169` for memory-merkle here and `49b4b5a1…a331` with the fresh
  `HOME`. Nothing compares these ids to a fixed value (they are benchmark and test programs; mining
  jobs bring their own ELFs), and receipts from either build verify.
- The Metal compiler version is part of the kernel cache key and of what the GPU runs. The validated
  binaries were built with Metal toolchain 27B47 (`Apple metal version 32023.922`), which step 1
  fetches; `assemble-macos.sh` refuses metallibs from any other compiler unless
  `METAL_COMPILER_UNVALIDATED=1` (then `BUILDINFO` says `metal_compiler_validated=no`, which
  `release.yml` refuses).
- The runner most likely has no usable Metal GPU, so it can build but not run the worker's GPU tests,
  the benchmark, or the AOT archive build (whose dump tests load the kernels on the device).

## Local development against a risc0 checkout

Cargo.toml is never edited for this. Two ways:

```sh
# Recommended: Makefile.mac. RISC0_SRC=auto (the default) picks `local` when $(RISC0_DIR) holds a risc0
# checkout (default ../deps/risc0-3.1), else `git`.
make -f Makefile.mac RISC0_SRC=local RISC0_DIR=/path/to/risc0 mac-build-worker

# Plain cargo (paths relative to this repository: ../deps/risc0-3.1):
cargo --config .cargo/risc0-local.toml build --release -p zkminer-prove-risc0 --features metal --bin zkminer-prove-risc0-metal
```

The committed `Cargo.lock` always records the git rev. A path patch changes 20 entries of it: the
risc0 crates lose their `source` line, and the zkrs crates become the checkout's path crates. In
local mode, Makefile.mac derives that local form from the committed lock (an awk filter; the
B9-DEP note shows it is byte for byte what cargo writes). It swaps the local form in for the recipe,
runs cargo `--locked`, and moves the committed lock back on exit, so the working tree stays clean. A
checkout whose dependency graph differs from the pinned rev fails `--locked`: use
`RISC0_LOCAL_LOCKED=0` for that, and expect cargo to re-resolve those entries. Plain
`cargo --config .cargo/risc0-local.toml` rewrites `Cargo.lock` in place. Run `git checkout Cargo.lock`
before committing. In local mode cargo warns that the two zkrs patches are unused. That is expected,
because the checkout's own zkrs crates are used (with their LFS content, so the checkout needs
`git lfs pull`).

`mac-test-risc0-*` run the fork's suites inside `$(RISC0_DIR)`, so they need a checkout in both
modes. `mac-build-aot` / `mac-install-worker` build the dump tests in the risc0 tree the worker came
from. In local mode that is the checkout. In git mode it is a copy of cargo's checkout in
`target/aot-risc0-<rev>`, with the two LFS pointers replaced by the crates.io tarballs, each checked
against its pointer's sha256. Cargo's own checkout is never modified.

## Testing the git build before the branch is pushed

Point the git URL at a local mirror. The second rule matters: `https://github.com/hemilabs/risc0` is
a prefix of `https://github.com/hemilabs/risc0-sppark`, and git's `insteadOf` matches prefixes, so
without that rule sppark would be fetched from the mirror and fail.

```sh
git clone --mirror /Users/user/zkminer/deps/risc0-3.1 /Users/user/zkminer/scratch/w9/mirror/risc0.git
CARGO_NET_GIT_FETCH_WITH_CLI=true GIT_CONFIG_COUNT=2 \
  GIT_CONFIG_KEY_0=url.file:///Users/user/zkminer/scratch/w9/mirror/risc0.git.insteadOf \
  GIT_CONFIG_VALUE_0=https://github.com/hemilabs/risc0 \
  GIT_CONFIG_KEY_1=url.https://github.com/hemilabs/risc0-sppark.insteadOf \
  GIT_CONFIG_VALUE_1=https://github.com/hemilabs/risc0-sppark \
  make -f Makefile.mac RISC0_SRC=git mac-build-worker
```
