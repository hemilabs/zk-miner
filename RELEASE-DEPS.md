# Release dependencies (macOS / Metal, risc0 3.1)

What a zk-miner build on this branch takes from outside the repository, how it is pinned, and how
to build it on a clean macOS machine (a CI runner) or against a local risc0 checkout. Item B9-DEP;
evidence in `docs/metal-port-notes/B9-DEP.md`.

## The pins

| what | source | pin |
|---|---|---|
| 17 risc0 crates (`risc0-zkvm`, `-zkp`, `-sys`, `-build`, `-build-kernel`, `-groth16`, `-groth16-sys`, `-circuit-{rv32im,recursion,keccak}` and their `-sys`, `-core`, `-binfmt`, `-zkos-v1compat`, `-zkvm-platform`) | `https://github.com/hemilabs/risc0`, branch **`zkminer/metal-3.1`** | `rev = "d94ef65015f4753c5496ad7302f15c44513370f3"` (`Cargo.toml` `[patch.crates-io]`) |
| `rzup` (risc0-build's toolchain lookup) | same rev, through risc0-build | (follows the rev) |
| `risc0-circuit-recursion-zkrs`, `risc0-circuit-recursion-control-zkrs` | crates.io | `=4.1.0` (`Cargo.toml` `[patch."https://github.com/hemilabs/risc0"]`); `Cargo.lock` checksums `667665b4…6fb5d` and `bc7f8b26…f1667` |
| sppark | `hemilabs/risc0-sppark` | rev `5f68eb3e…` (unchanged) |
| SP1 crates | `hemilabs/sp1` | rev `9a0de746…` (unchanged) |
| guest crates (`crates/zkminer-prover/guests/risc0/*`) | crates.io (`risc0-zkvm` 3.0.5) and the RustCrypto risc0 forks on GitHub | each guest's own `Cargo.lock` (unchanged) |

`d94ef6501` is `/Users/user/zkminer/deps/risc0-3.1` at the end of the Wave 9 phase-1 merges
(`Merge metal/B9-4G`). It contains the release-3.1 port (Wave 8), the 3.1 security fixes (B9-SEC,
merge `abea7c97c`), and the 4 GiB Groth16 wrap (B9-G1 `afb524d8e`, B9-4G `d94ef6501`). **The branch
has to be pushed to hemilabs/risc0 unchanged as `zkminer/metal-3.1`** before anyone outside this Mac
can build: until then `https://github.com/hemilabs/risc0` has no commit `d94ef6501` (checked
2026-11-17 with `git ls-remote`; the repository is public, so no credentials are needed once it is
pushed). If the branch is rebased or amended before the push, the rev in `Cargo.toml` and the 18
`source = "git+…"` lines in `Cargo.lock` must be updated to the pushed sha.

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

Tested on this Mac with a fresh `HOME` and `CARGO_HOME`, no `env.sh`, no Homebrew on `PATH`, no
`~/.risc0/bin` and no RISC Zero C++ toolchain (the B9-DEP note has the exact environment). A GitHub
macOS 26 runner with Xcode needs:

```sh
# 1. Xcode's Metal toolchain. Since Xcode 26 it is a separate download; the build calls
#    `xcrun --sdk macosx metal` and `metallib` (and mac-build-aot calls `metal-tt`).
sudo xcode-select -s /Applications/Xcode.app        # whichever Xcode the runner has
xcodebuild -downloadComponent MetalToolchain
xcrun --sdk macosx metal --version                  # must print "Apple metal version ..."

# 2. Rust: rustup reads rust-toolchain.toml (1.97.1) on the first cargo call.
curl -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain none

# 3. The RISC Zero Rust guest toolchain (risc0-build compiles the 13 benchmark guests at build time).
#    1.97.0 is the version these guests were built and measured with. No C++ toolchain (rzup install
#    cpp) and no Docker are needed.
curl -L https://risczero.com/install | bash          # installs rzup into ~/.risc0/bin
~/.risc0/bin/rzup install rust 1.97.0

# 4. protoc, for risc0-groth16's circom-witnesscalc build script.
brew install protobuf                                # or: export PROTOC=/path/to/protoc

# 5. Build (no risc0 checkout: RISC0_SRC=git, the default when ../deps/risc0-3.1 does not exist).
make -f Makefile.mac RISC0_SRC=git mac-build-worker
#    = cargo build --locked --release -p zkminer-prove-risc0 --features metal --bin zkminer-prove-risc0-metal
#      cargo build --locked --release -p zkminer-cli
```

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
  binaries were built with Metal toolchain 27B47 (`Apple metal version 32023.922`). A runner's Xcode 26
  compiler is a different build: see the open issue in the B9-DEP note before shipping a CI-built
  binary without an on-hardware check.
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
