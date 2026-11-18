# zkminer

Multi-zkVM, multi-GPU-vendor ZK proof generator for Hemi's ZK proving marketplace
(HemiProve).

zkminer watches the marketplace for open proving jobs, estimates whether each one is
worth taking, claims the ones that are, generates the proof on a local GPU, and submits
it on-chain. Proving runs in separate worker processes — one per GPU — so a wedged or
OOM-killed prover can't take the miner down with it.

Backends: **RISC Zero** (CUDA, ROCm, Intel, and Metal on Apple Silicon Macs) and **SP1**.
**OpenVM** is experimental: its worker builds and starts, but the miner claims no OpenVM job
unless `ZKMINER_ENABLE_OPENVM=1` is set, so leave `zkminer-prove-openvm` out of an install.
`zkminer doctor` shows, card by card, what this host can prove, and why not.

## Requirements

| | |
|---|---|
| Rust | 1.97.1 (pinned in `rust-toolchain.toml`) |
| RISC Zero toolchain | `rzup`, see below — **required to build, and to prove** |
| CUDA | toolkit with `nvcc` (12.8–13.x tested) for NVIDIA workers |
| ROCm | 6.4+ with `hipcc` for AMD workers |
| Metal | macOS on Apple Silicon: the Metal shader compiler (`xcrun --sdk macosx metal`), see [macOS](#macos-apple-silicon-metal) |
| oneAPI | DPC++/C++ compiler `icpx` (2026.0 tested) and `ocloc` (the `intel-ocloc` package, the same version as the installed compute runtime) for Intel workers; at run time the Level Zero loader, the compute runtime and `intel-ocloc` |
| Build deps | `build-essential cmake pkg-config protobuf-compiler libclang-dev` (+ `libhipcub-dev librocthrust-dev` for ROCm) |
| Foundry | `cast` — only for the example job submitters under `examples/` |

### RISC Zero toolchain (easy to miss)

Building needs `rzup`'s Rust toolchain for the guest ELFs (without it, cargo build fails):

```bash
curl -sSL https://risczero.com/install | bash
export PATH="$HOME/.risc0/bin:$PATH"
rzup install rust
```

Running needs RISC Zero's `risc0-groth16` component, version 0.2.0 for risc0 3.1 (the Groth16
proving key of the 2026-10-20 setup; 5.8 GB installed), but not `rzup`: the risc0 worker installs
it in its one-time setup, before the miner claims any risc0 job, when
`~/.risc0/extensions/v0.2.0-risc0-groth16` (or `RISC0_GROTH16_DIR`) does not hold it. It downloads
the 2.4 GB archive rzup itself uses from RISC Zero's artifact store and checks its SHA-256
(`crates/zkminer-prove-risc0/src/groth16_component.rs`). `rzup install risc0-groth16` installs the
same files. risc0 3.1 refuses the 3.0 component (`v0.1.0-risc0-groth16`), which can be deleted.

### risc0 3.1 and the on-chain verifier

zk-miner builds against risc0 **3.1** (risc0-zkvm 3.1.0, risc0-groth16 3.0.6,
risc0-circuit-recursion 4.1.0; the GHSA-g6qg-9j8p-7j87 circuit and verifier fixes). Its Groth16
seals carry the selector `0xe71e6620` and go on chain as risc0-ethereum-contracts 3.1.0's
`encode_seal` makes them: 260 bytes, the selector then the 256-byte proof. The HemiProve deployment
of 2026-11-16 on Hemi testnet (743111) verifies exactly these: its `risczero.groth16.v1` adapter wraps
a risc0-ethereum v3.1.0 `RiscZeroGroth16Verifier` (`SELECTOR()` `0xe71e6620`). risc0 3.0 receipts
(selector `0x73c457ba`) are refused there, and zkminer refuses to claim risc0 jobs with a 3.0
selector (`prover.risc0_groth16_selector` left over in an old config: remove it).

On macOS the Groth16 wrap runs natively on the Metal GPU (no Docker, no x86 host). risc0 falls back
to its Docker prover only if Metal is unavailable or one of `RISC0_METAL=0`,
`RISC0_METAL_SKIP=groth16` or `RISC0_GROTH16_METAL_PROVER=docker` is set: do not set them.

Before claiming any risc0 job, `zkminer run` checks the chain end to end: the adapter and verifier
code against their pins, `SELECTOR()` against the build's selector, and an `eth_call` of
`Registry.verifyProof` with a known-good risc0 3.1 receipt from the Metal worker
(`zkminer_chain::deployment::risc0_preflight`; `ZKMINER_SKIP_RISC0_RECEIPT_PREFLIGHT=1` skips that
call).

Workers and the CLI must come from the same tree: the CLI refuses a worker with another protocol
version or another risc0 (`risc0-zkvm 3.0.x`) at the handshake.

## Build

```bash
cargo build --release -p zkminer-cli        # the CLI; no GPU toolchain needed
```

A miner that serves witness jobs (`[witness] enabled`) also runs four binaries from the CLI's own
directory (`target/release` here): the sandbox probe its self-test runs, the builder and broker
sandboxes, and the risc0 CPU worker that executes requesters' guests. Each is built on its own, so
no feature of one reaches another:

```bash
cargo build --release -p zkminer-witness-sandbox --bin zkminer-witness-sandbox-probe
cargo build --release -p zkminer-witness-builder --bin zkminer-witness-builder
cargo build --release -p zkminer-witness-broker --bin zkminer-witness-broker
env NVCC=off HIPCC=off cargo build --release -p zkminer-prove-risc0 --features cpu \
    --bin zkminer-prove-risc0-cpu
```

GPU prover workers are separate binaries, built with the toolchain for their vendor:

```bash
# NVIDIA. NVCC/HIPCC must be set explicitly: sppark's build.rs resolves them with
# which::which(), not PATH. Set the other to "off" so it isn't auto-detected.
env NVCC=/usr/local/cuda/bin/nvcc HIPCC=off \
    NVCC_APPEND_FLAGS="--expt-relaxed-constexpr -gencode arch=compute_120,code=sm_120" \
    cargo build --release -p zkminer-prove-risc0 --features cuda \
                --bin zkminer-prove-risc0-cuda --target-dir target/release-cuda

# AMD. Use a SEPARATE --target-dir from the CUDA build to avoid lock contention.
env HIPCC=/opt/rocm/bin/hipcc NVCC=off RISC0_HIP_ARCH="gfx1100" \
    cargo build --release -p zkminer-prove-risc0 --features rocm \
                --bin zkminer-prove-risc0-rocm --target-dir target/release-rocm

# Intel (Arc / Data Center GPUs, through SYCL on Level Zero). Source oneAPI first; name your
# cards' ahead-of-time targets (intel_gpu_bmg_g21 = Arc B580/B570, intel_gpu_bmg_g31 = Arc Pro
# B60/B70; the default adds spir64 and a second, slower build for others).
source /opt/intel/oneapi/setvars.sh
env NVCC=off HIPCC=off RISC0_INTEL_SYCL_TARGETS=intel_gpu_bmg_g21 \
    cargo build --release -j 4 -p zkminer-prove-risc0 --features intel \
                --bin zkminer-prove-risc0-intel --target-dir target/release-intel
scripts/stage-intel-worker-libs.sh target/release-intel/release/zkminer-prove-risc0-intel
```

The Intel build takes 1–2 hours the first time (the kernels are compiled ahead of time with
`ocloc`) and needs about 11 GB of RAM at `-j 4`. `scripts/stage-intel-worker-libs.sh` copies the
libraries the worker needs and the system lacks (the risc0 kernel libraries the build leaves in
its target dir, and oneAPI's SYCL runtime) into `zkminer-intel/lib/` beside the binary, which the
binary looks in first; it then runs without `LD_LIBRARY_PATH`.

Each `-gencode` adds a GPU family the worker can run on, so name your card's. The miner
reads which families a worker binary carries (for SP1, its `sp1-gpu-server`) and will not
start it on a card that has none of them, logging why. `Dockerfile.build` lists the
families the release builds.

Never set `RISC0_SKIP_BUILD=1` — it produces empty guest ELF stubs, and every
benchmark then silently reports zero work.

`make` wraps portable Docker builds: `make cli | cuda | rocm | sp1 | openvm | all | test`.
On a Mac, `make -f Makefile.mac` builds, tests and installs the Metal worker natively, see
[macOS](#macos-apple-silicon-metal).

## Install the workers

The miner looks for worker binaries in `~/.zkminer/provers/` under exact names. **The
directory is hand-managed: a missing binary means that backend is silently skipped, with
no error.**

```
~/.zkminer/provers/
├── zkminer-prove-risc0-cuda
├── zkminer-prove-risc0-rocm
├── zkminer-rocm/               (ROCm 7.1's HIP runtime, which the risc0 AMD prover loads)
├── zkminer-prove-risc0-intel
├── zkminer-prove-risc0-metal    (macOS, Apple Silicon)
├── zkminer-intel/              (the Intel provers' libraries and Intel's compute runtime)
├── zkminer-prove-sp1
├── sp1-gpu-server
├── sp1-gpu-server-hip
├── sp1-gpu-server-hip-lib/    (ROCm 10.1's HIP runtime, which SP1's AMD server loads)
├── sp1-gpu-server-sycl
├── sp1-gpu-server-sycl-lib -> zkminer-intel/lib
├── libcudart.so.12
├── libcudart.so.12.LICENSE.txt
└── zkminer-prove-openvm          (experimental, not mined: leave it out)
```

**From a release**, put the single-file provers there and unpack the AMD or Intel tarball into the
same directory (`tar --zstd -xf zkminer-provers-amd-linux-x86_64.tar.zst -C ~/.zkminer/provers`).
`zkminer` goes elsewhere (`~/.zkminer/zkminer`, or a directory on your `PATH`), with the four witness
binaries beside it: `zkminer-witness-sandbox-probe`, `zkminer-witness-builder`,
`zkminer-witness-broker` and `zkminer-prove-risc0-cpu`. A miner serving witness jobs looks for them
in its own directory, and without them serves none, saying which is missing. Each
prover carries the GPU runtime it loads, so a host needs only its GPU's driver: NVIDIA's driver for
RTX cards, and for AMD (Radeon RX 7000 and 9000) and Intel (Arc A and B) cards just the kernel
driver every distribution ships (amdgpu; i915 for Arc A, xe for Arc B): no CUDA toolkit, ROCm or
oneAPI install, and a ROCm the distribution has is not used. A miner run outside a desktop session
(a systemd unit, SSH) needs its user in the `render` group for AMD and Intel cards
(`sudo usermod -aG render $USER`). The release workflow checks all of this on real GPUs before it
publishes (`.github/workflows/release.yml`).

**SP1** needs three more things, all handled for you:

- `sp1-gpu-server` ships beside `zkminer-prove-sp1`, built from the same hemilabs/sp1 commit as
  the worker. The worker installs it as `~/.sp1/bin/sp1-gpu-server`, where the SP1 SDK runs it
  from; without it the SDK downloads upstream's server, which lacks the fork's GPU fixes. Keep it
  beside the real binary, not a wrapper script. `ZKMINER_SP1_SERVER_INSTALL=0` leaves
  `~/.sp1/bin` alone, for a server you manage yourself.
- `libcudart.so.12`, the CUDA 12 runtime `sp1-gpu-server` links, ships beside it too. The worker
  puts its own directory on the server's library path, so a host needs only the NVIDIA driver,
  whatever CUDA toolkit it has, or none. Without that file the worker looks for a CUDA 12 runtime
  elsewhere (`ZKMINER_SP1_CUDA_RUNTIME_DIR`, a CUDA 12 toolkit, pip's `nvidia-cuda-runtime-cu12`)
  and SP1 declines if there is none. It is NVIDIA's software, under NVIDIA's CUDA EULA rather
  than zkminer's license: see `libcudart.so.12.LICENSE.txt`.
- The Groth16 circuit artifacts (~8 GB, in `~/.sp1/circuits/groth16/`) are downloaded once, when
  the miner starts, before it claims any SP1 job; until then SP1 jobs are skipped. A download cut
  short is detected and redone. Final Groth16 proofs on one host take turns through lock files in
  `~/.zkminer/locks/` (hemilabs/sp1 v6.8.1 and later).

**Intel**: copy `zkminer-intel/` together with `zkminer-prove-risc0-intel`. A release built on a large
CI runner has the kernels compiled in advance for the Arc B580/B570, the B-series Pro cards and the
A770/A750/A580; otherwise, and on any other Intel card, they are compiled for the card on first use,
which took about 8 minutes on an Arc B580. The driver caches them
under `~/.cache/` (`libsycl_cache`, `neo_compiler_cache`) for every later process. The miner warms
each Intel card up with one small verified proof before its first benchmark or proof, outside their
time limits. Discovery reads an Intel card's memory from the xe driver.

**SP1 on AMD and Intel**: put `sp1-gpu-server-hip` (AMD), or `sp1-gpu-server-sycl` with its
`sp1-gpu-server-sycl-lib/` (Intel), beside `zkminer-prove-sp1`, and those cards get SP1 slots too.
Build them from the same hemilabs/sp1 commit as the worker, with `SP1_GPU_BACKEND=hip` and
`HIP_ARCHS` (e.g. `gfx1100`), or `SP1_GPU_BACKEND=sycl`. The HIP server needs ROCm 7.2 or newer:
built against Ubuntu 26.04's ROCm 7.1, its proofs on an RX 7900 XTX fail verification; against
AMD's ROCm 10.1 they verify. Its kernels' device asserts and `printf` also need PCIe atomics
between the card and the CPU; without them (some VM passthrough setups) a launch fails with
"AQL dispatch failed". Where AMD's ROCm is installed beside a distribution's ROCm in `/usr`, point
the build at it explicitly, or the compiler picks up the older HIP headers and runtime:

```bash
# In the hemilabs/sp1 checkout, with the usual SP1 build prerequisites.
R=/opt/rocm/core-10.1
printf 'set(CMAKE_HIP_COMPILER_ROCM_ROOT "%s")\n' "$R" > hip-rocm.cmake
env SP1_GPU_BACKEND=hip HIP_ARCHS=gfx1100 ROCM_PATH=$R HIP_PATH=$R \
    CMAKE_TOOLCHAIN_FILE=$PWD/hip-rocm.cmake HIPCXX=$R/lib/llvm/bin/clang++ \
    HIPFLAGS="--hip-path=$R --rocm-path=$R -isystem $R/include" CXXFLAGS="-isystem $R/include" \
    RUSTFLAGS="-C link-arg=-Wl,--disable-new-dtags,-rpath,$R/lib" \
    cargo build --release -p sp1-gpu-server
```

The rpath matters: ROCm 10.1's `libamdhip64.so.7` has the same name as ROCm 7's, and without it the
loader takes the distribution's. A card both risc0 and SP1 use takes turns: before a proof, the
miner stops the other backend's idle worker if it holds memory the proof needs (SP1's HIP server
keeps all but 2 GB of the card once it has proved). It reads each process's share from the
kernel's DRM fdinfo, as it reads `nvidia-smi` on NVIDIA.

If a worker needs environment the miner's own process won't have (a systemd unit or cron
job does *not* source `~/.bashrc`), install a small wrapper script under the expected
name that sets it up and then `exec`s the real binary — `exec` preserves the PID and
process group the dispatcher relies on.

## macOS (Apple Silicon, Metal)

The RISC Zero worker also runs on Apple Silicon Macs, on the GPU through Metal:
`zkminer-prove-risc0-metal`. It is built from the Metal port of the risc0 3.1 fork, which
`Cargo.toml`'s `[patch.crates-io]` pins by git rev (hemilabs/risc0 branch `zkminer/metal-3.1`:
hemilabs `release-3.1`, risc0 v3.1.0, with the Metal port merged onto it; one pin for every
platform). `make -f Makefile.mac RISC0_SRC=local` builds against a checkout at `../deps/risc0-3.1`
instead (`RELEASE-DEPS.md`). The
segment proofs, the recursion and the Groth16 wrap run on the GPU (two steps still run on the CPU
for now: the rv32im witness generation and the last recursion step before the wrap), and neither
Docker nor a CUDA/ROCm toolkit is involved. SP1 and OpenVM have no Mac worker; the miner never gives an Apple
GPU an SP1 slot.

### Install the beta (prebuilt kit)

The macOS beta ships as `zkminer-<version>-macos-arm64.tar.gz`, built by
`scripts/ci/assemble-macos.sh`. It needs **macOS 26.0 (Tahoe) or later** on an Apple Silicon Mac
with **16 GB or more**. It contains the CLI, the Metal worker, an installer, a
smoke test (`tools/macos-smoke.sh`, run from the kit folder after `./install.sh --with-groth16`) and a
README. It has no offline GPU pipeline archives (its `metal-aot/` is empty). The kit is about
0.2 GB; the Groth16 component adds 5.8 GB (5.4 GiB), and about 8.3 GB must be free while it installs
(its 2.4 GB archive and the unpacked files are on disk together).

```sh
shasum -a 256 -c --ignore-missing SHA256SUMS   # the release's SHA256SUMS, beside the tarball: "...: OK"
tar -xzf zkminer-<version>-macos-arm64.tar.gz
cd zkminer-<version>-macos-arm64
./install.sh                    # ~/.zkminer/zkminer and ~/.zkminer/provers/; --help for options
export PATH="$HOME/.zkminer:$PATH"
zkminer init                    # testnet config; prints the next steps
export ZKMINER_PRIVATE_KEY=0x... # then testnet ETH and tHEMI from the HemiProve team
zkminer stake 100 && zkminer run
```

`zkminer init` is needed once, on the first install (`--with-groth16` or not); it leaves an existing
config alone, so an update needs none. There is no `zkminer --version`:
the kit's `BUILDINFO` names its version and commit, and `zkminer help` lists the commands.

- **Unsigned.** The kit has no Developer ID and is not notarized. Download it only from the GitHub
  release over HTTPS and check its SHA-256 against the release's `SHA256SUMS` before unpacking: the
  kit's own `SHA256SUMS` only catches damage. `install.sh` checks the kit's
  `SHA256SUMS` and removes `com.apple.quarantine` from the files it installs. To run a binary from the
  kit directly, use `xattr -d com.apple.quarantine <file>`, or System Settings → Privacy & Security →
  Open Anyway. Over SSH a quarantined binary hangs without output instead of showing a dialog.
- **Groth16 component.** It is not in the kit (2.4 GB). The worker downloads it at its first warm-up,
  checked against its pinned SHA-256; `./install.sh --with-groth16` fetches it at install time instead.
- **First start.** Every Mac compiles its GPU pipelines once, at the worker's first start: about a
  minute on an M5 Max (60.3 s measured for the beta) and longer on base M1-M4 chips. Later starts
  take about 2.5 s from the cache.

The kit's own `README.md` covers the details for users. Maintainers: see
[docs/macos-beta.md](docs/macos-beta.md) for how the kit is built, why macOS 26, and which GPU
families get archives.

### Supported Macs

| Tier | Hardware | What to expect |
|---|---|---|
| Not supported | Intel Macs; any Mac with 8 GB (including the A18 Pro MacBook Neo); an x86_64 build or a shell under Rosetta | The worker refuses, with the reason in its log: Capabilities reports no GPU, Prove, Warmup and Benchmark answer with the refusal, and `--benchmark` exits 2. Executing guests (job measurement) still works. |
| Minimum | M1–M6 base chip with 16 GB (7–10 GPU cores) | po2 19 at the 8 GiB tier the miner gives it (po2 18 under a 4 GiB budget). Simulated on the M5 Max only, see the limitations below. |
| Primary target | M4/M5 base (10 cores) with 24 GB; M4/M5 Pro with 24–48 GB | po2 19–20 |
| High end | Max (36–128 GB), Ultra | po2 20 |

The worker's check: an aarch64 build, not translated by Rosetta (`sysctl.proc_translated`), a Metal
device with unified memory, and `hw.memsize` of at least 12 GiB (so 8 GB Macs are refused, and a
16 GB Mac is never refused over rounding). It never assumes a core count or a share of RAM: it
sizes everything from the device's `recommendedMaxWorkingSetSize` (about 75% of RAM; 28.1 GiB on a
36 GB M5 Max), lowered by `RISC0_METAL_MAX_WORKING_SET_BYTES` if set and by the miner's own figure
(`hw.memsize` minus an 8 GiB host reserve). Only a 36 GB M5 Max has been measured so far; the rows
for smaller Macs come from budget runs on it.

Default segment size (po2) when the job names none, and what risc0 3.1 measured at that size on
the M5 Max (`--benchmark` of memory-merkle under `RISC0_METAL_MAX_WORKING_SET_BYTES`; Metal peak per
phase, segments / recursion / Groth16 wrap; process peak footprint):

| Working-set limit | po2 | STARK, memory-merkle | Wrap | Peak GPU memory, MiB | Footprint | Typical Mac |
|---|---|---|---|---|---|---|
| < 6 GiB (4 GiB measured) | 18 | 13.9 s (602K c/s) | 1.72 s | 2404 / 2199 / 3944 | 4.9 GB | 16 GB under a ~4 GB budget |
| 6 to < 10 GiB (8 GiB) | 19 | 10.2 s (770K c/s) | 1.74 s | 4738 / 4337 / 5635 | 7.3 GB | 16 / 18 GB |
| ≥ 10 GiB (28.1 GiB) | 20 | 8.35 s (879K c/s) | 1.58 s | 9437 / 9437 / 5635 | 13.2 GB | 24 GB and up |

(The footprint model can keep a smaller po2 than the limit allows on a Mac with little RAM: a
simulated 18 GB Mac proves at po2 19.) `--benchmark` at po2 20 proves main's suite: the discarded
fibonacci warm-up and the five programs (154.5M cycles) in 169.6-171.1 s of STARK (903-911K c/s),
each wrapped in 1.57-1.60 s, then the two zkOP/s scoring proofs of zkop-mix (4.2M and 61.9M cycles,
no wrap) in 73 s: 254 s of wall time (BASELINES '3.1', W10-INT). The worker keeps the
Groth16 proving key loaded between proofs only when the working-set limit holds the largest STARK
phase, the resident key and 12 GiB of host headroom (`keep_groth16_cache` in
`crates/zkminer-prover/src/metal_sizing.rs`: about 29.5 GiB at po2 20), so 36 GB Macs and smaller,
the M5 Max above included, load the key for each wrap and free it after (it logs `Groth16 proving
key released: ... MiB of device memory freed (prover layout ...)` per proof). A po2 larger than
the limit allows is refused as ResourceExhausted instead of being swapped through (`ZKMINER_METAL_NO_PO2_CEILING=1` disables that, for diagnostics only).

### Prerequisites

- Rust from `rust-toolchain.toml`, and RISC Zero's guest toolchain (`rzup install rust`, see
  [above](#risc-zero-toolchain-easy-to-miss)). The fork's own `risc0-zkvm` tests also need the C++
  guest toolchain: `rzup install cpp` (`env.sh` below then points cargo at its archiver).
- The **Metal shader compiler**. The Command Line Tools do not include it. With Xcode 26 or later,
  download it as a component: `xcodebuild -downloadComponent MetalToolchain`. Check with
  `xcrun --sdk macosx metal --version`; the fork's build scripts call exactly that, and stop with a
  hint if it is missing. Release kits are compiled with Metal Toolchain 27B47 (`Apple metal version
  32023.922`), the compiler the beta was validated with: `scripts/ci/fetch-metal-toolchain.sh`
  fetches it (no Xcode needed), and `assemble-macos.sh` refuses metallibs from another compiler
  unless `METAL_COMPILER_UNVALIDATED=1` is set.
  Xcode 26's own component is another compiler build, whose GPU code was never validated
  ([docs/macos-beta.md](docs/macos-beta.md), "Metal compiler").
- Without Xcode (no admin rights, Command Line Tools only), the toolchain can be fetched the way
  Xcode does it; this is how the development machine got it. Apple's downloadable index
  (`index2.dvtdownloadableindex`) maps an Xcode build to its Metal Toolchain build (Xcode 27.2 →
  27B47); Apple's asset server answers a `com.apple.MobileAsset.MetalToolchain` query for that build
  with an encrypted archive and its key (no Apple ID); `aea decrypt` and `aa extract` give
  `MetalToolchain-<build>.dmg`, and a user-level `hdiutil attach -nobrowse -readonly` mounts
  `Metal.xctoolchain`. With its `usr/bin` on `PATH`, `xcrun --sdk macosx metal` finds it (if xcrun
  keeps resolving an old path, `xcrun --kill-cache`). The exact requests are in
  `deps/metal-toolchain/README.md` beside the fork on that machine.
- No Docker, no CUDA, no ROCm. Builds set `NVCC=off HIPCC=off` so sppark looks for neither.

### env.sh

Source one small script before any cargo command. `Makefile.mac` sources it for you, from
`ENV_SH` (default: `env.sh` in the directory that holds `zk-miner/` and `deps/`). On the
development machine it is:

```bash
# ~/zkminer/env.sh
export PATH="$HOME/.cargo/bin:$HOME/.risc0/bin:$PATH"
# Metal shader compiler mounted from the toolchain dmg (skip this block if Xcode's component is installed).
METAL_TC="$HOME/zkminer/deps/metal-toolchain/mnt/Metal.xctoolchain"
if [ ! -x "$METAL_TC/usr/bin/metal" ]; then          # remount after a reboot
  hdiutil attach -nobrowse -readonly -mountpoint "$HOME/zkminer/deps/metal-toolchain/mnt" \
      "$HOME/zkminer/deps/metal-toolchain/MetalToolchain-27B47.dmg" >/dev/null || echo "WARN: could not mount Metal toolchain dmg" >&2
fi
export PATH="$METAL_TC/usr/bin:$PATH"
# The C++ guest crates (the fork's risc0-zkvm tests) need RISC Zero's riscv32 archiver; without it
# their link fails with undefined blst_* symbols.
_R0_AR="$(ls -d "$HOME"/.risc0/toolchains/*-cpp-aarch64-apple-darwin/riscv32im-osx-arm64/bin/riscv32-unknown-elf-ar 2>/dev/null | tail -1)"
[ -n "$_R0_AR" ] && export AR_riscv32im_risc0_zkvm_elf="$_R0_AR"
```

Never set `RISC0_SKIP_BUILD` (the Makefile refuses to run with it).

### Build, test, install: `Makefile.mac`

```bash
make -f Makefile.mac mac-check            # this Mac and its toolchains, then cargo check
make -f Makefile.mac mac-build-worker     # target/release/zkminer-prove-risc0-metal and zkminer
make -f Makefile.mac mac-install-worker   # into ~/.zkminer/provers, then warm the GPU pipelines
make -f Makefile.mac mac-test-miner       # zk-miner's macOS tests
make -f Makefile.mac mac-test-risc0       # the fork's Metal conformance suites
make -f Makefile.mac mac-bench BENCH_ONLY=fibonacci
```

| Target | What it runs | Time on a 36 GB M5 Max (warm caches, other work running) |
|---|---|---|
| `mac-check` | prerequisite checks (the worker's own refusal rules, the Metal compiler, rzup toolchains, the Groth16 component, the fork), then `cargo check` of the Metal worker and the CLI | ~4.5 min from an empty target dir |
| `mac-build-worker` | `cargo build --release` of `zkminer-prove-risc0-metal` (`--features metal`) and `zkminer-cli` | ~6 min from an empty target dir (with the compiled Metal libraries already in the risc0 build cache, `~/Library/Caches/com.risczero.RISC-Zero.risc0`; a machine's first build also compiles those); ~35 s with nothing changed (the worker's build script always reruns) |
| `mac-install-worker` | copies the worker into `PROVERS_DIR` (default `~/.zkminer/provers`; copy then rename, so a running worker is never modified in place), then proves fibonacci once with it to warm the pipelines (`WARM=0` skips) | ~1 min warm; add the cold warm-up below on a new machine |
| `mac-test-miner` | the worker's unit tests, `zkminer-prover` `discovery::`/`dispatcher::`, and the real worker over its IPC protocol: Capabilities, Warmup (pipelines + a verified Groth16 proof), one Prove (`MINER_IPC=0` skips this one) | ~4 min |
| `mac-test-risc0` | in `RISC0_DIR`: `risc0-zkp` `hal::metal`, `risc0-circuit-rv32im` `prove::`, `risc0-circuit-recursion`, `risc0-circuit-keccak`, `risc0-groth16-sys` and `risc0-groth16`; each also alone as `mac-test-risc0-{zkp,rv32im,recursion,keccak,groth16}` | ~5 min once built |
| `mac-bench` | builds, then `zkminer-prove-risc0-metal --benchmark` (the miner's suite: a discarded fibonacci warm-up, the five programs, then the zkOP/s scoring proofs; about 4.2 min (254 s) at po2 20; `BENCH_ONLY=<program>` runs the warm-up and that program) | ~1 min for fibonacci (the warm-up alone) |

Every target sources `env.sh`, sets `NVCC=off HIPCC=off`, passes `--locked` (never `cargo update`,
see [Layout](#layout)), and builds with `-j` = `CARGO_BUILD_JOBS` if set, else the number of
performance cores, never below 4. Override `ENV_SH`, `RISC0_DIR`, `PROVERS_DIR` or `JOBS` on the
make command line. `zkminer benchmark` drives the installed worker the way the miner does.

### First start: building the GPU pipelines

Metal compiles each kernel for the GPU the first time a process creates its pipeline, and the
translated circuits are large. With no cache at all (`MTL_SHADER_CACHE_SIZE=0 RISC0_METAL_ARCHIVE=0`)
the worker's warm-up took **242 s** on the M5 Max while other builds ran (four circuits in parallel:
rv32im+zkp 242 s, groth16 188 s, recursion 108 s, keccak 59 s); with the caches warm it takes 0.1 s.
The compile runs on the CPU, so a base chip with fewer cores takes longer (not yet measured).

The results are kept in the OS Metal shader cache (per user, shared with every app, can be
evicted) and, for keccak, in a binary archive of the worker's own under
`~/Library/Caches/com.risczero.RISC-Zero.risc0/metal-archives` (`RISC0_METAL_ARCHIVE_DIR` moves it).
A new build of the worker only recompiles what changed. The worker builds every pipeline in its
Warmup, which the miner sends once, before the worker's first benchmark or proof and outside any
job's deadline (it allows the warm-up an hour); `mac-install-worker` does the same at install time.

### Groth16 without Docker

The Metal worker wraps STARKs in Groth16 natively on the GPU (no Docker, no x86 emulation). It needs
RISC Zero's `risc0-groth16` component, which it downloads in its one-time setup like the other
workers (`~/.risc0/extensions/v0.2.0-risc0-groth16`, or `RISC0_GROTH16_DIR`). A wrap takes
1.58 s on the M5 Max (1.72-1.74 s under a 4 or 8 GiB budget) and peaks at 5.6 GB of GPU memory
(3.9 GB under a 4 GiB budget, where the prover takes its smallest layout); the worker keeps the
~4.1 GB proving key loaded between proofs only when the working-set limit has room for it beside a
full STARK and 12 GiB of host state (about 29.5 GiB at po2 20, so not on 36 GB Macs and
smaller). `RISC0_GROTH16_METAL_PROVER=docker` switches to RISC Zero's Docker prover. The CPU-only
worker (`--features cpu`) has no native wrap and needs Docker for it.

### Environment knobs

Read at run time by the worker (they pass through the miner's environment):

| Variable | Effect |
|---|---|
| `RISC0_METAL_MAX_WORKING_SET_BYTES` | A GPU memory budget below `recommendedMaxWorkingSetSize`, in bytes or with a `K`/`M`/`G`/`T` suffix (`8G`, `4GiB`). The worker picks its default po2 and its po2 ceiling from it, and every Metal allocation that would exceed it fails early with "Metal working-set budget exceeded" (a Prove then answers ResourceExhausted) instead of pushing the Mac into swap. Use it to leave the owner room on a shared Mac. Under 4 GiB no Groth16 wrap fits. |
| `RISC0_METAL_RV32IM_GPU_PHASES=witgen` | Run the rv32im witness generation on the GPU. **Off by default**: the generated GPU witgen kernel is not deterministic on real segments (a proof made with it can fail verification); the default runs that phase's CPU kernel over the GPU buffers and the rest (accum, eval_check, NTTs, hashing) on the GPU. For debugging that issue only. |
| `RISC0_METAL_RV32IM_CPU_PHASES` | Comma list of `witgen`, `accum`, `eval`: run those rv32im phases' CPU kernels over the GPU buffers (wins over `..._GPU_PHASES`). Diagnostics. |
| `RISC0_METAL=0`, `RISC0_METAL_SKIP=<units>` | Disable Metal entirely, or for some of `zkp`, `rv32im`, `recursion`, `keccak`, `groth16` (comma list); those fall back to the CPU prover (groth16: Docker). Diagnostics. |
| `RISC0_GROTH16_METAL_PROVER=docker` | Use the Docker Groth16 prover. |
| `RISC0_GROTH16_DIR` | Directory holding the `risc0-groth16` component. |
| `RISC0_KECCAK_METAL_WITGEN` | `auto` (default: GPU from po2 13), `gpu`, or `host` (the CPU's witness generator). |
| `RISC0_METAL_REC_KERNELS` | `monolith` (default) or `split`: which recursion eval_check kernels to use. |
| `RISC0_METAL_ARCHIVE=0`, `RISC0_METAL_ARCHIVE_DIR` | Disable or move the keccak pipeline archive. |
| `RISC0_METAL_DEBUG=1` (with `MTL_DEBUG_LAYER=1`) | Metal API validation and extra checks; slow, for debugging. |
| `ZKMINER_METAL_PREWARM_KECCAK` | `auto` (default): build the keccak pipelines at start unless the Groth16 prover would then not fit the limit beside them (it fits from 4 GiB up); `on` / `off` force it. |
| `ZKMINER_METAL_NO_PO2_CEILING=1` | Let a po2 above what the working-set limit allows run anyway. Diagnostics. |
| `ZKMINER_CUDA_VRAM_BYTES` | Set by the miner for each Mac worker (`hw.memsize` − 8 GiB); also caps the worker's limit. |

### Known limitations

- **Not yet run on a real 16 GB Mac.** The 16 GB rows above come from budget runs on a 36 GB M5 Max
  (`RISC0_METAL_MAX_WORKING_SET_BYTES`, and `ZKMINER_METAL_HOST_RAM_BYTES` for the footprint model);
  a simulated 16 GB Mac proves memory-merkle at po2 19 with a 7.4 GB process footprint. Fewer GPU
  cores and less memory bandwidth will make it slower than these numbers.
- Under a 4 GiB budget every job wraps, keccak jobs included (since risc0 B9-4G the Groth16 prover
  plans 3885 MiB there and leaves ~150 MiB of headroom beside the worker's pipelines). It relies on
  the worker freeing the key after each proof; two wraps with the key kept do not fit.
- **Beta.** The Mac build is a beta. It is unsigned (no Developer ID, not notarized), so Gatekeeper
  blocks a downloaded binary until its quarantine flag is removed. The kit's `install.sh` removes it,
  and building the worker yourself avoids it.
- The rv32im GPU witness generation is disabled by default (see the knob above).
- The benchmark takes about 4.2 minutes at po2 20 on an M5 Max for `--benchmark` (254 s of wall
  time) and 4.4-5.2 minutes for `zkminer benchmark` with its warm-up (262-314 s), longer on smaller
  Macs.
- GPU power is not read on macOS; the miner's cost model assumes its 300 W default.

## Configure

Copy or write `~/.zkminer/config.toml`:

```toml
[chain]
rpc_url  = "https://testnet.rpc.hemi.network/rpc"
chain_id = 743111                   # Hemi testnet (43111 is mainnet)

[contracts]                         # Hemi testnet, HemiProve deployment of 2026-11-16
hemi_prove          = "0xD931725db336B57dBB9A3123F2238A4FE3c6Ed58"   # router (diamond proxy)
hemi_prove_staking  = "0xF3498fCF729Eb7d4E0323880e4E6aD1EB6da2e2D"
hemi_prove_registry = "0xA80D9172931521f9bce0491C6374A5f28e79f10F"
hemi_token          = "0x46955EdCF61b23a8c0b0d71428A9F1C07Bbf36cc"   # tHEMI (owner-minted)
program_registry    = "0xeBB9Fb9B82f80518f74725eFc2f3FD24ded7695D"   # where programs' ELF sources are read

[wallet]
key_source  = "env"                 # reads $ZKMINER_PRIVATE_KEY
key_env_var = "ZKMINER_PRIVATE_KEY"

[prover]
max_concurrent_proofs = 0           # 0 = one proof per detected GPU
skip_benchmark_gate   = true

[egress]                            # optional
deny_cidrs = ["203.0.113.0/24"]     # the rest of your fleet, your VPC's ranges
```

`zkminer init` will scaffold a config, but **verify the contract addresses it writes
against the deployment you intend to use** before running against a live market. On a
chain zkminer knows (743111), `run` checks the addresses, their wiring and their code
against the live deployment; a mismatch starts the miner without claiming anything (it
still drives locks it already holds) and logs a `PAGE:` line naming the difference, so
fix `[contracts]` and restart. On 743111 the live deployment is the 2026-11-16 one (router
`0xD931725db336B57dBB9A3123F2238A4FE3c6Ed58`, risc0 3.1 verifier). Log scans start at block
7226094, the deployment's first block (`chain.scan_from_block`).

Every older 743111 stack is abandoned. A config that still names the 2026-10-29 stack (router
`0xE1a492Dc6D57fCC2B6deb5B64087E69666cA470e`) or the old free-mint tHEMI
`0x60525eEBB1BD630Fb093d433675E28221DE1E698` is refused as abandoned, even with `ZKMINER_ALLOW_UNKNOWN_DEPLOYMENT=1`:
rewrite it with `zkminer init --network testnet --force`.

The code pins (`crates/zkminer-chain/src/deployment.rs`) are the contracts repo's
`script/lib/ReleaseCorePins.sol` and `VerifierPins.sol` at 3bc441d (8e1808b); `ZKMINER_CONTRACTS_REPO=<checkout>
cargo test -p zkminer-chain --lib the_pins_match_the_contracts_repo` checks them against those files.

### Network guard: `[egress]` and `[dev]`

Anyone can register a program and post a job, so the URLs a miner downloads programs from
are chosen by strangers. zkminer only ever connects to **public internet** addresses on
their behalf: never loopback, the LAN, link-local or cloud metadata, this host's own
addresses (its public address behind NAT included, which it learns from fixed reflectors), a
neighbour on a network it is connected to or routes to other than through its default route
(the kernel is asked, per destination and port, how it would route the connection, policy rules
included), an address a `local` route delivers to this host, the rest of its IPv6 site (a /32)
or of the IPv4 /16 around a public address on its interfaces, the DNS servers it uses, a
private address behind NAT64, a destination within 2 hops of this host (its router, a neighbour
in the same VPC: hop-limited probes ask right before each connection, and a destination is taken
as farther only when a router past the limit says a probe ran out of hops, never on silence), or a name
only a local resolver answers (`localhost`, `*.local`, `*.internal`, `*.lan`, single-label
names, …). Requester host names are resolved over DNS-over-HTTPS by public resolvers, never
through this host's own resolver. Anycast service addresses (`2001:1::/32`, AMT, AS112) are
refused too. See [SECURITY.md](SECURITY.md) for exactly what is refused and why.

It **fails closed**: while this host's public address of a family it routes is unknown
(outbound DNS and HTTPS to the reflectors blocked or intercepted), no requester connection goes
out over that family, and the miner says so at startup, when it changes, and in `zkminer status`;
`[egress] public_addresses` fixes it. A host with a public IPv4 address on an interface (a campus,
a data centre) or a default route through a tunnel (a full-tunnel VPN) does not start in public
mode until `[egress] internal_ranges` lists its own network's ranges (`[]` if there are none),
and stops making requester connections if that happens later (a VPN that comes up).

Run the miner with the host's network (`--network host` in a container): inside a container
it sees only the container's interfaces and routes, so list the host's networks and addresses
in `[egress] deny_cidrs` if it cannot.

**macOS.** The guard makes the same decisions on a Mac, unprivileged: the routing table comes
from the BSD routing socket's sysctl (what `netstat -rn` shows), the kernel is asked per
destination with an `RTM_GET` (what `route -n get` shows), and the near-hop probes follow the
same rule as on Linux: the routers' ICMP "time exceeded" is read from an unprivileged ICMP socket
and matched to its probe by addresses, ports and initial sequence number, which macOS gives only
through a private `TCP_INFO` option (a Mac where either cannot be read refuses every requester
connection, and says so once at startup). macOS has no
policy-routing rules; its interface-scoped routes (netstat's `I` flag, such as the system's
`utun` interfaces' IPv6 defaults) carry no ordinary connection, so they are neither default
routes nor uplinks, and a connection whose socket would leave by another interface than its
route names (a Network Extension VPN) is refused. A `utun` or `ppp` default route needs
`[egress] internal_ranges`, as a tunnel does on Linux. Details and residual differences:
[docs/netguard-macos.md](docs/netguard-macos.md). Windows still refuses every requester
connection in public mode (no route oracle there).

*Troubleshooting (macOS):* if every requester connection is refused with `this host's network
facts ... could not be read again`, the message names what failed. A file in `/etc/resolver`
that this user may not read (`Permission denied`) or that is larger than 1 MiB stops the guard,
because the system reads that file's DNS servers and the guard must refuse them: make it
readable (`sudo chmod 644 /etc/resolver/<name>`) or remove it. A symbolic link there that loops
is skipped with a warning. `the system configuration daemon did not answer` means `configd` is
not responding (restarting the Mac clears it). Every requester connection refused as near
(`within 2 hops ... accepted a connection`) while a VPN app is on that adds no `utun` route
points to a Network Extension proxy VPN (flow divert, app proxy): it is expected to accept every
connection itself, so every probe connects, and the guard cannot see past it.
`this kernel refused a route query sent as RTM_GET_SILENT` means the macOS version lacks a
routing-socket call the guard needs (none known among those the miner supports).

*Troubleshooting (Linux and macOS):* the hardening the macOS reviews added applies on every
platform ([docs/netguard-hardening.md](docs/netguard-hardening.md)). If every requester
connection is refused with `this host's network facts ... could not be read again`, the message
names what failed (on Linux a netlink read: the interfaces, routes, rules). A download refused
with `could not tell how near ... is (whether it is within 2 hops of this host): no router past 2
hops said a probe ran out of hops (a time exceeded), and silence is not taken as far (...)` comes
from a path whose routers at hops 2 to 4 sent no ICMP "time exceeded" for the probes (they filter
or rate-limit ICMP, as many cloud and corporate networks do, or the destination was down): the
guard admits a destination only on that evidence, so it refuses. Another attempt usually gets the
evidence on a rate-limited path; on a host whose first hops never send ICMP, every destination is
refused every time (cloud servers such as EC2 are not supported for now). This applies to every
store alike, AWS S3 included: from a path whose routers send ICMP, S3 is judged by distance like
any other server. Right after a host with IPv6
and no IPv4 (or IPv4 only through a CLAT, 464XLAT) joins a network, IPv6 destinations are refused
for up to 2 s (`NAT64 prefix is still being learned`); on any host they are refused while the
network names NAT64 prefixes the guard does not believe or cannot hold (more than two in one DNS
answer, more than four live ones in one router's advertisements): the refusal names the source,
and it clears as soon as that source names what fits (a router's next advertisement replaces what
it named before, and a PREF64 lifetime is believed for 30 minutes at most). Withdrawn, expired
and other networks' prefixes stay refused for an hour, then are forgotten; if a network names so
many that one withdrawn less than an hour ago must make room, IPv6 is refused there until that
hour ends. Once a forger on the network stops, such a refusal ends within about 95 minutes (one
forged advertisement: at the real router's next one). `its public ... address there is being
learned again` follows a move to another network (on Linux also a default gateway that shows
another link-layer address, until it shows the known one again or the new one holds; or a
gateway whose neighbour entry is gone and does not come back when asked): it clears by itself
within seconds. `the connection to ... was dropped
once made` means the route changed between the check and the connection (a VPN coming up): the
next attempt is judged on the new route.

**Witness jobs.** The witness broker, which talks to your `[[evm_rpc]]`, mirror and artifact
endpoints for builders, has no network of its own: its sandbox denies every socket call. The
miner's *connector* makes each connection for it — the broker can only name one of the endpoints
in its config file, which the miner reads itself — and admits the address with this same guard
(the near-hop probe right before connecting included), using the miner's `[egress]` settings (the broker file's `[egress] deny_cidrs` are added to
them) and the miner's `[dev] private_network`. So a broker an attacker took over still reaches
only your configured endpoints. See SECURITY.md, "Witness jobs: the broker".

Give each chain two `[[evm_rpc]]` endpoints on independent nodes (distinct host and port) if you
can. When a builder asks for a block or state an endpoint lacks, two independent endpoints that
both lack it make the answer final, and so does one whose head is fresh (its latest block stamped
within `head_fresh_secs`, default 36 s; set a few of the chain's block times): the builder is then
judged on its own exit. With one endpoint per chain whose head is stale, the lag is unconfirmed and
the job is retried unblamed (up to 6 times) when its builder gave up or trapped.

| key | default | meaning |
|---|---|---|
| `[egress] deny_cidrs` | `[]` | More addresses no requester-caused connection may reach: CIDRs (`"203.0.113.0/24"`, `"2001:db8::/32"`) or bare addresses. Name the rest of your fleet and, on a cloud host, your VPC's IPv6 range (its other subnets have global addresses and are reached through the default route). Host bits must be zero. |
| `[egress] internal_ranges` | unset | The ranges of your own network this host reaches by the same route as the internet: a campus's or data centre's public ranges, your VPC's, what a full-tunnel VPN leads to. Refused like `deny_cidrs`. **Required** (`internal_ranges = []` states there are none) on a host with a global IPv4 address on an interface or an uplink that is not plainly physical: a default route out of anything but a NIC, bridge, bond, team, VLAN, macvlan, ipvlan, veth or VRF (so any tunnel or VPN, and `ppp` unless it is a PPPoE session), a default route in a routing table other than `main` (strongSwan's table 220), or one through a nexthop object whose interface cannot be read. In public mode the miner refuses to start without it, naming the reason; when such a condition appears later (a VPN that comes up after startup), every requester-caused connection is refused until it is set or the condition clears. |
| `[egress] ipv6_site_prefix_len` | `32` | The site refused around each of this host's global IPv6 addresses: its enclosing /N, 16 to 64. The default is the `/32` an organisation usually holds; it also refuses the rest of your own ISP's `/32` over IPv6 (a name there that also has an IPv4 address still connects over IPv4). Set 48 or 56 if your site is no wider and that is in the way. |
| `[egress] ipv4_site_prefix_len` | `16` | The site refused around each global IPv4 address on this host's interfaces: its enclosing /N, 8 to 32. |
| `[egress] discover_public_addresses` | `true` | Learn this host's public addresses (behind NAT) at startup and every 5 minutes from fixed reflectors — `ns1.google.com` and `1.1.1.1` over DNS, and Cloudflare's `https://1.1.1.1/cdn-cgi/trace` over HTTPS (also over IPv6, and on an IPv6-only host through its NAT64 prefix) — and refuse every address any reports. A family counts as known only when the HTTPS reflector or both DNS reflectors confirm it (and the DNS agreement counts for nothing when the HTTPS reflector's connection was made but its TLS or answer failed), for 10 minutes after the last confirmation, and only on the uplink it was learned on (discovery runs again when the default route changes); while a family this host routes is unknown, requester connections over it are refused. Off: `public_addresses` must name an address of every family this host routes, or the miner does not start. |
| `[egress] public_addresses` | `[]` | This host's public addresses as you know them (behind NAT, your router's; on an IPv6-only host, the NAT64 translator's IPv4 address). Refused as its own, and a family named here counts as known: set it where outbound DNS or HTTPS to the reflectors is filtered or intercepted. |
| `[egress] near_hop_limit` | `2` | Right before every requester-caused connection, probes limited to this many hops, one more and two more (`N`, `N+1`, `N+2`) connect to the destination at once, from the address the connection will use (a second round a second later if the first told nothing): a destination that answers one limited to `N` hops or fewer (accepts, or refuses with a reset) is this host's own network and is refused; it is admitted only when a router past the limit sends an ICMP "time exceeded" for a probe (and the destination answered none at that limit or below), and the connection is then made from the probes' source address and interface, from a new local port. Silence, an unreachable or anything else refuses (`could not tell how near`). A "hop" is a router that decrements the hop count: a box that hides one (a second NAT router behind the ISP's, a VM's NAT, a VPN) moves the limit. 2 to 16. |
| `[egress] doh_resolvers` | Cloudflare, Google, Quad9 | The DNS-over-HTTPS resolvers requester host names are resolved with (never this host's resolver, `/etc/hosts` or a local stub): `https://` URLs whose host is a public IP literal, e.g. `["https://9.9.9.9/dns-query"]`. |
| `[egress] nat64_prefixes` | `[]` | NAT64 prefixes this host's translator uses besides the well-known `64:ff9b::/96` (RFC 6052: a `/32`, `/40`, `/48`, `/56`, `/64` or `/96`, e.g. `"2001:db8:64::/96"`). An address under one is judged by the IPv4 address it carries, so `<prefix>::10.0.0.1` is refused. The prefix a DNS64 resolver uses is learned at startup from this host's DNS servers (`ipv4only.arpa`, RFC 7050); name it here when it cannot be. |
| `[dev] private_network` | `false` | **Developer mode.** Lets those connections reach private destinations, so a local test network can serve programs from this machine (names then resolve through the system resolver, and no near-hop probe is sent). The only way to turn the guard off (there is no environment variable or flag). Needs `[dev] chain_id`; refused on Hemi mainnet (43111); while it is on, every start logs `DEV MODE: private network access enabled — never run on a public market`, `zkminer status` prints it, and the TUI's status bar shows a red `DEV MODE` badge. Never set it on a miner that serves a public market. |
| `[dev] chain_id` | unset | The test network `private_network` is meant for: it must equal `[chain] chain_id` (which the RPC confirms at startup), or the miner refuses the config. A config copied to another network does not open the guard there. |

The prover workers that run requesters' guests are confined before the first one runs: no
sockets of any kind, the filesystem limited by Landlock to what proving needs (nothing of your
home directory but `~/.risc0`/`~/.sp1` and a private temporary directory), and no reaching the
miner or other processes; `sp1-gpu-server` likewise, under a supervisor (its socket is now
`/tmp/zkminer-confined-<server>-<device>.sock`). This needs Linux with Landlock ABI 6, and ABI 8
(`TSYNC`) for the SP1 worker and GPU workers that start threads before their first guest; a worker
that cannot confine itself refuses to run guests. Workers (and the witness sandboxes) also refuse
to run guests while **any network or remote-capable FUSE filesystem, or an automount map, is
mounted where this user can reach it** (NFS, SMB, 9p and virtiofs shares, sshfs, rclone, a GNOME
session's gvfs, autofs `/net`, ...): Landlock cannot stop a path lookup, which would query that
filesystem's server. Of FUSE filesystems only two that root mounts are fine (lxcfs, and ntfs-3g
or exfat-fuse on a block device); a user's own FUSE mounts (gvfs, the document portal, AppImages,
rclone, ...) are not, whatever they call themselves. Unmount them, or run the miner as a dedicated
user (another user's FUSE mount without `allow_other` is closed to it) or in a container or mount
namespace that leaves them out. Confined workers also
change no file's mode, owner, attributes or times. Nothing a worker starts outlives it: each worker
runs in a cgroup of its own, killed with `cgroup.kill` when the worker ends (below the miner's when
the miner runs in a cgroup delegated to it, such as under `systemd-run --user --scope -p
Delegate=yes zkminer run`, else in a scope of your systemd user manager); a small reaper process
(`zkminer-worker-reaper`) kills every worker if the miner dies abruptly; and the miner kills every
worker the moment a filesystem that is not local is mounted. The CPU risc0 worker's Docker Groth16 wrap runs in
a helper process that accepts only a strictly checked prover input, with the image pinned by digest
and `--network none`. See [SECURITY.md](SECURITY.md#inline-workers-confined).

Unknown keys in `[dev]` and `[egress]` are errors, so a misspelt setting stops the miner
instead of being ignored. `ZKMINER_ELF_ALLOW_PRIVATE_URLS`, which older builds read, is no
longer read: move a test setup that used it to `[dev] private_network = true` with `[dev]
chain_id` set to the test network's chain id.

## Run

```bash
zkminer init --generate-key   # a key file only you can read (or: read -rs ZKMINER_PRIVATE_KEY; export ZKMINER_PRIVATE_KEY)

zkminer status                # balance, stake, collateral, job stats
zkminer benchmark             # measure real per-GPU proving throughput
zkminer benchmark --calibrate # also time each segment size (po2); saves benchmarks.json
zkminer run                   # interactive TUI
zkminer -v run --headless     # headless; -v shows per-job claim/skip reasoning
zkminer run --watch-only      # watch the market; claim, sign and send nothing
zkminer stop                  # stop the running miner (drain); --keep-locks, --abandon
zkminer doctor                # what this host can prove, and why not
```

`run --watch-only` runs every check up to the claim against the live market and logs each
job's verdict instead of claiming it: `WATCH <job>: WOULD CLAIM at …` for a job this miner
would take, and for every open job, what its descriptor, measurement, journal binding and
claim quote show, whatever this host's GPUs or stake. It signs with a throwaway key, and its
transport refuses every send. It also skips lock recovery and the nonce watchdog, and never
writes the job journal, so it cannot touch the locks or nonces of a miner running on the same
key. It keeps its own ELF cache (`~/.zkminer/watch/elfs`), starts workers only for the proof
systems this build serves, and paces its RPC to 1 request/s, since it shares the endpoint's
per-IP limit with any miner on the same host. A `chain.max_requests_per_sec` in the config
overrides that for both, so give watch-only its own config file (`zkminer --config …`) if
the miner's sets one. It does execute guests, though, so don't run it on a host whose RAM a live
miner needs. It is always headless. It watches as the configured key's address unless you pass `--address 0x…`, which
needs no key at all. It measures guests on the CPU, so it runs on a host without a GPU if
`[prover.worker_binaries]` names a risc0 worker.

Its verdicts are a rehearsal, not a replay. Its per-job report measures every job on the same
measure workers and RPC budget the WOULD CLAIM decisions use, so on a busy market those can
come a tick or two later than a real miner's would, and the per-job reports can lag well
behind the market.

Verbosity is `-v`/`-vv`, before or after the subcommand (`RUST_LOG` is ignored). Logs go to
stderr, so `zkminer benchmark --json` on stdout stays machine-readable.

Worth knowing:

- **The miner benchmarks itself at startup when it has to.** If the saved results don't cover
  every card and prover it started, `zkminer run` benchmarks the GPUs, shows the results on the
  Benchmark screen, and claims no jobs until that finishes. `--watch-only` skips it.
- **Don't run `benchmark` while the miner is running.** Both spawn a worker per GPU and
  the GPU lock is per-process, so they will double-book VRAM.
- **If the miner sits idle with jobs available, suspect collateral.** Available
  collateral is `staked − locked`, and a claimed job that passes its deadline locks
  collateral permanently. This surfaces as a throttled warning at default verbosity.
- **Stopping can cost locks, so choose how.** Releasing a lock costs 5% of its collateral
  at its deadline and up to 30% with the whole fulfilment window left. There are three ways
  to stop:
  - **Drain** (the default): stop claiming, let the jobs in flight finish and be paid, then
    exit. That can take up to 50 minutes, after which whatever is still held is released.
  - **Keep locks**: stop claiming and exit without releasing (exit status 75), after any proof
    already being submitted lands; a lock too close to its deadline for a restart to release
    it in time is released first. That takes seconds to several minutes. The next start picks
    the locks up from `~/.zkminer/job_journal.json`, re-proves each one that still has time,
    and releases the rest. Use it for restarts and upgrades, and start again by the time it
    prints (the earliest kept lock's cutoff less ~15 minutes for the restart and a release): a
    lock left past its deadline is slashed.
  - **Abandon**: release everything now, then exit.

  In the dashboard, `q` or Ctrl+C asks which one when jobs are held: `d` drain, `k` keep
  locks, `a` abandon, `Esc` to keep mining. The dashboard stays open while the miner stops,
  and `a`, `k` and `x` (force exit) still change course; a second Ctrl+C does nothing.

  From another terminal or a script, `zkminer stop` drains, `zkminer stop --keep-locks` keeps
  the locks, `zkminer stop --abandon` releases everything and `zkminer stop --force-exit`
  exits at once; `--wait` waits for the miner to exit. It works on Windows too. It talks to
  the miner running under the same home directory, so run it as the same user.

  Signals, for headless and supervised runs: SIGINT (Ctrl+C) drains, a second one abandons,
  a third exits at once. A signal during a drain already under way counts as the second: a
  Ctrl+C after `zkminer stop` abandons (the contrib unit's `systemctl stop` does not: it asks
  for a drain and waits). A signal never force-exits an abandon it did not start; the one after
  does. During a keep-locks stop, signals
  never abandon (only `zkminer stop --abandon` or `a` does); the third still exits at once.
  Closing the dashboard's terminal (SIGHUP) starts a drain if no stop was chosen, and
  otherwise changes nothing. SIGTERM, the default stop signal of systemd, `docker stop` and
  Kubernetes, releases every held lock at once, because a supervisor kills the process
  before any drain could finish. [`contrib/zkminer.service`](contrib/zkminer.service) sets
  `KillSignal=SIGINT`, `KillMode=mixed` and a long `TimeoutStopSec`, so `systemctl stop`
  drains, and `Restart=on-failure`, so `zkminer stop --keep-locks` restarts it in place. To
  upgrade, `install -m755` the new miner and every worker over the old ones (all of them: a
  worker from another build is refused), then `zkminer stop --keep-locks`. For Docker, run
  with `--stop-signal SIGINT --stop-timeout 4200 --restart on-failure` and keep `~/.zkminer`
  on a volume (`-v zkminer-home:/root/.zkminer`): the kept locks are found through the job
  journal there, and a new container without it never finds them. Restart in place with
  `docker exec <container> zkminer stop --keep-locks` (not `--wait`, which ends with the
  container); for a new image, start the new container on the same volume promptly. On
  Windows, the workers have consoles of their own, so Ctrl+C reaches only the miner.
  Closing the console window or shutting Windows down gives the miner only seconds, so it
  stops as keep-locks: the locks stay held for the next start (if Windows delivers the event,
  a lock too close to its deadline is released), and its workers end with it. Start it again
  soon, or stop it with `zkminer stop` first.

  Exit status 75 means it stopped with locks still held (or by keep-locks): start it again
  well before their deadlines. A miner killed outright (SIGKILL) picks its locks up the same way.
  Under `Restart=on-failure` (or Docker's `--restart on-failure`) that exit restarts it, and the
  restarted miner mines again; to stop it for good, use `systemctl disable --now` (a plain
  `systemctl stop` starts again at the next boot) / `docker stop`, which the supervisor never
  restarts. After installing new workers, restart only with `zkminer stop --keep-locks`, not
  `systemctl restart`: the old miner would drain for up to 50 min while any worker it respawns
  is the new build, which it refuses. A reboot or poweroff under the systemd unit drains like
  `systemctl stop` and can hold the shutdown for up to 70 minutes; a hypervisor or cloud stop
  rarely waits that long, and whatever it cuts off keeps its locks. So stop the miner first
  and let it finish, or `zkminer stop --abandon`, or, for maintenance you'll be back from
  soon, `zkminer stop --keep-locks --wait && sudo systemctl stop zkminer` (within the 10 s
  before systemd restarts it). On Windows, a miner run as a service keeps its `.zkminer` in
  the service account's profile (for LocalSystem,
  `C:\Windows\System32\config\systemprofile\.zkminer`), so run `zkminer stop` as that
  account (`psexec -s` for LocalSystem). A service wrapper's stop (NSSM sends Ctrl+C, then
  kills the process after its timeout) starts a drain it then cuts off: run `zkminer stop
  --wait` (as the service account) before stopping the service, or give NSSM a timeout long
  enough for a drain (`nssm set <service> AppStopMethodConsole 3900000`).
- **One miner per key.** Two miners on one key drive the same locks and replace each
  other's transactions. `run` holds `~/.zkminer/miner.lock`, so a second one from the same
  home refuses to start (including while the first is still draining); it can't see one in
  another home or on another host. `--watch-only` takes no lock.
- **`PAGE:` lines need a human.** They say claiming has stopped (the deployment or proof
  system failed its check, the protocol is paused, the clock is off, funds are short) or a
  lock is at risk. The dashboard shows them; headless, they go to stderr.
- **Drain before an upgrade that changes the `sys_rand` rule.** risc0 guests' randomness is a
  public function of the program and input (`crates/zkminer-prover-protocol/src/sys_rand.rs`), so
  a measurement and the proof after it agree on any host, and no key needs keeping (an old
  `~/.zkminer/risc0-sys-rand.key` is unused and can be deleted). A new rule re-seeds whatever a lock
  was measured under: a guest whose journal or path follows its random bytes may then fail or commit
  something else, and that lock is released at the job's release penalty (5% by default). So for such a release let the locks finish first
  (SIGINT, and wait), not SIGINT then SIGKILL. A restart that finds such a lock says so on a `PAGE:` line.
- **Escape hatches, for after you've checked by hand:** `ZKMINER_SKIP_CODE_PINS=1` skips
  the audited-code checks (router, Staking, Registry, facets, and the risc0 and SP1 adapters
  and verifiers), `ZKMINER_ALLOW_UNKNOWN_DEPLOYMENT=1` accepts contract addresses that aren't
  the known deployment's, `ZKMINER_RISC0_SKIP_PROGRAM_ID_CHECK=1` proves an ELF whose image
  id isn't the job's program id. Each one turns off a guard against losing collateral.
- **Rebuild every worker with the miner.** A worker built for another protocol version is
  refused at start, and its proof system is not offered on that card. Workers in
  `~/.zkminer/provers` are found before the ones shipped beside the miner: replace them too, or
  remove them, when you upgrade.
- **One job locks at most half the stake, and so do one program's and one submitter's jobs
  together.** A submitter chooses a job's collateral rate (up to 500%) and its maximum price, and a
  forced release burns a share of what is locked. The cap is `ZKMINER_MAX_JOB_COLLATERAL_FRACTION`
  (default `0.5`; `0` turns it off) of the total stake, but never less than the deployment's
  per-job floor (`MIN_COLLATERAL_AMOUNT`, 100 HEMI on 743111), so a stake of 100–199 HEMI can still
  claim one job (the miner says so once at startup). A job whose collateral at its maximum price is
  over the cap is set aside, not claimed; one that would take the jobs of its program, or of its
  submitter, that this miner holds and has not proven yet over the cap waits until they are proven.
  Witness jobs are held to the same cap, inline and witness locks counting together, and
  `run --watch-only` reports a job over it. A value that is not a number from 0 up is warned
  about and the default used.
- **SP1 jobs are sized by gas** (protocol 15): SP1's measured cost weights precompiles (keccak,
  sha, bigint) by what they cost to prove, where the instruction count counted each as one.
  Benchmarks saved by an older miner count SP1 instructions per second, which is close for code
  without precompiles; run `zkminer benchmark` (again with `--calibrate` if you calibrated) to
  record SP1 in gas.
- **risc0 proofs write their segments to disk**, not to the temporary directory: a long proof
  stages gigabytes there, which on a tmpfs would be RAM the miner does not count. Each worker has
  a directory of its own (mode 0700): `<segment_dir>/inline/<pid>-<start>` when `[retention]` is
  configured, beside the witness proofs', else `~/.zkminer/risc0-segments/<pid>-<start>`
  (`~/.zkminer` may be a link of yours to a directory of yours, on another disk). Keep room there:
  an inline risc0 job is claimed only while its segments (estimated at 4 bytes per sized cycle)
  fit beside those of every proof planned or running, witness ones included, with 1 GiB to spare,
  and a worker does not start a proof with under 1 GiB free. A proof that fails while the disk
  has no room for its segments (a full disk or quota) is this host's failure: it is not held
  against the job's program or submitter. Each proof empties its directory, and a worker that was
  killed has its directory removed when the next one starts. That sweep tells a live worker by
  its pid and start time in `/proc`. On another OS it cannot, and keeps every directory: remove a
  killed worker's by hand. Workers that share one home from different pid namespaces (containers)
  cannot see each other and would remove each other's: give each its own home, or its own
  `[retention] segment_dir`.
- **A card that proves nothing says why.** At startup the log lists, card by card, whether
  each zkVM proves there, and if not, why and what changes it: a worker binary that isn't
  found (with the directories searched) or isn't executable, a card the build has no GPU code
  for, too little VRAM. The ones that need attention also go to the dashboard's activity log.
  `zkminer doctor` prints the same table on demand, with the config, chain, gas and stake
  checks, and starts nothing.
- **12 GB NVIDIA cards prove both zkVMs** (measured on an RTX 4070). SP1 runs at its larger
  shard size when about 11.6 GiB of the card is free, which an idle 12 GB card has, and at the
  smaller one (about 20% slower) from 9 GiB, so a card driving a display steps down by itself.
  On NVIDIA cards above 16 GiB, SP1 needs 17.1 GiB free for the smaller shard size and 22.9 GiB
  for the larger one (measured on an RTX 5090), so an idle 24 GB card runs the larger. AMD and
  Intel cards of any size (not yet measured) need 15.2 GiB free, so a smaller one gets no SP1
  jobs. `ZKMINER_MIN_AVAILABLE_VRAM_MB` lowers that floor, untested: a larger job can run out
  part-way and lose its lock. A 12–16 GB NVIDIA card
  gets none either while `SP1_GPU_DROP_LDES` or `SP1_GPU_RECOMPUTE_FIRST_LAYER` is set to `0`:
  that switches off the server memory savers the figures above were measured with. An SP1 proof
  that runs out of GPU memory is retried on the same card one shard size smaller, and when it
  proves there the card keeps that size in later runs too (`~/.zkminer/sp1_shard_caps.json`;
  `zkminer doctor` lists it; stop the miner and remove the card's entry to lift it). Until it is
  re-benchmarked, such a card's SP1 jobs are planned about 20% slower per size step. Under
  Windows too, whatever the driver's settings (below). RISC Zero
  proves at po2 19 on a 12 GB card, 20 from 14 GiB, and benchmarks at that size. A 12 GB card
  benchmarked by an earlier version (at 20, which doesn't fit) has saved rates far too low:
  re-benchmark it with `b` on the Benchmark screen, or `zkminer benchmark --calibrate` with the
  miner stopped (a plain `zkminer benchmark` saves nothing). Under Windows, at the NVIDIA driver's
  default CUDA - Sysmem Fallback Policy, a proof that outgrows its card isn't refused memory: the
  driver puts part of it in system memory and it runs many times slower (an SP1 proof on an RTX
  4070: 408 s instead of 33), which can cost a lock. The SP1 server refuses that memory itself, so
  an SP1 proof fails at once and is retried one shard size smaller (60 s, the same proof), with no
  setting changed. For RISC Zero, which has no such check, "Prefer No Sysmem Fallback" (NVIDIA
  Control Panel → Manage 3D settings, globally or for `zkminer-prove-risc0-cuda.exe`) makes the
  driver refuse it instead (not measured for RISC Zero). `zkminer doctor` can't read the setting:
  the driver hides it. Memory another program takes while a proof runs doesn't fail the
  proof under either setting: Windows pages the two programs' memory in turns, and the proof runs
  8–12 times slower. The miner watches for that (Windows' per-process GPU memory counters): the
  dashboard's GPU row shows "⚠ … GiB paged to RAM", and once it has gone on for a few seconds the
  proof is stopped and run again where it fits, on another card or on this one at a size that
  fits beside the other program (on an RTX 4070: stopped 6 s after a 2 GB program started, then
  proved in 62 s, against 242 s left to page). Still, leave the card the room these figures say.
  The miner helps:
  a RISC Zero proof on an NVIDIA card starts only when its segment size's measured peak fits in
  what is free (else it waits, or goes to another card, and no RISC Zero job is claimed for that
  card until a check every 5 minutes finds the room; a job that waits about 2 minutes without room
  is released), and under Windows an NVIDIA card that another program also uses (a display) is
  sized 1 GiB smaller, for that program to grow into (on a 12 GB card that means SP1's smaller
  shard size: re-benchmark such a card after upgrading, as its saved SP1 rate was measured at the
  larger one). `ZKMINER_MIN_AVAILABLE_VRAM_MB=0` turns all of this off.

Each card proves risc0 jobs at its own segment size (po2), between 16 and 22:
- the size set for it, keyed by its benchmark device id in lower case (`gpu0`, `gpu1`, … for
  NVIDIA cards, `gpu-rocm0`, … for AMD, `gpu-intel0`, … for Intel, `gpu-metal0` for a Mac's GPU):

  ```toml
  [prover.risc0_job_po2]
  gpu1 = 19
  ```

  or a po2 under Settings → Advanced, which applies for the session while Advanced mode is on.
  The config is read when the miner starts. The log lists each card's size whenever it changes,
  and names a configured card that isn't here;
- else, on an NVIDIA card, the largest measured size that fits it with 1.9 GiB to spare: 20
  from 14 GiB of VRAM (po2 20 peaks around 12.1 GiB), 19 from 9.8 GiB (8.0 GiB), 18 from
  6.5 GiB (4.6 GiB), and none below that; on an AMD or Intel card, whose sizes haven't been
  measured, 20 from 14 GiB and none below.
  A card whose VRAM isn't known gets 20: an Intel card on the i915 driver, a CUDA query that
  failed, or the card
  behind a risc0 worker named in `[prover.worker_binaries]` (which isn't pinned to a card).
  A Mac's GPU instead takes the Metal tier of its RAM (19 on a 16 GB Mac, 20 from 24 GB; see
  [Supported Macs](#supported-macs));
- `benchmark --calibrate` proves a 62M-cycle Groth16 job at each size, on a card whose VRAM
  is known (NVIDIA; an AMD card under 14 GiB needs a size set for it). Run it with
  the miner stopped. A card then uses its fastest size, up to one step below the largest that
  proved when a larger one failed (or at 22, past which the prover refuses). On an NVIDIA card
  the sweep also stops at the largest measured size its free VRAM holds, below 20. Calibration can raise a card above 20, or give a smaller card a size, but
  never takes a card below its default size if that size proved during calibration. A plain re-benchmark drops the
  calibration. A slow card may need a larger `benchmark_timeout_secs` at sizes below 18.

A guest can tell the segment size it runs at, so every job is measured at each card size on the
rig before it's claimed. It's claimed only if it measures clean at all of them, with one
journal. A rig whose cards share a size measures once. A claimed job is proven at a measured
size that fits the card. If a restart or a re-benchmark has since moved every card below those
sizes, each card proves the job at its own size rather than releasing it. If no enabled card has
a size, the job waits for one (switch a card back on, or give one a po2 under Settings →
Advanced; a config size or a calibration applies only after a restart, which releases it) and
is released before its deadline.

## Upgrading from a version without `zkminer stop`

The miner already running is the old binary, which never reads `zkminer stop` requests (they
time out with that as a likely cause). For that one upgrade, stop it the old way: Ctrl+C or
SIGINT to stop claiming (`systemctl kill -s INT --kill-whom=main zkminer` under systemd), then
SIGKILL (`systemctl kill -s KILL zkminer`) to keep its locks for the next start, or let it
drain. Then install the new miner and every worker, `contrib/zkminer.service` if you use it
(`systemctl daemon-reload`), and start it promptly. What changes for an operator:

- Quitting the dashboard with jobs held asks how to stop; a second `q` or Ctrl+C does nothing
  (`k` is the quick restart that keeps the locks). The setup wizard's stake takes two presses.
- `zkminer run` with no terminal (cron, `nohup`) runs headless instead of failing: check for
  forgotten `@reboot` entries. A dropped SSH session (SIGHUP) now drains instead of killing the
  miner: from a new session, `zkminer stop --keep-locks` or `--abandon` changes course.
- On Windows, Ctrl+C no longer kills the workers (a drain now really finishes its proofs), the
  workers end with the miner, and closing the window keeps the locks for the next start.
- `stake`, `unstake` and `withdraw` refuse while a miner holds this home's lock, even with
  `--force` (which now only overrides the cross-home and mempool checks), and `stake` refuses a
  deployment that fails the check `run` makes (set the same `ZKMINER_ALLOW_UNKNOWN_DEPLOYMENT`
  / `ZKMINER_SKIP_CODE_PINS` for it as for the miner, if you rely on them). A top-up script
  that staked beside the running miner should stake from the dashboard, or stop with
  `--keep-locks`, stake, and start again.
- `zkminer status` prints `Network:`, `Deployment:`, `Unstake pending:` and `Payouts held:`
  lines, and checks the deployment (more RPC reads per call). Exit 75 also means a keep-locks
  stop, with or without locks held.
- Logs: a `claims:` line (why open jobs are not claimed) at most every minute or on a change, a
  per-card table at start, no colour codes when stderr is not a terminal, and some reworded
  lines ("drain interrupted — abandoning", "another zkminer holds ...", stake amounts in HEMI).
- `~/.zkminer` gains `stop-request`, `stop-response` and `miner.lock.holder`, and is made
  private (0700) on Linux. `zkminer init --generate-key` refuses an existing key file others can
  read on Linux.

## Simulate (measure jobs without mining)

`zkminer simulate` runs the miner's own pre-claim measurement on any job, whatever its state, and
prints one JSON line per job on stdout: the cycle count proving would report, or why there is none.
It is for an indexer or a dashboard that wants the work a job took: the chain records none
(`JobFulfilled.actualCycles` is 0 under every governance adapter; only a custom verifier, chosen by
the job's caller, reports one).

```bash
zkminer --config simulate.toml simulate --job 0x… --job 0x…
zkminer --config simulate.toml simulate --stdin   # one request per line: a job id, or
                       # {"jobId":"0x…","submitTx":"0x…","publicValues":"0x…"} (both optional)
```

A request line is at most 132,096 bytes; `publicValues` (the fulfil's on-chain public values, to
compare the measured journal with) is `0x` and an even number of hex digits, at most 65,536 bytes
decoded. Any other field, or a malformed one, is an `invalid_request`.

Each job goes through the steps a claim depends on: its descriptor rebuilt from the submit
transaction and checked against its on-chain hash, the program's ELF from the ProgramRegistry, those
bytes bound to the job's `programId`, and execution on a measure worker: at all seven segment sizes
for risc0 (below), once for SP1. A `submitTx` hint whose receipt holds the job's `JobSubmitted` log is the submit
transaction, so its calldata decides alone: calldata that does not decode is `undecodable` at once,
with no log scan (any other hint is only tried first). The ELF is the bytes that bound before, else
the bytes the registry's `elf_hash` names from any URI that serves them, else what the first URI that
answers serves. The binding is derived, never trusted: the risc0 image id, or the SP1 verifying-key
hash from SP1's `setup` on the CPU (minutes per program, cached on disk per ELF under `--cache-dir`,
default `~/.zkminer/simulate`). SP1 PLONK jobs are measured by the SP1 worker (the same ELF and vkey
hash as Groth16), though the miner does not claim them. A journal-prefix job runs on its prover's
input, `abi.encode(jobId, prover)` and then `inputData` (risc0; an SP1 one is `not_served`, since its
prefix is a stdin buffer of its own, which one execution input cannot reproduce).

A report's `outcome` is one of:

| outcome | meaning | `retryable` |
|---|---|---|
| `measured` | executed; `cycles` is the count (a decimal string) | no |
| `not_served` | this build can never measure it: its proof system is not one it measures (OpenVM, a custom verifier, unknown), or it is an SP1 journal-prefix job | no |
| `no_worker` | no measure worker for its backend runs here | yes |
| `undecodable` | its descriptor can never be rebuilt | no |
| `no_program` | the program is not in the registry, or has no storage URIs | yes |
| `program_mismatch` | the risc0 ELF the registry declares (its keccak256 is the registry `elf_hash` or a URI's content hash) is not the job's program (an image id depends on the bytes alone) | no |
| `too_heavy` | past the executor's cycle cap, or above `--max-cycles` (default 1e9, risc0's keccak charge included) | no |
| `failed` | the guest or the worker failed; bytes the registry does not vouch for did not bind; or a declared SP1 ELF derived another vkey (a vkey depends on the SDK's circuit version too: the reason names `sdkVersion`) | yes, a few times |
| `timeout` | the execution or the program-id derivation hit its bound | yes, a few times |
| `unavailable` | nothing conclusive: the RPC, the registry or the ELF host failed (no URI served usable bytes, or none could be fetched, its URI unparseable or of a kind not fetched included: the registrant can change them), a worker was busy or found dead, or the program's last failure is remembered (the reason begins `remembered from`) | yes |

A `measured` report also says whether its count is evidence of the proven run:

- `proven`: the measured journal against the request's `publicValues`, byte for byte, an SP1
  proof-nonce job's included (the nonce is in the seal; the guest cannot read it): `matches`,
  `differs`, or `unknown` (none sent, or no whole journal came back: over 32 KiB). The router's fulfil
  takes the journal as `publicValues` for both risc0 (the receipt's journal) and SP1 (its public
  values).
- `hostInput` and `hostInputReads`: whether the guest called `sys_rand` past the one 4-word draw its
  runtime makes before `main`, and how often. risc0 only: an SP1 guest's generator runs inside the
  guest from a fixed seed, so it is `false`, 0 (and the proof covers it). `hostInputReads` is absent
  when nothing could be counted: a guest without risc0's runtime, or a keccak request the guest never
  assumes, which costs its prover nothing. std's `HashMap` seeds itself from `sys_rand`, so a risc0
  guest that builds one reads it once. Reading is not a fault: see below.
- `sysRandRule`: the rule that seeded a risc0 run (also on the READY line); absent for SP1.
- `sizeCheck` (risc0 only): `same`, `differs` or `skipped`; see below.
- `binding`: the job's journal binding against the measured journal, as the router checks it:
  `satisfied`, `fails`, `none` (nothing binds the journal; an SP1 proof-nonce job with no statement
  included), `unchecked` (no whole journal). For a proof-nonce job the statement is checked with the
  marker cleared, as the router does.
- `sdkVersion`: the measure worker's SDK, as its handshake names it (on every report once the job's
  backend is known to have a worker).

A count is evidence when `proven` is `matches`, `binding` is not `fails`, `hostInputReads` is
present and `sizeCheck` is not `differs`. risc0 guests' `sys_rand` is seeded by a public rule (`SYS_RAND_RULE`) that zkminer's proofs
use from protocol 13 (on the macOS line from its 14; one line since 17): a function of the image id and every byte the guest reads, so a guest's random
bytes, and the path it takes on them, are the same here as in a proof zkminer makes under that rule.
The figure is the cost of that run at the size the report names (a miner proves at its own card's).

What this does not show: the proof binds neither the seed nor the input. A job proven before the
rule, by an older zkminer, was seeded by its miner's key, so when `hostInputReads` is above 0 its
count is the public-seed run, not necessarily the proven one. A prover on other software
can answer `sys_rand` with anything, and a requester who is also the prover can prove another input
with the same journal and choose a count up to `--max-cycles`. An SP1 proof binds the ELF image and
address 0, but not the first value of any other register or memory word: this run starts them at
zero, as an honest prover does, and another prover can start them at anything.

**The segment-size check.** A guest can read the segment size it runs at, and a miner proves at its
own card's size, so a guest could cost one thing here and another there. `simulate` therefore runs a
risc0 job at all seven sizes a miner can prove at (2^16 to 2^22) and compares the journal, the guest's
own cycles, its keccak charges and its random reads. Any difference reports `sizeCheck: differs`. If
none differs it reports `same`, and `cycles` and `po2` are those of the LOWEST of the seven: a guest
can keep every compared value equal and still read more memory at one size, inflating that size
through paging alone, but a miner paid at least the lowest figure at whichever size it proved at. A
request with `singleRun: true` is measured once at `--po2` and reports `skipped`, for a program the
caller trusts, and only the caller decides that. A guest failure at another size is `differs` too; a
timeout or a host problem there is reported as it would be for any execution. `--max-cycles` applies
to the `--po2` run. Seven executions bound one request by `7·E`, and small segments are slower, so a
job takes about 8 to 21 times as long as one run at 2^20 (measured).
`RISC0_KECCAK_PO2`, which a guest can also see, is pinned to the SDK's default here.

**The failure memory.** A program whose ELF did not bind (refused, another id, a derivation past its
bound, or for a shorter 15 minutes a worker that died deriving it, which may be the host's doing) is remembered under `<cache-dir>/program-failures` for
`--program-failure-ttl-secs` (default 6 h, 0 = off), and one whose ELF could not be fetched for
15 minutes (at most that TTL). Its other jobs are answered from the memory, `unavailable` (or
`program_mismatch` when that was the verdict), instead of each paying a download and a derivation, or
the fetch budget. An entry holds only while the program's registry entry reads as it did (its
`elf_hash`, its URIs and their content hashes; a final verdict only while the registry still vouches
for the very bytes it judged), and only for the zkminer build that wrote it (its version and binary),
backend and worker SDK; an entry dated more than 60 s ahead of the clock is dropped. Bytes that bind
clear it. **Re-queuing jobs after a fix outside the registry (an upgraded worker, a host problem)
includes deleting `<cache-dir>/program-failures`**, or the new run may answer from it.

**Bounds.** `--execute-timeout-secs` (default 600) and `--program-id-timeout-secs` (default 900)
bound one execution and one derivation: at least 60 (a lower value is raised to it) and at most
86400. An SP1 measure worker's one-time setup (its CPU prover: about 170 CPU-seconds, so 38 s with
five free cores and nearly three minutes with one) is not in them: it runs before READY, and again
before the next SP1 request when its worker was respawned, bounded at 120 s. A host with fewer than
two free cores can need longer: the setup is then stopped, and the request's derivation or execution
builds the prover within its own bound. Every
other wait is bounded too, so the longest one request can take, in seconds, is

```text
4·R + 2·F + 4·W + 2·S + P + 7·E  =  584 + P + 7·E      (+ local work)
R = 30   each chain read outside the two fetches: the status view, the head refresh,
         the registry entry, its re-read after a derivation that did not bind
F = 90   the descriptor fetch, and the ELF fetch (every URI, twice when elf_hash is set)
W = 11   one worker (re)start: process and handshake (10 s), before each worker request
S = 120  the SP1 set-up, before the derivation and the execution (0 for risc0)
P = --program-id-timeout-secs     E = --execute-timeout-secs
```

where local work is a keccak, a cache read and a cache write of an ELF of at most 248 MiB, and a
few small files: seconds on a working disk. With the defaults that is 2084 s. (risc0 requests stay
under `3·R + 2·F + 2·W + P + E`.)

With `--stdin`, a READY line comes first, once the measure workers run (an SP1 one set up) and before
any request is read; a reader should send nothing before it:

```json
{"schema":1,"ready":true,"backends":["risc0","sp1"],"zkminerVersion":"0.1.0","protocolVersion":15}
```

(`backends`: those with a live measure worker, sorted.) A line that is not a request is answered
`{"error":"invalid_request","reason":"…","schema":1}` in its place. Reasons are sanitized and carry
no URL path, query or userinfo.

It signs and sends nothing (the watch-only client), and starts measure workers only, never a prover,
so it runs on a host without a GPU: build the CPU risc0 worker and, for SP1 jobs, the SP1 worker
(not a default workspace member; it needs the SP1 toolchain, installed with `sp1up`), and name them.

```bash
cargo build --release -p zkminer-prove-risc0 --features cpu --bin zkminer-prove-risc0-cpu
CARGO_TARGET_DIR=target-sp1 cargo build --release -p zkminer-prove-sp1
zkminer --config simulate.toml simulate --stdin \
    --risc0-worker target/release/zkminer-prove-risc0-cpu \
    --sp1-worker target-sp1/release/zkminer-prove-sp1
```

Reading the counts:

- **Units differ by backend.** risc0's count is cycles with every segment padded to its power of two
  at the report's `po2`, plus a charge of 2^20 for each keccak proof request (a price, not cycles: about a 2^20
  segment's proving time; doubled per step of a larger keccak po2). SP1's is SP1's gas, which
  weights each operation by what it costs to prove: about the instruction count for plain code, far
  more for precompiles (keccak, sha, ...), which the instruction count counted once. Never add or
  compare the two.
- **po2.** risc0 counts depend on the segment size: a job proven on a small card (po2 16) has about
  1.8 times the po2-20 count. A report carries the `po2` of its figure, which is the lowest of the
  seven sizes unless the request was `singleRun`.
- **`--max-cycles`.** Every count up to it is the guest's to choose (a keccak request costs a few
  hundred cycles of guest work and is charged 2^20), so it bounds what one job adds to a sum. The
  default, 1e9, is ten times the largest proof seen on this market.

**Never run `simulate` on a host that runs a miner.** The miner's host-RAM ledger is per process: a
simulate measurement (an SP1 one stages gigabytes of shared memory and may hold up to 24 GiB) is
invisible to a miner beside it, and the two can together run the host out of memory under its proofs.

## Witness jobs: requester tools

A witness-construction job carries an envelope in `inputData` instead of the guest input: the miner
runs the requester's builder (a WASM module) in a sandbox to construct the witness `W`, executes the
guest on `W` and checks the journal against the binding before it claims (see
`docs/witness-construction-jobs.md`). These commands are for the requester; none of them needs a
miner's key.

**The envelope.** `zkminer witness envelope encode SPEC` writes `inputData = WITNESS_JOB_TAG_V1 ‖
abi.encode(WitnessJobV1)` as 0x hex from a TOML (by its extension) or JSON spec, and checks it with
the miner's own strict decoder (a spec the miner would skip is refused with its reason). With
`--builder b.wasm` the builder id is the module's sha256 (and must equal a given one). A *job* spec
adds the program, the binding and the envelope, and with `--descriptor-out` also writes the
descriptor file `zkminer simulate --descriptor` reads:

```toml
program_id = "0x…"                 # the guest's risc0 image id
# assigned_prover = "0x…"          # needed for a NONE binding
[binding]
prefix = true                      # the journal-prefix marker (the default for open witness jobs)
header = ["uint:1", "bytes32:0x…", "address:0x…", "keccak:my-layout-rule", "uint:3"]   # FIELDS
# full_statement = "0x…"           # or FULL, for a journal known in full at submit
[envelope]
builder_uris = ["hemi-code://743111/0x…"]
builder_params_abi = ["uint64:8453", "bytes32:0x…", "address:0x…"]   # abi.encode of static values
[[envelope.sources]]
class = "evm-rpc/v1"
chain_id = 8453
archive = true
method_set = "state-read"
max_proof_age = 300
[envelope.limits]                  # every limit explicit: 0 means none allowed
max_fetches = 64
max_fetch_bytes = 16777216
max_request_bytes = 65536
max_response_bytes = 4194304
max_builder_fuel = 10000000000
max_builder_memory_bytes = 268435456
max_builder_seconds = 60
max_witness_bytes = 1048576
max_guest_cycles = 67108864
```

`zkminer witness envelope decode 0x…|FILE [--chain-id N]` explains an existing `inputData`: the
decoder's verdict, each builder URI as a miner on that chain reads it (usable, or why it is
ignored), size warnings, and the envelope as an editable spec (TOML; JSON when a value is above
2^63 − 1, which TOML cannot hold). Control and bidirectional-format characters in what it prints are
escaped (`\u{1b}`): an envelope's URIs are the requester's bytes. It exits non-zero when the miner
would skip the job, and 0 for any envelope the miner decodes.

**The binding.** `zkminer witness binding compute --word TYPE:VALUE …` derives `journalFields` and
`expectedJournalHash` from your own parameters, FIELDS over the whole header (`H = 32 × words`,
pinned at statement offset 0, with the journal-prefix marker unless `--no-prefix`); `--full-statement
0x… --program-id …` is FULL, `--none --assigned 0x…` is NONE. Never take these from a prover's
journal. Word types: `uintN`, `bool`, `address`, `bytesN`, `bytes32`, `word` (raw), `keccak:<text>`.
`zkminer witness binding check` is the mutation check: give the binding (`--journal-fields` and
`--expected-journal-hash`, or `--descriptor`) and the statement (`--word …`, `--statement 0x…`, or a
whole `--journal`), and it changes each byte in turn, recomputes the router's hash, and reports the
pinned and free byte ranges, the header's free bytes, the free bytes of each header word, and
whether the expected hash matches. It exits non-zero when:
- a header byte is free; the header's length is `--header-bytes`, or 32 × the `--word`s;
- the header's length is unknown under FIELDS (give it: a binding cannot be shown to pin a header of
  unknown length), or it is longer than the statement given;
- no expected hash is given (the mode is reported `unknown`: FULL and NONE look alike without it);
- the binding is NONE without `--assigned` (or the descriptor's assigned prover);
- the router would refuse the binding at submit (`InvalidJournalBinding`), a range ends past the
  statement, or the hash does not match.

A descriptor file whose binding the router would refuse at submit (NONE without an assigned prover,
FIELDS without a hash, a range past the journal) does not load anywhere.

**Simulate a job before submitting it.** `zkminer simulate --descriptor d.json` runs the job through
the miner's own pre-claim pipeline: the static gates, the builder (from `--builder`, or fetched by
the broker from the envelope's `hemi-code` locators exactly as a miner fetches it), the sandboxed
builder and execute at every `--po2` (one size, a range or a list), the router's binding check, a
bundle published to a throwaway retention store under `--cache-dir` (removed at the end; it must
not be tmpfs), and the claim gate's DA check (the exact fulfil against `[witness]
fulfil_da_cap_bytes`). The guest ELF is `--elf`, else the ProgramRegistry's. The broker uses your own
endpoints: `--broker-config` (the broker's TOML; default `[broker] config`), copied into the run's
work directory with a spool of its own, so a simulation never shares a running miner's. The
configuration's `[witness]` limits apply, the miner's per-job artifact budget (bytes and chunk reads)
holds `hemi-code` reads, and `[witness] sandbox_mode = "rootless"` on a host without root; the
sandbox and broker self-tests must pass first. A miner without `[witness] max_guest_cycles` derives
its cycle maximum from its cards and proving timeout; give `--max-guest-cycles` to judge the job by
one (else 2^34 applies, and the check is listed as not done). Without `--po2`, `maxGuestCycles` is
judged at the sizes this configuration's risc0 cards prove at (its benchmark cache and
`prover.risc0_job_po2`), else every job size is executed and judged at po2 20, the size every card
without a calibration or an operator's size proves at (`po2Source` says which). The miner also sizes
a card by its VRAM, which the benchmark cache does not record: a card under 14 GiB proves at its
calibrated size, below 20 when 20 failed there, or no job at all uncalibrated. `po2Source` names
the size each such card would have, and `--po2` judges at it. Run it in a delegated cgroup:

```bash
systemd-run --user --scope -q -p Delegate=yes -- \
    zkminer -c simulate.toml simulate --descriptor d.json --builder b.wasm --elf guest.elf \
    --prover 0x… --out report.json
```

The report (one JSON document, `"kind": "witness"`) has the outcome (`simulated`, or `skipped` with
the verdict, its step — `static_gates`, `artifact`, `builder`, `execute`, `binding`, `publish` or
`claim_gate` — and its retry class — `never`, `once_jittered`, `backoff` with `retryMaxAttempts`,
`on_host_change` or `deferred` — or `aborted`), the builder's fuel, fetches, fetched bytes, compile
and run time and peak memory, `|W|` and its hashes, cycles per po2 in the `maxGuestCycles` unit,
the journal, the pinned bytes and the binding's mutation check (the header's length from a scheme-1
`W`'s word count, or `--header-bytes`), the fulfil's estimated DA size (by the chain's
`GasPriceOracle` when `[chain] rpc_url` answers, else an upper bound) against the cap, this
configuration's admission parameters, and `notChecked`: what was not checked and a miner would
(claimability, submission form, deployment pins, admission, reservation, the DA backlog, deadline,
prove resources; the builder's availability through its URIs or a mirror with `--builder`; the
registry's ELF with `--elf`; a card-derived cycle maximum without `--max-guest-cycles`). The
`sys_rand` seed is the public rule's, as a miner's (`sysRandRule`), and a journal-prefix job is
reproduced exactly only with the real `jobId` (the file's `jobId`) and `--prover`. It exits non-zero
when a miner with this configuration would skip the job: a journal the router's binding check
refuses included (`BindingMismatch`). A binding the router accepts but that leaves header bytes
free, or whose header's length is unknown, is reported (`binding.ok`, `binding.warnings`, and a
line on stderr) with exit 0, since a miner serves it; `--adversarial` fails it. In `--job`/`--stdin` mode a witness job on
chain is reported `not_served`: its proven input is the builder's `W`, not its `inputData`.

**`--adversarial`** then attacks the witness and the host inputs, within `--adversarial-secs`
(default 600; every execute and broker start gets what is left of it and is killed there). It
checks the binding's coverage, then the host inputs and the providers (a few runs each), then
spends what is left on the mutations, each execute getting a share of the time left (the time over
the mutations still to run, and at least four times the unchanged `W`'s execute): one mutation that
runs away cannot starve the others, and one cut at its share is inconclusive. Every re-execution
runs under the attack's cycle cap: this host's maximum when one is configured (`--max-guest-cycles`,
`[witness] max_guest_cycles`), else 4 × the job's `maxGuestCycles` (`attackCycleCap`):

- **the binding's coverage** first: it must pin the whole journal header `[0, H)` with a non-zero
  `expectedJournalHash` (`H` from a scheme-1 `W`, or `--header-bytes`), else the verdict is `fail`.
  A free header word is exploitable only with a consistent change of `W` (another block and its
  header, another `k` and its proofs), which no mutation makes, so the mutations alone would pass it;
- **mutations of `W`**, each made just before it runs (repeats recognised by their sha256) and
  re-executed by the same sandboxed worker under the attack's cycle cap, not the job's (the router
  does not check cycles: a run past `maxGuestCycles` is judged on its journal, and only one stopped
  at the cap, cut at its share of the time, or that ends in an executor panic or a run no proof can
  verify is inconclusive, which under FULL decides nothing): byte flips at `--flips`
  sampled offsets (default 32; the first and last byte always), truncations, trailing bytes, and
  the drop, duplication and reordering of items in every length-delimited framing `W` parses as
  (u32/u64 length prefixes, risc0's word-padded `Vec<u8>`, a top-level RLP list), plus, first, the
  structured mutations of the job's scheme, by the scheme id in the header's first word (or
  `--scheme`). Scheme 1 (`eth-block`) is registered, from the reference prelude's codec
  (`reference/eth-prelude`): byte flips in header words, headers and trie nodes, nodes dropped,
  duplicated and appended, proof kinds flipped (inclusion for exclusion), proofs truncated,
  dropped, duplicated and swapped (another slot's proof), and the block header replaced by its
  parent's and the next block's, fetched through the job's own `evm-rpc/v1` source. At most
  `--max-mutations` run (default 256). Each must fail in the guest, give the same journal byte for
  byte, or change pinned bytes (which the router refuses); a changed journal that still satisfies
  the binding is a **soundness failure**, reported with the mutation that caused it;
- **host inputs**: the same `W` under two `sys_rand` seeds (the rule's and a random one: the proof
  binds no seed, so a prover on other software can answer with anything), two po2s (the first
  `--po2` and the one farthest from it, else the far end of 16..22; one request each) and two keccak
  po2s; any journal change is a dependence on an input the prover controls (a run past the cycle
  maximum is reported as such, not as a dependence). These compare journals only, and a guest can
  check `W` by the seed while its journal ignores it (a spot check at a drawn index passes an honest
  `W` under every seed, and a forged one under the seed its prover picks). So every execute counts
  the guest's own `sys_rand` calls (`perPo2[].sysRandDraws`, past the one its runtime makes before
  `main`): a job whose guest makes any is skipped before any attack (`GuestUsesSysRand`, the
  caller's, as a miner skips it), and a pair whose run draws is dependent. The count is of calls; a
  guest that reads its runtime's own draw from memory is not caught by it;
- **providers**: the whole pipeline against two `[[evm_rpc]]` endpoints of the broker configuration
  (`--providers a,b`, default the first two serving the job's chain), each alone; different
  journals that both satisfy the binding are a soundness failure. So a `pass` needs two `evm-rpc`
  endpoints for the job's chain in the broker configuration (with fewer the differential is not run,
  and the verdict is `incomplete`).

`adversarial.verdict` is `pass`, `fail`, or `incomplete`: something not run in time or
inconclusive, no mutation run (`--max-mutations 0`), or, unless the binding is FULL (which decides
every journal), no structured mutations (the job's scheme is not registered, or `W` is not of it:
the generic ones change bytes, never a consistent `W`). The command exits non-zero unless it is
`pass`. A `W` above `--adversarial-max-w-bytes` (default 8 MiB) is not attacked (`refused`): the
attack runs in this process, unsandboxed, and its peak memory grows with `W`: about 4 × `|W|` for
the generic mutations, and up to about 32 × `|W|` for a scheme-1 `W` of many small trie nodes
(the decoded proofs it rearranges), so set the bound by the memory you can give it.

**Publish a builder.** `zkminer artifact publish FILE --kind builder|elf --rpc-url URL --chain-id N
--keystore KEY.json` stores the file on the HemiProve chain as contract code (`hemi-code`): chunks
of at most 24,575 bytes as `0x00`-prefixed data contracts, then a manifest. It is permanent and
public. The rules it follows are the format's own (§13.5 of the design):

- the key is an encrypted keystore of its own (password from the terminal, or `--password-fd N`:
  N ≥ 3, a pipe or a file the caller opened for the command, checked before anything else
  starts), never the miner's key file, the environment or argv; it is refused when it is
  `[witness] prover_address`, staked as a prover, authorized as a prover's operator (read from the
  chain; an authorization voided by `revokeAllOperators` no longer counts), or has pending
  transactions it did not send. A stuck chunk blocks every later nonce of its sender, so a prover
  key would stall its fulfils. The keystore's parameters are checked before any work, and the
  password, the derived key and the decrypted key are zeroed after use;
- every request goes through the network guard with a rate limit of its own
  (`--max-requests-per-sec`, default 4); the RPC must be `https://` unless the configuration's
  `[dev] private_network` is for that very chain (which also lets it be on loopback or the LAN);
  `--rpc-url` may not be the miner's `[chain] rpc_url` while a miner runs. The URL can come from
  `--rpc-url-file FILE` or `ZKMINER_PUBLISH_RPC_URL` instead of argv, where every local user sees
  it (it may carry a provider key);
- **the RPC is trusted**: the pacing gate's readings and the key checks are its answers, so a
  lying one could open the gate or pass a prover key. Two things bound that. Sends are paced by
  the local clock too, at least a block time apart whatever the RPC reports (12 s on Hemi, else
  measured, never under 1 s outside developer mode; `--block-time-ms` sets it, never below a known
  chain's). And `--verify-rpc-url URL` (or `--verify-rpc-url-file`) names a second provider:
  each deployment must show there, in the same block and with the same code, before the next
  chunk is signed, and the artifact is read back there too;
- a cost preview (L2 gas at the chosen tip, the L1 data fee from `GasPriceOracle`, the balance one
  in-flight chunk needs) comes first, confirmed on the terminal or with `--yes`;
- one chunk in flight, at most one send per block and per block time, and only while the DA
  backlog plus its own unmined estimates is under 250 KB, the safe head lags at most 300 s, the
  router is not paused and the head is at most 60 s old: about twenty minutes per MiB. Each chunk's
  transaction estimates at most 19,500 DA bytes. A chunk unmined for 3 blocks with the gate open is
  replaced at its nonce with both fee fields raised, at most 16 times, the tip never past 64 times
  the measured tip floor and the max fee never past 8 times the starting base fee plus that; a
  refused replacement leaves the pooled fees as they were. Past the replacements or the caps it
  waits while the pool holds the chunk; one the pool dropped is sent again as it was, at most 3
  times, and the publish stops with an error if the pool refuses it or keeps dropping it. A failed
  creation is redeployed at a new nonce;
- it waits until every deploying block is at or below the safe head with its hash unchanged, reads
  the artifact back there with the miner's manifest, chunk and assembly checks, and only then
  prints the locator, sha256, length, addresses, total cost, and the `builderId` (or, for an ELF,
  the `addStorageURI` arguments). Submit the job only after that. `--json` prints it as JSON;
- `--progress FILE` records each mined deployment, and each transaction before it is sent (synced
  to disk); run the same command again after a failure and it reuses the recorded chunks whose code
  is on chain, and the transaction a killed run left in flight when it created the next one, sending
  only the rest (while that transaction is still pending, the run refuses to start: let it settle).
  Without it, a run that stopped part-way is run again from the start: every chunk is sent (and
  paid) again.

The router is the known deployment's on the chain, else `--router`. A configuration's `[dev]
da_backlog_bytes` stands in for the backlog reading only in developer mode, and on Hemi testnet's
chain id only against a node on loopback (a local fork).

## Layout

| crate | role |
|---|---|
| `zkminer-cli` | binary entry point: `status`, `benchmark`, `run`, `simulate`, `witness`, `artifact`, `init` |
| `zkminer-chain` | chain client, auction math, staking, monitor, tx/nonce layer, RPC metering |
| `zkminer-netguard` | the network guard: what a requester-caused connection may reach (see SECURITY.md) |
| `zkminer-contracts` | `sol!()` bindings — the source of truth for the on-chain ABI |
| `zkminer-prover` | worker dispatcher, ELF registry, benchmarks, guest programs |
| `zkminer-prover-protocol` | worker↔dispatcher IPC types |
| `zkminer-prove-risc0` / `-sp1` / `-openvm` | standalone GPU worker binaries |
| `zkminer-strategy` | profitability evaluation, cost model, timing prediction |
| `zkminer-tui` | ratatui interface |
| `zkminer-config` | TOML config and wallet key loading |

RISC Zero, SP1 and sppark are patched to the `hemilabs` forks (GPU + AMD support, and Metal for
risc0) via `[patch.crates-io]`, each pinned by an immutable git rev in `Cargo.toml` and recorded in
`Cargo.lock`. **Don't run `cargo update`**: builds use `--locked`, and the lockfile is what holds every
other dependency on the versions that were validated.

## Testing

```bash
cargo test                                    # unit + integration
ZKVM_ALLOW_SKIP=1 cargo test                  # skip tests needing GPUs/guest ELFs

# comprehensive zkVM suite — dispatches to the installed GPU workers
cargo test -p zkminer-prover --features risc0,sp1 --test comprehensive_zkvm_test \
    -- --test-threads=1 --nocapture
```

On a Mac, `make -f Makefile.mac mac-test-miner mac-test-risc0` runs the macOS and Metal suites
(see [macOS](#macos-apple-silicon-metal)).

The zkVM suite is **fail-closed**: a missing worker or guest ELF fails the test rather
than skipping, so a half-installed box can't look green. Set `ZKVM_ALLOW_SKIP=1` to skip
instead. Run it single-threaded to avoid GPU contention, and log to a file rather than
piping to `tail`, which buffers and can hide a hang.

### Witness requester tools end to end

`crates/zkminer-cli/tests/simulate_witness.rs` runs `zkminer witness envelope encode`, `zkminer
simulate --descriptor` (with `--adversarial`) and `zkminer artifact publish` on anvil with the real
sandboxed runner, broker and CPU risc0 worker, and checks that a builder published with `artifact
publish` is fetched by the broker's own `hemi-code` reader. It needs a delegated cgroup, anvil and
the SDK's pinned toolchain:

```bash
systemd-run --user --scope -q -p Delegate=yes -- env ZKMINER_SANDBOX_TESTS_REQUIRED=1 \
    cargo test -p zkminer-cli --test simulate_witness -- --test-threads=1
```

The publisher's own tests (pacing, a chunk dropped from the pool and replaced at its nonce, an
out-of-gas creation redeployed, the key refusals) run against anvil in `cargo test -p zkminer-cli
--bin zkminer artifact::` (skipped without anvil unless `ZKMINER_ANVIL_TESTS_REQUIRED` is set).

### Localnet end-to-end test

`crates/zkminer-cli/tests/localnet.rs` runs the real `zkminer` binary against a local anvil
fork of Hemi testnet 743111. The fork carries the live HemiProve v2 contracts. On the fork,
the tests:

- mints tHEMI and stakes a prover;
- registers its programs, with storage URIs the test serves itself;
- submits jobs covering the binding, assignment and collateral cases: four the miner must claim
  (one of them assigned to another prover with no exclusivity window, which anyone may claim),
  and the rest (wrong FULL or FIELDS journals, jobs reserved for another prover, a job inside
  another prover's exclusivity window, a job whose 500% collateral exceeds the prover's whole
  stake, the journal-prefix marker, an unreachable ELF, and — with the real risc0 worker, so in
  the watch-only and mining tests — a decoy ELF whose image id is not the job's program) it must
  refuse.

Some jobs are submitted before the miner starts and some after, so both the startup backfill
and the live monitor are covered; the backfill starts at the first job's block, so one that
starts a block late loses it. Nothing touches the real chain, and no key of yours is involved;
each miner runs with its own HOME and a cleaned environment. The programs are served from
127.0.0.1, so each miner's config sets `[dev] private_network = true` and `[dev] chain_id =
743111` (the fork's chain id, where developer mode is allowed).

```bash
env NVCC=/usr/local/cuda/bin/nvcc HIPCC=off \
    cargo build --release -p zkminer-prove-risc0 --features cuda --bin zkminer-prove-risc0-cuda
cargo build -p zkminer-prover --features testing --bin mock-worker
cargo test -p zkminer-cli --test localnet -- --ignored --nocapture --test-threads=1
```

On a Mac, build the Metal worker (`--features metal --bin zkminer-prove-risc0-metal`) and point
`ZKMINER_LOCALNET_RISC0_WORKER` at `target/release/zkminer-prove-risc0-metal`. Foundry 1.5.1
(`anvil`) is the version the HemiProve reference daemons support.

- **`watch_only_reports_every_job`** (CPU only) runs `zkminer run --watch-only`, as the staked
  prover and then as an unstaked address, with an unknown `RISC0_EXECUTOR` that the worker must
  ignore. It checks every job's verdict, that exactly the claimable jobs would be claimed, that
  every measured cycle count is a power of two, and that nothing was sent.
- **`fulfils_with_a_replayed_receipt`** (CPU only) mines for real on a risc0 3.1 Groth16 receipt
  that the Metal worker made (the fibonacci guest), which the deployed v3.1.0 verifier accepts: the
  mock worker replays the receipt instead of proving. It requires exactly the claimable jobs to be claimed and then fulfilled in a
  later transaction, the exclusive and over-collateralised jobs never even dispatched, nothing
  released, and no collateral left locked.
- **`holds_its_lock_through_a_pause`**: a lock held while the router pauses is kept, then
  fulfilled after the lift.
- **`holds_off_while_the_router_is_paused`**, **`refuses_to_claim_while_its_adapter_is_disabled`**,
  **`refuses_to_claim_on_a_skewed_clock`**: the miner's own gates hold every claim (none is even
  dispatched).
- **`refuses_to_claim_without_a_matching_verifier`**: a miner configured with the risc0 3.0
  selector refuses every risc0 claim.
- **`mines_the_claimable_jobs`** (`ZKMINER_LOCALNET_MINE=1`, needs a GPU) is the replay test with
  real risc0 proofs of the fibonacci guest; it also checks each `JobFulfilled` payout
  (settled price + speed bonus - 1% protocol fee).
- **`serves_witness_jobs`** (Linux, CPU only, a delegated cgroup) serves witness-construction jobs
  with the real broker, builder runner and CPU worker under the rootless sandbox: one simulated,
  claimed, proven and fulfilled with `fulfillJobHashed`; one whose binding the guest does not meet,
  never claimed; one from a caller not allowed, never simulated.
- **`serves_the_proxy_slots_witness_job`** (Linux, a delegated cgroup, the risc0 toolchain) runs the
  plan's §12 job: an EIP-1967 proxy changed by real transactions on a second anvil (the `evm-rpc`
  chain), the reference builder published with `zkminer artifact publish`, the job made with
  `zkminer witness envelope encode` and `binding compute` (FIELDS over its 160-byte header, the
  journal-prefix marker, an exclusivity window), proven on the CPU worker, and `publicValues`
  checked against the second chain's state at the job's block. **`..._on_a_gpu`** proves it on
  `ZKMINER_LOCALNET_RISC0_WORKER` (default the release CUDA worker).

The tests need Foundry's `anvil` and the testnet RPC, which serves archive state; anvil caches
what it fetches. Settings (fork URL and block, worker paths, echoing the log) are in the file's
header. Move its `FORK_BLOCK` forward whenever `zkminer-chain/src/deployment.rs` changes.

## Examples

`examples/` holds job submitters for testing against a live market. They read their
signing key from the environment (`SUBMITTER_KEY`, `REQUESTER_KEY`) and refuse to run
without it — never commit a funded key. The forge-based submitters additionally need
`CONTRACTS_DIR` pointing at a HemiProve Foundry checkout; `testnet_submitter_cast.sh`
needs only `cast`. The two `testnet_submitter*.sh` scripts still target an abandoned stack and the
old descriptor and proof-system id: they are kept for reference and do not work against the
2026-11-16 deployment.

## License

MIT — see [LICENSE](LICENSE).

Releases also ship `libcudart.so.12`, NVIDIA's CUDA runtime, unmodified. It is NVIDIA's software,
distributed under the NVIDIA CUDA Toolkit End User License Agreement, which lists it as
distributable with an application, and not under this license. Its notice and that agreement ship
beside it as `libcudart.so.12.LICENSE.txt`. The AMD tarball ships AMD's ROCm HIP runtime, and the
Intel tarball oneAPI's SYCL runtime and Intel's compute runtime, Level Zero loader and graphics
compiler, each unmodified (Intel's built from source) and under its own license, in
`zkminer-rocm/LICENSES/`, `sp1-gpu-server-hip-lib/LICENSES/` and `zkminer-intel/LICENSES/`.
