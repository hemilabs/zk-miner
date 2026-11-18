# zkminer

Multi-zkVM, multi-GPU-vendor ZK proof generator for Hemi's ZK proving marketplace
(HemiProve).

zkminer watches the marketplace for open proving jobs, estimates whether each one is
worth taking, claims the ones that are, generates the proof on a local GPU, and submits
it on-chain. Proving runs in separate worker processes — one per GPU — so a wedged or
OOM-killed prover can't take the miner down with it.

Backends: **RISC Zero** (CUDA, ROCm, Intel, and Metal on Apple Silicon Macs), **SP1**, **OpenVM**.

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
└── zkminer-prove-openvm
```

**From a release**, put the single files there and unpack the AMD or Intel tarball into the same
directory (`tar --zstd -xf zkminer-provers-amd-linux-x86_64.tar.zst -C ~/.zkminer/provers`). Each
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
`Cargo.toml`'s `[patch.crates-io]` takes from `../deps/risc0-3.1` (branch `zkminer/metal-3.1`:
hemilabs `release-3.1`, risc0 v3.1.0, with the Metal port merged onto it). The
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
0.2 GB; the Groth16 component adds 5.4 GB (about 7.8 GB free while it downloads and unpacks).

```sh
shasum -a 256 zkminer-<version>-macos-arm64.tar.gz   # compare with the release's SHA256SUMS first
tar -xzf zkminer-<version>-macos-arm64.tar.gz
cd zkminer-<version>-macos-arm64
./install.sh                    # ~/.zkminer/zkminer and ~/.zkminer/provers/; --help for options
export PATH="$HOME/.zkminer:$PATH"
zkminer init && zkminer benchmark
```

`zkminer init` is needed once, on the first install (`--with-groth16` or not); it leaves an existing
config alone, so an update needs none. There is no `zkminer --version`:
the kit's `BUILDINFO` names its version and commit, and `zkminer help` lists the commands.

- **Unsigned.** The kit has no Developer ID and is not notarized. Download it only from the GitHub
  release over HTTPS and check its SHA-256 against the release's `SHA256SUMS` before unpacking: the
  kit's own `SHA256SUMS` only catches damage. `install.sh` checks the kit's
  `SHA256SUMS` and removes `com.apple.quarantine` from the files it installs. To run a binary from the
  kit directly, use `xattr -d com.apple.quarantine <file>`, or System Settings → Privacy & Security →
  Open Anyway.
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
simulated 18 GB Mac proves at po2 19.) The full six-program `--benchmark` at po2 20 proves 154.5M
cycles in 169.6 s of STARK (911K c/s) and wraps each program in 1.57-1.59 s. The worker keeps the
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
  hint if it is missing.
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
| `mac-bench` | builds, then `zkminer-prove-risc0-metal --benchmark` (all six programs, about 3 min at po2 20; `BENCH_ONLY=<program>` for one) | ~1 min for fibonacci |

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
- The six-program benchmark takes about 3 minutes at po2 20 on an M5 Max (177-180 s of wall time:
  169.6 s of STARK plus six wraps), longer on smaller Macs.
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

## Run

```bash
export ZKMINER_PRIVATE_KEY=0x...

zkminer status                # balance, stake, collateral, job stats
zkminer benchmark             # measure real per-GPU proving throughput
zkminer benchmark --calibrate # also time each segment size (po2); saves benchmarks.json
zkminer run                   # interactive TUI
zkminer -v run --headless     # headless; -v shows per-job claim/skip reasoning
zkminer run --watch-only      # watch the market; claim, sign and send nothing
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

Verbosity is `-v`/`-vv` **before** the subcommand (`RUST_LOG` is ignored). Logs go to
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
- **Stopping costs locks.** Ctrl-C (SIGINT) stops claiming and lets the jobs in flight
  finish, for up to 50 minutes; a second signal stops waiting, and every lock still held is
  then released. SIGTERM (a supervisor's stop: `systemctl stop` or `restart`, `docker stop`,
  a Kubernetes rollout) releases every held lock at once. Each release costs 5% of that
  lock's collateral. A miner that dies without releasing (SIGKILL) picks its locks up again
  when it restarts, and drives each one that still has time; its workers die with it.
  So to restart without paying for the locks — to upgrade the binary, say — send SIGINT
  (it stops claiming), then SIGKILL (`systemctl kill -s KILL`, `docker kill`), and start
  it again promptly. Exit status 75 means it stopped with locks still held: start it again
  before their deadlines.
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
  refused at start.

Each card proves risc0 jobs at its own segment size (po2), between 16 and 22:
- the size set for it, keyed by its benchmark device id in lower case (`gpu0`, `gpu1`, … for
  NVIDIA cards, `gpu-rocm0`, … for AMD, `gpu-intel0`, … for Intel):

  ```toml
  [prover.risc0_job_po2]
  gpu1 = 19
  ```

  or a po2 under Settings → Advanced, which applies for the session while Advanced mode is on.
  The config is read when the miner starts. The log lists each card's size whenever it changes,
  and names a configured card that isn't here;
- else po2 20, or none for a card with less than 14 GiB of VRAM (po2 20 peaks around 12.1 GiB).
  A card whose VRAM isn't known gets 20: an Intel card, a CUDA query that failed, or the card
  behind a risc0 worker named in `[prover.worker_binaries]` (which isn't pinned to a card);
- `benchmark --calibrate` proves a 62M-cycle Groth16 job at each size, on a card whose VRAM
  is known (NVIDIA; an AMD card under 14 GiB needs a size set for it). Run it with the miner
  stopped. A card then uses its fastest size,
  up to one step below the largest that proved when a larger one failed (or at 22, past which
  the prover refuses). Calibration can raise a card above 20, or give a smaller card a size, but
  never takes a card below 20 if 20 proved during calibration. A plain re-benchmark drops the
  calibration. A slow card may need a larger `benchmark_timeout_secs` at sizes below 18.

A guest can tell the segment size it runs at, so every job is measured at each card size on the
rig before it's claimed. It's claimed only if it measures clean at all of them, with one
journal. A rig whose cards share a size measures once. A claimed job is proven at a measured
size that fits the card. If a restart or a re-benchmark has since moved every card below those
sizes, each card proves the job at its own size rather than releasing it. If no enabled card has
a size, the job waits for one (switch a card back on, or give one a po2 under Settings →
Advanced; a config size or a calibration applies only after a restart, which releases it) and
is released before its deadline.

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
use from protocol 13 (14 since the macOS line merged): a function of the image id and every byte the guest reads, so a guest's random
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
{"schema":1,"ready":true,"backends":["risc0","sp1"],"zkminerVersion":"0.1.0","protocolVersion":11}
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
  segment's proving time; doubled per step of a larger keccak po2). SP1's is
  the RV64 instruction count, where a precompile (keccak, sha, ...) counts once. Never add or compare
  the two.
- **po2.** risc0 counts depend on the segment size: a job proven on a small card (po2 16) has about
  1.8 times the po2-20 count. A report carries the `po2` of its figure, which is the lowest of the
  seven sizes unless the request was `singleRun`.
- **`--max-cycles`.** Every count up to it is the guest's to choose (a keccak request costs a few
  hundred cycles of guest work and is charged 2^20), so it bounds what one job adds to a sum. The
  default, 1e9, is ten times the largest proof seen on this market.

**Never run `simulate` on a host that runs a miner.** The miner's host-RAM and `/dev/shm` ledgers are
per process: a simulate measurement (an SP1 one stages gigabytes in `/dev/shm` and may hold up to
24 GiB) is invisible to a miner beside it, and the two can together OOM or SIGBUS its proofs.

## Layout

| crate | role |
|---|---|
| `zkminer-cli` | binary entry point: `status`, `benchmark`, `run`, `simulate`, `init` |
| `zkminer-chain` | chain client, auction math, staking, monitor, tx/nonce layer, RPC metering |
| `zkminer-contracts` | `sol!()` bindings — the source of truth for the on-chain ABI |
| `zkminer-prover` | worker dispatcher, ELF registry, benchmarks, guest programs |
| `zkminer-prover-protocol` | worker↔dispatcher IPC types |
| `zkminer-prove-risc0` / `-sp1` / `-openvm` | standalone GPU worker binaries |
| `zkminer-strategy` | profitability evaluation, cost model, timing prediction |
| `zkminer-tui` | ratatui interface |
| `zkminer-config` | TOML config and wallet key loading |

RISC Zero and SP1 are patched to the `hemilabs` forks (GPU + AMD support) via
`[patch.crates-io]`, pinned by `Cargo.lock`. **Don't run `cargo update`** — those two are
referenced by moving branch heads, so the lockfile is what holds the build on validated
commits. (sppark is pinned by immutable rev and is not exposed to that drift.)

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
each miner runs with its own HOME and a cleaned environment.

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
