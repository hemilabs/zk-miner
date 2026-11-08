# zkminer

Multi-zkVM, multi-GPU-vendor ZK proof generator for Hemi's ZK proving marketplace
(HemiProve).

zkminer watches the marketplace for open proving jobs, estimates whether each one is
worth taking, claims the ones that are, generates the proof on a local GPU, and submits
it on-chain. Proving runs in separate worker processes — one per GPU — so a wedged or
OOM-killed prover can't take the miner down with it.

Backends: **RISC Zero** (CUDA, ROCm and Intel), **SP1**, **OpenVM**.

## Requirements

| | |
|---|---|
| Rust | 1.93.0 (pinned in `rust-toolchain.toml`) |
| RISC Zero toolchain | `rzup`, see below — **required to build, and to prove** |
| CUDA | toolkit with `nvcc` (12.8–13.x tested) for NVIDIA workers |
| ROCm | 6.4+ with `hipcc` for AMD workers |
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

Running needs RISC Zero's `risc0-groth16` component (the Groth16 proving key, 5 GB), but not
`rzup`: the risc0 worker installs it in its one-time setup, before the miner claims any risc0 job,
when `~/.risc0/extensions/v0.1.0-risc0-groth16` (or `RISC0_GROTH16_DIR`) does not hold it. It
downloads the 2.3 GB archive rzup itself uses from RISC Zero's artifact store and checks its
SHA-256 (`crates/zkminer-prove-risc0/src/groth16_component.rs`). `rzup install risc0-groth16`
installs the same files.

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

## Configure

Copy or write `~/.zkminer/config.toml`:

```toml
[chain]
rpc_url  = "https://testnet.rpc.hemi.network/rpc"
chain_id = 743111                   # Hemi testnet (43111 is mainnet)

[contracts]
hemi_prove          = "0x..."       # router (diamond proxy)
hemi_prove_staking  = "0x..."
hemi_prove_registry = "0x..."
hemi_token          = "0x..."
program_registry    = "0x..."       # where programs' ELF sources are read; defaults to the known deployment's

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
fix `[contracts]` and restart.

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
- **Keep `~/.zkminer/risc0-sys-rand.key`.** It seeds guests' randomness, so a measurement
  and the proof after it agree; a lock re-proved after a restart needs the same key. Don't
  copy it off the host.
- **Escape hatches, for after you've checked by hand:** `ZKMINER_SKIP_CODE_PINS=1` skips
  the audited-code checks (router, Staking, Registry, facets, and the risc0 adapter and
  verifier), `ZKMINER_ALLOW_UNKNOWN_DEPLOYMENT=1` accepts contract addresses that aren't
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
(`JobFulfilled.actualCycles` is 0 for every adapter but PoVW).

```bash
zkminer --config simulate.toml simulate --job 0x… --job 0x…
zkminer --config simulate.toml simulate --stdin   # one request per line: a job id, or
                                                  # {"jobId":"0x…","submitTx":"0x…"}
```

Each job goes through the steps a claim depends on: its descriptor rebuilt from the submit
transaction and checked against its on-chain hash (a `submitTx` hint saves the log scan), the
program's ELF from the ProgramRegistry, those bytes bound to the job's `programId`, and one execution
on a measure worker at `--po2` (risc0, default 20). The binding is derived, never trusted: the risc0
image id, or the SP1 verifying-key hash from SP1's `setup` on the CPU (minutes per program, cached on
disk per ELF under `--cache-dir`, default `~/.zkminer/simulate`). SP1 PLONK jobs are measured by the
SP1 worker (the same ELF and vkey hash as Groth16), though the miner does not claim them. A
journal-prefix job runs on its prover's input, `abi.encode(jobId, prover)` and then `inputData`
(risc0; an SP1 one is reported `failed`, since its prefix is a stdin buffer of its own).

A report's `outcome` is one of:

| outcome | meaning | `retryable` |
|---|---|---|
| `measured` | executed; `cycles` is the count (a decimal string) | no |
| `not_served` | its proof system is not one this build measures (OpenVM, unknown) | no |
| `no_worker` | no measure worker for its backend runs here | yes |
| `undecodable` | its descriptor can never be rebuilt | no |
| `no_program` | the program is not in the registry, or has no storage URIs | yes |
| `program_mismatch` | the ELF the registry declares (its keccak256 is the registry `elf_hash` or a URI's content hash) is not the job's program | no |
| `too_heavy` | past the executor's cycle cap, or above `--max-cycles` (default 4e9, risc0's keccak charge included) | no |
| `failed` | the guest or the worker failed, or bytes the registry does not vouch for did not bind | yes, a few times |
| `timeout` | the execution or the program-id derivation hit its bound | yes, a few times |
| `unavailable` | nothing conclusive: the RPC, the registry or the ELF host failed, a worker was busy or found dead, or the program's last derivation failed and is remembered | yes |

A program whose ELF did not bind (refused, another id, a derivation past its bound) is remembered
under `--cache-dir` for `--program-failure-ttl-secs` (default 6 h, 0 = off): its other jobs are
answered from that memory, `unavailable` (or `program_mismatch` when that was the verdict), instead
of each paying a download and a derivation. `--execute-timeout-secs` (default 600) and
`--program-id-timeout-secs` (default 900) bound one execution and one derivation, each at most 86400.

With `--stdin`, a READY line comes first, once the measure workers run and before any request is
read; a reader should send nothing before it:

```json
{"schema":1,"ready":true,"backends":["risc0","sp1"],"zkminerVersion":"0.1.0","protocolVersion":11}
```

(`backends`: those with a live measure worker, sorted.) A line that is not a request is answered
`{"error":"invalid_request","reason":"…","schema":1}` in its place.

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
  at `--po2`, plus a charge of 2^20 for each keccak proof request (a price, not cycles: about a 2^20
  segment's proving time; doubled per step of a larger keccak po2). SP1's is
  the RV64 instruction count, where a precompile (keccak, sha, ...) counts once. On the same program
  and input, risc0 reports about twice SP1's figure: never add or compare the two.
- **po2.** risc0 counts depend on the segment size: a job proven on a small card (po2 16) has about
  1.8 times the po2-20 count. A report carries the `po2` it was measured at; changing `--po2` mixes
  sizes in what was already stored.
- **sys_rand.** A guest's randomness is seeded from this host's key file, not its prover's (which is
  secret), so a guest that reads it may take another path, and commit another journal, than the
  proven run. `binding` (`satisfied`, `fails`, `unchecked`, `none`) says whether the measured journal
  satisfies the job's binding; `fails` means the measured run is provably not the proven one.

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

- **`watch_only_reports_every_job`** (CPU only) runs `zkminer run --watch-only`, as the staked
  prover and then as an unstaked address, with an unknown `RISC0_EXECUTOR` that the worker must
  ignore. It checks every job's verdict, that exactly the claimable jobs would be claimed, that
  every measured cycle count is a power of two, and that nothing was sent.
- **`fulfils_with_a_replayed_receipt`** (CPU only) mines for real on the contract suite's RISC
  Zero receipt fixture, which the deployed verifier accepts: the mock worker replays the receipt
  instead of proving. It requires exactly the claimable jobs to be claimed and then fulfilled in a
  later transaction, the exclusive and over-collateralised jobs never even dispatched, nothing
  released, and no collateral left locked.
- **`holds_its_lock_through_a_pause`**: a lock held while the router pauses is kept, then
  fulfilled after the lift.
- **`holds_off_while_the_router_is_paused`**, **`refuses_to_claim_while_its_adapter_is_disabled`**,
  **`refuses_to_claim_on_a_skewed_clock`**: the miner's own gates hold every claim (none is even
  dispatched).
- **`mines_the_claimable_jobs`** (`ZKMINER_LOCALNET_MINE=1`, needs a GPU) is the replay test with
  real risc0 proofs of the fibonacci guest.

The tests need Foundry's `anvil` and the testnet RPC, which serves archive state; anvil caches
what it fetches. Settings (fork URL and block, worker paths, echoing the log) are in the file's
header. Move its `FORK_BLOCK` forward whenever `zkminer-chain/src/deployment.rs` changes.

## Examples

`examples/` holds job submitters for testing against a live market. They read their
signing key from the environment (`SUBMITTER_KEY`, `REQUESTER_KEY`) and refuse to run
without it — never commit a funded key. The forge-based submitters additionally need
`CONTRACTS_DIR` pointing at a HemiProve Foundry checkout; `testnet_submitter_cast.sh`
needs only `cast`.

## License

MIT — see [LICENSE](LICENSE).

Releases also ship `libcudart.so.12`, NVIDIA's CUDA runtime, unmodified. It is NVIDIA's software,
distributed under the NVIDIA CUDA Toolkit End User License Agreement, which lists it as
distributable with an application, and not under this license. Its notice and that agreement ship
beside it as `libcudart.so.12.LICENSE.txt`. The AMD tarball ships AMD's ROCm HIP runtime, and the
Intel tarball oneAPI's SYCL runtime and Intel's compute runtime, Level Zero loader and graphics
compiler, each unmodified (Intel's built from source) and under its own license, in
`zkminer-rocm/LICENSES/`, `sp1-gpu-server-hip-lib/LICENSES/` and `zkminer-intel/LICENSES/`.
