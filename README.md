# zkminer

Multi-zkVM, multi-GPU-vendor ZK proof generator for Hemi's ZK proving marketplace
(HemiProve).

zkminer watches the marketplace for open proving jobs, estimates whether each one is
worth taking, claims the ones that are, generates the proof on a local GPU, and submits
it on-chain. Proving runs in separate worker processes — one per GPU — so a wedged or
OOM-killed prover can't take the miner down with it.

Backends: **RISC Zero** (CUDA, ROCm and Intel) and **SP1**. **OpenVM** is experimental: its
worker builds and starts, but the miner claims no OpenVM job unless `ZKMINER_ENABLE_OPENVM=1`
is set, so leave `zkminer-prove-openvm` out of an install. `zkminer doctor` shows, card by card,
what this host can prove, and why not.

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

Running needs RISC Zero's `risc0-groth16` component (the Groth16 proving key, 5.8 GB), but not
`rzup`: the risc0 worker installs it in its one-time setup, before the miner claims any risc0 job,
when `~/.risc0/extensions/v0.2.0-risc0-groth16` (or `RISC0_GROTH16_DIR`) does not hold it. It
downloads the 2.4 GB archive rzup itself uses from RISC Zero's artifact store and checks its
SHA-256 (`crates/zkminer-prove-risc0/src/groth16_component.rs`). `rzup install risc0-groth16`
installs the same files.

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
(`sudo usermod -aG render $USER`). Run it as such a user, not as root: its workers drop every
capability, but as uid 0 they could still read root's files after an executor escape, so a run as
root on a bare host logs `PAGE: RUNNING-AS-ROOT` and `zkminer doctor` warns of it (only the
dashboard's GPU tuning needs root). The release workflow checks all of this on real GPUs before it
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
max_locked_stake_fraction = 0.5     # every held lock together: at most this share of the stake

[egress]                            # optional
deny_cidrs = ["203.0.113.0/24"]     # the rest of your fleet, your VPC's ranges
```

`zkminer init` will scaffold a config, but **verify the contract addresses it writes
against the deployment you intend to use** before running against a live market. On a
chain zkminer knows (743111), `run` checks the addresses, their wiring and their code
against the live deployment; a mismatch starts the miner without claiming anything (it
still drives locks it already holds) and logs a `PAGE:` line naming the difference, so
fix `[contracts]` and restart. On 743111 the live deployment is the 2026-11-16 one (router
`0xD931725db336B57dBB9A3123F2238A4FE3c6Ed58`, risc0 3.1 verifier); a config written for the
2026-10-29 stack (router `0xE1a492Dc…470e`) names an abandoned deployment, so rewrite it with
`zkminer init --network testnet --force`.

### Network guard: `[egress]` and `[dev]`

Anyone can register a program and post a job, so the URLs a miner downloads programs from
are chosen by strangers. zkminer only ever connects to **public internet** addresses on
their behalf: never loopback, the LAN, link-local or cloud metadata, this host's own
addresses (its public address behind NAT included, which it learns from fixed reflectors), a
neighbour on a network it is connected to or routes to other than through its default route
(the kernel is asked, per destination and port, how it would route the connection, policy rules
included), an address a `local` route delivers to this host, the rest of its IPv6 site (a /32)
or of the IPv4 /16 around a public address on its interfaces, the DNS servers it uses, a
private address behind NAT64, a destination that answers within 2 hops of this host (its router,
a neighbour in the same VPC: a hop-limited probe asks right before each connection), or a name
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
| `[egress] near_hop_limit` | `2` | Right before every requester-caused connection, a probe whose packets may cross at most this many hops connects to the destination: one that answers (accepts, or refuses with a reset) is this host's own network and is refused. When the probe gets no answer, a check connection decides: once connected, its FIN, limited to the same hop count, must go unanswered. 2 to 16. |
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
runs in a cgroup of its own, with its memory ceiling, killed with `cgroup.kill` when the worker
ends (below the miner's when the miner runs in a cgroup delegated to it, such as under
`systemd-run --user --scope -p Delegate=yes zkminer run` or
[`contrib/zkminer.service`](contrib/zkminer.service), which has `Delegate=cpu memory pids`, else
in a scope of your systemd user manager; a system unit has no user manager, so one without
`Delegate=` leaves every worker with no memory ceiling, which the miner reports at start-up as
`PAGE: WORKERS-UNCAPPED` and `zkminer doctor` as a warning); a small reaper process
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
  drains, and `Restart=on-failure`, so `zkminer stop --keep-locks` restarts it in place. It
  also sets `Delegate=cpu memory pids`, which gives every worker a memory ceiling, and
  `OOMPolicy=continue`, without which systemd stops the whole unit (a drain, then a restart)
  when the kernel kills one worker for memory; a unit installed from an older copy has neither:
  copy the new one over it, `systemctl daemon-reload`, and restart the miner when its locks
  allow (`zkminer doctor` says whether the installed unit has both). A key in the unit's
  `/etc/zkminer/env` must be readable by root only: create the file with `sudo install -m 600
  -o root -g root /dev/null /etc/zkminer/env` before the key goes in (an editor or `tee`
  alone makes it readable by every user), or pass the key as a systemd credential (the unit
  shows how). The miner pages `KEY-FILE-READABLE`, and `zkminer doctor` fails, when other
  users can read or change the key's file; doctor also checks that only root and the miner's
  user can replace the miner, its workers, its configuration and `~/.sp1/bin`. To
  upgrade, `install -m755` the new miner and every worker over the old ones (all of them: a
  worker from another build is refused), then `zkminer stop --keep-locks`. For Docker, run
  with `--stop-signal SIGINT --stop-timeout 4200 --restart on-failure` and keep `~/.zkminer`
  on a volume (`-v zkminer-home:/root/.zkminer`): the kept locks are found through the job
  journal there, and a new container without it never finds them. The miner runs as root in
  that container, and its workers drop every capability; `--cap-drop=ALL --security-opt
  no-new-privileges`, or `--user` with a uid that owns the volume (mounted at that user's
  `~/.zkminer`), narrows the container further. Restart in place with
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
  before systemd restarts it). For a Windows service, see the next point.
- **A Windows service runs as a dedicated standard user, with its key in a file.** The miner's
  workers run requesters' guest programs as the account the miner runs as, so give the miner an
  account of its own with no other rights. `zkminer run` refuses LocalSystem, LocalService and
  NetworkService (NSSM's default is LocalSystem): a guest that broke out of a worker would have
  that account's rights, and under LocalSystem the miner could not keep any worker from its key.
  It refuses an administrator's account as a service too (UAC filters no service logon), and a
  start that cannot tell which account it runs as.
  `ZKMINER_DANGEROUSLY_ALLOW_PRIVILEGED_ACCOUNT=1` runs it anyway, paged at every start. An
  elevated (administrator) console is paged, not refused, and an administrator's console that is
  not elevated is warned of. From an administrator console:

  ```
  net user zkminer * /add
  copy nssm.exe "C:\Program Files\zkminer\"
  cd "C:\Program Files\zkminer"
  .\nssm install zkminer "C:\Program Files\zkminer\zkminer.exe" run --headless
  .\nssm set zkminer ObjectName .\zkminer <password>
  .\nssm set zkminer AppStopMethodConsole 3900000
  sc privs zkminer SeChangeNotifyPrivilege/SeCreateGlobalPrivilege/SeIncreaseWorkingSetPrivilege
  ```

  A service logon gives the account `SeImpersonatePrivilege` through the SERVICE group, and with
  it a guest that broke out of a worker could make itself SYSTEM. `sc privs` leaves the service
  (NSSM included) only the three privileges named. Whatever the service is given, `zkminer run`
  removes every other privilege from itself at start-up and from each worker before it runs; a
  worker that still holds a dangerous one is not started (`PAGE: WORKER-PRIVILEGES`).

  Install the miner, its workers and `nssm.exe` (the program the service actually starts) in a
  directory only administrators can write (`C:\Program Files\zkminer`), not in a new folder under
  `C:\`, which every local user can write to: a user who can replace any of them runs code as
  the miner's account, key included. Keep a `--config` file there too, or in the account's own
  `.zkminer`. `zkminer doctor` fails when any of these, or its directory, can be written by
  anyone but SYSTEM, Administrators, TrustedInstaller and the miner's account. NSSM grants the account "Log on as a service". Its home is `C:\Users\zkminer`, so the
  miner keeps its `.zkminer` there; run `zkminer` commands for it as that account (`runas
  /user:zkminer cmd`, then `zkminer init`, `zkminer doctor`, `zkminer stop`). Give it its key in
  a key file (`key_source = "file"`), never in its environment: NSSM keeps `AppEnvironmentExtra`
  in `HKLM\SYSTEM\CurrentControlSet\Services\<service>\Parameters` and `setx /M` keeps a
  variable in the machine's environment, and every user of the PC can read both. `zkminer init
  --generate-key --network <network>` run as the account writes the key to its `.zkminer` with
  an ACL for that account and SYSTEM only; for a key file made another way, `icacls <file>
  /inheritance:r /grant:r zkminer:(R,WO)` leaves only the account on it. Keep `WO`: the miner
  labels the key file so that its Low-integrity workers cannot read it, which needs the right to
  change the file's owner (the account's own files have it). A key file it can neither label nor,
  as its owner, open to labelling is paged (`PAGE: SECRETS-UNLABELLED`) and no worker starts
  until it is fixed. `zkminer doctor` says when the miner's account is refused or elevated,
  which dangerous privileges it holds, when the key file cannot be labelled, and when the key's
  variable is kept in the machine's, a service's or the user's environment; the miner's start-up
  pages each.

  On Windows the workers run at Low integrity. They read neither the key file, `.env` nor the job
  journal; they cannot open or end the miner, nor open each other or the threads each starts; and
  they write only where Low processes may (their temporary, cache and segment directories, which
  the miner repairs before each Low worker it starts). What their first warm-up downloads or builds
  in your profile (the SP1 server in `~/.sp1/bin`, the Groth16 artifacts in `~/.risc0` and
  `~/.sp1/circuits`) the miner installs itself, at Medium, before it. What they still can do: use
  the network, see and end the processes a sibling starts (SP1's `sp1-gpu-server`) and use the
  temporary and cache directories every Low worker shares. It fails closed: a worker that cannot
  start at Low is never started at Medium instead; its slot proves nothing, with `PAGE:
  LOW-IL-WORKER-FAILED` naming the worker binary and its last words (`PAGE: LOW-IL-WARMUP-FAILED`
  for one whose warm-up fails), and the miner tries it again at Low with back-off. A job whose
  proof the miner has died in the middle of three runs in a row (a crash, or a guest that broke
  out and ended it) is released, with `PAGE: JOB-CRASH-LOOP`, rather than proven again. If a zkVM
  works on your card only at Medium, `ZKMINER_WINDOWS_LOW_IL_WORKERS=0` runs every worker at
  Medium, where a guest that breaks out can read the key: it is paged at every start (`PAGE:
  MEDIUM-WORKERS`) and `zkminer doctor` warns.

  Moving from LocalSystem: stop the old service with `zkminer stop --wait` run as LocalSystem
  (`psexec -s`; its home was `C:\Windows\System32\config\systemprofile\.zkminer`) so it finishes
  or releases its locks, then change the account. A miner started in the new account's home does
  not see the old journal, so locks kept there are never driven. A LocalSystem service upgraded
  in place to this build while it holds locks does not prove them: it releases each one (at its
  penalty, starting no worker), pages `PRIVILEGED-ACCOUNT`, and exits with the refusal and the
  list of what it released; what it could not release is tried again at the next start. Consider
  a key that was in
  `AppEnvironmentExtra` exposed. A service wrapper's stop (NSSM sends Ctrl+C, then kills the
  process after its timeout) starts a drain it then cuts off: run `zkminer stop --wait` (as the
  service account) before stopping the service, or keep NSSM's timeout long enough for a drain
  (`AppStopMethodConsole` above).
- **One miner per key.** Two miners on one key drive the same locks and replace each
  other's transactions. `run` holds `~/.zkminer/miner.lock`, so a second one from the same
  home refuses to start (including while the first is still draining); it can't see one in
  another home or on another host. `--watch-only` takes no lock.
- **`PAGE:` lines need a human.** They say claiming has stopped (the deployment or proof
  system failed its check, the protocol is paused, the clock is off, funds are short) or a
  lock is at risk. The dashboard shows them; headless, they go to stderr.
  `PAGE: CHAIN-UNREACHABLE` says no chain read has succeeded for a minute while locks are held
  (repeated every 5 minutes): fulfils and releases go through the same RPC, so the locks can be
  neither proven nor given back until it returns. `PAGE: LOCK-AT-RISK <job>` follows for each lock
  whose cutoff comes inside its release margin meanwhile. The dashboard's link badge shows the age
  of the last chain read (`STALE`, then `DISCONNECTED` after 2 minutes). On Windows, where a Low
  worker has the network, an outage of 10 minutes with locks held also stops every worker once
  (`PAGE: WORKERS-RECYCLED`; they start again on demand) in case one of them is holding the link.
  `PAGE: ESTIMATE-OVERRUN <card>` says jobs claimed on that card's benchmark rate overran their
  cutoff (a release penalty each) after its learned rate had refused them: the card is proving
  slower than benchmarked (a VRAM spill, heat, a smaller shard size). For the next 6 hours claims
  for it are sized on the learned rate; re-run `zkminer benchmark` once the cause is fixed.
- **After a slash the miner stops claiming until you say so.** `PAGE: SLASHED` says a lock of
  this prover was slashed (the on-chain `jobsSlashed` rose, a lock ended past its deadline, or the
  miner slashed its own expired lock); `PAGE: STAKE-DROP` says the stake fell by more than a
  withdrawal and the miner's own release penalties explain. Either trips the slash latch,
  `~/.zkminer/slash_latch.json`: no new claims, across restarts, until `zkminer resume-claims`
  (it prints what tripped it, then clears it; `--yes` skips the prompt). Locks already held are
  still fulfilled or released. The page repeats every 30 minutes while it holds; `zkminer status`
  shows it and exits 2, `zkminer doctor` fails on it, and the dashboard shows `SLASHED`. Find out
  why the lock was lost (the link, the RPC, the card) before resuming: see the cut-off point below.
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
  submitter, that this miner holds and has not settled yet (fulfilled, released or slashed) over
  the cap waits until they settle. Witness jobs are held to the same cap, inline and witness locks
  counting together, and `run --watch-only` reports a job over it. A value that is not a number
  from 0 up is warned about and the default used.
- **Every lock held at once comes to at most half the stake.** Programs and submitters cost
  nothing to make, so the per-program and per-submitter caps alone let a few of them lock nearly
  the whole stake together. `[prover] max_locked_stake_fraction` (default `0.5`, more than 0 and
  at most 1; `1` lets the whole stake be locked) bounds the collateral of every lock this miner
  holds and has not settled, across programs and submitters, with the same per-job floor. A lock
  counts until it settles, not until its proof is done, and the locks found at a restart count
  again. A job that would take them over the cap waits. `zkminer status` and the startup log show
  the cap in HEMI.
- **A miner cut off from the chain is slashed for every lock it holds.** A lock that is neither
  fulfilled nor released by its deadline (plus grace) is slashed in full, and the miner reaches the
  chain through one `[chain] rpc_url`. A submitter can single a miner out (a job assigned to it, or
  one only it measures), learn its IP from the ELF download, and then flood that link, or drop its
  traffic from an on-path position, until the deadlines pass: a home connection or a small VPS
  without DDoS protection is the realistic target. The cap above bounds what one such round costs
  to its share of the stake, not what an incident costs: the cap is taken of the stake that is
  left, so every further round could take that share again. The slash latch (above) is what stops
  the next round: after a slash the miner claims nothing new until `zkminer resume-claims`, so do
  not clear it while the cause is still there. Neither stops the slash itself. Stake only what you
  accept losing, lower `max_locked_stake_fraction` on a link a booter can saturate, and prefer a
  DDoS-protected host with an RPC endpoint you trust.
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
  proved in 62 s, against 242 s left to page). Benchmarks are guarded the same way, since the
  miner saves their rates and plans with them: one that another program's memory paged, or that
  ran while another program took more of the card, is measured again (up to four runs, 30 s
  apart), and an SP1 benchmark that runs out of GPU memory is measured again one shard size
  smaller, that size then kept for the card. Still, leave the card the room these figures say.
  The miner helps:
  a RISC Zero proof on an NVIDIA card starts only when its segment size's measured peak fits in
  what is free (else it waits, or goes to another card, and no RISC Zero job is claimed for that
  card until a check every 5 minutes finds the room; a job that waits about 2 minutes without room
  is released), and under Windows an NVIDIA card that another program also uses (a display) is
  sized 1 GiB smaller, for that program to grow into (on a 12 GB card that means SP1's smaller
  shard size: re-benchmark such a card after upgrading, as its saved SP1 rate was measured at the
  larger one). `ZKMINER_MIN_AVAILABLE_VRAM_MB=0` turns all of this off.

- **Under Windows, a proof needs both RAM and commit** (Task Manager → Performance → Memory,
  "Committed"). Windows charges every allocation to its commit limit, RAM plus the page file, and
  under WDDM it charges a program's GPU memory too, which never touches RAM. Measured on an RTX
  5090: an SP1 proof uses 37 GB of RAM and commits 63 GB (22 GB of it VRAM), and a RISC Zero proof
  at po2 20 uses 2–6 GB of RAM and commits 28 GB. A proof starts when its card's RAM figure fits in
  free RAM and its commit figure fits in what can still be committed, beside what the proofs
  already running have still to take. Until a card has proved, those figures are 8 / 30 GiB for
  RISC Zero and 40 / 64 GiB for SP1; after that, they are that card's own peaks plus an eighth.
  Windows' default page file (system-managed) grows by itself when commit runs short, so it needs
  no setting: the miner counts how far it can still grow. A fixed page file can't grow, so with
  one, keep it at least as large as the commit the proofs you run at once need beyond RAM, or make
  it system-managed again (System Properties → Advanced → Performance → Virtual memory). Only the
  VRAM part of a proof's commit counts on the page file growing: the miner waits to start a proof
  until the commit free now holds the RAM it and the running proofs have still to take, plus
  4 GiB, since pinned memory fails at the limit instead of waiting for the page file to grow
  (measured). An idle worker of the other zkVM is stopped
  when a proof needs what it holds (an idle SP1 server keeps 11 GB of RAM and 22 GB of VRAM on an
  RTX 5090). If a proof fails while the host is out of commit, the failure isn't held against the
  card.

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
- else, on an NVIDIA card, the largest measured size that fits it with 1.9 GiB to spare: 20
  from 14 GiB of VRAM (po2 20 peaks around 12.1 GiB), 19 from 9.8 GiB (8.0 GiB), 18 from
  6.5 GiB (4.6 GiB), and none below that; on an AMD or Intel card, whose sizes haven't been
  measured, 20 from 14 GiB and none below.
  A card whose VRAM isn't known gets 20: an Intel card on the i915 driver, a CUDA query that
  failed, or the card
  behind a risc0 worker named in `[prover.worker_binaries]` (which isn't pinned to a card);
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
use from protocol 13: a function of the image id and every byte the guest reads, so a guest's random
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
