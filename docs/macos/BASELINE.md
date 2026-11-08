# macOS baseline — 2026-10-31

Initial audit recorded before implementation. Gate 1 now has complete independent
Groth16 proof evidence; see VALIDATION.md for current gate status.
Specification: `/Users/dbur/Downloads/HEMI_MACOS_PROVER_SPEC.md` v1.0.

## Source provenance (before edits)

All three supplied checkouts were clean; no applicable AGENTS.md was found.

| Role | Path | Origin | Branch | HEAD |
|---|---|---|---|---|
| Miner target | `/Users/dbur/dev/zk-miner` | `https://github.com/hemilabs/zk-miner.git` | main | `1bbdd68edf66f4bb9e72d2aad73e41ae36751d0e` |
| Hemi engine supplied | `/Users/dbur/dev/risc0` | `https://github.com/hemilabs/risc0.git` | release-3.0 | `6b673a0c26c0c195c1e4c9e59408de25fc434492` |
| Upstream reference, READ ONLY | `/Users/dbur/dev/risc0-parent` | `https://github.com/risc0/risc0.git` | main | `164c64bb3a844d393bb7addc5781c705c647f2d5` |

Miner Cargo.toml and Cargo.lock resolve Hemi to
`f8dcbdf8124a3f1528146bb01d539c55545cbb3d`, **not the supplied engine HEAD**.
The managed worktree `/Users/dbur/.codex/worktrees/hemi-macos-cpu/risc0`
was created at that exact revision for implementation; both targets now use
local branch `codex/hemi-macos-cpu`. Original
engine and upstream branches remain untouched.

Initial Cargo.lock SHA-256:

* Miner: `3cdf30e0f792fcbf0697ecda9f9b3af2cfbb3c8dba00b0f899ce2e4267b88b05`
* Supplied Hemi: `bfb2dfc5820bf0dab28eff193b1eef3216d7459022df12d1568d6fbab5bd9e62`
* Upstream: `b61698541dbde2c136408b37d97046e40c461625d1a779f711e2e9b13d7cab2d`

## Machine and prerequisites

Runtime `system_profiler SPHardwareDataType SPDisplaysDataType` reports Mac17,6,
Apple M5 Max, 18 CPU cores (6 Super, 12 Performance), 40 GPU cores,
128 GB unified memory, and Metal supported. Serial/UUID identifiers are omitted.
`sw_vers`: macOS 26.4 (25E246); `uname -m`: arm64.
`xcode-select -p`: `/Library/Developer/CommandLineTools`;
`xcrun --show-sdk-version`: 26.4. Clang is present; `xcrun --find metal`
fails with exit 72. Full Xcode is absent from `/Applications`.
Native runtime probe (`scripts/macos/hardware.m`) confirms unified memory,
Apple families 1–10, Mac2, Metal3 and Metal4; maximum buffer 86,586,540,032
bytes and recommended working set 115,448,725,504 bytes. This recommendation
is not an allocation entitlement. The sandbox exposes no GPU; native probe
outside the sandbox succeeded. Full result: `target/macos/hardware-native.json`.
`df -h .`: 532 GiB available at audit time (1.8 TiB filesystem).
`sysctl hw.memsize ...` is denied by the execution sandbox; this is not absence
of hardware support.

Rust/cargo/rustup are not installed in PATH or the usual user directories.
Miner pins Rust 1.93.0; the resolved Hemi engine pins 1.97. Project-local
Rust 1.93.0 and 1.97.1 were installed with no shell-profile changes; builds
use 1.93.0. Guest compiler r0.1.88.0 is linked locally as `risc0`.
Docker client 29.9.2, Colima 0.10.3; no Podman. Docker socket needs execution
outside the sandbox. Read-only Docker info succeeds there: Ubuntu 24.04.4 LTS,
Linux aarch64, 4 virtual CPUs, 8,307,093,504 bytes memory. This is **not** the
Mac's total memory. The first image pull failed because that VM disk was full. A separate
6-CPU/32-GiB/80-GiB Colima profile now runs the pinned helper using QEMU
x86_64 emulation. Existing VM remains intact. See SETUP.md and evidence.

## Production path and compatibility

`zkminer-prove-risc0/src/main.rs` is the common CUDA/ROCm worker. Protocol v5
uses length-prefixed bincode, a 256 MiB frame ceiling, request IDs and canonical
`risc0`. No wire changes are planned. The worker handles Hello, Capabilities,
Prove, Execute, Benchmark, Warmup, CalibrateSegmentLimit, Cancel, Shutdown.
Proving blocks its reader; Cancel acknowledges only after proving. Parent
watchdog/process termination is therefore required. The parent process-identity
guard reads `/proc/<pid>/stat` under `cfg(unix)`, which cannot establish owned
process identity on macOS. Host memory, pressure and cgroup observations are
Linux-specific. macOS resource protection must be implemented before admission.

Discovery searches explicit paths, configured directories, `~/.zkminer/provers`,
binary siblings, PATH; CUDA/ROCm/Intel/generic variants. GPU variants expand by
physical device. CPU and Metal must share a single Mac admission slot.

The worker's `run_proof_once` calls `default_prover().prove_with_opts` with
`ProverOpts::groth16()`, verifies against `compute_image_id(elf)`, and returns
journal plus the raw Groth16 seal. SDK default selection can choose Bonsai,
external IPC/subprocess or local proving depending on features/environment.
The baseline harness must directly instantiate LocalProver, disable dev mode,
exclude Bonsai and reject accidental proof-selection environment overrides.
Existing build scripts can emit empty guest stubs via RISC0_SKIP_BUILD; those
are explicitly inadmissible for this baseline.

The native wrapper must not inherit Dockerfile/Windows x86 target flags.
No unrestricted cargo update or dependency-version substitution is authorized.
Local engine selection will be recorded using metadata/tree, including separate
guest workspaces and an unchanged independent verifier.

## Stage matrix at the pinned revision

| Stage | Current implementation | macOS build | Native CPU | Metal | Helpers | Compatibility / required evidence |
|---|---|---|---|---|---|---|
| Guest compilation | risc0-build + RISC-V toolchain | Untested, toolchain absent | Host build | N/A | RISC Zero Rust | Authentic ELF, hash, expected image/journal |
| Execute/witness | LocalProver / ExecutorImpl, RV32IM | Untested | Present in source | Not validated | Native C++ kernels | Real execution/cycles |
| Segment STARK | rv32im CPU HAL | Untested | Present | Selection commented out | Native C++ | Verified composite receipt |
| Keccak | CPU implementation | Untested | Present | Not validated | Native C++ | Hash/precompile workload |
| Recursion/composition | recursion CPU HAL, composite_to_succinct | Untested | Present | Selection commented out | Recursion artifacts | Verified succinct receipt |
| Identity p254 | succinct_to_groth16 → identity_p254 | Untested | Present | Not validated | Recursion artifacts | Correct final wrapping input |
| Groth16 wrap | shrink_wrap → Docker when no CUDA/ROCm | Untested | Not established on ARM | None | `risczero/risc0-groth16-prover:v2025-04-03.1`, x86 | Image digest, artifact hashes, actual complete proof |
| Verification/encoding | receipt.verify + Groth16 seal | Untested | Present | N/A | Unchanged compatible verifier | Positive and tampered claim/output/proof rejection |

`risc0-zkvm/metal` merely enables `prove` at this pin. Retained Metal files do
not establish acceleration. Gate 1 (complete independent Groth16 verification)
precedes broad Metal work. Gate 2 worker integration, Gate 3 hybrid validation,
and network acceptance are all pending. No wallets or network jobs are used.

## Measured stage status after the first CPU milestone

| Stage | macOS result | Evidence / limits |
|---|---|---|
| Guest compilation/packing | Native ARM64 host compiler, real RISC-V ELF | Original fixture sources; pinned v1 compatibility kernel; provenance JSON per guest |
| Execution and segment STARK | Native CPU, verified | Fibonacci and SHA-256-chain; composite receipts retained |
| Recursion/compression | Native CPU, verified | Succinct receipts retained; po2 14 boundary attempt fails on missing lift_13 artifact |
| Identity p254 | Native CPU, completed | Approximately 29–34 seconds in worker logs |
| Groth16 wrapping | Local emulated x86_64 helper, completed | Pinned digest/keys; approximately 120–123 seconds; NOT native ARM64 |
| Verification/raw seal | Native unchanged verifier, passed | Exact Git engine, 256-byte seal; wrong image/journal/seal rejected |
| Metal stages | None executed | Runtime device exists; compiler absent; upstream APIs/circuits differ |

The initial matrix above is the pre-edit audit, not a statement that later
proofs remain untested. BASELINE preserves the initial findings; VALIDATION
and HANDOFF contain current outcomes. No contract/network acceptance is claimed.
