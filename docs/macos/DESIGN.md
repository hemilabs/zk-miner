# Native macOS CPU and hybrid proving architecture

The native miner and worker keep backend `risc0`, protocol v5 and the generic
executable basename `zkminer-prove-risc0`. Existing discovery launches one Mac
worker slot and serializes requests; CPU and Metal are not separate devices.
The worker shares the existing protocol implementation and keeps non-Mac paths
behind their original features. Setup and acceptance scripts perform local work
without invoking marketplace commands.

The CPU baseline and standalone hybrid harness have complete independently
verified Groth16 evidence. The native forced-Metal worker has also passed a
bounded lifecycle milestone: three consecutive proofs, controlled wrapping
cancellation/watchdog cleanup, one verified proof after restart, and shutdown.
Its four proofs each recorded 194 Metal completions and passed the unchanged
verifier and negative checks. CPU-build auto fallback, Metal-build forced CPU,
and Metal-build auto selection also passed: seven complete proofs across four
source-bound runs (five Metal, two CPU), with 21 negative-verifier rejections.
Subsequent twenty-request acceptance and a fixed-setting five-pair Fibonacci
CPU/Metal comparison completed. Broader workload/resource characterization and
full production readiness remain open; see BENCHMARKS.md for measured limits.
Exact results and failures belong in [VALIDATION.md](VALIDATION.md) and
[HANDOFF.md](HANDOFF.md).

## Cryptographic and source boundary

The reviewed engine is `0d5b41e8e44876c1e8b5a8a671aabc154e33106c`, descended
from Hemi's pinned `f8dcbdf8124a3f1528146bb01d539c55545cbb3d`. The miner's
Git pin remains unchanged. The adaptation retains the pinned circuit, exact
field arithmetic, security parameters, keys, verifier parameters, public inputs
and raw 256-byte Groth16 seal format. Retained Metal buffer and empty-input
handling fixes are checked against CPU behavior; they do not replace the proof
system. Supplied upstream remains a read-only reference rather than a replacement
for the SDK 3.0.6 engine.

CPU construction uses `LocalProver::new`; explicit hybrid construction uses
`LocalProver::new_metal(name, staging_bytes)`. Worker preflight rejects remote,
dev, skip-build, skip-verification and injection overrides, then selects the
local executor/prover. Acceptance builds disable development proofs. Source
metadata checks the complete local dependency graph and expected feature closure;
a linked Metal framework alone is not proof of GPU execution.

The independent verifier uses the unchanged pinned Git source, no local patches
and no proving features. It accepts complete receipts or reconstructs the
expected claim from raw worker seal/journal, then rejects wrong image, changed
journal and corrupted seal. Exact contract-adapter encoding and deployed-verifier
execution remain unrun; library verification does not establish those results.

Guests are unchanged miner fixtures built in isolated workspaces. The v3
ProgramBinary contains the authentic user ELF plus the pinned V1COMPAT kernel;
a raw user ELF is not accepted as that container. Source, ELF, kernel, packed
program, image and input hashes are retained. Explicit overrides cover crates.io,
Git sources and independent guest workspaces. Root lock changes record dependency
edges using already-resolved packages without changing the engine pin or package
versions. `build-worker.py` validates a temporary local-source lock, records it,
then restores the root Git-source lock. Builds that mutate that lock run serially.

## Selection and interfaces

* `macos` builds the native CPU-capable worker. `macos-metal` is an opt-in worker
  marker with host dependencies; the local build script additionally enables the
  reviewed SDK's `risc0-zkvm/metal-hybrid` feature. Keeping that local-only feature
  out of the marker preserves resolution against the original Git pin.
* CPU and Metal-capable binaries have the same basename under separate
  `target/macos/worker` and `target/macos/worker-metal` directories. Build seals
  bind source inputs, engine revision/diff, fixtures, features, locks and binary.
* `ZKMINER_RISC0_MODE=cpu|metal|auto` is frozen at startup. CPU skips the GPU probe.
  Metal requires a usable device and fails startup otherwise. Auto selects Metal
  after a successful probe or records an explicit CPU fallback reason. Fallback
  occurs only at startup; a later proving failure does not change backend.
* The isolated three-second probe compiles retained kernels, queries actual
  device capabilities and compares real bounded Metal folds with CPU. Positive
  completed GPU work is required. A CPU-only build reports its missing Metal
  feature as the reason for auto fallback.
* `ZKMINER_RISC0_METAL_STAGING_BYTES` defaults to `524288`, range
  `4096..=16777216`. Optional `ZKMINER_RISC0_EVIDENCE_DIR` enables per-request JSON
  sidecars. Mode, fallback reason, stage timings and counters are diagnostics,
  not additions to the positional worker wire format.
* `ZKMINER_RISC0_DOCKER_CONTEXT` names an explicit local Unix-socket context with
  the pinned helper image already present. `ZKMINER_RISC0_WORK_ROOT` names the
  shared local directory. The supervisor creates a unique owned directory and
  helper lease through internal `RISC0_GROTH16_CONTAINER_NAME` and `RISC0_WORK_DIR`.
* Authentic packed guests come from `ZKMINER_RISC0_GUEST_DIR`; absent or stub
  guests fail the build. Prove/Execute allow at most 4M guest cycles, po2 14..18
  (default 18), six Rayon threads and no Mac proof retry ladder.
* The genuine Fibonacci(20) and SHA-256-chain(10) benchmark fixtures use the same
  staged proving and final-verification path as proof requests. Calibration is
  explicitly unsupported. Tiny-fixture results are not comparable GPU rankings.

Warmup returns the completed startup preflight/capability summary; it does not
claim a complete proof. The existing capability response reports the observed
GPU availability and device name. Normal worker stdout remains binary IPC;
structured diagnostics use stderr or sidecars. Only the isolated internal probe
uses captured JSON stdout. The dispatcher's legacy `[cpu]` label can describe an
unindexed generic slot; the capability response and per-request
`requested_mode`/`observed_stages` evidence identify actual acceleration.

## Stage boundary, ownership and timing

Only segment Poseidon2 Merkle pair folding runs on Metal. Witness generation,
NTTs, constraints, leaf hashing, FRI arithmetic, other segment operations,
recursion and identity retain their pinned CPU implementations. Final Groth16
wrapping uses the pinned local Linux/amd64 helper under QEMU emulation. This is
not a fully native final-wrapping pipeline.

CPU buffers own the proving state. Each fold chunk copies required digests into
bounded shared Metal staging, dispatches the retained exact-arithmetic kernel,
waits for `Completed`, and copies results back into the CPU buffer consumed by
the proof. Staging owners and autoreleased command resources are released before
the next chunk. Fixed constants and driver overhead are outside the staging cap.
No selected fold silently falls back to CPU. Each completed proof segment must
report positive GPU commands, fold calls and output digests, consistent input
counts and staging within the configured cap.

The worker verifies composite, succinct and final Groth16 receipts. Sidecars
preserve proof phases and actual per-segment evidence even if a later stage
fails. Current timings combine execution with segment proving and combine final
identity transformation with wrapping; recursion and final verification have
separate measurements. `total_ms` covers the request body, excluding startup and
IPC overhead. These boundaries are disclosed rather than presented as finer
measurements than the instrumentation supports.

## Resource and lifecycle policy

The dedicated Colima VM uses 6 CPUs, 32 GiB RAM and 80 GiB disk. Rosetta is not
installed, so the x86 helper uses QEMU binfmt. Image and proving artifacts are
pinned. Helpers have `--pull never --network none --memory 24g --cpus 6` and an
internal 1800-second timeout. Sequential requests reuse the worker lease; each
helper is `--rm`. The supervisor removes only its exact helper on
shutdown/timeout/drop, and a worker parent-watch thread cleans that lease if the
parent dies. If both processes are killed or Docker is unreachable, the helper's
internal deadline is the remaining bound; daemon-failure recovery is untested.

macOS process identity uses proc_pidinfo start time, parent PID and group-leader
identity; missing identity fails closed. Workers own process groups. Native
proc_listpids enumerates surviving members, excluding zombies, while an unreaped
leader pins identity. Process-group tests use real children. Existing Linux
proc/cgroup paths are preserved; unavailable non-Mac runtime tests remain unrun.

Host capacity comes from hw.memsize. Admission estimates available memory as
`(free_pages + min(file_backed_pages, inactive_pages)/2) * page_size`, then
reserves 16 GiB. This is not Darwin's guarantee of allocatable memory or a
memory-pressure metric. Anonymous/compressed pages receive no separate credit,
and overlapping cache counters are not added. A one-second watchdog requires
worker RSS <=32 GiB and the available estimate >=8 GiB; failed observations
terminate only the identity-checked owned group. Sampling is not a kernel limit.
The helper cap is inside the 32 GiB VM, whose host footprint already reduces
host availability. CPU and GPU never receive independent 128 GiB allowances.

Metal maximum-buffer size is a device limit; recommended working-set size is a
performance recommendation, not an allocation entitlement. The small configurable
staging cap operates within the existing host admission policy. Native cgroup-like
anonymous/high-water observations remain unavailable, so the scheduler can
conservatively recycle a warm worker. Sampled native RSS excludes helper/VM
memory; logical staging peaks exclude driver allocations. These figures must not
be added together or treated as proof of leak-free repeated operation.

Synchronous proving cannot consume IPC Cancel mid-proof. The parent watchdog
terminates the owned group, removes its helper, releases the slot and permits
restart. The source-bound acceptance suite requires observed wrapping
cancellation/timeout cases and a complete independently verified proof after
restart. Existing framing and version checks handle malformed/oversized requests.
Native forced-Metal run `f8ff5abb2cef4a19bb02e24fbcb318d0` passed those bounded
proof/lifecycle requirements. Its per-process RSS high-water mark over the whole
attempt was 2,013,675,520 bytes, excluding the helper VM; this does not establish
a per-proof allocation trend. The current-revision CPU/auto matrix also passed:
a CPU-only build's auto mode recorded its missing-feature fallback, forced CPU
in a Metal-capable build performed no GPU proof work, and auto selected the
validated fold stage when available. The three additional requests each produced
a complete independently verified Groth16 proof.

Additional native acceptance now covers SHA-256-chain(10) after controlled
admission refusal/recovery, five-segment proving at requested po2 16, and a
complete Fibonacci proof at the minimum 4 KiB Metal staging budget. Those three
proofs passed unchanged verification and negative checks with 593, 1,269 and
16,680 GPU completions respectively. The admission case held 107 GiB of logical
reservations using small bookkeeping handles, received a typed pre-dispatch
refusal, released the ledger to zero and verified a proof after worker recycle.
It did not allocate that physical memory or exercise the resident-limit kill.

The twenty-request run `28bdd9ca009a4f6eacda4e11df402aed` passed twenty
consecutive independently verified WorkerPool requests with zero failed
requests and 60 negative-verifier rejections. Normal memory-driven recycling
used sixteen worker PIDs, with a longest same-PID success streak of two. This
covers the accepted-request/recovery path under the production policy, not twenty
requests in one process or leak-free long-lived retention. With the three added
workload/resource runs, this continuation produced 23 complete proofs, 69
negative checks, and eight executed tests with none ignored.
Per-request RSS baseline, periodic peak and post-verification idle observations
preserve PID/start identity and exclude helper/VM and unmeasured driver memory.
The production engine, workers, CPU binary and pin were unchanged for this
coverage; changes were confined to acceptance tooling and documentation.

## Known envelope and remaining gates

The pinned recursion archive lacks `lift_rv32im_v2_13.zkr`; a tiny final segment
can fail after valid segment proving. A po2-14 boundary run exposed this; the
supported five-segment fixture was verified at po2 16. No key/artifact regeneration
or upstream parameter substitution is permitted. This does not establish support
for arbitrary marketplace jobs. Keccak and other precompile coverage are not
established by SHA-256-chain tests.

Standalone complete hybrid proofs and retained primitive/bridge differential
results are recorded separately from native-worker acceptance. The runtime
Metal compiler works without manual installation; offline `xcrun metal` and full
Xcode remain absent. Any future privileged provisioning requires approval.

The twenty-request operational repeat target is met under normal recycling.
The fixed-setting Fibonacci comparison completed with two warmups and five
measured complete runs per mode: 12 accepted Groth16 proofs and 36 tamper
rejections, with no observed Metal speedup. Startup timing is separate; each
trial uses a fresh worker, not a cold OS boot or a persistent warm process.
Larger-workload comparisons and further resource characterization remain open;
long-lived single-process retention remains unvalidated. SHA, five-segment,
logical-admission and minimum-staging coverage now has real native proofs.
Broader precompile coverage, physical host-pressure/resident-limit failure,
GPU-fault/driver-allocation observations, exact contract-adapter validation and
non-Mac runtime coverage remain separate work.
No speedup, unattended stability or profitability is claimed. Network acceptance
is unrun and unauthorized.
