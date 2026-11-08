# RV32IM Metal assessment — step 6

Assessed against the committed step-5 engine `0515e0bde` and miner `4cbfb3e`.
This records the assessment before implementation began. The subsequently
authorized [bounded evaluator prototype](RV32IM_METAL_PROTOTYPE.md) now passes
its feasibility gate, and the subsequent [resident worker integration](RV32IM_METAL_WORKER.md)
passes complete-proof validation. These records were captured before their
publication checkpoint. Current commit and publication status is recorded in
the [worker report](RV32IM_METAL_WORKER.md); historical source IDs are preserved
and mapped in the [authorship record](evidence/authorship-rewrite.json).

## Decision

The agreed usefulness goal is already met: step 4 established five-sample warm
10M-cycle complete medians below ten minutes for both fixtures. A full RV32IM
port is therefore a separate scalability investment, not required completion
work for that goal.

There is a credible performance opportunity, but the evidence supports a
bounded feasibility prototype before committing to a full port. Target
constraint evaluation, Merkle commitments and polynomial transforms. Keep CPU
witness generation and accumulation initially. Their combined share is only
2.1–2.6% of segment time on these fixtures, so porting the generated witness
machinery first offers little measured benefit.

The first feasibility gate should establish whether the RV32IM constraint
evaluator compiles, fits and runs efficiently on Metal at the existing po2-20
cap. Generic transforms and hashing already have a verified Metal foundation;
the much larger evaluator is the principal new technical uncertainty. No
measured Metal speedup for RV32IM was available at this assessment checkpoint.

## Measured basis

The latest nonverbose step-5 observations remain the latency reference:

| Fixed 10M fixture | Complete latency | Execution + segment proving | Share |
|---|---:|---:|---:|
| Arithmetic | 418.323 s | 381.356 s | 91.16% |
| Hashing | 421.236 s | 384.603 s | 91.30% |

Each is one first-process observation, not a new warm median. They show that
segment work dominates after Poseidon2 recursion acceleration. The measured
non-segment remainder is 36.6–37.0 seconds. It is an optimistic lower bound if
the *entire combined execution/segment stage* vanished, not an achievable port
floor: execution and other CPU work remain, and a changed implementation can
change other costs.

Two additional complete diagnostic proofs used the exact same worker binary
with the existing `RISC0_VERBOSE=1` timers. Arithmetic took 416.158 seconds and
hashing 425.240 seconds, including independent verification. Both passed the
unchanged verifier and all three tamper checks. Rebuilding/resealing after the
checkpoint preserved the worker byte for byte:

`d157305ba0e0830671c6b8f6238dc68e59ae8a68dc3454865c2084c21bc347b9`.

The diagnostics are for attribution, not a speedup comparison. They use one
proof per fixture, have logging overhead, and round internal timers to 0.1 ms.
Only messages before recursion starts enter the following segment breakdown;
nested timers are not summed twice. CPU `eval_check_launch` is synchronous and
measures constraint computation, despite its launch-oriented label.

| Exclusive segment work | Arithmetic seconds / share | Hashing seconds / share |
|---|---:|---:|
| Constraint evaluation | 195.627 / 51.51% | 199.306 / 51.41% |
| Merkle commitments | 118.232 / 31.13% | 119.277 / 30.77% |
| Polynomial transforms | 40.846 / 10.75% | 41.383 / 10.68% |
| Witness generation | 1.494 / 0.39% | 3.339 / 0.86% |
| Accumulation | 6.351 / 1.67% | 6.826 / 1.76% |
| Remaining segment protocol | 17.268 / 4.55% | 17.514 / 4.52% |
| Summed segment prover | 379.819 | 387.644 |

The combined stage also includes execution/preflight/caller work. Its residual
after the segment timers is recorded separately; it is not an independent
measurement of every preflight task, which can overlap proving.

Merkle timers combine allocation, leaf hashing and tree folding. The present
logs do not time those pieces separately. Large input widths (211 DATA and
103 ACCUM columns) make leaf hashing a sensible prototype priority, but that
is an inference, not a measured leaf/fold split. Preserve the old fold-only
results; do not restart tuning of their bounded staging path as the main port.

## What the opportunity can support

For the diagnostic arithmetic observation, accelerating only transforms and
Merkle work has an ideal complete-job ceiling of 1.62×. Constraint evaluation
alone has an ideal ceiling of 1.89×. Witness plus accumulation alone has an
ideal ceiling of 1.02×. Hashing gives similar ceilings (1.61×, 1.88×, 1.02×).
These are zero-cost limits for the selected work, not expected GPU performance.

Constraint evaluation plus transforms/Merkle accounts for 354.706 arithmetic
seconds and 359.966 hashing seconds. Amdahl scenarios for that combined set,
with all other costs held constant, are:

| Hypothetical effective speedup of the combined hot phases | Arithmetic complete time | Hashing complete time |
|---|---:|---:|
| 2× | 238.805 s | 245.257 s |
| 3× | 179.688 s | 185.263 s |
| 5× | 132.394 s | 137.267 s |

No row is a measured or predicted Metal result. A new objective of doubling
complete throughput would require about 2.42–2.44× effective speedup across
those combined phases under this model. Individual kernels need not improve
by the same factor; added overhead and changed memory behavior still need
whole-proof measurement. A 2× objective is a proposed scalability gate, not a
replacement for the owner's original ten-minute requirement.

The 46M CPU stretch remains one 35.7-minute result. It has not been rerun with
recursion Metal or RV32IM Metal. No 46M GPU timing or ten-minute promise follows
from these diagnostics, and ten minutes for 46M was never an acceptance gate.

## Port scope and risks

| Area | Current state | Assessment |
|---|---|---|
| Shared buffers, completion and ownership | Step-5 Metal HAL and autorelease scopes verified | Reuse; keep one in-flight segment and preserve early witness release. |
| NTT, bit reversal, row hashing, folding, FRI primitives | Existing Metal HAL, primitive tests and complete recursion proofs | Reuse, then validate at RV32IM widths/domain sizes. Existing recursion timing is not an RV32IM speed estimate. |
| RV32IM circuit adapter | CPU/CUDA/HIP/Intel adapters; zero RV32IM Metal kernel files | New adapter and explicit local feature chain required. |
| Constraint evaluator | Four generated CUDA chunks, 20 functions, 26,686 lines | New MSL generation/address-space adaptation and differential tests required. It is not the flat recursion polynomial transplant. |
| Witness/accumulation | CPU FFI over shaped buffers; Rust preprocessing/scatter | First reuse CPU routines on shared buffers, including the CPU `pre_data` alias. |
| Fully GPU witness execution | Generated CUDA `steps.cu` alone is 62,013 lines | Defer until broader workloads show a worthwhile remaining cost. |
| Identity-p254 / Groth16 | Native CPU path | Preserve; Poseidon254 Metal remains a separate milestone. |

The CUDA polynomial declares 1,007 `Fp` and 144 `FpExt` scratch entries,
6,332 bytes per invocation before other state. The CUDA source explicitly
configures cache preference for spills. Declared arrays are not a measurement
of Metal registers, occupancy, spill backing or peak memory. Metal compilation,
inlining and scratch behavior at the full domain are go/no-go questions, not
details to postpone until a full witness port is finished.

At po2 20 the domain is 4,194,304 points. The source has 211 DATA, 103 ACCUM and
one CODE column. The largest evaluated DATA buffer is **3.297 GiB**. Retaining
the three committed groups' coefficients, evaluated matrices and tree nodes
accounts for **6.902 GiB** by itself. This excludes the check group, raw witness,
trace, transform/private scratch, driver allocations, native helper and retained
allocator memory. It is an allocation lower bound, not a peak forecast.

The observed Apple M5 Max reports unified memory and an 80.64-GiB single-buffer
limit, so that one allocation fits the reported device limit. This does not
establish that the complete port fits the existing 32-GiB owned-group watchdog.
Do not add estimated GPU bytes to the old process peak: shared pages and
allocation lifetimes make that sum unreliable. Measure the owned physical
footprint at each phase, with existing reserve/pressure protection intact.

Also preserve Metal thread affinity and its global serialization lock. Share
or explicitly sequence HAL/queue ownership between segment and recursion
provers; do not introduce cached HALs on different threads that wait on one
another. Do not raise the segment cap or pipeline multiple segments to claim
an initial port speedup.

## Bounded follow-up plan

1. De-risk the evaluator first: generate from the pinned current circuit,
   preserve 458 mixing powers and exact tap ordering, compare every result
   against CPU at small domains and then the full po2-20 domain. Measure compile
   time, latency and physical footprint; collect compiler/counter data where
   available. Stop a failing owned process rather than relaxing memory guards.
2. Integrate the existing Metal HAL for resident transforms and commitments,
   with CPU witness/accumulation over shared buffers. Preserve the existing
   buffer release order and begin with synchronous completion. Avoid hardening
   a temporary CPU/GPU staging design that will then be discarded.
3. Validate intermediate buffers, offsets, empty/edge shapes and reuse, followed
   by complete arithmetic/hash/tiny-tail/boundary proofs under the unchanged
   verifier. Require cancellation, watchdog, restart and twenty-request stability.
4. Establish a fresh five-sample warm baseline on committed step 5, then compare
   the candidate with identical programs, inputs, cap 20, 18/18 threads and proof
   format. Counterbalance order and retain all trials. If a new 2× throughput
   objective is chosen, require it in complete latency, not kernel timings.
5. Only after those gates consider a full witness/accumulation port or a larger
   segment cap. Reprofile BigInt/ECDSA/memory-heavy guests before generalizing
   these arithmetic/hash results. Make no marketplace competitiveness claim.

## Evidence and reproduction

[Assessment JSON](evidence/rv32im-metal-assessment.json) binds source hashes,
device capability output, checkpoint continuity, raw proof artifacts, parsed
timers and scenario arithmetic. [Exclusive profile CSV](evidence/rv32im-metal-profile.csv)
contains the six non-overlapping categories per fixture. The latest latency
reference remains [step-5 evidence](evidence/recursion-metal-validation.json).

The diagnostic driver is `scripts/macos/profile-rv32im.py`; it enables existing
timers without changing engine implementation. Raw profiles are under
`target/macos/step6-assessment/profile-runs/b2112a5f7787478598e5c894a16f0e91`.
The before/after checkpoint manifests in `target/macos/step6-assessment` show
that committing/resealing preserved compiled inputs and the exact worker binary.

After loading `scripts/macos/env.sh` and the project-local `PROTOC`, reproduce
the diagnostic pair with `python3 scripts/macos/profile-rv32im.py --engine ENGINE`.
Collect using `python3 scripts/macos/assess-rv32im-metal.py --engine ENGINE
--profiles PROFILE_DIR --device DEVICE_JSON`. The device JSON comes from the
sealed worker's `--macos-recursion-probe` command. Source, binary, input and
verifier checks must pass before interpreting results.
