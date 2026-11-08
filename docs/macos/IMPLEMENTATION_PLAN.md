# Native macOS proving implementation plan

Agreed 2026-11-01. The owner subsequently authorized committing completed
steps 1–4 before proceeding with Poseidon2 lift/join recursion Metal. Native
wrapping, resource tuning, workload expansion and the resident RV32IM integration
have since passed their recorded validation. On 2026-11-02 the owner authorized
committing and publishing all completed local work to the personal forks.
Original published engine checkpoint: `cef3559d6805769c5b33fb4040abe548e670e268`.
The subsequent parent refresh and retirement checkpoint `dcbe9f4b9`
passed fresh correctness, CPU differentials, 31 focused checks, both 10M warm
usefulness medians, the 46M stretch and the five-pair whole-stack gate
(3.645× median speedup; 5/5 faster pairs). See [current handoff](HANDOFF.md)
and [paired evidence](evidence/rv32im-five-pair-validation.json). On 2026-11-03
the owner authorized committing and publishing the review follow-up to both
personal forks. The [review publication record](evidence/rv32im-review-publication.json)
binds this miner commit to the unchanged validated engine and binaries.
Historical commit IDs remain in measurement records; see the
[authorship map](evidence/authorship-rewrite.json) and
[publication record](evidence/rv32im-publication.json).

Progress on 2026-11-01: steps 1–4 passed. Step 3 selected 18 Rayon / 18 Go
threads. Step 4 selected native po2 20, a configurable 64-Mi guest-cycle ceiling,
and compatible final padding. Five measured warm complete proofs per 10M fixture
had medians of 483.927 seconds (arithmetic) and 476.853 seconds (hashing), both
within the agreed ten-minute target. Twenty consecutive requests plus helper
cancellation, watchdog, restart and shutdown passed. One 46M arithmetic stretch
verified in 2,139.840 seconds; the hashing stretch was execution sized only.
See [BENCHMARKS.md](BENCHMARKS.md) and its bound evidence. These results were
captured before the checkpoint commits. Step 5 starts from the committed native
CPU baseline; its exact measured worker is archived under
`target/macos/native-wrap/step4-cpu-baseline`.

The Poseidon2 lift/join milestone of step 5 subsequently passed: five warm
CPU/Metal pairs on the fixed 1.5M fixture measured 86.921/77.772 seconds complete
median latency, all five pairs faster. Separate single 10M arithmetic/hash
proofs verified in 418.323/421.236 seconds; the twenty-request lifecycle gate,
primitive/differential/reuse tests and Linux CPU feature checks passed. The
initial Metal memory budget is 20 GiB after a measured 17.3-GiB startup peak,
with final admission refusal/recovery verified on the unchanged worker binary.
See [BENCHMARKS.md](BENCHMARKS.md). The owner authorized committing step 5 before the step-6 assessment. The
engine checkpoint is `0515e0bde`; measurement-time source hashes remain historical
evidence. Identity-p254 Metal remains its own milestone; a full RV32IM port
is the separate investment decision in step 6.

## Acceptance target

Useful local proving means at least 10 million guest cycles in at most 10 minutes,
measured as the median of five complete warm proofs for each fixed arithmetic
and hashing fixture. Include execution, segment proving, recursion, wrapping,
and verification. Record guest cycles and padded total cycles separately, and
freeze the fixture source, program, input, and segment settings before comparing
implementations. Measure cold startup separately.

Every proof must pass the unchanged independent verifier. Require 20 consecutive
supervised requests plus failure, cancellation, parent-death, and restart
coverage before recommending unattended test use. A 46-million-cycle workload
is a stretch test with separate timing and memory results, not a mandatory
10-minute target. These are acceptance criteria, not performance predictions.

## Baseline and compatibility

The existing controlled campaign measured median worker times of 165.582 seconds
on CPU and 165.823 seconds with Metal folds. CPU diagnostic medians were 121.498
seconds for wrapping and 33.826 seconds for identity-p254. Subtracting the wrap
leaves approximately 44 seconds at those settings, before adding a replacement
wrap. Native gnark time was unmeasured at this baseline; subsequent native results
are recorded in [BENCHMARKS.md](BENCHMARKS.md).

Preserve the independently verified CPU path, fold-only Metal path, and archived
evidence. Freeze further fold-only performance work. Instrumentation and source
provenance accompany each implementation step; they are not a separate gate.

Keep Hemi's circuit, security parameters, original proving and verification
keys, public inputs, control roots, and raw seal format unchanged. The resolved
base remains `f8dcbdf8124a3f1528146bb01d539c55545cbb3d`; the current engine branch
was `0d5b41e8e44876c1e8b5a8a671aabc154e33106c` for the recorded measurements.
The steps 1–4 engine checkpoint is `98d940d4b`; committing changed no measured
source content or binary. Preserve the independent verifier
at the original pin. Use explicit local source overrides and isolated build
directories; avoid dependency updates unrelated to the implementation.

## 1 ARM64 wrapper feasibility

Build the pinned `groth16_proof/docker/prover.Dockerfile` for `linux/arm64` in the
existing dedicated VM. Preserve its Circom revision, Go dependency lock, circuit
source, and checksum-pinned original zkey. Run the converter on ARM64: gnark's
`.pk.dmp` is a platform-dependent representation of the existing key, not a new
trusted setup.

Use retained identity-p254 inputs from previously verified arithmetic, hashing,
and multi-segment proofs. Measure witness generation and gnark proving
separately, including key loading where observable; record helper startup and
overall wrap time. Bind outputs to input hashes, image identity, source inputs,
architecture, resources, and unchanged-verifier provenance.

The initial build includes a 2,579,300,897-byte compressed zkey download,
conversion, and witness-generator compilation. Account separately for download,
extraction, intermediate disk use, build memory, and build time. Cache only
verified artifacts. Native wrapping speed is unmeasured; CUDA wrap timings are
not a gnark CPU baseline.

Acceptance: complete rewrapped proofs pass independent verification and wrong
image, modified journal, and corrupt seal checks; isolated wrap timing is saved.
Keep this a feasibility harness. Defer production worker image selection,
extended container lifecycle testing, and five-pair campaigns to the permanent
native implementation.

## 2 Native macOS wrapper

Build the pinned Go prover for `darwin/arm64`. Extract witness generation from
`risc0/groth16/src/prove/fast.rs` into reusable code independent of Intel feature
selection and Docker orchestration. Compare deterministic witnesses with the
established C++ generator before using them for proofs.

The rzup `risc0-groth16` 0.1.0 release is published as target-agnostic. Its archive
is 2,335,797,480 bytes; download and verify it, confirm `stark_verify_graph.bin`,
and record the complete graph SHA-256 rather than relying only on the existing
prefix check. Build and exercise the graph evaluator on macOS ARM64. If graph
compatibility fails, use the pinned C++ witness generator as a separately
validated native fallback rather than assuming the evaluator works.

Integrate an owned native prover child with explicit artifacts, bounded output,
deadlines, cancellation, and cleanup. Preserve the worker IPC format. Include
native helper memory in resource observations and retain conservative existing
protection while integration is underway. Start with serial lifecycle behavior;
key preloading or persistent helpers are later measured optimizations.

Acceptance: complete arithmetic, hashing, and multi-segment proofs verify with
Docker stopped. Missing/corrupt artifacts, helper failure, cancellation during
witness generation and proving, parent death, and restart behave correctly.
Repeated requests have bounded memory use and leave no owned helper behind.

## 3 Tune the native pipeline

Replace the hard-coded six Rayon threads with explicit bounded configuration
shared by the worker and scripts. Sweep Rayon and host `GOMAXPROCS` independently
at 6, 12, and 18 threads, then compare promising combinations. Measure the native
Go process on the host, not only a six-vCPU VM. Record effective settings and
avoid oversubscription if stages later overlap.

Refine admission using native process footprints, system memory-pressure
observations, and a configurable reserve. Distinguish worker, helper, shared GPU,
and unrelated system memory without double counting. Validate the estimator
against cache-heavy and bounded pressure cases instead of substituting an
unvalidated formula. Keep one active proof per Mac.

Acceptance: choose defaults from sustained complete-proof timing, thermal
behavior, and memory use. Demonstrate safe refusal, cancellation, and recovery
without unnecessary rejection of small proofs under ordinary filesystem cache.

## 4 Expand supported workloads

Replace the fixed 4,194,304-cycle ceiling with configurable limits supported by
measurements. Increase total workload before increasing segment size. Cover
small arithmetic, hashing, segment boundaries, tiny final segments, 10-million
guest-cycle workloads, and a selectable 46-million-cycle stretch workload.

The pinned allowed control IDs start at `MIN_LIFT_PO2 = 14`; `lift_13` cannot be
fixed by fetching another artifact. Implement and verify a compatible final
segment padding floor, including cycle accounting and unchanged claims. Reject
unsupported segment settings or workloads before claim where compatibility
cannot be established. The shared executor has no Linux-specific padding fix;
exercise equivalent boundary cases on the existing Linux path as well.

Feed measured fixed wrap cost and workload/segment scaling into deadline
estimation. Tiny-fixture throughput and cost-model examples do not establish
marketplace job distributions or large-job throughput.

Acceptance: the agreed 10-million-cycle target, independent verification, all
boundary cases, 20 consecutive supervised requests, and failure/restart tests.
Report 46-million-cycle timing and resources separately. Network job acceptance
remains a separate explicitly authorized activity.

## 5 Recursion Metal

Use persistent shared Metal buffers with explicit CPU/GPU synchronization and
bounded lifetimes. Adapt current recursion interfaces and runtime compilation.
Implement the missing constraint evaluator against the pinned circuit before
trusting the retained kernels: `eval_check.metal` has an empty `poly_fp` body.
The two retained accumulation bodies match CUDA after include/address-space
normalization; still require differential execution tests.

Deliver Poseidon2 lift/join first. Identity-p254 is a separate milestone requiring
Poseidon254 and exact BN254 arithmetic, or an explicitly disclosed CPU hashing
path. Validate primitives, offsets, empty/boundary sizes, intermediate states,
complete proofs, failures, and buffer reuse.

Acceptance: independent complete-proof verification, lifecycle stability, and
repeatable complete-job improvement against the tuned native CPU baseline.
GPU dispatch counts alone are not a performance acceptance criterion.

## 6 Decide on the full RV32IM Metal port

The authorized resident worker integration now passes its full-proof validation:
28 independently verified proofs, 84 tamper checks, real-witness CPU
differentials, boundaries, explicit CPU selection and twenty-request lifecycle
recovery. Both 10M workloads pass in single observations of 126.680/130.646
seconds; completed-proof guarded group footprint peaked at 16.305 GiB. CPU-only
and resident feature builds each pass their unit tests, and workload limits hold.
The integration is included in this publication checkpoint. See
[RV32IM_METAL_WORKER.md](RV32IM_METAL_WORKER.md).
The next performance gate is a controlled comparison with step 5; do not infer
the proposed whole-job 2× result from these single observations. Witness and
accumulation remain CPU, with no cap/concurrency increase or 46M Metal claim.

The subsequently authorized bounded evaluator prototype now passes through
po2 20 with independent CPU differentials and buffer reuse. The isolated
evaluator takes about 5.85 seconds on Metal versus 19.3–19.5 seconds on CPU,
with a 13.1-GiB peak charged footprint. This supports the next shared-buffer
circuit adapter gate, not full-port or whole-job throughput acceptance. Retain
CPU witness/accumulation and the documented threadgroup/normalization fixes.
See [RV32IM_METAL_PROTOTYPE.md](RV32IM_METAL_PROTOTYPE.md).

Assessment completed after the step-5 checkpoints (miner `4cbfb3e`, engine
`0515e0bde`). The original goal already passes. Two verified 10M diagnostics put
about 51% of segment time in constraints, 31% in Merkle commitments and 11% in
transforms; CPU witness/accumulation together are only 2–3%. Recommendation:
a bounded evaluator/shared-buffer feasibility prototype before a full scalability
investment, with GPU witness work deferred. A proposed 2× complete-throughput
gate would need roughly 2.4× effective acceleration of the combined hot phases;
this is conditional arithmetic, not measured Metal performance or a new agreed
target. See [RV32IM_METAL_ASSESSMENT.md](RV32IM_METAL_ASSESSMENT.md). This
assessment preceded the isolated prototype and subsequent integration above.

Any follow-up port is a separate scalability investment because the agreed
10-minute usefulness target already passes. First test the full-domain evaluator,
then reuse shared buffers for transforms and commitments while retaining CPU
witness generation and accumulation. Commit to a full port only after measured
complete-proof improvement justifies the work. Make no competitive-mining claim
from synthetic workloads.

## Validation and reporting

Parameterize the existing benchmark machinery. Hold fixtures, engine sources,
proof format, and resources fixed for comparisons; counterbalance run order,
separate tuning from comparisons, and retain failures without selective retries.
Record startup, execution/segment, recursion, identity, witness, wrap,
verification, total request latency, and resource observations where valid.

Run relevant non-Mac regression checks for changed feature/build paths and state
which GPU runtime tests are unavailable. Keep current status and next actions in
[HANDOFF.md](HANDOFF.md), measurements in [BENCHMARKS.md](BENCHMARKS.md), and raw
large build/proof artifacts under `target/macos/`. Keep new implementation work
local until explicitly authorized for publication. The owner has authorized
publication of steps 1–6 and the validated resident worker integration to the
personal fork branches; further implementation scope is unchanged.
