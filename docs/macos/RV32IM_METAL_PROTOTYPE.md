# RV32IM Metal evaluator feasibility — 2026-11-02

This records the isolated feasibility checkpoint. The subsequent
[resident worker integration](RV32IM_METAL_WORKER.md) now passes complete-proof
validation; that subsequent engine implementation is separate from these prototype
measurements and frozen inputs.

The bounded evaluator gate passes on this Apple M5 Max. The isolated Metal
evaluator compiles, matches the pinned CPU oracle through po2 20, and stays
inside the existing 32-GiB physical-footprint guard. The next gate at this
checkpoint was a shared-buffer circuit adapter with CPU witness/accumulation,
followed by complete-proof verification; see the subsequent worker report for
that result. This is not acceptance of a full port or a whole-job speedup.

At measurement time, prototype and assessment changes were uncommitted, engine
`0515e0bde` was clean and miner HEAD was `4cbfb3e`. The author-only rewrite and
subsequent publication are recorded in the [commit map](evidence/authorship-rewrite.json)
and [worker report](RV32IM_METAL_WORKER.md). The measured step-5 worker binary is
`d157305ba0e0830671c6b8f6238dc68e59ae8a68dc3454865c2084c21bc347b9`.

## What was implemented

The independent workspace in `tools/macos-rv32im-metal` uses the committed
shared-buffer Metal HAL and the existing RV32IM CPU FFI. It does not enter the
worker's proof path. No verifier, control IDs, proof format or engine source
changed.

The generator reads all four pinned CUDA evaluator chunks, supplies Metal
address spaces and explicit mixing-power arguments, and preserves the twenty
generated function boundaries. It checks all twenty functions plus `poly_fp`
against the generated CPU bodies after narrowly defined normalization of names,
declarations, constructor spelling and commutative field products. A mismatch
stops generation. All 458 mixing exponents come from the pinned circuit info;
the sequence is not replaced with consecutive powers.

Local field compatibility operators supply mixed Fp/FpExt addition and
subtraction missing from the retained Metal headers. The GPU uses a four-entry
normalization table: for `N = 2^po2` and a domain root `rou` of order `4N`,
`((3 * rou^cycle)^N - 1)^-1` depends only on `cycle mod 4`. The table is checked
with independent modular-u64 arithmetic. The CPU oracle still computes the
original per-cycle exponentiation for every point.

## Measured result

The final candidate passed seven cases at po2 4, 8, 14, 18 and 20. Each case
compares every output, resets the output through its mapped CPU view, repeats
the GPU dispatch on the same buffers, and compares again. Inputs, offsets and
sentinels are checked. There were fourteen successful commands and 76,030,976
field-element comparisons including reuse. Two different datasets exercise
the complete po2-20 domain of 4,194,304 points / 16,777,216 output elements.

| Full-domain dataset | GPU first dispatch | GPU reused buffers | CPU oracle | Lifetime peak charged footprint |
|---|---:|---:|---:|---:|
| Seed 19 | 5.847 s | 5.853 s | 19.258 s | 13.070 GiB |
| Seed 23 | 5.845 s | 5.848 s | 19.469 s | 13.070 GiB |

This is approximately 3.3× isolated evaluator acceleration. The inputs are
synthetic field matrices, not valid guest witnesses. CPU evaluation uses eighteen
threads; GPU groups contain thirty-two threads. These are two observations with
fixed execution order, not a controlled warm-median proof comparison. GPU timing
includes command submission and completion; library/pipeline compilation,
allocation, input initialization, hashing and result comparison are outside
that dispatch timing. The full diagnostic case took about 49 seconds.

The final shader's first observed library compilation took 9.790 seconds and
pipeline creation 40.159 seconds. Subsequent processes benefited from the driver
cache (roughly 0.006–0.009 and 0.003–0.004 seconds respectively). The cold
observation used the identical final shader with an earlier harness binary;
it is not a repeated cold-build benchmark. Keep startup cost visible in future
whole-proof comparisons.

Physical footprint comes from `proc_pid_rusage`, including the kernel-reported
lifetime peak. The harness guards current footprint at 32 GiB, estimates at
least 8 GiB available host memory, accepts only normal/warning pressure and
requires a 16-GiB prototype budget plus a 16-GiB host reserve for admission.
Sampling is every 500 ms, not a kernel-enforced hard cap. Compiler services are
outside the harness process; host availability is still watched. This isolated
peak does not establish the peak of resident commitments, trace and recursion
in an integrated worker.

## Failures retained and corrections

Seventeen attempts are recorded, including five earlier failures. None was
retried as an unchanged passing acceptance sample:

- Missing mixed-field operators initially prevented shader compilation; the
  local compatibility header supplies the same field promotions as CUDA.
- The HAL's default 1,024-thread group failed. A diagnostic dispatcher confirmed
  Metal error 8, `Insufficient Memory`. The prototype retains thirty-two threads
  and records command completion/errors directly. Do not select the pipeline's
  reported maximum automatically for this evaluator.
- The original post-polynomial per-cycle normalization produced mismatches at
  256 po2-14 cycles, despite passing smaller domains. A second diagnostic
  recorded differing cycle positions and base-field-only error ratios repeating
  every four cycles. The equivalent table wrapper passed the final tests.
  The compiler/driver mechanism remains unconfirmed; these results do not
  establish a general Metal power-function defect. Retain the failing data and
  do not reuse that wrapper without a separate fix and full-domain validation.

The evaluator's private/spill backing remains significant: even a tiny dispatch
charged about 8 GiB. This and the threadgroup failure are port constraints,
not resolved by the small declared CUDA scratch-array size. The measurements
support this bounded configuration, not a threadgroup or concurrency sweep.

## Next implementation gate

1. Add an explicit opt-in RV32IM Metal circuit adapter using the current shared
   buffers, evaluator and resident transforms/commitments. Keep CPU witness and
   accumulation, including `pre_data` aliasing. Reuse or sequence HAL ownership
   with recursion on the same thread; retain cap 20 and one in-flight segment.
2. Verify intermediate buffers and complete tiny-tail/boundary/arithmetic/hash
   proofs under the unchanged independent verifier with tamper checks. Measure
   actual integrated phase peaks and retain current watchdog/reserve protection.
3. Establish five warm samples against the committed step-5 worker and test
   cancellation/restart and twenty-request stability. The proposed 2× whole-job
   scalability gate remains unmeasured. The original 10M/ten-minute requirement
   already passes; do not convert isolated evaluator ratios into a job forecast.

## Evidence and reproduction

[Collected evidence](evidence/rv32im-evaluator-prototype.json) binds the final
binary, source inputs, generated shader, CPU/CUDA comparison hashes, every run
and all failures. Raw logs, manifests and results are under
`target/macos/rv32im-metal/runs`. The frozen final candidate is under
`target/macos/rv32im-metal/archive/candidate`.

From the miner root, load `scripts/macos/env.sh`, then run:

```sh
python3 scripts/macos/test-rv32im-evaluator.py --engine ENGINE --case 4 --seed 11 --build
python3 scripts/macos/test-rv32im-evaluator.py --engine ENGINE --case 8 --seed 13
python3 scripts/macos/test-rv32im-evaluator.py --engine ENGINE --case 14 --seed 17
python3 scripts/macos/test-rv32im-evaluator.py --engine ENGINE --case 18 --seed 7
python3 scripts/macos/test-rv32im-evaluator.py --engine ENGINE --case 20 --seed 19
python3 scripts/macos/test-rv32im-evaluator.py --engine ENGINE --case 20 --seed 23
python3 scripts/macos/test-rv32im-evaluator.py --engine ENGINE --case 4 --seed 29
python3 scripts/macos/collect-rv32im-evaluator.py ENGINE
```

The collector requires po2 4 and 8 controls as well as 14, 18 and two distinct
po2-20 datasets. All commands run offline against the clean reviewed engine;
the runner checks source/binary seals and preserves each failure. The harness
has a ten-minute default deadline, with cleanup restricted to its owned process
group. It produces no proof and submits no job.
