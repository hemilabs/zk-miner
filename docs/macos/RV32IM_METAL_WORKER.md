# Resident RV32IM Metal worker — integration and validation


## Post-publication review follow-up

The original `cef3559d6` campaign is preserved in its own section below. The subsequent
`c6b67b15e` parent merge passed an additional eight proofs, 24 negative checks
and 29 unit/differential tests; see [refresh evidence](evidence/engine-refresh-validation.json).
The retirement checkpoint `dcbe9f4b9` has now passed fresh smoke,
full-domain real-witness CPU differential, 10M hashing and a 46M stretch:
four proofs plus twelve negative checks, with 31 focused tests passing.
See [current-tip validation](evidence/rv32im-current-tip-validation.json).

The stretch proved 46,003,116 guest cycles in 46 segments in **484.740 seconds**,
including independent verification, with a **15.401 GiB** guarded group peak.
Pressure remained normal and the default 16 GiB reserve was used. This is one
complete observation and meets the proposed 600-second stretch target.

Two additional verified diagnostic 10M proofs establish the current Metal split:

| Segment phase | Arithmetic | Hashing |
|---|---:|---:|
| Constraints | 63.70% | 62.01% |
| Polynomial transforms | 20.11% | 19.54% |
| Merkle commitments | 4.28% | 4.16% |
| CPU witness generation | 1.98% | 4.01% |
| CPU accumulation | 7.27% | 7.64% |
| Other segment protocol | 2.66% | 2.64% |

Segment prover totals were 88.658/91.054 seconds of 127.653/128.682 seconds
complete time. These are synchronous phase wall times, not GPU occupancy or
hardware-cycle counters. The historical CPU 51/31/11 split is superseded for
this backend. Constraints remain the first optimization candidate; no evaluator
occupancy or kernel changes were made. See [Metal profile evidence](evidence/rv32im-metal-current-profile.json).

Five warm 10M hashing samples passed, with complete times of 124.663, 122.647,
120.800, 120.176 and 120.173 seconds: **120.800 seconds median**, below the
600-second usefulness bar. The excluded warm-up verified in 130.704 seconds.
See [warm hashing evidence](evidence/rv32im-warm-hash-validation.json).

The formal five-pair gate passed: complete medians of **427.192 seconds
step-5 baseline / 117.192 seconds resident Metal**, **3.645×** speedup,
with 5/5 faster pairs. One warm-up per mode was excluded; all twelve proofs
and 36 negative checks passed on unchanged worker identities. Fresh-campaign
admission waits were zero. The arithmetic median and the hashing median above
both meet the 600-second usefulness target. This compares the entire refreshed
stack, including parent changes; it does not isolate Metal-only gains. See
[paired evidence](evidence/rv32im-five-pair-validation.json) and
[proof CSV](evidence/rv32im-five-pair-proofs.csv).

Current-tip validation totals 22 proofs and 66 negative checks, plus the
31 focused checks. Earlier admission refusals and the interrupted partial run
remain recorded separately in [HANDOFF.md](HANDOFF.md). The largest review
worker/helper peak, including warmed proofs, is **19.783 GiB**; see the
[machine floor](SETUP.md). The clean engine checkpoint is `dcbe9f4b9`.
The owner authorized publication to both personal forks on 2026-11-03; the
[review publication record](evidence/rv32im-review-publication.json) binds this
miner commit to the validated engine, runtime files and existing proof results.

## Original resident-port checkpoint (`cef3559d6`)

The opt-in worker now uses shared Metal buffers for RV32IM transforms,
commitments and constraint evaluation. Poseidon2 lift/join remains Metal;
CPU witness generation, accumulation, scatter, prefix products, zeroization,
identity-p254 and the native Groth16 helper remain in place. Default segment
selection is CPU. This report accompanies the miner publication checkpoint;
the engine implementation is committed at
[`cef3559d6`](https://github.com/dimitryB/risc0/commit/cef3559d6805769c5b33fb4040abe548e670e268).

The final candidate has passed independently verified 10M-cycle arithmetic and
hashing jobs in **126.680 seconds** and **130.646 seconds**, respectively.
These are individual complete-request observations, including the external
verifier, rather than controlled warm medians or a measured speedup ratio.
Both meet the agreed 10M/ten-minute usefulness target. The 46M stretch was not
rerun, and these fixtures establish no marketplace competitiveness result.

The final campaign passed **28 complete proofs and 84 negative verifier checks**:
27 proofs used resident RV32IM Metal and one exercised explicit CPU selection.
Three proofs also compared every constraint output with the CPU oracle on
valid witnesses. Twenty consecutive tiny requests completed on one worker,
followed by successful cancellation, watchdog, recovery-proof and shutdown checks.
Initial and final idle footprints were 3.873 and 3.860 GiB; their observed range
was 3.859–3.948 GiB. The maximum guarded worker/helper footprint across completed
proofs was **16.305 GiB**. This validation was on the Apple M5 Max; it is not a
memory guarantee for other Macs or guest workloads.

## Implementation

The worker feature is `macos-rv32im-metal`. Build tooling explicitly selects
the local engine's `metal-rv32im`, `metal-recursion` and native Groth16 feature
chain; the unchanged Git pin remains resolvable by existing builds. The engine
rejects mixing resident Metal with CUDA, ROCm, Intel or the legacy fold-only
segment backend, and rejects the feature outside Apple Silicon macOS.

Runtime selection is explicit through `RISC0_SEGMENT_HAL=metal`. CPU is the
default, and invalid or unsupported values fail. Current tooling retires the
legacy fold-only backend, so `ZKMINER_RISC0_MODE` is no longer needed. Use
`RISC0_RECURSION_HAL=metal` and `ZKMINER_RISC0_WRAP=native` with resident Metal.
The old `metal` mode, build and probe fail with migration guidance. The acceptance runner supplies these settings and the supervisor's
native-helper lease. Select `--segment-hal cpu` on the same worker for a CPU
segment control.

CPU witness/accumulation routines operate directly on mapped raw pointers.
They retain the CPU `pre_data` alias and checked shapes. Writable FFI buffers
are not wrapped in shared Rust slices. Every Metal dispatch completes before
CPU access, input release or the next segment. Segment and recursion HALs are
sequenced on the same proving thread, preserving the global reentrant Metal
lock; CPU-only background preparation does not initialize a Metal HAL.

The engine's bundled build-time generator checks all twenty evaluator functions
and `poly_fp` against the CPU-generated bodies after the reviewed mechanical
normalization, then embeds the current shader. All 458 mixing exponents come
from the circuit source. The shader is byte-identical to the independently
validated prototype:

`4de746306b22bd756e919f2d27d28848e28ed7e4fabcb6e6c526537bac01708b`.

The evaluator retains thirty-two-thread groups and the equivalent four-entry
normalization table. The earlier 1,024-thread out-of-memory failure and
divergent-normalization mismatches remain recorded in the
[prototype evidence](RV32IM_METAL_PROTOTYPE.md). Their constraints are not
relaxed by integration.

Per-request evidence records completed GPU dispatches, one constraint check
and CPU witness/accumulation call per segment, evaluation points, both shader
hashes and the selected CPU stages. CPU selection requires zero RV32IM Metal
checks/dispatches. An optional diagnostic compares every Metal constraint
output with the CPU oracle on the same valid witness, including the original
per-cycle normalization; it neither copies the full trace nor creates a second
HAL. The normal timing observations disable that diagnostic.

## Validation scope

The final worker binary is
`318676ce86d7f96f6dbff1ca111016e62d95095ffc65cb2a2ab7923b76635f04`.
The independent verifier remains byte-identical to the original pinned verifier:
`2bcdcb7f50e2303545898962d23bdc6cba9512038383a93c975f95b89cf8225c`.
Its dependency metadata contains no proving backend or local engine overrides.
Control IDs, verifier parameters, proof format and setup artifacts are unchanged.
After the campaign, the engine workspace lock gained the new optional `metal`
dependency edge. Both feature variants were rebuilt and resealed: binaries,
root-worker metadata/local locks and code diffs were byte-identical. No package
versions changed. `target/macos/rv32im-worker/lock-continuity.json` preserves
the before/after manifests and exact lock-only transition; the proof counts
remain bound to the same tested executable.

| Case | Verified behavior |
|---|---|
| Initial smoke | Complete Groth16 proof and real-witness CPU differential. |
| Tiny tail, cap 14 | Five minimum-size segments verify under the pinned control root, with CPU differentials. |
| Full domain, cap 20 | Two-segment arithmetic proof; every valid-witness constraint output matches CPU, including a full po2-20 segment. |
| Segment boundary, cap 16 | Five-segment proof with padded final segments. |
| CPU segment control | Complete proof with no RV32IM Metal work; recursion remains Metal. |
| Arithmetic 10M | 10,003,116 guest cycles / ten segments; complete verification in 126.680 seconds. |
| Hashing 10M | 10,003,440 guest cycles / ten segments; complete verification in 130.646 seconds. |
| Twenty-request lifecycle | Twenty unique requests on one worker, cancellation of an observed running helper, worker watchdog, independently verified recovery proof and clean shutdown. |

Every completed proof is checked by the original external verifier, with wrong
image, modified journal and corrupt seal rejection. Guest outputs are calculated
independently. Five selected-worker unit tests pass, including explicit segment
selection and unsupported-build rejection. The CPU-only feature build also
passes its five unit tests, with no Metal features in its engine closure.
Workload-limit controls reject malformed/session limits and unsupported po2
before proving; they claim no proof success. A prior candidate's three successful
proofs are preserved separately and excluded from final acceptance after the
writable-FFI-pointer review.

Initial resident-worker admission reserves 24 GiB plus the existing host reserve.
The 32-GiB owned worker/helper guard, host-availability floor, pressure checks,
cap 20 and 64M session ceiling remain intact. Physical footprint and helper
resources are observed through the real WorkerPool; these are sampled guards,
not a kernel-enforced memory cap. Do not infer integrated peaks by adding
prototype allocation estimates or reuse CPU-only memory calibration blindly.

## Build and reproduce

The established native assets and unchanged verifier must already be available.
Use the published engine checkpoint below. The origin remains the Hemi fork,
which the local source checker requires; fetch the implementation from the
personal fork before selecting the exact commit:

```sh
git clone https://github.com/hemilabs/risc0.git ENGINE
git -C ENGINE remote add dimitryB https://github.com/dimitryB/risc0.git
git -C ENGINE fetch dimitryB codex/hemi-macos-metal
git -C ENGINE checkout --detach cef3559d6805769c5b33fb4040abe548e670e268
```

From the miner root, use the project-local toolchain:

```sh
source scripts/macos/env.sh
export PROTOC="$PWD/target/macos/bootstrap/protoc-36.2/bin/protoc"
export CARGO_NET_OFFLINE=true
python3 scripts/macos/local-engine.py ENGINE target/macos/rv32im-worker/engine.toml --revision cef3559d6805769c5b33fb4040abe548e670e268
python3 scripts/macos/build-worker.py --mode native-rv32im-metal --config target/macos/rv32im-worker/engine.toml --engine ENGINE --revision cef3559d6805769c5b33fb4040abe548e670e268 --tests > target/macos/rv32im-worker/build-final.log 2>&1
python3 scripts/macos/test-native-worker.py --engine ENGINE --worker-kind native-rv32im-metal --segment-hal metal --recursion-hal metal --segment-check-cpu --repeat 1 --proof-only
python3 scripts/macos/validate-rv32im-worker.py --engine ENGINE --smoke SMOKE_RUN
python3 scripts/macos/test-native-worker.py --engine ENGINE --worker-kind native-rv32im-metal --segment-hal metal --recursion-hal metal --limit-controls --repeat 1 --proof-only
python3 scripts/macos/build-worker.py --mode native --config target/macos/rv32im-worker/engine.toml --engine ENGINE --revision cef3559d6805769c5b33fb4040abe548e670e268 --tests > CPU_BUILD_LOG 2>&1
python3 scripts/macos/collect-rv32im-worker.py CAMPAIGN --engine ENGINE --limits LIMIT_RUN --cpu-regression-log CPU_BUILD_LOG
```

The build records tracked changes and untracked engine files, verifies the full
local feature closure, and restores the original root Git-source lock. The
campaign freezes its plan before serial trials, retains all results, and checks
worker/verifier seals between cases. Large raw proofs and build artifacts live
under `target/macos/rv32im-worker` and the native worker-run directories.
The final campaign is
`target/macos/rv32im-worker/campaigns/c76287bac2dc468396bf81ee6a91f8f6`.
Its compact [validation JSON](evidence/rv32im-worker-validation.json),
[proof CSV](evidence/rv32im-worker-proofs.csv) and
[engine patch](evidence/rv32im-worker-engine.patch) are saved with this report.
The source/binary archive is `target/macos/rv32im-worker/archive/final`.
No test worker/helper remains, the dedicated VM remains stopped, and the original
default VM remains running. Neither profile was started or stopped by this work.

The proof records retain their measurement-time commit IDs and uncommitted-state
flags. They have not been rewritten to imply a new proof campaign. The
[authorship map](evidence/authorship-rewrite.json) records the author-only history
rewrite, and the [publication record](evidence/rv32im-publication.json) binds the
tested files and binaries to the committed engine checkpoint and rebuilt seals.

At the original checkpoint, an integrated performance claim still needed a
controlled comparison against the committed step-5 baseline. The completed
review comparison above now records that gate with identical fixtures and settings.
GPU witness/accumulation, larger segment caps and overlapping segments remain
outside this implementation.
