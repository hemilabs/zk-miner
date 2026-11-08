# Phase 2: Metal proving performance on macOS

Re-exported spec SHA-256 (2026-11-07):
`9a0e052f6c1e72a1a8a31d3081fe3a3604bbfe11cb9fd661e30109c21c12f6f1`.

## Parent review publication — 2026-11-08

The owner authorized opening both parent Mac backend PRs before #30 merges.
[risc0 #35](https://github.com/hemilabs/risc0/pull/35) proposes the engine
Phase 2 branch against `release-3.0` at `54921e770`; it is open and ready
for review, with the overlap with still-open
[#30](https://github.com/hemilabs/risc0/pull/30) disclosed in its body.
[zk-miner #29](https://github.com/hemilabs/zk-miner/pull/29) proposes the
miner Phase 2 branch against `main` at `af44acc`; it is open and ready for
review and depends on the engine PR. Both were reported mergeable on
creation, with no CI checks yet reported. The root miner engine pin remains
the upstream `main` pin, and the local override continues to bind the
validated engine commit. No direct push to either parent branch occurred.
The WP6 archive fork draft PR was closed after its missed gate; its branch
and evidence were kept. The phase-2 performance and correctness ladder is
closed; only upstream review and the declared PR dependency remain.

## WP8 identity_p254 on Metal — closed, 2026-11-07/08

The owner authorized full WP8 after the identity profile. The re-exported
spec SHA-256 remains
`9a0e052f6c1e72a1a8a31d3081fe3a3604bbfe11cb9fd661e30109c21c12f6f1`.
The work was validated on isolated `codex/hemi-macos-metal-wp8` branches.
On 2026-11-08, both `codex/hemi-macos-metal-phase2` branches were
fast-forwarded to the WP8 tips and pushed to the `dimitryB` forks without
force: engine `bcdca76fc8e83d0a42b5fecbda5f048e01cd2bce` and miner
`a4ee58e037240e0dd9494619981cd2926e01d4ea`.
Its Metal hash suite runs the CPU Poseidon254 permutation over BN254 Fr using
eight 32-bit Montgomery limbs, explicit carries and native 32-bit low/high
products. The 150 round constants and nine MDS entries were checked against
the CPU suite after conversion to Montgomery form. The recursion Metal HAL
now selects this suite for the actual `poseidon_254` recursion selector;
the first build exposed and corrected a `poseidon254` selector mismatch.

Parity passed for 134 field-input pairs including zero, one, p−1, R, R² and
deterministic random elements; `hash_rows`/`hash_fold` boundary suites; and
the full identity data commitment of 2^18 rows by 128 columns with every
Merkle fold level against the CPU HAL. The final source-bound worker was
sealed at binary SHA-256
`9b2532dd859292c53545f14324b5ef264ce2d6fbc4e686863e276f45078e0a55`
(manifest SHA-256
`1841887196b5686e577e515e7fdfc62656a321f58d0a982c16b7d9e4dfa7b728`).
Its build-time po2-14 proof verified against the unchanged external verifier
with all three tamper rejections; complete proving took 18.168 s. The run is at
`target/macos/native-wrap/worker-runs/28bd6e9445694b04b3f5bbff11aa608f/`.
Its sidecar records Metal identity execution, one completed constraint check,
seven Poseidon254 row dispatches, 116 folds, and about 3.00 s of GPU time
in the batched identity Merkle command buffers. The CPU implementation remains
available as the differential oracle.

A 10M arithmetic proof with recursion CPU evaluator differential enabled
verified with three tamper rejections at
`target/macos/native-wrap/worker-runs/9d0ce927788b4bb786c6457f41bc95ed/`;
its 4.550 s identity time includes the differential and is not a timing
gate reading. A 10M hashing proof without that diagnostic verified with
three tamper rejections at
`target/macos/native-wrap/worker-runs/8536e2be1edb4d838166da7985a7827c/`;
identity took 3.518 s. On the final worker, complete real-witness Metal/CPU
differentials at po2 14, 18 and 20 passed, with unchanged external verification
and three tamper rejections per proof. The 20-request lifecycle plus recovery
verified 21 proofs with 63 tamper rejections; idle worker/helper footprint fell
from 3.617 to 3.413 GB between requests 1 and 20. Nine input-limit controls
and a po2-20 cancellation during observed CPU/GPU segment overlap passed,
including recovery proofs. The final CPU-only worker build passed 11 tests;
the generic Metal primitive suite passed 24 tests, including identity-size
Poseidon254 Merkle parity. The first cancellation attempt used a tiny
single-segment workload that completed before cancellation; it is retained
as a harness fixture miss. Evidence paths and SHA-256 values are recorded in
`evidence/phase2-wp8-validation.json`.

The sealed post-diagnosis Phase 2 worker
`c3428c3717c331c452e3621736e779ae1f06311003dfd65b50f292d39877e5f9`
was paired against the final WP8 worker with both resident, identities pinned,
one excluded warmup per arm, five alternating measured pairs per fixture,
18 Rayon and Go threads, po2 20, and the default 8 GiB reserve. All 36 proofs
verified with the unchanged verifier and 108 tamper rejections; no proof row
was excluded or retried. The earlier two paired harness attempts failed
before a usable pair because their acceptance assertion assumed Metal identity
for the sealed baseline. The harness now admits CPU identity only for this
explicit paired campaign; the collector requires CPU identity in arm 0 and
Metal identity in arm 1. All failed attempts remain in the validation record.

| Fixture | Baseline median (s) | WP8 median (s) | Median saving (s) | WP8 min–max (s) |
| --- | ---: | ---: | ---: | ---: |
| 10M arithmetic | 49.516 | 39.404 | 10.113 | 39.384–40.423 |
| 10M hashing | 49.496 | 39.419 | 10.077 | 39.397–39.431 |
| 46M arithmetic | 158.565 | 149.425 | 9.141 | 149.382–149.461 |

Identity plus wrap fell from 17.009 to 7.417 s in arithmetic and from 16.947
to 7.327 s in hashing; the candidate's identity Merkle GPU batch medians were
2.535 and 2.466 s. The 46M identity plus wrap median fell from 16.841 to
7.257 s. All paired peak owned footprints stayed below 32 GiB. The per-proof
stages, background and thermal snapshots, min–max, and five within-pair ratios
are in `evidence/phase2-wp8-paired.json` and `.csv`.

The first absolute-reading preflight reached 900.1 s idle with Brave closed
and nominal thermal, then stopped before any proof because its prebuilt
acceptance harness no longer matched the paired-harness source fix. The
source-bound harness was rebuilt and verified with one po2-14 proof and three
tamper rejections; a new browser-closed idle interval began at
2026-11-08T03:50:19Z. The controlled reading passed after 900.09 s idle,
with Brave closed, default 8 GiB reserve, nominal thermal at the start,
one excluded warmup and five measured proofs per fixture. All 12 proofs
verified with 36 tamper rejections. The identity wall timer, not only GPU
dispatch time, meets the spec's ≤4 s gate on both fixtures:

| Fixture | Identity median (s) | Identity min–max (s) | Complete median incl. verifier (s) |
| --- | ---: | ---: | ---: |
| 10M arithmetic | **2.724** | 2.711–2.764 | 40.418 |
| 10M hashing | **2.717** | 2.710–2.726 | 40.405 |

After both phase-2 branches were fast-forwarded and published, a separate
controlled 46M arithmetic reading on the same sealed worker passed after
900.09 s browser-closed idle with default 8 GiB reserve and nominal thermal
state at start. One warmup was excluded; the five measured complete proofs
had median **150.448 s** (149.460–151.488), under the 180 s desirable line.
Identity wall time was 2.817 s median (2.704–3.088). All six proofs passed
the unchanged external verifier and all 18 tamper checks rejected. The
116.295 / 25.512 / 7.452 s stage medians (execution plus segments /
recursion / identity plus wrap), per-proof rows, source hashes and host
snapshots are in `evidence/phase2-wp8-final-46m-controlled.json` and `.csv`.
Two earlier browser-open preflights stopped before any proof (Brave, then
Safari), and their raw result hashes are retained in the evidence record.

The complete proof times here are absolute readings, while the paired campaign
above identifies WP8's code cost and saving. Per-proof stage timers, verifier
and tamper results, Metal dispatches, GPU timing, memory and host snapshots
are in `evidence/phase2-wp8-controlled.json` and `.csv`. The Mac correctness
and timing gates pass. After the owner approved the privileged Colima action,
the exact engine `bcdca76fc8e83d0a42b5fecbda5f048e01cd2bce` passed all
three offline Linux feature paths: recursion `prove,metal`, RV32IM `prove`,
and zkVM `prove,metal-recursion`. The cached `rust:1.93-trixie` image was run
with `--pull never`, `--network none`, and Cargo `--offline --locked`; the
snapshot and log hashes are in `evidence/phase2-wp8-linux.json` (SHA-256
`c1e0ce99e4bc5b8f196afd5a98f1c15b7d714406fa7f8eaefa2eee717ee0681a`).
The WP8 checkpoint is closed. Colima reported already running when started;
two pre-existing Postgres and pgAdmin containers were still up, so the VM was
left running to avoid interrupting them. Neither default po2 nor the memory
ceiling changed.

## Identity_p254 profile — 2026-11-07/08

The re-exported spec's Identity profile section was re-read; its SHA-256
remains `9a0e052f6c1e72a1a8a31d3081fe3a3604bbfe11cb9fd661e30109c21c12f6f1`.
The published sealed worker `c3428c3717c331c452e3621736e779ae1f06311003dfd65b50f292d39877e5f9`
was preserved. A source-bound diagnostic worker
`5832edb772968101731a192d0cde232ff2eaf4d1a203098fc1362a95541743c5`
from timer-only engine commit `6cfd014fcdb5fe035b950a6b35e53ed1192359bd`
(base `881513e02`) exposed CPU Poseidon254 HAL spans and forwarded the
unchanged gnark helper's debug timings to worker stderr under `RISC0_VERBOSE`.
Three consecutive 10,003,116-cycle arithmetic proofs verified with the
unchanged external verifier and nine tamper rejections. The final run began
2,002.3 s after the last build with Brave and Safari closed, default 8 GiB
reserve, 18 Rayon/Go threads, po2 20, nominal thermal at start and end,
and no browser in either host snapshot. Two earlier start gates found Brave
open and stopped before proof; their failed preflights are retained. Brave
had reopened during the wait, so a continuously browser-closed final
15-minute interval was not established; these are component timings, not a
new controlled absolute latency line.

| Component | Median (s) | Min–max (s) |
| --- | ---: | ---: |
| Identity proof, excluding helper prestart | 14.044 | 13.743–14.976 |
| Poseidon254 `hash_rows` + `hash_fold` (Merkle commitments and FRI) | **11.968** | 11.665–12.975 |
| Recursion transforms + evaluator | 1.970 | 1.842–1.977 |
| Other identity work, measured residual | 0.107 | 0.101–0.159 |
| Native wrap elapsed | 4.926 | 4.825–9.223 |
| Rust witness generation/streaming | 0.339 | 0.320–4.978 |
| Gnark constraint-system + key load | 0.614 | 0.597–0.677 |
| Gnark proving | 4.240 | 4.014–4.371 |
| Wrap residual after Rust witness and gnark proving | 0.235 | 0.231–0.246 |

Hashing was **85.2%** of identity (84.9–86.6% per proof).
`RISC0_VERBOSE` supplied the identity boundary, `poly_group`,
`start_finalize` and `finalize` cross-checks; new diagnostic-only CPU
HAL timers separate hash rows/folds from NTT, zk-shift, polynomial
evaluation, FRI fold and synchronous `eval_check`. WP0's GPU/CPU
attribution covers Metal lift/join but not CPU-only identity; its profile
is bound by SHA in the [evidence](evidence/phase2-identity-profile.json).
The helper's `loadWitness` timer includes waiting on stdin throughout
identity and is not witness compute; key loading overlaps identity, and
the first proof's 4.98 s Rust witness path explains the wrap's 9.22 s
maximum. The raw run, stage logs, per-proof timers, worker and engine
SHAs, and the two stopped preflights are in
`evidence/phase2-identity-profile.json`.

**Recommendation.** Choose full WP8: the measured 85% hash share leaves at most about 2 s for a hybrid transform/evaluator port before transfer costs. If a full BN254-limb Poseidon254 kernel reaches the spec's ≤4 s identity gate, it could save roughly 8–10 s and move a 49.5 s 10M proof toward 40–42 s; that is an estimate requiring a paired campaign. Require CPU `poseidon_254` parity on random and edge field values (zero, one, p−1, Montgomery boundaries), `hash_rows`/`hash_fold` parity at identity sizes, and complete identity receipts and Groth16 proofs accepted by the unchanged verifier with three tamper rejections; the owner subsequently authorized WP8, with progress recorded above.

## Upstream padding PR #30 — ready for review, 2026-11-07

The existing [hemilabs/risc0 PR #30](https://github.com/hemilabs/risc0/pull/30)
now points to the validated `d354733d6efa627d72521eea19482f5b328a7ed0`
rebase on `release-3.0` `54921e770`. The old
`f9455a518` head was replaced on the `dimitryB` fork with a
SHA-pinned force-with-lease; the local PR branch was aligned to the new
head. GitHub reports one commit, three changed files, a clean merge, and
draft=false. The PR description now records the 37/37 execute tests and
the unchanged-verifier 10M proof with three tamper rejections. The
[#33 conflict/re-proof note](https://github.com/hemilabs/risc0/pull/33#issuecomment-6714421285)
was answered with the same evidence. No parent branch was merged.
The evidence manifest remains
`evidence/upstream-final-segment-padding-r2.json`.

## Post-merge regression diagnosis — paired gate passed, 2026-11-07

The upstream-merge publication stop was held pending this controlled paired reading;
campaign A subsequently met the lift rule below.
The first campaign attempt is retained at
`target/macos/phase2/upstream-diagnosis-pairs/a-37ba8e734f7c43e3b3f80aa77e5e4c84/`:
it stopped before any proof because the sealed WP8-lite worker speaks IPC
protocol 5 and the merged supervisor speaks protocol 10. A test-feature-only
v5 command/response adapter now lets the same supervisor keep both exact
worker binaries resident; production worker hashes are unchanged. A four-proof
small-fixture diagnostic passed external verification and all tamper checks at
`target/macos/native-wrap/worker-runs/60569d475d2a40c4bc7fd646ef9e3d2d/`.
The failed sandboxed diagnostics are retained in their own worker-runs; their
old-worker process was killed by the safety guard when sandboxed process reads
were unavailable. The successful diagnostic used ordinary user-level macOS
process reads. The source-bound acceptance harness is prebuilt at
`target/macos/phase2/upstream-diagnosis-acceptance-prebuild/` so the paired
reading can begin after the prescribed 15-minute idle interval without a
build between the preflight and first proof. Historical old/new logs and bundle
file identities are recorded in
`evidence/phase2-upstream-diagnosis-historical-logs.json`.

Campaign A ran with the browser closed, the current default 8 GiB host
reserve, nominal thermal at the start, and **920.8 s idle** after the last
acceptance build. Each fixture kept both exact workers resident and ran one
proof at a time in alternating order, with one excluded warmup per arm. All
32 complete proofs passed the unchanged verifier and 96 tamper rejections.
There were no admission waits; pressure stayed normal and the maximum owned
footprints were 18.86, 18.89 and 19.33 GiB respectively, below the 32 GiB
ceiling.
The paired median of complete-latency gaps is the decision statistic:

| Fixture | WP8-lite median (s) | Merged median (s) | Paired gap, merged − WP8-lite (s) | Within-pair gaps (s) |
| --- | ---: | ---: | ---: | --- |
| Arithmetic 10M | 49.508 | 49.516 | +0.007 | +2.035, −0.008, +0.007, +0.008, −0.068 |
| Hashing 10M | 49.507 | 49.513 | +0.001 | +0.039, +0.001, −0.010, −0.057, +0.006 |
| Arithmetic 46M | 159.542 | 160.540 | +0.999 | −1.003, +0.999, +1.031 |

The 10M gaps are ≤1 s and the 46M gap is ≤3 s, so the spec's paired
lift rule is met. Campaign B and the upstream-commit bisect are not triggered.
The old and merged workers had the same 18 Rayon/18 Go settings and actual
nice 0 / priority 31 at process start in every fixture. macOS `ps` did not
expose thread QoS, so QoS is unmeasured. Median request → first `gpu_submit`
was 1.739/1.738 s (old/merged) on arithmetic 10M, 1.978/1.968 s on hashing
10M and 1.974/1.972 s on 46M. There was no per-proof bundle re-verification
or identity-mismatch line in either the paired or historical worker logs. The
successful rehash path does not itself log a line, so absence of a line alone
cannot rule out a silent rehash; the bundle file identities and near-equal
identity+wrap medians supply additional evidence. The full per-proof stage
timers, GPU totals, pair ratios, process status and log lines are in
`evidence/phase2-upstream-diagnosis-a.json` and `.csv`; the raw campaign is
`target/macos/phase2/upstream-diagnosis-pairs/a-59db709f867b4af1b29dc6d867d019ec/`.

| Fixture | Segment stage old/merged (s) | Recursion old/merged (s) | Identity + wrap old/merged (s) | Segment GPU old/merged (s) |
| --- | ---: | ---: | ---: | ---: |
| Arithmetic 10M | 26.101 / 26.187 | 5.448 / 5.463 | 17.488 / 17.477 | 29.246 / 29.249 |
| Hashing 10M | 26.277 / 26.249 | 5.449 / 5.384 | 16.907 / 17.002 | 27.269 / 27.220 |
| Arithmetic 46M | 116.023 / 116.730 | 25.629 / 25.660 | 16.925 / 17.008 | 134.394 / 135.670 |

The segment GPU column sums per-kernel GPU timestamps; it is a profile total,
not elapsed wall time, and can exceed the segment-stage wall duration.

The amended absolute reading began after **920.3 s idle** following campaign
A, with browser closed, default 8 GiB reserve and nominal thermal at the
start. The unchanged worker and verifier passed all 18 complete proofs and
54 tamper rejections. Five measured complete medians after one excluded
warmup per fixture were:

| Fixture | Median (s) | Min–max (s) | Segment stage (s) | Recursion (s) | Identity + wrap (s) | Peak owned GiB |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Arithmetic 10M | 49.532 | 49.500–51.529 | 26.171 | 5.480 | 17.474 | 18.84 |
| Hashing 10M | 50.274 | 49.244–52.297 | 26.569 | 5.562 | 17.460 | 18.77 |
| Arithmetic 46M | 159.559 | 158.379–161.553 | 116.345 | 25.772 | 16.937 | 19.29 |

All three meet the 55/55/220 s minimum lines; 46M also meets its 180 s
desirable line, while the 10M fixtures do not meet 45 s. Memory pressure
stayed normal and every peak remained below the unchanged 32 GiB guard.
See `evidence/phase2-post-diagnosis-controlled.json` and `.csv`, raw campaign
`target/macos/phase2/controlled-post-diagnosis/a0f3f00ec4b9416d869c91ab2f31da11/`.
The final worker is re-sealed at
`target/macos/phase2/post-diagnosis-final-checkpoint/` with manifest SHA-256
`c9e2ea296cbbcc243665e5f48719c28b295aed15502ecb273c67b9d576288dd1`;
the worker binary remains SHA-256 `c3428c3717c331c452e3621736e779ae1f06311003dfd65b50f292d39877e5f9`.

Reproduction from the sealed files and already-built source-bound harness:

```sh
HEMI_MINER_DIR=/Users/dbur/dev/zk-miner source scripts/macos/env.sh
export PROTOC=/Users/dbur/dev/zk-miner/target/macos/bootstrap/protoc-36.2/bin/protoc CARGO_NET_OFFLINE=true
python3 scripts/macos/phase2-run-upstream-diagnosis-pairs.py --baseline-archive target/macos/phase2/wp8lite-checkpoint --expected-baseline-sha256 625589c35f6583bfaf4510a00d6f98dceb781b004064500ce38b44b42d659be7 --label a --last-activity-file target/macos/phase2/upstream-diagnosis-acceptance-prebuild/acceptance-build.json --acceptance-build-manifest target/macos/phase2/upstream-diagnosis-acceptance-prebuild/acceptance-build.json
python3 scripts/macos/phase2-collect-upstream-diagnosis-pairs.py target/macos/phase2/upstream-diagnosis-pairs/a-59db709f867b4af1b29dc6d867d019ec
python3 scripts/macos/phase2-run-post-diagnosis-reading.py --last-campaign-result target/macos/phase2/upstream-diagnosis-pairs/a-59db709f867b4af1b29dc6d867d019ec/result.json --acceptance-build-manifest target/macos/phase2/upstream-diagnosis-acceptance-prebuild/acceptance-build.json
python3 scripts/macos/phase2-collect-post-diagnosis-reading.py target/macos/phase2/controlled-post-diagnosis/a0f3f00ec4b9416d869c91ab2f31da11
python3 scripts/macos/phase2-seal-post-diagnosis.py
```

Both run scripts enforce their 15-minute idle gaps and nominal start
thermal before timing. The final seal script refuses to overwrite an
existing checkpoint.

Publication: non-force pushes to the `dimitryB` forks succeeded, engine
`codex/hemi-macos-metal-phase2` at
`881513e022d98ac7c07460ba090a5f6a5657334a` and miner diagnosis/evidence
commit `d333818483bdd0c16b45d48c2aff11e3ebcf4698` on its same-named
branch. No upstream or existing PR branch was pushed.

## Upstream final-segment padding r2 — 2026-11-06

The separate `codex/upstream-final-segment-padding-r2` engine branch is based
on upstream `release-3.0` `54921e770bcb62578d4ffb7a7f70131b611bda2a`.
Commit `d354733d6efa627d72521eea19482f5b328a7ed0` cherry-picks
`f9455a5181cb733e45085ee0daf25afe7737eb66`. Its one conflict was the
append collision in `risc0/circuit/rv32im/src/execute/tests.rs`; the #33
refusal tests precede the two final-padding tests. The execution-only test
suite passed 37/37 cases.

A CPU worker sealed against this r2 engine commit produced one complete
10,003,116-user-cycle arithmetic proof at cap po2 18. The unchanged pinned
external verifier accepted it and rejected the wrong image, modified journal,
and corrupt seal. The 44 segment sizes, derived from the worker's total cycles
and the executor's full-size nonfinal segments, are 43 × po2 18 followed by a
padded final po2 17. The CPU worker required an explicit 64M guest-cycle
limit and 1800-second watchdog; its proof took 1562.2 seconds. This Mac lacks
Apple's `metal` compiler, so the CPU-only build used a recorded placeholder
for the unused Metal asset while compiling CPU kernels normally. The original
CPU collector reported failure after the test and external verification passed
because it expected the retired staging-byte field. The corrected collector
validated the saved proof without another run. See
`evidence/upstream-final-segment-padding-r2.json` and the raw run path there.
The existing PR branches were not changed.

## Upstream merge after WP6b — 2026-11-06

WP6b was merged into the Phase 2 branches before this sync. The engine merge
commit `881513e022d98ac7c07460ba090a5f6a5657334a` brings
`hemilabs/risc0` `release-3.0` at `54921e770bcb62578d4ffb7a7f70131b611bda2a`
into the Mac engine. The miner merge brings `hemilabs/zk-miner` `main` at
`af44acc9b5f3cf15d93395d54407eb5382561404`; its `Cargo.toml` keeps
upstream's `risc0` pin, while the local engine override names the reviewed
merged engine SHA. The root `Cargo.lock` retains Git-source pins after local
worker builds.

Every merge conflict and resolution:

| Repository | File | Resolution |
| --- | --- | --- |
| engine | `risc0/circuit/rv32im/src/execute/tests.rs` | Kept upstream #33 execution refusal tests first and the Mac branch's two final-padding tests afterward. The combined 37 execute tests passed with `--features prove`. |
| miner | `Cargo.lock` | Kept upstream dependency and Git-source updates, adding the Mac worker's `metal`, `risc0-binfmt`, and `serde_json` edges; no local path-source lock is committed. |
| miner | `crates/zkminer-cli/src/commands/run.rs` | Took upstream claim-window, measured-cycle, and backend sizing checks. Dropped the older Mac CPU-row cost and timeout overrides because upstream removes fabricated CPU benchmark rows. |
| miner | `crates/zkminer-prove-risc0/build.rs` | Kept upstream Intel/ROCm runtime search paths and the separate Mac embedded-guest early return. |
| miner | `crates/zkminer-prove-risc0/src/main.rs` | Kept upstream IPC isolation, panic containment, program binding, deterministic `sys_rand`, and execute/prove validation; retained Mac probes, preflight, direct proof and warmup paths. The Mac proof environment now uses the same program/input seed as pre-claim execution. |
| miner | `crates/zkminer-prover/src/benchmark.rs` | Took upstream's measured GPU-only rows and removed the local row merge that depended on its old CPU-row shape. |
| miner | `crates/zkminer-prover/src/engine.rs` | Kept the Mac-specific po2 calibration guard; upstream added no competing implementation in that location. |
| miner | `crates/zkminer-prover/src/memory.rs` | Kept upstream's Linux `/dev/shm` capacity check and the Mac-specific reserve, footprint and pressure functions. The shared floor uses the platform reserve on Mac. |

The merged Metal worker SHA-256 is
`c3428c3717c331c452e3621736e779ae1f06311003dfd65b50f292d39877e5f9`.
Its build-time po2-14 proof verified with three tamper rejections. The
20-request lifecycle and restart suite verified 21 proofs; po2-14/18/20
real-witness segment and recursion CPU differentials, nine input-limit
controls, and multi-segment pipeline cancellation passed. The CPU-only worker
and unit tests built, and the offline Colima recursion, rv32im, and zkvm
feature paths passed against the merged engine. The root Git-source lock was
restored. See `evidence/phase2-upstream-merge-acceptance.json`. An initial
pipeline-cancel harness invocation used a single-segment boundary workload,
so it could not observe overlap and failed its assertion; the 10M arithmetic
multi-segment rerun passed.

The source-bound checkpoint manifest SHA-256 is
`e7a3cae3ab845a2f84050c8d737d7bbe8fb62fd43189efa64b98416a92c1c13d`.
The controlled reading used the newly sealed worker, browsers closed, normal
memory pressure, the new default 8 GiB reserve, one excluded warmup and five
measured independently verified proofs per fixture. Complete medians were:

| Fixture | Prior final median (s) | New median (s) | Change (s) | Prior measured range (s) |
| --- | ---: | ---: | ---: | ---: |
| arithmetic 10M | 48.458 | 52.479 | +4.021 | 48.452–50.316 |
| hashing 10M | 49.511 | 51.350 | +1.838 | 49.498–50.512 |
| arithmetic 46M | 165.835 | 167.162 | +1.327 | 162.522–167.474 |

The first two new medians exceeded even the prior measured maxima and
triggered a conservative publication stop. The subsequent paired campaign A
above did not reproduce a code-cost gap and met the amended lift rule; the
absolute difference is not used as a regression verdict. The 46M median
stayed within its prior range. The old final
reading used its then-default 16 GiB reserve; this reading uses the current
default 8 GiB reserve, as requested. Both campaigns were browser-closed and
started at nominal thermal state. The full 18-proof campaign and all 54
tamper rejections passed; see `evidence/phase2-upstream-merge-controlled.json`
and its CSV. The merged branches remained local through diagnosis, with their
upstream merge commits preserved.

## WP7 admission estimator — 2026-11-06

The revised spec export SHA-256 is
`ecd565ffba5582c00c1191d8a427cd5bb48d90440b21b8d0423735e9e7847031`.
WP7 admission uses normal kernel pressure plus measured owned worker/helper
footprint, with the conservative VM estimate as a secondary admission floor.
The reserve default is 8 GiB (range 8..64 GiB). The in-proof guard now follows
pressure and the 32 GiB owned-footprint ceiling: normal or warning continues;
critical, unreadable pressure/footprint, or an exceeded ceiling stops the group.
The VM estimate is sampled and logged, not used to kill a running proof.

The held-memory integration used a sibling process writing 64 GiB of
incompressible pages. Admission was at 20.17 GiB estimated and normal pressure;
the proof verified with a guard minimum of 8.04 GiB, pressure levels 1 and 2,
and a 14.84 GiB peak owned footprint. A 60 GiB case also passed at 24.40 GiB
admission headroom. The explicit unit case at 16 → 3 GiB estimated and normal
pressure continues. Under Brave, Zed and Colima, a 10M proof verified with an
admission-wait upper bound of 0.212 s. A real warning-pressure refusal named
level 2, preserved the raw estimate, and started no request or helper; logical
reservation refusal and recovery also passed. The 20-request lifecycle plus
recovery verified 21 proofs with 63 tamper rejections and 16.25% lower idle
RSS; po2-14/18/20 differentials, nine limit controls, macOS/Linux CPU-only
builds, and unit tests passed. The sealed WP8-lite worker SHA-256 stayed
`625589c35f6583bfaf4510a00d6f98dceb781b004064500ce38b44b42d659be7`.
See `evidence/phase2-wp7-validation.json`. WP7 passed all three merge
conditions and is merged into the Phase 2 miner branch.

## WP6b startup off the critical path — 2026-11-06

WP6 closed on a timing miss: the source-keyed binary archive saved about
0.16 s with the driver shader cache already warm. Its engine draft PR remains
open and unmerged. WP6b moves full bundle hashing off worker startup while
joining it before helper use, runs one po2-14 proof during every Metal worker
build to warm the driver cache, and records one true cold reading. Its gate is
warm-driver spawn → handshake at most 1.0 s (three-run median), then first
request → first GPU dispatch at most 5 s after build-time warm-up, with
lifecycle, differential, limit controls, tamper checks, and unchanged assets
green. Evidence will be under `evidence/phase2-wp6b-*.json`.

Engine `7816a0002642bf97bbcdd82bd55ebaa22d84ad80` and the source-bound
worker `f65ff7a374e4471404d9bc52dab57d010e12cb5af4d0f5197053b0f8107060ab`
passed the warm-driver gates. With browsers closed and the default 8 GiB
reserve, three sealed pre-WP6b launches had a 4.619 s handshake median;
three WP6b launches had a 0.107 s median. `build-worker.py` completed and
verified its mandatory po2-14 proof in 29.164 s. The first direct proof
after that build reached a completed GPU dispatch in 57.1 ms from request,
well inside the 5 s gate. These are warm-driver readings. On the first login
to the fresh `zkmac` account, launch → handshake was 0.106 s, handshake →
request was effectively immediate, and request → first completed GPU dispatch
was 25.129 s; the complete proof took 62.467 s and verified with three tamper
rejections. No driver cache was deleted. The exact final worker
passed 21 lifecycle/recovery proofs, po2-14/18/20 segment and recursion CPU
differentials, nine input-limit controls and a corrupted-bundle rejection
before helper spawn. See `evidence/phase2-wp6b-validation.json` and
`evidence/phase2-wp6b-cold.json`. WP6b is closed with both warm gates and
correctness passing; the fresh-user cold reading is a single observation.

## Controlled final reading — revised brief, 2026-11-06

The spec export used for this controlled reading had SHA-256
`c7cd2ab3cf8f6f67fb4deeabfd9ed86c28d24aa98c0e7c1a7b578640718d475d`.
The unchanged WP8-lite worker is sealed at
`target/macos/phase2/wp8lite-checkpoint/` (manifest SHA-256
`c8d537ec642be3edc7d3baec9763084b3d492cb8fd3af7ffdaa8c7556dc39574`).
The absolute reading uses the default 16 GiB reserve, a closed browser,
nominal thermal state at the start, po2 20 with segment pipelining, 18
Rayon/Go threads, and the same unchanged verifier. Each of the arithmetic
10M, hashing 10M and arithmetic 46M fixtures gets one excluded complete
warmup and five measured complete proofs. The minimum lines are 55 s at
10M and 220 s at 46M; the desirable lines are 45 s and 180 s. The WP8-lite
validation record binds the final worker to its lifecycle, differential and
input-limit checks.

The sealed checkpoint campaign passed all 18 complete proofs and 54 tamper
rejections. Five measured medians were **48.458 s** arithmetic 10M,
**49.511 s** hashing 10M and **165.835 s** arithmetic 46M. All three meet
the minimum line; the 46M stretch meets its desirable line, while both 10M
fixtures miss the 45 s desirable line. The maximum guard footprint was
19.24 GiB under the 32 GiB ceiling, with normal memory pressure on every
proof. The browser was absent at every fixture boundary; thermal state was
reported nominal at the start and fair thereafter. Codex, Claude and Colima
were present throughout and are recorded in the host snapshots. See
`evidence/phase2-controlled-final.json` and `.csv`. WP6/WP7 precede the
new one-hour identity profile; WP8 requires an owner decision after that
profile.

## WP8-lite scope — native wrap overlap, 2026-11-06

The revised brief SHA-256 is
`a7ab34ce1697757bcb73622aebe0b503d42b38e3a601942f76e90fd5744f581c`.
The immediately preceding WP1b worker is sealed at
`target/macos/phase2/wp1b-baseline/` (manifest SHA-256
`7b117d05a76c9307abe3ce54752a2ddfdf0036e86b406c1d428ae578e2491950`).
Engine `cd018ee72` starts the native gnark child as `identity_p254` begins,
owns it through identity and wrap, and streams the unchanged witness through
stdin after the helper loads its circuit and proving key. `6521f87c2`
defers Go GC during setup, with 18 Go threads retained for proving. The Go
prover still accepts the prior witness-file path for sealed WP1b. The native
child keeps its parent watchdog, deadline, cleared environment and drop-time
kill/wait behavior.

The one-day WP8-lite time box is closed. The first candidate's arithmetic
10M five-pair median saved 0.030 s (see
`evidence/phase2-wp8lite-iteration1.json`), so a bounded setup-scheduling
iteration was tried. The final campaign against sealed WP1b used one excluded warmup
per arm and five alternating measured pairs on each 10M fixture and the 46M
stretch, with po2 20, WP2 pipeline, 18 Rayon/Go threads, 8 GiB reserve,
the same active helper bundle and unchanged verifier. All 36 proofs and 108
tamper rejections passed. The complete medians were 49.497 → 49.479 s
arithmetic 10M, 49.519 → 49.484 s hashing 10M, and 167.598 → 166.609 s
arithmetic 46M. Identity plus wrap improved 0.509/0.425 s at 10M. The
required 1.5 s complete saving was missed on both 10M fixtures; the
candidate is retained as the best correct measured variant. Maximum guard
footprint was 19.31 GiB with normal pressure. See
`evidence/phase2-wp8lite-paired.json` and `.csv`.

Complete real-witness CPU checks passed at po2 14/18/20 (22/1/1 checks),
as did input limits, five CPU-only unit tests and three offline Linux
feature paths. The 20-request lifecycle plus recovery proof verified 21
proofs and 63 tamper rejections; idle footprint decreased 17.86%.
Cancellation during identity and wrap left no owned helper, and separate
real-helper parent-death probes during key loading and proving exited
without a proof. See `evidence/phase2-wp8lite-validation.json`.
The controlled final absolute-line reading at the default 16 GiB reserve
is recorded above; WP6/WP7 are next.

## WP1b scope — remaining evalfast passes, 2026-11-06

The current brief SHA-256 is
`a8627ca24baec008b140a4bb75f9ef8bb75fd67281e9a8e628c328afb6542a09`.
Engine `7222459e3` retargets the pinned CUDA pipeline's `mksm2.py` hot-slab
placement and `mksub.py` chain-tail split to Metal. The generated shader
places the 32 hottest words per main or LogUp phase in one 32 KiB
threadgroup array at 256 threads; other words remain in private memory.
The existing `RISC0_RV32IM_TAIL_SPLIT=1` fallback remains available.
The sealed WP4 po2-20 pipelined worker is the baseline arm.

The build-time CPU/CUDA polynomial check and the pinned CUDA generator
`--check` pass. The synthetic Metal-vs-CPU harness matches at po2
4/8/14/18/20 with reuse, offsets and sentinels. Complete po2-14/18/20
real-witness proofs passed the segment CPU differential and unchanged
external verifier. A source-identical po2-20 sweep with CPU checks and reuse
measured evaluator GPU times of 3.132, 1.966, 1.179 and 0.994 seconds at
32, 64, 128 and 256 threads respectively; 256 remains selected. See
`evidence/phase2-wp1b-sweep.json` and `.csv`.
The five-pair package campaign against sealed WP4 verified all 36 proofs
and 108 tamper rejections. Arithmetic and hashing 10M complete medians
fell 57.324 → 50.477 s and 57.322 → 50.299 s, saving 6.846 and
7.022 s. The corresponding evaluator GPU medians fell 1.700 → 1.043 s
and 1.681 → 1.001 s per segment. Both 10M package gates pass. The
46M stretch improved 191.189 → 168.031 s. All rows had normal memory
pressure and the largest guard footprint was 22.14 GiB. See
`evidence/phase2-wp1b-paired.json` and `.csv`. The final clean worker passed
22/22, 1/1 and 1/1 exact real-witness CPU checks at po2 14/18/20,
the tail-split fallback, input-limit controls, five CPU-only unit tests and
all three offline Linux feature paths. The 20-request lifecycle plus
recovery proof verified 21 proofs and 63 tamper rejections; idle worker
footprint decreased 7.06% from request 1 to request 20. See
`evidence/phase2-wp1b-validation.json`. WP1b is closed; WP8-lite is next.

## WP4 scope — revised source brief, 2026-11-05

The latest re-export has SHA-256
`a8627ca24baec008b140a4bb75f9ef8bb75fd67281e9a8e628c328afb6542a09`.
WP4 applies the existing recursion split generator to the Metal gated-sum
evaluator, keeps the six parts in order inside one command buffer per check,
and keeps Poseidon2 unchanged. The sealed WP5 po2-20 pipelined worker is the
baseline arm. The gate is lift/join at most 7 seconds on each 10M fixture,
with a build-time body check, recursion CPU differential on real witnesses,
and complete externally verified proofs. The five-pair campaign holds po2 20,
WP2 pipelining, 18 Rayon/Go threads, and the helper bundle fixed across arms.
The six-part Metal evaluator is selected by default; set
`RISC0_RECURSION_METAL_SPLIT=0` to select the prior single-kernel body for
bisection. Set `RISC0_RECURSION_METAL_CHECK_CPU=1` in a validation run to
compare every recursion constraint result with the CPU oracle on the same
valid witness. The Metal port applies the CUDA generator's pinned lazy-REDC
rewrite after the gated-sum split. HIP-specific arithmetic variants remain
CUDA/HIP only.

The split-only iteration on engine `47bbd7f5a` passed exact recursion
differentials and all 36 paired proofs, reaching 6.829/6.560 s recursion
medians on arithmetic/hashing 10M. A bounded lazy-REDC iteration reduced
evaluator GPU time further, passed the 43-check po2-14 CPU differential,
and became engine `bca7044c5`. The final source passed 19/19 CPU recursion
checks on each complete po2-20 arithmetic and hashing witness. Its five-pair
campaign against sealed WP5 verified all 36 proofs and 108 tamper rejections,
with normal memory pressure and a 22.49 GiB maximum guard footprint.
Recursion medians were 7.733 → 5.609 s arithmetic and 7.480 → 5.489 s
hashing, meeting the ≤7 s gate on both. Complete medians were
57.615 → 55.571 s arithmetic 10M, 57.570 → 55.589 s hashing 10M, and
199.888 → 189.745 s arithmetic 46M. See
`evidence/phase2-wp4-paired.json` and `.csv`; the pre-lazy iteration remains
in `evidence/phase2-wp4-split-paired.json` and `.csv`.
The final 20-request lifecycle plus recovery proof passed with 21 external
verifications and 63 tamper rejections. Idle worker footprint decreased
9.94% from request 1 to request 20. The fallback proof, input-limit controls,
CPU-only build and five unit tests, and all three offline Colima Linux feature
paths passed. See `evidence/phase2-wp4-validation.json`. WP4 is closed;
WP1b is next.

## WP5 scope — revised source brief, 2026-11-05

The latest re-export has SHA-256
`7b67d229839eb5f9d424dc27fed31906e766ea8bcea3c9d892e323d9ebcf5df7`.
WP5 assesses native po2 21 against po2 20 on arithmetic and hashing 10M
fixtures and the 46M arithmetic stretch, each with WP2 pipelining enabled
and disabled. A faster option becomes the default only after complete
unchanged-verifier acceptance, normal pressure, and the existing 32 GiB
owned worker/helper ceiling hold. Po2 20 remains available as the other
profile. The sealed WP3 worker is the preceding checkpoint because WP2b's
candidate was reverted. The revised post-WP5 order is WP4, WP1b, WP8-lite,
then WP6/WP7; WP8 remains optional. The minimum absolute final lines are
55 s on both 10M fixtures and 220 s on 46M under controlled conditions.

The first po2-21 complete proofs verified with the unchanged external
verifier and all three tamper rejections. Pipelining passed a single 10M
proof at 29.25 GiB guard peak and a 46M diagnostic at 29.09 GiB, but a
second resident 10M proof reached 35,255,359,656 bytes (32.84 GiB) with
normal pressure and the production guard stopped it at the 32 GiB ceiling.
The 46M outer harness run is diagnostic only because its test source changed
during execution. Two serial po2-21 resident proofs verified at 19.21 and
22.94 GiB peaks; the warm second proof took 62.40 s. The fixed campaign
therefore compares po2 21 without WP2 pipelining against the sealed WP3
po2-20 pipeline. See `evidence/phase2-wp5-feasibility.json`.

The fixed campaign completed 36 externally verified proofs and 108 tamper
rejections, with normal pressure, zero admission wait and a largest guard
footprint of 23.57 GiB. Five-pair complete medians for sealed WP3 po2-20
pipeline versus po2-21 serial were 59.586 → 58.607 s arithmetic 10M,
58.599 → 61.616 s hashing 10M, and 213.049 → 206.186 s arithmetic 46M.
The candidate is slower on hashing, so it misses the WP5 default-change
gate. Po2 20 with pipelining remains the default; po2 21 with
`RISC0_SEGMENT_PIPELINE=0` is the measured optional profile. Full rows and
source identities are in `evidence/phase2-wp5-paired.json` and `.csv`.
The 20-request lifecycle plus recovery proof passed with 21 external
verifications and 63 tamper rejections; idle worker footprint decreased
17.28% from request 1 to request 20. CPU-only build and tests, protocol
and calibration unit tests, input-limit controls, and all three offline
Linux feature paths passed. The serial po2-20 warm screens were 67.625,
66.339 and 227.060 s on arithmetic 10M, hashing 10M and arithmetic 46M;
each followed an excluded warmup and verified. See
`evidence/phase2-wp5-validation.json`. WP5 is closed with the existing
default; WP4 is next.

## WP2b scope — revised source brief, 2026-11-05

The latest re-export has SHA-256
`f92bf25a4d8d6c94f83acca60383ff7b81fc04e0c5bd1ada20ec603df72d4454`.
It places WP2b immediately after the closed WP3 checkpoint, followed by WP5
and WP4. WP2b has one bounded iteration: widen the overlap so CPU preflight,
witness generation and accumulation can run during the preceding segment's
GPU work, while preserving WP2's explicit buffer ownership and cancellation
rules. Its paired gate is at least 4 s saved on both 10M fixtures against the
sealed WP3 worker at `target/macos/phase2/wp3-baseline/` (manifest SHA-256
`8f1f57c81a2955c91c7aa773c8309822d13557f8527bf1b2c93b4b2953888836`).

The revised protocol distinguishes paired package gates, which record
background load without closing apps, from absolute midpoint and final-line
readings. The latter require a closed browser, default 16 GiB reserve and
nominal initial thermal state. The sealed WP3 midpoint retake under those
conditions passed all 12 proofs and 36 tamper checks: arithmetic 59.556 s,
hashing 60.369 s complete five-proof medians. The campaign started nominal,
with Brave closed and the default 16 GiB reserve; thermal state was fair by
the hashing fixture. The hashing absolute line remains 0.369 s above 60 s,
so the owner's recorded choice to continue into WP2b is supported by the
controlled reading. See `evidence/phase2-wp3-controlled-midpoint.{json,csv}`.

WP2b closed after its single bounded iteration. Engine `a9120a42e` put the
next segment's DATA transforms and Merkle stages on a second Metal queue while
the previous eval-check command buffer was pending. It kept the same dispatch
order and buffer sets, and a complete 10M diagnostic proof verified. The
profile showed that the overlapped transform command took about 1.7 s GPU,
while the prior eval-check took about 1.6 s; DATA commitment still occupied
about 2.0 s wall per steady segment. The second queue competed for GPU time
instead of hiding the dependency. The 21-test Metal primitive suite passed.

The fixed paired campaign passed all 24 external proof verifications and 72
tamper rejections. With recorded Codex, Claude and Colima load, Brave absent,
8 GiB reserve, 18 Rayon/Go threads and fair initial thermal state, the
five-proof complete medians were arithmetic **60.602 s WP3 → 61.630 s WP2b**
and hashing **63.472 s WP3 → 63.342 s WP2b**. Savings were −1.028 s and
+0.129 s, both below the required 4 s. Median transform dispatch wall time
per segment was effectively unchanged: 1.992 → 1.994 s arithmetic and
1.895 → 1.901 s hashing. Peak owned guard footprint was 21.962 GiB.
Engine `bc5dfd6eb` reverts the experiment; its tree is identical to the
sealed WP3 engine. WP3 remains the best correct worker and the WP5 baseline.
No WP2b candidate is deployed, so candidate lifecycle and cancellation were
not used as acceptance gates. See `evidence/phase2-wp2b-paired.{json,csv}`
and `evidence/phase2-wp2b-validation.json`.

## WP3 transform checkpoint — 2026-11-05

The current re-export has SHA-256
`07467098c3493a0bbc0f543b0960676ba3a3e21ebd1fb7a65d10bb8dec40dc97`.
It clarifies that each package pairs against the immediately preceding closed
checkpoint. WP3 therefore uses the sealed WP2 worker at
`target/macos/phase2/wp2-baseline/` (manifest SHA-256
`274a86fb0e10438983285aed6232a6ef922fcb7a73d3cec4bb64f7be9420ca19`).
It also attributes about 3–4 s of the WP2 campaign's measured 6 s to
pipelining itself, with the earlier WP0.5 batching contribution included in
that WP1 comparison. Engine
`7143255acda4e51383237a479b51f914a8be904a` adds fused commit NTT,
zk-shift, LDE, resident twiddles and folded bit reversal; engine
`8520c737725698ddb156ccda2a41e0521213b878` makes radix-four tiles and
column-parallel dispatch the default. `RISC0_METAL_NTT_RADIX2=1` selects the
old transform route for bisection. The separate local Merkle differential
uses existing engine crates and adds no dependency or version to the miner
or engine production graph.

WP3's fixed five-pair campaign against sealed WP2 passed all 24 proofs and
72 tamper checks: arithmetic 72.684 → 61.589 s and hashing
76.409 → 65.384 s, saving 11.095 and 11.025 s. Brave, Codex, Claude and
Colima were present, as recorded by the revised spec's background-load
protocol; both arms used po2 20, 18 Rayon/Go threads and 8 GiB reserve.
The largest paired guard peak was 22.544 GiB, below the existing 24 GiB
initial budget and 32 GiB ceiling. One pipeline-disabled complete proof
measured 0.455 s GPU and 0.636 s dispatch wall steady transform time per
segment; the requested-buffer traffic model gives 327 GB/s, above the
180 GB/s floor. The 21-test Metal primitive suite on both default and
radix-two fallback, exact Merkle differential,
real-witness CPU differentials at po2 14/18/20, CPU-only build, three
offline Colima feature paths, and 20-request lifecycle passed. Idle footprint
fell 14.58%; the 46M stretch verified in 217.957 s with a 17.905 GiB guard
peak. See `evidence/phase2-wp3-{paired,validation}.json` and
`evidence/phase2-wp3-paired.csv`.

The WP3 stage and paired-saving gates pass. Its recorded-load paired medians
were 1.589 s arithmetic and 5.384 s hashing above 60 s; these are not
absolute midpoint readings under the clarified protocol. The controlled
retake above puts arithmetic below 60 s and hashing 0.369 s above it.
The next baseline arm is sealed at `target/macos/phase2/wp3-baseline/` with
manifest SHA-256 `8f1f57c81a2955c91c7aa773c8309822d13557f8527bf1b2c93b4b2953888836`;
it pins engine `8520c7377` and miner checkpoint `afa97e3`.
The 46M result is below the 220 s minimum line but above the 180 s pass
line. A separate browser-closed repeat was stopped after arithmetic once
the revised recorded-load rule was re-read; its partial ledger is retained.
A first lifecycle attempt passed 20 steady proofs and idle drift, then used
a 60 s helper-timeout deadline that exceeded the tiny proof's 45.4 s
completion. The 35 s rerun passed every control and is the closure run.

Earlier WP3 launch-grid diagnostics are recorded in
`docs/macos/evidence/phase2-wp3-start.json`. Full butterfly coverage measured
2.420 s steady transform wall time per po2-20 segment; a bounded grid per
column measured 2.220 s. Both complete arithmetic proofs passed the pinned
external verifier and its three tamper tests. The 20-test Metal primitive
suite passed for each variant. These were unfused pre-port diagnostics and
are separate from the final paired gate measurement above.

## Revised source brief — 2026-11-05

The current re-export of `Phase 2 spec Metal proving performance on macOS.md`
has SHA-256 `966e6bbfd2cbef4912c5cd18903e776b9ffc67c50f612ac2f71805d53247359d`.
It recalibrates WP0.5's 2–3 s batching closure while retaining its measured
results, assigns the remaining transform host gap to WP3's wall-time gate, and
keeps WP2 segment pipelining next. WP2 is closed below on the existing Phase 2
branches.

## WP2 checkpoint — 2026-11-05

Engine `6ebdadd840257b4c8b59171f6e12f063b496b1a7` commits the evalfast
phase command buffer without waiting; engine
`a80fcb3c0d912f0ca82befe0fbcbff18e9f35eaa` overlaps the next segment's
CPU witness and accumulation with the previous GPU-owned buffer set, logging
buffer-set handoffs and completion. `RISC0_SEGMENT_PIPELINE=0` restores the
synchronous route for bisection. No kernel, proof format, or 32 GiB ceiling
change was needed.

Po2-14/18/20 real-witness CPU differentials and the unchanged external
verifier passed, including all three tamper rejections. Targeted cancellation
occurred at `cpu_begin set=12 gpu_owned_set=Some(11)` and left no worker group
or helper. The 20-request lifecycle passed with 21 verified proofs, expected
cancel/timeout failures, recovery, shutdown, normal pressure, and a 15.50%
decrease in idle footprint. A first lifecycle attempt retained in evidence
failed only its harness assertion: the 20-second watchdog fired during
recursion before the helper had started. The 35-second rerun reached the helper
and passed. The CPU-only worker and its five tests passed; Colima compiled the
recursion Metal, RV32IM prove, and zkVM Metal-recursion Linux paths.

Against the sealed WP1 worker, the fixed five-pair campaign passed both 10M
gates: arithmetic 80.419 → 74.391 s (6.029 s saved), hashing
81.463 → 75.413 s (6.050 s saved). All 24 proofs and 72 tamper rejections
passed. The campaign used an 8 GiB reserve on both arms with Brave, Codex,
Claude, and Colima present; thermal snapshots changed from nominal to fair.
One excluded arithmetic warmup waited 60.95 s for admission, while all
measured proofs had zero wait. The maximum paired WP2 guard peak was
22.014 GiB, below the existing 24 GiB initial resident budget and 32 GiB
ceiling. One 46M stretch proof verified in 284.415 s with 46 handoffs and
normal pressure. WP2 is closed and WP3 is next. See
`evidence/phase2-wp2-{paired,validation}.json` and
`evidence/phase2-wp2-paired.csv`.

## Revised source brief — 2026-11-04

The re-exported `Phase 2 spec Metal proving performance on macOS.md` has
SHA-256 `299ebd441aa2e1c0c70f7587a88b8cc32154d0835a0eaea0d807adef11028597`.
It adds WP0.5 command batching before WP2, makes the 20-request idle footprint
criterion one-sided (at most 5% growth), and amends the WP3 mid-point decision.
The WP1 final lifecycle's 10.60% decrease passes the revised memory rule;
WP1 is closed at 78.688 s arithmetic and 80.779 s hashing paired medians.
WP0.5 is closed below; WP2 is next.

Engine checkpoint `6b3ec9539fb3a4e5c267c2a4f8f81d6d90ac577d`
adds command-buffer batching for NTT, shift/LDE, Merkle, and GPU-only prover
stages, plus per-buffer counters. The sealed WP1 baseline binary and provenance live in
`target/macos/phase2/wp1-baseline/` (manifest SHA-256
`4fb202a4b4578b49763c90dbe89ee7a4edf45b7a8886d02377f968ee7b6882a2`).
The 20-test Metal primitive suite, recursion offset differential, and
CPU-only feature build passed before candidate timing.

Three bounded batching iterations have verified complete po2-14, po2-18 and
po2-20 proofs with exact real-witness CPU differentials and the unchanged
external verifier. The final GPU profile cuts 10M command buffers from
1,873 to 143 for transforms, 1,163 to 61 for Merkle, and 5,539 to 540 for
recursion. Its host dispatch overhead remains 1.809/1.756 s for transforms
and 0.703/0.715 s for recursion (arithmetic/hash), above the 0.3 s gate.
The two earlier profiles and their raw runs are retained as iteration evidence.
The po2-14/18/20 real-witness differentials, external verification and tamper
checks, CPU-only build, Linux feature-path check, and 20-request lifecycle
passed. The initial lifecycle's 10-second helper watchdog captured a partial
sidecar and failed; the recorded 20-second rerun passed all controls with
21 verified proofs and a 14.51% drop in idle footprint. The controlled
five-pair campaign saved 2.049 s on arithmetic (77.758 → 75.709 s) and
3.023 s on hashing (79.801 → 76.778 s), with all 24 proofs verified and
72 tamper rejections. Arithmetic misses the required 3 s saving; transform
and recursion host overhead also miss the 0.3 s target. WP0.5 is closed as
gate-failed after three bounded iterations, retaining the best correct
variant on the Phase 2 branch. The 2026-11-05 source brief subsequently
recalibrated the WP0.5 gate to the measured 2–3 s range and records this
variant as the closed default; the original 3 s and 0.3 s misses remain in
the evidence. WP2 is in progress. See
`evidence/phase2-wp05-{gpu-profile,validation,paired}.json`.

## WP1 paired checkpoint — 2026-11-04

The five-pair campaign against the sealed WP0 archive passed both timing
gates with Brave closed and the default 16 GiB reserve: arithmetic complete
median 118.554 → 78.688 s (39.867 s saved), hashing complete median
119.566 → 80.779 s (38.787 s saved). Evalfast median split-kernel GPU time
per segment was 1.692 s and 1.633 s. All 24 paired-campaign proofs verified,
all 72 tamper checks rejected, and admission wait was zero. The hashing WP0
median is now re-baselined under the same conditions; the prior 130.6 s
Brave-open, 12 GiB result is historical. See
`evidence/phase2-wp1-paired.{json,csv}`.

Engine `5acb4b8721b54ba2621d89f5f8d677cd5eca29d2` now selects evalfast
by default; `RISC0_RV32IM_TAIL_SPLIT=1` selects the tail-split/256 fallback.
Both routes passed a rebuilt-worker po2-14 real-witness CPU differential and
external verification. The final build's 20-request lifecycle also passed
functionally, with 21 verified proofs and 63 tamper rejections. Its idle
footprint fell 10.60% from request 1 to request 20, which passes the revised
one-sided memory condition. The later settled range was 3.68% and pressure
stayed normal. WP1 is closed; see
`evidence/phase2-wp1-default.json`.

## WP1 reopened — 2026-11-04

The owner reset WP1's iteration budget. The explicit scope is to port the
in-tree evalfast pass pipeline's output to MSL, beginning with its main/LogUp
phase split and then the lazy-reduction representation across the phase
boundary. The committed tail-split/256 worker remains the fallback until a new
shader passes the synthetic CPU oracle and real-witness differentials. The
prior bounded-trial gate miss remains a historical measurement, not a closure
of the reopened package.

The requested one-hour diagnosis finished within the hour: a diagnostic shader
returns the main-chain value at the same `rv32im_v2_3` `x1102` boundary used by
`accfirst_cuda.py`, omitting the LogUp continuation and the calls to v2_2..0.
Five alternating, counterbalanced po2-20 timing pairs at 256 threads measured
median repeat-command GPU time of 4.969 s for the unchanged fallback and
4.470 s for main-only, a 1.112× ratio (0.499 s saved). Each pair was
1.070–1.115×. The diagnostic does not check a CPU oracle and cannot produce a
proof. This is a percent-scale result, so it does not confirm the proposed
multiples-scale live-state diagnosis. See
`evidence/phase2-wp1-logup-probe.{json,csv}`.

Engine `d194533fa5138a8d9a352c977ae622d59cca4d41` now regenerates the
evalfast pass output through `remat_lu.py` during the Metal build and translates
its main/LogUp phase split to three MSL kernels. Set
`RISC0_RV32IM_EVALFAST=1` to select it; the existing tail-split/256 evaluator
remains the default fallback. The isolated po2-20 CPU differential passed with
1.694 s repeat GPU time at 256 threads and 1.741 s at 512 threads. Complete
po2-14, po2-18 and po2-20 proofs passed real-witness CPU differentials and the
external verifier. In 10M diagnostics, the three-kernel constraint stage took 16.899 s
for arithmetic and 16.948 s for hashing, saving 30.914 s and 34.111 s against
the prior tail-split/256 diagnostics. The same phase split without `EF_WIDE`
took 4.766 s per repeat po2-20 dispatch. The 20-request lifecycle passed with
21 verified proofs including recovery, 63 tamper rejections, cancellation,
helper timeout, restart, and shutdown. Nine workload-limit controls passed.
Pressure stayed normal. Idle footprint fell 12.39% from the first proof, then
varied 0.25% after settling. A separate po2-14 proof passed with the default
tail-split/256 fallback and CPU differential.
See `evidence/phase2-wp1-evalfast.json` for source hashes and verified run paths.
This first MSL target stops after `remat_lu.py`; CUDA's `mksm2.py` shared-memory
placement and `mksub.py` chain tails remain follow-on port work.

Original source brief: `Phase 2 spec Metal proving performance on macOS.md`, dated
2026-11-04, SHA-256
`22c73353915de7154577858ab4556d6d52fc6af3f463b3e6b2009f3ec5c707b7`.
This page records implementation status and measured checkpoints. The source
brief remains the detailed technical and acceptance specification.

## Starting point

- Miner: `9bc7466eaf6a4b48d8655d39f69cc89fa40f0298` on
  `codex/hemi-macos-metal-phase2`.
- Engine: `dcbe9f4b9140a48d4792ffcd3a3eba19897be175` on
  `codex/hemi-macos-metal-phase2`.
- Both starting commits match the published Phase 1 fork branches. The brief's
  earlier request to commit an uncommitted tree is already satisfied. New
  Phase 2 branches follow the owner's request for this task.
- The pinned external verifier SHA-256 is
  `2bcdcb7f50e2303545898962d23bdc6cba9512038383a93c975f95b89cf8225c`.

## Gates and status

| Package | Required gate | Status |
| --- | --- | --- |
| WP0 baseline and GPU timing | Sealed archive; five warm proofs per 10M fixture, one 46M proof; per-kernel GPU and pipeline statistics | Baseline, profiles, CPU-only build, limits, and 20-request lifecycle measured; transform GPU-only wall reconciliation misses 10%; Linux cross-target compile unavailable locally |
| WP1 RV32IM evaluator | At most 2.0 s per po2-20 segment, at least 25 s saved per 10M proof, exact CPU differential | Closed under the revised one-sided memory gate; five paired proofs per fixture pass timing and correctness; evalfast is default with tail-split override. |
| WP0.5 command batching | Revised 2026-11-05 gate: about 2–3 s saved; command counts and correctness/lifecycle gates | Closed with batching default after three iterations. Arithmetic saves 2.049 s, hashing saves 3.023 s; the former 3 s and 0.3 s targets missed, and the remaining transform gap moves to WP3. |
| WP2 segment pipeline | At least 6 s saved per 10M proof, 20-request stable idle footprint, cancellation clean | Closed, passed: 6.029/6.050 s paired savings; 15.50% idle decrease; overlap cancellation and CPU differential passed. |
| WP3 transforms | At most 0.8 s transform wall time per po2-20 segment, at least 30% of the approximately 600 GB/s bandwidth ceiling, exact primitive tests and unchanged Merkle outputs | Closed, stage and paired-saving gates passed: 0.636 s isolated transform wall, 327 GB/s modeled requested-buffer bandwidth, 11.095/11.025 s paired savings. Midpoint 60 s line missed. |
| WP2b wider overlap | At least 4 s saved at 10M against WP3, lifecycle and cancellation green | Closed after one bounded iteration; gate missed (−1.028/+0.129 s). Queue experiment reverted; WP3 worker retained. |
| WP5 po2 21 assessment | Faster on both 10M fixtures and 46M within the 32 GiB ceiling | Closed; five-pair gate missed: +0.978/−3.016/+6.864 s savings. Po2-21 pipeline exceeded ceiling on resident reuse; po2-20 pipeline remains default. Lifecycle and build checks passed. |
| WP4 recursion evaluator | At most 7 s lift/join at 10M, exact differential | Closed: 5.609/5.489 s recursion medians, 19/19 CPU differentials on both 10M witnesses, 36 paired proofs and 21-proof lifecycle passed; split plus lazy REDC is default. |
| WP1b remaining evalfast passes | Evaluator at most 1.2 s per segment and at least 3 s saved at 10M | Closed: 1.043/1.001 s evaluator GPU medians, 6.846/7.022 s complete savings, exact differentials and lifecycle passed. |
| WP8-lite native wrap overlap | At least 1.5 s saved at 10M; cancellation during identity and wrap leaves no helper; lifecycle green | Closed, timing gate missed: 0.018/0.034 s saved at 10M and 0.988 s at 46M; 36 paired proofs, 21 lifecycle proofs, cancellation and platform checks passed. Best correct variant retained. |
| WP6 pipeline cache | Warm process first dispatch at most 5 s, stale archive rebuilds | Closed on a miss; re-scoped to WP6b. Archive PR remains draft and unmerged. |
| WP7 admission | No refusal under specified desktop load with at least 40 GiB truly free; pressure refusal still works | Passed and merged after held-memory proof, guard-floor reconciliation and pressure-level refusal text. |
| WP6b startup | Warm-driver spawn → handshake at most 1.0 s; first request → first dispatch at most 5 s after build-time warm-up | Closed, passed: 0.107 s median handshake and 0.057 s first dispatch; correctness passed. Fresh-user cold dispatch took 25.129 s in one reading. |
| WP8 identity_p254 on Metal | Exact differential and verified identity receipts; identity ≤4 s on both 10M fixtures | Closed: exact parity, complete po2-14/18/20 differentials, 21-proof lifecycle, 36 paired proofs, controlled identity medians 2.724/2.717 s, and three offline Linux feature paths passed. |

The mid-point decision after WP3 targets both 10M warm medians at most 60 s.
A near miss within a few seconds is the owner's call; the revised order is
WP2b wider overlap, then WP5 with the profile. A large miss above roughly
70 s stops for a re-plan. The final
pass lines are at most 45 s for both 10M fixtures and 180 s for
46M; minimum acceptance is 55 s and 220 s respectively. Every complete proof
must pass the unchanged verifier and the three tamper rejections. Campaigns use
one excluded warmup per arm, five measured proofs, and retain failures.

## Frozen conditions

The pinned circuit, tap set, control IDs, proving and verification keys, 256-byte
seal, original verifier, dependency versions, and on-wire protocol remain fixed.
Metal dispatch must fail rather than silently fall back to CPU. CPU access to a
shared buffer requires completion of every command that can write it. The
worker/helper ceiling remains 32 GiB until a measured peak and owner approval
justify a change. Apple Silicon Metal features stay opt-in; CPU-only and other
platform feature paths must keep compiling. No mining, network jobs, or
transactions are part of Phase 2.

Each evaluator change requires build-time body checks, the synthetic Metal
prototype suite, and real-witness CPU differentials at po2 14, 18, and 20
before timing. NTT, hashing, or FRI changes require the primitive suite and a
full verified proof. Each checkpoint also runs the 20-request lifecycle,
limit controls, and CPU-only and Linux feature checks. The source brief gives
the exact per-package performance gates and bounded iteration rules.

Checkpoint order is WP0, WP1, WP0.5, WP2, WP3, the 60-second mid-point decision,
WP2b, WP5, WP4, WP6/WP7, and optional WP8. Changing the default po2, raising the
32 GiB ceiling, or starting WP8 requires owner approval. Engine commits precede
miner commits that cite the engine SHA. Only personal fork Phase 2 branches are
publication destinations; the three open upstream PR branches are untouched.

## WP0 record

The first Phase 2 worker was rebuilt with the existing pinned dependencies and
local recursion artifact. Its sealed binary, build inputs, Cargo lock, metadata,
verifier, and helper manifest are archived at
`target/macos/phase2/baseline/`. The archive manifest records file hashes and
both starting commits. Five warm arithmetic and hashing proofs and one 46M
stretch are complete; see `BENCHMARKS.md` and
`evidence/phase2-wp0-baseline.{json,csv}`. GPU timing instrumentation is
committed in engine `09c2f4d2836cbcd88cd29e65b6a6bdd8db262416`; two
verified diagnostic profiles are in `evidence/phase2-wp0-gpu-profile.{json,csv}`.
The 10% GPU-only reconciliation target is missed by the transform stage because
host dispatch consumes about 1.9 s across 1,873 commands. The profile separates
that cost from GPU execution. Native and CPU-only builds, the po2-14 CPU
differential, nine limit controls, and the 20-request lifecycle passed; see
`evidence/phase2-wp0-validation.json`. The measured first-to-last idle footprint
drift was 4.49%. Linux cross-target compilation remains unrun because the local
pinned toolchain has only the Apple Silicon target. WP1 is the next package.

The arithmetic campaign used the unchanged 16 GiB host reserve. The first
hashing campaign was refused by the host-memory admission gate before any proof
dispatched, with about 40 GiB conservatively estimated available. Its raw
failure remains under `target/macos/phase2/baseline/hash-10m.log`. A new
hashing and stretch campaign uses the previously documented 12 GiB local trial
override; the default worker policy is unchanged. Campaign settings are
recorded separately in the evidence.

## WP1 bounded iteration

Engine `afd4342f90160c60829818dca953bcfe952a5639` adds a generated
function-tail split to all 20 RV32IM chain functions and selects 256 threads
per group. The pass reissues only literal field constants and immutable trace
loads in each tail; the original CPU/CUDA normalized body check still runs
before the transformation. The isolated Metal prototype matched the CPU oracle
at po2 4, 8, 14, 18, and 20, including a repeated dispatch. Complete proofs
at po2 14, 18, and 20 passed real-witness CPU differentials and the unchanged
external verifier. The worker SHA-256 is
`9b0f07321888abf9292c466fe4d3dee93d499de3dca8b03cec491020d66bc2c1`.

The second iteration retargeted the in-tree fast Fp and extension-field
reduction forms as opt-in RV32IM-only shader variants. Both were exact in the
synthetic matrix but slower at po2 20, so production leaves them disabled. The
third iteration swept 32/64/128/256 threads on the split shader; 256 was
fastest. One diagnostic 10M proof per fixture measured constraint wall time
at 47.813 s arithmetic and 51.059 s hashing, or 4.78 and 5.11 s per segment.
The ≤2.0 s gate is missed, so no five-pair ≥25 s saving claim is made. The
main/LogUp phase split from the evalfast pipeline, lazy Fp values across a
scratch buffer, and the resulting larger occupancy target remain unported.
See `BENCHMARKS.md` and `evidence/phase2-wp1-iteration.json` for the bounded
trial and validation record.

The lifecycle passed 20 steady proofs and one recovery proof, each with three
tamper rejections. First-to-last steady idle worker footprint changed by
−0.42%; pressure stayed normal. Cancellation, worker timeout, restart, and
shutdown controls passed, as did nine workload-limit rejections. The helper
timeout control was not exercised in this run. The checkpoint has no new crates
or version bumps. Linux cross-target compilation remains unavailable locally.

## Fold-only cleanup

A dedicated follow-up engine commit,
`fca0c099582f15729f98af0743f45bc56c217705`, removes the old fold-only
Metal HAL, CPU fold adapter, hybrid feature chain and local prover constructor.
The miner's isolated hybrid probe manifest and launcher are removed. The
shared verifier source and its provenance script remain unchanged to preserve
the pinned verifier binary. The active resident Metal worker was rebuilt and
resealed at the cleanup engine commit; its SHA-256 is
`c5f369bb7f76d6bdb61823149997e850bbb47299981be58cde17ae7aff31b7f5`.
This binary differs from the preceding WP1 measurement binary, so its timing
gate is not reinterpreted. A fresh po2-20 CPU differential and verified proof
passed. The 20-request lifecycle plus recovery proof passed with 63 tamper
rejections, −0.68% idle footprint drift and normal sampled pressure.
Cancellation, worker timeout, restart and shutdown controls passed. See
`evidence/phase2-fold-cleanup.json` for the validation record.
