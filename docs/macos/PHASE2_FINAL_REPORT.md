# Phase 2 final report: Metal proving on macOS

2026-11-06, updated 2026-11-08 · Dimitry Burukhin

Phase 2 took the resident RV32IM Metal worker on the Apple M5 Max from
117 s to 40.4 s on the fixed 10M-cycle arithmetic fixture and from 485 s
to 150.4 s on the 46M stretch. WP8 moved
identity_p254's Poseidon254 Merkle hashing onto Metal and saved about 10 s
in a paired campaign. The circuit, constants, Groth16 assets and unchanged
pinned verifier are the same; Metal and CPU hash outputs were checked for
exact parity. The published branches also carry the upstream security merge.

## Final readings

The final worker has binary SHA-256 `9b2532dd859292c53545f14324b5ef264ce2d6fbc4e686863e276f45078e0a55`
and engine commit `bcdca76fc8e83d0a42b5fecbda5f048e01cd2bce`.
The controlled 10M reading on 2026-11-08 used a browser-closed 900.09 s
idle gap, default 8 GiB reserve, nominal thermal state at the start, po2 20
with segment pipelining, 18 Rayon and 18 Go threads, one excluded warmup
and five measured proofs per fixture. The separate 46M reading used the
same settings, a 900.09 s idle gap and nominal thermal state at its start.
Across both readings, all 18 complete proofs passed the unchanged external
verifier and all 54 tamper checks rejected. All three minimum and desirable
latency lines are met.

| Fixture | WP8 absolute median (range) | Pre-WP8 absolute median | Minimum line | Desirable line | Phase 1 end | Phase 2 start |
| --- | --- | --- | --- | --- | --- | --- |
| Arithmetic 10M (10,003,116 guest cycles) | **40.418 s** (40.412–41.407) | 49.5 s (49.5–51.5) | 55 s, met | 45 s, met | 117.2 s | 119.6 s |
| Hashing 10M (10,003,440 guest cycles) | **40.405 s** (39.411–40.417) | 50.3 s (49.2–52.3) | 55 s, met | 45 s, met | 120.8 s | 119.6 s |
| Arithmetic 46M | **150.448 s** (149.460–151.488) | 159.6 s (158.4–161.6) | 220 s, met | 180 s, met | 484.7 s | 501 s |

The paired WP8 campaign used both workers resident, alternating order, one
excluded warmup per arm and five measured pairs per fixture. Complete median
latency fell 49.516 → 39.404 s arithmetic, 49.496 → 39.419 s hashing and
158.565 → 149.425 s at 46M: savings of 10.113, 10.077 and 9.141 s. All 36
proofs verified with 108 tamper rejections and peaks below the 32 GiB ceiling.
The paired campaign isolates WP8's code effect; absolute readings can move
by seconds between days. The earlier upstream merge likewise had no material
paired cost (+0.007/+0.001 s at 10M and +1.0 s at 46M), despite a post-build
absolute reading that triggered a temporary stop. The 15-minute idle rule
and paired comparisons address that drift. The sealed WP0 arithmetic reading
was 119.6 s; its re-run as WP1's baseline arm was 118.6 s, used below.
Per-proof timings, resources and verifier outcomes are in the
[WP8 paired evidence](evidence/phase2-wp8-paired.json) and
[controlled 10M evidence](evidence/phase2-wp8-controlled.json), with the
separate [controlled 46M evidence](evidence/phase2-wp8-final-46m-controlled.json).
The 46M execution-plus-segment, recursion and identity-plus-wrap medians
were 116.295, 25.512 and 7.452 s. Two 46M preflights stopped without a
proof because Brave, then Safari, were open; both raw failures are retained
in the 46M evidence. The successful reading restarted the full idle interval.

## Results by package

Each package was measured as a paired five-proof campaign against the immediately preceding sealed worker (after the WP2 correction), so the savings below are attributable to that package. Running totals are the arithmetic-10M median of the candidate arm in its own campaign, which drift a few seconds with background load; the controlled readings are the authoritative absolute numbers.

| Package | Engine commit(s) | What changed | Measured effect | 10M after |
| --- | --- | --- | --- | --- |
| WP0 | `09c2f4d28` | Sealed baseline, per-kernel GPU timing in the profile | Attribution of GPU vs host time per stage | 119.6 s |
| WP1 | `d194533fa`, `5acb4b872` | Evalfast phase split ported to MSL (three kernels, `EF_WIDE`), made default | Evaluator 5.65 → 1.69 s/segment; −39.9 / −38.8 s | 78.7 s |
| WP0.5 | `6b3ec9539` | One command buffer per stage | −2.0 / −3.0 s; recursion host overhead 1.9 → 0.7 s; transform gap unchanged | 75.7 s |
| WP2 | `6ebdadd84`, `a80fcb3c0` | Next segment's CPU witgen/accum under the prior segment's eval | ~−8 s by serial-vs-pipelined screens (6.0 s in its campaign incl. batching) | 74.4 s |
| WP3 | `7143255ac`, `8520c7377` | Fused iNTT + zk-shift + LDE, resident twiddles, radix-4 tiles, column-parallel | Transforms 1.78 → 0.64 s/segment wall; −11.1 / −11.0 s; recursion 10 → 8 s | 61.6 s |
| WP2b | `a9120a42e` (reverted `bc5dfd6eb`) | Second queue for next segment's commit | −1.0 / +0.1 s; segment stage is GPU-bound | — |
| WP5 | `748e7a202` | po2 21 enabled; assessed with and without pipelining | po2 21 + pipelining needs ~36 GiB vs the 32 GiB ceiling; serial po2 21 slower on hashing; not adopted, kept as profile | — |
| WP4 | `47bbd7f5a`, `bca7044c5` | Recursion gated-sum evaluator in six ordered MSL parts + lazy REDC | Recursion 7.7 → 5.6 s; −2.0 s at 10M, −10.1 s at 46M | 55.6 s |
| WP1b | `7222459e3` | `mksm2.py` hot slab (32 hottest words in threadgroup memory), `mksub.py` chain tails | Evaluator 1.70 → 1.04 s/segment; −6.8 / −7.0 s; −23 s at 46M | 50.5 s |
| WP8-lite | `cd018ee72`, `6521f87c2` | gnark child pre-started under identity, witness streamed over stdin | identity + wrap −0.5 s, complete ~0; kept | 49.5 s |
| WP7 | miner `ed649c6`…`ea8cd11` (engine unchanged) | Admission on kernel pressure plus measured owned footprint; VM estimate kept as a floor (16 GiB for a fresh worker instead of 40); guard pressure-first; default reserve 8 GiB | No latency effect. Admitted and completed with a sibling holding 64 GiB (20 GiB estimated); refuses in 0.5 ms under real warning pressure and recovers | — |
| WP6 | `11025fe0e` (closed fork PR, unmerged) | `MTLBinaryArchive` pipeline cache keyed by shader hash, device and OS build | −0.16 s with a warm driver cache; gate missed | — |
| WP6b | `fc7af4317`, `7816a0002` | Groth16 bundle verification off the start path; build-time driver-cache warm-up | Spawn → handshake 4.62 → 0.11 s; first-ever proof on a fresh account 25 s to first dispatch | — |
| Upstream merge | `881513e02` (engine), miner `d359e01` | hemilabs `release-3.0` @ `54921e770` and `main` @ `af44acc` folded in: execution refusals, deterministic `sys_rand`, security hardening, Intel AOT | Paired cost +0.007 / +0.001 s at 10M, +1.0 s at 46M | 49.5 s |
| WP8 | engine `bcdca76fc`, miner `a4ee58e` | Poseidon254 identity Merkle hashing on Metal with eight 32-bit Montgomery limbs | Paired complete savings 10.113 / 10.077 s at 10M, 9.141 s at 46M; controlled identity wall time 2.724 / 2.717 s | 39.4 s paired |
| Final | published worker `9b2532dd…` | Controlled absolute readings, 2026-11-08 | All three desirable lines met | **40.418 s** |

The evaluator alone went from 5.65 s to 1.04 s per po2-20 segment across WP1 and WP1b, removing about 46 s over ten segments. WP7 and WP6b changed admission and startup behavior; their gates were memory pressure and handshake time. WP8 removed roughly ten seconds from identity plus wrap in the paired campaign.

## Where the time goes

Arithmetic 10M fixture, medians of five measured proofs, stage timers from
the worker's own instrumentation. Start: the phase2-wp1 baseline arm of the
sealed WP0 worker. Final: [WP8 controlled rows](evidence/phase2-wp8-controlled.csv).

| Stage | Phase-2 start (118.6 s) | Pre-WP8 (49.5 s) | WP8 controlled (40.418 s) |
| --- | ---: | ---: | ---: |
| Segment stage (witgen + STARK) | 89.1 s | 26.2 s | 26.406 s |
| Recursion (lift and join) | 11.3 s | 5.5 s | 5.590 s |
| identity_p254 + Groth16 wrap | 17.4 s | 17.5 s | 7.638 s |
| Residual (IPC, verification; derived from rounded stage medians) | 0.8 s | 0.3 s | 0.784 s |

The old 17.5 s identity-plus-wrap block was 35% of the pre-WP8 proof.
WP8 reduced it to 7.6 s in the controlled absolute reading, and the
identity_p254 wall timer alone to 2.724 s. The stage medians are computed
independently; the residual is an approximate difference, not a separately
timed stage.

Phase 2 took the segment stage from 89 s to about 26 s and recursion from
11 s to about 5.6 s. In the pre-WP8 segment stage, attribution was roughly
evaluator 10 s, transforms 6 s, CPU accumulation 6–7 s and Merkle 4 s,
overlapping under pipelining. The identity profile found CPU Poseidon254
hashing dominated the old identity stage; WP8 moved that work to Metal.

## Memory, cold start and machine floor

Peak owned worker-plus-helper footprint fell during the phase from 22.5 GiB
(WP3) to 18.8–19.3 GiB in the pre-WP8 final readings, because WP1b's
hot-slab evaluator spills far less private memory. WP8's controlled proofs
peaked below 18.5 GiB. The 32 GiB owned-group ceiling and 24 GiB initial
resident budget are unchanged; the one configuration that needed more
(po2 21 with pipelining, 32.8–35.3 GiB) was not adopted. WP7 changed
admission: the gate refuses unless kernel memory pressure is normal, the
conservative VM estimate covers the reserve plus at most 8 GiB of projected
growth, and the in-proof guard follows pressure and the ceiling. The default
reserve is 8 GiB. With a sibling process holding 64 GiB, a proof was
admitted and completed; under warning pressure, the gate refused before a
worker request and recovered when pressure returned to normal. Idle
footprint after 20 consecutive requests met the one-sided ≤5% growth rule.

Cold start: WP6's `MTLBinaryArchive` pipeline cache was built and is correct but saved 0.16 s, because macOS's own driver shader cache already covers every repeat start; its fork PR is closed and its branch retained. What every worker start actually paid was 4.6 s of SHA-256 over the 2.8 GB Groth16 bundle before the handshake. WP6b moved that onto a background thread joined before any helper use — with size, mtime, inode and device checks, and a corrupted bundle still rejected before a helper spawns — taking spawn → handshake to 0.11 s, and `build-worker.py` now runs one po2-14 proof after every build to warm the driver cache. The one true cold measurement, on a freshly created macOS account, was 25 s from first request to first GPU dispatch and 62 s for that first po2-14 proof: paid once per worker build per machine, and absorbed by the build-time warm-up.

The configuration is intended for a 64 GiB-class Mac or larger; every measurement in this phase was on a 128 GiB M5 Max (18 CPU / 40 GPU cores, macOS 26.4). No cross-machine result exists.

## What missed and why

| Package | Gate | Result | Why |
| --- | --- | --- | --- |
| WP0.5 batching | ≥ 3 s saved, host overhead ≤ 0.3 s/stage | 2.0 / 3.0 s; transform overhead stayed 1.8 s | The transform "host overhead" was inter-dispatch idle from per-column kernels, not commit cost; only WP3's column-batched kernels removed it |
| WP2 pipelining | ≥ 6 s | 6.0 s against WP1, ~3–4 s net in that campaign | Paired against WP1 instead of WP0.5 (spec wording); later serial-vs-pipelined screens measured its true value at ~8 s |
| WP2b wider overlap | ≥ 4 s | −1.0 / +0.1 s, reverted | The only exposed CPU phase (accumulation) depends on the same segment's DATA commit; pulling the next commit forward puts GPU work on a GPU already busy ~3.4 s per ~1 s of CPU. The segment stage is GPU-bound |
| WP5 po2 21 | faster on 10M and 46M within the ceiling | serial po2 21: −1.0 / +3.0 / −6.8 s | po2 21 with pipelining exceeded the 32 GiB ceiling; the owner declined a 40 GiB large-memory profile |
| WP8-lite wrap overlap | ≥ 1.5 s | identity + wrap −0.5 s, complete ~0 | The native path already had an in-process witness and a raw-dump key load; under a second was overlappable and the pre-started child cost identity about as much CPU as it saved. The 17 s block is compute: identity_p254 ~12 s, gnark proving 3.5–4 s, witness ~1 s |
| WP6 pipeline archive | second process start ≤ 5 s to first dispatch | 8.27 s cold / 8.11 s warm; archive worth 0.16 s | The campaign cleared only the archive directory, so the driver cache stayed warm and the compile was 0.27 s in both arms; the 8 s was the bundle hash at every start plus harness steps. Re-scoped as WP6b, which removed the hash from the start path |

Every miss was closed with its best correct variant retained (or reverted when it was slower), its profile recorded, and the lesson written into the spec so it is not retried.

## Correctness and validation

The pinned circuit and tap set, control IDs (`MIN_LIFT_PO2 = 14`),
Poseidon254 constants, proving and verification keys, 256-byte Groth16 seal,
and original-pin verifier binary (`2bcdcb7f…`) did not change. WP8 added a
Metal implementation of the existing CPU Poseidon254 function; 134 field
input pairs, `hash_rows`/`hash_fold` boundaries, and the full 2^18-row by
128-column identity commitment and all Merkle levels matched the CPU exactly.
The unchanged external verifier checked every complete proof with wrong-image,
modified-journal and corrupt-seal rejection; no measured proof was retried
or excluded.

Each checkpoint ran: the build-time body check of the generated polynomial against the CPU-generated one (and the pinned CUDA generator's own `--check` for WP1b); the synthetic Metal-vs-CPU evaluator harness at po2 4/8/14/18/20 with buffer reuse, offsets and sentinels; real-witness CPU differentials on complete po2-14, po2-18 and po2-20 proofs (`RISC0_RV32IM_METAL_CHECK_CPU=1`, and `RISC0_RECURSION_METAL_CHECK_CPU=1` for WP4, 19/19 recursion checks); the Metal primitive suite on both the default and fallback kernel routes after NTT or hash changes, with Merkle outputs byte-identical on the same witness; a fallback-route proof; the 20-request lifecycle with cancellation, helper timeout, restart and shutdown, plus a recovery proof; input-limit controls; the CPU-only feature build and unit tests; and the three Linux feature paths compiled in the Colima VM. Every kernel route keeps an environment switch for bisection: `RISC0_RV32IM_TAIL_SPLIT`, `RISC0_SEGMENT_PIPELINE`, `RISC0_METAL_NTT_RADIX2`, `RISC0_RECURSION_METAL_SPLIT`.

The same ladder ran on the WP7, WP6b and upstream-merged workers on the last two days: 21-proof lifecycle and recovery suites, po2-14/18/20 segment and recursion differentials, nine input-limit controls, multi-segment pipeline cancellation, the corrupted-bundle rejection before helper spawn, the CPU-only builds and the three Linux feature paths in Colima. The post-merge regression check used the paired protocol with both exact worker binaries resident; the upstream merge raised the worker IPC protocol from 5 to 10, so a test-feature-only v5 adapter (`ZKMINER_TEST_LEGACY_PROTOCOL`, behind `cfg(feature = "testing")`) drives the sealed old worker from the new supervisor without touching production code or either binary's hash.

WP8 passed 24 Metal primitive tests, complete real-witness CPU differentials
at po2 14, 18 and 20, 21 lifecycle and recovery proofs with 63 tamper
rejections, nine input controls, pipeline cancellation and recovery, 11
CPU-only tests, and three offline Linux feature paths. Its 36 paired proofs
and 18 controlled proofs all verified with 162 tamper rejections. The
worker, source, proof and Linux hashes are in
[WP8 validation](evidence/phase2-wp8-validation.json),
[paired campaign](evidence/phase2-wp8-paired.json) and
[Linux checks](evidence/phase2-wp8-linux.json).

## Repository state

Both phase-2 branches were fast-forwarded to the validated WP8 tips and
pushed to the `dimitryB` forks on 2026-11-08 without force. The sealed
source-bound WP8 worker is `9b2532dd…`; the pre-WP8 worker `c3428c37…`
remains archived as the paired baseline. The parent repositories have not
merged these phase-2 branches; both are now proposed as PRs for review.

| Repository | Branch | Reference commit | Notes |
| --- | --- | --- | --- |
| `dimitryB/zk-miner` | `codex/hemi-macos-metal-phase2` | `a4ee58e` Close WP8 after offline Linux feature checks | Published WP8 code tip; this report commit descends from it and carries the 46M evidence |
| `dimitryB/zk-miner` | `codex/hemi-macos-metal` | `9bc7466` | Phase-1 publication branch; not yet merged with phase 2 |
| `dimitryB/risc0` | `codex/hemi-macos-metal-phase2` | `bcdca76fc` Verify Poseidon254 Merkle parity at identity size | Published WP8 engine tip on the upstream `release-3.0` merge |
| `dimitryB/risc0` | `codex/hemi-macos-metal` | `dcbe9f4b9` | Phase-1 engine branch |
| `dimitryB/risc0` | `codex/upstream-final-segment-padding-r2` and #30 head `codex/upstream-final-segment-padding` | `d354733d6` | #30 rebased onto `release-3.0`'s tip (one test-file append collision resolved), 37/37 execute tests, one verified 10M CPU proof; pushed to the PR branch and marked ready for review on 2026-11-07 |
| `dimitryB/risc0` PR #1 (closed) | `codex/hemi-macos-metal-wp6` | `11025fe0e` | WP6 archive gate missed; branch and evidence retained |
| `hemilabs/risc0` PR #30 (open, ready); #31 and #32 (closed) | `codex/upstream-final-segment-padding`, `-locked-circom`, `-native-helper-lifetime` | #30 at `d354733d6` on `54921e770` | #30 is cleanly mergeable and carries the r2 proof evidence in its description; #33's conflict note was answered. #31 and #32 only mattered alongside a Mac-backend PR and were closed unmerged on 2026-11-07 |
| [hemilabs/risc0 #35](https://github.com/hemilabs/risc0/pull/35) | `dimitryB:codex/hemi-macos-metal-phase2` → `release-3.0` | `bcdca76fc` | Open for review; final-segment padding overlaps still-open #30 and is disclosed in the PR |
| [hemilabs/zk-miner #29](https://github.com/hemilabs/zk-miner/pull/29) | `dimitryB:codex/hemi-macos-metal-phase2` → `main` | `a4b633b` at creation | Open for review; depends on engine #35; evidence files collapsed by `.gitattributes` |

Sealed checkpoints include `baseline`, `wp1-baseline`, `wp2-baseline`,
`wp3-baseline`, `wp4-baseline`, `wp5-baseline`, `wp1b-baseline`,
`wp8lite-checkpoint` (pre-merge `625589c3…`), `upstream-merge-checkpoint`,
`post-diagnosis-final-checkpoint` (pre-WP8 `c3428c37…`) and the source-bound
WP8 worker (`9b2532dd…`, manifest `18418871…`). The original-pin verifier
binary is unchanged (`2bcdcb7f…`). The miner's root `Cargo.lock` retains
upstream Git-source pins. The retired fold-only path was deleted early in
the phase (engine `fca0c0995`, miner `7d2dae1`).

## Reproduction

From `/Users/dbur/dev/zk-miner` on the M5 Max, with the project-local
toolchain (Rust 1.93.0, guest r0.1.88.0, protoc 36.2 under
`target/macos/bootstrap`), engine `bcdca76fc` in `/Users/dbur/dev/risc0`,
the native Groth16 bundle under `target/macos/native-wrap/assets`, and
the Colima profile for offline Linux feature checks:

```sh
export HEMI_MINER_DIR=/Users/dbur/dev/zk-miner
source scripts/macos/env.sh
export PROTOC=$HEMI_MINER_DIR/target/macos/bootstrap/protoc-36.2/bin/protoc
export CARGO_NET_OFFLINE=true
ENGINE_DIR=/Users/dbur/dev/risc0
ENGINE_REV=bcdca76fc8e83d0a42b5fecbda5f048e01cd2bce
ACCEPTANCE_BUILD=target/macos/native-wrap/worker-runs/94695d6260bd493e8ae2100fa97618b9/acceptance-build.json

# local engine override + worker build with tests; the build ends with one po2-14 proof that warms the driver cache
python3 scripts/macos/local-engine.py "$ENGINE_DIR" target/macos/local-engine.toml --revision "$ENGINE_REV"
python3 scripts/macos/build-worker.py --mode native-rv32im-metal --engine "$ENGINE_DIR" --config target/macos/local-engine.toml --revision "$ENGINE_REV" --tests

# correctness ladder on the built worker
python3 scripts/macos/test-native-worker.py --engine "$ENGINE_DIR" --worker-kind native-rv32im-metal --segment-hal metal --recursion-hal metal --segment-check-cpu --recursion-check-cpu --repeat 1 --proof-only
python3 scripts/macos/test-native-worker.py --engine "$ENGINE_DIR" --worker-kind native-rv32im-metal --segment-hal metal --recursion-hal metal --limit-controls --repeat 1 --proof-only
python3 scripts/macos/test-native-worker.py --engine "$ENGINE_DIR" --worker-kind native-rv32im-metal --segment-hal metal --recursion-hal metal --kernel-pressure --repeat 1 --proof-only

# controlled readings on the sealed WP8 worker; each driver waits out the
# browser-closed 15-minute idle gap and checks thermal state at its start
date -u '+%Y-%m-%dT%H:%M:%S+00:00' > /tmp/phase2-idle-since.txt
python3 scripts/macos/phase2-run-wp8-reading.py --idle-since /tmp/phase2-idle-since.txt --acceptance-build "$ACCEPTANCE_BUILD"
python3 scripts/macos/phase2-collect-wp8-reading.py target/macos/phase2/wp8-reading/<run-id>
date -u '+%Y-%m-%dT%H:%M:%S+00:00' > /tmp/phase2-idle-since.txt
python3 scripts/macos/phase2-run-wp8-final-46m.py --idle-since /tmp/phase2-idle-since.txt --acceptance-build "$ACCEPTANCE_BUILD"
python3 scripts/macos/phase2-collect-wp8-final-46m.py target/macos/phase2/wp8-final-46m-reading/<run-id>

# paired comparison against sealed pre-WP8 worker
python3 scripts/macos/phase2-run-wp8-pairs.py
python3 scripts/macos/phase2-collect-wp8-pairs.py target/macos/phase2/wp8-pairs/<run-id>
```

Runtime selectors for the validated configuration: `RISC0_SEGMENT_HAL=metal`, `RISC0_RECURSION_HAL=metal`, `ZKMINER_RISC0_WRAP=native`; po2 20, pipelining and the 8 GiB reserve (`ZKMINER_MACOS_HOST_RESERVE_GIB`, 8..64) are the defaults. Each package's paired campaign and collector are `scripts/macos/phase2-run-<wp>-pairs.py` and `phase2-collect-<wp>-pairs.py`, run against the sealed archive the script names; `phase2-host-snapshot.py` records the load, pressure and thermal state the protocol requires. Evidence JSON binds source hashes, worker and verifier SHAs, engine commit and raw run directories, so a reproduction is checked by hash rather than by eye.

## Open items and decisions

1. **Parent review** — [engine #35](https://github.com/hemilabs/risc0/pull/35) and [miner #29](https://github.com/hemilabs/zk-miner/pull/29) are open and ready for parallel review. #35 overlaps the unmerged [padding #30](https://github.com/hemilabs/risc0/pull/30); reconcile that overlap before merging #35, then integrate the engine before the miner. Both PRs reported mergeable at creation; no CI checks were reported then.
2. **Fork cleanup** — the WP7 work is already merged into Phase 2, and there is no open WP7 fork PR. The WP6 binary-archive draft PR was closed after its timing-gate miss, while its branch and evidence were retained. Folding Phase 2 back into the historical Phase 1 fork branches is unnecessary for these parent PRs.
3. **Optional local housekeeping** — the `zkmac` account used for one cold reading may be removed by its owner. The roughly one-second completion tick matters only for future subsecond gates, not the measured WP8 saving or final absolute lines.
4. **Not pursued, by decision** — a 40 GiB large-memory profile for po2 21 with pipelining, GPU witness generation and accumulation, further CPU/GPU overlap, and the WP6 archive after its missed gate.

What the phase did not measure: any machine other than the 128 GiB M5 Max, cold start on another GPU generation (the fresh-account reading is one observation on this machine), and a direct comparison against an NVIDIA card; the 5070 Ti figures remain estimates from hemilabs' published per-segment timings on other GPUs.
