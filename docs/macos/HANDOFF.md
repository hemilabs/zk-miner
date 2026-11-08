# macOS proving handoff

Final report for the phase: [PHASE2_FINAL_REPORT.md](PHASE2_FINAL_REPORT.md)
(2026-11-08, published WP8 worker `9b2532dd…`).

## Parent PRs opened — 2026-11-08

The owner chose to open both Mac backend PRs while
[risc0 #30](https://github.com/hemilabs/risc0/pull/30) awaits team review.
[Engine #35](https://github.com/hemilabs/risc0/pull/35) targets
`hemilabs/risc0:release-3.0` from the validated engine Phase 2 branch
`bcdca76fc8e83d0a42b5fecbda5f048e01cd2bce`.
[Miner #29](https://github.com/hemilabs/zk-miner/pull/29) targets
`hemilabs/zk-miner:main` from the Phase 2 miner branch; its code and
controlled-reading commit at PR creation was
`a4b633b794ec90bb3cec3dc9ca0b1c145257a8e2`.
Both PRs were open, ready for review and reported mergeable against the
current parent tips when created. No CI checks were reported then.
Engine #35 contains the same final-segment padding behavior as #30; its
description asks reviewers to resolve that overlap before merging.
Miner #29 depends on engine #35, and its root Cargo engine pin remains the
parent pin until the engine change is integrated. The parent PRs are review
destinations; no parent branch was pushed directly.

The abandoned WP6 binary-archive
[fork draft #1](https://github.com/dimitryB/risc0/pull/1) was closed after
its 0.16 s warm-cache gain missed the gate. Its branch and evidence remain.
The WP7 work is already in the Phase 2 branch, and there is no open WP7 fork
PR. Generated benchmark records and standalone tool lockfiles are marked
with `linguist-generated` so GitHub collapses them in the miner PR diff by
default; the records remain available for audit.

## WP8 Metal identity — 2026-11-07/08

Full Poseidon254 identity on Metal was implemented on isolated
`codex/hemi-macos-metal-wp8` branches. On 2026-11-08 both
`codex/hemi-macos-metal-phase2` branches were fast-forwarded to their
validated WP8 tips and pushed to the `dimitryB` forks without force:
engine `bcdca76fc8e83d0a42b5fecbda5f048e01cd2bce`, miner
`a4ee58e037240e0dd9494619981cd2926e01d4ea`.
The final source-bound worker SHA-256 is
`9b2532dd859292c53545f14324b5ef264ce2d6fbc4e686863e276f45078e0a55`.
Field, hash and identity-size Merkle parity, the 24-test Metal primitive
suite, po2-14/18/20 complete-proof CPU differentials, a 21-proof lifecycle,
input limits, pipeline cancellation and recovery, and the CPU-only build passed.
In five alternating pairs per fixture against the sealed pre-WP8 worker,
median complete times fell 49.516 → 39.404 s arithmetic, 49.496 → 39.419 s
hashing, and 158.565 → 149.425 s at 46M. All 36 proofs verified with 108
tamper rejections. See [paired evidence](evidence/phase2-wp8-paired.json),
[paired rows](evidence/phase2-wp8-paired.csv) and
[validation evidence](evidence/phase2-wp8-validation.json).

The controlled absolute identity-time gate passed after 900.09 s idle with
Brave closed, default 8 GiB reserve and thermal nominal at the start. After
one excluded warmup, five measured proofs per 10M fixture gave identity
medians **2.724 s arithmetic and 2.717 s hashing**, each below the 4 s gate;
all 12 proofs verified with 36 tamper rejections. See
[controlled evidence](evidence/phase2-wp8-controlled.json) and
[per-proof rows](evidence/phase2-wp8-controlled.csv). The first reading
preflight stopped before a proof because its prebuilt acceptance harness was
stale; the harness was rebuilt, verified by a po2-14 proof, and the idle
interval restarted. Automatic approval review initially rejected starting
Colima as a privileged action; the owner then approved it. Recursion
`prove,metal`, RV32IM `prove`, and zkVM
`prove,metal-recursion` all passed in the cached Rust container with pulls,
container networking, and Cargo network access disabled. See
[Linux evidence](evidence/phase2-wp8-linux.json). WP8 is closed and published
on the phase-2 fork branches; the parent repositories and verifier pin were
not changed.
The later controlled 46M arithmetic reading on the same worker had a
**150.448 s** complete median (149.460–151.488) from five measured proofs
after one excluded warmup, with 900.09 s idle, browser closed, default
reserve and nominal thermal at start. All six proofs verified and all 18
tamper checks rejected. Two earlier browser-open preflights stopped before
any proof and remain recorded in the
[46M evidence](evidence/phase2-wp8-final-46m-controlled.json) and
[per-proof rows](evidence/phase2-wp8-final-46m-controlled.csv).
Colima was left running because it already hosted two long-lived Postgres and
pgAdmin containers when the checks began.

## Upstream padding PR #30 — 2026-11-07

[hemilabs/risc0 #30](https://github.com/hemilabs/risc0/pull/30) now
points to the validated rebase `d354733d6` on `release-3.0`
`54921e770`. GitHub reports a clean merge and the PR is ready for
review. Its description includes the 37/37 execute tests and complete
10M CPU proof accepted by the unchanged verifier with three tamper
rejections. The [#33 note](https://github.com/hemilabs/risc0/pull/33#issuecomment-6714421285)
has the conflict resolution and proof evidence. The parent branch has
not been merged. Details and hashes are in
[PHASE2_PLAN.md](PHASE2_PLAN.md) and
[the evidence manifest](evidence/upstream-final-segment-padding-r2.json).

## Post-merge paired diagnosis — 2026-11-07

The re-exported Phase 2 spec SHA-256 is
`9a0e052f6c1e72a1a8a31d3081fe3a3604bbfe11cb9fd661e30109c21c12f6f1`.
Sealed merged worker `c3428c3717c331c452e3621736e779ae1f06311003dfd65b50f292d39877e5f9`
was paired against sealed WP8-lite worker
`625589c35f6583bfaf4510a00d6f98dceb781b004064500ce38b44b42d659be7`.
With both workers resident, alternating order, closed browser, default 8 GiB
reserve, nominal thermal at the start and 920.8 s idle after the harness
build, the paired median complete-latency gaps (merged minus WP8-lite) were
**+0.007 s arithmetic 10M, +0.001 s hashing 10M, +0.999 s arithmetic 46M**.
All 32 proofs verified with 96 tamper rejections. The 1/1/3 s lift rule is
met, so campaign B and the engine/miner bisect are not triggered. The first
GPU-submit delay was near-identical in each arm; worker startup nice/priority
were 0/31 with 18 Rayon and 18 Go threads. Thread QoS is not exposed by
macOS `ps`. Neither paired nor historical logs contained a bundle rehash or
identity-mismatch line. See [paired evidence](evidence/phase2-upstream-diagnosis-a.json),
[paired rows](evidence/phase2-upstream-diagnosis-a.csv), and
[historical log scan](evidence/phase2-upstream-diagnosis-historical-logs.json).
The stop is lifted by the paired gate. The amended absolute reading began after
920.3 s idle with nominal thermal, browser closed and the default 8 GiB reserve.
Five measured complete-proof medians after one excluded warmup were **49.532 s
arithmetic 10M, 50.274 s hashing 10M and 159.559 s arithmetic 46M**. All meet
the 55/55/220 s minimum lines; 46M meets the 180 s desirable line, while the
10M fixtures remain above 45 s. All 18 proofs and 54 tamper rejections passed;
pressure stayed normal, and peak owned footprints were 18.84/18.77/19.29 GiB.
See [controlled evidence](evidence/phase2-post-diagnosis-controlled.json) and
[per-proof rows](evidence/phase2-post-diagnosis-controlled.csv). The final
worker is sealed at `target/macos/phase2/post-diagnosis-final-checkpoint/`:
manifest SHA-256
`c9e2ea296cbbcc243665e5f48719c28b295aed15502ecb273c67b9d576288dd1`,
worker SHA-256 `c3428c3717c331c452e3621736e779ae1f06311003dfd65b50f292d39877e5f9`.
Both Phase 2 branches were published by non-force push to the `dimitryB`
forks, engine at `881513e022d98ac7c07460ba090a5f6a5657334a` and miner
diagnosis/evidence commit at `d333818483bdd0c16b45d48c2aff11e3ebcf4698`.
This handoff status update follows those pushes. No upstream or existing PR
branch was changed.

## WP6b warm gates and correctness — 2026-11-06

WP6b engine `7816a0002642bf97bbcdd82bd55ebaa22d84ad80` starts native
bundle manifest hashing during worker preflight and joins before witness or
helper use. Its `sha2/asm-aarch64` path is present in the source-bound
dependency tree; size, mtime, inode and device identities are checked before
trusting the result. A cloned bundle with a corrupted `prover` byte still
handshook, then failed the proof with the existing hash-mismatch message
before a helper spawned. The WP6 archive PR remains draft and unmerged, with
the [miss diagnosis comment](https://github.com/dimitryB/risc0/pull/1#issuecomment-6697430623).

The final worker SHA-256 is
`f65ff7a374e4471404d9bc52dab57d010e12cb5af4d0f5197053b0f8107060ab`.
With browsers closed and the default 8 GiB reserve, sealed pre-WP6b
spawn-to-handshake was 4.619 s median of three, versus 0.107 s for WP6b.
The mandatory build-time po2-14 proof took 29.164 s and verified. Its first
post-build direct proof reached a completed GPU dispatch 57.1 ms after the
request; the unchanged verifier and three tamper checks passed. The exact
final worker also passed 21 lifecycle/recovery proofs and 63 tamper checks,
po2-14/18/20 segment and recursion CPU differentials, nine limit controls,
and a macOS CPU-only build. Idle RSS rose 1.03% from request 1 to 20.
Thermal was nominal during validation and fair afterward. The Linux CPU-only
check was not repeated because both Colima profiles reported Broken.
See [WP6b evidence](evidence/phase2-wp6b-validation.json).

The newly created `zkmac` account made one true cold-driver reading on its
first login, with no cache deletion: 0.106 s spawn → handshake, 0.0007 ms
handshake → request, and 25.129 s request → first completed GPU dispatch.
The complete po2-14 proof took 62.467 s and passed the unchanged verifier
and three tamper rejections. Browser processes were closed and thermal was
nominal before and after. The raw script's optional cache-directory count
used a path one level too high; the count is excluded from the cold claim,
and the script is corrected. See [cold evidence](evidence/phase2-wp6b-cold.json).
WP6b is closed. At that checkpoint the proposed next step was the one-hour
`identity_p254` profile; the newer post-merge diagnosis above supersedes that
sequence. The profile has not started, and WP8 remains unstarted.

## WP7 admission estimator — 2026-11-06

The revised Phase 2 spec SHA-256 is
`ecd565ffba5582c00c1191d8a427cd5bb48d90440b21b8d0423735e9e7847031`.
The WP7 miner branch `codex/hemi-macos-metal-wp7` passed its three merge
conditions and is merged into the Phase 2 branch. Its Metal worker is the
unchanged WP8-lite binary
`625589c35f6583bfaf4510a00d6f98dceb781b004064500ce38b44b42d659be7`
from engine `6521f87c2`. The default host reserve changes from 16 to 8 GiB;
normal kernel pressure and measured owned footprint drive admission, with the
conservative VM estimate retained as a floor. The 8..64 GiB override range and
32 GiB worker/helper ceiling remain. The guard now continues at normal or
warning pressure while owned footprint is readable and below the ceiling;
critical or unreadable safety signals stop the worker. Its per-second minimum
VM estimate and pressure levels are exposed in resource observations.

With 64 GiB of incompressible sibling memory held, the 10M proof admitted at
20.17 GiB estimated and normal pressure, verified, and saw 8.04 GiB minimum
in guard samples, levels 1/2 and 14.84 GiB peak owned footprint. At 60 GiB
held, admission was 24.40 GiB and the proof also verified. With Brave, Zed
and default Colima running, the separate 10M proof verified with a 0.212 s
admission-wait upper bound. A real warning-pressure allocation returned a
typed refusal naming level 2 and preserving the raw VM estimate, before any
request or helper; the next proof verified. The logical reservation case
still refused and recovered. The 20-request lifecycle plus restart verified
21 proofs and 63 tamper rejections, with idle RSS down 16.25%. Po2-14/18/20
real-witness CPU differentials, nine limit controls, six macOS policy tests,
twelve ledger tests, and CPU-only builds on macOS and offline Linux passed.
See [WP7 evidence](evidence/phase2-wp7-validation.json) and [setup](SETUP.md).

Next from this WP7 checkpoint: WP6b as documented above. WP6's archive PR
remains draft and unmerged after a 0.16 s measured gain missed its gate.

## Controlled final reading — 2026-11-06

The updated Phase 2 brief SHA-256 is
`c7cd2ab3cf8f6f67fb4deeabfd9ed86c28d24aa98c0e7c1a7b578640718d475d`.
The sealed WP8-lite manifest SHA-256 is
`c8d537ec642be3edc7d3baec9763084b3d492cb8fd3af7ffdaa8c7556dc39574`.
On that unchanged checkpoint, a browser-closed run at the default 16 GiB
reserve, po2 20, 18 Rayon/Go threads and the unchanged verifier gave five
measured complete-proof medians of **48.458 s** arithmetic 10M,
**49.511 s** hashing 10M and **165.835 s** arithmetic 46M. One complete
warmup per fixture was excluded. All 18 proofs verified and all 54 tamper
checks rejected. The maximum guard footprint was 19.24 GiB with normal
pressure throughout. Thermal telemetry read nominal at the start and fair
later; Codex, Claude and Colima remained present in all host snapshots.
The minimum 55/55/220 s line is met; the desirable 45/45/180 s line is
met only for 46M. See [validated evidence](evidence/phase2-controlled-final.json),
[proof rows](evidence/phase2-controlled-final.csv) and
[reproduction notes](BENCHMARKS.md).

Next: WP6 cold start and WP7 admission, followed by the revised one-hour
identity profile. WP8 needs an owner decision after the profile.

## WP8-lite native wrap overlap — 2026-11-06

The revised brief SHA-256 is
`a7ab34ce1697757bcb73622aebe0b503d42b38e3a601942f76e90fd5744f581c`.
Engine `6521f87c2daf873c54d011a33d48fee8097db924` prestarts the
owned native gnark helper at `identity_p254` and streams its witness through
stdin; Go GC is deferred during setup. The source-bound candidate worker
SHA-256 is `625589c35f6583bfaf4510a00d6f98dceb781b004064500ce38b44b42d659be7`.
The sealed WP1b baseline manifest SHA-256 is
`7b117d05a76c9307abe3ce54752a2ddfdf0036e86b406c1d428ae578e2491950`.

The full five-pair campaign with an 8 GiB reserve, po2 20, WP2 pipelining,
18 Rayon/Go threads and the same active helper/verifier in both arms gave
complete medians of 49.497 → 49.479 s arithmetic 10M, 49.519 →
49.484 s hashing 10M, and 167.598 → 166.609 s arithmetic 46M. Identity
plus wrap fell 17.509 → 17.000 s and 17.448 → 17.023 s at 10M. All 36
proofs verified, all 108 tamper checks rejected, pressure stayed normal,
and the largest guard footprint was 19.31 GiB. The 1.5 s 10M saving gate
was missed; the correct candidate is retained as the best measured variant.
See [paired evidence](evidence/phase2-wp8lite-paired.json) and
[all rows](evidence/phase2-wp8lite-paired.csv).

The [validation record](evidence/phase2-wp8lite-validation.json) binds
22/1/1 exact CPU checks on complete po2-14/18/20 proofs, 21 verified
lifecycle/recovery proofs, 63 tamper rejections, a 17.86% idle-footprint
decrease, no helper after cancellation during identity or wrap, input
limits, five CPU-only tests and three offline Linux feature paths.
WP8-lite is closed with a timing-gate miss. Its controlled final absolute
reading is above; WP6/WP7 are next.

## WP1b evalfast hot slab and chain tails — 2026-11-06

The revised Phase 2 brief SHA-256 is
`a8627ca24baec008b140a4bb75f9ef8bb75fd67281e9a8e628c328afb6542a09`.
Engine `7222459e3` runs `mksm2.py` and `mksub.py` after the WP1 evalfast
pipeline and retargets their output to MSL. At 256 threads, 32 hot slab
words per phase occupy the full 32 KiB threadgroup budget; all other slab
words remain private. The prior tail-split evaluator is available with
`RISC0_RV32IM_TAIL_SPLIT=1`.

The source-bound WP4 worker is sealed at
`target/macos/phase2/wp4-baseline/manifest.json`. The pinned CUDA generator
check, po2-4/8/14/18/20 synthetic CPU comparisons with reuse, and complete
po2-14/18/20 real-witness CPU differentials passed. The po2-20 sweep
selected 256 threads at 0.994 s repeated evaluator GPU time, versus 1.179,
1.966 and 3.132 s at 128, 64 and 32. See
[sweep evidence](evidence/phase2-wp1b-sweep.json).

The first two five-pair fixture medians against sealed WP4 are
57.324 → 50.477 s arithmetic 10M and 57.322 → 50.299 s hashing 10M,
saving 6.846 and 7.022 s. Evaluator GPU medians are 1.043 and 1.001 s
per segment. Both package gates pass on the 10M fixtures. The 46M median
was 191.189 → 168.031 s, saving 23.158 s. All 36 campaign proofs
verified with 108 tamper rejections, normal memory pressure, and a
22.14 GiB maximum guard footprint. See
[paired evidence](evidence/phase2-wp1b-paired.json) and
[all paired rows](evidence/phase2-wp1b-paired.csv). The source-bound
[validation record](evidence/phase2-wp1b-validation.json) binds 22/22,
1/1 and 1/1 exact segment CPU checks at po2 14/18/20, the tail-split
fallback, input limits, five CPU-only unit tests and three offline Linux
feature paths. The 20-request lifecycle and recovery proof verified 21
proofs with 63 tamper rejections; idle footprint decreased 7.06%.
WP1b closed before WP8-lite. Its package-gate 10M medians were below
55 s; the controlled default-reserve final reading is recorded above.

## WP4 recursion evaluator — 2026-11-06

The revised Phase 2 brief SHA-256 is
`a8627ca24baec008b140a4bb75f9ef8bb75fd67281e9a8e628c328afb6542a09`.
Engine `47bbd7f5a` generates six ordered Metal recursion evaluator parts
from the pinned CUDA gated-sum split; `bca7044c5` applies its pinned
lazy-REDC rewrite. The parts dispatch in one command buffer per recursion
check. The old single-kernel evaluator remains
selectable with `RISC0_RECURSION_METAL_SPLIT=0`. Poseidon2 hashing is
unchanged. `RISC0_RECURSION_METAL_CHECK_CPU=1` enables an exact CPU oracle
comparison on each valid recursion witness.

The sealed WP5 po2-20 pipeline worker and WP4 candidate completed five
measured alternating pairs per fixture after one warmup per arm. Both used
po2 20, WP2 pipelining, 18 Rayon/Go threads, 8 GiB reserve, the same native
helper and unchanged external verifier. All 36 proofs verified, all 108
tamper checks rejected, memory pressure stayed normal, and the largest
guard footprint was 22.49 GiB. The recursion medians were 7.733 →
5.609 s arithmetic 10M and 7.480 → 5.489 s hashing 10M, passing the
≤7 s gate. Complete medians were 57.615 → 55.571 s arithmetic 10M,
57.570 → 55.589 s hashing 10M, and 199.888 → 189.745 s arithmetic 46M.
See [paired evidence](evidence/phase2-wp4-paired.json) and
[all paired rows](evidence/phase2-wp4-paired.csv). These are package-gate
results with an 8 GiB reserve, not controlled 16 GiB absolute-line readings.
The pre-lazy split iteration is preserved in
[split iteration evidence](evidence/phase2-wp4-split-paired.json); the
lazy rewrite reduced evaluator GPU time further and is the default.
The [WP4 validation record](evidence/phase2-wp4-validation.json) binds
19/19 exact CPU recursion checks on each complete po2-20 arithmetic and
hashing witness, the 21-proof lifecycle and 63 tamper rejections, a 9.94%
idle-footprint decrease, the verified single-kernel fallback, input-limit
controls, five CPU-only unit tests and three offline Linux feature paths.
WP4 is closed; WP1b is next. The package-gate 10M medians are near the
55 s minimum line, which still requires a controlled default-reserve reading.

## WP5 segment po2 assessment — 2026-11-05

The revised Phase 2 brief SHA-256 is
`7b67d229839eb5f9d424dc27fed31906e766ea8bcea3c9d892e323d9ebcf5df7`.
Engine `748e7a202` permits native Metal RV32IM evaluation at po2 21. The
miner accepts native po2 21 while leaving its po2-20 default in place.
The admission calibration permits po2 21 only when
`RISC0_SEGMENT_PIPELINE=0`; an explicit po2 override can select the same
optional serial profile. The production 32 GiB owned worker/helper ceiling
is unchanged.

A resident po2-21 pipeline worker verified one 10M proof but reached
35,255,359,656 bytes (32.84 GiB) on its second request and was stopped by
the guard at normal pressure. Po2-21 serial verified two resident proofs
at 19.21 and 22.94 GiB peaks. The fixed campaign then compared the sealed
WP3 po2-20 pipeline with po2-21 serial: five measured pairs on each 10M
fixture and the 46M stretch, plus two excluded warmups per fixture. All
36 proofs externally verified and all 108 tamper checks rejected. The
medians were 59.586 → 58.607 s arithmetic 10M, 58.599 → 61.616 s hashing
10M, and 213.049 → 206.186 s arithmetic 46M. Po2-21 loses on hashing,
so the default remains po2 20 with WP2 pipelining. Po2-21 serial is a
documented profile for large arithmetic work. The campaign's desktop load
and thermal observations are recorded, and reserve was 8 GiB; these are
package-gate numbers, not a new controlled absolute-line reading. See
[paired evidence](evidence/phase2-wp5-paired.json),
[all paired rows](evidence/phase2-wp5-paired.csv), and
[feasibility diagnostics](evidence/phase2-wp5-feasibility.json).
The [WP5 validation record](evidence/phase2-wp5-validation.json) binds the
21-proof lifecycle, its 17.28% idle-footprint decrease, CPU-only build,
32 protocol tests, calibration test, limit controls, three offline Linux
feature paths and the po2-20 serial screens. The corrected lifecycle
timeout assertion checks a partial in-flight sidecar; previous harness
attempts and their failures remain in the validation record. WP5 is
closed with the po2-20 pipeline default. WP4 recursion evaluation is next.

## WP2b bounded overlap iteration — 2026-11-05

The latest Phase 2 brief SHA-256 is
`f92bf25a4d8d6c94f83acca60383ff7b81fc04e0c5bd1ada20ec603df72d4454`.
The controlled WP3 midpoint retake gave 59.556 s arithmetic and 60.369 s
hashing five-proof complete medians with Brave closed, default 16 GiB
reserve and nominal initial thermal state. It passed 12 external proofs and
36 tamper checks. The owner had already chosen to proceed after the WP3
near miss.

Engine `a9120a42e` tested a second Metal queue for next-segment DATA
transforms and Merkle stages under the prior eval-check. The complete
arithmetic diagnostic verified, the 21-test Metal primitive suite passed,
and the fixed five-pair campaign against sealed WP3 verified all 24 proofs
and 72 tamper rejections. With 8 GiB reserve, 18 Rayon/Go threads, fair
initial thermal state and recorded desktop load, the complete medians were
60.602 → 61.630 s arithmetic and 63.472 → 63.342 s hashing. The required
4 s saving on both fixtures was not observed. Transform wall time was
unchanged; the extra queue contended with the evaluator.

Engine `bc5dfd6eb` reverts that iteration. Its source tree is identical to
the sealed WP3 engine `8520c7377`; the retained WP5 baseline is the
[sealed WP3 archive](../../target/macos/phase2/wp3-baseline/manifest.json)
with manifest SHA-256
`8f1f57c81a2955c91c7aa773c8309822d13557f8527bf1b2c93b4b2953888836`.
No candidate lifecycle or cancellation check was used for deployment, since
the candidate was rejected on latency and reverted. WP5 po2-21 assessment
is next. See [WP2b paired evidence](evidence/phase2-wp2b-paired.json),
[all paired rows](evidence/phase2-wp2b-paired.csv), and
[controlled midpoint](evidence/phase2-wp3-controlled-midpoint.json).
The [WP2b validation record](evidence/phase2-wp2b-validation.json) pins the
primitive and diagnostic logs and the tree-equivalence check.

## WP3 fused transforms — 2026-11-05

The revised Phase 2 source brief SHA-256 is
`07467098c3493a0bbc0f543b0960676ba3a3e21ebd1fb7a65d10bb8dec40dc97`.
Engine `7143255acda4e51383237a479b51f914a8be904a` adds the fused
commit interpolation, zk-shift, LDE and evaluation path with resident
twiddles and scale tables. Engine
`8520c737725698ddb156ccda2a41e0521213b878` makes radix-four
threadgroup tiles and a column-parallel grid the default. The old path is
selectable with `RISC0_METAL_NTT_RADIX2=1` for bisection. There is no proof
format, admission budget, or external verifier change.

The final 21-test Metal primitive suite passed on both the default fused
path and `RISC0_METAL_NTT_RADIX2=1` fallback. A standalone local
differential matched the unfused path's witness, coefficients, full LDE and
all Merkle nodes at po2 12/14/18. The fixed five-pair campaign against the
sealed WP2 archive verified all 24 proofs and rejected all 72 tamper cases.
Complete medians were 72.684 → 61.589 s arithmetic and 76.409 → 65.384 s
hashing, saving 11.095 and 11.025 s. Both arms used po2 20, 18 Rayon/Go
threads and 8 GiB reserve; measured admission wait was zero. Brave, Codex,
Claude and Colima were present and recorded; thermal snapshots changed from
nominal to fair. The largest paired guard peak was 22.544 GiB, below the
24 GiB initial budget and 32 GiB ceiling.

A separate pipeline-disabled complete proof measured 0.455 s GPU and
0.636 s dispatch wall steady transform time per segment, passing the 0.8 s
stage gate. The requested-buffer traffic model gives about 327 GB/s,
54.4% of the 600 GB/s reference ceiling. A 46M stretch proof passed the
unchanged verifier and three tamper checks in 217.957 s complete latency,
with 17.905 GiB guard peak. The 10M medians are above the 60 s midpoint;
the revised brief leaves a near miss to the owner before reserved WP2b.
The next baseline arm is sealed at `target/macos/phase2/wp3-baseline/`:
manifest SHA-256 `8f1f57c81a2955c91c7aa773c8309822d13557f8527bf1b2c93b4b2953888836`,
engine `8520c7377`, miner checkpoint `afa97e3`.
The paired and per-proof data are in [WP3 paired evidence](evidence/phase2-wp3-paired.json)
and [paired rows](evidence/phase2-wp3-paired.csv); the remaining validation
is recorded in [WP3 validation](evidence/phase2-wp3-validation.json).

An additional browser-closed campaign was started after misreading an older
protocol; its arithmetic fixture completed, then the repeat was stopped.
The revised WP3 brief says to record background load and close nothing to
improve a number, so the original Brave-present campaign is the gate run.
The extra partial run remains under `target/macos/phase2/wp3-pairs/` as a
diagnostic. A first 20-request lifecycle attempt verified all 20 steady
proofs with a 14.83% idle-footprint decrease, then failed only the harness's
helper-timeout assertion: its 60 s deadline exceeded the tiny proof's 45.4 s
completion. The 35 s rerun is the closure check.

## WP2 segment pipeline — 2026-11-05

The updated source brief SHA-256 is
`966e6bbfd2cbef4912c5cd18903e776b9ffc67c50f612ac2f71805d53247359d`.
Engine `6ebdadd840257b4c8b59171f6e12f063b496b1a7` introduced a
deferred Metal evalcheck command buffer, and engine
`a80fcb3c0d912f0ca82befe0fbcbff18e9f35eaa` overlaps the next segment's
CPU accumulation with the previous finalize. The CPU/GPU buffer-set ownership
and completion handoffs are logged. `RISC0_SEGMENT_PIPELINE=0` disables the
pipeline for bisection. The kernel source, arguments, and proof format are
unchanged.

Complete po2-14/18/20 proofs passed real-witness CPU differentials, external
verification, and all three tamper rejections each. A separate 10M proof was
cancelled after its log showed `cpu_begin set=12 gpu_owned_set=Some(11)`;
the supervisor left no worker group or helper. The 20-request lifecycle
passed with 21 verified proofs, 63 tamper rejections, the helper controls,
recovery, and shutdown. Idle footprint fell 15.50% from request 1 to 20.
The first lifecycle run is retained as a harness diagnostic: its 20-second
watchdog fired during recursion, before the helper existed, so the partial
sidecar did not have final recursion fields. The 35-second rerun reached the
helper and passed.

The fixed five-pair campaign against sealed WP1 passed the 6 s median gate
on both 10M fixtures: arithmetic 80.419 → 74.391 s (6.029 s), hashing
81.463 → 75.413 s (6.050 s). All 24 proofs and 72 tamper rejections passed.
Both arms used 8 GiB reserve and 18 Rayon/Go threads. Brave, Codex, Claude,
and a Colima process remained present; thermal observations were nominal then
fair. One warmup had a 60.95 s admission wait; measured rows had none.
The paired WP2 peak was 22.014 GiB, so the existing 24 GiB initial budget
and 32 GiB ceiling remain. The separate 46M stretch verified in 284.415 s.
The CPU-only worker build and five tests passed. Colima compiled the
recursion Metal, RV32IM prove, and zkVM Metal-recursion feature paths; the
final zkVM compile ran offline after fetching missing lockfile-pinned crates.
WP2 is closed; WP3 transforms is next.
See [paired evidence](evidence/phase2-wp2-paired.json),
[paired rows](evidence/phase2-wp2-paired.csv), and
[validation evidence](evidence/phase2-wp2-validation.json).

## WP0.5 command batching — 2026-11-05

The 2026-11-04 Phase 2 source brief has SHA-256
`299ebd441aa2e1c0c70f7587a88b8cc32154d0835a0eaea0d807adef11028597`.
Engine `6b3ec9539fb3a4e5c267c2a4f8f81d6d90ac577d` batches GPU-only
NTT/shift/LDE, Merkle, and prover stages at CPU access boundaries. The sealed
WP1 worker is archived at `target/macos/phase2/wp1-baseline/` for the paired
campaign. Three bounded iterations reduced command buffers from 1,873 to
143 for transforms, 1,163 to 61 for Merkle, and 5,539 to 540 for recursion
in a 10M profile. Transform host overhead remains 1.809/1.756 s and
recursion overhead 0.703/0.715 s (arithmetic/hash), above the 0.3 s target.
The [profile](evidence/phase2-wp05-gpu-profile.json) retains both fixtures.

The 20-test Metal primitive suite, recursion offset differential, po2-14/18/20
complete real-witness CPU differentials, unchanged verifier and tamper checks,
CPU-only feature build, and Colima Linux feature-path check passed. The
20-request lifecycle passed with 21 externally verified proofs, 63 tamper
rejections, failure/recovery controls, and a 14.51% lower idle worker
footprint. A first run with the 10-second helper watchdog failed on a partial
sidecar; the 20-second rerun passed. Both attempts are bound in
[validation evidence](evidence/phase2-wp05-validation.json).

The controlled five-pair campaign against the sealed WP1 worker saved
2.049 s arithmetic (77.758 → 75.709 s) and 3.023 s hashing
(79.801 → 76.778 s). All 24 proofs and 72 tamper rejections passed;
admission wait was zero and sampled pressure stayed normal. Brave was absent
before and after both fixtures, with the default 16 GiB reserve. Arithmetic
missed the original 3 s saving and transforms/recursion missed the 0.3 s host
overhead target. The 2026-11-05 source brief recalibrated WP0.5's closure to
the measured 2–3 s range and retained batching as the default checkpoint.
See [paired evidence](evidence/phase2-wp05-paired.json) and
[rows](evidence/phase2-wp05-paired.csv).

The WP1 paired CSV now fills both GPU columns. The sealed WP0 worker could
not timestamp individual kernels, so its values are labeled references from
the separate verified WP0 GPU profile; evalfast values are from paired proofs.

## WP1 paired checkpoint — 2026-11-04

Engine `d194533fa` is pushed. The five-pair campaign against the sealed WP0
archive passed the timing gate with Brave closed, the default 16 GiB reserve,
18 Rayon and 18 Go threads, and no admission waits. Arithmetic complete
median was 118.554 → 78.688 s (39.867 s saved); hashing was
119.566 → 80.779 s (38.787 s saved). The 119.566 s WP0 hashing median is the
controlled re-baseline; the old 130.6 s Brave-open, 12 GiB result is not a
comparison arm. All 24 proofs and 72 tamper rejections passed. See
[paired evidence](evidence/phase2-wp1-paired.json).

Engine `5acb4b8721b54ba2621d89f5f8d677cd5eca29d2` flips evalfast to
the default and provides `RISC0_RV32IM_TAIL_SPLIT=1` for the fallback. The
rebuilt worker SHA-256 is
`6896db28ae15053f63377dff745ca64ac67cba68c1f52e1c8ba3d02928e983e9`.
Default and fallback proofs passed real-witness CPU differentials and external
verification. The final-build lifecycle verified 21 proofs and passed all
failure and recovery controls. Idle footprint after request 20 was 10.60%
below request 1; this passes the revised one-sided memory gate. The settled
range was 3.68%, with normal pressure. WP1 is closed. See
[default-path evidence](evidence/phase2-wp1-default.json).

## Reopened WP1 evalfast port — 2026-11-04

Engine `d194533fa5138a8d9a352c977ae622d59cca4d41` regenerates the
in-tree evalfast pipeline through `remat_lu.py` and emits the main/LogUp
phase split as MSL. Select it with `RISC0_RV32IM_EVALFAST=1`; leaving that
variable unset retains the tail-split/256 fallback. The synthetic po2-20 CPU
oracle passed at 1.694 s repeat GPU time, and po2-14/18/20 real-witness proofs
passed CPU differentials and external verification. Single verified 10M
arithmetic and hashing diagnostics saved 32.10 s and 36.07 s in complete time
against the prior tail-split/256 run. The 20-request lifecycle passed with
21 verified proofs, 63 tamper rejections, cancellation, a calibrated helper
watchdog, recovery and shutdown. Nine workload-limit controls passed. Pressure
stayed normal; idle footprint decreased 12.39% from the first proof and varied
0.25% after settling.
The default tail-split/256 fallback also passed a fresh po2-14 real-witness
CPU differential and complete proof. The initial 10-second watchdog control
failed because it sampled a partial sidecar; its diagnostic run is preserved.
The MSL generator currently stops after `remat_lu.py`; the later CUDA
`mksm2.py` and `mksub.py` passes remain to port.

The LogUp-removal timing diagnosis below was negative, while the wide-arithmetic
evalfast port met the timing target. Keep the two results separate when
reviewing the mechanism.

## Phase 2 WP1 reopened — 2026-11-04

The owner reset WP1's iteration budget and specified a port of the in-tree
evalfast pass pipeline output to MSL, starting with the main/LogUp phase split.
The current tail-split/256 worker remains the fallback. A one-hour, timing-only
LogUp-removal experiment finished within the hour: five counterbalanced
po2-20 pairs measured **4.969 s** median repeat GPU time for the fallback and
**4.470 s** for main-only, a **1.112×** ratio. The result is percent-scale and
does not confirm the proposed multiples-scale live-state diagnosis. The
diagnostic shader was never used for proofs. See
[probe evidence](evidence/phase2-wp1-logup-probe.json) and
[reopened WP1 scope](PHASE2_PLAN.md).

## Phase 2 fold-only cleanup — 2026-11-04

Engine `fca0c099582f15729f98af0743f45bc56c217705` removes the retired
fold-only Metal adapter, hybrid feature chain, and `LocalProver::new_metal`.
The old isolated hybrid probe manifest and launcher are removed from the miner.
The shared `tools/macos-proof/src/main.rs` is retained unchanged because it is
an input to the pinned external verifier. The resident RV32IM and recursion
Metal feature paths remain active. The cleanup worker SHA-256 is
`c5f369bb7f76d6bdb61823149997e850bbb47299981be58cde17ae7aff31b7f5`;
it differs from the measured WP1 binary. A fresh po2-20 proof passed its
real-witness CPU differential, unchanged verifier, and three tamper rejections.
Native and CPU-only worker unit builds each passed five tests. The WP1 timing
numbers below belong to the preceding WP1 worker; no performance claim is made
for this cleanup build. The final-binary lifecycle passed 20 steady proofs plus
one recovery proof and 63 tamper rejections; idle footprint drift was **−0.68%**
with normal sampled pressure. Cancellation, worker timeout, restart and shutdown
passed. See [cleanup evidence](evidence/phase2-fold-cleanup.json).

## Phase 2 WP1 checkpoint — 2026-11-04

The Phase 2 branches now carry the bounded RV32IM evaluator trial. Engine
`afd4342f90160c60829818dca953bcfe952a5639` generates a low-live-value
tail split for all 20 chain functions and selects 256-thread groups. The
sealed native worker SHA-256 is
`9b0f07321888abf9292c466fe4d3dee93d499de3dca8b03cec491020d66bc2c1`.
Synthetic CPU comparisons passed at po2 4/8/14/18/20; complete po2 14/18/20
proofs passed the real-witness CPU differential, unchanged verifier, and all
three tamper checks. Native and CPU-only unit builds passed. The optional
fast-reduction variants were slower and are disabled.
The 20-request lifecycle passed with **−0.42%** first-to-last idle footprint
drift, plus one verified restart proof, 63 tamper rejections, cancellation,
worker timeout, shutdown, and nine limit controls. Helper timeout was not
exercised. Linux cross-target compilation was unavailable locally.

Single diagnostic 10M proofs measured **47.813 s arithmetic** and **51.059 s
hashing** constraint wall time, or **4.78/5.11 s per segment**. Complete proof
plus external verification took **118.593/124.648 s**, versus the WP0
diagnostic **128.053/129.157 s**. The ≤2.0 s per-segment WP1 gate is missed;
these are unpaired single proofs, so the ≥25 s five-pair whole-proof gate is
unclaimed. The main/LogUp phase split and lazy scratch-buffer reduction remain
unported. See [WP1 measurements](BENCHMARKS.md) and
[WP1 evidence](evidence/phase2-wp1-iteration.json). The next package in the
brief is WP2 segment pipelining.

## Phase 2 current status — 2026-11-04

New `codex/hemi-macos-metal-phase2` branches started at miner
`9bc7466eaf6a4b48d8655d39f69cc89fa40f0298` and engine
`dcbe9f4b9140a48d4792ffcd3a3eba19897be175`. The WP0 engine timing
checkpoint is `09c2f4d2836cbcd88cd29e65b6a6bdd8db262416`; this miner
checkpoint contains its matching sidecar, tools and evidence. The starting worker is
rebuilt and sealed in `target/macos/phase2/baseline/` (worker SHA-256
`1c70d2ef9eb3dddd94ded3588eedf7c93f3cca176a5b4a9d660ec570637938d8`).
New complete-proof measurements are **119.568 s arithmetic 10M** and
**130.641 s hashing 10M** five-proof warm medians, plus a **501.037 s** single
arithmetic 46M stretch. All 13 dispatched proofs and 39 negative checks passed.
The first hashing attempt was refused before dispatch by the default 16 GiB
host reserve; the subsequent hashing and stretch campaigns used a recorded
12 GiB local override. See [Phase 2 plan](PHASE2_PLAN.md),
[measurements](BENCHMARKS.md), [baseline evidence](evidence/phase2-wp0-baseline.json),
and [GPU profile](evidence/phase2-wp0-gpu-profile.json).

The instrumented worker SHA-256 is
`9b7ab90957fefe60232e871a2823056d8683c8852476666483a8721b08cce545`.
Two diagnostic 10M proofs and the po2-14 CPU differential verified. Native and
CPU-only unit builds, the nine limit controls, and the 20-request lifecycle
passed. First-to-last idle footprint drift was **4.49%**; see
[WP0 validation](evidence/phase2-wp0-validation.json). The GPU-only sum is
12–13% below transform wall time, outside the brief's 10% reconciliation gate;
about 1.9 s is measured host dispatch overhead. Linux cross-target compilation
was unavailable because only the Apple Silicon target is installed locally.
The protected circuit, verifier, seal, and dependency versions have not changed.

## Review follow-up — validation complete

The refreshed pipeline is validated at the clean engine checkpoint
`dcbe9f4b9`, descending from parent `8007a9972`, merge `c6b67b15e`, and published
documentation checkpoint `3747d12ff`. On 2026-11-03 the owner authorized committing
and publishing this review follow-up to both personal forks' `codex/hemi-macos-metal`
branches. The [review publication record](evidence/rv32im-review-publication.json)
binds this miner commit and the unchanged engine checkpoint to the validated
source inputs and binaries. Measurement-time records retain their original IDs.
The owner's explicit parent-refresh request superseded the earlier instruction
against merging a newer default branch merely to publish the port.

The predeclared five-pair 10M arithmetic gate passed: **427.192 seconds
baseline / 117.192 seconds resident Metal** median complete latency,
**3.645×** speedup, with **5/5 faster pairs**. The required
thresholds were 2× median speedup and four faster pairs. Both workers retained
their identities for six proofs each; one warm-up per worker was excluded and
request order alternated. All twelve proofs verified independently and passed
36 negative checks. No fresh-campaign admission wait or proof failure occurred.
See [paired gate](evidence/rv32im-five-pair-validation.json) and
[all proof rows](evidence/rv32im-five-pair-proofs.csv).

The comparison uses the exact archived committed step-5 worker. All 18 miner
inputs and its engine delta match the committed checkpoints; see
[baseline bridge](evidence/step5-baseline-bridge.json). It compares the whole
refreshed stack, including upstream changes, rather than attributing the entire
gain to Metal. The fixed fixture executes 10,003,116 guest cycles in ten segments
at po2 20, with 18 Rayon / 18 Go threads. No statistical-significance claim is made.

Both agreed usefulness fixtures now pass five-sample warm medians including
independent verification: **117.192 seconds arithmetic** and
**120.800 seconds hashing**, each below 600 seconds.
See [warm hashing](evidence/rv32im-warm-hash-validation.json). The 46M stretch
also passed: 46,003,116 guest cycles in 46 segments, **484.740 seconds** complete,
**15.401 GiB** guarded group peak, and normal pressure throughout. This is a
single stretch observation, not a five-sample median; see
[current-tip correctness and stretch](evidence/rv32im-current-tip-validation.json).

Current-tip validation totals **22 complete proofs and 66 negative checks**,
including four current-candidate proofs from the interrupted attempt. The 31
focused checks cover both worker unit suites, 18 Metal primitives, the recursion
CPU differential and two padding tests. The merge itself had already passed
eight proofs and 24 negative checks; their original artifacts are recorded in
[engine refresh validation](evidence/engine-refresh-validation.json).

Current arithmetic/hash 10M profiles put constraints at 62–64% of segment wall
time, transforms near 20%, Merkle commitments near 4%, and CPU accumulation at
7–8%. These supersede the CPU-only split for this backend. They measure synchronous
phase wall time, not GPU occupancy. No further kernel optimization has started.
See [Metal profiles](evidence/rv32im-metal-current-profile.json).

The production fold-only path and staging probe are retired. Old build, forced
mode and probe requests fail with migration guidance; the SDK's `metal-hybrid`
compatibility feature also fails explicitly. Use `RISC0_SEGMENT_HAL=metal` and
`RISC0_RECURSION_HAL=metal` with native wrapping. The old mode variable is
unnecessary, and CPU remains the default. The worker runtime patch is archived
in [review worker patch](evidence/rv32im-review-worker.patch).

The default 16 GiB host reserve, 24 GiB initial resident-prover budget and 32 GiB
worker/helper ceiling remain unchanged. Largest observed review proof-group
peak is **19.783 GiB**, including warmed proofs; this excludes the other retained
worker. The configuration is intended for a 64 GiB-class Mac or larger; validation
used 128 GiB. See [hardware guidance](SETUP.md). Colima was left running throughout.

In the November 4 [desktop spot check](evidence/rv32im-desktop-admission-spot-check.json),
one worker verified the 10M arithmetic fixture with Brave open at both reserves.
Estimated headroom just before the proof call was 40.43 GiB with the default
16 GiB reserve and 39.28 GiB with a 12 GiB reserve. Both runs peaked at about
15.42 GiB for the worker/helper group and sampled normal pressure throughout.
This supports a local 12 GiB trial under desktop load. The kernel must already
report normal pressure for admission; keep the byte check for the allocation
the next proof is expected to add. Before changing the default, test cold
startup, repeated warm requests and the 46M fixture with ordinary apps open.
Track swap, pressure, guard outcomes and verification. The two-worker comparison
adds the idle baseline's footprint and should remain separate.

The engine still contains `metal_fold.rs`, `LocalProver::new_metal` and the
`metal-hybrid` feature chain. The compile errors retire the feature from use.
Before opening an upstream PR for the resident Mac backend, remove the legacy
code and feature wiring, retain the shared `metal-runtime` dependency used by
the active backend, and recheck the CPU and resident Metal builds. This is
separate from the three small upstream PRs below.

Earlier attempts remain separate: the first refused admission before measured
pairs; the next verified seven proofs and two pairs, then an incorrectly computed
outer suite timeout interrupted the next CPU proof. The owner quit Brave during
that attempt's recorded 132-second admission wait. The fresh campaign started
after Brave closed and does not pool those partial measurements. The runner now
budgets every comparison request, its unchanged proof watchdog and permitted
admission waits. Five suite-budget checks pass. See
[initial refusal](evidence/rv32im-paired-attempt.json) and
[interrupted attempt](evidence/rv32im-paired-interrupted.json).

Three separate draft PRs are open against `hemilabs/risc0:release-3.0`:
[padding + tests](https://github.com/hemilabs/risc0/pull/30),
[locked Circom install](https://github.com/hemilabs/risc0/pull/31), and
[native helper lifetime flags](https://github.com/hemilabs/risc0/pull/32).
Their correctly authored single commits are based directly on parent `8007a9972`.
Isolated padding and native-helper lifecycle checks pass; the Dockerfile matches
the previously validated ARM64 build. See [PR evidence](evidence/upstream-macos-prs.json)
and [status snapshot](evidence/upstream-macos-pr-status.json).

## Original resident-port publication (historical)

Resident RV32IM worker integration and full-proof validation are complete and
recorded in this miner publication checkpoint. The engine commit is
`cef3559d6805769c5b33fb4040abe548e670e268`. See
[RV32IM_METAL_WORKER.md](RV32IM_METAL_WORKER.md),
[validation JSON](evidence/rv32im-worker-validation.json),
[proof CSV](evidence/rv32im-worker-proofs.csv) and
[engine patch](evidence/rv32im-worker-engine.patch). The owner authorized
committing and publishing the completed local work after correcting authorship.
Both repositories use `dimitryB <5238240+dimitryB@users.noreply.github.com>`.
Only the personal fork's `codex/hemi-macos-metal` branches are publication
destinations; upstream/default branches are unchanged.

Historical evidence retains its original commit IDs. The
[authorship map](evidence/authorship-rewrite.json) maps step-5 miner `4cbfb3e`
to `55b6d87` and engine `0515e0bde` to `1f6eb352d`, with identical source trees.
The [publication record](evidence/rv32im-publication.json) records source/binary
continuity through the engine commit and rebuilt seals. Reproduction uses the
new committed engine SHA; do not replace IDs inside historical proof records.

The explicit `macos-rv32im-metal` worker uses shared Metal buffers for RV32IM
transforms/commitments/constraints and retains CPU witness/accumulation and
native identity/Groth16. CPU segments remain the default. Runtime selection is
`RISC0_SEGMENT_HAL=metal`, with `ZKMINER_RISC0_MODE=cpu` disabling the separate
legacy fold-only selector and `RISC0_RECURSION_HAL=metal` retaining Metal
lift/join. Keep thirty-two-thread evaluator groups, the four-entry normalization
table, cap 20, one in-flight segment and all existing resource guards.

The final candidate passed 28 complete proofs plus 84 negative verifier checks,
including three real-witness CPU differentials, tiny-tail/boundary cases, CPU
selection, two 10M workloads, twenty requests on one worker, observed-helper
cancellation, worker watchdog, recovery and shutdown. The original verifier
remains byte-identical. CPU-only and resident feature builds each pass five unit
tests; workload-limit controls pass. Three preliminary proofs were excluded
after correcting writable FFI buffer handling to pass raw pointers directly.

The single 10M arithmetic/hash observations were 126.680/130.646 seconds, with
maximum completed-proof guarded worker/helper footprint 16.305 GiB. The twenty
tiny requests' idle footprint ranged 3.859–3.948 GiB (first 3.873, last 3.860).
These establish the agreed usefulness goal and tested stability, not a controlled
speedup or the proposed 2× scalability gate. A five-pair comparison against the
committed step-5 baseline remains the next performance assessment. GPU witness,
larger caps, overlap and 46M Metal proving remain unimplemented/unmeasured.

Final worker SHA: `318676ce86d7f96f6dbff1ca111016e62d95095ffc65cb2a2ab7923b76635f04`.
Campaign: `target/macos/rv32im-worker/campaigns/c76287bac2dc468396bf81ee6a91f8f6`.
Archive: `target/macos/rv32im-worker/archive/final`. Worker/helper processes are
gone; VM states are unchanged (default running, dedicated profile stopped).

## Historical assessment and prototype checkpoints

The owner authorized the bounded RV32IM evaluator prototype after the step-6
assessment. Its feasibility gate now passes; see
[RV32IM_METAL_PROTOTYPE.md](RV32IM_METAL_PROTOTYPE.md) and
[collected evidence](evidence/rv32im-evaluator-prototype.json). Two po2-20
synthetic datasets matched every CPU result, including reused buffers. GPU
dispatch took about 5.85 seconds versus 19.3–19.5 seconds on CPU; peak charged
footprint was 13.1 GiB. This is isolated evaluator performance, not a proof or
whole-job speedup. The engine and step-5 worker remain unchanged.

Retain thirty-two-thread groups and the equivalent four-entry normalization
table. The 1,024-thread control failed with Metal out-of-memory; the original
divergent per-cycle normalization mismatched at po2 14. Five earlier failures
remain recorded alongside fourteen successful final-candidate commands.
The normalization failure's compiler/driver mechanism is unconfirmed.
Next: opt-in shared-buffer RV32IM adapter with CPU witness/accumulation, then
complete-proof correctness, measured integrated memory and controlled latency.
All new assessment/prototype work remains uncommitted; do not start a full
witness port or claim the proposed whole-job 2× gate has passed.

Step 5 is now committed: miner `4cbfb3e`, engine `0515e0bde`. The exact measured
worker remained byte-identical after rebuilding/resealing at the new checkpoint.
The owner authorized the step-6 assessment, which is complete and saved in
[RV32IM_METAL_ASSESSMENT.md](RV32IM_METAL_ASSESSMENT.md). New assessment work
remains uncommitted; nothing has been pushed. That assessment preceded the
isolated prototype and subsequent worker integration recorded above.

The original 10M/ten-minute goal already passes, so a full RV32IM port is a
separate scalability investment. The two new verified verbose 10M diagnostics
agree: segment time is approximately 51% constraints, 31% Merkle commitments,
11% transforms and only 2–3% witness/accumulation. De-risk the full-domain Metal
evaluator first, then integrate existing Metal transforms/hashing on shared
buffers with CPU witness/accumulation. For a proposed 2× whole-job objective,
the combined hot phases would need roughly 2.42–2.44× effective acceleration;
that performance has not been demonstrated. Generic transforms/Merkle alone
have an ideal whole-job ceiling near 1.6× on these observations.

Raw diagnostics: `target/macos/step6-assessment/profile-runs/b2112a5f7787478598e5c894a16f0e91`.
Both complete proofs passed the unchanged verifier and six negative checks.
The diagnostic worker SHA remains `d157305ba0e0830671c6b8f6238dc68e59ae8a68dc3454865c2084c21bc347b9`.
The source audit found no RV32IM Metal kernels, four CUDA evaluator chunks with
20 functions, 6,332 declared scratch bytes per invocation (not a measured Metal
allocation), and a 3.297-GiB largest evaluated DATA buffer at po2 20. Current
committed groups/trees alone account for 6.902 GiB; measure real phase peaks
rather than adding that to old process peaks. Retain cap 20, one in-flight
segment and the existing memory/ownership guards for any future prototype.

The assessment generator is `scripts/macos/assess-rv32im-metal.py`; its JSON and
CSV are under `docs/macos/evidence/rv32im-metal-*`. It binds latest observations,
current source hashes, diagnostic proofs, device limits and checkpoint
continuity. Do not treat hypothetical speedup tables as measured performance.

The owner subsequently authorized committing steps 1–4 and proceeding with
step 5, Poseidon2 lift/join recursion Metal. The engine checkpoint is
`98d940d4b`; the exact measured CPU worker and original build manifests were
preserved in `target/macos/native-wrap/step4-cpu-baseline` before committing.
The measurement-time source hashes below remain historical evidence. Do not push.

The Poseidon2 lift/join milestone of step 5 passed. The owner subsequently
authorized its commit and the step-6 RV32IM assessment. The engine checkpoint is
`0515e0bde`; the exact measured binaries/manifests remain archived. Nothing was pushed.
The separate `native-recursion-metal` worker uses `RISC0_RECURSION_HAL=metal`
and `ZKMINER_RISC0_MODE=cpu` for CPU segments. Witness/accumulation use pinned
CPU routines directly on shared buffers; identity-p254 remains CPU. Every GPU
command completes and drains its temporary Objective-C objects before CPU access.

The worker SHA-256 is
`d157305ba0e0830671c6b8f6238dc68e59ae8a68dc3454865c2084c21bc347b9`.
The completed final campaign is
`target/macos/native-wrap/workload-campaigns/ed853b04d39243a4b6da292774bc34f6`:
37 complete proofs and 111 negative checks, plus nine input controls. Its five
warm CPU/Metal pairs on Fibonacci(150000), po2 20, had complete medians of
86.921/77.772 seconds (10.5% less time; all five pairs faster), exceeding the
predefined 1.05× / four-pair criterion. The two 10M fixtures verified once each
in 418.323/421.236 seconds; these are not five-sample usefulness medians.
Twenty consecutive requests on one worker, cancellation, watchdog, verified
restart and shutdown passed. Idle worker footprints stayed within 3.849..4.008
GiB across those twenty requests. The largest sampled group peak was 17.279 GiB
at Metal startup; pressure stayed normal. The largest CPU comparison peak was
15.112 GiB. Host availability stayed above 22.0 GiB with two resident paired
workers; one proof was active at a time.

After timing, the initial Metal admission budget was raised from 16 to 20 GiB;
native CPU remains 16 GiB. A final production-ledger check held 93 GiB of logical
reservations, refused before dispatch, released to zero and independently
verified a recovery proof plus three negative checks. No represented memory was
allocated. This supervisor-only change leaves the measured worker binary
unchanged; both timing and final acceptance binaries/source manifests survive
in `target/macos/recursion-metal-final-build/acceptance`.

The unchanged verifier remains SHA-256
`2bcdcb7f50e2303545898962d23bdc6cba9512038383a93c975f95b89cf8225c`.
Shader SHA-256 is
`137564beae0d2804c66d1957411d6be97b6b4d7b9cb4d7868eecdc80b0c69bb5`.
The worker, manifests and exact generated shader are archived in
`target/macos/recursion-metal-final-build`. The evaluator takes the current CUDA
polynomial body verbatim; legacy Metal accumulation kernels are audited but unused.

Validation passed 18 Metal primitives, the evaluator CPU differential (po2
4/7/10 with offsets/sentinels), four worker startup tests, 62 benchmark tests,
12 memory tests and CLI compilation. Isolated shared-buffer controls in
`target/macos/metal-buffer-controls/1ff7cd33ecf046a8b780167fe64c8041` exercised
36 GPU hash commands with actual allocation reuse, intervening CPU writes,
empty inputs, nonzero offsets and grid boundaries, matching CPU outputs.
Expected zero-output rejection panics were caught. Linux ARM64 CPU checks for
both recursion and zkVM feature paths passed with Rust 1.93.1. The dedicated VM
is stopped; the original default VM remains running.

The preliminary campaign `ac530c478a9047daa7a424c43b76de8d` was deliberately
interrupted to add the per-dispatch autorelease pool. Its seven verified
artifacts, started request and pending slots remain with `replan.json` and
`target/macos/recursion-metal-before-pools`. A separate three-proof pilot
`71684d3b53884fc2bc4fb3b3cfe654ee` is retained and excluded from final timing.
Pre-proof setup errors and one operator-interrupted Linux check remain alongside
the corrected runs. No failed cryptographic proof was retried.

See [workload results](BENCHMARKS.md), [setup](SETUP.md),
[validation](evidence/recursion-metal-validation.json),
[comparison CSV](evidence/recursion-metal-comparison.csv) and
[engine diff](evidence/recursion-metal-engine.patch). The root Cargo.lock is
unchanged. Engine Cargo.lock adds only the already-existing build-kernel
package dependency edge. Identity-p254 Metal and full RV32IM acceleration have
not started; those are separate follow-up decisions.

The owner approved [IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md) on
2026-11-01 and requested implementation with all new changes left uncommitted.
This supersedes the earlier next step of extending fold-only benchmarks.
Target: 10 million guest cycles within 10 minutes (median of five complete warm
proofs per fixed arithmetic/hash fixture), with 46 million cycles as a stretch
test. Preserve independent verification and 20-request lifecycle acceptance.

Native macOS helper milestone passed: six complete WorkerPool proofs (including
hashing and five-segment jobs), three native rewraps, 27 tamper rejections, and
three byte-identical witnesses. Worker helper cancellation, a ten-second
watchdog, restart, shutdown, native witness cancellation, helper deadline,
parent death, and artifact rejection passed. The Intel wrapping feature compiles;
two macOS process/group tests passed. See [native evidence](evidence/native-wrap-validation.json).
The initial Rust build needed project-local `protoc`; an intermediate worker
build correctly refused a provenance seal while inputs were changing. The final
worker was rebuilt and sealed after those changes; no failed proof was retried
or excluded from the recorded acceptance runs.

The native bundle is `target/macos/native-wrap/assets`; the worker is
`target/macos/worker-native/release/zkminer-prove-risc0`. Use
`ZKMINER_RISC0_WRAP=native` and the settings in [SETUP.md](SETUP.md). Native
Fibonacci body times were 59.714 seconds first, then 44.712/45.763 seconds on the
same worker; the five-segment proof took 129.774 seconds. These are the earlier
six-thread correctness observations.

Step 3 selected **18 Rayon / 18 Go threads**. The five-pair warm-worker comparison
measured median bodies of 46.069 seconds at 6/6 and 22.421 seconds at 18/18
(2.05×), with all twelve proofs and 36 tamper checks passing. Independent screens
covered Rayon 6/12/18 with Go fixed at six, and Go 6/12/18 on the actual host.
The final paired run used one sealed worker binary and alternated request order.

Admission now observes owned worker/helper physical footprints, gates new work
on normal kernel memory pressure, and uses a configurable 8..64-GiB reserve
(default 16). The native unmeasured budget is 16 GiB, with guard-sampled group
peaks feeding calibration. The 32-GiB watchdog ceiling and 8-GiB estimated
headroom floor remain. Measured pairs peaked near 11.1 GiB combined footprint;
the host stayed at normal pressure. See [tuning evidence](evidence/native-tuning-validation.json)
and [consolidated engine diff](evidence/native-tuning-engine.patch).

Cache-warm logical-reservation refusal and a verified recovery proof passed.
The first queued follow-up attempt omitted `env.sh`, so Cargo was missing before
any proof or test build; its failed result and cache record are preserved under
`target/macos/native-wrap`. The corrected run is separate. One reserve parser
unit test initially exposed an eager overflow; that was corrected before the
final tests, worker build and paired campaign.

Final 18/18 validation passed hashing, five-segment proving, three consecutive
proofs, observed helper cancellation, a ten-second worker watchdog, a verified
restart proof and shutdown. This milestone totals 31 complete worker proofs,
18 rewraps and 147 tamper rejections, plus 20 Rust unit tests and eight invalid
thread startup checks. The unchanged verifier binary and root lock were checked;
no owned proof process remains. The dedicated VM is stopped and the original
default VM remains running. All changes remain uncommitted/unpushed.

Step 4 passed. Native workers default to a configurable 64-Mi guest-cycle
ceiling (`ZKMINER_RISC0_MAX_GUEST_CYCLES`, bounded at 67,108,864) and po2 20,
with local caps 14..20. Legacy Mac builds retain 4,194,304 cycles and po2 18,
with caps 14..18. The shared RV32IM executor floors final padding at po2 14
for proving caps. Fifty-one before/after boundary executions preserved claims,
journals, guest cycles and paging, with padding charged only to reserved/total
cycles. Four shared executor tests passed on both macOS and Linux ARM64; the
Linux runtime test had networking disabled. Its build allowed only existing
unused prover-field warnings in the execution-only feature subset.

Native sizing now reports padded total cycles, matching proof output, while
checking SDK guest counts separately against the ceiling. Claim admission
rejects unknown/oversized work and unsupported overrides before claim, after
permitting the existing background sizing path. Claims keep the selected Mac
pipeline's calibrated default segment setting. Non-Mac worker inputs below
po2 14 are rejected too. Measured fixed identity/wrap cost plus segment/recursion
scaling informs native deadline evaluation and the watchdog. Native built-in
benchmarks use the fixed 10M arithmetic/hash inputs. Configure
`[prover] benchmark_timeout_secs = 1800` for the two-proof benchmark suite;
the generic default is a 600-second per-suite cap.

The completed serial campaign is
`target/macos/native-wrap/workload-campaigns/2edca085145446d5a3e89270d6087a7a`.
It passed nine input controls, tiny-tail and segment-boundary proofs, one excluded
warmup plus five measured complete proofs per 10M fixture, one arithmetic 46M
stretch, and twenty consecutive requests followed by cancellation, watchdog,
verified restart and shutdown. Its 36 full proofs passed the unchanged verifier
and 108 negative checks. Complete 10M medians were 483.927 seconds arithmetic
and 476.853 seconds hashing. The 46M arithmetic result was 2,139.840 seconds
complete (2,139.636 body), 1.5% above the model frozen before that holdout.
Hashing at 46M was sized only. The campaign's peak sampled simultaneous group
footprint was 12.6 GiB and sampled memory pressure stayed normal.

The earlier po2-18 campaign `a90a508b35fc4e9d926e9582781284bf` was intentionally
stopped after one verified 10M warmup: 731.067 seconds of body time. Its three
verified proofs, nine negative checks, partially started next request, pending
slots and interrupted result are retained separately, with `replan.json`.
This is a single sizing screen, not a five-sample speed comparison. Sources,
binaries and manifests are archived in `step4-po218-build`; the final campaign
acceptance binary is preserved in `step4-po220-acceptance`. The final worker
binary and unchanged verifier remain sealed; no worker rebuild followed timing.

The final automatic po2 resolver keeps 20 for native mode and 18 for legacy
mode. Its pure mode regression test passed. A separate short final acceptance
passed on final supervisor sources: it loaded the measured CPU memory profile,
confirmed refusal before dispatch under production reservations, released them
to zero and verified a recovery proof at requested po2 19 (503,116 guest /
589,824 padded cycles, two segments). Its one proof and three negative checks
are separate from the measured campaign. The CLI check also passed. See [workload evidence](evidence/native-workloads-validation.json),
[measured CSV](evidence/native-workloads-comparison.csv),
[calibration](evidence/native-workloads-calibration.json) and
[engine diff](evidence/native-workloads-engine.patch).

Worker tests, protocol limits, 62 benchmark tests, shared executor regressions
and CLI compilation passed. Earlier pre-proof setup failures (network lookup,
dependency test workspace selection, default container toolchain and
execution-only dead-code warnings) remain archived. No proof failure was retried.
At the step-4 measurement checkpoint, the root dependency lock and both
repository HEADs were unchanged and all changes were uncommitted. The owner
subsequently authorized the checkpoint commits and step 5 described above.

Order: ARM64 wrapper feasibility, native macOS helper, native thread/memory
tuning, larger workloads, Poseidon2 recursion Metal, then separate Poseidon254
identity and RV32IM investment decisions. The ARM64 image is a feasibility
step; production container integration is deliberately deferred. Current build
and proof artifacts live under `target/macos/arm64-wrap-builds` and
`target/macos/wrap-runs`. Existing benchmark and CPU/Metal binaries are retained.

The first implementation fixes the helper Dockerfile's Circom build to use its
existing lockfile. The build runner materializes the original checksum-pinned
circuit LFS object in a snapshot and records native ARM64 image provenance.
The measurement runner reuses archived identity inputs and the sealed unchanged
verifier. ARM64 feasibility passed: four new wraps, 12 tamper rejections, and five
control tests. Serial witness/gnark times were about 4.7/9.8–10.0 seconds; the
original pipelined Fibonacci wrap took 11.312 seconds including Docker launch
and exit. These are isolated wraps, not complete newly executed jobs. See
[BENCHMARKS.md](BENCHMARKS.md) and its compact machine-readable evidence.

Successful build: `target/macos/arm64-wrap-builds/fcafe2c4fbec45f0a81bb939254d09b7`.
The finalized build script also passed using the cache in build
`6ecc1f125fb54a9c9488a2e9aac6a78f`, with identical input hashes. Initial build
attempts record missing Buildx, standalone-context selection, an unlocked Circom
dependency requiring newer Cargo, and the unresolved circuit LFS pointer.
The exact LFS object was recovered from its introducing upstream commit and
checked against the Hemi pin's size and SHA-256. No circuit/key was substituted.

Reproduce after starting the documented dedicated Colima profile:

```sh
python3 scripts/macos/build-arm64-wrap.py --engine /Users/dbur/.codex/worktrees/hemi-macos-cpu/risc0 --buildx target/macos/bootstrap/buildx-v0.38.1/buildx-v0.38.1.darwin-arm64
python3 scripts/macos/measure-wrap.py --build target/macos/arm64-wrap-builds/fcafe2c4fbec45f0a81bb939254d09b7 --source target/macos/runs/08b5cca54b024b9ca9d3400f41b23b1b --layout pipeline
python3 scripts/macos/test-wrap-controls.py
```

Use the directory printed by a new build for its measurements. The build runner
accepts an installed Docker Buildx plugin instead when `--buildx` is omitted.
Local Buildx URL/hash provenance is in its adjacent `download.json`. Hashing and
compilation should finish before controlled timing proofs. The native macOS
helper has superseded this feasibility path; retain the image as a verified
reference, without hardening it into the production worker.

After acceptance, no containers remained in the dedicated profile; it was
stopped. The original default VM remains running. All new miner and engine
changes are uncommitted, and neither branch was pushed during this work.

## Earlier completed milestones

Updated 2026-11-01. CPU Gates 1/2 and the bounded native hybrid worker milestone
passed. Expanded workloads and twenty consecutive supervised-worker requests
also passed. Segment Poseidon2 Merkle folds run on Metal; complete Groth16
outputs pass the unchanged pinned verifier. The controlled Fibonacci comparison is now complete; broader workload
performance and fault/memory coverage remain open. No production-readiness claim.
No push, privileged installation, wallet access, job claim or transaction.

## Fork publication and future push destinations

On 2026-11-01 the owner explicitly authorized pushing all pending session work
to their forks, superseding the earlier local-only/no-push instruction. Publish
only the `codex/hemi-macos-metal` feature branch in each repository:

* Miner: [dimitryB/zk-miner](https://github.com/dimitryB/zk-miner/tree/codex/hemi-macos-metal).
  The branch includes all nine implementation/validation commits through
  `42c40dfb28b0f40b450d3cd94ed65ba551b65372`, plus this handoff update.
* Pinned engine: [dimitryB/risc0](https://github.com/dimitryB/risc0/tree/codex/hemi-macos-metal)
  at `0d5b41e8e44876c1e8b5a8a671aabc154e33106c`, containing all four task commits
  above pin `f8dcbdf8124a3f1528146bb01d539c55545cbb3d`.

Both implementation repositories use remote `dimitryB` with the corresponding
HTTPS clone URL, `remote.pushDefault=dimitryB`, and this branch's
`pushRemote=dimitryB`. The existing `origin` remotes remain source references;
do not push to them. The standalone upstream `risc0/risc0` reference checkout
remains read-only. No default branch, dependency URL/revision, or proof artifact
was changed for publication, and no force push or pull request is requested.
The GitHub fork default branches are independent of this pinned task branch;
do not merge a newer engine default branch merely to publish this work.

Earlier CPU branch names point at their original baselines; their complete task
work is already included in the Metal branch histories. There were no stashes
or other uncommitted task files to publish. Tracked implementation, scripts,
reports, JSON/CSV evidence and lockfiles are included. Ignored local build caches,
VM/toolchain binaries and raw `target/macos` run artifacts remain local; committed
evidence binds their identities and reproducing them requires the documented
local build/acceptance steps. Earlier “no push” statements describe the local
milestones before this explicit authorization.

## Current completed controlled benchmark

Campaign `f57fcc0ff71d4d6391605cb761c0a1a6` completed on 2026-11-01 in
2234.736s (37.246 minutes): 12 genuine complete Groth16 proofs, 36 negative
verifier rejections, 24 native tests passed, zero failed/ignored or retries.
Two warmups are excluded; all five measured CPU/Metal pairs are retained.
The immutable plan/accepted miner HEAD is `a3342fb80ec2fcfba909f921e381c6636fefb731`;
the containing results commit changes only documentation/evidence. Engine,
production worker/protocol code, pins and sealed CPU/Metal/verifier binaries
remain unchanged. Earlier failed attempt `f8b460…` is retained separately.

Same sealed Metal-capable binary, explicit CPU/Metal modes, Fibonacci(20), po2
cap 18, six threads, 512 KiB staging and the same local emulated Groth16 helper.
Measured worker-body median/range seconds: CPU 165.582 [164.774–166.101], Metal
165.823 [165.439–166.970]. Execution+segment: CPU 2.731 [2.723–2.843], Metal 2.791
[2.723–2.922]. No observed speedup for this fixture. Identity plus wrapping is
about 93.8% of the body; this does not establish performance on larger workloads.
Every Metal proof recorded 194 actual GPU commands (1,164 total); CPU proving
recorded none. Fresh worker startup is timed separately; no persistent warm-
worker or cold-boot claim. No application was closed or guard reduced.

Evidence: `docs/macos/evidence/benchmark-comparison.json/.csv`, companion
`-acceptance.json/.csv`, and `benchmark-comparison-controls.json` (13 reporting
guards passed, zero proofs). Raw runs are bound in the campaign archive and
BENCHMARKS.md reports sample counts, ranges, paired ratios and limitations.
A separate review recomputed results and checked 365 archived artifact hashes,
142 planned source hashes, worker/verifier seals and all 36 negative records.

Memory nuance: the earlier ad hoc `vm_stat` readiness numbers below omitted
speculative pages, so they were conservative proxies, not exact production
policy readings. `benchmark-memory-counter-check.json` verifies the SDK counter
mapping. Production guard/resource records were correct and unchanged; their
observed available range was 25.122–42.469 GiB during this campaign. All 240
thermal snapshots were nominal/AC, with the documented unknown-state caveat;
background fseventsd and other activity remained. No energy/GPU-allocation peak
or broad statistical significance claim is made.

No workers/containers remained after that acceptance campaign. The dedicated VM
was stopped and the original default VM remained running. No privileged
installation, push, wallet access, job claim or transaction occurred during the
campaign. Its proposed follow-up benchmarks are superseded by the implementation
plan above. Broader resource/fault and deployment gates remain open; see
VALIDATION.md for exact commands and unrun checks.

## Earlier benchmark attempt and readiness checks

Readiness recheck on 2026-11-01: policy-estimated available memory was
29.324 GiB with the dedicated VM stopped and 27.596 GiB after restarting it
with the same 6 CPU/32 GiB configuration. This clears the unchanged 22 GiB
startup floor but is below the previous campaign's 32.955 GiB pre-proof level.
That warmup ended at 21.212 GiB (11.743 GiB less; this includes all host and
background activity, not an isolated helper allocation measurement).
A conservative retry target is 36–38 GiB available **with the VM running**,
roughly 8–10 GiB more than this recheck. This is guidance, not a new admission
rule or allocation guarantee. No new proof was launched. `vm_stat`, the existing
Darwin policy formula, `colima list --json`, and the same documented VM start/stop
commands were used. The dedicated VM was stopped again; default remains running.
No code, pins, CPU binaries or resource guards changed; no push or installation.

Instrumentation/runner/thermal helper are locally committed at `461965e` on
`codex/hemi-macos-metal`; the following collector/evidence/documentation commit
records this attempt. Production workers, engine and CPU path remain unchanged.
The first campaign **did not complete**: host memory admission refused Metal
warmup before proving. Do not infer a CPU/Metal speedup from that attempt.

Campaign `f8b460c76d594ae88e6430ab29e1aa27` planned one complete warmup per mode,
then five alternating complete trials per mode. It uses the same sealed
Metal-capable worker in explicit CPU/Metal modes, identical Fibonacci(20), po2 18,
512 KiB staging, six Rayon/helper CPUs, 32 GiB dedicated VM and 24 GiB helper cap.
Fresh WorkerPools receive readiness and execute validation before proving;
startup/setup, exact prove-call latency, external verification and cleanup have
separate monotonic timers. This is neither a cold-boot nor a persistent warm-worker
benchmark. Each successful proof requires unchanged-verifier acceptance and
three tamper rejections; no automatic proof retries or sample removal.

CPU warmup `257de3edef294d10b2f03edda0048d95` completed a real Groth16 proof:
worker total 164.432s, supervisor prove call 164.731s, external verification
39.937ms; all three negatives rejected, zero proving GPU commands. Metal warmup
`dc005b12db1d44a5a98dad07ecb7ed01` failed production admission: 23,597,678,592 bytes
available at the pre-call sample (21.977 GiB), below the unchanged 22 GiB
requirement (6 GiB proof estimate + 16 GiB host reserve). Recycling its small
preflight worker did not free enough memory. No Metal proof/helper started.
Ten measured trials remain unattempted; no comparative statistics are emitted.
Across both runs, 3 actual Rust tests passed, 1 failed, 0 ignored.

Source-bound archive: `docs/macos/evidence/benchmark-attempt-1.json/.csv` and
`benchmark-attempt-1-acceptance.json/.csv`; raw plan, ledger, telemetry and logs
are in `target/macos/benchmarks/f8b460c76d594ae88e6430ab29e1aa27`, with receipts
under `target/macos/worker-runs/<run-id>`. The 13 collector guards passed and
count as zero proofs (`benchmark-summary-controls.json`). Source hashes bind
all inputs; the failed trial and ten unattempted rows are retained.

Host telemetry showed AC power and Foundation nominal/low-power=false; those
API values can also mean unknown. `pmset` had no recorded warnings, not a measured
absence of throttling. Background fseventsd CPU activity was retained (up to
100.4% in decaying `ps` samples). No temperature, wattage or GPU driver-allocation
peak was measured. Available-memory readings stayed around 21.8–21.9 GiB after
the refusal. The user was asked to free roughly 4–8 GiB from unused applications;
no application was closed and no admission guard or resource limit was reduced.

Recovery procedure used for the successful campaign: after headroom recovered,
restart the dedicated VM and rerun the entire campaign, retaining attempt 1.
Do not resume at the failed Metal trial or count the old warmup as a measured
sample. The dedicated VM was stopped after confirming no containers or trial workers
remained; the original default VM is still running. Both worker binaries and
the verifier seal were rechecked, as were 44 raw acceptance artifacts and nine
benchmark artifacts. No installation is required. See SETUP.md for the thermal helper build
and benchmark/collector commands; BENCHMARKS.md and VALIDATION.md record the
attempt and exact timing limits.

## Previously completed workload/stability milestone

The stability changes start at miner
`b871d7ed0f0de83d99cc3e5674bfba95c3f04d7f` and were committed in
`244a3a1eb69e2ed611fa1b52e00abfaae31b32f7`. Worker binaries, production worker/protocol code,
engine, dependency pins and root lock remain unchanged. Changed code is
`crates/zkminer-prover/tests/macos_worker.rs`,
`scripts/macos/test-worker.py`, new `scripts/macos/summarize-worker.py` and
its runnable `test-worker-summary-controls.py` guards.

Four source-bound runs passed: SHA/admission recovery
`71387ac25ac74d4395278a3459680152`; five segments
`3c0b5d8179934bafb482174615a05d22`; minimum 4 KiB staging
`d93743621b584487accb84c7df1833c6`; twenty requests
`28bdd9ca009a4f6eacda4e11df402aed`. Total: **23 complete Groth16 proofs,
69 negative-verifier rejections, 8 actual tests, zero ignored or failed tests**.
All outputs use the unchanged pinned verifier. The logical admission refusal
is separately recorded and never counted as a completed proof.

Twenty consecutive independently verified requests passed in 3341.356s (55.69 minutes),
with zero failed requests. Normal memory-driven recycling used 16 proving processes; the
longest same-PID streak was 2. Proof seconds ranged 157.222–166.442, median 164.845.
Sampled request peaks ranged 1,970,487,296–1,996,292,096 bytes. All twenty outputs
passed 60 tamper rejections and recorded 3,880 completed GPU commands.

The admission test holds real production accounting reservations without
allocating their pages: 107 GiB held, typed attempted=false refusal before any
proof/helper, ledger released to zero, then a complete SHA proof. The five-
segment proof records 1,269 GPU completions; the 4 KiB proof records 16,680
completions with exactly 4,096 bytes peak staging. Physical host-memory pressure,
RSS-limit kills and sustained same-process memory behavior remain untested.

Aggregate evidence: `docs/macos/evidence/worker-stability-validation.json` and
`worker-stability-measurements.csv`; raw run artifacts are under
`target/macos/worker-runs/<id>`. The collector rechecks source-bound acceptance,
raw proof/artifact hashes and resource observations. Nonpositive outer RSS
readings are preserved as unavailable. One-ULP JSON timing round-trip differences
are explicitly recorded; cryptographic fields and counters compare exactly.
No raw proof or measurement file was rewritten to make collection pass.
All 12 collector guards passed separately and count as zero proving tests;
results and prior collection refusals are in `worker-stability-controls.json`.

The dedicated VM is stopped after checking no containers remained. No privileged
installation, push, wallet access, job claim or transaction occurred.

## Repositories and refs

Implementation branch: `codex/hemi-macos-metal` in both implementation worktrees.

* Miner `/Users/dbur/dev/zk-miner`, remote `https://github.com/hemilabs/zk-miner.git`:
  the native-worker checkpoint was based on `3b2720110c1721a53d19c09a6ff2a16235aeb9be`;
  its sealed worker builds remain unchanged for this acceptance-only continuation.
  The stability checkpoint is `244a3a1eb69e2ed611fa1b52e00abfaae31b32f7`; benchmark instrumentation is `461965e`. Resolve the latest local evidence commit with `git log -1`.
* Engine `/Users/dbur/.codex/worktrees/hemi-macos-cpu/risc0`, remote
  `https://github.com/hemilabs/risc0.git`: unchanged during this milestone at
  `0d5b41e8e44876c1e8b5a8a671aabc154e33106c`.
* Supplied Hemi `/Users/dbur/dev/risc0`: clean release-3.0 at
  `6b673a0c26c0c195c1e4c9e59408de25fc434492`.
* Read-only upstream `/Users/dbur/dev/risc0-parent`, remote
  `https://github.com/risc0/risc0.git`: clean main at
  `164c64bb3a844d393bb7addc5781c705c647f2d5`.

Miner pin and independent verifier remain
`f8dcbdf8124a3f1528146bb01d539c55545cbb3d`; the local engine descends from it.
No circuit, field constant, key, proof format, dependency version or pinned
revision changed. The previous native-worker milestone added four existing dependency edges:
metal, risc0-zkp, serde_json and sha2. This continuation leaves Cargo.lock unchanged. No broad updates/upstream import.
CPU checkpoints remain miner `3503563849661f0e99b5ad9c7da7229bd561ea4f` and
engine `e274e19ee6e77bcd5704ca25c9880bd143f0783c`.

## Implemented native worker

One native worker implementation now supports frozen startup `cpu|metal|auto`
selection. Forced Metal requires an isolated, bounded CPU/Metal differential
probe and actual per-segment GPU work; failures do not retry proving on CPU.
CPU explicitly selects LocalProver's CPU path. Auto reports a startup fallback
reason when the Metal feature/device is unavailable. A generic slot serializes
requests; no fake CUDA device or second unified-memory budget is introduced.

Only segment Poseidon2 Merkle folds run on Metal. Witness, leaf hashing, NTTs,
constraints, FRI arithmetic, recursion and identity remain CPU. Staging defaults
to 512 KiB, configurable from 4 KiB through 16 MiB. Final Groth16 still uses the
pinned local Linux/amd64 helper under QEMU emulation. This is not fully native
wrapping. IPC and non-Mac proving branches retain their existing semantics.

Previously committed production implementation: `crates/zkminer-prove-risc0/{Cargo.toml,src/main.rs,
src/macos.rs,src/macos_metal.rs}`, four root lock dependency edges,
`scripts/macos/{build-worker.py,worker_provenance.py,test-worker.py}` and
`crates/zkminer-prover/tests/macos_worker.rs`. Build seals bind worker sources,
local engine revision/diff, actual dependency graph/lock and executable. The
acceptance runner additionally binds the real WorkerPool test and unchanged
verifier. Optional atomic per-request JSON preserves stage evidence before
wrapping, including interrupted requests, without changing positional IPC.

## Earlier native-worker evidence

Native Metal lifecycle run `f8ff5abb2cef4a19bb02e24fbcb318d0` passed:
2 tests, 0 failed, 0 ignored, 777.73 seconds. Four complete Groth16 proofs were
independently verified, with wrong-image, changed-journal and corrupt-seal
rejection each time. Three consecutive proofs used one worker PID; cancellation
and a separate 70-second watchdog killed owned workers only after real wrapping
helpers appeared and Metal work was recorded. Helpers were cleaned, a restart
proof passed, and shutdown left no owned worker/helper. Proof seconds:
163.997, 159.590, 159.140 and 164.465; each has 194 completed GPU dispatches.
Sampled native worker peak was 2,013,675,520 bytes, excluding the VM/helper;
this is a per-PID run peak, not a driver-memory or per-proof growth measurement.

The mode matrix also passed: CPU build/auto (`2b17330c44b84da099de8089a72032aa`,
164.497s) records fallback because it lacks the Metal feature; Metal build/cpu
(`0a20964eec5f4643b0805f52e49a4d44`,164.718s) explicitly stays CPU. Both have
zero GPU proving work. Metal build/auto (`ac9cf5773bf34427925ab5f29ce18ac5`,
164.798s) selects Metal and records 194 completions. Across four runs: seven
complete independently verified proofs (five Metal, two CPU), 21 tamper rejections,
eight actual tests passed, zero ignored. All proofs match program/input hashes,
image, journal, po2 and cycle/segment stats; randomized proof bytes are not compared.
Two mode/deadline unit tests and actual preflight checks passed. Runtime probe equality passed at budgets 4096, 4097,
524288 and 16777216 bytes; invalid lower/upper budgets reject. The full suite
also executes invalid mode, dev/skip-verification, malformed/out-of-range budget,
missing helper, protocol mismatch and invalid guest checks.

Prior source-bound harness evidence remains valid: 235 differential/bridge
cases, 451 actual GPU commands; two complete hybrid Fibonacci proofs and one
five-segment hybrid proof; independent CPU regression and earlier CPU hash/
multi-segment/worker acceptance. See VALIDATION.md and evidence/hybrid-validation.json.
These earlier workload results do not imply the new native worker ran them.

## Environment and reproduction

Discovered Mac17,6 Apple M5 Max, 18 CPU/40 GPU cores, 128 GiB unified memory,
macOS/SDK26.4. No manual installation is needed: the Metal runtime compiler
works without Xcode.app or `xcrun metal`, both still absent. Ask before any
future privileged installation. Host Rust1.93.0 and guest r0.1.88.0 are task-local.

From `/Users/dbur/dev/zk-miner`:

```sh
export HEMI_MINER_DIR=/Users/dbur/dev/zk-miner
source scripts/macos/env.sh
ENGINE_DIR=/Users/dbur/.codex/worktrees/hemi-macos-cpu/risc0
ENGINE_REV=0d5b41e8e44876c1e8b5a8a671aabc154e33106c
python3 scripts/macos/build-worker.py --mode metal --engine "$ENGINE_DIR" --config target/macos/local-engine.toml --revision "$ENGINE_REV"
python3 scripts/macos/build-worker.py --mode cpu --engine "$ENGINE_DIR" --config target/macos/local-engine.toml --revision "$ENGINE_REV"
python3 scripts/macos/test-worker.py --engine "$ENGINE_DIR" --worker-kind metal --mode metal --context colima-hemi-macos-cpu --repeat 3
```

SETUP.md documents local source generation, verifier build and dedicated VM
restart. CPU and Metal workers have the same basename in separate `worker` and
`worker-metal` target dirs; never substitute the build under an existing seal.
The verifier target is separate, built from original Git pin without local
patches/proving features. Raw runs, seals and logs are under
`target/macos/worker-runs/<id>`; aggregate evidence is `docs/macos/evidence/native-worker-validation.json` and
`native-worker-measurements.csv`, with executed commands in VALIDATION.md.
The current separate miner diff is `target/macos/benchmark-comparison-miner.patch`
from `a3342fb`; `target/macos/benchmark-comparison-engine.patch` is empty. The
earlier tooling diff remains `target/macos/benchmark-miner.patch` from `244a3a1`.
The earlier stability diff remains `target/macos/worker-stability-miner.patch`. Previous engine patches remain under
docs/macos/evidence. Source changes require rebuilding sealed artifacts.

Dedicated profile `hemi-macos-cpu` / context `colima-hemi-macos-cpu` is
stopped after acceptance and confirming no containers remained. It has 6 CPUs,
32 GiB VM RAM,80 GiB disk; each helper is
capped at 24 GiB/6 CPUs with network disabled. Original Colima is untouched.
Pinned helper image digest:
`sha256:a4f80ce2e0b8e2bb7637a93c37136a6776ac00ec843a3fdf1c67b1d5ffea64ee`.

## Next work and limits

Next concrete step: extend controlled comparisons to the already validated hash
and multi-segment workloads. The Fibonacci campaign is complete; its earlier
admission failure remains archived separately. Benchmark/calibration IPC
acceptance remains separate. The completed twenty-request run retained normal
recycling; longer same-process and physical-memory-pressure recovery coverage
remain open. Earlier correctness-run timings remain separate from the completed
fixed-setting Fibonacci benchmark above.

GPU hardware-fault recovery, driver allocation peaks/growth trends and full
Linux/CUDA/ROCm runtime regression remain unrun. Optional offline Linux CUDA
metadata failed on uncached `approx v0.5.1`; it is not a passed build. Pinned
`lift_rv32im_v2_13.zkr` remains unavailable, so earlier supported multi-segment
coverage uses po2 16. Do not regenerate keys or substitute artifacts. Exact
contract-adapter/deployed verifier acceptance and network mining remain separate,
unrun and unauthorized. No speedup or production-readiness claim is made.
