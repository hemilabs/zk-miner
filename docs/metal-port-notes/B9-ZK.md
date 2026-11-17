# B9-ZK: zk-miner on risc0 3.1, finished for the beta

Branch `item/B9-ZK` (worktree `/Users/user/zkminer/zk-miner-3.1-wt-B9-ZK`), from `metal-3.1` `0e57ab4`. The
`[patch.crates-io]` lines (`../deps/risc0-3.1/...`) resolve from the worktree to
`/Users/user/zkminer/deps/risc0-3.1` (`zkminer/metal-3.1` at `d94ef6501`, which includes B9-4G, B9-G1 and
B9-SEC). The release build is `--locked`, so `Cargo.lock` is unchanged. Wave 9 is the beta and does no
performance work. Scratch and logs are in `/Users/user/zkminer/scratch/w9/B9-ZK/`:
- `bin/worker-A`: `metal-3.1` unmodified, built against the same risc0 tree. `bin/worker-B`: this item.
- `ab/{4g,8g,def}` and `scripts/{ab.sh,ana.py}`: the A/B runs and their analysis.
- `ipc/`: the IPC sequence runs.
- `sv/`: receipts and the stock-verifier run.
- `gates/`: the test gates.

No Metal kernel and no risc0 file changed, so R17 (`ir_scan.py`, `run_stress.sh`) does not apply.

## Summary

| sub-track | result |
|---|---|
| (1) 4 GiB worker, keccak, key release | No functional change was needed. The risc0 B9-4G fix alone lets the unmodified worker wrap at 4 GiB after warm-up and after keccak jobs (profile below). Added: one log line per Groth16 key release, giving the MiB freed, the prover layout that size identifies, and the device allocation after the release. Also a new IPC test of the sequence warm-up -> fibonacci -> keccak -> rv32im -> fibonacci, every job wrapped, which checks one release per wrap. `GROTH16_PLAN_FALLBACK` refreshed (4235118872 B -> 3886 MiB). |
| (2) README and docs | Updated for 3.1: fork path and branch, v0.2.0 component directory and sizes, a section on the 3.1 verifier and selector, the tier table with 3.1 measurements, the 4 GiB tier now wrapping, beta/unsigned, and the keccak prewarm knob. The `dispatcher.rs` comment now gives 2.4 GB download / 5.4 GB installed. |
| (3) macOS-incompatible capture test | `proc::capture_tests::a_persistently_busy_executable_is_reported_transient` is `#[cfg(target_os = "linux")]`. `zkminer-prover-protocol` passes 42/42 on macOS. |
| (4) 3.1 verifier pin | `pins::RISC0_V3_1_SELECTOR` (`e71e6620`, derived from the 3.1 parameters and tested against the linked risc0). `pins::RISC0_V3_1_GROTH16_VERIFIER: Option<B256> = None` is the place to fill in. `verify_proof_system` picks the verifier pin by seal selector. Startup logs `PAGE: risczero.groth16.v1 cannot be served yet — ...` naming exactly what is missing. No address or hash was invented. |
| (5) worker/CLI version-skew check | Unchanged. `worker_lifecycle::a_worker_on_another_risc0_or_protocol_is_refused_at_the_handshake` passes, twice. |

## Profile before (worker A = `metal-3.1` 0e57ab4 on risc0-3.1 d94ef6501)

- `BENCH_ONLY=fibonacci --benchmark` at 4 GiB (`logs/profA_fib_4g.log`):
  - The startup pipeline build includes keccak: "keccak 0.0 s". Since B9-4G the `auto` rule sees a 3885 MiB plan.
  - Wrap 1.72 s, verified. GPU wrap peak 3944 MiB. 62 MiB held after the release.
- The new IPC sequence test, run against worker A (`ZKMINER_B9_WORKER=bin/worker-A`, 4 GiB, `ipc/ipcA_4g.log`):
  - Warm-up wrap, fibonacci (1,179,648 cycles), keccak (`multi_test` `KeccakUnion(1)`), memory-merkle and fibonacci all proved, wrapped and verified (each Groth16 seal 256 bytes).
  - Wrap peaks 3944 / 3976 (keccak job) / 3944 / 3944 MiB. 61.9 MiB held after each proof.
- So item (1)'s acceptance holds with B9-4G alone; zk-miner needed no fix. What the unmodified worker did not show was *what* it released and in which layout. B9-4G's open items 1 and 8 asked for that, at both tiers.

## (1) Changes

- `metal_host::log_groth16_release(before, after)`, called by `release_groth16_cache_if_tight` around
  `release_srs` (the worker's per-proof release whenever `metal_sizing::keep_groth16_cache` says no:
  below about 29.5 GiB at po2 20, so on the Metal default of this 36 GB Mac too). It
  logs one line per release:
  `Groth16 proving key released: 3882.3 MiB of device memory freed (prover layout split_h + tw_lent, tw_prefault on; planned whole 4141.0, split_h 4010.9, whole + tw_lent 4013.0, split_h + tw_lent 3885.0 MiB), device allocation now 61.9 MiB`.
  - The layout comes from the freed size: the nearest of the four forced-layout plans
    (`risc0_groth16_sys::metal::prover::planned_bytes` with `split_h` / `tw_lent` forced, header
    reads only). They are read once in `warm_up_pipelines`, so no proof waits for them.
  - Two layouts within 8 MiB of each other are both named. That only happens between split_h and
    whole + tw_lent. Since fix round 1 only the layouts `choose_layout` can take under the process's
    switches are candidates, so under `auto` (where whole + tw_lent is never taken) a split_h release
    is named split_h alone.
  - The cost is two `currentAllocatedSize` reads per proof.
  - The line is not hidden behind a knob because it is a log line. A/B below: no change.
- `GROTH16_PLAN_FALLBACK` (the plan assumed while the component is not installed yet) changed from
  4235118872 B (pre-B9-4G) to 3886 MiB (the 3885.0 MiB split_h + tw_lent plan, rounded up).
  - A host upgraded from 3.0 at 4 GiB now builds keccak at start, the same as a host whose plan is known.
  - Limits below about 3.9 GiB still defer keccak.
  - Unit test updated: 4 GiB with an unknown plan builds keccak; 3900 MiB defers it.
  - The knob `ZKMINER_METAL_PREWARM_KECCAK=off` still defers keccak.
- `--export-guest memory-merkle` (test aid for the new IPC test).

### What the release line shows (B9-4G open items 1 and 8)

| tier | layout logged | freed | after | runs |
|---|---|---|---|---|
| 4 GiB | `split_h + tw_lent, tw_prefault on` | 3882.3 MiB | 61.9 MiB | every wrap of the IPC sequence (5/5, three runs) and of 8 `--benchmark` runs |
| 8 GiB | `whole` | 4138.1 MiB | 62.0-62.2 MiB | every wrap of the IPC sequence (5/5, two runs) and of 8 `--benchmark` runs |
| default (28.1 GiB) | `whole` | 4138.1 MiB | 61.9 MiB | `--benchmark` (this Mac's tier releases the key there too) |
| 4300 MiB (round 1) | `split_h` | 4008.0 MiB | 61.9 MiB | IPC sequence 5/5 (round 0 build logged `split_h or whole + tw_lent, tw_prefault on`) |

At 8 GiB the worker never fell into B9-4G's 4141-4269 MiB split window in these runs, keccak jobs
included. The line will show it in the field if it ever does.

### IPC sequence test (new): `metal_worker::a_tight_worker_wraps_after_keccak_and_releases_the_key_between_jobs`

- One worker at `RISC0_METAL_MAX_WORKING_SET_BYTES` = 4 GiB. `ZKMINER_B9_BUDGET=<bytes>` selects any other limit at which the worker releases the key (the test asserts that with `metal_sizing::keep_groth16_cache`).
- Sequence: Warmup (all pipelines including keccak, then a verified Groth16 proof), then four jobs, each wrapped:
  - fibonacci 100000;
  - keccak: the fork's `multi_test.bin` with `KeccakUnion(1)` (serde words `[16, 1, 0]`; override with `ZKMINER_B9_KECCAK_ELF`);
  - rv32im: memory-merkle 64;
  - fibonacci 1000.
- Every seal is a 256-byte Groth16 proof, and the worker verifies each receipt before it answers.
- The worker's stderr must show 5 releases. Each must:
  - free more than 3800 MiB;
  - name the tier's layout (4 GiB: split_h + tw_lent; 8 GiB: whole);
  - leave less than 256 MiB allocated.
- Results:
  - 4 GiB, pass, 3 runs (`ipc/ipcB_4294967296.log`, `ipc/ipc_all_final.log`). Jobs 4.03 / 4.88 / 3.78 / 1.92 s.
  - 8 GiB, pass, 2 runs (`ipc/ipcB_8589934592.log`, `ipc/ipc_8g_final.log`).
  - Worker A runs the same jobs. Its release checks are skipped because A does not log releases.
- This confirms P31-14 open issue 2 as far as zk-miner is concerned: the worker releases the key between jobs at 4 and 8 GiB. Two wraps with the key kept still do not fit at 4 GiB (B9-4G). The worker never does that below the keep threshold (about 29.5 GiB at po2 20).

## A/B (interleaved, A = metal-3.1 unmodified, B = this item, one discarded launch per arm, 7 pairs, order alternating)

`BENCH_ONLY=memory-merkle --benchmark`, `gpu-run --budget 4G | 8G | --no-budget`, `/usr/bin/time -l`.
Medians [min-max]; B-A per pair, with the count of pairs where B > A.

| budget | STARK A | STARK B | B-A | wrap A / B | B-A wrap | footprint A / B GB | load |
|---|---|---|---|---|---|---|---|
| 4 GiB (po2 18) | 13.930 [13.910-13.960] | 13.930 [13.900-13.950] | +0.000 [-0.030, +0.040] (2/7) | 1.73 / 1.73 | +0.000 [-0.010, 0] (0/7) | 4.933 / 4.929 | 2.3-4.4 |
| 8 GiB (po2 19) | 10.250 [10.190-10.260] | 10.240 [10.230-10.290] | +0.010 [-0.010, +0.040] (4/7) | 1.75 / 1.75 | +0.000 [0, +0.010] (2/7) | 7.325 / 7.326 | 1.6-2.2 |
| default (po2 20) | 8.370 [8.340-8.400] | 8.390 [8.350-8.400] | +0.010 [-0.040, +0.060] (4/7) | 1.59 / 1.59 | +0.000 [-0.010, 0] (0/7) | 13.204 / 13.204 | 1.7-2.2 |

- No change at any budget. Each B-A median is within the pairs' own spread (no A-vs-A arm was run; the arms' min-max ranges overlap).
- Against BASELINES '3.1': 4 GiB 13.92 s / 603K c/s (here 602K); 8 GiB 10.22 s / 770K (here 768K); default 8.35 s (here 8.37-8.39 s, both arms). Wrap 1.72-1.75 / 1.59 s.
- Footprint at 4 GiB is 4.93 GB, against BASELINES 5.02 GB. That drop comes from risc0 B9-4G's 126 MiB smaller key layout, and it is equal in both arms.
- GPU peaks of B (MiB, segments / recursion / wrap): 4 GiB 2404 / 2199 / 3944; 8 GiB 4738 / 4337 / 5635; default 9437 / 9437 / 5635.
- No peak rises.

## Correctness

| gate | result |
|---|---|
| `cargo test -p zkminer-prove-risc0 --features metal` (gpu-run heavy) | 61 passed (+4 ignored), **twice** |
| `cargo test -p zkminer-prover --features testing --test worker_lifecycle` | 27 passed, 3 ignored, **twice** (includes the P31-19 skew test) |
| `cargo test -p zkminer-prover --lib` | 291 passed, 1 ignored, **twice** |
| `cargo test -p zkminer-cli --bin zkminer` | 142 passed, twice (new: `the_3_1_verifier_pin_slot_matches_the_linked_risc0`) |
| `cargo test -p zkminer-chain --lib` | 152 passed, 1 ignored, twice (new: `the_risc0_verifier_pin_follows_the_selector`) |
| `cargo test -p zkminer-prover-protocol` | 42 passed, twice (the ETXTBSY test is now Linux-only) |
| `cargo test -p zkminer-cli --test localnet --no-run` | compiles. The localnet suite was **not run**: no anvil/forge here |
| `metal_worker -- --ignored` (release) | 4 passed: warm-up + prove, first prove without warm-up, M9 10 proofs, the new B9 sequence at 4 GiB; the B9 sequence at 8 GiB also passes |
| release build `--locked` (worker `--features metal`, CLI) | OK. Warnings only pre-existing (`stark_peak_bytes`, `parse_nvidia_power_csv` ... never used) |
| stock crates.io 3.1.0 verifier (`stock-verify31` built unmodified in `scratch/w8/baseline/target-stock`) on worker B's Groth16 receipts (`ZKMINER_BENCH_RECEIPT_DIR`): fibonacci and memory-merkle at 4 GiB and 8 GiB | **4/4 STOCK 3.1 VERIFY: OK**, selector `e71e6620` (`sv/stock_verify.log`) |
| 3.0 receipts rejected | not re-run: no prover path changed. B9-4G's matrix at this risc0 HEAD rejects 30/30 (plain and relabelled) |

## (4) The 3.1 on-chain verifier: what is ready, what is missing

- `zkminer-chain/src/deployment.rs`:
  - `pins::RISC0_V3_1_SELECTOR = e71e6620`, documented as derived from the 3.1 verifier parameters.
    The CLI test ties it to `risc0_groth16_default_selector()`.
  - `pins::RISC0_V3_1_GROTH16_VERIFIER: Option<B256> = None`. The doc says to fill it from the
    audited deployment's `VerifierPins.sol` and never from anything else.
  - `risc0_verifier_pin(selector)` picks the pin by selector:
    - 3.0 seals get the v3.0 pin;
    - 3.1 seals get the 3.1 pin, or the missing-verifier message while it is `None`;
    - any other selector is refused.
  - `verify_proof_system` uses it in place of the hard 3.0 pin. Before, a 3.1 verifier would have
    failed the code-pin check as "not the audited risc0-ethereum v3.0 verifier".
  - `risc0_v3_1_verifier_missing()` says exactly what is missing:
    1. a risc0-ethereum 3.1 `RiscZeroGroth16Verifier` (SELECTOR 0xe71e6620) deployed and routed by
       the `risczero.groth16.v1` adapter;
    2. its runtime keccak in `RISC0_V3_1_GROTH16_VERIFIER` (file named), and a rebuilt zkminer.

    It also says that no risc0 job is claimed meanwhile and that held locks are still driven.
- `zkminer-cli/src/commands/run.rs`: at startup, before the risc0 adapter check,
  `risc0_verifier_pin_startup_notice` logs
  `PAGE: risczero.groth16.v1 cannot be served yet — <that message>`.
  - It is not logged when the code pins are skipped (`ZKMINER_SKIP_CODE_PINS=1`).
  - It is not logged when a selector override is already refused (that refusal is reported instead).
  - The adapter check then refuses with the same text, and `risc0_claimable` stays false. This is the
    existing non-fatal path, so held locks are still recovered.
- `zkminer-cli/tests/localnet.rs` (doc only): while the pin is empty, a `ZKMINER_LOCALNET_FORCE_RISC0=1`
  run against a 3.1 verifier also needs `ZKMINER_SKIP_CODE_PINS=1`.
- The adapter pin (`RISC0_GROTH16_ADAPTER`, immutables zeroed) is unchanged. A 3.1 deployment that
  reuses the audited adapter code passes it. A new adapter contract would need its own pin.

## Fix round 1 (review findings)

Base for the round: adae4e0 (round 0). Logs: `scratch/w9/B9-ZK/r1/`.

- **Blocking: README claimed the Metal worker keeps the Groth16 key from 20 GiB up.** Wrong: the
  worker keeps it only when `metal_sizing::keep_groth16_cache(limit, po2)` holds, i.e.
  `limit >= stark_peak_bytes(po2) + GROTH16_RESIDENT_BYTES + KEEP_HEADROOM_BYTES` (12 GiB + 5.52 GiB +
  12 GiB, about 29.5 GiB at po2 20). The 20 GiB figure is the CUDA `RELEASE_GROTH16_CACHE_BELOW_BYTES`
  path. Evidence it was wrong: this note's own release table (the 28.1 GiB default releases the key),
  and every round-1 unbudgeted A/B run logs a release. Fixed: README "Performance" paragraph and the
  Groth16 paragraph now state the real rule and name `keep_groth16_cache`; 36 GB Macs and smaller
  release the key after every proof. The IPC test's doc and its guard no longer say 20 GiB: the guard
  now calls `zkminer_prover::metal_sizing::keep_groth16_cache(budget, job_po2_for_limit(budget))`, the
  same rule the worker applies, so it can no longer drift from the code.
- README: the "six-program benchmark takes ~19 minutes" line now says about 3 minutes (177-180 s of
  wall per BASELINES '3.1', 169.6 s STARK plus six wraps).
- **Release line tie (non-blocking finding, reproduced first).** At a 4300 MiB budget
  (`ZKMINER_B9_BUDGET=4508876800`) the round-0 worker logged `split_h or whole + tw_lent, tw_prefault
  on` and the IPC test failed on its layout assertion. Reproduced with the round-0 worker binary under
  the new test (`r1/ipc_4300_oldB.log`: panics "one named layout expected", 6 such lines). Fix: the
  candidate plans are only the layouts `choose_layout` can build under the process's switches
  (`groth16_layout_reachable`: a forced switch admits only its side; under auto/auto whole + tw_lent
  is never taken, because its plan (4013.0) is above split_h's (4010.9), which is tried first). The
  `tw_prefault` suffix is printed only when every named layout lends the twiddles. Unit tests
  `a_released_prover_is_named_by_its_size` (extended) and `a_forced_layout_switch_admits_only_its_side`.
  Round-1 worker at 4300 MiB: 5/5 releases named `split_h`, 4008.0 MiB freed, test passes
  (`r1/ipc_4508876800.log`).
- **IPC test at budgets other than 4 / 8 GiB.** The expected layout was picked by `budget <= 5 GiB`. It
  now names the layout only at exactly 4 GiB (split_h + tw_lent) and 8 GiB (whole); at any other
  budget each release must name exactly one layout (not a tie, not `unidentified`). Passes at 4 GiB,
  4300 MiB and 8 GiB.
- **`GROTH16_PLAN_FALLBACK` assumed the default switches.** With `RISC0_G16_METAL_SPLIT_H` /
  `RISC0_G16_METAL_TW_LENT` forced (or `RISC0_G16_METAL_G10=0`) the real plan can be up to whole's
  4141.0 MiB. `groth16_plan_fallback()` now takes 3886 MiB under auto/auto and
  `GROTH16_PLAN_FALLBACK_FORCED` = 4142 MiB otherwise, so a 4 GiB host with a forced layout and no
  component yet defers keccak. Unit test `the_keccak_fallback_plan_follows_the_layout_switches`. Not
  exercised end to end with the component absent (that run would download the 2.4 GB component).
- **localnet gate followed the 3.0 selector.** `risc0_proofs_verify_on_the_fork` now gates on
  `deployment::risc0_verifier_pin(build_selector()).is_ok()`, so it opens by itself once
  `RISC0_V3_1_GROTH16_VERIFIER` is filled. The stale doc comments (refusal "from the verifier's
  `SELECTOR()`") now say that while the 3.1 pin is empty the refusal comes from the empty pin, before
  any eth_call. Compiles (`--no-run`); the suite still cannot run here (no anvil/forge).
- Not changed, on purpose: reading the real `BuildStats` instead of inferring the layout needs risc0
  to expose the cached prover's stats through `risc0-groth16`; that is a fork change outside this item
  (open issue 8). The test's parsing of the log text and the unlocked read-only run.rs test are as the
  review accepted.

### Round 1 gates

| gate | result |
|---|---|
| `gpu-run -- cargo test --locked -p zkminer-prove-risc0 --features metal` x2 | 63 passed, 4 ignored, both (`r1/prove_risc0_{1,2}.log`) |
| `gpu-run -- cargo test -p zkminer-prover --features testing --test worker_lifecycle` x2 | 27 passed, 3 ignored, both |
| `gpu-run -- cargo test -p zkminer-prover --lib` x2 | 291 passed, 1 ignored, both |
| `cargo test -p zkminer-cli --bin zkminer` x2 / `zkminer-chain --lib` x2 / `zkminer-prover-protocol` x2 | 142 / 152 (1 ignored) / 42, both |
| `cargo build --release --locked` (worker `--features metal`, zkminer-cli) | clean (pre-existing never-used warning only) |
| IPC sequence (release, `--ignored`) at 4 GiB / 4300 MiB / 8 GiB | pass: 5/5 releases `split_h + tw_lent` 3882.3 / `split_h` 4008.0 / `whole` 4138.1 MiB, 61.9 MiB left |

One earlier `zkminer-prover-protocol` run in this round failed 8 of 42 tests; its log was overwritten
before I read it, so the cause is unknown. The same command then passed 7 times in a row (logs
`r1/proto_{1..5}.log` and two more). It runs no code this round changed.

### Round 1 A/B (A = metal-3.1 0e57ab4 unmodified worker, B1 = this round; one discarded launch per arm, 7 pairs, order alternating, `memory-merkle --benchmark`)

| budget | STARK s A | STARK s B1 | B1-A median [min, max] | wrap A / B1 | footprint A / B1 | load |
|---|---|---|---|---|---|---|
| 4 GiB | 13.900 [13.880-13.930] | 13.910 [13.880-13.930] | +0.010 [-0.030, +0.050], 4/7 | 1.72 / 1.72 s | 4.925 / 4.925 GB | 1.6-3.1 |
| 8 GiB | 10.220 [10.210-10.260] | 10.230 [10.170-10.280] | -0.010 [-0.040, +0.040], 3/7 | 1.74 / 1.74 s | 7.326 / 7.325 GB | 2.1-3.4 |
| 16 GiB (gpu-run's default budget now) | 8.410 [8.370-8.430] | 8.390 [8.350-8.440] | -0.040 [-0.060, +0.040], 3/7 | 1.74 / 1.74 s | 12.374 / 12.374 GB | 2.0-2.9 |
| none (`--no-budget`, 28.1 GiB) | 8.350 [8.340-8.370] | 8.340 [8.330-8.390] | -0.010 [-0.040, +0.030], 3/7 | 1.58 / 1.58 s | 13.204 / 13.203 GB | 1.6-1.9 |

No change at any budget; all 56 runs verified. Against BASELINES '3.1': 4 GiB 603K c/s (603K), 8 GiB
769K (767-770K), unbudgeted 8.34 s / wrap 1.58 s (8.35 s / 1.57-1.59 s). No peak rises.

## Fix round 2 (review findings)

### Blocking: the keccak prewarm unit test depended on the layout revert knobs (fixed)

Round 1 made `keccak_prewarm_refusal(.., None)` resolve the unknown Groth16 plan through
`groth16_plan_fallback()`, which reads `MemOptions::from_env()`. With `RISC0_G16_METAL_SPLIT_H=on`,
`RISC0_G16_METAL_TW_LENT=off` or `RISC0_G16_METAL_G10=0` the fallback becomes
`GROTH16_PLAN_FALLBACK_FORCED` (4142 MiB), and the test's
`keccak_prewarm_refusal(None, Some(4 GiB), 46 MiB, None) == None` fails (46 + 4142 + 32 > 4096).

- Reproduced first, on the round-1 debug test binary: each of the three knobs fails exactly
  `the_keccak_prewarm_yields_to_the_groth16_prover_under_a_tight_limit` (62 passed, 1 failed;
  `r2/repro_{RISC0_G16_METAL_SPLIT_H,RISC0_G16_METAL_G10,RISC0_G16_METAL_TW_LENT}.log`).
- Fix at the root: `keccak_prewarm_refusal` is pure again. It takes the fallback as an explicit
  argument (`fallback: u64`); both production call sites in `warm_up_pipelines` pass
  `groth16_plan_fallback()`, so behaviour is unchanged. The test names the default fallback
  (`GROTH16_PLAN_FALLBACK`) explicitly. `the_keccak_fallback_plan_follows_the_layout_switches` now
  also checks that an unknown plan with the forced fallback defers keccak at 4 GiB and the default
  one builds it.
- The env-reading path keeps its own test, `the_process_fallback_plan_reads_the_layout_knobs`: with
  none of `RISC0_G16_METAL_{G10,G10_OFF,SPLIT_H,TW_LENT}` set it must be `GROTH16_PLAN_FALLBACK`;
  with any set, one of the two; and the 4 GiB decision must follow whichever it is.
- After the fix the suite (64 tests) passes with no knob and with each of `RISC0_G16_METAL_SPLIT_H=on`,
  `RISC0_G16_METAL_G10=0`, `RISC0_G16_METAL_TW_LENT=off` and `RISC0_G16_METAL_G10_OFF=compact`
  (`r2/fixed_*.log`).

### Non-blocking items addressed

- `GROTH16_PLAN_FALLBACK_FORCED`'s doc comment now says it covers the split_h/tw_lent switches only:
  with compact, mmap or alias off (`RISC0_G16_METAL_G10=0`, the G9 layout, or
  `RISC0_G16_METAL_G10_OFF=compact|alias`) the real plan is about 1.3 GB larger and both fallbacks
  understate it. That matters only before the component is installed and with a debug knob set, so
  no code change.
- IPC test `a_tight_worker_wraps_after_keccak_and_releases_the_key_between_jobs`: the per-tier layout
  name (4 GiB: split_h + tw_lent, 8 GiB: whole) is checked only under the default switches. With any
  `RISC0_G16_METAL_{G10,G10_OFF,SPLIT_H,TW_LENT}` set, every release must still name exactly one
  layout. The reviewer's failing case, `RISC0_G16_METAL_SPLIT_H=off` at 4 GiB, now passes: 5/5
  releases `whole + tw_lent`, 4010.3 MiB freed (`r2/ipc_4g_splitoff.log`).
- README: the two long lines from round 1 are wrapped; the Makefile table's `mac-bench` says about 3
  minutes instead of ~19; the stale test counts in the `mac-test-miner` / `mac-test-risc0` rows are
  removed (they went stale with every item).
- localnet.rs doc comments: while the 3.1 pin is empty, the refusal comes after the registry/adapter
  reads and before the verifier's `SELECTOR()` call, not "before any eth_call".
- `rustfmt` on `metal_host.rs` also removed two pre-existing format drifts in that file.
- Still open (needs a risc0 fork change): reading the real `BuildStats` for the release line.

How to run the IPC test (for the beta checklist):

    cargo test --release --locked -p zkminer-prove-risc0 --features metal --test metal_worker --no-run
    gpu-run --tag <who> --budget 4294967296 -- <metal_worker binary> --ignored --nocapture --test-threads=1 a_tight_worker
    gpu-run --tag <who> --budget 8589934592 -- env ZKMINER_B9_BUDGET=8589934592 <metal_worker binary> --ignored --nocapture --test-threads=1 a_tight_worker

The worker's budget comes from `ZKMINER_B9_BUDGET` (default 4 GiB), not from gpu-run's `--budget`.
A run with only `--budget 8589934592` proves at 4 GiB (`r2/ipc_8g_wrongenv_ran4g.log`).

### Round 2 gates (logs in `scratch/w9/B9-ZK/r2/`)

| gate | result |
|---|---|
| `gpu-run -- cargo test --locked -p zkminer-prove-risc0 --features metal` x2 | 64 passed, 4 ignored, both (`prove_risc0_{1,2}.log`) |
| the same unit binary under each of 4 Groth16 layout knobs | 64 passed each (`fixed_*.log`) |
| `gpu-run -- cargo test -p zkminer-prover --features testing --test worker_lifecycle` x2 | 27 passed, 3 ignored, both |
| `gpu-run -- cargo test -p zkminer-prover --lib` x2 | 291 passed, 1 ignored, both |
| `cargo build --release --locked` (worker `--features metal`, zkminer-cli) | clean (pre-existing warnings only) |
| `cargo test -p zkminer-cli --test localnet --no-run` | compiles (anvil/forge not installed) |
| IPC sequence at 4 GiB / 8 GiB / 4 GiB with `RISC0_G16_METAL_SPLIT_H=off` | pass: 5/5 releases `split_h + tw_lent` 3882.3 / `whole` 4138.1 / `whole + tw_lent` 4010.3 MiB |

### Round 2 A/B (A = metal-3.1 0e57ab4 unmodified worker, B2 = this round; one discarded launch per arm, 7 pairs, order alternating, `memory-merkle --benchmark`)

| budget | STARK s A | STARK s B2 | B2-A median [min, max] | wrap A / B2 | footprint A / B2 | load |
|---|---|---|---|---|---|---|
| 4 GiB | 13.910 [13.890-13.910] | 13.910 [13.890-13.940] | +0.010 [-0.020, +0.030], 4/7 | 1.73 / 1.72 s | 4.926 / 4.928 GB | 1.9-2.8 |
| 8 GiB | 10.240 [10.210-10.280] | 10.240 [10.210-10.280] | +0.000 [-0.030, +0.030], 2/7 | 1.74 / 1.74 s | 7.326 / 7.326 GB | 1.7-2.6 |
| none (`--no-budget`, 28.1 GiB) | 8.340 [8.320-8.360] | 8.340 [8.310-8.390] | +0.000 [-0.040, +0.050], 3/7 | 1.59 / 1.59 s | 13.203 / 13.203 GB | 1.6-2.2 |

No change at any budget; all 42 runs verified. Against BASELINES '3.1': 4 GiB ~603K c/s (603K),
8 GiB 765-768K (767K), unbudgeted 8.34 s / wrap 1.59 s (8.35 s / 1.57-1.59 s). No peak rises. The
round's only product-code change is an argument passed at worker start, off every proof's path.

## Knobs

- New: none.
- Existing knobs that apply:
  - `ZKMINER_METAL_PREWARM_KECCAK=auto|on|off`. Its `auto` fallback plan is refreshed.
  - `ZKMINER_SKIP_CODE_PINS=1`: skips every code pin, including the 3.1 notice.
  - risc0's `RISC0_G16_METAL_TW_LENT` / `_TW_PREFAULT` / `_SPLIT_H`: they change the layout that the release line reports.

## Open issues

1. **On-chain (user/org action):** deploy the risc0-ethereum 3.1 `RiscZeroGroth16Verifier`, route
   `risczero.groth16.v1` to it, and fill `RISC0_V3_1_GROTH16_VERIFIER` from the audited pin file. Until
   then a beta miner claims no risc0 job on 743111, by design.
2. `hemiprove-abi/INTERACTION_GUIDE.md` (not owned here) already describes 3.1's selector and says no
   3.1 verifier is deployed (P31-19). It needs an update when the verifier is deployed: the new
   verifier's address and pin, and prover checklist step 8.
3. The localnet suite (anvil/forge) has never run against the 3.1 build, here or in P31-19.
4. Not measured on a real 16 GB Mac. The 4 GiB and 8 GiB tiers are simulated budgets on the M5 Max.
   B9-4G's +2 ms per wrap at 4 GiB on a Mac whose witness is slower than the key load is unchanged.
5. The IPC sequence test's keccak guest is the fork's `multi_test.bin` from the fork's target dir. zk-miner
   ships no guest that uses the keccak precompile, so the test needs that file (or `ZKMINER_B9_KECCAK_ELF`).
6. The footprint saving of B9-G1's graph release (`MallocLargeCache=0`, tier table `r2`) remains off in
   the beta (`w7` default). That is a separate zk-miner decision.
7. The P31-19 open issues closed here are: 4 (dispatcher comment), 7 (README), 8 (capture test), and
   2 (deployment pins: the 3.1 slot is ready but empty).
8. The release line infers the layout from the freed size; the exact `BuildStats` (`split_h`,
   `tw_lent`, `tw_prefault`) live on groth16-sys's cached prover and are not exposed through
   `risc0-groth16`. Exposing them is a risc0 fork change. The `tw_prefault` suffix reports the knob.
9. Already present before this item: at a 3963 MiB budget Warmup verifies a Groth16 proof but every
   Prove is refused as ResourceExhausted (po2 18 needs ~4.0 GiB), so such a Mac passes warm-up and
   takes no jobs (review observation).
10. The run.rs startup PAGE about the missing 3.1 verifier is logged even when no risc0 worker is
    configured, as the existing `reverify_risc0` PAGE is.
11. The IPC sequence test is `#[ignore]` (it proves on the GPU), so it is not in the default gate; its
    run commands are in "Fix round 2". It hard-codes the default-switch layouts at exactly 4 and 8 GiB.
12. `GROTH16_PLAN_FALLBACK` / `_FORCED` are the v0.2.0 key's measured plans; they go stale if the key
    or the layouts change, and they understate the plan with compact/mmap/alias off (see round 2).
13. The `zkminer-prover-protocol` 8/42 failure from round 1 was not reproduced by the reviewer
    (14 runs) or since; the lost log may have been a harness quoting mistake like the
    `r1/repro_zkminer-{cli,chain}.log` ones.
