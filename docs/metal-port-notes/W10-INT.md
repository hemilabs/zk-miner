# W10-INT: GitHub main merged into the macOS beta

Branch `item/W10-INT`, worktree `/Users/user/zkminer/zk-miner-3.1-wt-W10-INT`, from `metal-3.1` @ `6e7a1c1`
(RC2). `git merge --no-ff origin/main` (`c030355`, 88 commits since `cde7815`, 78 of them non-merge), then
separate follow-up commits. Neither history was rewritten. Logs, scripts and benchmark output are in
`/Users/user/zkminer/scratch/w10/W10-INT/` (`bench/`, `final/`, `localnet/`, `cross/`, `scripts/`).

| commit | what |
|---|---|
| `c0cafbc` | the merge: 15 conflicting files and the semantic conflicts needed to compile (tables below) |
| `721d4fa` | macOS CPU probe in the TUI; Metal IPC tests read past `SetupProgress` |
| `72b4000` | Metal release after a no-wrap benchmark proof (memory fix, A/B below); RELEASE-DEPS, Makefile.mac and README for the new pin and the new suite |
| this note | |

**risc0 pin:** hemilabs/risc0 `zkminer/metal-3.1` @ **`28b4bef339773e96539879c5c4314c23e20c5249`** (W10-R0's
merge). It contains main's `release-3.1` @ `5beab26b5` (`git merge-base --is-ancestor` holds). The pin uses
the same git+rev form as B9-DEP: the 17 crates in `[patch.crates-io]` and the zkrs crates from crates.io
`=4.1.0` (one patch table, main's spelling with `registry = "crates-io"`). The LFS oids of both zkrs tarballs
at `28b4bef33` equal crates.io's (`53388c58…`, `202fd7e7…`). Apart from docs, the fork's code diff from
the beta's pin `d94ef6501` is the 4 ROCm evalfast files, so the Metal binary's risc0 code is unchanged.
Cargo.lock is main's lock re-resolved: 18 `source` lines take the new rev, and the beta's Metal dependency
edges come back. Nothing else moved. `--locked` passes in git mode and in `RISC0_SRC=local` mode
(Makefile's derived lock). RELEASE-DEPS.md is updated and lists what the fork changes on other platforms,
from W10-R0's audit.

## Conflicting files (git-flagged)

| file | main | beta (metal-3.1) | resolution and why |
|---|---|---|---|
| `Cargo.toml` | risc0 rev `5beab26b5` with the 3.0-era history comment; zkrs crates.io table at the end | rev `d94ef6501` with the B9-DEP comment and local-mode note; its own zkrs table after the SP1 lines | Main's history comment is kept. Its "The pin is release-3.1" paragraph is rewritten for `28b4bef33` (what it contains, the selector and control root, 3.0/3.1 incompatibility, `-j 4`) plus the beta's local-mode note. The 17 lines use the beta's form at the new rev. There is **one** zkrs table (main's, with a corrected comment); two would be a duplicate TOML table. The SP1 rev is main's `a4df7c8f7` (auto-merged). |
| `Cargo.lock` | lock for `5beab26b5` | lock for `d94ef6501` + Metal deps | Main's lock, re-resolved with `cargo metadata` through the mirror. The diff against main is 18 rev lines plus Metal dependency edges (`metal`, ark-*, `risc0-groth16-sys` → `risc0-zkp`, …). |
| `README.md` | Groth16 component 5.8 GB; deployment paragraph with the 2026-11-16 router | 0.2.0 component section, risc0 3.1/verifier section, abandoned-stack paragraph, pin provenance | Union. The component is "5.8 GB" (5,812,781,917 B measured in `~/.risc0/extensions/v0.2.0-risc0-groth16`; the beta's "5.4" was GiB). The pin provenance now says the pins are the repo's (3bc441d/8e1808b), checked by `the_pins_match_the_contracts_repo`. |
| `crates/zkminer-chain/src/deployment.rs` | 2026-11-16 pins from the repo's pin files; `masked_keccak` (the repo's 32-byte-window method); adapter **size** checks; SP1 **PLONK** adapter/verifier; `RISC0_V3_1_GROTH16_VERIFIER: B256`; ignored live lib test | the same pins computed from live code (B9-CHAIN), then checked against 8e1808b; `keccak_self_zeroed` (20-byte); `risc0_verifier_pin` (3.0 selector refused); `ABANDONED_743111` + `abandoned_stack_refusal`; `risc0_preflight` (`Registry.verifyProof` `eth_call` with a Metal receipt) | **Every shared pin is identical** (core, facets, adapters, risc0 v3.1 verifier `26e455ef…`, SP1 Groth16; diff of all `b256!`/`address!` literals). Main's file is the base: `masked_keccak` is the only hash implementation (both give the same pins on live code; the live test passes), and the size checks and PLONK pins stay. Added from the beta: the 3.0 selector constant, the selector-keyed `risc0_verifier_pin` (the Option form and the "missing pin" message went away because the pin exists), the abandoned-stack refusal as step 0 of `verify_deployment`, and the receipt preflight after the SELECTOR check. Tests are the union. `the_pins_match_the_contracts_repo` now also checks the 3 PLONK values and each adapter's `*_SIZE` constant. |
| `crates/zkminer-cli/src/commands/run.rs` | `const RISC0_GROTH16_SELECTOR = pins::RISC0_V3_1_SELECTOR`; splash status lines | selector derived from the linked risc0 (`risc0_groth16_default_selector`); P31-19 override refusal; B9-ZK pin notice | The beta's derived selector and override refusal stay (stricter; its test ties it to `pins::RISC0_V3_1_SELECTOR`), and main's `splash.status(...)` steps stay. The B9-ZK test is rewritten for a filled pin. |
| `crates/zkminer-cli/tests/localnet.rs` | fork block 7_226_550; fixture = the contracts' risc0-ethereum 3.1 test receipt | fork block 7_234_420; fixture = a Metal-made 3.1 receipt (also the preflight's) | Beta's kept. The fixture is a receipt this build's worker makes, and the later block passed B9-CHAIN's suite. Both blocks are after the deployment's setup (router 7226099, adapters by 7226300). |
| `crates/zkminer-config/src/config.rs` | short selector doc | the override-refusal doc | Beta's (it describes what run.rs does). |
| `crates/zkminer-prove-risc0/src/groth16_component.rs` | `VERSION` private, "5.8 GB installed" | `pub(crate)` `VERSION` + `GRAPH_SHA256_PREFIX` (used by Metal), "5.4 GB" | Beta's constants, main's 5.8 GB (see README). The archive sha256 and URL were identical on both sides. |
| `crates/zkminer-prove-risc0/src/main.rs` (7 hunks) | `Benchmark { programs }`; public seed (`sys_rand_seed(image_id, input)`, no key); `warm_up(report)`; `--export-guest` sys-rand-echo, segment-size-steer; no-wrap benchmark path | Metal worker start (budget, footprint guard, graph preload, first-job prewarm), `gpu_refusal`, Metal `warm_up`, `before_prove(seed)`, `--export-guest memory-merkle` | Union: every export guest; the Metal start without the key load; the Benchmark handler keeps the refusal and prewarm and runs main's `run_benchmarks_streaming(&programs)`; `before_prove` gets the public seed; the Metal `warm_up(report)` reports its pipeline step. The no-wrap path also needed `power_state` (helper `bench_power_state_over`) and, after measurement, the Metal release (below). |
| `crates/zkminer-prover-protocol/src/types.rs` | **12**: `Benchmark { programs }`, `SetupProgress`; **13**: public seed, `ExecuteResult.user_cycles/keccak_cycles` | **12**: `BenchmarkEntry.power_state`; **13**: risc0 3.1 | **Protocol 14.** Both lines used 12 and 13 for different wires, so a worker of either v13 must be refused. The history keeps both lines. New test `a_worker_of_either_v13_is_refused`. Doc comments that said "v12"/"13" now name their line. |
| `crates/zkminer-prover/src/benchmark.rs` | Windows CPU name | macOS CPU name (sysctl) | Union. |
| `crates/zkminer-prover/src/discovery.rs` | Windows Intel discovery tests | Metal discovery, owner-tier and power tests | Union (both test blocks). |
| `crates/zkminer-prover/src/dispatcher.rs` (5) | `startup_problems`, `setup_status`, `run_benchmark_requests` (warm-up, suite, scoring), `SetupProgress` loop in warm-up | owner tier, enforce/recycle overrides, tier job counters, `slot.note_used(UseKind::Other)` after warm-up/benchmark | Union of fields and constructors. `note_used` is kept after main's warm-up loop and after `run_benchmark_requests` (both benchmark paths), so M9's recycle accounting still counts them. |
| `crates/zkminer-prover/src/memory.rs` | `#[cfg(not(windows))]` on `mem_available_bytes` / `mem_total_bytes` | macOS docs on the same functions | Union. |
| `hemiprove-abi/VENDORED_FROM.txt` | one line: 3bc441d | the B9-CHAIN provenance + repo cross-check | **All ABI files are byte-identical on both sides** (`git diff metal-3.1 origin/main -- hemiprove-abi` touches only this file). Main's sentence first, then a short cross-check section. |

## Semantic conflicts (not flagged by git)

| what | main | beta | resolution |
|---|---|---|---|
| Protocol numbering | 12/13 = programs, SetupProgress, public seed | 12/13 = power_state, risc0 3.1 | 14 (above). |
| `BenchmarkEntry.power_state` / `ProgramStage.power_reduced` | constructed without them (TUI tests, scoring tests) | fields added | `None` added in main's 4 test constructions. |
| Warmup now streams `SetupProgress` | dispatcher loops | the beta's IPC test helpers read one answer | the helpers skip `SetupProgress` (`721d4fa`). All 4 Metal IPC tests pass. |
| Benchmark rework vs Metal `--benchmark` and kit scripts | suite of 5 programs, fibonacci only as a discarded warm-up, then zkOP/s scoring; `BENCH_ONLY` filters the suite | kit `install.sh`, `macos-smoke.sh`, `Makefile.mac` use `BENCH_ONLY=fibonacci` | No code change was needed. `BENCH_ONLY=fibonacci` runs the warm-up alone, which still proves, wraps and verifies, logs `fibonacci: … cycles … verified` (the smoke script's regex) and writes `fibonacci.groth16.receipt` (stock-verified below). Docs updated. |
| No-wrap scoring proofs on Metal | `benchmark_stages` returns before `release_after_proof()` | Metal relies on that release between proofs | **Memory regression found and fixed** (`72b4000`, below). |
| Public seed | key gone | Metal `before_prove(…, seed)` and the start-up `sys_rand_key()` | public seed passed; key load removed |
| `warm_up(report)` | new signature | Metal `warm_up()` | signature adopted; Metal reports its pipeline step |
| `RISC0_DEFAULT_JOB_PO2` import | used by main's `run_proof_once` | beta uses `default_job_po2()` (Mac tiers) | beta's code; unused import dropped |
| Selector source | constant from zkminer-chain | derived from the linked risc0 | derived (test ties both together); main's `groth16_selector_tests` kept |
| TUI CPU probe | `/proc/cpuinfo` + Windows branch | nothing for macOS (0 threads; `test_probe_detects_hardware` failed on macOS) | macOS takes the Windows branch's route (brand string, `available_parallelism`, `hw.physicalcpu`); Linux/Windows unchanged |
| Windows GPU / SP1 tiers / splash | new | — | compiled as is; `cfg(windows)` code could not be type-checked here (see cross-target) |
| 2026-11-16 deployment pins | main's | B9-CHAIN's | identical values (above); one implementation |

## Main's 78 non-merge commits by topic

(The 10 merge commits are `c030355 5acb2b2 b46975b b6aa618 bf336e3 ca2ef82 0d86fb2 8608bf6 75ac312 b40abed`.)

| topic (count) | result | commits |
|---|---|---|
| Windows GPU workers: discovery, process control, IPC, memory, Intel/AMD/NVIDIA workers, SP1 on Windows, Windows TUI telemetry/keys, power on Windows (24) | kept as is (unions in discovery.rs, memory.rs, benchmark.rs, tui hardware.rs; all `cfg(windows)`) | `630f28d` cli: build the instance lock on Windows, `d1f5b01` Run the workers on Windows: discovery, process control, IPC, memory, `45d34d5` fix(windows): credit a slot with its own GPU memory, so a warm SP1 worker is not refused, `83f1a2c` test: make the SP1 VRAM tests meaningful on a desktop card or a big one, `2e6b5a6` test: compare the SP1 server path in its canonical spelling, `64b83e0` Intel GPUs on Windows: discovery and a RISC0 worker build, `00fa803` Intel workers: card VRAM from Windows discovery; proof_format_test covers Intel, `fdfba06` tests: run the backoff and Groth16 VRAM tests on any risc0 GPU slot, `30fbba0` Intel worker on Windows: release the Groth16 cache below 48 GiB, `8271d28` AMD (ROCm) worker on Windows: HIP device discovery, `befdcb2` sp1: put the server's own DLLs on its PATH on Windows, `ca7c948` sp1: on Windows, let an evicted proving key's teardown finish, `8f0e53c` sp1: install the MSVC runtime beside the server on Windows, `be2b305` tui: list Intel and AMD GPUs on Windows, `9ac7ffe` sp1: install the SYCL server's own library beside it on Windows, `91e5d9c` Windows AMD: card VRAM from the HIP probe, `f9df188` SP1 on Windows AMD: fewer, cheaper readbacks, `2895379` SP1 on Windows AMD: keep the trace LDEs on 16 GB cards, `7e392e4` Revert "SP1 on Windows AMD: keep the trace LDEs on 16 GB cards", `b4d2cd0` sp1 worker: keep the wrap key on 16 GB Intel cards (Windows), `ade4017` sp1: ship the GPU Groth16 prover with the Windows CUDA server, `a12ce82` TUI: GPU telemetry on Windows from the vendors' driver libraries, `8547bda` TUI: ignore key releases on Windows, `df6c7f8` Benchmark: measure Intel and AMD power on Windows |
| CI for the Linux/Windows builds (build-windows.yml, toolkits, runners, caches) (18) | kept as is (actionlint + shellcheck pass with the repo config) | `17af201` ci: build every Windows worker, for NVIDIA, AMD and Intel, driver-only, `bce480d` ci: build the RISC Zero guests through zkminer-prover, `ed64e53` ci: unpack the HIP SDK's hipCUB and rocPRIM headers, `1df7e60` ci: ship the SYCL runtime's loader and hwloc, `c14f639` ci: build the risc0 ROCm worker with HIP's own asserts, `608fe43` ci: run the Windows GPU builds on a larger runner when one is named, `ea6cf59` ci: keep compiled risc0 kernels across runs; HIP release flags, `07c09be` ci: compile the Intel risc0 device images on Linux, with IGC's quadratic fixed, `e8740b1` ci: ship the HIP runtime's license in the AMD zip, `70014cc` ci: compile the ROCm worker's GPU targets in parallel on a larger runner, `a315119` ci: give the Intel build the Level Zero headers, `dc5e28f` ci: record A770 recursion variants at other reload distances (temporary), `8a1af67` ci: build the recursion variants through the worker, never fail on them, `2f983d2` ci: drop the A770 recursion variant recording, `fb4d609` ci: size the ROCm build's HIP parallel jobs by RAM, `1024067` CI: install sp1up from its repository at a pinned commit, `ba09af5` CI: do not name the sp1up pin SP1UP_COMMIT, `8036766` CI: retry the toolkit and SP1 toolchain downloads |
| risc0 pins (3.0 fork branches, then release-3.1 58dfae89 / 5beab26b and the v0.2.0 Groth16 component) (8) | superseded for the rev (28b4bef33 contains 5beab26b5); their Cargo.toml history comments kept; groth16 component v0.2.0 identical on both sides | `9ce882f` risc0: pin the fork's witgen fix, so Intel cards use their ahead-of-time kernels, `960f192` risc0: pin the fork's Intel ahead-of-time kernels, so a B580's first proof compiles almost nothing, `6810caa` deps: pin risc0 to zkminer/windows-a770-perf (Arc A770 fixes), `78255ea` deps: pin risc0 73a665792 (Windows ROCm fix + windows-a770-perf @ 7f6350f64), `85d68e9` deps: pin risc0 c98b3f269 (Intel keep-alive on Windows), `8702e1a` risc0: move to release-3.1 (Groth16 ceremony fix) and its v0.2.0 component, `5aa01dd` risc0: pin release-3.1 at 58dfae89 (Intel Poseidon-254 x^7 fix), `f13d57a` risc0: pin release-3.1 at 5beab26b (AMD fix) and the risc0-ethereum v3.1 verifier |
| SP1 pins (SYCL event fix, Windows AMD/server-connect) (2) | kept as is (SP1 rev a4df7c8f7 in Cargo.toml, CLI and lock) | `1d22431` sp1: pin the fork's SYCL event fix, so the Intel server stops aborting proofs, `cc61b6b` deps: pin the Windows AMD fixes (risc0 b35b0acc0, sp1 a4df7c8f7) |
| Benchmark rework: zkop-mix guest, zkOP/s scoring, suite in the protocol crate, miner-sent suite, fibonacci dropped, warm-up, per-GPU rows, monotonic clock, power line, mock limit (11) | kept; adapted for Metal: the worker's Benchmark handler keeps the Metal refusal/prewarm/power-state, BenchmarkEntry keeps power_state, protocol 14, and the no-wrap scoring path releases Metal provers (W10-INT fix) | `90d545d` Add the zkop-mix benchmark guest for RISC Zero and SP1, `a1a322e` Score zkOP/s on a fixed program instead of a placeholder baseline, `f54b3b9` Benchmark: drop fibonacci from the suite, `6573f8d` Benchmark: define the suite once, in the protocol crate, `101edae` Benchmark: the miner sends the suite, and scores zkOP/s itself, `cdf5921` Benchmark: warm each worker up before the suite, `fe277a0` zkOP/s: score each GPU on SP1 and RISC Zero together, `98e9aa8` Benchmark tab: a row per GPU, so eight fit a standard terminal, `4788721` Benchmark screen: time the run on the monotonic clock, `a4837c6` Benchmark screen: say the power line is the last run's peak, `26f055f` Mock mode: use the configured benchmark limit |
| Startup: splash, one-time setup with download progress (SetupProgress), startup problems (8) | kept; adapted: Metal warm_up takes the report callback (and reports its pipeline step); the beta's IPC tests skip SetupProgress | `b1cb635` TUI: splash while starting, benchmark at startup, name the card in progress, `71ea587` Startup: name each GPU vendor and contract check on the splash, `d2b2523` Startup: say what was found and which workers did not start, `e3edc04` Startup: report what a first run's one-time setup is doing, `77d955a` Startup: do the one-time setup on the splash, with download progress, `a988a8a` Splash: a line and a progress bar per prover being set up, `a8186df` Splash: give SP1's download its total, so it gets a bar, `f6500cd` Splash: format the SP1 download size check |
| Public risc0 sys_rand seed; simulate checks every segment size (1) | kept; adapted: Metal before_prove uses the public seed, the key load at worker start is gone | `c4ba622` Seed risc0 guests publicly and check every segment size in simulate |
| SP1 12 GiB tier, SP1 measure-worker setup outside the bound (2) | kept as is | `b5de292` sp1: re-measure the shard-tier VRAM for circuit v6.1.0 so 12 GiB cards prove, `17b0211` Set the SP1 measure worker up outside a measurement's bound, and drop DUMP_ELF_OUTPUT |
| The 2026-11-16 deployment (ABIs from 3bc441d, pins, localnet fork block, watch-only warm-up gate) (4) | merged with B9-CHAIN/bb4de8b: ABIs byte-identical, every pin identical; union of checks in deployment.rs; beta's localnet fixture and fork block kept; 32b225e = the same fix as B9-CHAIN's, main's comment taken | `f7f0abe` hemiprove-abi: re-vendor from hemiprove-contracts 3bc441d (the 2026-11-16 deployment), `1cbbb91` deployment: the 2026-11-16 743111 stack and the 3bc441d release pins, `3c98003` localnet: fork 743111 after the 2026-11-16 deployment, `32b225e` watch-only: report a claim the warm-up gate would only delay |

## Profile first, and the memory regression the merge brought

No Metal kernel, risc0 source or proving code on the job path changed, so R17 (`ir_scan.py`,
`run_stress.sh`) does not apply. Main changed what `--benchmark` and `zkminer benchmark` run, so I measured
before keeping anything. Logs are in `bench/`. A = the installed reference 3.1 worker
(`~/.zkminer/provers/zkminer-prove-risc0-metal`, sha256 `9161605e…`, the BASELINES '3.1' binary). B = this
branch's `make -f Makefile.mac RISC0_SRC=git mac-build-worker` through the mirror. Every run was alone under
`gpu-run` (heavy, `--no-budget`; budgets set as `RISC0_METAL_MAX_WORKING_SET_BYTES`), with `/usr/bin/time -l`,
at load 0.6-3.4.

**memory-merkle (`BENCH_ONLY`), interleaved A/B, 7 pairs, merge build (`c0cafbc`):**

| budget | A STARK median [min-max] | B STARK | A / B peak footprint |
|---|---|---|---|
| default (po2 20) | 8.420 [8.400-8.440] s, 872.2K c/s | 8.430 [8.410-8.450] s, 870.3K c/s | 13.20 / 13.96 GB |
| 8 GiB (po2 19) | 10.330 [10.300-10.340] s, 761.2K c/s | 10.380 [10.360-10.400] s, 757.4K c/s | 7.31-7.33 / 8.31-8.32 GB |
| 4 GiB (po2 18), final build `72b4000` | 14.115 [14.090-14.170] s, 594.2K c/s (6 of 7: A3's Groth16 key load was refused at 4 GiB, the pre-B9-4G behaviour of this older binary) | 14.190 [14.150-14.250] s, 591.1K c/s (7 of 7 wrapped) | 4.79-5.05 / 5.80-5.83 GB |

These are not like for like. B's `--benchmark` first proves main's discarded fibonacci warm-up, with its
Groth16 wrap, so memory-merkle runs second in a process that has wrapped once. A's memory-merkle is the
process's first proof. The full suite compares like for like: both binaries prove fibonacci(1000) with a
wrap first (A as its first program, B as the warm-up), then the same five programs in the same order.

**Full `--benchmark`, A then B:**

| budget | A: 5 programs (+fib) STARK | B: 5 programs (+fib) | memory-merkle row A / B | peak A / B |
|---|---|---|---|---|
| default | 170.80 (171.08) s, 902.8K c/s | 170.66 (170.93) s, 903.6K c/s | 8.34 / 8.32 s | 14.69 / **16.26** GB |
| simulated 16 GB host (`ZKMINER_METAL_HOST_RAM_BYTES` 16 GiB, HAL 10.67 GiB, dispatcher figure 8 GiB → po2 19) | 206.15 (206.42) s | 206.21 (206.49) s | 10.22 / 10.21 s | 9.46 / **10.99** GB |
| 4 GiB, final build | 291.83 (292.10) s | 291.67 (291.94) s | 14.03 / 14.06 s | 6.32 / 6.33 GB |

- Every suite program is unchanged in the like-for-like comparison. The `BENCH_ONLY` deltas above
  (+0.05 s, +0.08 s, +0.8-1.0 GB) are the warm-up order and not code.
- The full-suite peak rose by 1.5 GB at the default budget and on the simulated 16 GB host. The cause is
  main's new no-wrap path for the zkOP/s scoring proofs (zkop-mix: 61.9M cycles at po2 20, 67.1M at
  po2 19, no wrap). It returned before `release_after_proof()`, so on Metal the thread's cached recursion
  provers stayed allocated into the next proof. On a 16 GB Mac (allowance 11.5 GiB) that left 10.99 GB.

**Fix (`72b4000`):** the no-wrap path releases on Metal as the wrapped path does, and logs the same
Metal/footprint peaks. On other backends main's path is unchanged (nothing was wrapped, so there is nothing
to release). Revert: `ZKMINER_METAL_NOWRAP_RELEASE=0`.

Interleaved A/B, `BENCH_ONLY=zkop-mix` on the simulated 16 GB host, 7 pairs (A = merge build `c0cafbc`,
B = with the release):

| | A | B |
|---|---|---|
| scoring proof (67.1M cycles) STARK | 85.48 [85.43-85.72] s | 85.84 [85.64-86.04] s |
| per pair B-A | | +0.22 / +0.33 / +0.16 / +0.16 / +0.27 / +0.49 / +0.36 s (median +0.27) |
| process peak footprint | 11.04 [10.94-11.04] GB | **9.05** [9.05-9.14] GB |

- Cost: +0.3 % on the scoring proof only. It appears in all 7 pairs and is about the size of the A-vs-A
  spread (0.29 s); the released pools are rebuilt for the next proof. The zkOP/s score moves by the same
  0.3 %. Suite programs and jobs are unaffected: they already release after their wrap.
- Kept, because it returns ~2 GB of the owner's RAM on a 16 GB Mac.

**Final binary (`72b4000`), the gate runs:**

- Full `--benchmark`, default budget: 5 programs 170.77 s / 904.3K c/s; with fibonacci **171.05 s /
  903.0K c/s**. RC2 measured 169.92 s / 909.0K. That is +0.7 %, and A measured in this session shows
  the same offset (171.08 s), so it is the machine state and not this branch. Wraps 1.59-1.60 s. Peak
  **14.74 GB** (baseline 14.69). The two zkop-mix proofs took 4.88 s and 68.25 s; wall 254 s.
- Simulated 16 GB host: 206.80 s with fibonacci (A 206.42). Peak **9.47 GB** (A 9.46, RC2 9.34).
- 4 GiB: like for like as A (table above), every program wrapped. Peak 6.33 GB.
- `zkminer benchmark` through the CLI (sandbox HOME, so the user's saved benchmark was not touched): warm-up,
  the 5 programs and the zkop-mix score through the dispatcher. 2.72 MzkOP/s, Groth16 1.60 s, rc 0, 314 s.

## Correctness and gates (all foreground; logs in `final/`, `localnet/`, `bench/`)

| gate | result |
|---|---|
| `cargo test --workspace --exclude zkminer-prove-sp1 --exclude zkminer-prover` | 497 passed / 18 ignored in runs 2 and 3. Run 1 hit a timing flake in main's `proc::tests::a_healthy_child_is_fast_and_successful` (151 ms against a 150 ms bound; it poisoned that module's test lock, so its 7 siblings failed too). It then passed 5 of 5 alone and in both later runs. Not merge-related. |
| `cargo test -p zkminer-prover --features testing --tests` (`ZKVM_ALLOW_SKIP=1`), ×2 | 384 passed / 21 ignored, both runs: lib **292**, `worker_lifecycle` **27 passed / 3 ignored**, orphan reaping, proof format and others. `comprehensive_zkvm_test` is the Linux GPU validation suite. It fails closed without CUDA/SP1 workers and guest ELFs, so it ran in its documented skip mode. |
| `cargo test -p zkminer-prove-risc0 --features metal`, ×2 | 66 passed (B9: 64; main added the selector and seed known-answer tests), 4 ignored (the release IPC tests, next row) |
| Metal IPC tests (`--release … --test metal_worker -- --ignored`) | 4/4 at the merge and at `72b4000`: warm-up + prove, a first prove without warm-up, the 4 GiB keccak-then-Groth16 sequence with key releases, 20 sequential proofs |
| localnet suite against the 743111 fork (block 7234420), ×2 | **9/9 runnable pass, both passes**: replayed receipt (106-108 s), `mines_the_claimable_jobs` with the real Metal worker (154-164 s), watch-only (246-247 s), simulate (124 s; it was 50 s before main's seven-size check), pause ×2, adapter disabled, 3.0 selector refused, skewed clock. Not run, by design: `serves_a_tui_miner` and `serves_jobs_to_simulate` (they serve a miner run by hand), and `mines_on_every_gpu` (SP1 server, CUDA) |
| live read-only (`tests/live_743111.rs --ignored` and main's lib `live_743111_deployment_verifies`), generic User-Agent `zkminer/0.1.0` | 4/4 + 1/1. Deployment, wiring and code pins pass. risc0 (with the receipt preflight `eth_call`), SP1 Groth16 and SP1 PLONK adapters pass. 102 live job descriptors decode. The abandoned stack is refused. Proof nonces match. |
| `the_pins_match_the_contracts_repo`, `ZKMINER_CONTRACTS_REPO=…/contracts-repo/ms` (8e1808b) | pass. Negative controls: one PLONK hash changed → fails "absent"; `SP1_PLONK_VERIFIER_ADAPTER_SIZE` 1848 → fails |
| receipts | B's fibonacci and memory-merkle Groth16 receipts at the default budget and at 4 GiB: **STOCK 3.1 VERIFY: OK** (crates.io 3.1.0 `stock-verify31`). A 3.0 receipt is **REJECTED** (parameters digest 73c457ba…). Bit-exactness vs CPU: no kernel or prover code changed (fork diff ROCm-only), not re-run. |
| release worker + CLI through the mirror (`RISC0_SRC=git mac-build-worker`, the brief's env) | rc 0, risc0 @ `28b4bef33` from the mirror; worker 184,536,672 B, CLI 15,949,552 B. `RISC0_SRC=local mac-check` also passes, and the tree stays clean. |
| `scripts/ci/test-metal-tc.sh <cargo's build_kernel @28b4bef>` | 18/18 |
| `scripts/ci/test-assemble-macos.sh` (sdk = this build; kit = RC2's kit binaries: main changed nothing under `scripts/ci`, `scripts/mac` or `packaging`) | 44/44 |
| actionlint 1.7.12 + shellcheck via `scripts/ci/lint-workflows.sh` (repo config), all workflows incl. main's `build-windows.yml` | ok; expression tests 425/425 |
| cross-target `cargo check` (rustup targets installed user-locally) | `zkminer-prover-protocol`: **ok** for `x86_64-unknown-linux-gnu` and `x86_64-pc-windows-msvc`. Every other crate (CLI, chain, prover, TUI, config, contracts, strategy) **could not be checked**: their C build scripts (blst, ring, c-kzg, openssl-sys) need the target's libc headers and OpenSSL. This Mac has no Linux or Windows sysroot and no Docker; Homebrew clang/clang-cl with the macOS SDK headers fails (`assert.h`, `stdlib.h`, typedef clashes). So no `cfg(windows)` / `cfg(target_os = "linux")` code of main's was type-checked after the merge. A Linux and Windows CI build is needed. |
| `zkminer-prove-sp1` | cannot build on this Mac: its build script needs the `succinct` toolchain (SP1 guests), which is not installed. Excluded from the workspace runs. |

## Knobs added

- `ZKMINER_METAL_NOWRAP_RELEASE=0`: no release after a no-wrap (zkop-mix scoring) benchmark proof on Metal.

## Open issues

1. **Push** `zkminer/metal-3.1` @ `28b4bef33` to hemilabs/risc0 unchanged before anyone off this Mac builds
   (RELEASE-DEPS.md). The rev in `Cargo.toml` and the 18 lock lines must follow any rebase.
2. **Linux/Windows not built or run here.** Main's Windows/CUDA/ROCm/Intel/SP1 code compiled only for macOS,
   where most of it is `cfg`'d out. The Metal fork's cross-platform changes (RELEASE-DEPS table: keccak
   right-sizing, zkr cache, noise thread, early data drop on CpuHal, Intel graph memo) replace main's stock
   `5beab26b5` for those platforms. A CI run on each platform is needed before tagging from main.
3. **Protocol 14** refuses every v13 worker of either line: a beta 0.1 kit worker under a new miner (or the
   reverse) is refused at the handshake. That is intended, but kits must ship CLI and worker together
   (they do).
4. `--benchmark` / `zkminer benchmark` on a Mac now takes ~4.2 min instead of ~3 min (warm-up + zkop-mix
   scoring; 254 s wall at po2 20). The Metal benchmark deadline (`METAL_BENCHMARK_CORE_SECS`) still has
   >10x headroom on this Mac.
5. Main's `proc` timing test can flake under load (above).
6. `BENCH_ONLY=<program>` peaks are now ~0.8-1.0 GB above the old single-program runs: the warm-up wrap
   comes first. BASELINES-style single-program footprint comparisons must use the full suite or account
   for that. Production jobs always follow a warm-up anyway.
