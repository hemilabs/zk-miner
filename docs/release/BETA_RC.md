# macOS beta, release candidate 3 (integrated branch: GitHub main + the macOS beta, RISC Zero 3.1)

2026-11-19, round 2. This round re-checks the **integrated** `metal-3.1` after the beta fix round.
`metal-3.1` contains GitHub zk-miner `main`. It is pinned to a risc0 fork rev that contains upstream
hemilabs/risc0 `release-3.1`.

The kit was built the way the CI job builds it, from a fresh clone, then installed and used as a new
user would. It ships **unsigned**: no Developer ID and no notarization. Evidence and scripts are in
`/Users/user/zkminer/scratch/w10/rc2/`: `ci/` (harness, per-step logs, `report.md`), `logs/`,
`out/`, `live/`, `scripts/`, `dist/`.

History:
- RC1 (`ca07773`, kit `54296dc6…`) and RC2 (`6e7a1c1`, kit `02e5ca12…`) checked the pre-merge beta
  (risc0 `d94ef6501`).
- RC3 round 1 (`8b448a0`, kit `d0099a51…`) found one failing check: a worker failure made `zkminer
  benchmark` print a simulated table and exit 0.
- Step 0 (`f9f535b`, kit `5153fac0…`) fixed that.

All of them are in this file's history.

**Verdict: every check passed. Nothing blocks the push.** What is left is the user checklist (section
6): push, CI on the real runners, a real macOS 26 Mac, and the funded-key tests.
- The kit is **`6ec9411e…`**, built from `f539d5c`. It contains W10-BENCH, W10-DOC and the BETA-FIX
  startup-error fix.
- Both forced worker failures make `zkminer benchmark` exit 1, with the worker's own error and no
  table.
- A working `zkminer benchmark` exits 0 with real numbers.
- The six-program STARK total is 170.56 s, which is +0.59 % against BASELINES '3.1' and inside the
  1.5 % threshold.

## The candidate

| | |
|---|---|
| kit | `zkminer-0.1.0-macos-arm64.tar.gz`, 121,315,795 bytes (201.5 MB = 192 MiB unpacked, 10 files) |
| **sha256** | **`6ec9411eb14b9d5310cfba92b6635c407484ca8a68bc77219f66a561f05c4cb3`** |
| where | `/Users/user/zkminer/scratch/w10/rc2/dist/` (the tarball and its `SHA256SUMS`) |
| zk-miner | `metal-3.1` @ `f539d5cc0a41ddf46b353ed37fbd1580e2b03ae7` (`BUILDINFO commit`, `commit_dirty=no`) |
| risc0 | hemilabs/risc0 `zkminer/metal-3.1` @ `37b434755ce77dd1354d957a7b61912aa4359423` (`BUILDINFO risc0_rev`, `risc0_src=git`) |
| minimum macOS | 26.0: binaries minos 26.0, metallibs target 26.0. `check-macos-release.sh`: "a self-contained arm64 kit for macOS 26.0 and later" |
| Metal compiler | `Apple metal version 32023.922 (metalfe-32023.922.4)` (27B47, pinned, `metal_compiler_validated=yes`), SDK 27.2, built on macOS 27.2.1 (26B131) |
| offline archives | none (`aot_arches=`; CI builds with `AOT_ARCHES=none`) |
| Groth16 component | not bundled; v0.2.0, sha256 `173354ab…57e5`, fetched by the worker or by `install.sh --with-groth16` |
| worker metallib digests | `build-metal-aot.sh --worker-digests`: `261571a7…`, `62805de6…`, `c934c282…`, `cf978db9…`, `f42fd572…`. These are the same 5 as RC1, RC2, RC3 and B9-M26 |

- The commit that adds this file changes only `docs/release/BETA_RC.md`, which is not an input of the
  kit. A kit built from that commit differs only in `BUILDINFO commit`, and so in its sha256.
- A kit that CI builds for a tag also differs in `BUILDINFO commit`. On the runner's Xcode 26 SDK,
  `metal_sdk` and the metallib digests change too (B9-M26, B9-CI).

## 0. Integration facts (all hold)

| fact | check | result |
|---|---|---|
| pushing `metal-3.1` to `main` is a fast-forward | `git merge-base --is-ancestor origin/main metal-3.1` | **yes**. `origin/main` = `c030355`. `metal-3.1` (`f539d5c`) is 78 commits ahead and 0 behind, or 79 with this file's commit |
| the pin contains upstream `release-3.1` | `git -C deps/risc0-3.1 merge-base --is-ancestor origin/release-3.1 37b434755` | **yes** (`origin/release-3.1` = `5beab26b5`) |
| the pin is the fork's HEAD | `deps/risc0-3.1` HEAD | **`37b434755`** (`Merge metal/W10-GATE`), clean tree |
| `Cargo.toml` and `Cargo.lock` | grep | 17 `[patch]` revs and 18 lock `source` lines are `37b434755…`, and no other hemilabs/risc0 rev appears. sppark stays at `5f68eb3e…` |
| the mirror has it | `scratch/w9/mirror/risc0.git`, refreshed from `deps/risc0-3.1` | `zkminer/metal-3.1` = `37b434755…` |
| non-Metal code = `release-3.1` in effect | W10-GATE (`deps/risc0-3.1/docs/metal-port/notes/W10-GATE.md`) and RELEASE-DEPS.md's table | Unchanged since round 1, because there is no risc0 change. Every fork change off Metal is gated to its `release-3.1` default. No Linux or Windows build was run (open issue 1) |
| workflows | `actionlint` 1.7.12 (with shellcheck) on all 5 workflows | Clean once the self-hosted labels (`zkminer-gpu`, `zk-runner-mac-new`) are declared in a config (`rc2/actionlint.yaml`). Without that config the only finding is `release.yml:168` "label zkminer-gpu is unknown", which comes from main. `scripts/ci/test-workflow-expressions.py`: 425 passed |

## 1. CI build (`build-macos.yml`, all three jobs, run locally)

**How it was run.** B9-CI's harness (`ci/sim.py`; only its paths differ from round 1) ran every step
of `.github/workflows/build-macos.yml` at `f539d5c`, in order and exactly as written:
- on a fresh clone of `metal-3.1`, inside a 14 GB APFS disk image (`hdiutil`, 13.79 GB usable),
  which was detached and deleted afterwards;
- with a fresh `HOME` and `CARGO_HOME` inside the image, and `CARGO_BUILD_JOBS=5`;
- with the hemilabs/risc0 URL sent to the mirror (`CARGO_NET_GIT_FETCH_WITH_CLI=true` and
  RELEASE-DEPS.md's two `GIT_CONFIG_*` rules).

The workflow file is byte-identical to round 1's.

| job / step | rc | wall | disk (of 13.79 GB) |
|---|---|---|---|
| build: Metal toolchain (27B47, pinned) | 0 | 18 s | |
| build: Rust, rzup guest toolchain, protoc | 0 | 57 s | |
| build: Metal worker and CLI (`ASSEMBLE_BUILD_ONLY=1 assemble-macos.sh`) | 0 | 316 s | peak used 12.57 GB, **min free 1.22 GB** (round 1: 1.22 GB) |
| build: delete intermediates | 0 | 3 s | 12.55 -> 4.84 GB |
| build: package and check (`check-macos-kit.py` ok with 0 archives; `test-check-macos-kit.sh` **16/16**) | 0 | 60 s | |
| cpu-tests: tests that need no GPU (2 suites, **65 + 135 passed**; `test-metal-tc` 18/18) | 0 | 298 s | min free 1.90 GB (round 1: 2.07) |
| metal-probe: install, probe, Groth16 download (67 s), one fibonacci proof (verified, wrap 1.75 s) | 0 | 74 s | min free 3.18 GB |

- **The suites grew.** cpu-tests now has 65 + 135 tests, against 62 + 131 in round 1: the tests
  merged since then (W10-BENCH, BETA-FIX).
- **First probe attempt.** The Groth16 download ran at about 10 MB/s and hit the harness's 420 s
  step limit. The resumed step then skipped the proof for lack of disk, because the partial download
  was still in its `RUNNER_TEMP`. That is a harness artifact: a runner has no step limit and starts
  each job with a fresh `RUNNER_TEMP`. The job was re-run from its first step (`ci/logs/rc2bmetal-*`)
  and passed. Its first log is kept as `ci/logs/rc2metal-probe-03.attempt1.log`.
- **Checks on the uploaded kit:**
  - `check-macos-release.sh` on the tarball: rc 0.
  - `check-macos-kit.py --version 0.1.0 --commit f539d5c… --require-validated`: ok ("every macOS
    program links only system libraries, is arm64, signed, with the kit's minimum macOS").

## 2. Install as a new user (sandbox HOME, quarantined download)

**Setup.**
- The sandbox is `HOME=scratch/w10/rc2/home`, entered through `env -i` with the system `PATH` plus
  `~/.zkminer` (the README's `export PATH`).
- The tarball and the CI run's `SHA256SUMS` were put in `~/Downloads`. The tarball was marked as a
  Safari download (`com.apple.quarantine 0083;…;Safari;…`).

The kit README (`packaging/macos/README.md`), followed literally (`logs/install.log`):
- **Checksums.** `shasum -a 256 -c --ignore-missing SHA256SUMS` printed `zkminer-0.1.0-macos-arm64.tar.gz: OK`.
- **Unpack.** `tar -xzf` passes the quarantine flag to every file, and `spctl --assess` rejects
  `zkminer` (rc 3).
- **`./install.sh --with-groth16`:** rc 0 in 74 s.
  - It checked the kit (commit `f539d5cc0a41`) and installed both binaries without the quarantine
    flag (`xattr -l` is empty).
  - It said that the kit has no offline archives, so the first start compiles the pipelines.
  - It downloaded and installed Groth16 v0.2.0 (`du`: 5.4G).
  - Its "Next" list: `init`, `stake 100`, `benchmark`, `run`, and where `BUILDINFO` is.
- **`zkminer help`:** ok. **`zkminer init`:** rc 0. It wrote `config.toml` for 743111 (router
  `0xD931…Ed58`, token `0x4695…36cc`). Its next steps are key, tHEMI and ETH, `zkminer stake 100`,
  `status`, `run`.
- **`zkminer status`** with no key: rc 1, "Environment variable 'ZKMINER_PRIVATE_KEY' not set". This is
  the README's order: the key comes first.
- **First start** (section 3.4), **`zkminer benchmark`**: rc 0 with real numbers (section 3.6).
- **`tools/macos-smoke.sh` from the kit:** `RESULT: ok (exit 0)`.
- **`./install.sh --warm`:** rc 0 in 4.3 s.
- **`./install.sh --uninstall`:** rc 0. It removed the CLI and the worker. It left `config.toml`,
  `~/.risc0` and the pipeline cache, as documented.

**Doc errors found: none that would stop a new user.** Round 1's doc items are all fixed by W10-DOC:
- `--ignore-missing` in the README and in `release.yml`'s notes;
- Gatekeeper over SSH;
- `zkminer stake` in `init` and the README;
- the benchmark's duration;
- the Troubleshooting section.

Minor points, none blocking:
1. The README gives `zkminer benchmark` as "about 4.5 to 5 minutes … (262-314 s measured)". This
   round measured 261 s.
2. The README's first start is "60.3 s measured". This round measured 61.7 s (round 1: 57.8 s).
3. `zkminer benchmark` still prints Linux and NVIDIA advice on a Mac (`nvidia-smi did not answer`)
   and re-logs the worker's INFO lines at WARN (open issue 4).
4. `install.sh --uninstall` also leaves `~/.zkminer/miner.lock`, an empty file that the README does
   not mention.

## 3. The installed worker on this Mac (M5 Max, 36 GB, macOS 27.2.1)

- Every GPU run went through `gpu-run` (heavy, exclusive).
- Each run used the sandbox's installed `~/.zkminer/provers/zkminer-prove-risc0-metal` under `env
  -i`, so budgets were passed explicitly as `RISC0_METAL_MAX_WORKING_SET_BYTES`.
- The load average was 1.2-4.1, and no other GPU work ran.

### 3.1 Full `--benchmark`, default budget (one run)

| program | cycles | STARK | c/s | wrap |
|---|---|---|---|---|
| fibonacci (main's discarded warm-up) | 32,768 | 0.27 s | | 1.60 s |
| sha256-chain | 46,137,344 | 50.72 s | 910K | 1.58 s |
| ecdsa-verify | 65,011,712 | 71.16 s | 914K | 1.59 s |
| bigint-mul | 27,525,120 | 30.61 s | 899K | 1.61 s |
| memory-merkle | 7,340,032 | 8.35 s | 879K | 1.60 s |
| chacha-mix | 8,404,992 | 9.72 s | 865K | 1.61 s |
| **all six** | 154,451,968 | **170.56 s, 905.6K c/s** | | |
| zkop-mix scoring (main; no wrap) | 4,194,304 + 61,865,984 | 4.89 + 68.33 s | | |

- **Against BASELINES '3.1'** (169.56 s, 910.9K c/s): **+0.59 %**. **Against RC2** (169.92 s):
  +0.38 %. Round 1 measured 171.88 s and step 0 171.41 s.
- This is below the 1.5 % threshold, so no A/B was required and none was run. Round 1's interleaved
  `BENCH_ONLY=memory-merkle` A/B at three budgets is in this file's history.
- Peak footprint 14.72 GB (baseline 14.69 GB). Wraps took 1.58-1.61 s. Wall time was 267 s, which
  includes the warm-up and the zkop-mix proofs. Load at the start was 2.96.

### 3.2 Budgets, sequences, hosts

- **memory-merkle at 8 GiB** (po2 19, 7,864,320 cycles), 2 runs:
  - STARK 10.29 / 10.39 s, 765K / 757K c/s, wrap 1.72 s;
  - peak footprint 7.60 / 8.31 GB;
  - round 1 measured 10.39-10.41 s.
- **memory-merkle at 4 GiB** (po2 18, 8,388,608 cycles), 2 runs:
  - STARK 14.15 / 14.17 s, 593K / 592K c/s, wrap 1.72 s;
  - peak footprint 5.79 GB;
  - round 1 measured 14.18-14.23 s.
- **BASELINES '3.1'** gives memory-merkle ~767K c/s at 8 GiB and ~603K c/s at 4 GiB. These `c/s`
  figures are not directly comparable, because since the merge po2 changes memory-merkle's cycle
  count. RC2's own runs were 10.23 s and 13.93 s.
- **4 GiB, Groth16 after keccak.**
  - Test: `a_tight_worker_wraps_after_keccak_and_releases_the_key_between_jobs`, built from
    `f539d5c` and pointed at the installed worker (`ZKMINER_B9_WORKER`; keccak guest
    `multi_test.bin` from `deps/risc0-3.1`). It ran twice.
  - **rc 0 both times.** The warm-up, fibonacci, keccak, memory-merkle and fibonacci again were all
    wrapped (256-byte seals).
  - Each run had 5 of 5 key releases, each "3882.3 MiB freed". keccak took 4.99 s and 4.96 s.
- **20 sequential jobs in one worker at 4 GiB.**
  - Test: `m9_proofs_in_one_worker` with the installed worker, a Warmup first, and fibonacci at
    4,587,520 cycles, 9.59-9.75 s each.
  - The idle footprint was 4836 MiB after proof 1 and 4303-4794 MiB after proofs 2-20. The last
    one, 4712 MiB, is below the first.
  - The lifetime peak was 6207 MiB from proof 2 on (round 1: 6206 MiB), with 21 key releases.
    **No footprint growth.**
- **Simulated 16 GB host.**
  - Settings: `ZKMINER_METAL_HOST_RAM_BYTES=16 GiB`, HAL limit 10.67 GiB,
    `ZKMINER_CUDA_VRAM_BYTES=8 GiB`. The worker planned 8 GiB at po2 19.
  - **Full suite: 206.12 s** for the six programs (round 1: 206.49 s), plus zkop-mix 6.04 + 85.97 s.
    Every program was wrapped (1.73-1.75 s) and verified.
  - **Peak footprint 9.36 GB** (round 1: 9.39 GB). That is inside a 16 GB Mac's 11.5 GiB allowance.
- These are all simulated budgets on this Mac. No real 16 GB Mac has been measured.

### 3.3 Peak memory

This round raised no peak:
- default budget: 14.72 GB;
- 8 GiB: at most 8.31 GB;
- 4 GiB: 5.79 GB, and 6207 MiB in the 20-job run;
- simulated 16 GB host: 9.36 GB.

All of these equal round 1's figures within 0.03 GB.

### 3.4 First start

`BENCH_ONLY=fibonacci --benchmark` (the warm-up alone), timed as process wall time:

| case | wall | pipelines |
|---|---|---|
| **cold first start** (first run in the new HOME, `MTL_SHADER_CACHE_SIZE=0`, no archives) | **61.7 s** | built in 59.3 s (cold): rv32im+zkp 59.3, recursion 28.8, keccak 16.4, groth16 28.8 (in parallel). zkp: 72 PSOs in 28.8 s. rv32im: 13 PSOs in 30.5 s |
| second start (runtime archive kept) | 2.46 s | 72 + 13 hits |
| third start, cold OS shader cache | 2.47 s | 72 + 13 hits |

The cold start ran at a load of 1.95. Round 1 measured 57.8 s, and the README says 60.3 s.

### 3.5 Correctness

- **Stock crates.io risc0-zkvm 3.1.0 verifier** (`tools/stock_verify31`, the RC2 build, selector
  `e71e6620`):
  - **23 of 23** Groth16 receipts from this round pass with `STOCK 3.1 VERIFY: OK`. They come from
    the full suite, every memory-merkle budget run, the simulated 16 GB host and the three starts:
    fibonacci 9, memory-merkle 6, and 2 each for the other four.
  - A fibonacci receipt checked against memory-merkle's image id is rejected ("claim digest does not
    match").
- **Receipt types.** The worker returns Groth16 receipts only. Composite and succinct receipts stay
  inside the worker, which verifies them there: zkop-mix's no-wrap path and the keccak and M9 tests.
- **The fork's verifier matrix.** For this risc0 tree (`37b434755`, unchanged since round 1),
  W10-GATE's `run_matrix.sh` judged composite, succinct and Groth16 receipts at the default, 8 and 4
  GiB budgets: 30/30 OK.
- **3.0 receipts are rejected.** All 30 of B9-M26's receipts from the 3.0 producer are **REJECTED**,
  plain and with `--relabel-as-31`: **60 of 60** (`out/sv/r30.log`).
  - They cover composite, succinct and Groth16 receipts of fibonacci, merkle, keccak and compose.
  - They were made at the default, 8 and 4 GiB budgets, including the `_wpso` sets.
- **CLI end to end on a local chain.**
  - Setup: the test binary `crates/zkminer-cli/tests/localnet.rs`, built from `f539d5c`.
    `ZKMINER_LOCALNET_ZKMINER` and `ZKMINER_LOCALNET_RISC0_WORKER` point at the installed CLI and
    worker. Anvil forked live 743111 at block 7,234,420.
  - **`mines_the_claimable_jobs`** (`ZKMINER_LOCALNET_MINE=1`): **rc 0 in 180 s.**
    - The 4 claimable risc0 jobs (Full, Fields, NoneForUs, FullForAnother) were each claimed, proved
      on Metal and fulfilled.
    - Each paid 4.95 tHEMI (5 tHEMI minus the 1 % fee).
    - The 8 non-claimable jobs were not claimed.
  - **`refuses_to_claim_without_a_matching_verifier`** (the 3.0 selector): rc 0 in 58 s.
  - **`fulfils_with_a_replayed_receipt`** (mock worker): rc 0 in 121 s.
- **B9-CHAIN live read-only checks** against `https://testnet.rpc.hemi.network/rpc`, head 7249407:
  - **Handoff section 13, tests 1-4** (`live/checks.log`):
    - the chain id is 743111;
    - the router, staking, registry and token wiring is as expected, and nothing is paused;
    - `getAdapter` for the three ids gives status 1, ratio 15,000, min stake 1e20 and fee 100;
    - the risc0 verifier gives `SELECTOR 0xe71e6620` and `VERSION "3.1.0"`;
    - `getProofNonce` answers live;
    - there are 453 `JobSubmitted` logs.
    - The script's `version()` decode error on the adapters is a mismatch in the script's return
      type and was the same in round 1.
  - **`live_743111`, built from `f539d5c`: 4/4.**
    - `the_live_deployment_verifies`: on "Hemi testnet (743111, 2026-11-16)".
    - `the_proof_nonce_matches_the_live_router`.
    - `every_live_job_descriptor_decodes`: 454 logs.
    - `the_abandoned_stack_is_refused_live`.
  - **`abi_pins`: 3/3.** The cross-check against a hemiprove-contracts checkout was not run, because
    there is none on this Mac.
  - **The decisive check** (`scripts/verify_live.sh`, `eth_call` only), using this kit's fibonacci
    and memory-merkle receipts (`dump31`, a 260-byte seal with prefix `0xe71e6620`):
    - `Registry.verifyProof` and the native verifier both accept them.
    - A flipped seal nibble, and a journal one byte too long, revert with `0x439cc0cd`.
    - The 3.0 fixture (`73c457ba`) and a 3.1 seal relabelled `73c457ba` revert with the
      selector-mismatch error `0xb8b38d4c`.

### 3.6 `zkminer benchmark` through the CLI (`out/cli/`)

| case | expected | got |
|---|---|---|
| working worker | rc 0, real numbers | **rc 0 in 261 s.** 2.72 MzkOP/s. Device row: po2 20, 892.3K c/s, Groth16 1.6 s. Per program: sha256-chain 51.04 s, ecdsa-verify 71.27 s, bigint-mul 30.65 s, memory-merkle 8.30 s, chacha-mix 9.73 s, zkop-mix 68.27 s. A plain `zkminer benchmark` saves nothing (by design; only `--calibrate` writes `benchmarks.json`) |
| the worker exits 3 at start-up (a script that prints "forced failure"; own HOME, same CLI and config) | non-zero exit, the worker's error, no table | **rc 1 in 4 s, no table.** Header `Workers: risc0:metal:0 (failed to start; see below)`. Then `BENCHMARK FAILED: nothing was measured or saved.` and `risc0:metal:0 (Apple M5 Max): could not start: Handshake with worker risc0 failed (timeout=10s): Worker risc0 process died (EOF) (the worker's last output: forced failure) (then, … Backoff …)`, followed by the smoke and quarantine advice |
| the real worker, warm-up fails (`RISC0_METAL_MAX_WORKING_SET_BYTES=1 GiB`) | the same | **rc 1 in 4 s, no table.** `risc0:metal:0 (Apple M5 Max): Worker risc0 process died (EOF) (the worker's last output: Metal working-set budget exceeded: allocating 536870912 bytes … limit of 1073741824 bytes …)` and the smoke advice |

**This closes RC3 round 1's failing check.**

### 3.7 Not run here

- **The interleaved A/B.** The full suite came in at +0.59 %, below the 1.5 % threshold that requires
  one. This round changed no risc0, kernel, metallib or compiler input, and the worker's commits since
  round 1 change only its benchmark exit codes and error text.
- **A real macOS 26 Mac, a real 16 GB Mac, and GPU families other than `applegpu_g17s`.** None is
  available.
- **The R17 audit, the stress run and the fork's Metal suites.** There has been no kernel or risc0
  change since W10-GATE's gates ran on this tree. The 5 metallib digests and the compiler (27B47) are
  unchanged.
- **A Linux or Windows build of the integrated branch.** There is no such host. CI on `main` will be
  the first (open issue 1).
- **The macOS 26 AOT fallback and the 3.0 producer.** Their inputs are unchanged, and RC2 and B9-M26
  cover them.
- **Live-chain transactions.** They are forbidden here (see the checklist).

## 4. macOS 26: what is validated

Unchanged since RC2, because no kernel, metallib or compiler change has gone in since.
- **B9-M26 on this Mac:**
  - the 26.0-target AIR 2.8 kernels;
  - `ir_scan` A=0 S=0, and a clean stress run;
  - the suites twice, the stock-verifier matrix, the A/B and the API audit.
- **Two macOS 26.6.2 VM sessions** passed (`scratch/w9/B9-M26/vm/out-gui/RESULTS.md` and
  `…/out-rc1/RESULTS.md`):
  - install, quarantine and `spctl`;
  - `install.sh`, the Groth16 download and `init`;
  - the clear missing-key error, the 8 GiB / po2 19 plan, and the loading of all 5 metallibs.
- **The VMs' paravirtual GPU says nothing about proving.** The VM run is how the benchmark failure,
  now fixed, was found.
- **Still required:** a real Apple Silicon Mac on macOS 26 with at least 16 GB (checklist step 5).

## 5. Open issues

1. **Linux (CUDA, ROCm, Intel) and Windows have not been built against the fork pin.**
   - W10-GATE makes every fork change behave like `release-3.1` off Metal by default, and the prover
     crate type-checks for Linux.
   - Main's CI will be the first real build. After the push, watch `build-docker.yml`,
     `build-windows.yml` and `e2e.yml` on `main`.
2. **Neither repository has these commits on GitHub yet.** `https://github.com/hemilabs/risc0` has no
   `37b434755` until checklist step 1.
3. **Disk on the 14 GB runner.**
   - The build job's minimum free space is 1.22 GB, the same as round 1 (RC2: 2.05 GB).
   - cpu-tests has 1.90 GB free at its peak (round 1: 2.07 GB).
   - Watch `macos-disk.sh` on the real runner. If it fails, prune more before packaging or give the
     runner more disk.
4. **Mac messages in `zkminer benchmark`** (from main):
   - the 300 W GPU power fallback "feeds the profitability model directly", so a Mac's profitability
     estimate uses 300 W. This needs a decision or a fix;
   - the `nvidia-smi` warning;
   - the worker's INFO lines re-logged at WARN.
5. **From W10-BENCH and BETA-FIX, not fixed:**
   - A worker file that is present but not executable is not discovered, so `zkminer benchmark` runs
     the labelled SIMULATED path and exits 0. This is not a kit path, because `install.sh` sets the
     mode.
   - The TUI drops a whole run when one card fails and another measures.
   - A simulated `--json` run exits 0.
   - `benchmark_targets()` ignores Metal.
   - The 150 ms proc test bound fails under load.
   - The quoted worker line in errors can come from guest stdout. It is sanitized, capped at 300
     characters, and only local.
   - The security reviewer's optional one-line warning for `RISC0_VERBOSE` and
     `RISC0_METAL_REC_CAPTURE` was not added.
6. **Carried over from RC2:**
   - every Mac has a first start of about a minute (no AOT archives);
   - B9-CI's runner items: nothing has run on the real runner, its SDK changes the metallib
     digests, and the `xcode` toolchain mode is untested;
   - B9-FX (the fixture symlink guard) is unmerged;
   - there is no kit-aware missing-Groth16 message from the worker itself;
   - the `Jimver/cuda-toolkit` tag in `build-windows.yml` is unpinned;
   - the `w7` dispatcher table and the debug-only knobs (B9-G1, B9-ZK) remain.
7. **Not measured:** a real 16 GB Mac (including its cold first start on an M1-M4), other GPU
   families, a real macOS 26 runtime, and `build-macos.yml` on the real runner.

## 6. User checklist

Nothing below was executed. The push URLs of the local checkouts are disabled on purpose, so each
command names its URL. Steps 0 and the RC are done: W10-BENCH, W10-DOC and the BETA-FIX fix are
merged (`f9f535b`), and this round checked `f539d5c`.

1. **Push the risc0 fork unchanged.** `Cargo.lock` pins this exact sha:

   ```sh
   cd /Users/user/zkminer/deps/risc0-3.1
   git rev-parse zkminer/metal-3.1      # must print 37b434755ce77dd1354d957a7b61912aa4359423
   git merge-base --is-ancestor origin/release-3.1 37b434755ce77dd1354d957a7b61912aa4359423 && echo contains-release-3.1
   git push git@github.com:hemilabs/risc0.git 37b434755ce77dd1354d957a7b61912aa4359423:refs/heads/zkminer/metal-3.1
   git ls-remote https://github.com/hemilabs/risc0 refs/heads/zkminer/metal-3.1   # must print 37b434755…
   ```

2. **Push zk-miner.** `main` (`c030355`) is an ancestor of `metal-3.1`, so this is a fast-forward:

   ```sh
   cd /Users/user/zkminer/zk-miner-3.1
   git fetch https://github.com/hemilabs/zk-miner main && git merge-base --is-ancestor FETCH_HEAD metal-3.1 && echo fast-forward
   git log --oneline -1 metal-3.1        # this file's commit (its parent is f539d5c)
   git push git@github.com:hemilabs/zk-miner.git metal-3.1:refs/heads/metal-3.1     # keep the branch
   git push git@github.com:hemilabs/zk-miner.git metal-3.1:main                     # fast-forward main
   ```

   If `main` is protected, open a PR and merge it with a merge commit, or with a fast-forward if the
   repository allows one. A squash or rebase merge changes the shas.

   ```sh
   gh pr create --repo hemilabs/zk-miner --base main --head metal-3.1 --title "macOS (Metal) beta on RISC Zero 3.1"
   ```

3. **Repository variable** (optional). The workflow falls back to `zk-runner-mac-new`, so set the
   variable only to use a different runner label. Never register this Mac as a runner.

   ```sh
   gh variable set ZKMINER_MACOS_RUNNER --repo hemilabs/zk-miner --body zk-runner-mac-new
   ```

4. **CI on the real runners.**
   - The push to `main` triggers `build-macos.yml`, `build-docker.yml` and `e2e.yml` (by path). Run
     `build-windows.yml` by hand.
   - `build-macos.yml` needs its build, cpu-tests and metal-probe jobs to pass; metal-probe is
     informational.
   - Compare the CI kit's `BUILDINFO` with "The candidate": `min_macos=26.0`, `metal_compiler …
     32023.922`, `risc0_rev 37b434755…`, no archives.
   - Watch the build job's disk line (open issue 3).
   - The Linux and Windows builds are the first builds of the fork pin on those platforms (open
     issue 1).

   ```sh
   gh workflow run build-macos.yml   --repo hemilabs/zk-miner --ref main -f metal_toolchain=pinned
   gh workflow run build-windows.yml --repo hemilabs/zk-miner --ref main
   gh run list --repo hemilabs/zk-miner --branch main --limit 10
   ```

5. **macOS 26 on real hardware (user decision: supported).**
   - **Before tagging**, test on a real Apple Silicon Mac with macOS 26 and at least 16 GB: ideally a
     16 GB M1-M4.
   - If you can, also test other GPU families: an M1/M2 (`applegpu_g13*`/`g14*`) and an M3/M4
     (`g15*`/`g16*`).
   - In the extracted CI kit (downloaded with a browser, so that the quarantine path is covered too):

     ```sh
     shasum -a 256 -c --ignore-missing SHA256SUMS        # the CI run's SHA256SUMS beside the tarball
     tar -xzf zkminer-0.1.0-macos-arm64.tar.gz && cd zkminer-0.1.0-macos-arm64
     ./install.sh --with-groth16
     tools/macos-smoke.sh                                # scripts/ci/macos-smoke.sh in the repository
     ~/.zkminer/provers/zkminer-prove-risc0-metal --metal-arch
     ~/.zkminer/provers/zkminer-prove-risc0-metal --benchmark
     export PATH="$HOME/.zkminer:$PATH"; zkminer init && zkminer benchmark
     ```

   - Expect the first start to compile the pipelines, which takes a minute or more. Then expect:
     - every program "verified";
     - the smoke script's `RESULT: ok`;
     - `zkminer benchmark` exiting 0 with real numbers.
   - Keep the logs. Note the chip, the RAM, the macOS build and the first-start time.

6. **HemiProve deployment of 2026-11-16 on 743111** (handoff `/Users/user/zkminer/zkminer-handoff-743111.md`).
   - Main's own update is now the code path: `deployment.rs`, with ABIs re-vendored from
     hemiprove-contracts `3bc441d`. `3bc441d` equals B9-CHAIN's `8e1808b` except for `LICENSE`.
   - This round re-ran these read-only checks against the live chain:
     - handoff tests 1-4;
     - `live_743111` 4/4;
     - `abi_pins` 3/3;
     - `Registry.verifyProof` with this kit's receipts.
   - It also re-ran test 6 on a fork (section 3.5).
   - After the governance handoff, check that `zkminer run` still passes its deployment checks.
   - With a hemiprove-contracts checkout at `3bc441d`, also run
     `ZKMINER_CONTRACTS_REPO=<checkout> cargo test -p zkminer-chain --lib`.

7. **Funded-key acceptance tests** (handoff section 13), live on 743111:
   - **What you need:**
     - a staked prover key;
     - tHEMI from the HemiProve team: at least 100 per lock, and 1,000 for custom-verifier jobs;
     - testnet ETH.
   - Keep the transaction hashes.
   - **Tests for the Mac beta: 5, 6, 10, 11, 13, 14, 15, 16, 17, 18, 19.**
     - Schedule 19 (the pause drill) with the team.
     - For 14, expect `InsufficientFreeStake`, not `Panic(0x01)` (B9-CHAIN).
   - **Not applicable to this build: 7, 8, 9, 12** (the SP1 nonce marker, PLONK,
     `claimAndFulfillAssigned`).

8. **Cut v0.1.0** once steps 1-7 are done.
   - `release.yml` requires the tag to equal `[workspace.package].version` (`0.1.0`).
   - It builds Linux, Windows and the macOS kit (`build-macos.yml`, pinned 27B47) from the tagged
     commit.
   - The release notes already say `--ignore-missing`.
   - Do a dry run on `main` first, which publishes nothing. Check its assets, then tag:

   ```sh
   gh workflow run release.yml --repo hemilabs/zk-miner --ref main -f dry_run=true -f gpu_validation=true
   gh run watch --repo hemilabs/zk-miner        # all jobs green; download and inspect the assets
   git -C <checkout of main> tag -a v0.1.0 -m "zk-miner 0.1.0 (macOS beta: Apple Silicon, RISC Zero 3.1; unsigned)"
   git -C <checkout of main> push git@github.com:hemilabs/zk-miner.git v0.1.0
   ```

   Compare the release's macOS kit `BUILDINFO` with this RC. Its sha256 will differ (the commit and
   the SDK).
