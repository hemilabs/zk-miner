# B9-CI: GitHub Actions for the macOS beta kit

Branch `item/B9-CI` (worktree `/Users/user/zkminer/zk-miner-3.1-wt-B9-CI`), from `item/B9-M26` `eb782ef`.
The maintainer documentation is `docs/ci-macos.md`. This note has the evidence.

**Scratch:** `/Users/user/zkminer/scratch/w9/B9-CI/`:

| path | what |
|---|---|
| `sim/sim.py`, `sim/dump.rb`, `sim/drive.sh` | the harness that runs the workflow's steps (round 1: expressions evaluated, `next <job>` driver) |
| `sim/logs/`, `sim/results.jsonl`, `sim/report-r1.md` | the round-1 run: build, cpu-tests, metal-probe, build, cpu-tests (log names `<n>-<job>-<step>.log`) |
| `sim/r0/` | the first round: `sim-r0.py`'s harness, logs of the final run and of tries 1 and 2, `report-final.md` |
| `sim/artifacts/` | the CI-built kit and the probe logs |
| `receipts/final/`, `receipts/r1/` | the probe's receipts (first round, round 1) |
| `expr-before.log` | `test-workflow-expressions.py` on the first-round workflow (the finding reproduced) |
| `reltest/` | the release-assembly tests: a fake staging set and shims |
| `dl/` | actionlint and shellcheck downloads |

**Ground rules followed:**

- No Rust, Metal or risc0 file changed, and no main checkout was edited.
- GPU commands ran under `gpu-run`: `--light` for the CPU-test step (worker unit tests), heavy for the
  probe's proof. No run was killed.
- Nothing was pushed, and no runner was registered.

The worktree resolves risc0 as Makefile.mac says: `RISC0_SRC=auto -> local`
(`/Users/user/zkminer/deps/risc0-3.1`, HEAD `d94ef6501`, the rev `Cargo.toml` pins). The CI and the
simulation build git mode through the mirror. The brief named `84df3e8c0`; the checkout is at
`d94ef6501`, as the B9-M26 note found.

## Files

| file | change |
|---|---|
| `.github/workflows/build-macos.yml` (new) | jobs `build` (required), `cpu-tests` (required), `metal-probe` (`continue-on-error`). Triggers: push/PR to `main` on the kit's paths, `workflow_dispatch`, `workflow_call`. Runner `${{ vars.ZKMINER_MACOS_RUNNER \|\| 'zk-runner-mac-new' }}`. Actions pinned by the same SHAs as the other workflows. A fork's PR is skipped |
| `.github/workflows/release.yml` | job `macos` calls `build-macos.yml` (`metal_probe: false`). `assemble` needs it and passes `ZKMINER_VERSION` (from `check-version`) and `EXPECT_COMMIT`. The release notes gain a macOS section |
| `scripts/ci/macos-metal-toolchain.sh` (new) | runner facts; the pinned 27B47 (default) or the runner's Xcode compiler (`xcode`: `xcodebuild -downloadComponent MetalToolchain` when missing, marked unvalidated); versions; `METAL_TC`. `--cleanup` unmounts |
| `scripts/ci/macos-toolchains.sh` (new) | rustup 1.29.3 (SHA-256), the `rust-toolchain.toml` Rust, rzup from the pinned fork rev, the guest toolchain 1.97.0, protoc 36.2 (SHA-256) |
| `scripts/ci/macos-cpu-tests.sh` (new) | worker unit tests without the device tests (round 1: and the host-state tests), zkminer-prover discovery/dispatcher, `test-metal-tc.sh`; kit build settings |
| `scripts/ci/macos-prune-target.sh` (new) | deletes intermediates: `--guests` keeps only the embedded guest programs; the default keeps only the two binaries |
| `scripts/ci/macos-disk.sh` (new) | `df` and `du` after every heavy step |
| `scripts/ci/macos-probe.sh` (new) | the metal-probe job: kit install in temp, device probe, the Groth16 component streamed into temp, one proof, summary |
| `scripts/ci/check-macos-kit.py` (new) | Mach-O and kit check without Apple tools (for the Linux assemble job) |
| `scripts/ci/test-check-macos-kit.sh` (new) | the kit passes; 11 broken copies are rejected (round 1: + `--require-validated`) |
| `scripts/ci/lint-workflows.sh`, `scripts/ci/actionlint.yaml` (new) | actionlint (+ shellcheck), with the self-hosted labels |
| `scripts/ci/assemble-macos.sh` | `ASSEMBLE_BUILD_ONLY=1`, `ASSEMBLE_ENV_OUT=<file>`, `ASSEMBLE_ENV_ONLY=1` (no default changed) |
| `scripts/ci/assemble-release.sh` | copies the macOS kit after checking its `SHA256SUMS` line, version and commit |
| `scripts/ci/check-release-libs.sh` | checks the macOS kit (Mach-O); fails on no kit, two kits, or a Mach-O file elsewhere |
| `scripts/ci/fetch-metal-toolchain.sh` | aborts and resumes a stalled download; resolves its directory physically (mount reuse check) |
| `scripts/ci/{assemble-release,check-release-libs,gpu-validate,unpack-provers}.sh` | mode 0755 (see "Before") |
| `docs/ci-macos.md` (new) | the jobs, the runner, the disk budget, release wiring, pins, knobs |
| `scripts/ci/macos-clean-home.sh` (new, round 1) | at the start and end of every job: deletes `~/.cargo/registry/src`, `~/.cargo/git/checkouts`, the Groth16 coefficient cache and the risc0 kernel cache |
| `scripts/ci/test-workflow-expressions.py` (new, round 1) | a GitHub expression evaluator and the per-event table test of `build-macos.yml`; run by `lint-workflows.sh` |

## Before

- **No macOS workflow.** `release.yml` assembled only the Docker build's artifacts. Nothing in CI read
  Mach-O.
- **actionlint 1.7.12 on the existing workflows: 1 error.** `release.yml:145` `label "zkminer-gpu" is
  unknown`, a self-hosted label. `scripts/ci/actionlint.yaml` now declares it and `zk-runner-mac-new`.
- **Release blocker found:**
  - `scripts/ci/assemble-release.sh`, `check-release-libs.sh` and `gpu-validate.sh` are run by path
    from `release.yml`, and `unpack-provers.sh` by path from the other two;
  - all four were committed `100644` since they were added (`git ls-tree a9ccb6e`);
  - on a Linux runner that is `Permission denied`, so the release's `assemble` and `validate` jobs could
    not have passed;
  - they are now `100755`.
- **Ground truth for the kit:** the B9-M26 kit (`scratch/w9/B9-M26/r2/dist`, commit `23804f3`, 208 MB with
  the `macos27` archives).

## Design decisions and their evidence

### The compiler: the pinned 27B47, as B9-M26 decided

- `macos-metal-toolchain.sh` mounts it through `fetch-metal-toolchain.sh`, and refuses a version line
  other than `VALIDATED_METAL_COMPILER`.
- It prints the runner's Xcode compiler only for information.
- The `xcode` mode is the brief's `xcodebuild -downloadComponent MetalToolchain` path:
  - it detects the component and installs it when missing;
  - it exports `METAL_COMPILER_UNVALIDATED=1`;
  - it is refused on a tag.
  - Not executed here: this Mac has no Xcode.
- **The CI-built worker embeds the validated GPU code.** `build-metal-aot.sh --worker-digests` over the
  simulated CI kit's worker and over the B9-M26 kit's worker gives the same sorted digest list (sha256
  `0d488ee9…a33` for both, 7 metallibs).
  - The binaries differ, as B9-DEP explains: the guest image ids depend on `HOME`, and so do the paths.
  - On the real runner, the Xcode 26 SDK changes the AIR's `SDK Version` only (B9-M26), so the digests
    will differ there but the code will not.

### No offline archives in a CI kit (`AOT_ARCHES=none`)

- Building the archives needs an Apple GPU (the dump tests) and about 5 GB more disk.
- They must match the build's metallib digests, and the runner's SDK changes those digests.
- So a CI kit's first start compiles the pipelines once: about 1 minute on an M5 Max (B9-M26).
- A kit with archives still comes from `assemble-macos.sh` on a Mac. `docs/ci-macos.md` says so.

### The tests run in their own job (tried first in the build job: rejected)

- **Attempt 1.** I ran the CPU tests after the build in the same job, reusing its environment
  (`ASSEMBLE_ENV_OUT`):
  - `cargo test --release` of the worker's bin recompiled **271 crates**, from `libc` up through the
    risc0 `-sys` kernel crates and the guests. The dev-dependency `zkminer-prover/testing` and
    `tempfile` change the features of shared dependencies.
  - Disk went from 8.09 GB to **13.76 GB of 13.79 GB**, and `test-metal-tc.sh` died with `No space left
    on device` (`logs-try1/build-05.log`).
  - Before that run I had pruned the guests to save space, which made it worse: the build script reran
    and rebuilt them (3.5 GB).
- **Fix: a `cpu-tests` job.** It starts from a clean workspace and builds the tests alone with the kit's
  settings (`ASSEMBLE_ENV_ONLY=1`). After the worker's tests it prunes the guests' intermediates
  (6236 → 2631 MiB), and it deletes `target/` before the cache post-step.
  - Without the mid-step prune: peak 12.13 GB, 1.66 GB free (`logs-try2`).
  - With it: 10.88-11.63 GB, at least 2.16 GB free.
- Changing `crates/zkminer-prove-risc0/Cargo.toml` to avoid the second build is not this item's.
- The three device tests that are skipped are `metal_host::tests::enforcement_on_this_mac`,
  `metal_host::tests::this_mac_is_supported` and `metal_start::tests::this_macs_gpu_architecture_is_readable`.
  They read the Metal device or need a 16 GB Mac. `mac-test-miner` keeps running them on Macs.

### metal-probe: the Groth16 component in the job's temp directory, streamed

- **Rejected: `install.sh --with-groth16` into `~/.risc0`.**
  - On a persistent runner the 5.4 GB would stay, and the build job's peak (11.75 GB) would no longer
    fit.
  - While it installs, the 2.4 GB archive and the 5.4 GB unpack coexist: 7.8 GB. With the toolchains
    in `HOME` that leaves about 1.0 GB free.
- **Now:**
  - the runner's own complete component is used if present;
  - otherwise `curl | python (SHA-256) | tar -xJ` into `$RUNNER_TEMP/probe/g16`, checked against the
    kit's `groth16_sha256` before use and deleted at the end;
  - peak 11.21 GB, 2.57 GB free.
- The proof is skipped, with a notice, below `PROBE_MIN_FREE_GIB` (7).

### Smaller findings fixed on the way

- **Stalled download.** `fetch-metal-toolchain.sh`'s `curl` sat at 0 bytes for the whole 9-minute
  chunk (`logs-try2/build-01.log`). The CDN answered at once afterwards.
  - `fetch-metal-toolchain.sh` and `macos-toolchains.sh` now abort under 100 kB/s for 60 s
    (`--connect-timeout 30 --speed-limit 102400 --speed-time 60 --retry-all-errors`) and resume.
  - The next download took 18-20 s.
- **`macos-cpu-tests.sh` committed `100644`.** The first run failed with `Permission denied`.
- **`test-metal-tc.sh` needs a toolchain choice.** Its crate lives outside the repository, and rustup
  installed with `--default-toolchain none` has no default ("rustup could not choose a version of
  cargo", 6 FAIL). The script now sets `RUSTUP_TOOLCHAIN` from `rust-toolchain.toml`, and the run
  passes 18/18.
- **YAML anchors** for the `paths:` list were replaced by two plain lists, not trusting every consumer
  with anchors.

## Validation

First-round evidence. Its log paths (`logs/`, `logs-try1/`, `logs-try2/`) are now under `sim/r0/`.
The round-1 re-runs are in "Fix round 1" below.

### Lint

- `scripts/ci/lint-workflows.sh` runs:
  - actionlint **1.7.12**, the official `actionlint_1.7.12_darwin_arm64.tar.gz`. Its SHA-256
    `aba9ced2…6953f` matches the release's `actionlint_1.7.12_checksums.txt`, whose own SHA-256
    `433028cf…a4f5` equals the release asset digest. Installed as `/Users/user/zkminer/bin/actionlint`.
  - shellcheck **0.11.0** (official darwin aarch64 tarball, SHA-256 `339b930f…d26f` = the asset digest;
    `/Users/user/zkminer/bin/shellcheck`).
- All 6 workflows are clean, including shellcheck on every `run:` script.
- `shellcheck -S warning` is clean on every script this item wrote or changed.

### Every `run:` step from a fresh clone in a 14 GB disk image

**Harness** (`sim/sim.py`):

- **Image:** `hdiutil create -size 13351m -fs APFS -type SPARSE` (14.0e9 bytes; 13.79 GB usable),
  attached with `-nobrowse` and Spotlight off. It holds:
  - `HOME` (so `CARGO_HOME=$HOME/.cargo`, rustup, `~/.risc0` and the kernel cache, all starting empty);
  - the workspace, a fresh `git clone --no-local` of `item/B9-CI`;
  - one `RUNNER_TEMP` per job.
- **Environment:**
  - `PATH` = `/usr/bin:/bin:/usr/sbin:/sbin` plus what the steps add through `GITHUB_PATH`;
  - `CARGO_BUILD_JOBS=5`;
  - `CARGO_NET_GIT_FETCH_WITH_CLI=true`, and the mirror through `GIT_CONFIG_*`. **Deviation:**
    `GIT_CONFIG_COUNT=2`, not 1. The second rule keeps `hemilabs/risc0-sppark` on GitHub (the prefix
    trap documented in B9-DEP / RELEASE-DEPS.md).
- **Running the steps:**
  - each `run:` is the text from the YAML (Ruby's YAML parser), run as `bash --noprofile --norc -eo
    pipefail` under `/usr/bin/time -l`, with the job and step env evaluated from a fixed expression
    table;
  - `GITHUB_ENV` and `GITHUB_PATH` are honoured;
  - a 1-s sampler records the volume's used bytes and the summed RSS of the step's process tree;
  - `uses:` steps are simulated: `checkout` (clone, or `git clean -ffdx` + reset), the cache (a miss),
    upload and download (a copy outside the image);
  - the cache's post-step is real `tar | zstd` of the cached paths: 628 MB, then deleted.
- The jobs ran one after another with `HOME` kept: the persistent-runner worst case.
- **Simulation-only deviation:** a user cannot mount a disk image on a mount point inside a user-mounted
  disk image (`hdiutil: attach failed - Permission denied`, reproduced by hand). So each job's
  `$RUNNER_TEMP/metal-tc` is a link to a directory outside the image, and an allocated 907,713,236-byte
  ballast file (the toolchain dmg's size) stands in for it inside the image.
  - On a runner `RUNNER_TEMP` is on the boot volume, where the B9-M26 mount worked.
  - The download's transient peak was measured inside the image in try 1: 1.79 GB, at a moment when
    11.9 GB were free.

**Final run** (pre-squash commit `b2a4a46`, every step rc 0, one chunk each; load average 2.9-4.4, other
agents active). Its workflows and scripts equal the committed ones but for a comment in
`lint-workflows.sh`:

| job | step | wall s | used start → end GB | peak used GB | least free GB | peak tree RSS GB | `time -l` max RSS GB |
|---|---|---|---|---|---|---|---|
| build | checkout | 1 | 0.95 → 0.96 | 0.96 | 12.83 | 0.00 | 0.04 |
| build | runner and Metal toolchain | 18 | 0.96 → 0.96 | 0.96 | 12.83 | 0.17 | 0.17 |
| build | toolchains (rustup, Rust 1.97.1, rzup build, guest toolchain, protoc) | 60 | 0.96 → 3.57 | 3.59 | 10.20 | 1.37 | 1.08 |
| build | build worker + CLI | 296 | 3.57 → 11.72 | **11.74** | **2.05** | 6.02 | 2.28 |
| build | delete intermediates | 2 | 11.72 → 4.84 | 11.72 | 2.07 | 0.01 | 0.00 |
| build | package + check + checker test | 43 | 4.84 → 4.97 | 7.34 | 6.45 | 0.39 | 0.38 |
| build | unmount | 1 | 4.97 → 4.96 | 4.97 | 8.82 | 0.00 | 0.00 |
| build | post: cache save | 1 | 4.96 → 4.96 | 4.96 | 8.83 | 0.00 | 0.24 |
| cpu-tests | checkout (cleans) | 1 | 4.94 → 4.61 | 4.94 | 8.85 | 0.00 | 0.01 |
| cpu-tests | runner and Metal toolchain | 18 | 4.61 → 4.61 | 4.61 | 9.18 | 0.17 | 0.17 |
| cpu-tests | toolchains (present: skipped) | 1 | 4.61 → 4.62 | 4.62 | 9.17 | 0.00 | 0.03 |
| cpu-tests | tests | 246 | 4.62 → 8.49 | **10.88** | **2.91** | 4.60 | 1.95 |
| cpu-tests | delete the test build | 1 | 8.49 → 5.38 | 8.49 | 5.30 | 0.00 | 0.00 |
| cpu-tests | unmount, post: cache save | 2 | 5.38 → 5.37 | 5.38 | 8.41 | 0.00 | 0.21 |
| metal-probe | checkout | 1 | 4.44 → 4.44 | 4.44 | 9.35 | 0.00 | 0.01 |
| metal-probe | probe + one proof | 79 | 4.56 → 5.20 | **11.21** | **2.57** | 5.09 | 7.52 |

- **Disk.** The worst least-free across all runs of the final scripts was **2.04 GB** (build), 2.16 GB
  (cpu-tests, try 2's sample) and 2.56 GB (probe). All are over the 1.5 GB bar.
- **Memory.** The peak RSS, at most 6.1 GB (summed over the build's process tree) and 7.5 GB (the
  worker's proof), is well under 14 GB.
- **Wall time.** About 6 min for `build` here, 4.5 min for `cpu-tests` and 1.5 min for the probe. A
  5-core VM is slower: the jobs have 240-minute and 60-minute timeouts.
- **Outputs.**
  - The kit: `zkminer-0.1.0-macos-arm64.tar.gz`, 121 MB (192 MB unpacked), no archives, sha256
    `ddd34ec2…40dd1`.
  - Its `BUILDINFO`: `min_macos=binaries_minos=metal_target=26.0`, `metal_compiler=Apple metal version
    32023.922 (metalfe-32023.922.4)`, `metal_compiler_validated=yes`, `metal_sdk=27.2`,
    `commit_dirty=no`.
  - `check-macos-release.sh` ok, `check-macos-kit.py` ok, `test-check-macos-kit.sh` **11/11**.
- **Tests:** worker unit tests **61 passed** (3 filtered), zkminer-prover **131 passed**,
  `test-metal-tc.sh` **18/18**.
- **Probe on this Mac.**
  - Device: `Apple M5 Max`, `applegpu_g17s`, families apple1-10/metal3/metal4,
    recommendedMaxWorkingSetSize 30,150,672,384.
  - The Groth16 component was streamed and checked in 71 s.
  - fibonacci: STARK 0.28 s and Groth16 wrap 1.62 s, verified by the worker; smoke exit 0, job exit 0.
  - **The receipt passes the stock crates.io 3.1.0 verifier:** `STOCK 3.1 VERIFY: OK`, selector
    `e71e6620`, using `scratch/w9/B9-M26/bin/stock-verify31`. Copy in `receipts/final/`.
- The image was detached and deleted afterwards.

### Release assembly (Linux scripts, run here with shims)

Setup (`reltest/`):

- a fake staging set: every Linux artifact as a dummy file, and `dist-macos` = the CI-built kit;
- a `tar` shim that drops GNU-only options;
- a `docker` shim, since there is no Docker here. The Linux `ldd` part is unchanged and was not run.

Results:

- **`assemble-release.sh`** with `ZKMINER_VERSION=0.1.0` and the kit's commit: rc 0. The release holds
  the kit, and the release's `SHA256SUMS` lists it.
- **Negative cases, each rc 1:**
  - another version ("missing … zkminer-0.2.0-macos-arm64.tar.gz");
  - another commit;
  - a `dist-macos/SHA256SUMS` that does not match;
  - no macOS artifact.
- **`check-release-libs.sh`:** rc 0 on the release. rc 1 for:
  - two kits;
  - a Mach-O file (`/usr/bin/true`) posing as `zkminer-prove-openvm`.
- **`check-macos-kit.py`** on the B9-M26 kit (with archives): ok, 11 GPU binary archives counted
  (Mach-O, CPU type `0x1000013`). `test-check-macos-kit.sh` on it: 11/11.
- **Not run on Linux.** The script is plain Python 3 (no Apple tools; `tarfile`, `hashlib`, `struct`)
  and `check-release-libs.sh` uses GNU `od`, but no Linux host or Docker was available.

### Not needed, not run

- **Performance A/B: none needed.** No Rust, kernel or host code changed, and the CI-built worker's
  metallibs are digest-identical to the validated B9-M26 kit's. Performance therefore stays at the
  '3.1' baseline as measured in B9-M26. Nothing ran at a simulated budget, since no runtime changed.
- **R17 `ir_scan.py` / `run_stress.sh`: not run.** No Metal kernel TU changed (identical metallib
  digests).
- **The 3.0 rejection matrix: not re-run.** No prover or verifier change.
- **`test-assemble-macos.sh`: not run in CI.** It needs a second (sdk) build of the worker: another
  7 GB. It was not rerun here because `assemble-macos.sh` only gained opt-in knobs whose default paths
  are unchanged; it is the B9-M26 harness.
  - The new knobs ran in the simulation: `ASSEMBLE_BUILD_ONLY`, `ASSEMBLE_ENV_ONLY` and
    `ASSEMBLE_SKIP_BUILD` after a pruned target.

## Fix round 1

Two blocking findings from the round-1 review, each reproduced before the fix. The review's
non-blocking items that were cheap are fixed too.

### 1. Disk on a persistent runner: a second build had 0.90 GB free

- **Finding.** The first simulation ran each job once, on an empty image. The reviewer ran the order
  build, cpu-tests, metal-probe, cpu-tests, build. The second build had **0.90 GB** free, below the
  1.5 GB bar, and the second test run 1.69 GB. Left in `HOME` between jobs:
  - `~/.cargo/registry` grew from 615 MB to 1.3 GB, because the tests' dev-dependencies unpack more
    crate sources into `registry/src`;
  - `~/.cache/risc0-groth16/coeffs_compact_metal_*.bin`, 343 MB, written by the probe's worker;
  - `~/.cargo/git/checkouts`, 857 MB.
- **Reproduced** in the reviewer's run of this item's harness
  (`/Users/user/zkminer/scratch/w9/B9-CI-verify/sim/logs`, `report.md`): `build[4]` used 5.84 → 12.85
  GB, peak 12.89 GB, `df` `Avail 893Mi`. Its `du` after the toolchains shows exactly the three items
  above.
- **Fix, at the root: no job leaves anything in `HOME` that a later job does not read back.**
  - `scripts/ci/macos-clean-home.sh` runs right after the checkout and again at the end of every job
    (`if: always()`, so also after a failure or cancellation). It deletes:
    - `~/.cargo/registry/src` and `~/.cargo/git/checkouts`, which cargo recreates from what
      `actions/cache` keeps (`registry/{index,cache}`, `git/db`);
    - the Groth16 coefficient cache (`RISC0_G16_CACHE_DIR`, else `$XDG_CACHE_HOME/risc0-groth16`, else
      `~/.cache/risc0-groth16`);
    - risc0-build-kernel's kernel cache (`~/Library/Caches/com.risczero.RISC-Zero.risc0`). A release
      build therefore never reuses an earlier job's kernel objects either.
  - `macos-probe.sh` exports `RISC0_G16_CACHE_DIR=<work dir>/g16-cache` and deletes it, so the worker
    never writes the coefficient cache into `HOME`.
  - `macos-disk.sh` also prints the Groth16 cache's size.
  - Rejected alternative: require an ephemeral runner. The repository's runner is what it is, and the
    cleanup costs about 2 s per job plus re-extracting about 0.7 GB of crate sources.
- **Validation: the round-1 simulation.** The commit before the docs, `81fdca1`, had the same
  workflows and scripts. The order was build, cpu-tests, metal-probe, build, cpu-tests, from a fresh
  clone in a new 14.0e9-byte image, with fresh `HOME`/`CARGO_HOME`, `CARGO_BUILD_JOBS=5`, the mirror,
  and `HOME` and the workspace kept throughout. Every step returned rc 0 in one chunk.

  | run | step | used start → end GB | peak used GB | least free GB | peak tree RSS GB | `time -l` max RSS GB | wall s |
  |---|---|---|---|---|---|---|---|
  | 1 build | toolchains | 0.96 → 3.58 | 3.76 | 10.03 | 1.36 | 1.08 | 56 |
  | 1 build | build worker + CLI | 3.58 → 11.73 | 11.74 | **2.05** | 6.06 | 2.28 | 295 |
  | 1 build | package + check | 4.84 → 4.97 | 7.68 | 6.11 | 0.35 | 0.38 | 48 |
  | 1 build | clean (end) | 4.96 → 4.10 | | | | | 3 |
  | 2 cpu-tests | tests | 3.76 → 8.54 | 10.90 | **2.89** | 6.52 | 2.29 | 262 |
  | 2 cpu-tests | clean (end) | 5.30 → 3.83 | | | | | 3 |
  | 3 metal-probe | probe + one proof | 3.94 → 4.21 | 10.60 | **3.19** | 5.43 | 6.83 | 58 |
  | 4 build | build worker + CLI | 3.82 → 11.73 | 11.76 | **2.03** | 6.50 | 2.28 | 284 |
  | 4 build | package + check | 4.84 → 4.98 | 7.68 | 6.11 | 0.30 | 0.38 | 48 |
  | 5 cpu-tests | tests | 3.83 → 8.54 | 10.97 | **2.82** | 5.73 | 2.28 | 261 |

  - The used space at the start of every job after the first is 3.75-3.83 GB, so the state is steady.
    The second build's least free is 2.03 GB, against 0.90 GB before the fix. The second test run's
    is 2.82 GB, against 1.69 GB.
  - After the probe, `HOME` has no `.cache` at all. `~/.cargo` holds 222 MB of registry and 538 MB of
    git databases.
  - Tests: the worker **60 passed, 4 filtered**; zkminer-prover **128 passed** (3 more filtered, see
    below); `test-metal-tc.sh` **18/18**; `test-check-macos-kit.sh` **13/13** in the build job.
  - Probe: Apple M5 Max `applegpu_g17s`, recommendedMaxWorkingSetSize 30150672384. Groth16 component
    streamed and checked in 51 s. fibonacci STARK 0.27 s, Groth16 wrap 1.75 s, verified.
    **`STOCK 3.1 VERIFY: OK`** (selector `e71e6620`) on the receipt, copied to `receipts/r1/`.
  - The CI kit's worker: `build-metal-aot.sh --worker-digests` gives the same sorted digest list as
    before (sha256 `0d488ee9…a33`), the validated GPU code.
  - The image was detached and deleted.

### 2. metal-probe never ran on push or pull_request

- **Finding.** `if: ${{ inputs.metal_probe != false }}`: on push and pull_request the `inputs` context
  is empty, so the value is null. GitHub's loose `!=` coerces null and false both to 0, so the condition
  is false and the job is skipped. `PROBE_PROOF: ${{ inputs.probe_proof == false && '0' || '1' }}` gave
  '0' there for the same reason. The first simulation substituted both expressions from a hand-written
  table, so it could not see this.
- **Reproduced.** `scripts/ci/test-workflow-expressions.py` evaluates expressions with GitHub's
  documented semantics. On the first-round workflow it reports `push: metal-probe runs: got False`,
  `PROBE_PROOF: got '0'`, and the same for a same-repository PR (`expr-before.log`; 15 failures, 10 of
  them the concurrency check below). It keeps the two old expressions as cases, which must evaluate to
  "skipped" and '0' on push.
- **Fix.** The inputs are compared as text, so an absent input counts as the default:
  `if: ${{ format('{0}', inputs.metal_probe) != 'false' }}` and
  `PROBE_PROOF: ${{ format('{0}', inputs.probe_proof) == 'false' && '0' || '1' }}`. `release.yml`'s call
  (`metal_probe: false`) still skips the probe.
- **Test** (`lint-workflows.sh` runs it). The evaluator is checked against the documented cases:
  `null == 0`, `'' == null`, case-insensitive strings, `format` of null and booleans, and `&&`/`||`
  returning operands. Then `build-macos.yml` is evaluated per event:
  - push, pull_request from the repository and from a fork;
  - workflow_dispatch with the defaults, `metal_probe=false`, `probe_proof=false` and
    `metal_toolchain=xcode`;
  - workflow_call with nothing, with `probe_proof=false`, and with `release.yml`'s own `with:` (read
    from the file).

  For each event it checks that `build` and `cpu-tests` run (except on a fork's PR), the probe's `if:`,
  `PROBE_PROOF`, `METAL_TOOLCHAIN`, the concurrency groups, and that every `${{ }}` of the file
  evaluates. Result: **425 passed, 0 failed**.
- **The simulation now uses the same evaluator.** The job's `if:`, each step's `if:` (with the job's
  status, so `always()` steps run after a failure) and every env value are evaluated in a push event's
  contexts. The round-1 run's probe ran because its `if:` said so.

### Non-blocking review items

- **Fixed: host-state tests in the required `cpu-tests` job.** They are now skipped there:
  - `metal_start::tests::this_macs_power_state_is_readable`;
  - `discovery::tests::this_mac_reports_one_apple_gpu`, `this_macs_owner_probes_answer` and
    `this_macs_power_state_answers_and_is_full`.

  They assert this Mac's GPU, HID idle time and power source, which a headless or VM runner may not
  have. `mac-test-miner` keeps running them on Macs.
- **Fixed: the release did not check the Metal compiler.** `check-macos-kit.py --require-validated`
  fails a kit whose `BUILDINFO` does not say `metal_compiler_validated=yes`, and
  `assemble-release.sh` always passes it.
  - `test-check-macos-kit.sh` case 2k: a kit with `metal_compiler_validated=no` and correct sums is
    rejected. 1b: the CI kit passes. 13/13.
  - `reltest/r1/`: `assemble-release.sh` on the staging set returns rc 0; with the unvalidated kit,
    rc 1 with `BUILDINFO metal_compiler_validated=no … a release needs the validated Metal compiler`.
- **Fixed: concurrency groups.** Each group now includes `github.workflow`. For a called workflow that
  is the caller's name, so a release's `macos` job and a manual run on the same ref no longer share a
  group. The expression test checks that the groups are distinct and name the workflow.
- **Fixed: no git low-speed limit.** The workflow sets `GIT_HTTP_LOW_SPEED_LIMIT=1000` and
  `GIT_HTTP_LOW_SPEED_TIME=120`. Cargo's CLI git fetches then fail on a stall instead of hanging for up
  to 240 minutes.
- **Fixed: an older rustup on the runner.** `macos-toolchains.sh` installs the toolchain by its channel
  and components from `rust-toolchain.toml`. Before 1.28, rustup did not take a bare `rustup toolchain
  install`.
- **Not changed, need a user decision (open issues 3 and 4):**
  - CI kits ship without AOT archives;
  - the runner's SDK changes the metallib digests.
- **Not changed:**
  - `macos-smoke.sh`/`macos-validated.sh` shellcheck notes: B9-M26's files;
  - the Groth16 tar is unpacked before its SHA-256 is compared: the pinned HTTPS URL, and bsdtar's
    refusal of absolute and `..` paths, bound the risk;
  - the `check-macos-kit.py` fat-file heuristic;
  - `check-release-libs.sh` not looking inside the AMD and Intel tarballs: unchanged Linux code;
  - the two version extractions: they agree, and a divergence fails the release loudly.

## Knobs

`vars.ZKMINER_MACOS_RUNNER`, inputs `metal_toolchain` (`pinned`/`xcode`), `metal_probe`, `probe_proof`,
`retention_days`; `PROBE_MIN_FREE_GIB`; `assemble-macos.sh` `ASSEMBLE_BUILD_ONLY`, `ASSEMBLE_ENV_OUT`,
`ASSEMBLE_ENV_ONLY`; `assemble-release.sh` `ZKMINER_VERSION`, `EXPECT_COMMIT`. Round 1 adds no knob.
To take back the per-job cleanup, remove the two `Clean the runner user's caches` steps of a job. The
disk numbers above then no longer hold on a persistent runner. To revert, remove the
`macos` job from `release.yml` and `macos` from `assemble.needs`. `assemble-release.sh` then fails for
the missing `dist-macos`, so the macOS block must go too.

## Open issues

1. **Nothing ran on the real runner.** No push is possible. The first run on `zk-runner-mac-new` will be
   the first real evidence. These are unverified:
   - its Xcode, SDK and python3;
   - that `hdiutil attach` works for the runner user;
   - its GPU;
   - the cache service from a self-hosted runner.
2. **The hemilabs/risc0 rev `d94ef6501` must be pushed** (RELEASE-DEPS.md) before any CI build can fetch
   it.
3. **CI kits have no AOT archives:** a 1-minute first start on every Mac. Maintainers who want the 2.3 s
   start build the kit on a Mac.
4. **SDK difference.** The runner's Xcode 26 SDK puts `SDK Version 26.x` into the metallibs. Same
   compiler and code, different digests and `BUILDINFO metal_sdk` (B9-M26). Not measured on a runner.
5. **Not this item's files, now out of date:**
   - `docs/macos-beta.md` "CI" says the workflow files are not part of B9-PKG/B9-M26;
   - RELEASE-DEPS.md's runner recipe uses `xcodebuild -downloadComponent MetalToolchain` (the pinned
     27B47 superseded it).

   Both should point at `docs/ci-macos.md`.
6. **`build-macos.yml` runs on push/PR for `crates/**`.** It occupies the single runner for about 10-40
   minutes per change. Narrow the paths if that hurts.
7. **The `xcode` toolchain mode is untested** (no Xcode here).
8. **`macos-clean-home.sh` assumes one runner per user account.** Two runners that share a `HOME` would
   delete each other's crate sources mid-build. `docs/ci-macos.md` says so; nothing checks it.
9. **The expression evaluator is this item's own** (no Node or `@actions/expressions` here). It
   implements the documented subset and is checked against the documented cases. GitHub itself has
   not evaluated these expressions yet, which happens on the first push.
10. **`check-macos-kit.py` has not run on Linux** (no Linux host or Docker here).
