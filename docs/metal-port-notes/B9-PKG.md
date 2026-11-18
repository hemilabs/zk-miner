# B9-PKG: the macOS beta release kit

Branch `item/B9-PKG` (worktree `/Users/user/zkminer/zk-miner-3.1-wt-B9-PKG`), from `item/B9-DEP` `49558f4`.
Kit commit `1ab965b`, note `bbd9fe7`; fix round 1: `16c2981` (code) and the note commit after it.
The fix round's evidence is in the section "Fix round 1" at the end.

**Scratch:** `/Users/user/zkminer/scratch/w9/B9-PKG/`:

| path | what |
|---|---|
| `fresh/zk-miner` | the fresh clone the kit was built from (`target/` deleted afterwards) |
| `dist/` | the final tarball and its `SHA256SUMS` |
| `logs/` | |
| `bench/{def,b8g,b4g}` | the A/B |
| `sbx/` | the sandbox benchmarks |
| `mismatch/` | the family-mismatch runs |
| `fs/` | the first starts |
| `ir/` | the R17 IR (deleted, scan logs kept) |
| `scripts/` | `build-env.sh`, `prebuild.sh`, `kitenv-run.sh`, `assemble.sh`, `ab.sh`, `summarize.py`, `firststart.sh`, `mismatch*.sh`, `sandbox-bench.sh`, `sb.sh` (sandbox user) |

**Ground rules followed:**

- No Rust, Metal kernel or risc0 file changed, and no main checkout was edited.
- Every GPU command ran under `gpu-run`: heavy `--no-budget` for timing (each arm sets its own budget),
  `--light` for the kit build (the AOT dump tests load metallibs) and for the installs (`--metal-arch`).
- No run was killed.

## Files

| file | |
|---|---|
| `scripts/ci/assemble-macos.sh` | builds and assembles `zkminer-<version>-macos-arm64.tar.gz` + `SHA256SUMS` (layout and settings: `docs/macos-beta.md`) |
| `scripts/ci/check-macos-release.sh` | no-GPU check of the tarball (`--binaries` mode for the build check) |
| `packaging/macos/install.sh` | the kit's installer |
| `packaging/macos/README.md` | the kit's user README (requirements, tiers, install, first start, Groth16, Gatekeeper, uninstall) |
| `docs/macos-beta.md` | maintainer documentation (build, minimum macOS rationale, AOT families, Groth16, quarantine, CI) |
| `README.md` | "Install the beta (prebuilt kit)" in the macOS section, and the beta bullet |

## Profile before (what a kit of the existing build would have been)

The B9-DEP worker (`bin/worker-A`, 184,089,696 B) is the starting point:

- **LC_BUILD_VERSION:** `minos 11.0, sdk 27.2`.
- **otool -L:** only `/usr/lib` and `/System/Library/Frameworks` (IOKit, CoreFoundation, Metal,
  CoreGraphics, libc++, libobjc, libiconv, libSystem). The CLI is the same, plus Foundation,
  Security and SystemConfiguration.
- **Metallibs target macOS 27.2.** All five embedded metallibs carry header `0x8001 / os 0x81 / 27.2`.
  The compiler reports `Target: air64-apple-darwin27.2.0` with no deployment target set.
  - So the existing worker would have run only on macOS ≥ 27.2, while its Mach-O header claimed 11.0.
  - The language level is `-std=metal3.2` (risc0-build-kernel `METAL_DEFAULT_STD` and keccak-sys),
    and MSL 3.2 needs macOS 15. `-mmacosx-version-min=14.0` is raised silently to 15.0.
- **AIR by target.** A test kernel, compiled per target:
  - 27.2 and 27.0: identical apart from the triple (AIR v29, metadata 2.9);
  - 26.0: AIR v28 / 2.8;
  - 15.0: AIR v27 / 2.7.
- **First start.** P31-M9b: 2.31-2.38 s with the AOT set, 76-81 s without. Today's cold compile is
  52-58 s; see below.

## Decisions and their evidence

### Minimum macOS 27.0, set by linker flag and a Metal compiler wrapper

- **Why 27.0, not 15 or 26:**
  - **The validated kernel code stays the same.** `tools/metal_audit/emit_ir.sh` ran twice on the kit
    build's OUT_DIRs and cargo's risc0 checkout, once with no extra flag and once with
    `-mmacosx-version-min=27.0`. All 175 translation units differ only in the line
    `target triple = "air64_v29-apple-macosx27.2.0"` vs `27.0.0`. `ir_scan.py` on both:
    `files=175 A=0 B=28 C=29 S=0 Z=7 P=0`, identical (tier A = S = 0).
  - The embedded metallibs of A and B have identical sizes and differ in 710-4373 bytes each (the
    triple strings and hashes).
  - Targets 26/15 change the AIR version. That is different input to the OS GPU compiler (the R17
    defect class) and has not been validated. It is left as an open issue.
- **Tried first: `MACOSX_DEPLOYMENT_TARGET=27.0`. Rejected:**
  1. The build failed at once with `E0463 can't find crate for zeroize_derive`, then for
     serde_derive. dyld: `mis-aligned LINKEDIT string pool, fileOffset=0x002C2CD4`.
  2. **Cause:** cargo passes `-C strip=debuginfo` (the manifest's `strip = "debuginfo"`, and
     cargo's own default for dependencies). rustc then runs the CLT `strip` (ld-27106 / CLT 27.2).
     For any target ≥ 12.0 that strip leaves `stroff % 8 = 4`, and dyld on macOS 27.2 refuses such
     images.
  3. **Minimal reproduction** (`ml/pm`: a crate using `zeroize` with `derive`):
     - 11.0 builds;
     - 12.0, 13.0, 14.0, 15.0, 26.0 and 27.0 all fail;
     - `-C strip=none` fixes it.
  4. `CARGO_PROFILE_RELEASE_STRIP=none` and `..._BUILD_OVERRIDE_STRIP=none` do not help here. The
     manifest's `[profile.release.package."*"]` keeps the dependencies at `strip=debuginfo`
     (verified with `cargo -v`).
  5. Even with that fixed, risc0-build passes `MACOSX_DEPLOYMENT_TARGET` to the guest cargo, since
     it drops only `CARGO*`. The guest proc-macros then failed the same way (`E0463 paste`,
     `logs/build-5.log`).
  6. Note: the normal worker also has `stroff % 8 = 4`. It loads only because its minos is 11.0.
- **What the kit does instead:**
  - **Binaries:** `CARGO_TARGET_AARCH64_APPLE_DARWIN_RUSTFLAGS="-C strip=none -C link-arg=-Wl,-S -C
    link-arg=-mmacosx-version-min=27.0"`.
    - Only the top-level cargo sees it.
    - `ld -S` drops the STABS that strip would drop. Test crate: 837 vs 839 symbols, 0 STABS in both.
  - **Metallibs:** `METAL_TC=target/macos-kit/metal-tc-27.0`, a directory of symlinks to the real
    toolchain whose `metal` adds `-mmacosx-version-min=27.0`.
    - Its `--version` first line gets ` [-mmacosx-version-min=27.0]` appended.
    - risc0-build-kernel keys the kernel cache by that line, so kit and default metallibs never share
      a cache entry. Without that, the cache key ignores the deployment target, and a cached 27.2
      library would have been reused.
  - **Results:**
    - worker and CLI: `minos 27.0`, `stroff % 8 = 0`, 7 metallibs `27.0`;
    - the AOT dump tests' metallibs matched the worker's digests: the set built, and nothing was refused.
- **Revert knob:** `ZKMINER_MACOS_MIN=sdk` (no target flags: minos 11.0, metallibs for the SDK, so
  the kit's `min_macos` is the SDK's version, 27.2 here). Round 0 got this wrong; see fix round 1.

### Archive families

- **Shipped: `AOT_ARCHES=applegpu_g17s`, `AOT_VALIDATED=applegpu_g17s`** (risc0 `tools/metal_aot`
  README: only g17s is validated on hardware). The set is 11 archives, 165 MiB, key `macos27`.
- **Forced family mismatch, three ways.** Each is a cold shader cache (`MTL_SHADER_CACHE_SIZE=0`), an
  empty runtime archive dir, `BENCH_ONLY=fibonacci` on the installed kit worker, and a receipt
  verified by the stock verifier:

| case | how | result |
|---|---|---|
| g16s set as is | `make mac-build-aot AOT_ARCHES=applegpu_g16s` for the kit worker (64 s, dump cached), `RISC0_METAL_AOT_DIR=` it | files never opened (name family ≠ GPU); every unit 0 hits / all misses, compiled, pipelines 54.6 s, wall 56.9 s, `verified` |
| **g16s binaries renamed to g17s** | same files, the family field rewritten to `applegpu_g17s` (checksum field still the file's own) | debug log shows each **offline file opened**: `offline .../zkp-...-applegpu_g17s-macos27-1587b576....binarchive: 0 hits` for all 6 units. Metal served nothing from them; every PSO was compiled. Pipelines 56 s, wall 52.3-58.0 s, `verified`, no WARN/ERROR |
| install on a non-validated family | `ZKMINER_AOT_VALIDATED=applegpu_g16s ./install.sh` | "this Mac is applegpu_g17s; archives are validated only for applegpu_g16s: none installed"; the previous set is removed; first start compiles (58.2 s), `verified` |

A wrong-family archive is therefore a clean miss followed by a runtime compile, with correct proofs.

### Groth16

- **Never bundled.** The check script fails on component files or a tarball over 1 GiB.
- **First need.** The worker (unchanged) downloads it at its first Warmup, SHA-256 pinned.
  `install.sh --with-groth16` fetches the same blob ahead of time:
  - **URL:** `BUILDINFO` takes it from `groth16_component.rs`, and the check script requires that
    exact URL string in the worker binary.
  - **Download:** curl, resumable.
  - **Install:** SHA-256 checked before unpacking, then unpacked into a staging directory and renamed
    into `~/.risc0/extensions/v0.2.0-risc0-groth16`.
- **Measured in the sandbox:** 70-74 s for the 2.4 GB download plus the unpack. The installed graph
  sha256 starts `887aa345d6adc257` (the pin). Negative test: a kit copy whose `BUILDINFO` names a
  different hash downloads, then refuses ("has SHA-256 173354ab..., not 000054ab...: removed it") and
  leaves no file behind.
- **`worker --benchmark` by hand does not install it** (worker code, not this item). The README says
  so and points to `--with-groth16`.

## Validation

### Build from a fresh clone

- **Setup:** `git clone -b item/B9-PKG` into scratch. Build with `HOME` = an empty
  `scratch/w9/B9-PKG/buildhome`, so risc0's Metal kernel cache started empty and was not shared with
  other agents. `CARGO_HOME`, `RUSTUP_HOME` and `RISC0_HOME` were the real ones, and the B9-DEP
  mirror `insteadOf` was used for hemilabs/risc0 (the rev is not on GitHub yet).
- **Build:** about 8 min (`logs/build-6.log`).
- **Assembly:** `scripts/ci/assemble-macos.sh dist` under `gpu-run --light`, from the squashed commit
  `1ab965b`, took **148 s** (215 s the first time):
  - cargo no-op;
  - AOT: 11 archives, 113 s;
  - packing.
- **Output:** `zkminer-0.1.0-macos-arm64.tar.gz`, **209 MB packed / 357 MB unpacked**, sha256
  `c890339c2658a6975b4eb24b636cc9b365f4ed6eff64955b179ecbb92dbea39e`. The check script passed.
- **Determinism:** the kit worker is byte-identical across two builds (`cmp` with `bin/worker-B`,
  184,609,784 B, which was taken from the first kit).

### Sandbox install

`HOME=scratch/w9/B9-PKG/home`, `env -i`, system `PATH` only (`scripts/sb.sh`):

1. The tarball was marked `com.apple.quarantine` (`0083;...;Safari;<uuid>`). macOS `tar -xzf` copied
   the mark onto every extracted file.
2. **Negative control:** `spctl -a -t exec` on the kit's `zkminer` says `rejected`, and running the
   quarantined `./zkminer` directly was **killed (rc 137)**.
3. `./install.sh --with-groth16` (rc 0, 70 s):
   - kit SHA256SUMS checked;
   - CLI and worker installed;
   - quarantine removed: `xattr -p com.apple.quarantine` fails on both installed files;
   - 11 g17s archives (165 MiB) installed;
   - Groth16 installed.
4. **The CLI runs:**
   - `zkminer help`;
   - `zkminer init` wrote `~/.zkminer/config.toml`;
   - `BENCH_ONLY=fibonacci zkminer benchmark` discovered `~/.zkminer/provers/zkminer-prove-risc0-metal`
     and drove it over IPC (Warmup, benchmark, shutdown): 8 s, `Groth16 1.6s`.
5. **First start with the AOT set.** Cold shader cache, `BENCH_ONLY=fibonacci --benchmark`; run 1 is
   the real first start (empty `~/Library/Caches` in the sandbox), runs 2-4 use fresh runtime
   archive dirs:
   - **2.353 / 2.349 / 2.374 / 2.372 s** (final kit);
   - 2.391 / 2.383 / 2.418 / 2.427 s (first kit).
   - Pipelines 0.1 s, served by the packaged archives (runtime archives seeded with the offline
     checksums).
6. **Worker `--benchmark`, `BENCH_ONLY=memory-merkle`, final kit:**

| budget | po2 | STARK | c/s | wrap | peak footprint | stock verifier |
|---|---|---|---|---|---|---|
| default (28.1 GiB) | 20 | 8.36 s | 877,757 | 1.59 s | 13.19 GB | OK |
| 8 GiB | 19 | 10.20 s | 770,638 | 1.73 s | | OK |
| 4 GiB | 18 | 13.91 s | 603,150 | 1.74 s | 4.89 GB | OK |

7. **Full six-program `--benchmark`** with the installed kit worker (one run, sandbox):
   - STARK total **169.98 s** (BASELINES '3.1': 169.56 s), 154.5M cycles, ~909K c/s;
   - wraps 1.59-1.60 s;
   - peak footprint **14.68 GB** (baseline 14.69);
   - all six programs verified, and all six receipts pass the stock verifier.
8. **install.sh error paths** (no GPU):
   - a corrupted kit file is refused;
   - `min_macos=99.0` is refused in plain words;
   - an unknown option exits 2;
   - `--help`;
   - `--prefix` with `--no-aot` installs;
   - `--uninstall` removes exactly the CLI, the worker and `metal-aot`.

### Interleaved A/B (no regression)

- **A:** `bin/worker-A`, the B9-DEP local-path build: minos 11.0, metallibs 27.2, strip.
- **B:** `bin/worker-B`, the kit worker: minos 27.0, metallibs 27.0, linker -S. Its guest ELFs come
  from a different `HOME`, so different image ids (B9-DEP).
- **Method:** memory-merkle `--benchmark`, real `HOME`. The pair order alternates (A,B on odd pairs,
  B,A on even), with one discarded warm-up pair. The warm-up also absorbs B's first compile:
  different digests mean separate runtime archives.
- **Results:** 7 pairs per cell, median [min..max] (`bench/`, `scripts/summarize.py`):

| budget | po2 | STARK A | STARK B | c/s A / B | wrap A / B | peak footprint A / B MiB | GPU seg / wrap peak A / B MiB | load A / B |
|---|---|---|---|---|---|---|---|---|
| full | 20 | 8.37 [8.34..8.42] | 8.36 [8.34..8.40] | 877,016 / 878,517 | 1.59 / 1.59 | 12,591 / 12,573 | 9437/5635 / 9405/5603 | 3.75 / 3.54 |
| 8 GiB | 19 | 10.24 [10.21..10.27] | 10.24 [10.22..10.26] | 767,690 / 767,846 | 1.74 / 1.75 | 6,986 / 6,969 | 4738/5635 / 4722/5619 | 2.09 / 2.21 |
| 4 GiB | 18 | 13.93 [13.92..13.97] | 13.94 [13.92..13.96] | 602,173 / 601,944 | 1.73 / 1.73 | 4,697 / 4,697 | 2404/3944 / 2388/3928 | 1.85 / 1.83 |

- **Verdict: no change.** The deltas (≤ 0.01 s STARK, ±0.2 % c/s) sit inside each arm's own spread.
- **Memory: not higher at any budget.** B's GPU peaks are 16-32 MiB lower: the same layout, with
  smaller pipeline/library residency.

### Correctness gates

| gate | result |
|---|---|
| stock crates.io 3.1.0 verifier (`tools/stock_verify31`, built unmodified `--locked` into `scratch/.../target-stock`, since deleted) | **64/64 `STOCK 3.1 VERIFY: OK`** (`logs/stock_verify.log`): 48 A/B (24 A + 24 B, three budgets incl. warm-up pairs), 6 full-suite, 6 sandbox memory-merkle (two kits × three budgets), 4 family-mismatch runs |
| worker unit tests, kit build environment (`cargo test --locked --release -p zkminer-prove-risc0 --features metal --bin zkminer-prove-risc0-metal`, `gpu-run`) | 64 passed, **twice** |
| `metal_worker -- --ignored` (release, `--test-threads=1`, `ZKMINER_M7_WORKER` = the installed kit worker) | 3/3 passed (warm-up + prove over IPC, first prove without warm-up, M9 ten proofs in one worker; 76 s). The keccak tight-worker test was skipped: it needs a fork test ELF (B9-DEP open issue 4) |
| `ir_scan.py` (R17) on the 27.0-target IR | A = S = 0 (identical to the 27.2 IR scan); `run_stress.sh` was not run: no kernel source changed, and the IR is identical apart from the triple |
| 3.0 receipts rejected | not re-run: no prover or verifier source changed (B9-4G's matrix at this risc0 rev rejects 30/30) |
| `check-macos-release.sh` | passes on both kits; fails on the B9-DEP worker (`minos 11.0`, `--binaries 27.2`) as it should |

## Knobs

`assemble-macos.sh`:

| knob | effect |
|---|---|
| `ZKMINER_MACOS_MIN` (default 27.0; `sdk` = revert, tested end to end in fix round 1) | the minimum macOS |
| `AOT_ARCHES` (default g17s; `none`) | the archive families built |
| `AOT_VALIDATED` | families `install.sh` installs archives for |
| `AOT_SRC` | a prebuilt set for this worker |
| `RISC0_SRC` (default git) | where the risc0 crates come from |
| `ZKMINER_VERSION` | the kit version |
| `ASSEMBLE_SKIP_BUILD=1` | package `target/release` as it is |
| `ENV_SH` | env.sh, sourced once by the script, not by make |

`install.sh`:

| knob | effect |
|---|---|
| `--prefix` | install directory |
| `--no-aot` | no offline archives |
| `--with-groth16` | fetch the Groth16 component now |
| `--warm` | prove one small program after installing |
| `--force` | install on a Mac the worker refuses (< 12 GiB) |
| `--uninstall` | remove what it installed |
| `ZKMINER_AOT_VALIDATED` | override the validated family list |

Run time (worker, unchanged): `ZKMINER_METAL_AOT=0`.

## Open issues

1. **macOS 15 / 26 support.** MSL 3.2 allows macOS 15. Lowering the minimum changes the AIR version
   (v27 / v28), so it needs a validation round: R17 IR scan + `run_stress.sh` + the unit suites with
   that target, a `--benchmark` on that macOS, and a `macos15` / `macos26` archive set (or none).
   Until then macOS 26 users (and the macOS 26 CI runner's own test runs) cannot run the kit.
2. **CI workflow not written.** `.github/workflows/**` is not owned by this item. `docs/macos-beta.md`
   has the job outline. On `zk-runner-mac-new`, which is probably a VM without a usable Metal device,
   the AOT dump tests cannot run. Use `AOT_ARCHES=none` or an `AOT_SRC` set built on a Mac from that
   same build. Its Xcode 26 Metal compiler is not the validated 27B47 (B9-DEP open issue 2), and its
   14 GB disk is tight. The macOS 26 runner also cannot run a 27.0-minimum kit's binaries to smoke-test
   them.
3. **The hemilabs/risc0 rev must be pushed** before anyone without the mirror can build (B9-DEP open
   issue 1).
4. **risc0-build-kernel's Metal cache key ignores the deployment target and
   `MACOSX_DEPLOYMENT_TARGET`** (risc0 side). A build with the variable set would silently reuse a
   library cached for another target. The kit sidesteps it with its wrapper's version line, and
   `check-macos-release.sh` checks every metallib's target. A risc0 fix would add the env var (and
   any `-mmacosx-version-min`) to `metal_cache_key`, and could take a target flag directly.
5. **CLT `strip` + dyld.** Any zk-miner build with a deployment target ≥ 12.0 and the release
   profile's `strip = "debuginfo"` produces images dyld 27 refuses. Changing the profile to
   `strip = "none"` plus `-Wl,-S` (owned by `Cargo.toml`, not this item) would make that the default.
6. **Gatekeeper first-run on other Macs.** The negative control (rc 137) and the quarantine removal
   were shown on this Mac. The System Settings → Open Anyway path in the README is Apple's documented
   flow and was not clicked through here (no GUI session).
7. **Not tested on a real 16 GB Mac, or on any GPU family but g17s** (the families other than g17s
   were tested only as mismatches).
8. `worker --benchmark` by hand does not download the Groth16 component (the worker's `--benchmark`
   path does not call `ensure_installed`). The README documents it; changing it belongs to the worker
   crate.
9. `zkminer` has no `--version`. `BUILDINFO` carries the version and commit.
10. `run_stress.sh` used to run its `ir` step through `emit_ir.sh`, which calls `xcrun metal` and
    ignores `METAL_TC`. So that step always scans the SDK-target IR. Fix round 1 ran the 27.0 scan by
    hand with the extra flag. A risc0-side option to pass `-mmacosx-version-min` through would close
    this.
11. The M5 Pro's GPU family is not verified. The docs now say only that the M5 Max here reports
    `applegpu_g17s`.
12. `ir_scan.py`'s per-line detail is not deterministic: two scans of the same `.ll` files differ
    in 62 detail lines, because the scanner reports different SSA instances. The totals are stable.
    This is a risc0 tool issue.

## Fix round 1 (review of `bbd9fe7`)

Scratch for this round: `scratch/w9/B9-PKG/fix1/`, `fresh2/` (default kit clone), `fresh3/` (sdk kit
clone), `dist2/`, `dist3/`, `home/` (sandbox, reinstalled), `home-sdk/`, `logs/fix1-*`.

### Blocking: `ZKMINER_MACOS_MIN=sdk` produced no kit

- **The finding was right.** In sdk mode the script took `min_macos` from the worker's minos
  (11.0). The metallibs target the build SDK (27.2), which caused three problems:
  - `install.sh` would accept macOS 26 or 27.0/27.1;
  - the archive key was `macos11`;
  - the script's own final check failed, so no outer `SHA256SUMS` was written.
- **Reproduced first.** `scripts/ci/test-assemble-macos.sh` is new. It assembles kits from prebuilt
  binaries in a scratch repo copy, with `ASSEMBLE_SKIP_BUILD=1 AOT_ARCHES=none`, no build and no GPU.
  It reads minos and the metallib target independently of the scripts under test.
  - On the round-0 scripts (`git archive bbd9fe7` plus the new test, the B9-DEP worker and an sdk
    CLI): **case 1 FAIL**. The check reported "embeds metallibs for another macOS than 11.0 ... 27.2"
    ×7, and assemble exited nonzero (`logs/fix1-test-old.log`).
  - Round-0 `install.sh` also failed new cases 6 and 7 (below): `logs/fix1-test-oldinstall.log`.
- **Fix (root cause).** A Mac must meet both requirements: dyld refuses a macOS older than minos,
  and Metal refuses a library built for a newer macOS. So the minimum is the newer of the two.
  - `BUILDINFO` gains `binaries_minos` and `metal_target`, and `min_macos` = max(both).
  - The archive key follows `min_macos`.
  - `check-macos-release.sh` checks every binary's minos against `binaries_minos`, every metallib
    against `metal_target`, and `min_macos` against their max. Both directions fail: an
    understated minimum lets `install.sh` accept a Mac where the kit cannot run; an overstated one
    refuses Macs where it can.
  - New `--requirements` mode: reads both values and fails if they disagree among the files.
  - Default mode is unchanged: `--binaries 27.0` stays strict, and all three fields are 27.0.
- **Test, final code** (`logs/fix1-test-final.log`, real sdk build from `fresh3` plus the 27.0
  build from `fresh2`): **17/17 pass**:
  1. sdk mode assembles; `binaries_minos 11.0`, `metal_target 27.2`, `min_macos 27.2`; the outer
     `SHA256SUMS` holds;
  2. default mode refuses the sdk build;
  3. both modes on the 27.0 build give 27.0 / 27.0 / 27.0;
  4. edited BUILDINFOs are rejected: `min_macos` 11.0 (the round-0 value), 27.1, 99.0, and a
     `metal_target` the worker does not embed;
  5. with a `sw_vers` shim, `install.sh --no-aot` refuses the sdk kit on 27.1 and installs it on
     27.2. With the round-0 BUILDINFO it would have accepted 27.1 (shown);
  6. and 7. see below.
- **End to end, real build.** In a fresh clone at `16c2981` (`fresh3`):
  `ZKMINER_MACOS_MIN=sdk scripts/ci/assemble-macos.sh dist3`, with the build (250 s) and then the
  full script under `gpu-run --light` (521 s, AOT 416 s). rc 0, and the check printed
  `ok ... kit for macOS 27.2 and later (minos 11.0, Metal libraries for 27.2)`.
  - 11 g17s archives, key `macos27`.
  - tarball sha256 `9857c066...`.
  - Installed from a quarantined tarball in `home-sdk`: first start **2.362 / 2.347 s**, all PSOs
    served by the archives (zkp 72 hits, rv32im 13 hits, 0 misses).
  - Both fibonacci receipts pass the stock verifier.
  - `--uninstall` removed exactly the CLI, the worker and `metal-aot`.

### Non-blocking items addressed

- **Groth16 lock.** `install.sh --with-groth16` now takes the worker's lock file,
  `$RISC0_HOME/tmp/.risc0-groth16-<v>.lock`.
  - Mechanism: flock(2) through perl on a file descriptor the shell keeps open. `std::fs::File::lock`
    is flock on macOS, so the two exclude each other.
  - It re-checks for a complete component under the lock.
  - Test case 6: a perl holder takes the lock, completes a fake component and releases it.
    `install.sh` waited 3.9 s, printed "installed meanwhile" and downloaded nothing. Its
    `groth16_url` points at a closed port; the control without a holder does try that URL.
- **Partial files.** An EXIT trap removes `.<name>.tmp.<pid>` and the Groth16 staging directory.
  Case 7: a `cp` shim fails on the worker copy, and nothing is left behind (round 0 left
  `.zkminer-prove-risc0-metal.tmp.<pid>`).
- **`metal_compiler` in BUILDINFO** now comes from the compiler that was actually used (`$real_metal`,
  else `METAL_TC`, else xcrun).
- **Kit README memory tiers.**
  - The limit is min(`recommendedMaxWorkingSetSize`, RAM − 8 GiB), as in `metal_sizing.rs`.
  - The owner-active column applies only with `ZKMINER_OWNER_ACTIVE=auto`; the default keeps the
    idle limit.
  - Rows for 36 GB and for 48 GB+ (the limit grows, po2 stays 20).
  - Same text in `docs/macos-beta.md`.
- **M5 Pro.** README.md, the kit README and the docs no longer claim it. They say the M5 Max here
  reports `applegpu_g17s`.
- **`install.sh` 12 GiB literal** now names `MIN_HOST_MEMORY_BYTES` in `metal_host.rs` as its source.
- **README.md "Beta." bullet** (outside the install section): kept. It is a one-line wording fix in
  the same macOS part, and it was flagged as non-blocking.

### R17 coverage of the 27.0-target libraries

- **`run_stress.sh` on the pinned risc0 rev `d94ef6501`.** Run in a scratch clone
  (`fix1/r0stress`, LFS zkrs copied from the main checkout read-only), with
  `METAL_TC` = the kit's wrapper (`metal-tc-27.0`).
  - All 5 test binaries embed metallibs for 27.0 (`--requirements`: `11.0 27.0`).
  - Segments: torture20 seg0, sha seg0, merkle seg0 (po2 20). Reps 30.
  - Logs: `fix1/stress/g1..g6`.

| step | result |
|---|---|
| control | repro 10/10 and 30/30 dispatches wrong (defect present); index-init 0/10 |
| zkp (`tests_r17`, incl. tier-Z bypass, z13 probe) | 8 passed; 71 lines all 0/30 vs rep 0 and vs CPU; z13 0/30 both |
| rv32im_accum | 9 lines (3 segments × 3 modes) 0/30, 0/30 |
| rv32im_witgen | par 0/200 ×3 = 0/600; sorted 0/30 ×3 |
| rv32im_eval / eval_forms | baseline 0/10; evalfast po2 20 0/30 (537-554 ms); all forms == CPU |
| recursion + lz, lz32, split, monolith | poseidon2 and sha-256 0/30 + 0/30 each |
| keccak_eval / keccak_witgen | 0/30 + 0/30; po2 17 and 18 30/30 bit-identical |
| groth16 | 4 passed (compact 0/10, MSM 5 shapes 10/10 = ark, window G2 0/10, NTT 10/10) |
| groth16_tierz | 152 lines: 108 × 0/30, 44 × 0/50 |

  - Not run: `rv32im_amp` (codegen -O-level perturbation, unrelated to the target) and
    `rv32im_gen` (static generator scans).
  - The `rv32im_witgen` + eval locked run took 11.6 min, over the 7-minute guideline. It completed
    and nothing was killed.
- **IR.** `run_stress.sh`'s `ir` step ignores `METAL_TC` (open issue 10), so `emit_ir.sh` ran by
  hand on the stress build's OUT_DIRs, once with `-mmacosx-version-min=27.0` and once without:
  - **175 files**: with the `target triple` line removed, **0 differ**;
  - `ir_scan.py` totals identical: `files=175 A=0 B=28 C=29 S=0 Z=7 P=0`;
  - the per-line detail differs in 72 lines, but two scans of the same default files differ in 62
    (open issue 12);
  - the `.ll` files are kept this time: `fix1/ir/ll-default-min27.tar.xz` (89 MB), with the scans
    `fix1/ir/scan-*.txt`.

### Gates re-run on the round-1 default kit

- **Build.** Fresh clone at `16c2981` (`fresh2`), empty kernel cache (sandbox build HOME):
  - build 253 s; `assemble-macos.sh dist2` under `gpu-run --light` 516 s;
  - check ok, `min_macos=binaries_minos=metal_target=27.0`;
  - tarball sha256 `5786ee30...` (209 MB).
  - The worker's metallib digests and archive names match the round-0 kit. The worker file differs
    only through its build-path string (`fresh` vs `fresh2`: one embedded `OUT_DIR` path, which
    shifts the layout). The archives' checksum field differs with it.
- **Sandbox** (`home` wiped first, `env -i`):
  - The tarball was quarantined and tar copied the mark to every file. `spctl` rejects the binary,
    and running it directly gives rc 137.
  - `install.sh --with-groth16`: rc 0 in 64 s. Lock taken, real 2.4 GB download, SHA-256 checked.
    No quarantine mark on the installed files. 11 archives.
  - CLI: `help`, `init`, and `BENCH_ONLY=fibonacci zkminer benchmark` (rc 0, worker spawned from
    `~/.zkminer/provers`, archive hits, Groth16 1.58 s).
  - First start: **2.375 / 2.376 / 2.410 / 2.411 s** (load 2.7-2.9).
  - memory-merkle `--benchmark`, all verified, all pass the stock verifier
    (`logs/fix1-stock_verify.log`; verifier rebuilt `--locked` into `fix1/target-stock`):

| budget | STARK | c/s | wrap |
|---|---|---|---|
| default | 8.37 s | 877,141 | 1.59 s |
| 8 GiB | 10.29 s | 764,228 | 1.73 s |
| 4 GiB | 13.91 s | 602,872 | 1.72 s |

- **Unchanged since round 0, not re-run:**
  - The worker's GPU code is unchanged, so round 0's A/B and full six-program benchmark stand:
    same source, same metallib digests.
  - The family-mismatch cases: `install-metal-aot.sh` and the runtime are unchanged.
- **Worker unit tests,** kit environment (`fresh2`): 64 passed, twice.

