# macOS beta release kit (maintainers)

How the Apple Silicon (Metal) beta of zk-miner on RISC Zero 3.1 is built, what it contains and why,
and how it was validated. The user-facing text ships in the kit as `README.md`
(`packaging/macos/README.md`). Evidence and numbers are in `docs/metal-port-notes/B9-PKG.md` and (macOS 26) `B9-M26.md`. The
build dependencies (the pinned hemilabs/risc0 rev, the toolchains) are in `RELEASE-DEPS.md`.

## Build the kit

On an Apple Silicon Mac with the toolchains of `RELEASE-DEPS.md` (Metal toolchain incl. `metal-tt`,
the rzup Rust guest toolchain, protoc, python3), from a clean checkout:

```sh
scripts/ci/assemble-macos.sh dist/macos
# -> dist/macos/zkminer-<version>-macos-arm64.tar.gz and dist/macos/SHA256SUMS
```

The script runs these steps in order:

1. **Build.** `make -f Makefile.mac mac-build-worker` (`RISC0_SRC=git` by default, the pinned rev),
   with the minimum-macOS settings below.
2. **Check the build.** Both binaries must be arm64, have LC_BUILD_VERSION `minos` = the minimum,
   link only system libraries, and carry a valid signature. Every metallib the worker embeds must
   target the minimum. (With `ZKMINER_MACOS_MIN=sdk` the script instead reads the binaries' minos
   and the metallibs' target, which must each be one value, and takes the newer as the minimum.)
3. **Archive set.** `make mac-build-aot` builds the offline Metal archive set for `AOT_ARCHES`, with
   macOS key `macos<major of the minimum>`.
4. **Stage.** It lays out `zkminer-<version>-macos-arm64/` (layout below), writes `BUILDINFO` and the
   kit's `SHA256SUMS`, normalizes modes and mtimes, and strips xattrs. It then packs a gzip tarball
   with `COPYFILE_DISABLE=1 tar --no-xattrs` (no `._` entries, no quarantine flag from the build
   host).
5. **Check the tarball.** `scripts/ci/check-macos-release.sh` runs on it (below), then the script
   writes `SHA256SUMS` over the tarball.

Settings (environment):

| variable | default | |
|---|---|---|
| `ZKMINER_MACOS_MIN` | `26.0` | minimum macOS; `27.0` = B9-PKG's kit (revert knob); `sdk` = no target flags (revert knob): minos 11.0 and metallibs for the build SDK, so the kit's `min_macos` is the SDK's version (27.2 here) |
| `AOT_ARCHES` | `applegpu_g17s` | GPU families of the archive set; `none` = no set |
| `AOT_OS_MAJORS` | the validated majors (`27`, `scripts/ci/macos-validated.sh`), whatever macOS the build host runs | macOS major versions the set has archives for (key `macos<N>`, built with `metal-tt -macos-version-min <N>.0`); `26 27` adds an unvalidated `macos26` set (below), and needs `AOT_ALLOW_UNVALIDATED_OS=1` |
| `AOT_ALLOW_UNVALIDATED_OS=1` | | opt-in for an archive key outside `VALIDATED_AOT_OS_MAJORS` (assemble and the check refuse it otherwise; `BUILDINFO` `aot_os_unvalidated` lists it) |
| `METAL_COMPILER_UNVALIDATED=1` | | opt-in for metallibs from another compiler than `VALIDATED_METAL_COMPILER` (`BUILDINFO` `metal_compiler_validated=no`) |
| `AOT_VALIDATED` | `applegpu_g17s` | families `install.sh` installs archives for (written to `BUILDINFO`) |
| `AOT_SRC` | | a prebuilt set for this exact worker (digests are checked) |
| `RISC0_SRC` | `git` | `local` builds a risc0 checkout (`RELEASE-DEPS.md`) |
| `ZKMINER_VERSION` | `[workspace.package].version` | |
| `ASSEMBLE_SKIP_BUILD=1` | | package `target/release` as it is (the checks still apply) |

Wall time on the M5 Max: about 8 min for the build from a fresh clone with an empty kernel cache, then 215 s for the rest (cargo no-op, the dump tests, 11 archives in 113 s, packing; B9-PKG note).

## Kit layout

```
zkminer-<version>-macos-arm64/
├── zkminer                              CLI            -> ~/.zkminer/zkminer
├── provers/zkminer-prove-risc0-metal    Metal worker   -> ~/.zkminer/provers/
├── metal-aot/                           archive set (*.binarchive, manifest.jsonl, SHA256SUMS, WORKER)
│                                                       -> ~/.zkminer/provers/metal-aot (validated family only)
├── install.sh                           packaging/macos/install.sh
├── tools/install-metal-aot.sh           scripts/mac (install.sh uses it)
├── tools/build-metal-aot.sh             scripts/mac (its --worker-digests)
├── README.md                            packaging/macos/README.md (says "This kit has no offline GPU
│                                        pipeline archives" exactly when metal-aot/ has none, and
│                                        "About <x> GB for the kit"; check-macos-kit.py checks both)
├── LICENSE
├── BUILDINFO                            version, commit, risc0 rev, min_macos (the newer of
│                                        binaries_minos and metal_target), Metal compiler,
│                                        aot_arches, aot_validated, groth16_{version,sha256,url}
└── SHA256SUMS                           every file above
```

The kit follows the Linux release's conventions:

- The CLI goes beside the provers directory (`unpack-provers.sh`).
- The workers go in `~/.zkminer/provers/`, which is where discovery looks.
- One `SHA256SUMS` sits beside the release assets.
- A no-GPU check script mirrors `check-release-libs.sh`.

## Minimum macOS: 26.0

- **The Metal kernels need macOS 15.** They are MSL 3.2 (`risc0-build-kernel` `-std=metal3.2`), and
  MSL 3.2 needs macOS 15. The compiler raises a lower target (14.0) to 15.0 by itself.
- **Without a setting the kit only runs on the build host's macOS.** The Metal compiler targets the
  build SDK's macOS by default (xcrun sets `SDKROOT`): the metallibs of a build on this Mac (SDK 27.2)
  say macOS 27.2 in their header. Metal does not load a library built for a newer macOS.
- **Why 26.0 (B9-M26; B9-PKG shipped 27.0).** The beta must run on macOS 26 Tahoe and 27. The
  validation of the 26.0-target kernels is in `docs/metal-port-notes/B9-M26.md`:
  - **AIR.** Compiled for 26.0 the AIR (Metal IR) is version 2.8 (`air64_v28-apple-macosx26.0.0`)
    instead of 2.9. Of the 175 kernel translation units, 144 are identical apart from the triple and
    the version; the other 31 differ only in the signatures of the barrier and atomic intrinsics
    (`air.wg.barrier`, `air.simdgroup.barrier`, `air.atomic.global.{add,or,load}`: AIR 2.9 adds one
    argument), 464 lines in all.
  - **R17.** `ir_scan.py` on the 26.0 IR: `files=175 A=0 B=28 C=29 S=0 Z=7 P=0`, every per-file row
    equal to the 27.0 scan. `run_stress.sh` (all families, kernels built with the 26.0 wrapper) is
    clean, with the positive control reproducing the defect.
  - **Suites and proofs.** The fork's Metal suites pass twice; the stock 3.1.0 verifier accepts every
    3.1 receipt at default, 8 and 4 GiB and rejects every 3.0 one; the interleaved A/B against the
    27.0 kit worker shows no change at any budget, and the six-program benchmark is at the baseline.
  - The language is unchanged (MSL 3.2), and 15.0 would give AIR 2.7, never validated.
  - **Not validated on this Mac: a real macOS 26 runtime.** The 26.0 libraries are validated as
    macOS 27.2 runs them. Before tagging, in the extracted kit on a real macOS 26 Apple Silicon Mac,
    run `./install.sh --with-groth16`, then `tools/macos-smoke.sh` and
    `~/.zkminer/provers/zkminer-prove-risc0-metal --benchmark` (note, user checklist).
- **The binaries.** `minos 26.0` in LC_BUILD_VERSION makes dyld refuse to start them on an older
  macOS with a clear message, instead of failing later at the first Metal library load. `install.sh`
  checks `sw_vers` first and says so in plain words. The audit of every API the binaries use (C
  imports against the macOS 26.5 SDK's `.tbd` files, every Objective-C selector and class name
  against the SDK headers' availability) found nothing newer than macOS 15 (note).

How the build sets it (`assemble-macos.sh`):

- **Not through `MACOSX_DEPLOYMENT_TARGET`.**
  - risc0-build passes the whole environment (minus `CARGO*`) to the guest builds.
  - The release profile's `strip = "debuginfo"` makes rustc run the Command Line Tools' `strip` on
    every linked image. For a target of 12.0 or later, its output has a string table that is not
    8-byte aligned.
  - dyld on macOS 27 refuses such an image ("mis-aligned LINKEDIT string pool"). The first victims are
    the build's own proc-macros (`E0463 can't find crate for zeroize_derive`), in ours and in the
    guests'.
  - The Metal compiler honours it too, but risc0's kernel cache key does not include it, so a library
    cached for another target would be reused. `assemble-macos.sh` (every mode), `Makefile.mac` and
    the compiler wrapper refuse to run with it set.
- **Binaries:** `CARGO_TARGET_AARCH64_APPLE_DARWIN_RUSTFLAGS="-C strip=none -C link-arg=-Wl,-S -C
  link-arg=-mmacosx-version-min=26.0"`.
  - The last `-C strip` wins over cargo's.
  - `ld -S` drops the same debug symbols (STABS) at link time.
  - The guests never see it (risc0-build drops `CARGO*`).
  - `CARGO_PROFILE_RELEASE_STRIP=none` does not work for this: the manifest's
    `[profile.release.package."*"]` keeps the dependencies at the manifest's strip.
- **Metallibs:** `METAL_TC` points at a toolchain directory made by `scripts/ci/metal-tc.sh --in`,
  `target/macos-kit/metal-tc-26.0-<fingerprint>`. Its `metal` runs the real compiler with
  `-mmacosx-version-min=26.0`, and its `--version` line names that flag.
  - **The compiler is in the path.** The fingerprint is a SHA-256 over the real compiler's path, its
    version line and the `metal` driver binary. Cargo reruns risc0-build-kernel's build scripts only
    when the value of `METAL_TC` (or a source) changes, so with one fixed path per target another
    compiler behind it would leave the old compiler's metallibs in the build, labelled with the new
    one (B9-M26 review; `scripts/ci/test-metal-tc.sh` case 5 reproduces it, case 6 shows the fix).
  - **The label comes from the kernels.** Every metallib's AIR carries its compiler's version line
    (`Apple metal version ...`). `assemble-macos.sh` takes `BUILDINFO` `metal_compiler` from there
    (`check-macos-release.sh --compilers`), refuses a build whose kernels are not from the wrapped
    compiler (a stale build) or not from the validated one (`VALIDATED_METAL_COMPILER` in
    `scripts/ci/macos-validated.sh`), and `check-macos-release.sh` checks the same on the tarball
    (`test-assemble-macos.sh` case 11).
  - **Kernel cache keyed by the target.** risc0's kernel cache
    (`~/Library/Caches/com.risczero.RISC-Zero.risc0`) is a SHA-256 over flags, SDK, sources and that
    version line, and not over any deployment target. With the target in the line, a 26.0 build, a
    27.0 build and a plain build (which targets the SDK) never share an entry: building 27.0 then
    26.0 from one clone left two entries per library (B9-M26 note). The cache directory itself is not
    split: risc0 derives it from `$HOME`, and a different `HOME` for the build would also change the
    guests' image ids (B9-DEP).
  - The AOT dump tests build with the same compiler, so their metallibs equal the worker's.
  - `check-macos-release.sh` checks every metallib's target, so a stale library cannot slip in.
- **Revert knobs:** `ZKMINER_MACOS_MIN=27.0` builds B9-PKG's kit (minimum 27.0).
  `ZKMINER_MACOS_MIN=sdk` sets no target flag, so the binaries keep minos 11.0 and the metallibs
  target the build SDK (27.2 with the CLT 27.2 SDK). A Mac must meet both, so the kit's minimum is
  the newer one: `BUILDINFO` records `binaries_minos`, `metal_target` and `min_macos` = the newer of
  the two (which `install.sh` enforces). `check-macos-release.sh` checks all three on every kit.
  `scripts/ci/test-assemble-macos.sh` assembles kits in each mode from prebuilt binaries (no build,
  no GPU) and checks that a BUILDINFO stating any other minimum is rejected.

### Metal compiler

- **The shipped kernels are compiled with Metal Toolchain 27B47** (Xcode 27.2,
  `Apple metal version 32023.922 (metalfe-32023.922.4)`), the compiler every R17 audit and benchmark
  was made with, targeting 26.0. Its binaries need macOS 14.0 (LC_BUILD_VERSION), so it also runs on
  the macOS 26 CI runner.
- **Not Xcode 26's compiler.** Xcode 26.5's Metal Toolchain (17F109, `metal 32023.883`) was fetched
  here the same way (Apple's asset server, no Xcode) and compared: for 26.0 it emits the same AIR
  version and the same `ir_scan.py` rows, but different code in 23 of the 175 units (the Groth16
  MSM window, poseidon254, the eval_check kernels), which would need the whole validation round
  again. CI must therefore not use the runner's own `xcrun metal`.
- **CI fetches the pinned toolchain:** `scripts/ci/fetch-metal-toolchain.sh` downloads build 27B47
  from Apple's CDN, checks the archive's SHA-256, decrypts and unpacks it, checks the disk image's
  SHA-256, mounts it (no sudo) and prints a `METAL_TC` for `assemble-macos.sh`.
- **The SDK version.** xcrun puts the SDK's version into each AIR module (`"SDK Version"`); nothing
  else in the IR depends on it (all 175 units compared against SDK 26.5). A CI build on Xcode 26's SDK
  therefore makes metallibs that differ from a local build in that flag, and so in their digests
  (and archive names). Compare a CI kit with the validated one by its kernels' AIR, not by digest,
  or build the release kit where SDK 27.2 is installed.

## Supported Macs and memory tiers

macOS 27 runs only on Apple Silicon; macOS 26 also runs on some Intel Macs, which `install.sh` and the worker refuse. The worker refuses Intel, Rosetta and Macs with less than
12 GiB of RAM (`gpu_refusal`). The tiers come from `crates/zkminer-prover/src/metal_sizing.rs`
(`active_limit_in`, `job_po2_for_limit_in`):

| Mac | idle limit, po2 | owner-active limit, po2 |
|---|---|---|
| 16 GB | 8 GiB, 19 | 4 GiB, 18 |
| 18 GB | 10 GiB, 19 | 4 GiB, 18 |
| 24 GB | 16 GiB, 20 | 8 GiB, 19 |
| 36 GB+ | 28 GiB, 20 | 20 GiB, 20 |

The limit is min(`recommendedMaxWorkingSetSize`, `hw.memsize` − 8 GiB) (`host_working_set_limit`);
above 36 GB it grows with RAM and po2 stays 20. The owner-active column applies only with
`ZKMINER_OWNER_ACTIVE=auto` (or `1`); by default the miner keeps the idle limit (`metal_sizing.rs`,
`OWNER_ACTIVE_ENV`).

Only a 36 GB M5 Max has been measured. The smaller rows come from runs on it under
`RISC0_METAL_MAX_WORKING_SET_BYTES` (BASELINES '3.1': memory-merkle ~767K c/s at 8 GiB, ~603K at
4 GiB).

## Offline archives: which families

- **Ship `applegpu_g17s` only** (the M5 Max here reports it; the M5 Pro's family was not checked). It is the only family validated on hardware (risc0
  `tools/metal_aot/README.md`: unit suites, seal equality, stress). `metal-tt` can build g13g-g17g as
  well, but no GPU of those families has run their output, and a GPU binary from the offline compiler
  differs from the OS compiler's. Per-family bit-exactness is a validation item: run the README's
  procedure on such a Mac, then add the family to `AOT_ARCHES` and `AOT_VALIDATED`.
- **Other Macs** install no archives (`install-metal-aot.sh` installs only an `AOT_VALIDATED` family)
  and compile their pipelines at first start, as without a kit.
- **A wrong archive is harmless.** The runtime opens only files whose name carries its own family and
  its macOS key, and it checks every file's checksum before Metal reads it. A file it cannot use is a
  clean miss, and that pipeline is compiled at runtime. B9-PKG tested this by forcing a family
  mismatch (note).
- **Which macOS.** The runtime opens only files keyed `os<its build>` or `macos<its major>`. The kit
  ships a `macos27` set; `install.sh` installs the archives of the running macOS's major only
  (`BUILDINFO` `aot_os_keys`), so macOS 26 installs none.
- **macOS 26 compiles at first start: 51-60 s on the M5 Max, once.** Measured here by running the
  kit worker with only a set it never opens (cold OS shader cache, empty runtime archive dir): a clean
  miss (`no offline archive ... <os26B131|macos27>`), every pipeline compiled, the receipts verified;
  the next starts take 2.34-2.36 s from the runtime's own archive. The miner's deadlines leave room
  for it: the Warmup that builds the pipelines has `WARMUP_TIMEOUT` = 60 min, and the Metal
  benchmark deadline is at least 109,200 GPU-core-seconds / cores (`metal_benchmark_timeout`, about
  45 min on a 40-core GPU), both in `crates/zkminer-prover/src/dispatcher.rs`.
- **No `macos26` set by default, on any build host.** The default keys are the validated ones
  (`VALIDATED_AOT_OS_MAJORS=27` in `scripts/ci/macos-validated.sh`), not the build host's major: on
  the macOS 26 CI runner a default build still ships `macos27` only (`test-assemble-macos.sh` case
  10, with a `sw_vers` shim). `metal-tt -macos-version-min 26.0` builds a `macos26` set
  (`AOT_OS_MAJORS="26 27" AOT_ALLOW_UNVALIDATED_OS=1`; without the opt-in assemble and the check
  refuse it), but it cannot be validated on macOS 27: renamed to the `macos27` key, the runtime opens each
  file and takes 0 pipelines from it (all compiled; proofs correct). Whether macOS 26 uses it, and
  whether its GPU code is bit-exact, is unknown. Validate on a macOS 26 Mac (README procedure, key
  `macos26`) before turning it on.
- **macOS 28 opens none of these files** (key `macos27`): it compiles at first start until a kit with
  a `macos28` set ships.

## Groth16 component

- **Never bundled** (2.4 GB). `check-macos-release.sh` fails if a component file or a tarball over
  1 GiB shows up.
- **The worker gets it** (`groth16_component.rs`), as on Linux: at its first Warmup (the miner and
  `zkminer benchmark` send it), from RISC Zero's artifact store, SHA-256 pinned. It unpacks into a
  staging directory and renames that into `~/.risc0/extensions/v0.2.0-risc0-groth16` under rzup's
  lock file.
- **`install.sh --with-groth16`** fetches the same URL ahead of time (`BUILDINFO` `groth16_url`, which
  the check script verifies is the string pinned in the worker binary). curl resumes a cut download.
  The script checks the SHA-256 before it unpacks and installs into the same directory by rename,
  holding the worker's lock file (`~/.risc0/tmp/.risc0-groth16-0.2.0.lock`, flock(2) taken through
  perl), so it and a worker installing at the same moment never both replace the directory; the one
  that comes second finds it complete (`test-assemble-macos.sh` case 6). A failed copy or unpack
  leaves no partial file (case 7).
- **`worker --benchmark` run by hand does not fetch it.** The README tells users to install it first.

## Unsigned beta: quarantine

- **Why it matters.** A browser download carries `com.apple.quarantine`, and macOS's `tar` copies it
  onto every extracted file. Gatekeeper then blocks the unsigned binaries.
- **What `install.sh` does.** It installs copies, removes the attribute from exactly those copies (and
  from the installed `metal-aot`), and fails if one still has it.
- **Manual steps.** The README documents `xattr -d com.apple.quarantine` and System Settings → Privacy
  & Security → Open Anyway.
- **Signing.** No Developer ID signing or notarization in the beta. The binaries carry the linker's
  ad hoc signature, which arm64 macOS requires, and the check script verifies it.

## CI

The workflow files are not part of this item (B9-CI). A macOS job would run:

```yaml
  macos:
    runs-on: ${{ vars.ZKMINER_MACOS_RUNNER || 'zk-runner-mac-new' }}
    steps:
      - uses: actions/checkout@<pinned sha>
      # The validated compiler (27B47), not the runner's Xcode 26 one ("Metal compiler" above).
      - run: echo "METAL_TC=$(scripts/ci/fetch-metal-toolchain.sh "$RUNNER_TEMP/metal-tc")" >> "$GITHUB_ENV"
      - run: scripts/ci/assemble-macos.sh dist/macos
        env: { AOT_SRC: ... }   # see below; leave AOT_OS_MAJORS unset (= 27, the validated key)
      - uses: actions/upload-artifact@<pinned sha>
        with: { name: dist-macos, path: dist/macos }
  metal-probe:     # opt-in: what the runner's GPU can do
    runs-on: ${{ vars.ZKMINER_MACOS_RUNNER || 'zk-runner-mac-new' }}
    steps:
      - run: tar -xzf zkminer-*-macos-arm64.tar.gz && cd zkminer-*-macos-arm64 && ./install.sh --no-aot
      - run: ~/.zkminer/zkminer --help && tools/macos-smoke.sh --no-proof   # in the kit dir; exit 4 = paravirtual
```

Pins for B9-CI:

| what | value |
|---|---|
| Metal toolchain | build **27B47** (Xcode 27.2), `Apple metal version 32023.922 (metalfe-32023.922.4)`; `fetch-metal-toolchain.sh` pins the `.aar` (SHA-256 `fcea0f3c…6513d9`) and the disk image (SHA-256 `9a7f6186…3b6265`) |
| kernel target | `-mmacosx-version-min=26.0` (AIR 2.8), MSL 3.2 (`metal-tc.sh` wrapper, `assemble-macos.sh`) |
| binaries | minos 26.0 (`-C link-arg=-mmacosx-version-min=26.0`, `-C strip=none`, `-Wl,-S`) |
| offline archives | `metal-tt` of the same toolchain, `-macos-version-min 27.0`, key `macos27`, family `applegpu_g17s`; `AOT_OS_MAJORS` unset (default `27`); never `AOT_ALLOW_UNVALIDATED_OS` or `METAL_COMPILER_UNVALIDATED` in a release job |
| SDK | the release kit was built with the CLT 27.2 SDK (`BUILDINFO` `metal_sdk`); the runner's Xcode 26 SDK changes only the AIR `"SDK Version"` flag (above) |

`scripts/ci/test-assemble-macos.sh <sdk worker> <sdk CLI> [<kit worker> <kit CLI>]` tests the
script's minimum-macOS handling (26.0, 27.0 and sdk), the kit checks and `install.sh` (the macOS
floor, the per-macOS archive selection), the archive keys on a macOS 26 build host and the compiler
label, from prebuilt binaries, without a build (a few minutes; case 8 runs the worker's
`--metal-arch`, `TEST_ASSEMBLE_GPU=0` skips it). `scripts/ci/test-metal-tc.sh [<risc0
build_kernel dir>]` tests the compiler wrapper, and with the crate dir rebuilds a one-kernel crate
through risc0-build-kernel under compilers A, B, C (no GPU, under a minute).

`scripts/ci/macos-smoke.sh` (also `tools/macos-smoke.sh` in the kit): launch checks (`zkminer --help`,
`worker --metal-arch`, crash reports), a device probe through `osascript` (name, architecture,
families, `recommendedMaxWorkingSetSize`; no developer tools needed), then one `fibonacci` proof with
its Groth16 wrap, verified by the worker (and by `STOCK_VERIFY=<stock-verify31>` if given). Exit 0
ok, 1 proof failed, 3 no Metal device, **4 paravirtual or non-Apple-Silicon device** (proof skipped;
`--try-paravirtual` tries it, informational), 5 the worker refuses this Mac, 6 a binary did not
launch, 7 no Groth16 component, **8 quarantined** (the chosen worker or CLI carries
`com.apple.quarantine`; nothing launched). By default it takes the first of the kit's own binaries,
the installed ones (`--prefix`, default `~/.zkminer`) and `target/release` that is not quarantined,
so in a browser-downloaded kit it uses the installed copies once `install.sh` has run, and says so
when they are from another build. Exit 6 is only for a binary that was launched and failed.

Caveats for that runner (macOS 26, 5 cores, 14 GB, 14 GB disk, likely a VM):

- **Probably a paravirtual Metal device.** A macOS guest of Apple's Virtualization framework gets
  Apple's paravirtualized GPU, not an `applegpu_*` family: `macos-smoke.sh` reports it and exits 4.
  The AOT dump tests load each metallib on a Metal device and `--metal-arch` needs one: on such a
  runner build with `AOT_ARCHES=none`, or pass a set built on a Mac for that exact worker as
  `AOT_SRC` (it must match the worker's metallib digests, so it has to come from the same build).
  The worker's own refusal checks (`metal_host.rs`) look at the device name's `Apple` prefix, unified
  memory and RAM; a paravirtual device may pass the first two, so do not treat a proof there as a
  GPU validation.
- **Not its own compiler.** Use `fetch-metal-toolchain.sh` (above); never the runner's `xcrun metal`.
- **Disk.** 14 GB is tight: the release target is ~7 GB, plus ~5 GB transient for the dump tests,
  plus 0.9 GB for the toolchain image.
