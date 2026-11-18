# macOS beta release kit (maintainers)

How the Apple Silicon (Metal) beta of zk-miner on RISC Zero 3.1 is built, what it contains and why,
and how it was validated. The user-facing text ships in the kit as `README.md`
(`packaging/macos/README.md`). Evidence and numbers are in `docs/metal-port-notes/B9-PKG.md`. The
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
| `ZKMINER_MACOS_MIN` | `27.0` | minimum macOS; `sdk` = no target flags (revert knob): minos 11.0 and metallibs for the build SDK, so the kit's `min_macos` is the SDK's version (27.2 here) |
| `AOT_ARCHES` | `applegpu_g17s` | GPU families of the archive set; `none` = no set |
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
├── README.md                            packaging/macos/README.md
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

## Minimum macOS: 27.0

- **The Metal kernels need macOS 15.** They are MSL 3.2 (`risc0-build-kernel` `-std=metal3.2`), and
  MSL 3.2 needs macOS 15. The compiler raises a lower target (14.0) to 15.0 by itself.
- **Without a setting the kit only runs on the build host's macOS.** The Metal compiler targets the
  build SDK's macOS by default: the metallibs of a build on this Mac (SDK 27.2) say macOS 27.2 in
  their header. Metal does not load a library built for a newer macOS, so such a worker would fail on
  27.0 and 27.1.
- **Why 27.0 and not 15 or 26.** 27.0 keeps exactly the validated kernel code. Compiled for 27.0, the
  AIR (Metal IR) is the same as for 27.2 except the target triple: `air64_v29-apple-macosx27.0.0`, AIR
  version 2.9. For 26.0 and 15.0 the compiler emits older AIR versions (v28 / 2.8 and v27 / 2.7).
  Those are different input to the OS's GPU compiler, which is where the R17 defect class lives. No
  R17 audit, stress run or bit-exactness check has been made for them.
- **Opening it to macOS 15 or 26 is a validation item:**
  1. build with `ZKMINER_MACOS_MIN=15.0`;
  2. run `ir_scan.py` and `run_stress.sh` on the emitted IR and the unit suites (risc0 R17.md);
  3. run the worker suites and a `--benchmark` on such a macOS;
  4. rebuild the archive set with that key (`macos15`).
- **The binaries.** `minos 27.0` in LC_BUILD_VERSION (it was 11.0) makes dyld refuse to start the
  binaries on an older macOS with a clear message, instead of failing later at the first Metal
  library load. `install.sh` checks `sw_vers` first and says so in plain words.

How the build sets it (`assemble-macos.sh`):

- **Not through `MACOSX_DEPLOYMENT_TARGET`.**
  - risc0-build passes the whole environment (minus `CARGO*`) to the guest builds.
  - The release profile's `strip = "debuginfo"` makes rustc run the Command Line Tools' `strip` on
    every linked image. For a target of 12.0 or later, its output has a string table that is not
    8-byte aligned.
  - dyld on macOS 27 refuses such an image ("mis-aligned LINKEDIT string pool"). The first victims are
    the build's own proc-macros (`E0463 can't find crate for zeroize_derive`), in ours and in the
    guests'.
  - The worker of a normal build has the same unaligned table: `stroff % 8 = 4`. It starts only
    because its minos is 11.0.
- **Binaries:** `CARGO_TARGET_AARCH64_APPLE_DARWIN_RUSTFLAGS="-C strip=none -C link-arg=-Wl,-S -C
  link-arg=-mmacosx-version-min=27.0"`.
  - The last `-C strip` wins over cargo's.
  - `ld -S` drops the same debug symbols (STABS) at link time.
  - The guests never see it (risc0-build drops `CARGO*`).
  - `CARGO_PROFILE_RELEASE_STRIP=none` does not work for this: the manifest's
    `[profile.release.package."*"]` keeps the dependencies at the manifest's strip.
- **Metallibs:** `METAL_TC` points at a generated toolchain directory, `target/macos-kit/metal-tc-27.0`.
  Its `metal` runs the real compiler with `-mmacosx-version-min=27.0`, and its `--version` line names
  that flag. risc0's kernel cache (`~/Library/Caches/com.risczero.RISC-Zero.risc0`) is keyed by that
  line (and not by any deployment target), so kit metallibs and default metallibs never share a cache
  entry. The AOT dump tests build with the same compiler, so their metallibs equal the worker's.
- **Revert knob:** `ZKMINER_MACOS_MIN=sdk`. It sets no target flag, so the binaries keep minos 11.0
  and the metallibs target the build SDK (27.2 with the CLT 27.2 SDK). A Mac must meet both, so the
  kit's minimum is the newer one: `BUILDINFO` records `binaries_minos`, `metal_target` and
  `min_macos` = the newer of the two (which `install.sh` enforces), and the archive key is
  `macos<major of min_macos>`. `check-macos-release.sh` checks all three on every kit.
  `scripts/ci/test-assemble-macos.sh` assembles kits in both modes from prebuilt binaries (no build,
  no GPU) and checks that a BUILDINFO stating any other minimum is rejected.

## Supported Macs and memory tiers

macOS 27 runs only on Apple Silicon. The worker refuses Intel, Rosetta and Macs with less than
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

The workflow files are not part of this item. A macOS job would run:

```yaml
  macos:
    runs-on: ${{ vars.ZKMINER_MACOS_RUNNER || 'zk-runner-mac-new' }}
    steps:
      - uses: actions/checkout@<pinned sha>
      - run: xcodebuild -downloadComponent MetalToolchain     # RELEASE-DEPS.md
      - run: scripts/ci/assemble-macos.sh dist/macos
        env: { AOT_SRC: ... }   # see below
      - uses: actions/upload-artifact@<pinned sha>
        with: { name: dist-macos, path: dist/macos }
```

`scripts/ci/test-assemble-macos.sh <sdk worker> <sdk CLI> [<27.0 worker> <27.0 CLI>]` tests the
script's minimum-macOS handling, the kit checks and `install.sh` from prebuilt binaries, with no
build and no GPU (about a minute), so it can run on that runner too.

Caveats for that runner (macOS 26, 5 cores, 14 GB, 14 GB disk, likely a VM):

- **No usable Metal GPU, probably.** The AOT dump tests load each metallib on a Metal device, and
  `--metal-arch` needs one. On a runner without a GPU, build with `AOT_ARCHES=none`, or pass a set
  built on a Mac for that exact worker as `AOT_SRC`. A set must match the worker's metallib digests,
  so it has to come from the same build.
- **Not the validated toolchain.** Its Xcode 26 Metal compiler is not the one validated (27B47,
  B9-DEP open issue 2). Run the R17 audit and a `--benchmark` on Apple Silicon with a CI-built worker
  before shipping it.
- **Disk.** 14 GB is tight: the release target is ~7 GB, plus ~5 GB transient for the dump tests.
