# macOS CI (Apple Silicon, Metal)

How GitHub Actions builds, tests and releases the macOS beta kit `zkminer-<version>-macos-arm64.tar.gz`
(item B9-CI; the kit itself: `docs/macos-beta.md`; evidence: `docs/metal-port-notes/B9-CI.md`).

## Workflows

| file | what |
|---|---|
| `.github/workflows/build-macos.yml` | the macOS build. Runs on push and pull request to `main` when a path the kit is built from changes, by hand (`workflow_dispatch`), and from `release.yml` (`workflow_call`) |
| `.github/workflows/release.yml` | calls `build-macos.yml` as job `macos` (`metal_probe: false`) beside `build-docker.yml`. The `assemble` job waits for both and puts the kit into the release |

`build-macos.yml` has three jobs, all on the runner `${{ vars.ZKMINER_MACOS_RUNNER || 'zk-runner-mac-new' }}`:

| job | required | what |
|---|---|---|
| `build` | yes | builds the worker and the CLI, packages the kit, checks it, uploads the artifact `dist-macos` (the tarball and its `SHA256SUMS`) |
| `cpu-tests` | yes | the tests that need no GPU, built with the kit's settings |
| `metal-probe` | no (`continue-on-error`) | what the runner's GPU can do: device facts and one tiny proof. Never a gate |

A pull request from a fork never runs on the self-hosted runner: both required jobs carry an `if:` that
skips them.

### `build`

1. **Runner and Metal toolchain** (`scripts/ci/macos-metal-toolchain.sh`):
   - prints macOS, CPUs, RAM, the developer directory, `xcodebuild -version`, the SDK, the Command Line
     Tools, and the runner's own Metal compiler, if there is one;
   - then mounts the pinned Metal Toolchain **27B47** (`fetch-metal-toolchain.sh`), which is SHA-256
     checked twice, and checks its version line against `macos-validated.sh`;
   - exports `METAL_TC`.

   Input `metal_toolchain: xcode` (manual runs only; a tag refuses it) uses the runner's Xcode compiler
   instead. It runs `xcodebuild -downloadComponent MetalToolchain` when Xcode 26+ does not have it, and
   sets `METAL_COMPILER_UNVALIDATED=1`, so `BUILDINFO` says `metal_compiler_validated=no`. That mode is
   for trying a new Xcode, never for a release.
2. **Cache**: `~/.cargo/registry/{index,cache}` and `~/.cargo/git/db` only (`actions/cache`). Never
   `target/`.
3. **Toolchains** (`scripts/ci/macos-toolchains.sh`). Each is pinned and skipped when already
   present:
   - rustup-init 1.29.3 (SHA-256), then the toolchain `rust-toolchain.toml` names (profile minimal);
   - `rzup`, built with `cargo install --locked` from the hemilabs/risc0 rev that `Cargo.toml` pins,
     then the RISC Zero Rust guest toolchain 1.97.0 through it;
   - protoc 36.2 (the official zip, SHA-256).
4. **Build**: `ASSEMBLE_BUILD_ONLY=1 scripts/ci/assemble-macos.sh`. This is `Makefile.mac
   mac-build-worker` with the kit's settings (minimum macOS 26.0, the compiler wrapper), followed by the
   minimum-macOS and compiler checks.
5. **Delete the intermediates** (`macos-prune-target.sh`): only the two binaries and
   `target/macos-kit` stay.
6. **Package and check**:
   - `ASSEMBLE_SKIP_BUILD=1 AOT_ARCHES=none scripts/ci/assemble-macos.sh dist/macos`, which runs
     `check-macos-release.sh`;
   - `check-macos-kit.py` with the version and commit;
   - `test-check-macos-kit.sh`, which builds ten broken copies of the fresh kit and checks that every one
     is rejected.
7. **Upload** `dist-macos`, then unmount the toolchain (`always()`).

### `cpu-tests`

`scripts/ci/macos-cpu-tests.sh` runs, with the kit's build settings (`ASSEMBLE_ENV_ONLY=1`):

- the Metal worker's unit tests (release), except the three that read the Mac's Metal device or need a
  16 GB Mac (`MACOS_GPU_TESTS` in the script);
- zkminer-prover's discovery and dispatcher tests;
- `test-metal-tc.sh`, which pushes the compiler wrapper through risc0-build-kernel and cargo. It
  compiles kernels and runs none.

The step deletes the guests' build intermediates after the worker's tests, and the job deletes
`target/` before the cache is saved.

Why a second job: the tests' dev-dependencies (zkminer-prover's `testing` feature, `tempfile`) change
the features of most dependencies, `libc` included. Their build therefore recompiles about 270 crates,
the Metal kernels and the guests. Run after the release build in one job, it filled the 14 GB disk
(measured: 13.76 GB used, `No space left on device`).

### `metal-probe`

`scripts/ci/macos-probe.sh` installs the kit with `install.sh --prefix <temp>`, so the runner user's
`~/.zkminer` is not touched. Then:

1. `tools/macos-smoke.sh --no-proof` reports the launch, `MTLCreateSystemDefaultDevice`'s name,
   architecture (family), unified memory and `recommendedMaxWorkingSetSize`.
2. The risc0-groth16 component comes from the runner's own `~/.risc0` when it is complete there.
   Otherwise it is streamed into the job's temp directory (`curl | SHA-256 | tar`, checked against the
   kit's pin, deleted at the end) and never into `~/.risc0`: 5.4 GB left there would take the build
   job's room on a persistent runner.
3. One fibonacci proof with its Groth16 wrap (`--try-paravirtual`).

The job summary gets the facts and the exit code's meaning. The job fails only on a code that points at
the kit: 1 (proof failed), 6 (did not launch), 7, 8 or 2. Codes 3 (no device), 4 (paravirtual) and 5
(worker refuses) pass.

## The runner

`zk-runner-mac-new`: macOS 26, 5 cores, 14 GB of RAM, 14 GB of disk, most likely a VM.

- **GPU.** A Virtualization.framework guest has Apple's paravirtual GPU, not an `applegpu_*` family. So
  nothing required needs a GPU, and a proof in `metal-probe` there is not a GPU validation (B9-M26).
  The kit's GPU validation is the user checklist on real Macs (`docs/macos-beta.md`, B9-M26 note).
- **No offline (AOT) archives** in a CI-built kit (`AOT_ARCHES=none`). The reasons:
  - building them runs risc0's dump tests on a real Apple GPU;
  - it needs about 5 GB more disk;
  - the archives must match the build's own metallibs. The runner's SDK (Xcode 26) changes the metallib
    digests (B9-M26: the AIR `SDK Version`), so a set built on another Mac does not fit.

  A Mac with a CI kit therefore compiles its GPU pipelines once at the first start: about a minute on an
  M5 Max, longer on smaller Macs, then about 2.3 s per start (B9-M26). A kit with archives is built on a
  Mac with `scripts/ci/assemble-macos.sh` (docs/macos-beta.md).
- **Never register a developer's Mac as a runner** (organisation rule). The runner is the repository's
  own.

### Disk budget

Measured by running every `run:` step of the three jobs locally, in order, from a fresh clone. The
setup:

- a fresh `HOME`/`CARGO_HOME`, `CARGO_BUILD_JOBS=5`;
- a 14.0 GB APFS disk image (13.79 GB usable) as workspace, `HOME` and `RUNNER_TEMP`;
- `HOME` kept between the jobs: the worst case, a persistent runner.

Full numbers are in the B9-CI note.

| job | peak used | least free | biggest single item |
|---|---|---|---|
| build | 11.74-11.75 GB (end of the build) | 2.04 GB | `target/` 7.1 GB, of it 3.5 GB the 13 guests' builds |
| cpu-tests | 10.88-11.63 GB | 2.16 GB | the test build, 6.2 GB before the guests are pruned |
| metal-probe | 11.21-11.23 GB | 2.56 GB | the risc0-groth16 component, 5.4 GB (temporary, in `RUNNER_TEMP`) |

Peak memory: about 6.1 GB summed over the build's process tree with 5 jobs, and 7.5 GB for the worker's
fibonacci proof with its Groth16 wrap. Both are well under the runner's 14 GB.

`HOME` after a build holds:

- rustup with the 1.97.1 toolchain: 0.57 GB;
- the RISC Zero guest toolchain: 1.3 GB;
- the cargo registry and git: about 1.6-2.1 GB;
- the risc0 kernel cache: 0.08-0.15 GB.

The toolchain disk image takes 0.9 GB in `RUNNER_TEMP`, and its download peaks at about 1.8 GB.

If the disk gets tighter (a bigger dependency tree, more guests), there are two levers:

- prune the guests' builds as soon as the build has embedded them (`macos-prune-target.sh --guests`;
  the build job does not need to, today);
- delete the cargo registry's `src/` after the build.

## Release wiring

- `release.yml` job `macos` calls `build-macos.yml` with `retention_days: 30` and `metal_probe: false`.
- The job `assemble` needs `[check-version, linux, macos]`.
- `scripts/ci/assemble-release.sh` copies `dist-macos/zkminer-<version>-macos-arm64.tar.gz` into the
  release:
  - `<version>` is `ZKMINER_VERSION`, which `release.yml` sets from `check-version`, the job that
    compared the tag with `Cargo.toml`;
  - it first checks the build job's `SHA256SUMS` line;
  - then it runs `check-macos-kit.py --version <version> --commit <github.sha>`;
  - a kit of another version in the artifact fails it.
- `scripts/ci/check-release-libs.sh` now also checks the macOS kit with `check-macos-kit.py` on the
  Linux host, since `ldd` cannot read Mach-O:
  - every file is in the kit's `SHA256SUMS`;
  - thin arm64 programs only;
  - only `/usr/lib` and `/System/Library` libraries;
  - `LC_BUILD_VERSION` minos = `BUILDINFO` `binaries_minos`;
  - a code signature;
  - no links or unsafe paths;
  - under 1 GiB.

  It fails a release with no kit, or two, and any Mach-O file elsewhere in the release.
- The release notes have a macOS section (unsigned beta, `./install.sh --with-groth16`).

## Pins

| what | pin |
|---|---|
| actions | the same commit SHAs as the other workflows: `actions/checkout@3d3c42e5…`, `actions/cache@0057852b…`, `actions/upload-artifact@ea165f8d…`, `actions/download-artifact@d3f86a10…`. Nothing outside the repository's allowed-actions list |
| Metal toolchain | 27B47, `Apple metal version 32023.922 (metalfe-32023.922.4)`. The `.aar` and the dmg are SHA-256 pinned (`fetch-metal-toolchain.sh`) |
| rustup | 1.29.3, `rustup-init` SHA-256 `63752a19…de20f9f` |
| Rust | `rust-toolchain.toml` (1.97.1) |
| rzup | built from the pinned hemilabs/risc0 rev (`Cargo.toml`), `--locked` |
| RISC Zero guest toolchain | 1.97.0 (rzup checks it against RISC Zero's manifest) |
| protoc | 36.2, `protoc-36.2-osx-aarch_64.zip` SHA-256 `9cd98a53…e23466` |
| risc0 | the `Cargo.toml` rev of hemilabs/risc0, which must be pushed before CI can build (RELEASE-DEPS.md) |

## Local checks

- `scripts/ci/lint-workflows.sh [actionlint]` lints every workflow. It uses actionlint 1.7.12 (the
  official release binary, checked against the release's checksums file), with shellcheck on PATH for
  the `run:` scripts, and `scripts/ci/actionlint.yaml` for the self-hosted labels.
- `scripts/ci/test-check-macos-kit.sh <kit tarball> [<commit>]` tests the Linux-side kit check (about
  a minute, no GPU).
- The B9-CI note has the harness that runs the jobs' steps locally in a 14 GB disk image.

## Knobs

| knob | where | effect |
|---|---|---|
| `vars.ZKMINER_MACOS_RUNNER` | repository variable | another runner label |
| `metal_toolchain` | `workflow_dispatch` input | `pinned` (default) or `xcode` (unvalidated, not on a tag) |
| `metal_probe`, `probe_proof` | inputs | skip the probe job, or its proof |
| `PROBE_MIN_FREE_GIB` | `macos-probe.sh` env | the proof needs this much free disk for the Groth16 download (default 7) |
| `ASSEMBLE_BUILD_ONLY`, `ASSEMBLE_ENV_OUT`, `ASSEMBLE_ENV_ONLY` | `assemble-macos.sh` env | build without packaging; write the build environment (and stop) |
| `ZKMINER_VERSION`, `EXPECT_COMMIT` | `assemble-release.sh` env | what the macOS kit must say |
