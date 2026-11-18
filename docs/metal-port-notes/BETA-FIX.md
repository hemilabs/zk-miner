# BETA-FIX: the macOS beta's blocking doc finding (no offline archives in the kit)

2026-11-18. Branch `metal-3.1`. Scratch, logs and the rebuilt kit: `/Users/user/zkminer/scratch/w9/BETA-FIX/`.

## The finding

The final beta review had one blocking finding, from the new-user lens. The security and release lenses
had none. The P31-SEC 64-bit-seed finding was already fixed by B9-SEC, which is an ancestor of the pinned
risc0 `d94ef6501`.

- **What the docs said.** `packaging/macos/README.md` (shipped as the kit's README.md) and the top-level
  README.md said:
  - the kit ships offline GPU pipeline archives for `applegpu_g17s` on macOS 27;
  - the first start takes about 2.3 s;
  - the kit takes about 0.5 GB.
- **What the kit has.** Every kit CI builds uses `AOT_ARCHES=none`, the RC1 kit included:
  - `metal-aot/` is empty and BUILDINFO has `aot_arches=`;
  - every Mac compiles its pipelines at the first start (60.3 s on the M5 Max in RC1);
  - the kit is 121 MB packed and 191 MB unpacked.

## Reproduction first

`check-macos-kit.py` now checks that the kit's README describes the kit:

- A kit without `metal-aot/*.binarchive` must contain "This kit has no offline GPU pipeline archives".
  A kit with archives must not.
- "About <x> GB for the kit" must be within a factor of 2 of the unpacked size.

Results:

- **RC1 tarball, before the doc fix.** 2 failures: the missing statement, and "About 0.5 GB for the kit"
  against 0.20 GB unpacked (`logs/repro-rc1-check.log`). `test-check-macos-kit.sh` fails case 1
  (`logs/repro-rc1-testcheck.log`).
- **The RC1 kit with only README.md and install.sh replaced** (re-summed and re-packed):
  `test-check-macos-kit.sh` 16/16 (`logs/readmeonly-testcheck.log`). It adds three new cases:
  - 2l: a README claiming archives the kit lacks;
  - 2n: a README saying "none" over a kit with one (a synthetic GPU-CPU-type Mach-O header);
  - 2m: a wrong size.

## Commits

1. `d03f8d1` **macOS kit docs: no offline archives in the beta; the kit check enforces it.**
   - Kit README:
     - install step 5 and `--no-aot` have no effect in this beta;
     - the new "First start" section: no archives, so every Mac compiles once, about a minute on an
       M5 Max and longer on M1-M4, then about 2.5 s from the cache;
     - disk: 0.2 GB for the kit plus 5.4 GB for Groth16, with 7.8 GB free during its download;
     - `metal-aot/` is marked empty in the Files table.
   - Top-level README: the same facts.
   - The checker and its test, as described above.
   - assemble-macos.sh, docs/macos-beta.md and docs/ci-macos.md: a kit with archives needs the README's
     archive text back first.
2. `b4707dd` **Cheap non-blocking items from the same review.**
   - Tarball provenance: download from the GitHub release over HTTPS and compare the tarball's SHA-256
     with the release's SHA256SUMS before unpacking. The kit's own SHA256SUMS only catches damage.
   - `zkminer init` is needed on the first install only. This is in both READMEs and in install.sh's
     Next list; init without `--force` keeps an existing config.
   - Kit README:
     - the worker's `--benchmark` exits 0 even when a program fails, so judge it by its "verified" lines
       or by `tools/macos-smoke.sh`;
     - the "rzup install risc0-groth16" hint maps to `./install.sh --with-groth16`;
     - the first-use Groth16 download is silent until it is done.
   - docs/macos-beta.md: the debug-only release-build knobs (`RISC0_METAL_REC_CAPTURE`,
     `RISC0_SKIP_VERIFY`, `RISC0_METAL_REC_SEAL_CHECK`, the stock fallbacks) and what each one affects.

No Rust, kernel or risc0 change was made, so the risc0 pin (`d94ef6501`), RELEASE-DEPS.md and performance
are unchanged and need no A/B. No hot path was touched.

## Gates re-run: the kit rebuilt as CI builds it

RC1's `ci/sim.py` was copied to `scratch/w9/BETA-FIX/ci`. It ran build-macos.yml's `build` and
`metal-probe` jobs at `b4707dd`, in a 14 GB APFS image, with a fresh HOME, `CARGO_BUILD_JOBS=5` and the
risc0 mirror at `d94ef6501`.

| step | rc | wall | min free (of 13.79 GB) |
|---|---|---|---|
| Metal toolchain (pinned 27B47) | 0 | 18 s | 12.83 GB |
| Rust, rzup guest toolchain, protoc | 0 | 57 s | 10.22 GB |
| build worker + CLI (`ASSEMBLE_BUILD_ONLY=1`) | 0 | 295 s | 2.05 GB |
| package + `check-macos-release.sh` + `check-macos-kit.py` + `test-check-macos-kit.sh` | 0 | 61 s | 5.09 GB |
| metal-probe: install, probe, Groth16 download, one fibonacci proof | 0 | 59 s | 3.25 GB |

The rebuilt kit:

- **Tarball.** `zkminer-0.1.0-macos-arm64.tar.gz`, 121,022,512 bytes, sha256
  `70852f6048f8361207a2f5ed1e2086730d9dfb6131069652b23aaa7e75d4aa6f`, in
  `scratch/w9/BETA-FIX/ci/artifacts/dist-macos/`.
- **BUILDINFO.** `commit=b4707dd`, `commit_dirty=no`, `risc0_rev=d94ef6501`,
  `metal_compiler_validated=yes`, `aot_arches=`.
- **check-macos-kit.py.** ok: "10 files, 2 programs, 0 GPU binary archives".
- **test-check-macos-kit.sh.** 16 passed, 0 failed.
- **check-macos-release.sh.** ok, macOS 26.0 and later.
- **Probe.** install.sh said "this kit has no offline Metal archives; the first start compiles the GPU
  pipelines". The fibonacci Groth16 proof verified, `RESULT: ok (exit 0)`.

The cpu-tests job was not re-run: no Rust code or test input changed.

## Open issues

- **RC1 and this kit are evidence only.** The tag has to be built from an integrated main, after the risc0
  fork merges hemilabs `release-3.1` and is re-pinned (RC open issues 1 and 2). Repeat the RC round on that
  commit.
- **Not done here.** These are listed in the review and the RC:
  - a non-zero `--benchmark` exit when no program verified;
  - a kit-aware missing-component message in the worker itself;
  - Linux-only MSR advice and a Mac power default in `zkminer benchmark`;
  - hashing an already-installed Groth16 zkey once;
  - an ephemeral runner for release builds;
  - the stale "Build the kit" and "CI" sections of docs/macos-beta.md and RELEASE-DEPS.md's runner recipe
    (B9-CI open issue 5);
  - RC docs items 3 (a quarantined binary hangs silently over SSH) and 4 (`zkminer run` needs the key,
    gas and stake steps that `init` prints);
  - the unpinned `Jimver/cuda-toolkit` tag in build-windows.yml.
- **Untested hardware.** A real macOS 26 Mac, a real 16 GB base Mac (M1-M4) and its cold first-start time
  are still unmeasured. build-macos.yml has never run on the real `zk-runner-mac-new`.
