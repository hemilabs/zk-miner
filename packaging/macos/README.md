# zk-miner for macOS (Apple Silicon): beta

This kit has the zk-miner CLI and its RISC Zero 3.1 prover for Apple GPUs (Metal). The prover makes
the segment proofs, the recursion and the Groth16 wrap on the GPU. Docker, CUDA and Xcode are not
needed. SP1 and OpenVM jobs are not proven on a Mac.

**Beta.** The binaries are **not signed with a Developer ID and not notarized**. macOS therefore
quarantines a downloaded copy, and Gatekeeper blocks the programs until the quarantine is removed.
`install.sh` does that for the files it installs (see [Gatekeeper](#gatekeeper-unsigned-beta)).

## Requirements

| | |
|---|---|
| macOS | **26.0 (Tahoe) or later** (`BUILDINFO` `min_macos`). The GPU kernels are Metal Shading Language 3.2 libraries built for macOS 26, and the binaries refuse to start on an older macOS. `install.sh` checks this first. |
| Mac | Apple Silicon (M1 or later) with **16 GB of RAM or more**. Not supported: Intel Macs, Macs with 8 GB, and a Terminal running under Rosetta. The prover refuses them and says why. |
| Disk | About 0.2 GB for the kit, plus 5.4 GB for RISC Zero's Groth16 component (downloaded once, see below). While the component downloads and unpacks, about 7.8 GB must be free. |
| Network | The first warm-up downloads the 2.4 GB Groth16 component from RISC Zero's artifact store. |

### Memory tiers

The prover picks its segment size (po2) from the GPU memory it may use. That limit is the smaller
of two figures: what macOS recommends for the GPU (`recommendedMaxWorkingSetSize`, about 75 % of
RAM), and the RAM minus an 8 GiB reserve for macOS and your apps. On a 16 GB Mac the second one
decides (8 GiB); from 36 GB up the first one does.

The miner can also lower the limit while you use the Mac yourself (the owner-active tier). That is
off by default: set `ZKMINER_OWNER_ACTIVE=auto` in the miner's environment to turn it on.

| Mac | GPU limit, po2 (default) | with `ZKMINER_OWNER_ACTIVE=auto`, while you use it |
|---|---|---|
| 16 GB | 8 GiB, 19 | 4 GiB, 18 |
| 18 GB | 10 GiB, 19 | 4 GiB, 18 |
| 24 GB | 16 GiB, 20 | 8 GiB, 19 |
| 36 GB | 28 GiB, 20 | 20 GiB, 20 |
| 48 GB and more | about 75 % of RAM, 20 | 8 GiB less, 20 |

You can set a lower cap yourself with `RISC0_METAL_MAX_WORKING_SET_BYTES` (for example `4G`). A run
that would go over the cap fails early with "Metal working-set budget exceeded" and does not swap.
Below 4 GiB no Groth16 wrap fits.

These figures were measured on an M5 Max (36 GB): memory-merkle at po2 20 runs at ~880K cycles/s.
The 16 and 24 GB rows were simulated with the budget variable on that Mac. A base chip with fewer
GPU cores is slower.

## Install

This beta has no signature. Download it only from the hemilabs/zk-miner release page on GitHub,
over HTTPS, and compare the tarball's SHA-256 with the release's `SHA256SUMS` before you unpack it:

```sh
shasum -a 256 zkminer-<version>-macos-arm64.tar.gz   # must equal the line in the release's SHA256SUMS
```

The `SHA256SUMS` inside the kit, which `install.sh` checks, catches a damaged file but says nothing
about who made the kit.

```sh
tar -xzf zkminer-<version>-macos-arm64.tar.gz
cd zkminer-<version>-macos-arm64
./install.sh                 # or: ./install.sh --with-groth16 --warm
```

`install.sh` does the following:

1. Checks the Mac: arm64 and not Rosetta, macOS ≥ `min_macos`, at least 12 GiB of RAM.
2. Checks every file against `SHA256SUMS`.
3. Copies `zkminer` to `~/.zkminer/zkminer` and the prover to
   `~/.zkminer/provers/zkminer-prove-risc0-metal`, which is where the miner looks for it. Each copy
   replaces the old file by a rename, so a running prover is never changed under it.
4. Removes `com.apple.quarantine` from those installed files, and only from them.
5. Installs offline GPU pipeline archives (`metal-aot/`) for this Mac's GPU family, when the kit has
   them. **This beta has none**, so this step installs nothing (see [First start](#first-start)).

Options: `--prefix DIR`, `--no-aot` (no effect in this beta), `--with-groth16` (download the
Groth16 component now), `--warm` (prove one small program now), `--uninstall`. `./install.sh --help`
explains each one.

Then:

```sh
export PATH="$HOME/.zkminer:$PATH"       # add to ~/.zshrc to keep it
zkminer init                            # ~/.zkminer/config.toml (and a key with --generate-key)
zkminer benchmark                       # measures this Mac the way the miner does
zkminer run
```

Run `zkminer init` once, on the first install (with or without `--with-groth16`). It leaves an
existing `~/.zkminer/config.toml` alone, so an update needs no `init`. Do not run
`zkminer init --force` after an update: it overwrites your config.

Neither `zkminer` nor the worker has a `--version` flag: the kit's version, commit and risc0
revision are in its `BUILDINFO` file, and `zkminer help` lists the commands.

`~/.zkminer/provers/zkminer-prove-risc0-metal --benchmark` exits with status 1 when any program
(the warm-up included) does not prove and verify, after printing the rows of those that did.
`tools/macos-smoke.sh` checks one proof end to end. See [Troubleshooting](#troubleshooting).

### First start

This kit has no offline GPU pipeline archives. Every Mac therefore compiles the prover's GPU
pipelines once, at the prover's first start. That takes about a minute on an M5 Max (60.3 s
measured for this beta on macOS 27), and longer on a base M1-M4 chip, which has fewer CPU cores.
macOS 26 and macOS 27 behave the same. The result is cached
(`~/Library/Caches/com.risczero.RISC-Zero.risc0` and the macOS shader cache), so later starts take
about 2.5 s. The miner and `zkminer benchmark` wait for this first compile (they allow the
warm-up an hour): it is not a hang.

- **Your GPU family:** `~/.zkminer/provers/zkminer-prove-risc0-metal --metal-arch`.
- `ZKMINER_METAL_AOT=0` makes the prover ignore installed archives. It changes nothing with this kit.

### The Groth16 component

Every proof ends in a Groth16 wrap, which needs RISC Zero's `risc0-groth16` component **v0.2.0**
(2.4 GB download, 5.4 GB installed in `~/.risc0/extensions/v0.2.0-risc0-groth16`). It is not in this
kit. You get it in one of two ways:

- The prover downloads it at its first warm-up. The miner and `zkminer benchmark` start that warm-up
  before any job.
- `./install.sh --with-groth16` downloads it at install time. curl resumes an interrupted download
  when you run the command again.

Either way, the archive's SHA-256 is checked against the value pinned in the prover (and in
`BUILDINFO`) before anything is unpacked. A copy that does not match is deleted.
`RISC0_GROTH16_DIR=<dir>` points the prover at a copy you already have. Running
`zkminer-prove-risc0-metal --benchmark` by hand does not download the component: install it first.
If the prover says "missing the `risc0-groth16` component ... install it with rzup install
risc0-groth16", run `./install.sh --with-groth16` from the kit instead (the kit does not need rzup).

The download prints one line when it starts and nothing more until it is done: 82 s were measured
on a fast link, and a slow link takes minutes. Let it run.

## Troubleshooting

**`zkminer benchmark` says `BENCHMARK FAILED` (exit status 1).** The prover started but could not
prove: the line under it names the prover (`risc0:metal:0`) and its error, for example a warm-up
that failed because a GPU pipeline did not compile. Rows printed above it under `the results above
are incomplete` are the programs that did prove; nothing was saved or used for pricing, so `zkminer
run` does not price jobs from it. Then:

1. Run `tools/macos-smoke.sh` from the kit folder. It proves and verifies one small proof and ends
   with `RESULT:` and an exit status: 1 means the proof failed (send its log with your report), 4
   that this is a virtual machine's GPU (results there say nothing about a real Mac), 5 that the
   prover refuses this Mac, 7 that the Groth16 component is missing (`./install.sh --with-groth16`),
   8 that the kit is quarantined (run `./install.sh`).
2. Check the prover's own lines above the failure in the `zkminer benchmark` output (prefixed
   `[worker:risc0]`): a missing component, a memory refusal or a pipeline that failed to compile is
   named there.
3. After a macOS update, run the benchmark again: the first start after an update recompiles the GPU
   pipelines (see [First start](#first-start)).

**`zkminer benchmark` prints a `SIMULATED` table.** No prover was found in `~/.zkminer/provers`, so
nothing was proved. The table is CPU stand-ins, has no zkOP/s score and is not saved. Run
`./install.sh` from the kit.

**`install.sh --warm` says the warm-up proof failed.** The kit is installed; the prover could not
prove on this Mac. Run `tools/macos-smoke.sh` as above.

## Gatekeeper (unsigned beta)

When a browser downloads the tarball, macOS marks it with the `com.apple.quarantine` attribute, and
`tar` passes that mark on to every extracted file. Gatekeeper then blocks an unsigned program with
"“zkminer” Not Opened" ("Apple could not verify ... is free of malware").

- **Using `install.sh`:** nothing else to do. The installed copies have no quarantine mark.
  `install.sh` itself runs because the shell reads it.
- **Running a file from the kit directly**, or installing by hand:

  ```sh
  xattr -d com.apple.quarantine ./zkminer ./provers/zkminer-prove-risc0-metal
  # or the whole kit:
  xattr -dr com.apple.quarantine zkminer-<version>-macos-arm64
  ```

- **If macOS has already blocked a program:** open System Settings → Privacy & Security. Under
  Security it lists "“zkminer-prove-risc0-metal” was blocked ...". Click **Open Anyway**, confirm
  with your password or Touch ID, and run the program again. (Since macOS 15 the old Control-click
  → Open shortcut no longer works for this.)
- **Downloading with `curl -LO`** sets no quarantine mark.

Check that a file is clear with `xattr -l <file>`: no `com.apple.quarantine` line should be listed.

## Uninstall

`./install.sh --uninstall` removes the CLI, the prover and any archives it installed. Your config,
keys, the Groth16 component (`~/.risc0`) and the compiled-pipeline cache
(`~/Library/Caches/com.risczero.RISC-Zero.risc0`) stay. Delete those by hand if you want them gone.

## Files

| file | |
|---|---|
| `zkminer` | the CLI |
| `provers/zkminer-prove-risc0-metal` | the Metal prover |
| `metal-aot/` | empty in this beta (no offline GPU pipeline archives; a kit with archives has them here, with `manifest.jsonl` and `SHA256SUMS`) |
| `install.sh`, `tools/` | the installer, its archive helper, and `macos-smoke.sh` (checks that the prover starts, shows your GPU, and makes and verifies one small proof; run it from the kit folder **after** `./install.sh --with-groth16`: `tools/macos-smoke.sh`. It uses the installed copies, because the kit's own files keep the browser's quarantine flag; before installing it stops with exit 8 "quarantined", or exit 9 if an older build is still installed, and launches nothing) |
| `BUILDINFO` | version, commit, risc0 revision, minimum macOS, Metal compiler, archive families, the Groth16 pin |
| `SHA256SUMS` | checksums of every file in the kit |
