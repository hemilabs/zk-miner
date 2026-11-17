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
| macOS | **27.0 or later** (`BUILDINFO` `min_macos`). The GPU kernels are Metal Shading Language 3.2 libraries built for macOS 27, and the binaries refuse to start on an older macOS. |
| Mac | Apple Silicon (M1 or later) with **16 GB of RAM or more**. Not supported: Intel Macs, Macs with 8 GB, and a Terminal running under Rosetta. The prover refuses them and says why. |
| Disk | About 0.5 GB for the kit, plus 5.4 GB for RISC Zero's Groth16 component (downloaded once, see below). |
| Network | The first warm-up downloads the 2.4 GB Groth16 component from RISC Zero's artifact store. |

### Memory tiers

The prover picks its segment size (po2) from the GPU memory it may use. That figure is about 75 % of
RAM (macOS's `recommendedMaxWorkingSetSize`), minus an 8 GiB reserve for macOS. While you use the Mac
yourself (the owner-active tier) the miner lowers it further:

| Mac | idle: GPU limit, po2 | while you use it: limit, po2 |
|---|---|---|
| 16 GB | 8 GiB, 19 | 4 GiB, 18 |
| 18 GB | 10 GiB, 19 | 4 GiB, 18 |
| 24 GB | 16 GiB, 20 | 8 GiB, 19 |
| 36 GB and more | 28 GiB, 20 | 20 GiB, 20 |

You can set a lower cap yourself with `RISC0_METAL_MAX_WORKING_SET_BYTES` (for example `4G`). A run
that would go over the cap fails early with "Metal working-set budget exceeded" and does not swap.
Below 4 GiB no Groth16 wrap fits.

These figures were measured on an M5 Max (36 GB): memory-merkle at po2 20 runs at ~880K cycles/s.
The 16 and 24 GB rows were simulated with the budget variable on that Mac. A base chip with fewer
GPU cores is slower.

## Install

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
5. Installs the **offline GPU pipeline archives** (`metal-aot/`) for this Mac's GPU family. It does
   this only for a family validated on hardware (this beta: `applegpu_g17s`, M5 Pro / M5 Max).

Options: `--prefix DIR`, `--no-aot`, `--with-groth16` (download the Groth16 component now),
`--warm` (prove one small program now), `--uninstall`. `./install.sh --help` explains each one.

Then:

```sh
export PATH="$HOME/.zkminer:$PATH"       # add to ~/.zshrc to keep it
zkminer init                            # ~/.zkminer/config.toml (and a key with --generate-key)
zkminer benchmark                       # measures this Mac the way the miner does
zkminer run
```

### First start and the offline archives

Metal compiles every GPU kernel the first time a process uses it. For this prover's circuits that
takes about a minute on an M5 Max (52-58 s measured), and longer with fewer CPU cores. The result is cached, so later
starts take ~0.1 s.

- **M5 Pro / M5 Max** (`applegpu_g17s`): the kit ships pre-compiled archives. The first start then
  takes about 2.3 s.
- **Other Macs** (M1 to M4, M5): no archives are installed, because none were validated on such a GPU.
  The first start compiles the kernels, once.
- **Mismatches:** an archive for another GPU family or another macOS major version is never used.
  The prover compiles that kernel instead.
- **Your GPU family:** `~/.zkminer/provers/zkminer-prove-risc0-metal --metal-arch`.
- **Turning the archives off:** `ZKMINER_METAL_AOT=0` makes the prover ignore installed archives.

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

`./install.sh --uninstall` removes the CLI, the prover and its archives. Your config, keys, the
Groth16 component (`~/.risc0`) and the compiled-pipeline cache
(`~/Library/Caches/com.risczero.RISC-Zero.risc0`) stay. Delete those by hand if you want them gone.

## Files

| file | |
|---|---|
| `zkminer` | the CLI |
| `provers/zkminer-prove-risc0-metal` | the Metal prover |
| `metal-aot/` | offline GPU pipeline archives (`manifest.jsonl`, `SHA256SUMS`) |
| `install.sh`, `tools/` | the installer and its archive helper |
| `BUILDINFO` | version, commit, risc0 revision, minimum macOS, Metal compiler, archive families, the Groth16 pin |
| `SHA256SUMS` | checksums of every file in the kit |
