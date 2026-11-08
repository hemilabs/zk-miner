#!/usr/bin/env python3
"""Build an unchanged miner guest in an isolated workspace with the local engine."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import re
import tomllib

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("workload", choices=["minimal-proof", "fibonacci", "sha256-chain", "segment-boundary"])
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--reset-lock", action="store_true", help="seed the isolated guest lock from the miner's resolved lock")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    source = root / "crates/zkminer-prover/guests/risc0" / args.workload
    dest = root / "target/macos/guests" / args.workload
    dest.mkdir(parents=True, exist_ok=True)
    for name in ("Cargo.toml", "Cargo.lock", "src/main.rs"):
        (dest / name).parent.mkdir(parents=True, exist_ok=True)
        # Keep an already-resolved local lockfile stable on repeated builds.
        if name != "Cargo.lock":
            shutil.copyfile(source / name, dest / name)
        elif args.reset_lock or not (dest / name).exists():
            # Some fixture locks already contain dependencies newer than the
            # engine's guest compiler supports. Preserve the miner's versions.
            shutil.copyfile(root / "Cargo.lock", dest / name)
    # A patch alone can lose to an older registry version already in the guest
    # lockfile. Make this isolated copy's SDK a direct local dependency as well.
    config = tomllib.loads(args.config.read_text())
    sdk = config["patch"]["crates-io"]["risc0-zkvm"]["path"]
    manifest, count = re.subn(r"(?m)^risc0-zkvm\s*=\s*\{", lambda _: 'risc0-zkvm = { path = ' + json.dumps(sdk) + ', ',
                             (source / "Cargo.toml").read_text())
    if count != 1:
        parser.error("expected exactly one guest SDK dependency")
    (dest / "Cargo.toml").write_text(manifest)
    env = os.environ.copy()
    for name in ("RISC0_SKIP_BUILD", "RISC0_SKIP_BUILD_KERNELS", "RISC0_DEV_MODE", "DOCS_RS"):
        if name in env:
            parser.error(f"unset {name}; no stub builds in acceptance")
    env.pop("RUSTFLAGS", None)
    # Match risc0-build at f8dcbdf8: no x86 flags, exact guest text address.
    env["CARGO_ENCODED_RUSTFLAGS"] = "\x1f".join([
        "-C", "passes=lower-atomic", "-C", "link-arg=-Ttext=0x00200800",
        "-C", "link-arg=--fatal-warnings", "-C", "panic=abort", "--cfg", 'getrandom_backend="custom"',
    ])
    command = ["cargo", "+risc0", "build", "--release", "--target", "riscv32im-risc0-zkvm-elf",
               "--manifest-path", str(dest / "Cargo.toml"), "--config", str(args.config.resolve()),
               "--target-dir", str(root / "target/macos/guest-build")]
    print("executing", command, flush=True)
    subprocess.run(command, env=env, check=True)
    metadata = subprocess.check_output(["cargo", "+risc0", "metadata", "--format-version", "1", "--locked",
        "--filter-platform", "riscv32im-risc0-zkvm-elf", "--manifest-path", str(dest / "Cargo.toml"),
        "--config", str(args.config.resolve())], env=env)
    (dest / "metadata.json").write_bytes(metadata)
    engine_root = Path(sdk).parents[1]
    subprocess.run(["python3", str(root / "scripts/macos/check-source.py"), str(dest / "metadata.json"),
                    "--engine", str(engine_root)], check=True)
    elf = root / "target/macos/guest-build/riscv32im-risc0-zkvm-elf/release" / args.workload
    data = elf.read_bytes()
    if not data.startswith(b"\x7fELF"):
        raise RuntimeError("guest compiler did not produce an ELF")
    packed = elf.with_name(elf.name + ".bin")
    pack = subprocess.check_output([str(root / "target/macos/cpu/release/hemi-macos-proof"),
                                   "pack", str(elf), str(packed)], text=True)
    provenance = {"source": str(source), "source_sha256": hashlib.sha256((source / 'src/main.rs').read_bytes()).hexdigest(),
                  "elf": str(elf), "elf_sha256": hashlib.sha256(data).hexdigest(), "command": command,
                  "program": str(packed), "packing": json.loads(pack)}
    (dest / "provenance.json").write_text(json.dumps(provenance, indent=2) + "\n")
    print(json.dumps(provenance))

if __name__ == "__main__":
    main()
