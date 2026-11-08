#!/usr/bin/env python3
"""Seal the source-bound WP5 worker as the next package's baseline arm."""

import json
from pathlib import Path
import shutil
import subprocess

from proof_provenance import ROOT, sha, verify_build as verify_verifier
from worker_provenance import paths, verify_build as verify_worker


ENGINE = Path("/Users/dbur/dev/risc0")
ARCHIVE = ROOT / "target/macos/phase2/wp5-baseline"
SPEC_SHA256 = "7b67d229839eb5f9d424dc27fed31906e766ea8bcea3c9d892e323d9ebcf5df7"


def main():
    if ARCHIVE.exists():
        raise RuntimeError(f"WP5 archive already exists: {ARCHIVE}")
    worker = verify_worker("native-rv32im-metal", ENGINE)
    verifier = verify_verifier("verifier")
    worker_paths = paths("native-rv32im-metal")
    files = {
        "zkminer-prove-risc0": worker_paths["binary"],
        "worker-build.json": worker_paths["manifest"],
        "worker-metadata.json": worker_paths["metadata"],
        "worker-local-Cargo.lock": worker_paths["local_lock"],
        "engine.toml": ROOT / "target/macos/phase2/wp5-engine.toml",
        "hemi-macos-proof": ROOT / "target/macos/verifier/release/hemi-macos-proof",
        "verifier-build.json": ROOT / "target/macos/verifier-build.json",
        "helper-manifest.json": ROOT / "target/macos/native-wrap/assets/manifest.json",
    }
    assert sha(files["zkminer-prove-risc0"]) == worker["binary_sha256"]
    assert sha(files["hemi-macos-proof"]) == verifier["binary_sha256"]
    ARCHIVE.mkdir(parents=True)
    for name, source in files.items():
        shutil.copy2(source, ARCHIVE / name)
    miner_commit = subprocess.check_output(["git", "rev-parse", "HEAD"],
                                           cwd=ROOT, text=True).strip()
    manifest = {
        "schema_version": 1, "status": "sealed",
        "baseline": "WP5 po2-20 pipelined Metal default after po2-21 assessment",
        "engine_commit": worker["source"]["engine_head"],
        "miner_commit": miner_commit, "source_spec_sha256": SPEC_SHA256,
        "files": {name: sha(ARCHIVE / name) for name in files},
    }
    path = ARCHIVE / "manifest.json"
    path.write_text(json.dumps(manifest, indent=2) + "\n")
    for name, digest in manifest["files"].items():
        assert sha(ARCHIVE / name) == digest
    print(path)
    print(sha(path))


if __name__ == "__main__":
    main()
