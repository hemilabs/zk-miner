#!/usr/bin/env python3
"""Seal the source-bound WP8-lite worker for the controlled final reading."""

import json
from pathlib import Path
import shutil
import subprocess

from proof_provenance import ROOT, sha, verify_build as verify_verifier
from worker_provenance import paths, verify_build as verify_worker


ENGINE = Path("/Users/dbur/dev/risc0")
ARCHIVE = ROOT / "target/macos/phase2/wp8lite-checkpoint"
SPEC_SHA256 = "c7cd2ab3cf8f6f67fb4deeabfd9ed86c28d24aa98c0e7c1a7b578640718d475d"


def main():
    if ARCHIVE.exists():
        raise RuntimeError(f"WP8-lite checkpoint already exists: {ARCHIVE}")
    worker = verify_worker("native-rv32im-metal", ENGINE)
    verifier = verify_verifier("verifier")
    worker_paths = paths("native-rv32im-metal")
    files = {
        "zkminer-prove-risc0": worker_paths["binary"],
        "worker-build.json": worker_paths["manifest"],
        "worker-metadata.json": worker_paths["metadata"],
        "worker-local-Cargo.lock": worker_paths["local_lock"],
        "engine.toml": ROOT / "target/macos/phase2/wp8lite-engine.toml",
        "hemi-macos-proof": ROOT / "target/macos/verifier/release/hemi-macos-proof",
        "verifier-build.json": ROOT / "target/macos/verifier-build.json",
        "helper-manifest.json": ROOT / "target/macos/native-wrap/assets/manifest.json",
    }
    assert sha(files["zkminer-prove-risc0"]) == worker["binary_sha256"]
    assert sha(files["hemi-macos-proof"]) == verifier["binary_sha256"]
    ARCHIVE.mkdir(parents=True)
    for name, source in files.items():
        shutil.copy2(source, ARCHIVE / name)
    miner_commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    manifest = {
        "schema_version": 1,
        "status": "sealed",
        "checkpoint": "WP8-lite native Groth16 prestart and piped witness",
        "engine_commit": worker["source"]["engine_head"],
        "miner_commit": miner_commit,
        "source_spec_sha256": SPEC_SHA256,
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
