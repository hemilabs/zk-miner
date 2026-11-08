#!/usr/bin/env python3
"""Seal the source-bound WP3 worker as the next package's baseline arm."""

import json
from pathlib import Path
import shutil
import subprocess

from proof_provenance import ROOT, sha, verify_build as verify_verifier
from worker_provenance import paths, verify_build as verify_worker


ENGINE = Path("/Users/dbur/dev/risc0")
ARCHIVE = ROOT / "target/macos/phase2/wp3-baseline"
SPEC_SHA256 = "07467098c3493a0bbc0f543b0960676ba3a3e21ebd1fb7a65d10bb8dec40dc97"


def main():
    if ARCHIVE.exists():
        raise RuntimeError(f"WP3 archive already exists: {ARCHIVE}")
    worker = verify_worker("native-rv32im-metal", ENGINE)
    verifier = verify_verifier("verifier")
    worker_paths = paths("native-rv32im-metal")
    files = {
        "zkminer-prove-risc0": worker_paths["binary"],
        "worker-build.json": worker_paths["manifest"],
        "worker-metadata.json": worker_paths["metadata"],
        "worker-local-Cargo.lock": worker_paths["local_lock"],
        "engine.toml": ROOT / "target/macos/phase2/wp3-radix4-engine.toml",
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
        "baseline": "WP3 fused radix-four Metal transforms default",
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
