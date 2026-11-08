#!/usr/bin/env python3
"""Bind offline Colima WP8 feature checks to the exact engine snapshot."""

import hashlib
import json
from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[2]
ENGINE = Path("/Users/dbur/dev/risc0")
DIRECTORY = ROOT / "target/macos/phase2/wp8-linux"
EVIDENCE = ROOT / "docs/macos/evidence/phase2-wp8-linux.json"
COMMIT = "bcdca76fc8e83d0a42b5fecbda5f048e01cd2bce"
CHECKS = {
    "recursion_prove_metal": "recursion.log",
    "rv32im_prove": "rv32im.log",
    "zkvm_prove_metal_recursion": "zkvm.log",
}
SOURCES = (
    "Cargo.lock",
    "risc0/circuit/recursion/src/prove/hal/metal.rs",
    "risc0/sys/build.rs",
    "risc0/sys/kernels/zkp/metal/poseidon254.metal",
    "risc0/zkp/src/core/hash/poseidon_254/mod.rs",
    "risc0/zkp/src/hal/metal.rs",
)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    assert subprocess.check_output(["git", "-C", str(ENGINE), "rev-parse", "HEAD"],
                                   text=True).strip() == COMMIT
    assert not subprocess.check_output(["git", "-C", str(ENGINE), "status", "--porcelain"],
                                       text=True).strip()
    sources = {}
    for name in SOURCES:
        path = DIRECTORY / "source" / name
        assert sha(path) == sha(ENGINE / name), name
        sources[name] = sha(path)
    archive = ROOT / "target/macos/phase2/wp05-linux/recursion_zkr.zip"
    logs = {}
    for check, filename in CHECKS.items():
        path = DIRECTORY / filename
        body = path.read_text()
        assert "rustc 1.93.1 (01f6ddf75 2026-02-11)" in body
        assert "Finished `dev` profile" in body and "error:" not in body
        logs[check] = {"path": str(path), "sha256": sha(path), "result": "passed"}
    image = subprocess.check_output(
        ["docker", "image", "inspect", "rust:1.93-trixie", "--format", "{{.Id}}"],
        text=True).strip()
    report = {
        "schema_version": 1, "status": "passed", "engine_sha": COMMIT,
        "container_image": "rust:1.93-trixie", "container_image_id": image,
        "compiler": "rustc 1.93.1 (01f6ddf75 2026-02-11)",
        "compile_network": "disabled (--pull never, --network none, cargo --offline --locked)",
        "recursion_archive_sha256": sha(archive),
        "source_snapshot_hashes": sources,
        "checks": {name: "passed" for name in CHECKS},
        "logs": logs,
        "runner_sha256": sha(ROOT / "scripts/macos/phase2-run-wp8-linux.sh"),
        "collector_sha256": sha(Path(__file__)),
    }
    DIRECTORY.mkdir(parents=True, exist_ok=True)
    (DIRECTORY / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    EVIDENCE.write_text(json.dumps(report, indent=2) + "\n")
    print(EVIDENCE)


if __name__ == "__main__":
    main()
