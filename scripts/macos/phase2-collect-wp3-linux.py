#!/usr/bin/env python3
"""Bind the offline Colima WP3 feature checks to the exact engine snapshot."""

import hashlib
import json
from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[2]
ENGINE = Path("/Users/dbur/dev/risc0")
DIRECTORY = ROOT / "target/macos/phase2/wp3-linux"
COMMIT = "8520c737725698ddb156ccda2a41e0521213b878"
IMAGE_ID = "sha256:ecbe59a8408895edd02d9ef422504b8501dd9fa1526de27a45b73406d734d659"
ARCHIVE_SHA = "744b999f0a35b3c86753311c7efb2a0054be21727095cf105af6ee7d3f4d8849"
CHECKS = {
    "recursion_prove_metal": "recursion.log",
    "rv32im_prove": "rv32im.log",
    "zkvm_prove_metal_recursion": "zkvm.log",
}
SOURCES = (
    "Cargo.lock",
    "risc0/circuit/rv32im/build.rs",
    "risc0/circuit/recursion/build.rs",
    "risc0/zkp/src/hal/metal.rs",
    "risc0/sys/kernels/zkp/metal/ntt.metal",
)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    assert subprocess.check_output(["git", "-C", str(ENGINE), "rev-parse", "HEAD"],
                                   text=True).strip() == COMMIT
    sources = {}
    for name in SOURCES:
        path = DIRECTORY / "source" / name
        assert sha(path) == sha(ENGINE / name), name
        sources[name] = sha(path)
    archive = ROOT / "target/macos/phase2/wp05-linux/recursion_zkr.zip"
    assert sha(archive) == ARCHIVE_SHA
    logs = {}
    for check, filename in CHECKS.items():
        path = DIRECTORY / filename
        body = path.read_text()
        assert "rustc 1.93.1 (01f6ddf75 2026-02-11)" in body
        assert "Finished `dev` profile" in body and "error:" not in body
        logs[check] = {"path": str(path), "sha256": sha(path), "result": "passed"}
    report = {
        "schema_version": 1, "status": "passed", "engine_commit": COMMIT,
        "container_image": "rust:1.93-trixie", "container_image_id": IMAGE_ID,
        "compiler": "rustc 1.93.1 (01f6ddf75 2026-02-11)",
        "compile_network": "disabled (--network none, cargo --offline --locked)",
        "recursion_archive_sha256": ARCHIVE_SHA,
        "source_snapshot_hashes": sources,
        "checks": {name: "passed" for name in CHECKS},
        "logs": logs,
    }
    path = DIRECTORY / "result.json"
    path.write_text(json.dumps(report, indent=2) + "\n")
    print(path)


if __name__ == "__main__":
    main()
