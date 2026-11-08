#!/usr/bin/env python3
"""Measure WP3 transform wall time without prior-segment GPU queue overlap."""

import json
import os
from pathlib import Path
import subprocess
import sys
import uuid
from datetime import datetime, timezone

from proof_provenance import ROOT, sha, verify_build as verify_verifier
from worker_provenance import verify_build as verify_worker


ENGINE = Path("/Users/dbur/dev/risc0")


def snapshot(directory, name):
    path = directory / f"host-{name}.json"
    subprocess.run([sys.executable, str(ROOT / "scripts/macos/phase2-host-snapshot.py"),
                    "--output", str(path)], check=True, capture_output=True, text=True)
    return {"path": str(path), "sha256": sha(path),
            "observation": json.loads(path.read_text())}


def main():
    for name in ("RISC0_METAL_NTT_RADIX2", "RISC0_METAL_NTT_LEGACY_GRID", "RISC0_METAL_NTT_FULL_GRID"):
        if os.environ.get(name) == "1":
            raise RuntimeError(f"WP3 transform diagnostic disabled by {name}")
    worker = verify_worker("native-rv32im-metal", ENGINE)
    verifier = verify_verifier("verifier")
    directory = ROOT / "target/macos/phase2/wp3-isolated" / uuid.uuid4().hex
    directory.mkdir(parents=True)
    toolchain = ROOT / "target/macos/toolchain"
    env = dict(os.environ, CARGO_NET_OFFLINE="true", CARGO_HOME=str(toolchain / "cargo"),
               RUSTUP_HOME=str(toolchain / "rustup"), RISC0_HOME=str(toolchain / "risc0"),
               PATH=str(toolchain / "cargo/bin") + os.pathsep + os.environ["PATH"],
               RAYON_NUM_THREADS="18", ZKMINER_MACOS_HOST_RESERVE_GIB="8",
               RISC0_SEGMENT_PIPELINE="0", RISC0_METAL_GPU_PROFILE="1", RISC0_VERBOSE="1")
    command = [sys.executable, str(ROOT / "scripts/macos/test-native-worker.py"),
               "--engine", str(ENGINE), "--worker-kind", "native-rv32im-metal",
               "--segment-hal", "metal", "--recursion-hal", "metal",
               "--workload", "fibonacci", "--iterations", "1000000",
               "--min-guest-cycles", "10000000", "--po2", "20",
               "--repeat", "1", "--proof-only", "--timeout-seconds", "1800"]
    report = {"status": "running", "started_utc": datetime.now(timezone.utc).isoformat(),
              "purpose": "uncontended transform wall-time diagnostic; paired complete-proof gate is separate",
              "pipeline_disabled": True, "rayon_threads": 18, "go_threads": 18,
              "host_reserve_gib": 8, "candidate_worker_sha256": worker["binary_sha256"],
              "verifier_sha256": verifier["binary_sha256"],
              "engine_commit": worker["source"]["engine_head"],
              "driver_sha256": sha(Path(__file__)),
              "acceptance_runner_sha256": sha(ROOT / "scripts/macos/test-native-worker.py"),
              "command": command, "host_before": snapshot(directory, "before")}
    result_path = directory / "result.json"
    result_path.write_text(json.dumps(report, indent=2) + "\n")
    print(directory, flush=True)
    try:
        with (directory / "acceptance.log").open("w") as log:
            process = subprocess.run(command, cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT)
        report["exit_code"] = process.returncode
        report["host_after"] = snapshot(directory, "after")
        run = Path((directory / "acceptance.log").read_text().splitlines()[0])
        report["run"] = str(run)
        report["run_result_sha256"] = sha(run / "result.json")
        assert process.returncode == 0
        assert json.loads((run / "result.json").read_text())["status"] == "passed"
        report["status"] = "passed"
    except BaseException as error:
        report.update(status="failed", error=str(error))
        raise
    finally:
        report["finished_utc"] = datetime.now(timezone.utc).isoformat()
        result_path.write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
