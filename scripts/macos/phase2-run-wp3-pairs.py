#!/usr/bin/env python3
"""Run WP3's fixed five-pair campaign against the sealed WP2 worker."""

import json
import os
from pathlib import Path
import subprocess
import sys
import uuid
from datetime import datetime, timezone

from proof_provenance import ROOT, sha, verify_build
from worker_provenance import verify_build as verify_worker, paths


ENGINE = Path("/Users/dbur/dev/risc0")
ARCHIVE = ROOT / "target/macos/phase2/wp2-baseline"
FIXTURES = (
    ("arithmetic-10m", "fibonacci", "1000000"),
    ("hash-10m", "sha256-chain", "2262"),
)


def stamp():
    return datetime.now(timezone.utc).isoformat()


def snapshot(directory, name):
    path = directory / f"host-{name}.json"
    subprocess.run([sys.executable, str(ROOT / "scripts/macos/phase2-host-snapshot.py"),
                    "--output", str(path)], check=True, capture_output=True, text=True)
    data = json.loads(path.read_text())
    return {"path": str(path), "sha256": sha(path), "observation": data}


def main():
    reserve_gib = int(os.environ.get("ZKMINER_MACOS_HOST_RESERVE_GIB", "8"))
    if not 8 <= reserve_gib <= 64:
        raise RuntimeError("WP3 pair reserve must be within the worker's 8..64 GiB range")
    if os.environ.get("RISC0_SEGMENT_PIPELINE") == "0":
        raise RuntimeError("WP3 comparison requires the WP2 pipeline in both arms")
    for name in ("RISC0_METAL_NTT_RADIX2", "RISC0_METAL_NTT_LEGACY_GRID", "RISC0_METAL_NTT_FULL_GRID"):
        if os.environ.get(name) == "1":
            raise RuntimeError(f"WP3 candidate path disabled by {name}")
    baseline = json.loads((ARCHIVE / "manifest.json").read_text())
    assert baseline["status"] == "sealed"
    for name, digest in baseline["files"].items():
        assert sha(ARCHIVE / name) == digest, name
    candidate = verify_worker("native-rv32im-metal", ENGINE)
    verifier = verify_build("verifier")
    assert verifier["binary_sha256"] == baseline["files"]["hemi-macos-proof"]
    assert sha(paths("native-rv32im-metal")["binary"]) == candidate["binary_sha256"]
    directory = ROOT / "target/macos/phase2/wp3-pairs" / uuid.uuid4().hex
    directory.mkdir(parents=True)
    report = {
        "status": "running", "started_utc": stamp(),
        "criterion": {"fixtures": [name for name, _, _ in FIXTURES],
                      "arms": ["sealed WP2 archive", "WP3 fused Metal transform"],
                      "order": "one warmup per arm, then five alternating pairs; fixture start arm counterbalanced",
                      "metric": "prove call plus unchanged external verifier",
                      "max_transform_wall_seconds_per_segment": 0.8,
                      "minimum_bandwidth_fraction_of_600_gbs": 0.30,
                      "host_reserve_gib": reserve_gib, "rayon_threads": 18, "go_threads": 18,
                      "po2": 20, "failures_excluded": False},
        "baseline_manifest_sha256": sha(ARCHIVE / "manifest.json"),
        "baseline_worker_sha256": baseline["files"]["zkminer-prove-risc0"],
        "candidate_worker_sha256": candidate["binary_sha256"],
        "candidate_pipeline": "WP2 overlap enabled in both arms; fused radix-4 commit default in candidate",
        "verifier_sha256": verifier["binary_sha256"],
        "engine_commit": candidate["source"]["engine_head"],
        "miner_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
        "driver_sha256": sha(Path(__file__)),
        "acceptance_runner_sha256": sha(ROOT / "scripts/macos/test-native-worker.py"),
        "cases": [],
    }
    def save():
        (directory / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    save()
    print(directory, flush=True)
    toolchain = ROOT / "target/macos/toolchain"
    environment = dict(os.environ, CARGO_NET_OFFLINE="true",
                       CARGO_HOME=str(toolchain / "cargo"), RUSTUP_HOME=str(toolchain / "rustup"),
                       RISC0_HOME=str(toolchain / "risc0"), CARGO_BUILD_JOBS="6",
                       RAYON_NUM_THREADS="18", ZKMINER_MACOS_HOST_RESERVE_GIB=str(reserve_gib),
                       PATH=str(toolchain / "cargo/bin") + os.pathsep + os.environ["PATH"])
    try:
        for start_case, (name, workload, iterations) in enumerate(FIXTURES):
            row = {"fixture": name, "status": "running", "started_utc": stamp()}
            report["cases"].append(row)
            row["host_before"] = snapshot(directory, f"{name}-before")
            command = [sys.executable, str(ROOT / "scripts/macos/test-native-worker.py"),
                       "--engine", str(ENGINE), "--worker-kind", "native-rv32im-metal",
                       "--segment-hal", "metal", "--recursion-hal", "metal",
                       "--paired-metal-baseline", str(ARCHIVE / "zkminer-prove-risc0"),
                       "--paired-start-case", str(start_case),
                       "--workload", workload, "--iterations", iterations,
                       "--min-guest-cycles", "10000000", "--po2", "20",
                       "--samples", "5", "--repeat", "1", "--proof-only",
                       "--timeout-seconds", "1800"]
            row["command"] = command
            save()
            with (directory / f"{name}.log").open("w") as log:
                process = subprocess.run(command, cwd=ROOT, env=environment,
                                         stdout=log, stderr=subprocess.STDOUT)
            row["host_after"] = snapshot(directory, f"{name}-after")
            row["exit_code"] = process.returncode
            run = Path((directory / f"{name}.log").read_text().splitlines()[0])
            row["run"] = str(run)
            row["result_sha256"] = sha(run / "result.json")
            if process.returncode or json.loads((run / "result.json").read_text())["status"] != "passed":
                row["status"] = "failed"
                save()
                raise RuntimeError(f"{name} paired campaign failed; see {run}")
            row["status"] = "passed"
            row["finished_utc"] = stamp()
            save()
            print(f"{name}: {run}", flush=True)
        report["status"] = "passed"
    except BaseException as error:
        report["status"] = "failed"
        report["error"] = str(error)
        raise
    finally:
        report["finished_utc"] = stamp()
        save()


if __name__ == "__main__":
    main()
