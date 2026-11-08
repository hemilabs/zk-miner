#!/usr/bin/env python3
"""Read Phase 2's absolute final lines on the sealed upstream-merged checkpoint."""

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
ARCHIVE = ROOT / "target/macos/phase2/upstream-merge-checkpoint"
SPEC_SHA256 = "ecd565ffba5582c00c1191d8a427cd5bb48d90440b21b8d0423735e9e7847031"
FIXTURES = (
    ("arithmetic-10m", "fibonacci", "1000000", "10000000"),
    ("hash-10m", "sha256-chain", "2262", "10000000"),
    ("arithmetic-46m", "fibonacci", "4600000", "46000000"),
)


def stamp():
    return datetime.now(timezone.utc).isoformat()


def snapshot(directory, name):
    path = directory / f"host-{name}.json"
    subprocess.run([sys.executable, str(ROOT / "scripts/macos/phase2-host-snapshot.py"),
                    "--output", str(path)], check=True, capture_output=True, text=True)
    return {"path": str(path), "sha256": sha(path),
            "observation": json.loads(path.read_text())}


def main():
    manifest_path = ARCHIVE / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    assert manifest["status"] == "sealed"
    assert manifest["source_spec_sha256"] == SPEC_SHA256
    for name, digest in manifest["files"].items():
        assert sha(ARCHIVE / name) == digest, name
    worker = verify_worker("native-rv32im-metal", ENGINE)
    verifier = verify_verifier("verifier")
    assert worker["binary_sha256"] == manifest["files"]["zkminer-prove-risc0"]
    assert verifier["binary_sha256"] == manifest["files"]["hemi-macos-proof"]
    assert worker["source"]["engine_head"] == manifest["engine_commit"]
    assert sha(ROOT / "target/macos/native-wrap/assets/manifest.json") == manifest["files"]["helper-manifest.json"]
    for name in ("RISC0_METAL_NTT_RADIX2", "RISC0_METAL_NTT_LEGACY_GRID",
                 "RISC0_METAL_NTT_FULL_GRID", "RISC0_RV32IM_TAIL_SPLIT"):
        assert os.environ.get(name) != "1", name

    directory = ROOT / "target/macos/phase2/controlled-upstream-merge" / uuid.uuid4().hex
    directory.mkdir(parents=True)
    toolchain = ROOT / "target/macos/toolchain"
    env = dict(os.environ, CARGO_NET_OFFLINE="true", RUSTUP_TOOLCHAIN="1.93.0",
               CARGO_HOME=str(toolchain / "cargo"), RUSTUP_HOME=str(toolchain / "rustup"),
               RISC0_HOME=str(toolchain / "risc0"), RAYON_NUM_THREADS="18",
               PATH=str(toolchain / "cargo/bin") + os.pathsep + os.environ["PATH"])
    for name in ("ZKMINER_MACOS_HOST_RESERVE_GIB", "RISC0_SEGMENT_PIPELINE",
                 "RISC0_RV32IM_TAIL_SPLIT", "RISC0_RECURSION_METAL_SPLIT"):
        env.pop(name, None)
    report = {
        "status": "running", "started_utc": stamp(),
        "source_spec_sha256": SPEC_SHA256,
        "checkpoint_manifest_sha256": sha(manifest_path),
        "worker_sha256": worker["binary_sha256"],
        "verifier_sha256": verifier["binary_sha256"],
        "helper_manifest_sha256": manifest["files"]["helper-manifest.json"],
        "engine_commit": manifest["engine_commit"],
        "miner_checkpoint_commit": manifest["miner_commit"],
        "driver_sha256": sha(Path(__file__)),
        "acceptance_runner_sha256": sha(ROOT / "scripts/macos/test-native-worker.py"),
        "conditions": {"browser_closed": True, "host_reserve_gib": 8,
                       "reserve_override": False, "initial_thermal": "nominal",
                       "rayon_threads": 18, "go_threads": 18, "po2": 20,
                       "segment_pipeline": True,
                       "warmups_per_fixture": 1, "measured_per_fixture": 5},
        "fixtures": [],
    }
    result_path = directory / "result.json"

    def save():
        result_path.write_text(json.dumps(report, indent=2) + "\n")

    save()
    print(directory, flush=True)
    try:
        for fixture, workload, iterations, min_cycles in FIXTURES:
            row = {"fixture": fixture, "status": "running", "started_utc": stamp()}
            report["fixtures"].append(row)
            row["host_before"] = snapshot(directory, fixture + "-before")
            host = row["host_before"]["observation"]
            assert not host["background_process_present"]["brave"]
            assert subprocess.run(["pgrep", "-x", "Safari"], capture_output=True).returncode == 1
            if fixture == FIXTURES[0][0]:
                assert host["thermal"]["thermal_state_name"] == "nominal"
            command = [sys.executable, str(ROOT / "scripts/macos/test-native-worker.py"),
                       "--engine", str(ENGINE), "--worker-kind", "native-rv32im-metal",
                       "--segment-hal", "metal", "--recursion-hal", "metal",
                       "--workload", workload, "--iterations", iterations,
                       "--min-guest-cycles", min_cycles, "--po2", "20",
                       "--rayon-threads", "18", "--go-threads", "18",
                       "--repeat", "5", "--warmup", "--proof-only",
                       "--timeout-seconds", "1800"]
            row["command"] = command
            save()
            with (directory / f"{fixture}.log").open("w") as log:
                process = subprocess.run(command, cwd=ROOT, env=env,
                                         stdout=log, stderr=subprocess.STDOUT)
            row["exit_code"] = process.returncode
            row["host_after"] = snapshot(directory, fixture + "-after")
            run = Path((directory / f"{fixture}.log").read_text().splitlines()[0])
            row["run"] = str(run)
            row["result_sha256"] = sha(run / "result.json")
            result = json.loads((run / "result.json").read_text())
            assert process.returncode == 0 and result["status"] == "passed"
            assert result["results"]["verified_proofs"] == 6
            row["status"] = "passed"
            row["finished_utc"] = stamp()
            save()
            print(f"{fixture}: {run}", flush=True)
        report["status"] = "passed"
    except BaseException as error:
        report.update(status="failed", error=str(error))
        raise
    finally:
        report["finished_utc"] = stamp()
        save()


if __name__ == "__main__":
    main()
