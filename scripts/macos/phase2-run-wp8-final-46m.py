#!/usr/bin/env python3
"""Controlled, source-bound absolute reading of WP8's 46M fixture."""

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import statistics
import subprocess
import sys
import time
import uuid

from proof_provenance import ROOT, sha
from worker_provenance import verify_build


ENGINE = Path("/Users/dbur/dev/risc0")
SPEC = Path("/Users/dbur/Downloads/Phase 2 spec Metal proving performance on macOS.md")
FIXTURES = (
    ("arithmetic-46m", "fibonacci", "4600000"),
)
IDENTITY = re.compile(r"\[succinct_to_groth16\] identity_p254=([0-9.]+)ms")
BROWSERS = ("Brave Browser", "Safari", "Google Chrome", "Firefox", "Microsoft Edge")


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def browser_closed():
    for browser in BROWSERS:
        if subprocess.run(["pgrep", "-x", browser], capture_output=True).returncode == 0:
            raise RuntimeError(f"browser is open: {browser}")


def host_snapshot(directory, label):
    path = directory / f"host-{label}.json"
    subprocess.run([sys.executable, str(ROOT / "scripts/macos/phase2-host-snapshot.py"),
                    "--output", str(path)], check=True, capture_output=True, text=True)
    value = json.loads(path.read_text())
    return {"path": str(path), "sha256": sha(path), "observation": value}


def summary(values):
    return {"median": statistics.median(values), "min": min(values), "max": max(values)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--idle-since", type=Path, required=True,
                        help="UTF-8 UTC timestamp recorded after the last build or check")
    parser.add_argument("--acceptance-build", type=Path, required=True)
    args = parser.parse_args()
    assert "ZKMINER_MACOS_HOST_RESERVE_GIB" not in os.environ, "reserve override is set"
    acceptance = args.acceptance_build.resolve(strict=True)
    baseline = verify_build("native-rv32im-metal", ENGINE)
    assert baseline["source"]["engine_head"] == subprocess.check_output(
        ["git", "-C", str(ENGINE), "rev-parse", "HEAD"], text=True).strip()
    directory = ROOT / "target/macos/phase2/wp8-final-46m-reading" / uuid.uuid4().hex
    directory.mkdir(parents=True)
    report = {
        "schema_version": 1, "status": "running", "started_utc": utc_now(),
        "spec_sha256": sha(SPEC), "engine_sha": baseline["source"]["engine_head"],
        "worker_sha256": baseline["binary_sha256"],
        "worker_manifest_sha256": sha(ROOT / "target/macos/worker-native-rv32im-metal-build.json"),
        "acceptance_build": str(acceptance), "acceptance_build_sha256": sha(acceptance),
        "conditions": {"browser_closed": True, "default_reserve_gib": 8,
                       "rayon_threads": 18, "go_threads": 18, "po2": 20,
                       "warmup_per_fixture": 1, "measured_per_fixture": 5,
                       "one_proof_in_flight": True},
        "fixtures": [],
    }
    result_path = directory / "result.json"

    def save():
        result_path.write_text(json.dumps(report, indent=2) + "\n")

    save()
    print(directory, flush=True)
    try:
        idle_since = datetime.fromisoformat(args.idle_since.read_text().strip())
        if idle_since.tzinfo is None:
            raise ValueError("idle marker must include timezone")
        browser_closed()
        while True:
            gap = (datetime.now(timezone.utc) - idle_since).total_seconds()
            if gap >= 900:
                break
            browser_closed()
            time.sleep(min(10, max(1, 900 - gap)))
        report["idle_since_utc"] = idle_since.isoformat()
        report["idle_gap_seconds"] = (datetime.now(timezone.utc) - idle_since).total_seconds()
        report["host_start"] = host_snapshot(directory, "start")
        browser_closed()
        thermal = report["host_start"]["observation"]["thermal"]["thermal_state_name"]
        if thermal != "nominal":
            raise RuntimeError(f"thermal state at start: {thermal}")
        save()
        env = dict(os.environ, CARGO_NET_OFFLINE="true", RAYON_NUM_THREADS="18")
        env.pop("ZKMINER_MACOS_HOST_RESERVE_GIB", None)
        for label, workload, iterations in FIXTURES:
            row = {"fixture": label, "status": "running", "started_utc": utc_now()}
            report["fixtures"].append(row)
            save()
            browser_closed()
            command = [sys.executable, str(ROOT / "scripts/macos/test-native-worker.py"),
                       "--engine", str(ENGINE), "--worker-kind", "native-rv32im-metal",
                       "--segment-hal", "metal", "--recursion-hal", "metal",
                       "--workload", workload, "--iterations", iterations,
                       "--min-guest-cycles", "46000000", "--po2", "20",
                       "--rayon-threads", "18", "--go-threads", "18",
                       "--repeat", "5", "--warmup", "--proof-only",
                       "--timeout-seconds", "1800",
                       "--prebuilt-acceptance-manifest", str(acceptance)]
            row["command"] = command
            process = subprocess.run(command, cwd=ROOT, env=env, capture_output=True, text=True)
            (directory / f"{label}.stdout").write_text(process.stdout)
            (directory / f"{label}.stderr").write_text(process.stderr)
            row["returncode"] = process.returncode
            paths = process.stdout.splitlines()
            if not paths:
                raise RuntimeError(f"{label}: missing run path: {process.stderr[-1000:]}")
            run = Path(paths[0]).resolve(strict=True)
            row["run_path"] = str(run)
            result = json.loads((run / "result.json").read_text())
            row["run_status"] = result["status"]
            if process.returncode or result["status"] != "passed":
                raise RuntimeError(f"{label}: proof campaign failed; retained at {run}")
            assert result["results"]["verified_proofs"] == 6
            identity_ms = [float(x) for x in IDENTITY.findall((run / "test.log").read_text())]
            assert len(identity_ms) == 6, (label, len(identity_ms))
            proofs = []
            for index in range(6):
                proof_dir = run / f"acceptance/proof-{index}"
                verification = json.loads((proof_dir / "verification.json").read_text())
                assert verification["verification"] == "passed"
                assert verification["negative_tests"] == [
                    "wrong_image", "modified_journal", "corrupt_seal"]
                timing = json.loads((proof_dir / "timing.json").read_text())
                worker = json.loads((proof_dir / "worker.json").read_text())
                resource = json.loads((proof_dir / "resource.json").read_text())
                assert worker["observed_stages"]["identity"] == "metal"
                identity = worker["observed_stages"]["identity_metal"]
                kernels = identity["gpu_kernels"]
                native = resource["idle_after_verification_and_settle"]["native_memory"]
                assert native["reserve_bytes"] == 8 * (1 << 30)
                proofs.append({"index": index, "excluded_warmup": index == 0,
                               "identity_seconds": identity_ms[index] / 1000,
                               "complete_seconds": timing["prove_call_ms"] / 1000,
                               "stage_ms": worker["stage_ms"],
                               "identity_merkle_gpu_seconds": kernels["recursion/batch_merkle"]["gpu_seconds"],
                               "poseidon254_rows_dispatches": kernels["recursion/poseidon254_rows"]["commands"],
                               "poseidon254_fold_dispatches": kernels["recursion/poseidon254_fold"]["commands"],
                               "identity_constraint_checks": identity["completed_constraint_checks"],
                               "peak_owned_footprint_bytes": native["guard_peak_footprint_bytes"],
                               "idle_owned_footprint_bytes": native["group"]["worker"]["footprint_bytes"]
                                   + native["group"]["helper_footprint_bytes"],
                               "pressure_levels_seen": native["guard_pressure_levels_seen"],
                               "timing_path": str(proof_dir / "timing.json"),
                               "timing_sha256": sha(proof_dir / "timing.json"),
                               "worker_path": str(proof_dir / "worker.json"),
                               "worker_sha256": sha(proof_dir / "worker.json"),
                               "resource_path": str(proof_dir / "resource.json"),
                               "resource_sha256": sha(proof_dir / "resource.json"),
                               "verification_path": str(proof_dir / "verification.json"),
                               "verification_sha256": sha(proof_dir / "verification.json")})
            row["proofs"] = proofs
            row["identity_seconds"] = summary([p["identity_seconds"] for p in proofs[1:]])
            row["complete_seconds"] = summary([p["complete_seconds"] for p in proofs[1:]])
            row["identity_merkle_gpu_seconds"] = summary(
                [p["identity_merkle_gpu_seconds"] for p in proofs[1:]])
            row["status"] = "passed"
            row["ended_utc"] = utc_now()
            assert verify_build("native-rv32im-metal", ENGINE) == baseline
            browser_closed()
            save()
        report["host_end"] = host_snapshot(directory, "end")
        browser_closed()
        report["status"] = "passed"
    except BaseException as error:
        report.update(status="failed", error=str(error))
        raise
    finally:
        report["ended_utc"] = utc_now()
        save()


if __name__ == "__main__":
    main()
