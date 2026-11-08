#!/usr/bin/env python3
"""Bind compact WP0 GPU profiles to verified proofs and committed source."""

import argparse
import csv
import hashlib
import json
from pathlib import Path
import subprocess

from proof_provenance import ROOT, sha
from worker_provenance import verify_build


def read(path):
    return json.loads(path.read_text())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--engine", type=Path, required=True)
    parser.add_argument("--profile", type=Path, required=True)
    args = parser.parse_args()
    raw = read(args.profile / "result.json")
    assert raw["status"] == "completed"
    assert raw["script_sha256"] == sha(ROOT / "scripts/macos/profile-rv32im.py")
    engine = args.engine.resolve()
    committed = verify_build("native-rv32im-metal", engine)
    measured = raw["worker_build"]
    assert measured["binary_sha256"] == committed["binary_sha256"]
    assert measured["metadata_sha256"] == committed["metadata_sha256"]
    assert measured["local_lock_sha256"] == committed["local_lock_sha256"]
    parent = measured["source"]["engine_head"]
    head = committed["source"]["engine_head"]
    delta = subprocess.check_output(["git", "diff", parent, head, "--binary"], cwd=engine)
    assert hashlib.sha256(delta).hexdigest() == measured["source"]["engine_working_diff_sha256"]
    assert committed["source"]["engine_working_diff_sha256"] == hashlib.sha256(b"").hexdigest()
    report = {
        "schema_version": 1, "status": "measured", "scope": "one verified 10M diagnostic proof per fixture with per-command GPU timing",
        "engine_parent": parent, "engine_commit": head,
        "miner_commit_at_measurement": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
        "measurement_time_engine_diff_sha256": hashlib.sha256(delta).hexdigest(),
        "worker_binary_unchanged_after_commit": True,
        "worker_sha256": committed["binary_sha256"],
        "verifier_sha256": raw["verifier_build"]["binary_sha256"],
        "profile_result_sha256": sha(args.profile / "result.json"),
        "profile_script_sha256": raw["script_sha256"],
        "collector_sha256": sha(Path(__file__)),
        "source_hashes": {str(path.relative_to(engine)): sha(path) for path in (
            engine / "risc0/zkp/src/hal/metal.rs",
            engine / "risc0/zkvm/src/host/server/prove/prover_impl.rs")},
        "profiles": [],
    }
    rows = []
    for case in raw["cases"]:
        assert case["status"] == "passed"
        run = Path(case["run"])
        result = read(run / "result.json")
        assert result["status"] == "passed" and result["results"]["verified_proofs"] == 1
        assert result["worker_build"] == measured and result["verifier_build"] == raw["verifier_build"]
        verification = read(run / "acceptance/proof-0/verification.json")
        assert verification["verification"] == "passed"
        assert set(verification["negative_tests"]) == {"wrong_image", "modified_journal", "corrupt_seal"}
        worker = read(run / "acceptance/proof-0/worker.json")
        commands = case["gpu_profile"]["commands"]
        assert commands and all(command["gpu_ms"] > 0 for command in commands)
        assert {command["segment"] for command in commands if command["segment"] >= 0} == set(range(10))
        for label, prefix, criterion in (("rv32im_metal", "segment/", lambda c: c["segment"] >= 0),
                                         ("recursion_metal", "recursion/", lambda c: c["segment"] < 0)):
            sidecar = worker["observed_stages"][label]["gpu_kernels"]
            assert all(name.startswith(prefix) and stats["invalid_gpu_timestamps"] == 0
                       for name, stats in sidecar.items())
            sidecar_count = sum(stats.get("command_buffers", stats["commands"])
                                for stats in sidecar.values())
            logged = [command for command in commands if criterion(command)]
            assert sidecar_count == len(logged)
            sidecar_gpu = sum(stats["gpu_seconds"] for stats in sidecar.values())
            logged_gpu = sum(command["gpu_ms"] for command in logged) / 1000
            assert abs(sidecar_gpu - logged_gpu) < 0.01
        stage_wall = dict(case["wall_seconds"], recursion=case["recursion_wall_seconds"])
        stage_rows = []
        for stage, seconds in stage_wall.items():
            summary = case["gpu_profile"]["by_stage"].get(stage, {})
            gpu = summary.get("gpu_seconds", 0.0)
            dispatch = summary.get("dispatch_wall_seconds", 0.0)
            entry = {
                "fixture": case["name"], "stage": stage, "wall_seconds": seconds,
                "gpu_seconds": gpu, "dispatch_wall_seconds": dispatch,
                "host_dispatch_overhead_seconds": dispatch - gpu,
                "wall_outside_matched_dispatch_seconds": seconds - dispatch,
                "gpu_fraction_of_wall": gpu / seconds if seconds else None,
                "gpu_within_10_percent_of_wall": abs(seconds - gpu) <= seconds * 0.1 if gpu else None,
                "command_count": summary.get("commands", 0),
            }
            rows.append(entry)
            stage_rows.append(entry)
        pipeline_limits = {}
        for command in commands:
            phase = "segment" if command["segment"] >= 0 else "recursion"
            key = f"{phase}/{command['kernel']}"
            limits = {field: command[field] for field in (
                "thread_execution_width", "max_total_threads_per_threadgroup",
                "static_threadgroup_memory_length")}
            assert key not in pipeline_limits or pipeline_limits[key] == limits
            pipeline_limits[key] = limits
        report["profiles"].append({
            "fixture": case["name"], "run": str(run), "run_result_sha256": sha(run / "result.json"),
            "program_sha256": result["program_sha256"], "input_sha256": result["input_sha256"],
            "worker_sidecar_sha256": sha(run / "acceptance/proof-0/worker.json"),
            "verification_sha256": sha(run / "acceptance/proof-0/verification.json"),
            "gpu_command_count": len(commands), "gpu_seconds": case["gpu_profile"]["gpu_seconds"],
            "synchronous_overlap_seconds": 0.0, "stages": stage_rows,
            "kernels": case["gpu_profile"]["by_kernel"], "pipeline_limits": pipeline_limits,
        })
    report["verified_proofs"] = 2
    report["negative_checks"] = 6
    report["notes"] = [
        "GPUStartTime/GPUEndTime measure device execution for one kernel per command buffer.",
        "Dispatch wall includes GPU execution, queue/synchronization cost and pipeline creation; the stage remainder includes CPU work and timer-scope differences.",
        "The current synchronous Metal path has no CPU/GPU segment overlap.",
        "The transform GPU-only fraction misses the brief's 10% wall-reconciliation threshold; host dispatch overhead is reported separately.",
    ]
    evidence = ROOT / "docs/macos/evidence"
    csv_path = evidence / "phase2-wp0-gpu-profile.csv"
    columns = list(rows[0])
    with csv_path.open("w", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=columns, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
    report["csv_sha256"] = sha(csv_path)
    json_path = evidence / "phase2-wp0-gpu-profile.json"
    json_path.write_text(json.dumps(report, indent=2) + "\n")
    print(json_path)
    print(csv_path)


if __name__ == "__main__":
    main()
