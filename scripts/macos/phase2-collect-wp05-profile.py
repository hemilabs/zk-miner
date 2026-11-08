#!/usr/bin/env python3
"""Bind WP0.5 GPU command counts and dispatch overhead to verified proofs."""

import argparse
import csv
import json
from pathlib import Path

from proof_provenance import ROOT, sha
from worker_provenance import verify_build


EVIDENCE = ROOT / "docs/macos/evidence"
STAGES = ("polynomial_transforms", "merkle_commitments", "recursion")
SPEC_SHA256 = "299ebd441aa2e1c0c70f7587a88b8cc32154d0835a0eaea0d807adef11028597"


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
    worker_build = verify_build("native-rv32im-metal", args.engine.resolve())
    assert raw["worker_build"] == worker_build
    wp0 = read(EVIDENCE / "phase2-wp0-gpu-profile.json")
    assert wp0["status"] == "measured"
    baseline = {profile["fixture"]: {row["stage"]: row for row in profile["stages"]}
                for profile in wp0["profiles"]}
    rows = []
    profiles = []
    for case in raw["cases"]:
        assert case["status"] == "passed"
        run = Path(case["run"])
        result = read(run / "result.json")
        assert result["status"] == "passed" and result["results"]["verified_proofs"] == 1
        assert result["worker_build"] == worker_build
        assert result["verifier_build"] == raw["verifier_build"]
        verification = read(run / "acceptance/proof-0/verification.json")
        assert verification["verification"] == "passed"
        assert set(verification["negative_tests"]) == {
            "wrong_image", "modified_journal", "corrupt_seal"}
        sidecar = read(run / "acceptance/proof-0/worker.json")
        commands = case["gpu_profile"]["commands"]
        assert commands and all(command["gpu_ms"] > 0 for command in commands)
        assert {command["segment"] for command in commands if command["segment"] >= 0} == set(range(10))
        for label, prefix, segment in (("rv32im_metal", "segment/", True),
                                        ("recursion_metal", "recursion/", False)):
            stats = sidecar["observed_stages"][label]["gpu_kernels"]
            assert all(name.startswith(prefix) and item["invalid_gpu_timestamps"] == 0
                       for name, item in stats.items())
            logged = [command for command in commands if (command["segment"] >= 0) == segment]
            assert sum(item.get("command_buffers", item["commands"]) for item in stats.values()) == len(logged)
            assert abs(sum(item["gpu_seconds"] for item in stats.values()) -
                       sum(command["gpu_ms"] for command in logged) / 1000) < 0.01
        stage_wall = dict(case["wall_seconds"], recursion=case["recursion_wall_seconds"])
        stage_rows = []
        for stage, wall in stage_wall.items():
            summary = case["gpu_profile"]["by_stage"].get(stage, {})
            gpu = summary.get("gpu_seconds", 0.0)
            dispatch = summary.get("dispatch_wall_seconds", 0.0)
            count = summary.get("commands", 0)
            prior = baseline[case["name"]].get(stage, {})
            prior_count = prior.get("command_count", 0)
            entry = {
                "fixture": case["name"], "stage": stage,
                "wall_seconds": wall, "gpu_seconds": gpu,
                "dispatch_wall_seconds": dispatch,
                "host_dispatch_overhead_seconds": dispatch - gpu,
                "wall_outside_matched_dispatch_seconds": wall - dispatch,
                "command_count": count, "wp0_command_count": prior_count,
                "command_reduction_ratio": prior_count / count if count else None,
                "command_gate_passed": prior_count >= 10 * count if stage in STAGES else None,
                "host_overhead_gate_passed": dispatch - gpu <= 0.3 if stage in STAGES else None,
            }
            rows.append(entry)
            stage_rows.append(entry)
        assert all(any(row["stage"] == stage for row in stage_rows) for stage in STAGES)
        profiles.append({
            "fixture": case["name"], "run": str(run),
            "run_result_sha256": sha(run / "result.json"),
            "worker_sidecar_sha256": sha(run / "acceptance/proof-0/worker.json"),
            "verification_sha256": sha(run / "acceptance/proof-0/verification.json"),
            "gpu_command_count": len(commands), "gpu_seconds": case["gpu_profile"]["gpu_seconds"],
            "stages": stage_rows, "kernels": case["gpu_profile"]["by_kernel"],
        })
    assert [profile["fixture"] for profile in profiles] == list(baseline)
    gate_rows = [row for row in rows if row["stage"] in STAGES]
    report = {
        "schema_version": 1,
        "status": "passed" if all(row["command_gate_passed"] and row["host_overhead_gate_passed"]
                                  for row in gate_rows) else "profile_gate_failed",
        "source_spec_sha256": SPEC_SHA256,
        "scope": "one externally verified 10M GPU diagnostic per fixture; counts compared with the WP0 GPU profile",
        "profile_run": str(args.profile),
        "profile_result_sha256": sha(args.profile / "result.json"),
        "baseline_wp0_profile_sha256": sha(EVIDENCE / "phase2-wp0-gpu-profile.json"),
        "engine_commit": worker_build["source"]["engine_head"],
        "worker_sha256": worker_build["binary_sha256"],
        "verifier_sha256": raw["verifier_build"]["binary_sha256"],
        "profile_script_sha256": raw["script_sha256"],
        "collector_sha256": sha(Path(__file__)),
        "verified_proofs": 2, "tamper_rejections": 6,
        "profiles": profiles,
        "note": "GPUStartTime/GPUEndTime cover whole batched command buffers. Individual dispatches retain their completed-dispatch counts in sidecars; command_count counts committed buffers. This is a diagnostic profile, not a paired latency campaign.",
    }
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    csv_path = EVIDENCE / "phase2-wp05-gpu-profile.csv"
    with csv_path.open("w", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=list(rows[0]), lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
    report["csv_sha256"] = sha(csv_path)
    json_path = EVIDENCE / "phase2-wp05-gpu-profile.json"
    json_path.write_text(json.dumps(report, indent=2) + "\n")
    print(json_path)
    print(csv_path)
    print(report["status"])


if __name__ == "__main__":
    main()
