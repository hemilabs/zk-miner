#!/usr/bin/env python3
"""Collect WP0 smoke, limit, and lifecycle checks from sealed worker runs."""

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


def verified_rows(run):
    records = [json.loads(line) for line in (run / "acceptance/requests.jsonl").read_text().splitlines()]
    return [record for record in records if record.get("status") == "complete_independently_verified"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--engine", type=Path, required=True)
    parser.add_argument("--smoke", type=Path, required=True)
    parser.add_argument("--limits", type=Path, required=True)
    parser.add_argument("--lifecycle", type=Path, required=True)
    args = parser.parse_args()
    worker = verify_build("native-rv32im-metal", args.engine)
    runs = {"smoke": args.smoke, "limits": args.limits, "lifecycle": args.lifecycle}
    results = {name: read(run / "result.json") for name, run in runs.items()}
    assert all(result["status"] == "passed" for result in results.values())
    assert results["limits"]["worker_build"] == results["lifecycle"]["worker_build"] == worker
    smoke_build = results["smoke"]["worker_build"]
    assert all(smoke_build[key] == worker[key] for key in
               ("binary_sha256", "metadata_sha256", "local_lock_sha256"))
    parent = smoke_build["source"]["engine_head"]
    delta = subprocess.check_output(["git", "diff", parent, worker["source"]["engine_head"], "--binary"],
                                    cwd=args.engine)
    assert hashlib.sha256(delta).hexdigest() == smoke_build["source"]["engine_working_diff_sha256"]
    assert results["smoke"]["results"]["verified_proofs"] == 1
    smoke_worker = read(args.smoke / "acceptance/proof-0/worker.json")
    assert smoke_worker["observed_stages"]["rv32im_metal"]["cpu_differential_checks"] > 0
    for stage in ("rv32im_metal", "recursion_metal"):
        assert all(value["invalid_gpu_timestamps"] == 0 for value in
                   smoke_worker["observed_stages"][stage]["gpu_kernels"].values())
    limit_result = results["limits"]["results"]
    assert limit_result["status"] == "workload_limit_controls_passed"
    assert len(limit_result["cases"]) == 9 and limit_result["verified_proofs"] == 0
    lifecycle_result = results["lifecycle"]["results"]
    assert lifecycle_result["verified_proofs"] == lifecycle_result["unique_completed_requests"] == 21
    assert lifecycle_result["helper_cancel"] and lifecycle_result["worker_timeout"]
    assert lifecycle_result["restart"] and lifecycle_result["shutdown"]
    rows = verified_rows(args.lifecycle)
    assert len(rows) == 21
    steady = rows[:20]
    assert len({row["worker"]["worker_pid"] for row in steady}) == 1
    assert rows[-1]["worker"]["worker_pid"] != steady[0]["worker"]["worker_pid"]
    idle = [row["resources"]["idle_after_verification_and_settle"]["native_memory"]["group"]["worker"]["footprint_bytes"]
            for row in steady]
    drift = idle[-1] / idle[0] - 1
    assert abs(drift) <= 0.05
    records = [json.loads(line) for line in (args.lifecycle / "acceptance/requests.jsonl").read_text().splitlines()]
    assert {row.get("case") for row in records if row.get("status") == "expected_failure"} == {
        "helper-cancel", "helper-timeout"}
    pressure = sorted({sample["native_memory"]["pressure_level"] for row in steady
                       for sample in row["resources"]["observations"] if sample.get("native_memory")})
    native_log = ROOT / "target/macos/phase2/wp0/build-committed.log"
    cpu_log = ROOT / "target/macos/phase2/wp0/cpu-build.log"
    assert "test result: ok. 5 passed;" in native_log.read_text()
    assert "test result: ok. 5 passed;" in cpu_log.read_text()
    report = {
        "schema_version": 1, "status": "checks_passed", "engine_commit": worker["source"]["engine_head"],
        "worker_sha256": worker["binary_sha256"],
        "verifier_sha256": results["smoke"]["verifier_build"]["binary_sha256"],
        "collector_sha256": sha(Path(__file__)),
        "smoke_binary_unchanged_after_engine_commit": True,
        "checks": {
            "native_worker_unit_tests": {"passed": 5, "build_log_sha256": sha(native_log)},
            "cpu_worker_unit_tests": {"passed": 5, "build_log_sha256": sha(cpu_log)},
            "smoke_cpu_differential": smoke_worker["observed_stages"]["rv32im_metal"]["cpu_differential_checks"],
            "workload_limit_rejections": len(limit_result["cases"]),
            "lifecycle_verified_proofs": len(rows), "lifecycle_negative_checks": len(rows) * 3,
            "helper_cancellation": True, "helper_timeout_expected_failure": True,
            "worker_timeout": True, "restart_proof_verified": True, "shutdown": True,
            "idle_first_bytes": idle[0], "idle_last_bytes": idle[-1],
            "idle_drift_fraction": drift, "idle_min_bytes": min(idle), "idle_max_bytes": max(idle),
            "pressure_levels_observed": pressure,
        },
        "runs": {name: {"path": str(run), "result_sha256": sha(run / "result.json"),
                        "request_ledger_sha256": sha(run / "acceptance/requests.jsonl")
                        if (run / "acceptance/requests.jsonl").exists() else None}
                 for name, run in runs.items()},
        "linux_feature_compile": "not run: only aarch64-apple-darwin is installed in the local pinned Rust toolchain",
        "new_dependencies_or_version_bumps": [],
    }
    evidence = ROOT / "docs/macos/evidence"
    csv_path = evidence / "phase2-wp0-lifecycle.csv"
    with csv_path.open("w", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=["request", "idle_worker_footprint_bytes", "complete_seconds"],
                                lineterminator="\n")
        writer.writeheader()
        for index, row in enumerate(steady, 1):
            writer.writerow({"request": index, "idle_worker_footprint_bytes": idle[index - 1],
                             "complete_seconds": (row["timings"]["prove_call_ms"] +
                                                  row["timings"]["external_verifier_ms"]) / 1000})
    report["lifecycle_csv_sha256"] = sha(csv_path)
    json_path = evidence / "phase2-wp0-validation.json"
    json_path.write_text(json.dumps(report, indent=2) + "\n")
    print(json_path)
    print(csv_path)


if __name__ == "__main__":
    main()
