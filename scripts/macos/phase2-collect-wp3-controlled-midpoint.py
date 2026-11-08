#!/usr/bin/env python3
"""Validate the sealed WP3 checkpoint's controlled absolute midpoint retake."""

import csv
import json
from pathlib import Path
from statistics import median
import argparse

from proof_provenance import ROOT, sha


ARCHIVE = ROOT / "target/macos/phase2/wp3-baseline"
SPEC_SHA256 = "f92bf25a4d8d6c94f83acca60383ff7b81fc04e0c5bd1ada20ec603df72d4454"
EVIDENCE = ROOT / "docs/macos/evidence"
EXPECTED_CYCLES = {"arithmetic-10m": 10_003_116, "hash-10m": 10_003_440}


def read(path):
    return json.loads(path.read_text())


def collect_fixture(fixture, campaign):
    run = Path(fixture["run"])
    result = read(run / "result.json")
    assert fixture["status"] == result["status"] == "passed"
    assert sha(run / "result.json") == fixture["result_sha256"]
    assert result["worker_build"]["binary_sha256"] == campaign["worker_sha256"]
    assert result["verifier_build"]["binary_sha256"] == campaign["verifier_sha256"]
    assert result["po2"] == 20 and result["segment_check_cpu"] is False
    assert result["results"]["verified_proofs"] == 6
    assert result["warmup_count"] == 1 and result["measured_repeats"] == 5
    assert result["program_sha256"] and result["input_sha256"]
    for host in (fixture["host_before"], fixture["host_after"]):
        assert sha(Path(host["path"])) == host["sha256"]
        assert not host["observation"]["background_process_present"]["brave"]
    rows = [json.loads(line) for line in
            (run / "acceptance/requests.jsonl").read_text().splitlines()]
    complete = [row for row in rows if row.get("status") == "complete_independently_verified"]
    assert len(complete) == 6
    assert [row["warmup"] for row in complete] == [True] + [False] * 5
    assert len({row["worker"]["worker_pid"] for row in complete}) == 1
    output = []
    for row in complete:
        worker = row["worker"]
        assert worker["stats"]["user_cycles"] == EXPECTED_CYCLES[fixture["fixture"]]
        assert worker["stats"]["segments"] == 10
        assert worker["rayon_threads"] == worker["gomaxprocs"] == 18
        verification = run / "acceptance" / row["case"] / "verification.json"
        v = read(verification)
        assert v["verification"] == "passed"
        assert set(v["negative_tests"]) == {
            "wrong_image", "modified_journal", "corrupt_seal"}
        memory = row["resources"]["idle_after_verification_and_settle"]["native_memory"]
        assert memory["reserve_bytes"] == 16 * 1024**3
        output.append({
            "fixture": fixture["fixture"], "case": row["case"], "warmup": row["warmup"],
            "complete_seconds": (row["timings"]["prove_call_ms"] +
                                 row["timings"]["external_verifier_ms"]) / 1000,
            "admission_wait_upper_bound_seconds": max(0.0,
                (row["resources"]["request_elapsed_ms"] -
                 row["timings"]["prove_call_ms"] -
                 row["timings"]["external_verifier_ms"]) / 1000),
            "guard_peak_footprint_bytes": memory["guard_peak_footprint_bytes"],
            "idle_worker_footprint_bytes": memory["group"]["worker"]["footprint_bytes"],
            "pressure_level": memory["pressure_level"],
            "worker_pid": worker["worker_pid"],
            "program_sha256": result["program_sha256"],
            "input_sha256": result["input_sha256"],
            "journal_sha256": worker["journal_sha256"],
            "seal_sha256": worker["seal_sha256"],
            "verification_sha256": sha(verification),
        })
    measured = [row["complete_seconds"] for row in output if not row["warmup"]]
    assert len(measured) == 5
    assert len({row["journal_sha256"] for row in output}) == 1
    return {"fixture": fixture["fixture"], "run": str(run),
            "result_sha256": sha(run / "result.json"),
            "request_ledger_sha256": sha(run / "acceptance/requests.jsonl"),
            "median_complete_seconds": median(measured),
            "range_complete_seconds": [min(measured), max(measured)],
            "max_measured_admission_wait_upper_bound_seconds": max(
                row["admission_wait_upper_bound_seconds"]
                for row in output if not row["warmup"]),
            "admission_wait_note": "standalone harness records total request elapsed, prove and verifier times; residual is a conservative upper bound including non-admission overhead",
            "max_guard_peak_footprint_bytes": max(
                row["guard_peak_footprint_bytes"] for row in output),
            "rows": output, "host_before": fixture["host_before"],
            "host_after": fixture["host_after"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run", type=Path)
    args = parser.parse_args()
    campaign = read(args.run / "result.json")
    assert campaign["status"] == "passed"
    assert campaign["source_spec_sha256"] == SPEC_SHA256
    manifest_path = ARCHIVE / "manifest.json"
    manifest = read(manifest_path)
    assert manifest["status"] == "sealed"
    assert sha(manifest_path) == campaign["baseline_manifest_sha256"]
    for name, digest in manifest["files"].items():
        assert sha(ARCHIVE / name) == digest
    assert manifest["files"]["zkminer-prove-risc0"] == campaign["worker_sha256"]
    assert manifest["files"]["hemi-macos-proof"] == campaign["verifier_sha256"]
    assert campaign["conditions"] == {
        "browser_closed": True, "host_reserve_gib": 16, "reserve_override": False,
        "initial_thermal": "nominal", "rayon_threads": 18, "go_threads": 18,
        "po2": 20, "warmups_per_fixture": 1, "measured_per_fixture": 5}
    assert (campaign["fixtures"][0]["host_before"]["observation"]
            ["thermal"]["thermal_state_name"] == "nominal")
    fixtures = [collect_fixture(row, campaign) for row in campaign["fixtures"]]
    assert [row["fixture"] for row in fixtures] == list(EXPECTED_CYCLES)
    report = {"schema_version": 1, "status": "complete",
              "source_spec_sha256": SPEC_SHA256,
              "scope": "sealed WP3 checkpoint absolute midpoint; browser closed, default 16 GiB reserve, nominal at start",
              "campaign_run": str(args.run),
              "campaign_result_sha256": sha(args.run / "result.json"),
              "baseline_manifest_sha256": campaign["baseline_manifest_sha256"],
              "worker_sha256": campaign["worker_sha256"],
              "verifier_sha256": campaign["verifier_sha256"],
              "engine_commit": campaign["engine_commit"],
              "driver_sha256": campaign["driver_sha256"],
              "acceptance_runner_sha256": campaign["acceptance_runner_sha256"],
              "collector_sha256": sha(Path(__file__)),
              "verified_proofs": 12, "tamper_rejections": 36,
              "midpoint_at_most_60_seconds_both": all(
                  row["median_complete_seconds"] <= 60 for row in fixtures),
              "fixtures": fixtures}
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    csv_path = EVIDENCE / "phase2-wp3-controlled-midpoint.csv"
    with csv_path.open("w", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=list(fixtures[0]["rows"][0]), lineterminator="\n")
        writer.writeheader()
        for fixture in fixtures:
            writer.writerows(fixture["rows"])
    report["csv_sha256"] = sha(csv_path)
    output = EVIDENCE / "phase2-wp3-controlled-midpoint.json"
    output.write_text(json.dumps(report, indent=2) + "\n")
    print(output)
    print(csv_path)


if __name__ == "__main__":
    main()
