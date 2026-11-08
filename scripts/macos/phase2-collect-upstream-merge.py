#!/usr/bin/env python3
"""Validate the sealed upstream-merged checkpoint's controlled absolute reading."""

import argparse
import csv
import json
from pathlib import Path
from statistics import median

from proof_provenance import ROOT, sha


ARCHIVE = ROOT / "target/macos/phase2/upstream-merge-checkpoint"
EVIDENCE = ROOT / "docs/macos/evidence"
SPEC_SHA256 = "ecd565ffba5582c00c1191d8a427cd5bb48d90440b21b8d0423735e9e7847031"
EXPECTED_CYCLES = {"arithmetic-10m": 10_003_116, "hash-10m": 10_003_440,
                   "arithmetic-46m": 46_003_116}
EXPECTED_SEGMENTS = {"arithmetic-10m": 10, "hash-10m": 10,
                     "arithmetic-46m": 46}


def read(path):
    return json.loads(path.read_text())


def collect_fixture(fixture, campaign):
    run = Path(fixture["run"])
    result = read(run / "result.json")
    assert fixture["status"] == result["status"] == "passed"
    assert sha(run / "result.json") == fixture["result_sha256"]
    assert result["worker_build"]["binary_sha256"] == campaign["worker_sha256"]
    assert result["verifier_build"]["binary_sha256"] == campaign["verifier_sha256"]
    assert result["bundle"] == read(ARCHIVE / "helper-manifest.json")
    assert result["po2"] == 20 and result["segment_check_cpu"] is False
    assert result["results"]["verified_proofs"] == 6
    assert result["warmup_count"] == 1 and result["measured_repeats"] == 5
    assert result["program_sha256"] and result["input_sha256"]
    assert result["worker_build"]["source"]["engine_head"] == campaign["engine_commit"]
    for host in (fixture["host_before"], fixture["host_after"]):
        assert sha(Path(host["path"])) == host["sha256"]
        assert not host["observation"]["background_process_present"]["brave"]
    ledger = [json.loads(line) for line in
              (run / "acceptance/requests.jsonl").read_text().splitlines()]
    complete = [row for row in ledger if row.get("status") == "complete_independently_verified"]
    assert len(complete) == 6
    assert [row["warmup"] for row in complete] == [True] + [False] * 5
    assert len({row["worker"]["worker_pid"] for row in complete}) == 1
    output = []
    for row in complete:
        worker = row["worker"]
        assert worker["stats"]["user_cycles"] == EXPECTED_CYCLES[fixture["fixture"]]
        assert worker["stats"]["segments"] == EXPECTED_SEGMENTS[fixture["fixture"]]
        assert worker["rayon_threads"] == worker["gomaxprocs"] == 18
        assert worker["segment_hal"] == worker["recursion_hal"] == "metal"
        assert worker["elf_sha256"] == result["program_sha256"]
        assert worker["input_sha256"] == result["input_sha256"]
        proof = run / "acceptance" / row["case"]
        verification = proof / "verification.json"
        accepted = read(verification)
        assert accepted["verification"] == "passed"
        assert set(accepted["negative_tests"]) == {
            "wrong_image", "modified_journal", "corrupt_seal"}
        memory = row["resources"]["idle_after_verification_and_settle"]["native_memory"]
        assert memory["reserve_bytes"] == 8 * 1024**3
        rv = worker["observed_stages"]["rv32im_metal"]
        recursion = worker["observed_stages"]["recursion_metal"]
        assert rv["completed_constraint_checks"] > 0
        assert recursion["completed_constraint_checks"] > 0
        output.append({
            "fixture": fixture["fixture"], "case": row["case"], "warmup": row["warmup"],
            "complete_seconds": (row["timings"]["prove_call_ms"] +
                                 row["timings"]["external_verifier_ms"]) / 1000,
            "prove_call_seconds": row["timings"]["prove_call_ms"] / 1000,
            "external_verifier_seconds": row["timings"]["external_verifier_ms"] / 1000,
            "admission_wait_upper_bound_seconds": max(0.0,
                (row["resources"]["request_elapsed_ms"] -
                 row["timings"]["prove_call_ms"] -
                 row["timings"]["external_verifier_ms"]) / 1000),
            "execution_and_segment_seconds": worker["stage_ms"]["execution_and_segment"] / 1000,
            "recursion_seconds": worker["stage_ms"]["recursion"] / 1000,
            "identity_and_wrap_seconds": worker["stage_ms"]["identity_and_wrap"] / 1000,
            "segment_gpu_kernel_seconds": json.dumps({
                name: item["gpu_seconds"] for name, item in rv["gpu_kernels"].items()},
                sort_keys=True),
            "recursion_gpu_kernel_seconds": json.dumps({
                name: item["gpu_seconds"] for name, item in recursion["gpu_kernels"].items()},
                sort_keys=True),
            "guard_peak_footprint_bytes": memory["guard_peak_footprint_bytes"],
            "idle_worker_footprint_bytes": memory["group"]["worker"]["footprint_bytes"],
            "pressure_level": memory["pressure_level"],
            "worker_pid": worker["worker_pid"],
            "program_sha256": result["program_sha256"],
            "input_sha256": result["input_sha256"],
            "image_id": worker["image_id"],
            "journal_sha256": worker["journal_sha256"],
            "seal_sha256": worker["seal_sha256"],
            "worker_sidecar_sha256": sha(proof / "worker.json"),
            "verification_sha256": sha(verification),
        })
    measured = [row for row in output if not row["warmup"]]
    assert len(measured) == 5
    assert len({row["journal_sha256"] for row in output}) == 1
    times = [row["complete_seconds"] for row in measured]
    return {
        "fixture": fixture["fixture"], "run": str(run),
        "result_sha256": sha(run / "result.json"),
        "request_ledger_sha256": sha(run / "acceptance/requests.jsonl"),
        "median_complete_seconds": median(times),
        "range_complete_seconds": [min(times), max(times)],
        "measured_complete_seconds": times,
        "median_stage_seconds": {name: median(row[name] for row in measured)
                                 for name in ("execution_and_segment_seconds",
                                              "recursion_seconds", "identity_and_wrap_seconds")},
        "max_measured_admission_wait_upper_bound_seconds": max(
            row["admission_wait_upper_bound_seconds"] for row in measured),
        "admission_wait_note": "standalone harness records total request elapsed, prove and verifier times; residual is a conservative upper bound including non-admission overhead",
        "max_guard_peak_footprint_bytes": max(row["guard_peak_footprint_bytes"] for row in output),
        "pressure_levels": sorted({row["pressure_level"] for row in output}),
        "rows": output, "host_before": fixture["host_before"],
        "host_after": fixture["host_after"],
    }


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
    assert sha(manifest_path) == campaign["checkpoint_manifest_sha256"]
    for name, digest in manifest["files"].items():
        assert sha(ARCHIVE / name) == digest
    assert manifest["files"]["zkminer-prove-risc0"] == campaign["worker_sha256"]
    assert manifest["files"]["hemi-macos-proof"] == campaign["verifier_sha256"]
    assert manifest["files"]["helper-manifest.json"] == campaign["helper_manifest_sha256"]
    assert campaign["conditions"] == {
        "browser_closed": True, "host_reserve_gib": 8, "reserve_override": False,
        "initial_thermal": "nominal", "rayon_threads": 18, "go_threads": 18,
        "po2": 20, "segment_pipeline": True,
        "warmups_per_fixture": 1, "measured_per_fixture": 5}
    assert (campaign["fixtures"][0]["host_before"]["observation"]
            ["thermal"]["thermal_state_name"] == "nominal")
    fixtures = [collect_fixture(row, campaign) for row in campaign["fixtures"]]
    assert [row["fixture"] for row in fixtures] == list(EXPECTED_CYCLES)
    baseline_path = EVIDENCE / "phase2-controlled-final.json"
    baseline = read(baseline_path)
    assert baseline["status"] == "complete"
    old = {row["fixture"]: row for row in baseline["fixtures"]}
    medians = {row["fixture"]: row["median_complete_seconds"] for row in fixtures}
    comparison = {name: {
        "baseline_median_seconds": old[name]["median_complete_seconds"],
        "baseline_range_seconds": old[name]["range_complete_seconds"],
        "merged_median_seconds": value,
        "delta_seconds": value - old[name]["median_complete_seconds"],
        "beyond_baseline_measured_range": value > old[name]["range_complete_seconds"][1],
    } for name, value in medians.items()}
    report = {
        "schema_version": 1, "status": "complete",
        "scope": "sealed upstream-merged worker controlled reading; browser closed, default 8 GiB reserve, nominal at start",
        "source_spec_sha256": SPEC_SHA256,
        "campaign_run": str(args.run),
        "campaign_result_sha256": sha(args.run / "result.json"),
        "checkpoint_manifest_sha256": campaign["checkpoint_manifest_sha256"],
        "worker_sha256": campaign["worker_sha256"],
        "verifier_sha256": campaign["verifier_sha256"],
        "helper_manifest_sha256": campaign["helper_manifest_sha256"],
        "engine_commit": campaign["engine_commit"],
        "miner_checkpoint_commit": campaign["miner_checkpoint_commit"],
        "driver_sha256": campaign["driver_sha256"],
        "acceptance_runner_sha256": campaign["acceptance_runner_sha256"],
        "collector_sha256": sha(Path(__file__)),
        "baseline_evidence_sha256": sha(baseline_path),
        "comparison": comparison,
        "regression_beyond_prior_measured_range": any(
            item["beyond_baseline_measured_range"] for item in comparison.values()),
        "verified_proofs": 18, "tamper_rejections": 54,
        "minimum_line_met": medians["arithmetic-10m"] <= 55 and
                            medians["hash-10m"] <= 55 and
                            medians["arithmetic-46m"] <= 220,
        "desirable_line_met": medians["arithmetic-10m"] <= 45 and
                              medians["hash-10m"] <= 45 and
                              medians["arithmetic-46m"] <= 180,
        "all_peaks_below_32_gib": all(row["max_guard_peak_footprint_bytes"] < 32 * 1024**3
                                      for row in fixtures),
        "normal_pressure_all_rows": all(row["pressure_levels"] == [1] for row in fixtures),
        "fixtures": fixtures,
    }
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    csv_path = EVIDENCE / "phase2-upstream-merge-controlled.csv"
    with csv_path.open("w", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=list(fixtures[0]["rows"][0]), lineterminator="\n")
        writer.writeheader()
        for fixture in fixtures:
            writer.writerows(fixture["rows"])
    report["csv_sha256"] = sha(csv_path)
    output = EVIDENCE / "phase2-upstream-merge-controlled.json"
    output.write_text(json.dumps(report, indent=2) + "\n")
    print(output)
    print(csv_path)


if __name__ == "__main__":
    main()
