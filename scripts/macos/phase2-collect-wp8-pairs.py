#!/usr/bin/env python3
"""Validate and collect WP8 paired proofs against the sealed Phase 2 worker."""

import argparse
import csv
import json
from pathlib import Path
from statistics import median

from proof_provenance import ROOT, sha


ARCHIVE = ROOT / "target/macos/phase2/post-diagnosis-final-checkpoint"
EVIDENCE = ROOT / "docs/macos/evidence"
SPEC = Path("/Users/dbur/Downloads/Phase 2 spec Metal proving performance on macOS.md")
FIXTURES = {
    "arithmetic-10m": (10_003_116, 10),
    "hash-10m": (10_003_440, 10),
    "arithmetic-46m": (46_003_116, 46),
}
ARMS = ("pre_wp8", "wp8_metal_identity")


def read(path):
    return json.loads(path.read_text())


def span(values):
    return {"median": median(values), "min": min(values), "max": max(values)}


def collect_case(case, campaign):
    run = Path(case["run"])
    assert case["status"] == "passed" and sha(run / "result.json") == case["result_sha256"]
    result = read(run / "result.json")
    assert result["status"] == "passed" and result["po2"] == 20
    assert result["paired_metal_baseline"]["sha256"] == campaign["baseline_worker_sha256"]
    assert result["worker_build"]["binary_sha256"] == campaign["candidate_worker_sha256"]
    assert result["verifier_build"]["binary_sha256"] == campaign["verifier_sha256"]
    assert result["results"]["samples_per_case"] == 5
    assert result["results"]["settings"] == [[18, 18], [18, 18]]
    assert result["results"]["segment_cases"] == ["metal", "metal"]
    assert result["results"]["worker_binaries"] == [
        str(ARCHIVE / "zkminer-prove-risc0"),
        str(ROOT / "target/macos/worker-native-rv32im-metal/release/zkminer-prove-risc0"),
    ]
    assert result["worker_build"]["source"]["engine_head"] == campaign["engine_commit"]
    assert sha(ROOT / "target/macos/native-wrap/assets/manifest.json") == campaign["helper_manifest_sha256"]
    rows = result["results"]["rows"]
    assert len(rows) == 12
    start_case = result["paired_start_case"]
    assert start_case == list(FIXTURES).index(case["fixture"]) % 2
    for round_index in range(6):
        assert [row["case"] for row in rows[2 * round_index:2 * round_index + 2]] == (
            [0, 1] if (round_index + start_case) % 2 == 0 else [1, 0]
        )
    for host in (case["host_before"], case["host_after"]):
        assert sha(Path(host["path"])) == host["sha256"]

    output = []
    expected_cycles, expected_segments = FIXTURES[case["fixture"]]
    for row in rows:
        arm = ARMS[row["case"]]
        worker = row["worker"]
        proof = run / "acceptance" / f"round-{row['round']}-case-{row['case']}"
        verification = read(proof / "verification.json")
        assert verification["verification"] == "passed"
        assert verification["negative_tests"] == [
            "wrong_image", "modified_journal", "corrupt_seal"]
        assert row["rayon_threads"] == row["gomaxprocs"] == 18
        assert row["warmup"] == (row["round"] == 0)
        assert worker["segment_hal"] == worker["recursion_hal"] == "metal"
        assert worker["stats"]["user_cycles"] == expected_cycles
        assert worker["stats"]["segments"] == expected_segments
        assert worker["po2"] == 20
        assert worker["elf_sha256"] == result["program_sha256"]
        assert worker["input_sha256"] == result["input_sha256"]
        assert worker["journal_hex"] == verification["journal_hex"]
        assert worker["observed_stages"]["identity"] == ("cpu" if row["case"] == 0 else "metal")
        rv32im = worker["observed_stages"]["rv32im_metal"]
        recursion = worker["observed_stages"]["recursion_metal"]
        segment_gpu_seconds = rv32im["gpu_kernels"]["segment/batch_rv32im_eval_check"]["gpu_seconds"] / expected_segments
        gpu_kernel_seconds = json.dumps({name: value["gpu_seconds"] for name, value in rv32im["gpu_kernels"].items()}, sort_keys=True)
        recursion_gpu_kernel_seconds = json.dumps({name: value["gpu_seconds"] for name, value in recursion["gpu_kernels"].items()}, sort_keys=True)
        if row["case"] == 0:
            assert "identity_p254" in worker["recursion_cpu_stages"]
            identity_gpu_seconds = None
            row_dispatches = None
            fold_dispatches = None
            identity_gpu_kernel_seconds = None
        else:
            assert "identity_p254" not in worker["recursion_cpu_stages"]
            identity = worker["observed_stages"]["identity_metal"]
            assert identity["completed_constraint_checks"] > 0
            kernels = identity["gpu_kernels"]
            identity_gpu_seconds = kernels["recursion/batch_merkle"]["gpu_seconds"]
            row_dispatches = kernels["recursion/poseidon254_rows"]["commands"]
            fold_dispatches = kernels["recursion/poseidon254_fold"]["commands"]
            assert identity_gpu_seconds > 0 and row_dispatches > 0 and fold_dispatches > 0
            identity_gpu_kernel_seconds = json.dumps({name: value["gpu_seconds"] for name, value in kernels.items()}, sort_keys=True)
        memory = row["resources"]["idle_after_verification_and_settle"]["native_memory"]
        assert memory["reserve_bytes"] == 8 * 1024**3
        output.append({
            "fixture": case["fixture"], "round": row["round"], "arm": arm,
            "warmup": row["warmup"], "worker_pid": worker["worker_pid"],
            "complete_seconds": (row["timings"]["prove_call_ms"] +
                                 row["timings"]["external_verifier_ms"]) / 1000,
            "execution_and_segment_seconds": worker["stage_ms"]["execution_and_segment"] / 1000,
            "recursion_seconds": worker["stage_ms"]["recursion"] / 1000,
            "identity_and_wrap_seconds": worker["stage_ms"]["identity_and_wrap"] / 1000,
            "identity_mode": worker["observed_stages"]["identity"],
            "identity_merkle_gpu_seconds": identity_gpu_seconds,
            "segment_gpu_seconds": segment_gpu_seconds,
            "gpu_kernel_seconds": gpu_kernel_seconds,
            "recursion_gpu_kernel_seconds": recursion_gpu_kernel_seconds,
            "identity_gpu_kernel_seconds": identity_gpu_kernel_seconds,
            "poseidon254_rows_dispatches": row_dispatches,
            "poseidon254_fold_dispatches": fold_dispatches,
            "admission_wait_seconds": row["admission_wait_ms"] / 1000,
            "guard_peak_footprint_bytes": memory["guard_peak_footprint_bytes"],
            "idle_worker_footprint_bytes": memory["group"]["worker"]["footprint_bytes"],
            "pressure_level": memory["pressure_level"],
            "program_sha256": result["program_sha256"],
            "input_sha256": result["input_sha256"],
            "image_id": verification["image_id"],
            "journal_sha256": worker["journal_sha256"],
            "seal_sha256": worker["seal_sha256"],
            "thermal": json.dumps(json.loads(row["thermal"]), sort_keys=True) if row["thermal"] else None,
            "worker_sidecar_sha256": sha(proof / "worker.json"),
            "verification_sha256": sha(proof / "verification.json"),
        })
    for arm in ARMS:
        assert len({row["worker_pid"] for row in output if row["arm"] == arm}) == 1
    assert len({row["journal_sha256"] for row in output}) == 1
    measured = [row for row in output if not row["warmup"]]
    assert len(measured) == 10
    grouped = {arm: [row for row in measured if row["arm"] == arm] for arm in ARMS}
    assert all(len(grouped[arm]) == 5 for arm in ARMS)
    ratios = []
    for round_index in range(1, 6):
        pair = {row["arm"]: row["complete_seconds"] for row in output[2 * round_index:2 * round_index + 2]}
        ratios.append(pair[ARMS[0]] / pair[ARMS[1]])
    complete = {arm: span([row["complete_seconds"] for row in grouped[arm]]) for arm in ARMS}
    return {
        "fixture": case["fixture"], "run": str(run),
        "result_sha256": sha(run / "result.json"),
        "request_ledger_sha256": sha(run / "acceptance/requests.jsonl"),
        "warmups": 2, "measured_proofs_per_arm": 5,
        "complete_seconds": complete,
        "median_complete_saving_seconds": complete[ARMS[0]]["median"] - complete[ARMS[1]]["median"],
        "within_pair_baseline_to_candidate_ratios": ratios,
        "identity_and_wrap_seconds": {arm: span([row["identity_and_wrap_seconds"] for row in grouped[arm]]) for arm in ARMS},
        "candidate_identity_merkle_gpu_seconds": span([row["identity_merkle_gpu_seconds"] for row in grouped[ARMS[1]]]),
        "pressure_levels": sorted({row["pressure_level"] for row in output}),
        "max_guard_peak_footprint_bytes": max(row["guard_peak_footprint_bytes"] for row in output),
        "host_before": case["host_before"], "host_after": case["host_after"],
        "rows": output,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run", type=Path)
    args = parser.parse_args()
    campaign = read(args.run / "result.json")
    assert campaign["status"] == "passed"
    manifest = read(ARCHIVE / "manifest.json")
    assert manifest["status"] == "sealed"
    assert sha(ARCHIVE / "manifest.json") == campaign["baseline_manifest_sha256"]
    for name, digest in manifest["files"].items():
        assert sha(ARCHIVE / name) == digest
    assert manifest["files"]["zkminer-prove-risc0"] == campaign["baseline_worker_sha256"]
    assert manifest["files"]["hemi-macos-proof"] == campaign["verifier_sha256"]
    candidate_manifest = read(ROOT / "target/macos/worker-native-rv32im-metal-build.json")
    assert candidate_manifest["binary_sha256"] == campaign["candidate_worker_sha256"]
    fixtures = [collect_case(case, campaign) for case in campaign["cases"]]
    assert [item["fixture"] for item in fixtures] == list(FIXTURES)
    harness_hashes = {
        read(Path(case["run"]) / "acceptance-build.json")["source_inputs"][
            "crates/zkminer-prover/tests/macos_worker.rs"]
        for case in campaign["cases"]
    }
    assert len(harness_hashes) == 1
    report = {
        "schema_version": 1, "status": "complete",
        "scope": "sealed pre-WP8 versus WP8, one warmup and five alternating pairs per arm per fixture",
        "campaign_run": str(args.run), "campaign_result_sha256": sha(args.run / "result.json"),
        "spec_sha256": sha(SPEC), "baseline_manifest_sha256": campaign["baseline_manifest_sha256"],
        "baseline_worker_sha256": campaign["baseline_worker_sha256"],
        "candidate_worker_sha256": campaign["candidate_worker_sha256"],
        "candidate_worker_manifest_sha256": sha(ROOT / "target/macos/worker-native-rv32im-metal-build.json"),
        "verifier_sha256": campaign["verifier_sha256"],
        "helper_manifest_sha256": campaign["helper_manifest_sha256"],
        "engine_sha": campaign["engine_commit"], "miner_code_sha": campaign["miner_commit"],
        "driver_sha256": campaign["driver_sha256"], "collector_sha256": sha(Path(__file__)),
        "paired_harness_sha256": harness_hashes.pop(),
        "default_reserve_gib": 8, "verified_proofs": 36, "tamper_rejections": 108,
        "all_peaks_below_32_gib": all(f["max_guard_peak_footprint_bytes"] < 32 * 1024**3 for f in fixtures),
        "fixtures": fixtures,
    }
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    csv_path = EVIDENCE / "phase2-wp8-paired.csv"
    with csv_path.open("w", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=list(fixtures[0]["rows"][0]), lineterminator="\n")
        writer.writeheader()
        for fixture in fixtures:
            writer.writerows(fixture["rows"])
    report["csv_sha256"] = sha(csv_path)
    json_path = EVIDENCE / "phase2-wp8-paired.json"
    json_path.write_text(json.dumps(report, indent=2) + "\n")
    print(json_path)
    print(csv_path)


if __name__ == "__main__":
    main()
