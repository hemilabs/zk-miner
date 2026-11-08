#!/usr/bin/env python3
"""Validate and publish the WP0.5 five-pair latency campaign."""

import argparse
import csv
import json
from pathlib import Path
from statistics import median

from proof_provenance import ROOT, sha


ARCHIVE = ROOT / "target/macos/phase2/wp1-baseline"
EVIDENCE = ROOT / "docs/macos/evidence"
EXPECTED_CYCLES = {"arithmetic-10m": 10_003_116, "hash-10m": 10_003_440}
SPEC_SHA256 = "299ebd441aa2e1c0c70f7587a88b8cc32154d0835a0eaea0d807adef11028597"


def read(path):
    return json.loads(path.read_text())


def collect_case(case, campaign):
    run = Path(case["run"])
    assert case["status"] == "passed" and sha(run / "result.json") == case["result_sha256"]
    result = read(run / "result.json")
    assert result["status"] == "passed" and result["po2"] == 20
    assert result["paired_metal_baseline"]["sha256"] == campaign["baseline_worker_sha256"]
    assert result["worker_build"]["binary_sha256"] == campaign["candidate_worker_sha256"]
    assert result["verifier_build"]["binary_sha256"] == campaign["verifier_sha256"]
    assert result["bundle"] == read(ARCHIVE / "helper-manifest.json")
    assert result["program_sha256"] == result["worker_build"]["source"]["inputs"][
        "target/macos/guest-build/riscv32im-risc0-zkvm-elf/release/" +
        ("fibonacci.bin" if case["fixture"] == "arithmetic-10m" else "sha256-chain.bin")]
    rows = result["results"]["rows"]
    assert len(rows) == 12 and result["results"]["samples_per_case"] == 5
    assert result["results"]["settings"] == [[18, 18], [18, 18]]
    assert result["results"]["segment_cases"] == ["metal", "metal"]
    assert result["results"]["worker_binaries"] == [
        str(ARCHIVE / "zkminer-prove-risc0"),
        str(ROOT / "target/macos/worker-native-rv32im-metal/release/zkminer-prove-risc0")]
    for host in (case["host_before"], case["host_after"]):
        assert sha(Path(host["path"])) == host["sha256"]
        assert not host["observation"]["background_process_present"]["brave"]
    for pair in range(6):
        assert [row["case"] for row in rows[2 * pair:2 * pair + 2]] == (
            [0, 1] if pair % 2 == 0 else [1, 0])

    output = []
    for row in rows:
        arm = "wp1" if row["case"] == 0 else "wp05"
        worker = row["worker"]
        proof = run / "acceptance" / f"round-{row['round']}-case-{row['case']}"
        verification = read(proof / "verification.json")
        assert verification["verification"] == "passed"
        assert set(verification["negative_tests"]) == {
            "wrong_image", "modified_journal", "corrupt_seal"}
        assert worker["segment_hal"] == worker["recursion_hal"] == "metal"
        assert worker["elf_sha256"] == result["program_sha256"]
        assert worker["input_sha256"] == result["input_sha256"]
        assert worker["stats"]["user_cycles"] == EXPECTED_CYCLES[case["fixture"]]
        assert worker["stats"]["segments"] == 10
        rv = worker["observed_stages"]["rv32im_metal"]
        assert rv["threads_per_threadgroup"] == 256 and rv["evalfast_phase_split"]
        assert rv["gpu_kernels"]["segment/ef_eval_split"]["invalid_gpu_timestamps"] == 0
        assert rv["gpu_kernels"]["segment/ef_eval_split"]["commands"] == 10
        if arm == "wp05":
            assert 0 < rv["completed_command_buffers"] <= rv["completed_dispatches"]
        else:
            assert "completed_command_buffers" not in rv
        memory = row["resources"]["idle_after_verification_and_settle"]["native_memory"]
        assert memory["reserve_bytes"] == 16 * 1024**3
        assert row["rayon_threads"] == row["gomaxprocs"] == 18
        assert row["warmup"] == (row["round"] == 0)
        output.append({
            "fixture": case["fixture"], "round": row["round"], "arm": arm,
            "warmup": row["warmup"],
            "complete_seconds": (row["timings"]["prove_call_ms"] +
                                 row["timings"]["external_verifier_ms"]) / 1000,
            "admission_wait_seconds": row["admission_wait_ms"] / 1000,
            "segment_gpu_seconds": rv["gpu_kernels"]["segment/ef_eval_split"]["gpu_seconds"] / 10,
            "gpu_kernel_seconds": json.dumps({name: item["gpu_seconds"] for name, item in
                                               rv["gpu_kernels"].items()}, sort_keys=True),
            "completed_dispatches": rv["completed_dispatches"],
            "completed_command_buffers": rv.get("completed_command_buffers"),
            "worker_pid": worker["worker_pid"],
            "guard_peak_footprint_bytes": memory["guard_peak_footprint_bytes"],
            "idle_worker_footprint_bytes": memory["group"]["worker"]["footprint_bytes"],
            "pressure_level": memory["pressure_level"],
            "program_sha256": result["program_sha256"],
            "input_sha256": result["input_sha256"],
            "journal_sha256": worker["journal_sha256"],
            "seal_sha256": worker["seal_sha256"],
            "shader_sha256": rv["kernel_source_sha256"],
            "execution_and_segment_seconds": worker["stage_ms"]["execution_and_segment"] / 1000,
            "recursion_seconds": worker["stage_ms"]["recursion"] / 1000,
            "identity_and_wrap_seconds": worker["stage_ms"]["identity_and_wrap"] / 1000,
            "thermal": json.dumps(json.loads(row["thermal"]), sort_keys=True) if row["thermal"] else None,
            "worker_sidecar_sha256": sha(proof / "worker.json"),
            "verification_sha256": sha(proof / "verification.json"),
        })
    assert len({row["worker_pid"] for row in output if row["arm"] == "wp1"}) == 1
    assert len({row["worker_pid"] for row in output if row["arm"] == "wp05"}) == 1
    for pair in range(6):
        assert output[2 * pair]["completed_dispatches"] == output[2 * pair + 1]["completed_dispatches"]
    assert len({row["journal_sha256"] for row in output}) == 1
    assert len({row["shader_sha256"] for row in output}) == 1
    measured = [row for row in output if not row["warmup"]]
    assert len(measured) == 10
    times = {arm: [row["complete_seconds"] for row in measured if row["arm"] == arm]
             for arm in ("wp1", "wp05")}
    assert all(len(values) == 5 for values in times.values())
    pair_ratios = []
    for pair in range(1, 6):
        proof_pair = output[2 * pair:2 * pair + 2]
        by_arm = {row["arm"]: row["complete_seconds"] for row in proof_pair}
        pair_ratios.append(by_arm["wp1"] / by_arm["wp05"])
    return {
        "fixture": case["fixture"], "run": str(run),
        "result_sha256": sha(run / "result.json"),
        "request_ledger_sha256": sha(run / "acceptance/requests.jsonl"),
        "warmups": 2, "measured_proofs_per_arm": 5,
        "median_complete_seconds": {arm: median(values) for arm, values in times.items()},
        "range_complete_seconds": {arm: [min(values), max(values)] for arm, values in times.items()},
        "within_pair_baseline_to_candidate_ratios": pair_ratios,
        "max_admission_wait_seconds": max(row["admission_wait_seconds"] for row in output),
        "pressure_levels": sorted({row["pressure_level"] for row in output}),
        "median_complete_saving_seconds": median(times["wp1"]) - median(times["wp05"]),
        "saving_gate_passed": median(times["wp1"]) - median(times["wp05"]) >= 3,
        "rows": output, "host_before": case["host_before"], "host_after": case["host_after"],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run", type=Path)
    args = parser.parse_args()
    campaign = read(args.run / "result.json")
    assert campaign["status"] == "passed"
    manifest_path = ARCHIVE / "manifest.json"
    manifest = read(manifest_path)
    assert manifest["status"] == "sealed"
    assert sha(manifest_path) == campaign["baseline_manifest_sha256"]
    for name, digest in manifest["files"].items():
        assert sha(ARCHIVE / name) == digest
    assert manifest["files"]["zkminer-prove-risc0"] == campaign["baseline_worker_sha256"]
    assert manifest["files"]["hemi-macos-proof"] == campaign["verifier_sha256"]
    fixtures = [collect_case(case, campaign) for case in campaign["cases"]]
    assert [fixture["fixture"] for fixture in fixtures] == list(EXPECTED_CYCLES)
    report = {
        "schema_version": 1,
        "status": "passed" if all(f["saving_gate_passed"] for f in fixtures) else "latency_gate_failed",
        "scope": "five paired complete 10M proofs per fixture against the sealed WP1 worker; one excluded warmup per arm",
        "campaign_run": str(args.run), "campaign_result_sha256": sha(args.run / "result.json"),
        "source_spec_sha256": SPEC_SHA256,
        "baseline_manifest_sha256": campaign["baseline_manifest_sha256"],
        "baseline_worker_sha256": campaign["baseline_worker_sha256"],
        "candidate_worker_sha256": campaign["candidate_worker_sha256"],
        "verifier_sha256": campaign["verifier_sha256"],
        "engine_commit": campaign["engine_commit"], "miner_commit": campaign["miner_commit"],
        "driver_sha256": campaign["driver_sha256"],
        "acceptance_runner_sha256": campaign["acceptance_runner_sha256"],
        "collector_sha256": sha(Path(__file__)),
        "host_reserve_gib": 16, "browser_closed": True,
        "verified_proofs": 24, "tamper_rejections": 72,
        "fixtures": fixtures,
    }
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    json_path = EVIDENCE / "phase2-wp05-paired.json"
    csv_path = EVIDENCE / "phase2-wp05-paired.csv"
    with csv_path.open("w", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=list(fixtures[0]["rows"][0]), lineterminator="\n")
        writer.writeheader()
        for fixture in fixtures:
            writer.writerows(fixture["rows"])
    report["csv_sha256"] = sha(csv_path)
    json_path.write_text(json.dumps(report, indent=2) + "\n")
    print(json_path)
    print(csv_path)
    print(report["status"])


if __name__ == "__main__":
    main()
