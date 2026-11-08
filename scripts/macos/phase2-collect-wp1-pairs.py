#!/usr/bin/env python3
"""Verify WP1 five-pair proofs and publish the paired gate evidence."""

import argparse
import csv
import json
from pathlib import Path
from statistics import median

from proof_provenance import ROOT, sha


EVIDENCE = ROOT / "docs/macos/evidence"
EXPECTED_CYCLES = {"arithmetic-10m": 10_003_116, "hash-10m": 10_003_440}


def read(path):
    return json.loads(path.read_text())


def collect_case(case, campaign, baseline, candidate_shader, wp0_profile):
    run = Path(case["run"])
    assert case["status"] == "passed" and sha(run / "result.json") == case["result_sha256"]
    result = read(run / "result.json")
    assert result["status"] == "passed" and result["po2"] == 20
    assert result["paired_metal_baseline"]["sha256"] == baseline["worker"]["binary_sha256"]
    assert result["worker_build"]["binary_sha256"] == campaign["candidate_worker_sha256"]
    assert result["verifier_build"]["binary_sha256"] == campaign["verifier_sha256"]
    assert result["bundle"] == read(ROOT / "target/macos/phase2/baseline/helper-manifest.json")
    assert result["program_sha256"] == baseline["worker"]["source"]["inputs"][
        "target/macos/guest-build/riscv32im-risc0-zkvm-elf/release/" +
        ("fibonacci.bin" if case["fixture"] == "arithmetic-10m" else "sha256-chain.bin")]
    rows = result["results"]["rows"]
    assert len(rows) == 12 and result["results"]["samples_per_case"] == 5
    assert result["results"]["settings"] == [[18, 18], [18, 18]]
    assert result["results"]["segment_cases"] == ["metal", "metal"]
    assert result["results"]["worker_binaries"] == [
        str(ROOT / "target/macos/phase2/baseline/zkminer-prove-risc0"),
        str(ROOT / "target/macos/worker-native-rv32im-metal/release/zkminer-prove-risc0")]
    assert all(not host["observation"]["background_process_present"]["brave"]
               for host in (case["host_before"], case["host_after"]))
    for host in (case["host_before"], case["host_after"]):
        assert sha(Path(host["path"])) == host["sha256"]
    output = []
    for round in range(6):
        expected_order = [0, 1] if round % 2 == 0 else [1, 0]
        assert [row["case"] for row in rows[2 * round:2 * round + 2]] == expected_order
    for row in rows:
        arm = "wp0" if row["case"] == 0 else "evalfast"
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
        assert rv["threads_per_threadgroup"] == (32 if arm == "wp0" else 256)
        if arm == "evalfast":
            assert rv["evalfast_phase_split"] and rv["kernel_source_sha256"] == candidate_shader
            split = rv["gpu_kernels"]["segment/ef_eval_split"]
            assert split["commands"] == 10 and split["invalid_gpu_timestamps"] == 0
            segment_gpu = split["gpu_seconds"] / 10
        else:
            assert not rv.get("evalfast_phase_split", False)
            # The sealed WP0 worker predates per-kernel timestamps. Use its
            # separately verified profile as a labelled fixture reference.
            segment_gpu = wp0_profile["kernels"]["constraint_evaluation/eval_check"]["gpu_seconds"] / 10
        gpu_kernels = ({name: item["gpu_seconds"] for name, item in
                        wp0_profile["kernels"].items()} if arm == "wp0" else
                       {name: item["gpu_seconds"] for name, item in
                        rv["gpu_kernels"].items()})
        assert gpu_kernels and segment_gpu > 0
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
            "segment_gpu_seconds": segment_gpu,
            "gpu_kernel_seconds": json.dumps(gpu_kernels, sort_keys=True),
            "gpu_measurement_source": "wp0_profile_reference" if arm == "wp0" else "paired_sidecar",
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
    assert len({row["worker_pid"] for row in output if row["arm"] == "wp0"}) == 1
    assert len({row["worker_pid"] for row in output if row["arm"] == "evalfast"}) == 1
    assert len({row["journal_sha256"] for row in output}) == 1
    measured = [row for row in output if not row["warmup"]]
    assert len(measured) == 10
    times = {arm: [row["complete_seconds"] for row in measured if row["arm"] == arm]
             for arm in ("wp0", "evalfast")}
    assert all(len(values) == 5 for values in times.values())
    paired = []
    for round in range(1, 6):
        base = next(row for row in measured if row["round"] == round and row["arm"] == "wp0")
        fast = next(row for row in measured if row["round"] == round and row["arm"] == "evalfast")
        paired.append({"round": round, "wp0_seconds": base["complete_seconds"],
                       "evalfast_seconds": fast["complete_seconds"],
                       "ratio": base["complete_seconds"] / fast["complete_seconds"]})
    gpu = [row["segment_gpu_seconds"] for row in measured if row["arm"] == "evalfast"]
    return {
        "fixture": case["fixture"], "run": str(run),
        "result_sha256": sha(run / "result.json"),
        "request_ledger_sha256": sha(run / "acceptance/requests.jsonl"),
        "warmups": 2, "measured_proofs_per_arm": 5,
        "median_complete_seconds": {arm: median(values) for arm, values in times.items()},
        "range_complete_seconds": {arm: [min(values), max(values)] for arm, values in times.items()},
        "median_complete_saving_seconds": median(times["wp0"]) - median(times["evalfast"]),
        "paired_ratios": paired,
        "evalfast_segment_gpu_median_seconds": median(gpu),
        "evalfast_segment_gpu_max_seconds": max(gpu),
        "saving_gate_passed": median(times["wp0"]) - median(times["evalfast"]) >= 25,
        "segment_gate_passed": median(gpu) <= 2.0,
        "rows": output,
        "host_before": case["host_before"], "host_after": case["host_after"],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run", type=Path)
    args = parser.parse_args()
    campaign = read(args.run / "result.json")
    assert campaign["status"] == "passed"
    baseline_path = ROOT / "target/macos/phase2/baseline/manifest.json"
    baseline = read(baseline_path)
    assert sha(baseline_path) == campaign["baseline_manifest_sha256"]
    for name, digest in baseline["files"].items():
        assert sha(baseline_path.parent / name) == digest
    prior = read(EVIDENCE / "phase2-wp1-evalfast.json")
    assert prior["worker_sha256"] == campaign["candidate_worker_sha256"]
    assert prior["engine_commit"] == campaign["engine_commit"]
    assert len(campaign["cases"]) == 2
    wp0_profile = read(EVIDENCE / "phase2-wp0-gpu-profile.json")
    assert wp0_profile["status"] == "measured"
    profiles = {profile["fixture"]: profile for profile in wp0_profile["profiles"]}
    fixtures = [collect_case(case, campaign, baseline, prior["shader_sha256"],
                             profiles[case["fixture"]]) for case in campaign["cases"]]
    assert [f["fixture"] for f in fixtures] == list(EXPECTED_CYCLES)
    report = {
        "schema_version": 1, "status": "passed" if all(
            f["saving_gate_passed"] and f["segment_gate_passed"] for f in fixtures) else "gate_failed",
        "scope": "five paired complete 10M proofs per fixture against the sealed WP0 archive; one warmup per arm",
        "campaign_run": str(args.run), "campaign_result_sha256": sha(args.run / "result.json"),
        "source_spec_sha256": "22c73353915de7154577858ab4556d6d52fc6af3f463b3e6b2009f3ec5c707b7",
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
        "hashing_rebaseline_note": "The WP0 hashing median here used a closed browser and the default 16 GiB reserve in the same paired campaign; it replaces the non-comparable Brave-open 12 GiB historical median.",
        "limitation": "The sealed WP0 worker does not emit per-kernel GPU timestamps in its proof sidecar. WP0 GPU values are fixture-level references from a separate verified, instrumented proof (worker SHA differs from the sealed archive); they are repeated on its five paired rows. Evalfast values come from each paired sidecar. GPU columns must not be treated as paired GPU measurements.",
    }
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    json_path = EVIDENCE / "phase2-wp1-paired.json"
    csv_path = EVIDENCE / "phase2-wp1-paired.csv"
    json_path.write_text(json.dumps(report, indent=2) + "\n")
    columns = list(fixtures[0]["rows"][0])
    with csv_path.open("w", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=columns, lineterminator="\n")
        writer.writeheader()
        for fixture in fixtures:
            writer.writerows(fixture["rows"])
    print(json_path)
    print(csv_path)
    print(report["status"])


if __name__ == "__main__":
    main()
