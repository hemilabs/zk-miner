#!/usr/bin/env python3
"""Seal the browser-closed WP8 46M absolute reading into evidence JSON and CSV."""

import argparse
import csv
import json
from pathlib import Path
from statistics import median

from proof_provenance import ROOT, sha


EVIDENCE = ROOT / "docs/macos/evidence"
SPEC = Path("/Users/dbur/Downloads/Phase 2 spec Metal proving performance on macOS.md")


def read(path):
    return json.loads(path.read_text())


def span(values):
    return {"median": median(values), "min": min(values), "max": max(values)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run", type=Path)
    parser.add_argument("--failed-preflight", type=Path, action="append", default=[])
    args = parser.parse_args()
    source = args.run / "result.json"
    raw = read(source)
    assert raw["status"] == "passed"
    assert raw["spec_sha256"] == sha(SPEC)
    assert raw["idle_gap_seconds"] >= 900
    assert raw["conditions"]["browser_closed"]
    assert raw["conditions"]["default_reserve_gib"] == 8
    assert raw["conditions"]["warmup_per_fixture"] == 1
    assert raw["conditions"]["measured_per_fixture"] == 5
    assert raw["host_start"]["observation"]["thermal"]["thermal_state_name"] == "nominal"
    for host in (raw["host_start"], raw["host_end"]):
        assert sha(Path(host["path"])) == host["sha256"]
        assert not host["observation"]["background_process_present"]["brave"]

    rows = []
    fixtures = []
    for fixture in raw["fixtures"]:
        assert fixture["status"] == "passed" and fixture["run_status"] == "passed"
        assert len(fixture["proofs"]) == 6
        for proof in fixture["proofs"]:
            assert proof["excluded_warmup"] == (proof["index"] == 0)
            assert proof["identity_seconds"] > 0 and proof["identity_constraint_checks"] > 0
            assert proof["poseidon254_rows_dispatches"] > 0
            assert proof["poseidon254_fold_dispatches"] > 0
            for item in ("timing", "worker", "resource", "verification"):
                assert sha(Path(proof[f"{item}_path"])) == proof[f"{item}_sha256"]
            timing = read(Path(proof["timing_path"]))
            worker = read(Path(proof["worker_path"]))
            verification = read(Path(proof["verification_path"]))
            assert verification["verification"] == "passed"
            assert verification["negative_tests"] == [
                "wrong_image", "modified_journal", "corrupt_seal"]
            assert worker["observed_stages"]["identity"] == "metal"
            assert worker["observed_stages"]["identity_metal"]["completed_constraint_checks"] > 0
            rv32im_kernels = worker["observed_stages"]["rv32im_metal"]["gpu_kernels"]
            recursion_kernels = worker["observed_stages"]["recursion_metal"]["gpu_kernels"]
            identity_kernels = worker["observed_stages"]["identity_metal"]["gpu_kernels"]
            rows.append({
                "fixture": fixture["fixture"], "index": proof["index"],
                "excluded_warmup": proof["excluded_warmup"],
                "identity_seconds": proof["identity_seconds"],
                "complete_seconds": (timing["prove_call_ms"] + timing["external_verifier_ms"]) / 1000,
                "external_verifier_seconds": timing["external_verifier_ms"] / 1000,
                "execution_and_segment_seconds": worker["stage_ms"]["execution_and_segment"] / 1000,
                "recursion_seconds": worker["stage_ms"]["recursion"] / 1000,
                "identity_and_wrap_seconds": worker["stage_ms"]["identity_and_wrap"] / 1000,
                "identity_merkle_gpu_seconds": proof["identity_merkle_gpu_seconds"],
                "segment_gpu_seconds": rv32im_kernels["segment/batch_rv32im_eval_check"]["gpu_seconds"] / worker["stats"]["segments"],
                "gpu_kernel_seconds": json.dumps({name: value["gpu_seconds"] for name, value in rv32im_kernels.items()}, sort_keys=True),
                "recursion_gpu_kernel_seconds": json.dumps({name: value["gpu_seconds"] for name, value in recursion_kernels.items()}, sort_keys=True),
                "identity_gpu_kernel_seconds": json.dumps({name: value["gpu_seconds"] for name, value in identity_kernels.items()}, sort_keys=True),
                "poseidon254_rows_dispatches": proof["poseidon254_rows_dispatches"],
                "poseidon254_fold_dispatches": proof["poseidon254_fold_dispatches"],
                "peak_owned_footprint_bytes": proof["peak_owned_footprint_bytes"],
                "idle_owned_footprint_bytes": proof["idle_owned_footprint_bytes"],
                "pressure_levels_seen": json.dumps(proof["pressure_levels_seen"]),
                "program_sha256": worker["elf_sha256"],
                "input_sha256": worker["input_sha256"],
                "journal_sha256": worker["journal_sha256"],
                "seal_sha256": worker["seal_sha256"],
                "worker_sidecar_sha256": proof["worker_sha256"],
                "verification_sha256": proof["verification_sha256"],
            })
        measured = [row for row in rows if row["fixture"] == fixture["fixture"] and not row["excluded_warmup"]]
        assert len(measured) == 5
        fixtures.append({
            "fixture": fixture["fixture"], "run_path": fixture["run_path"],
            "identity_seconds": span([row["identity_seconds"] for row in measured]),
            "complete_seconds": span([row["complete_seconds"] for row in measured]),
            "identity_merkle_gpu_seconds": span([row["identity_merkle_gpu_seconds"] for row in measured]),
            "identity_gate_le_4_seconds": median(row["identity_seconds"] for row in measured) <= 4,
            "verified_proofs": 6, "tamper_rejections": 18,
        })
    assert len(fixtures) == 1 and fixtures[0]["fixture"] == "arithmetic-46m"
    assert len(rows) == 6
    verifier = read(ROOT / "target/macos/verifier-build.json")
    failed_preflights = []
    for path in args.failed_preflight:
        result = path / "result.json"
        failure = read(result)
        assert failure["status"] == "failed" and not failure["fixtures"]
        failed_preflights.append({"path": str(path.resolve()),
                                  "result_sha256": sha(result),
                                  "error": failure["error"]})
    report = {
        "schema_version": 1, "status": "complete", "gate_passed": all(f["complete_seconds"]["median"] <= 180 for f in fixtures),
        "scope": "browser-closed absolute WP8 46M reading; one excluded warmup and five measured proofs",
        "raw_run": str(args.run.resolve()), "raw_result_sha256": sha(source),
        "spec_sha256": raw["spec_sha256"], "engine_sha": raw["engine_sha"],
        "worker_sha256": raw["worker_sha256"],
        "worker_manifest_sha256": raw["worker_manifest_sha256"],
        "verifier_sha256": verifier["binary_sha256"],
        "helper_manifest_sha256": sha(ROOT / "target/macos/native-wrap/assets/manifest.json"),
        "reading_driver_sha256": sha(ROOT / "scripts/macos/phase2-run-wp8-final-46m.py"),
        "collector_sha256": sha(Path(__file__)),
        "acceptance_build_sha256": raw["acceptance_build_sha256"],
        "conditions": raw["conditions"], "idle_since_utc": raw["idle_since_utc"],
        "idle_gap_seconds": raw["idle_gap_seconds"],
        "host_start": raw["host_start"], "host_end": raw["host_end"],
        "failed_preflights": failed_preflights,
        "verified_proofs": 6, "tamper_rejections": 18,
        "fixtures": fixtures,
    }
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    csv_path = EVIDENCE / "phase2-wp8-final-46m-controlled.csv"
    with csv_path.open("w", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=list(rows[0]), lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
    report["csv_sha256"] = sha(csv_path)
    json_path = EVIDENCE / "phase2-wp8-final-46m-controlled.json"
    json_path.write_text(json.dumps(report, indent=2) + "\n")
    print(json_path)
    print(csv_path)


if __name__ == "__main__":
    main()
