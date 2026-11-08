#!/usr/bin/env python3
"""Collect the sealed Phase 2 starting worker's fixed warm campaigns."""

import argparse
import csv
import json
from pathlib import Path
import statistics

from proof_provenance import ROOT, sha


def read(path):
    return json.loads(path.read_text())


def collect(name, directory, expected_count, archive):
    result = read(directory / "result.json")
    assert result["status"] == "passed", (name, result.get("error"))
    assert result["worker_build"] == archive["worker"]
    assert result["verifier_build"] == archive["verifier"]
    assert result["results"]["verified_proofs"] == expected_count
    raw_rows = [json.loads(line) for line in (directory / "acceptance/requests.jsonl").read_text().splitlines()]
    assert len(raw_rows) == 2 * expected_count
    rows = [row for row in raw_rows if row["status"] == "complete_independently_verified"]
    assert len(rows) == expected_count
    assert sum(bool(row["warmup"]) for row in rows) == (1 if expected_count == 6 else 0)
    assert len({row["worker"]["worker_pid"] for row in rows}) == 1
    output = []
    for index, row in enumerate(rows):
        proof = directory / "acceptance" / f"proof-{index}"
        verification = read(proof / "verification.json")
        assert verification["verification"] == "passed"
        assert set(verification["negative_tests"]) == {"wrong_image", "modified_journal", "corrupt_seal"}
        worker = row["worker"]
        assert worker["segment_hal"] == worker["recursion_hal"] == "metal"
        assert worker["elf_sha256"] == result["program_sha256"]
        assert worker["input_sha256"] == result["input_sha256"]
        seconds = (row["timings"]["prove_call_ms"] + row["timings"]["external_verifier_ms"]) / 1000
        final = row["resources"]["idle_after_verification_and_settle"]["native_memory"]
        output.append({
            "fixture": name, "proof": index, "warmup": bool(row["warmup"]),
            "complete_seconds": seconds, "guest_cycles": worker["stats"]["user_cycles"],
            "segments": worker["stats"]["segments"], "image_id": worker["image_id"],
            "program_sha256": result["program_sha256"], "input_sha256": result["input_sha256"],
            "journal_sha256": worker["journal_sha256"], "seal_sha256": worker["seal_sha256"],
            "worker_sidecar_sha256": sha(proof / "worker.json"),
            "verification_sha256": sha(proof / "verification.json"),
            "guard_peak_footprint_bytes": final["guard_peak_footprint_bytes"],
            "idle_worker_footprint_bytes": final["group"]["worker"]["footprint_bytes"],
            "host_reserve_bytes": final["reserve_bytes"],
            "pressure_level_after": final["pressure_level"],
            "stage_ms": worker["stage_ms"],
        })
    measured = [row["complete_seconds"] for row in output if not row["warmup"]]
    assert len({row["host_reserve_bytes"] for row in output}) == 1
    stage_keys = ("execution_and_segment", "recursion", "identity_and_wrap")
    stage_medians = {stage: statistics.median(row["stage_ms"][stage] / 1000
                                               for row in output if not row["warmup"])
                     for stage in stage_keys}
    return {
        "run": str(directory), "result_sha256": sha(directory / "result.json"),
        "request_ledger_sha256": sha(directory / "acceptance/requests.jsonl"),
        "count": len(measured), "warmup_count": expected_count - len(measured),
        "complete_seconds": measured, "median_complete_seconds": statistics.median(measured),
        "min_complete_seconds": min(measured), "max_complete_seconds": max(measured),
        "median_stage_seconds": stage_medians,
        "maximum_guard_lifetime_peak_footprint_bytes": max(row["guard_peak_footprint_bytes"] for row in output),
        "host_reserve_bytes": output[0]["host_reserve_bytes"],
        "proofs": output,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--arithmetic", type=Path, required=True)
    parser.add_argument("--hash", type=Path, required=True)
    parser.add_argument("--stretch", type=Path, required=True)
    args = parser.parse_args()
    archive_path = ROOT / "target/macos/phase2/baseline/manifest.json"
    archive = read(archive_path)
    assert archive["status"] == "sealed"
    for name, digest in archive["files"].items():
        assert sha(archive_path.parent / name) == digest, name
    assert archive["files"]["zkminer-prove-risc0"] == archive["worker"]["binary_sha256"]
    assert archive["files"]["hemi-macos-proof"] == archive["verifier"]["binary_sha256"]
    campaigns = {
        "arithmetic-10m": collect("arithmetic-10m", args.arithmetic, 6, archive),
        "hash-10m": collect("hash-10m", args.hash, 6, archive),
        "arithmetic-46m": collect("arithmetic-46m", args.stretch, 1, archive),
    }
    for name, guest_cycles in (("arithmetic-10m", 10_003_116),
                               ("hash-10m", 10_003_440),
                               ("arithmetic-46m", 46_003_116)):
        assert all(proof["guest_cycles"] == guest_cycles for proof in campaigns[name]["proofs"])
    assert all(campaigns[name]["count"] == 5 for name in ("arithmetic-10m", "hash-10m"))
    assert campaigns["arithmetic-46m"]["count"] == 1
    report = {
        "schema_version": 1, "status": "passed", "scope": "sealed Phase 2 starting worker; one excluded warmup and five warm proofs per 10M fixture, one 46M stretch",
        "source_spec_sha256": "22c73353915de7154577858ab4556d6d52fc6af3f463b3e6b2009f3ec5c707b7",
        "miner_commit": archive["miner_commit"], "engine_commit": archive["engine_commit"],
        "worker_sha256": archive["files"]["zkminer-prove-risc0"],
        "verifier_sha256": archive["files"]["hemi-macos-proof"],
        "archive_manifest_sha256": sha(archive_path),
        "collector_sha256": sha(Path(__file__)), "campaigns": campaigns,
        "verified_proofs": 13, "negative_checks": 39,
        "comparison_note": "The earlier 117.2 s and 484.7 s observations are historical; these are newly measured baseline values.",
    }
    report["host_snapshots"] = {}
    for name in ("hashing", "stretch"):
        snapshot = archive_path.parent / f"host-snapshot-{name}.json"
        if snapshot.exists():
            report["host_snapshots"][name] = {"observation": read(snapshot), "sha256": sha(snapshot)}
    refused_log = archive_path.parent / "hash-10m.log"
    if refused_log.exists():
        refused_run = Path(refused_log.read_text().splitlines()[0])
        refused_result = read(refused_run / "result.json")
        refused_test_log = refused_run / "test.log"
        if refused_result["status"] == "failed":
            assert "host RAM is short" in refused_test_log.read_text()
            assert not any(row.get("status") == "complete_independently_verified" for row in
                           (json.loads(line) for line in (refused_run / "acceptance/requests.jsonl").read_text().splitlines()))
            report["failed_before_dispatch"] = {
                "fixture": "hash-10m", "run": str(refused_run),
                "reason": "default 16 GiB reserve admission refusal before any proof dispatched",
                "result_sha256": sha(refused_run / "result.json"),
                "test_log_sha256": sha(refused_test_log),
            }
    evidence = ROOT / "docs/macos/evidence"
    evidence.mkdir(exist_ok=True)
    csv_path = evidence / "phase2-wp0-baseline.csv"
    columns = ["fixture", "proof", "warmup", "complete_seconds", "guest_cycles", "segments", "image_id", "program_sha256", "input_sha256", "journal_sha256", "seal_sha256", "guard_peak_footprint_bytes", "idle_worker_footprint_bytes", "host_reserve_bytes", "pressure_level_after", "worker_sidecar_sha256", "verification_sha256"]
    with csv_path.open("w", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=columns, lineterminator="\n")
        writer.writeheader()
        for campaign in campaigns.values():
            writer.writerows({key: proof[key] for key in columns} for proof in campaign["proofs"])
    report["csv_sha256"] = sha(csv_path)
    json_path = evidence / "phase2-wp0-baseline.json"
    json_path.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({name: {key: campaign[key] for key in ("count", "median_complete_seconds", "min_complete_seconds", "max_complete_seconds")} for name, campaign in campaigns.items()}, indent=2))


if __name__ == "__main__":
    main()
