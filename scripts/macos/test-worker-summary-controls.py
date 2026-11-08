#!/usr/bin/env python3
"""Check collector binding guards using copies of saved real-proof evidence.

These are evidence-collector controls. They do not generate or verify proofs,
modify archived runs, or change acceptance sources.
"""
import argparse
import copy
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import math
from pathlib import Path
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
RUNS = ROOT / "target/macos/worker-runs"
SHA_RUN = "71387ac25ac74d4395278a3459680152"
BOUNDARY_RUN = "3c0b5d8179934bafb482174615a05d22"


def artifact(path):
    data = path.read_bytes()
    return {"path": str(path.resolve()), "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}


def read_json(path):
    return json.loads(path.read_text())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if not __debug__:
        parser.error("run without Python optimization; assertions are required controls")
    if args.output.exists():
        parser.error("output exists; use a new path to preserve earlier control evidence")
    collector_path = ROOT / "scripts/macos/summarize-worker.py"
    spec = importlib.util.spec_from_file_location("worker_summary_controls_target", collector_path)
    collector = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(collector)
    worker_path = RUNS / SHA_RUN / "acceptance/proof-0/worker.json"
    fixture = read_json(worker_path)
    assert read_json(RUNS / SHA_RUN / "result.json")["status"] == "complete_independently_verified"
    assert fixture["phase"] == "complete" and fixture["proof_kind"] == "groth16"
    seal_path, journal_path = worker_path.with_name("seal.bin"), worker_path.with_name("journal.bin")
    assert artifact(seal_path)["sha256"] == fixture["seal_sha256"]
    assert artifact(journal_path)["sha256"] == fixture["journal_sha256"]
    outcomes = []

    def accepts(name, changed, difference_count):
        differences = collector.compare_worker_records(fixture, changed, "saved_real_worker", "controlled_copy")
        assert len(differences) == difference_count, name
        assert all(value["ulp_distance"] == 1 for value in differences), name
        outcomes.append({"case": name, "expected": "accept", "observed": "accept", "outcome": "passed",
                         "diagnostic_differences": differences})

    def refuses(name, changed, original=None):
        try:
            collector.compare_worker_records(fixture if original is None else original, changed,
                                             "saved_real_worker_or_control", "controlled_copy")
        except ValueError as error:
            outcomes.append({"case": name, "expected": "reject", "observed": "reject", "outcome": "passed",
                             "diagnostic": str(error)})
        else:
            raise AssertionError(f"{name}: collector accepted invalid evidence")

    accepts("identical actual worker evidence", copy.deepcopy(fixture), 0)
    for field in ("total_ms", "stage_ms.verification"):
        changed = copy.deepcopy(fixture)
        target = changed if field == "total_ms" else changed["stage_ms"]
        key = field.split(".")[-1]
        target[key] = math.nextafter(target[key], math.inf)
        accepts("one ULP in " + field, changed, 1)
        target[key] = math.nextafter(target[key], math.inf)
        refuses("two ULPs in " + field, changed)
    for name, key, value in (("modified raw seal hash", "seal_sha256", "0" * 64),
                             ("modified request identity", "request_id", fixture["request_id"] + 1)):
        changed = copy.deepcopy(fixture)
        changed[key] = value
        refuses(name, changed)
    changed = copy.deepcopy(fixture)
    changed["stats"]["segments"] += 1
    refuses("modified segment counter", changed)
    original, changed = copy.deepcopy(fixture), copy.deepcopy(fixture)
    original["observed_stages"]["diagnostic"] = 1.0
    changed["observed_stages"]["diagnostic"] = math.nextafter(1.0, math.inf)
    refuses("one ULP outside allowed timing fields", changed, original)
    for label, value in (("negative", -1.0), ("infinite", math.inf), ("NaN", math.nan)):
        original, changed = copy.deepcopy(fixture), copy.deepcopy(fixture)
        original["total_ms"] = changed["total_ms"] = value
        refuses(label + " timing even when both copies contain it", changed, original)
    assert len(outcomes) == 12

    # Retain the raw facts behind the two earlier collector-only refusals.
    # These diagnostics were observed before collector fixes, not proof failures.
    rss_path = RUNS / SHA_RUN / "rss-samples.jsonl"
    zero_rows = [{"line": number, "observation": json.loads(line)}
                 for number, line in enumerate(rss_path.read_text().splitlines(), 1)
                 if json.loads(line)["rss_bytes"] == 0]
    assert zero_rows
    boundary_worker_path = RUNS / BOUNDARY_RUN / "acceptance/proof-0/worker.json"
    boundary_worker = read_json(boundary_worker_path)
    boundary_sidecar_path = RUNS / BOUNDARY_RUN / "requests" / (
        f"{boundary_worker['worker_pid']}-{boundary_worker['request_id']}.json")
    boundary_differences = collector.compare_worker_records(boundary_worker, read_json(boundary_sidecar_path),
                                                            str(boundary_worker_path), str(boundary_sidecar_path))
    assert len(boundary_differences) == 2
    result = {
        "schema_version": 1, "status": "passed", "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "command": [sys.executable, str(Path(__file__).resolve()), *sys.argv[1:]],
        "scope": "collector binding controls on in-memory copies of archived evidence; no proving or cryptographic verification executed",
        "proofs_generated_or_verified": 0, "control_cases_passed": len(outcomes), "control_cases_failed": 0,
        "artifacts": {"control_script": artifact(Path(__file__)), "collector_script": artifact(collector_path),
                      "fixture_worker": artifact(worker_path), "fixture_seal": artifact(seal_path),
                      "fixture_journal": artifact(journal_path)},
        "cases": outcomes,
        "earlier_collector_refusals": [
            {"category": "outer RSS observation", "diagnostic_observed_before_fix": "evidence summary refused: invalid outer RSS sample",
             "run_id": SHA_RUN, "proof_failure": False, "raw_artifact": artifact(rss_path), "raw_zero_observations": zero_rows,
             "resolution": "retain zeros as unavailable_nonpositive_rss; exclude them from positive sample counts and peaks; cause remains unknown"},
            {"category": "diagnostic timing serialization", "diagnostic_observed_before_fix": "evidence summary refused: terminal sidecar differs from accepted request",
             "run_id": BOUNDARY_RUN, "proof_failure": False,
             "raw_worker_artifact": artifact(boundary_worker_path), "raw_sidecar_artifact": artifact(boundary_sidecar_path),
             "example_original_differences": boundary_differences,
             "resolution": "permit at most one adjacent finite nonnegative float step only in total_ms/direct stage_ms values; preserve originals and exact non-timing bindings"},
        ],
    }
    with args.output.open("x") as stream:
        stream.write(json.dumps(result, indent=2, allow_nan=False) + "\n")
    print(json.dumps({key: result[key] for key in ("status", "control_cases_passed", "control_cases_failed", "proofs_generated_or_verified")}))


if __name__ == "__main__":
    main()
