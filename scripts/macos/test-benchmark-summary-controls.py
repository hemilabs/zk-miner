#!/usr/bin/env python3
"""Focused benchmark-collector controls; never generate or verify a proof."""
import argparse
import copy
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]


def artifact(path):
    data = path.read_bytes()
    return {"path": str(path.resolve()), "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--benchmark", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if not __debug__ or args.output.exists():
        parser.error("assertions must be enabled and output must be a new file")
    source = ROOT / "scripts/macos/summarize-benchmark.py"
    spec = importlib.util.spec_from_file_location("benchmark_summary_target", source)
    target = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(target)
    plan_path = args.benchmark / "plan.json"
    plan = target.read_json(plan_path)
    rows = [dict(slot, run_id=f"{slot['index'] + 1:032x}", status=target.COMPLETE,
                 returncode=0, error=None, elapsed_seconds=1.0) for slot in plan["trials"]]
    result = {"status": "complete", "completed_trials": len(rows), "failed_trials": 0,
              "unattempted_trials": 0, "source_inputs_unchanged": True, "error": None}
    outcomes = []

    def accepts(name, action):
        action()
        outcomes.append({"case": name, "expected": "accept", "observed": "accept", "outcome": "passed"})

    def refuses(name, action):
        try:
            action()
        except ValueError as error:
            outcomes.append({"case": name, "expected": "reject", "observed": "reject", "outcome": "passed", "diagnostic": str(error)})
        else:
            raise AssertionError(name + ": invalid benchmark evidence accepted")

    accepts("declared alternating schedule", lambda: target.validate_schedule(plan, rows, result))
    changed = copy.deepcopy(rows)
    changed[2]["mode"] = "metal"
    refuses("swapped scheduled mode", lambda: target.validate_schedule(plan, changed, result))
    changed = copy.deepcopy(rows)
    changed[3]["run_id"] = changed[2]["run_id"]
    refuses("reused acceptance run", lambda: target.validate_schedule(plan, changed, result))
    stopped = copy.deepcopy(rows[:2])
    stopped[-1].update(status="failed", returncode=101, error="controlled failure")
    failure = dict(result, status="failed", completed_trials=1, failed_trials=1, unattempted_trials=len(rows)-2, error="controlled failure")
    accepts("failed prefix retains unattempted trials", lambda: target.validate_schedule(plan, stopped, failure))
    retried = stopped + copy.deepcopy(rows[2:3])
    refuses("attempt after failure", lambda: target.validate_schedule(plan, retried, failure))

    samples = len(rows) // 2 - 1
    measurements = []
    for row in rows:
        value = 100000.0 if row["phase"] == "warmup" else 100.0 + row["sample"]
        if row["mode"] == "metal":
            value /= 2.0
        measurements.append(dict(row, **{metric: value for metric in target.TIME_METRICS}, request_peak_rss_bytes=1000.0))
    def expected_statistics():
        stats = target.paired_statistics(measurements, samples)
        expected_median = 100.0 + (samples + 1) / 2.0
        for metric in target.TIME_METRICS:
            assert stats["by_mode"]["cpu"][metric]["median"] == expected_median
            assert stats["by_mode"]["metal"][metric]["median"] == expected_median / 2.0
            assert stats["paired_cpu_over_metal"][metric]["median"] == 2.0
            assert stats["by_mode"]["cpu"][metric]["n"] == samples
    accepts("known twofold ratios exclude extreme warmups", expected_statistics)
    refuses("missing measured mode", lambda: target.paired_statistics(measurements[:-1], samples))
    changed_measurements = copy.deepcopy(measurements)
    changed_measurements[2]["worker_total_ms"] = 0.0
    refuses("zero timing cannot become infinite speedup", lambda: target.paired_statistics(changed_measurements, samples))
    changed_measurements = copy.deepcopy(measurements)
    changed_measurements[2]["worker_total_ms"] = float("nan")
    refuses("nonfinite timing cannot enter statistics", lambda: target.paired_statistics(changed_measurements, samples))

    # Read one actual finalized warmup solely to check timing/identity bindings.
    actual_trials = target.read_rows(args.benchmark / "trials.jsonl")
    actual = next(row for row in actual_trials if row["status"] == target.COMPLETE)
    attempt = ROOT / "target/macos/worker-runs" / actual["run_id"]
    directory = attempt / "acceptance/proof-0"
    worker = target.read_json(directory / "worker.json")
    resource = target.read_json(directory / "resource.json")
    proof = {"case": "proof-0", "worker": worker, "resource": resource}
    ledger = next(row for row in target.read_rows(attempt / "acceptance/requests.jsonl") if row["status"] == target.COMPLETE)
    accepts("actual saved timing and worker identity bind", lambda: target.bind_timing(attempt, proof, ledger))
    changed_ledger = copy.deepcopy(ledger)
    changed_ledger["timings"]["request_id"] += 1
    refuses("changed timing request identity", lambda: target.bind_timing(attempt, proof, changed_ledger))
    changed_proof = copy.deepcopy(proof)
    changed_proof["resource"]["prove_call_ms"] += 1.0
    refuses("changed resource prove-call duration", lambda: target.bind_timing(attempt, changed_proof, ledger))
    diagnostic = target.wrap_diagnostics(attempt / "test.log")
    with tempfile.TemporaryDirectory(prefix="hemi-benchmark-control-") as temporary:
        duplicate = Path(temporary) / "duplicate.log"
        duplicate.write_text((diagnostic["raw_line"] + "\n") * 2)
        refuses("ambiguous duplicate wrapping diagnostic", lambda: target.wrap_diagnostics(duplicate))

    report = {"schema_version": 1, "status": "passed", "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "command": [sys.executable, str(Path(__file__).resolve()), *sys.argv[1:]],
        "scope": "controlled schedule/statistical cases plus read-only timing/identity bindings from one actual finalized warmup; no cryptographic verification or proving executed",
        "proofs_generated_or_verified": 0, "control_cases_passed": len(outcomes), "control_cases_failed": 0,
        "artifacts": {"controls": artifact(Path(__file__)), "collector": artifact(source), "actual_plan": artifact(plan_path),
            "actual_worker": artifact(directory / "worker.json"), "actual_resource": artifact(directory / "resource.json"),
            "actual_timing": artifact(directory / "timing.json"), "actual_run_timing": artifact(attempt / "acceptance/timing.json"),
            "actual_ledger": artifact(attempt / "acceptance/requests.jsonl"), "actual_test_log": artifact(attempt / "test.log")},
        "cases": outcomes}
    with args.output.open("x") as stream:
        stream.write(json.dumps(report, indent=2, allow_nan=False) + "\n")
    print(json.dumps({key: report[key] for key in ("status", "control_cases_passed", "control_cases_failed", "proofs_generated_or_verified")}))


if __name__ == "__main__":
    main()
