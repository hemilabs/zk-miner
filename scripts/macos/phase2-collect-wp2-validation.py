#!/usr/bin/env python3
"""Bind WP2 CPU differentials, lifecycle, and overlap cancellation to the worker."""

import argparse
import json
from pathlib import Path

from proof_provenance import ROOT, sha, verify_build as verify_verifier
from worker_provenance import verify_build as verify_worker


EVIDENCE = ROOT / "docs/macos/evidence"
SPEC_SHA256 = "966e6bbfd2cbef4912c5cd18903e776b9ffc67c50f612ac2f71805d53247359d"


def read(path):
    return json.loads(path.read_text())


def check_verification(path):
    verification = read(path)
    assert verification["verification"] == "passed"
    assert set(verification["negative_tests"]) == {
        "wrong_image", "modified_journal", "corrupt_seal"}
    return sha(path)


def differential(run, po2, worker_sha, verifier_sha):
    result = read(run / "result.json")
    assert result["status"] == "passed" and result["po2"] == po2
    assert result["segment_check_cpu"]
    assert result["worker_build"]["binary_sha256"] == worker_sha
    assert result["verifier_build"]["binary_sha256"] == verifier_sha
    assert result["results"]["verified_proofs"] == 1
    sidecar = run / "acceptance/proof-0/worker.json"
    worker = read(sidecar)
    rv = worker["observed_stages"]["rv32im_metal"]
    assert worker["segment_hal"] == worker["recursion_hal"] == "metal"
    assert rv["cpu_differential_checks"] == worker["stats"]["segments"] > 0
    assert 0 < rv["completed_command_buffers"] <= rv["completed_dispatches"]
    return {
        "po2": po2, "run": str(run), "result_sha256": sha(run / "result.json"),
        "worker_sidecar_sha256": sha(sidecar),
        "verification_sha256": check_verification(run / "acceptance/proof-0/verification.json"),
        "segments": worker["stats"]["segments"],
        "cpu_differential_checks": rv["cpu_differential_checks"],
        "completed_dispatches": rv["completed_dispatches"],
        "completed_command_buffers": rv["completed_command_buffers"],
    }


def lifecycle(run, worker_sha, verifier_sha):
    result = read(run / "result.json")
    assert result["status"] == "passed" and not result["segment_check_cpu"]
    assert result["worker_build"]["binary_sha256"] == worker_sha
    assert result["verifier_build"]["binary_sha256"] == verifier_sha
    assert result["results"]["verified_proofs"] == 21
    requests = [json.loads(line) for line in
                (run / "acceptance/requests.jsonl").read_text().splitlines()]
    complete = [row for row in requests
                if row.get("status") == "complete_independently_verified"]
    assert len(complete) == 21
    steady = complete[:20]
    assert len({row["worker"]["worker_pid"] for row in steady}) == 1
    idle = [row["resources"]["idle_after_verification_and_settle"]["native_memory"]
            ["group"]["worker"]["footprint_bytes"] for row in steady]
    pressure = sorted({sample["native_memory"]["pressure_level"]
                       for row in steady for sample in row["resources"]["observations"]
                       if sample.get("native_memory")})
    assert pressure == [1]
    for index, row in enumerate(steady):
        rv = row["worker"]["observed_stages"]["rv32im_metal"]
        assert rv["cpu_differential_checks"] == 0
        assert 0 < rv["completed_command_buffers"] <= rv["completed_dispatches"]
        check_verification(run / "acceptance" / f"proof-{index}" / "verification.json")
    recovery = check_verification(run / "acceptance/proof-after-restart/verification.json")
    controls = result["results"]
    assert all(controls[key] for key in ("helper_cancel", "worker_timeout", "restart", "shutdown"))
    assert all(any(row.get("case") == case and row.get("status") == "expected_failure"
                   for row in requests) for case in ("helper-cancel", "helper-timeout"))
    growth = idle[-1] / idle[0] - 1
    return {
        "run": str(run), "result_sha256": sha(run / "result.json"),
        "request_ledger_sha256": sha(run / "acceptance/requests.jsonl"),
        "verified_proofs": 21, "tamper_rejections": 63,
        "recovery_verification_sha256": recovery,
        "idle_first_bytes": idle[0], "idle_last_bytes": idle[-1],
        "idle_first_to_last_fraction": growth,
        "idle_growth_at_most_5_percent": growth <= 0.05,
        "pressure_levels": pressure,
        "helper_cancel": controls["helper_cancel"], "helper_timeout": True,
        "worker_timeout": controls["worker_timeout"],
        "restart": controls["restart"], "shutdown": controls["shutdown"],
    }


def overlap_cancellation(run, worker_sha, verifier_sha):
    result = read(run / "result.json")
    assert result["status"] == "passed" and result["pipeline_cancel"]
    assert result["worker_build"]["binary_sha256"] == worker_sha
    assert result["verifier_build"]["binary_sha256"] == verifier_sha
    assert result["results"]["verified_proofs"] == 1
    assert result["results"]["pipeline_cancel"] and result["results"]["shutdown"]
    requests = [json.loads(line) for line in
                (run / "acceptance/requests.jsonl").read_text().splitlines()]
    complete = [row for row in requests if row.get("status") == "complete_independently_verified"]
    assert len(complete) == 1
    proof_verification = check_verification(run / "acceptance/proof-0/verification.json")
    cancellation = [row for row in requests if row.get("case") == "segment-pipeline-cancel"
                    and row.get("status") == "expected_failure"]
    assert len(cancellation) == 1
    record, marker = cancellation[0]["observed_overlap"]
    assert "[metal_pipeline] cpu_begin set=" in marker and "gpu_owned_set=Some(" in marker
    assert record["phase"] == "started" and record["po2"] == 20
    assert record["worker_pid"] != complete[0]["worker"]["worker_pid"] or (
        record["request_id"] != complete[0]["worker"]["request_id"])
    log = (run / "test.log").read_text()
    assert marker in log
    assert "killed intentionally (timeout/cancel)" in log
    return {
        "run": str(run), "result_sha256": sha(run / "result.json"),
        "request_ledger_sha256": sha(run / "acceptance/requests.jsonl"),
        "test_log_sha256": sha(run / "test.log"),
        "verified_proofs": 1, "tamper_rejections": 3,
        "proof_verification_sha256": proof_verification,
        "overlap_marker": marker, "cancelled_worker_pid": record["worker_pid"],
        "cancelled_request_id": record["request_id"],
        "worker_group_and_helper_absence": "asserted by the acceptance test",
    }


def switch_diagnostic(run, worker_sha, verifier_sha, enabled):
    result = read(run / "result.json")
    assert result["status"] == "passed" and result["po2"] == 20
    assert result["worker_build"]["binary_sha256"] == worker_sha
    assert result["verifier_build"]["binary_sha256"] == verifier_sha
    assert result["results"]["verified_proofs"] == 1
    requests = [json.loads(line) for line in
                (run / "acceptance/requests.jsonl").read_text().splitlines()]
    complete = [row for row in requests if row.get("status") == "complete_independently_verified"]
    assert len(complete) == 1
    row = complete[0]
    assert row["worker"]["stats"]["segments"] == 10
    verification = check_verification(run / "acceptance/proof-0/verification.json")
    log = (run / "test.log").read_text()
    counts = {name: log.count("[metal_pipeline] " + name) for name in
              ("cpu_begin", "cpu_witness_ready", "gpu_submit", "gpu_complete", "accum_overlap")}
    expected = {"cpu_begin": 10, "cpu_witness_ready": 10, "gpu_submit": 10,
                "gpu_complete": 10, "accum_overlap": 9} if enabled else dict.fromkeys(counts, 0)
    assert counts == expected
    memory = row["resources"]["idle_after_verification_and_settle"]["native_memory"]
    return {
        "run": str(run), "result_sha256": sha(run / "result.json"),
        "request_ledger_sha256": sha(run / "acceptance/requests.jsonl"),
        "test_log_sha256": sha(run / "test.log"),
        "verification_sha256": verification,
        "enabled": enabled, "handoff_counts": counts,
        "complete_seconds": (row["timings"]["prove_call_ms"] +
                             row["timings"]["external_verifier_ms"]) / 1000,
        "execution_and_segment_seconds": row["worker"]["stage_ms"]["execution_and_segment"] / 1000,
        "guard_peak_footprint_bytes": memory["guard_peak_footprint_bytes"],
        "pressure_level": memory["pressure_level"],
    }


def stretch(run, worker_sha, verifier_sha):
    result = read(run / "result.json")
    assert result["status"] == "passed" and result["po2"] == 20
    assert result["iterations"] == 4_600_000 and result["workload"] == "fibonacci"
    assert result["worker_build"]["binary_sha256"] == worker_sha
    assert result["verifier_build"]["binary_sha256"] == verifier_sha
    assert result["results"]["verified_proofs"] == 1
    requests = [json.loads(line) for line in
                (run / "acceptance/requests.jsonl").read_text().splitlines()]
    complete = [row for row in requests if row.get("status") == "complete_independently_verified"]
    assert len(complete) == 1
    row = complete[0]
    assert row["worker"]["stats"]["user_cycles"] == 46_003_116
    assert row["worker"]["stats"]["segments"] == 46
    verification = check_verification(run / "acceptance/proof-0/verification.json")
    log = (run / "test.log").read_text()
    handoffs = {name: log.count("[metal_pipeline] " + name) for name in
                ("cpu_begin", "gpu_submit", "gpu_complete", "accum_overlap")}
    assert handoffs == {"cpu_begin": 46, "gpu_submit": 46,
                        "gpu_complete": 46, "accum_overlap": 45}
    memory = row["resources"]["idle_after_verification_and_settle"]["native_memory"]
    return {
        "run": str(run), "result_sha256": sha(run / "result.json"),
        "request_ledger_sha256": sha(run / "acceptance/requests.jsonl"),
        "test_log_sha256": sha(run / "test.log"),
        "verification_sha256": verification,
        "guest_cycles": row["worker"]["stats"]["user_cycles"],
        "segments": row["worker"]["stats"]["segments"],
        "handoff_counts": handoffs,
        "complete_seconds": (row["timings"]["prove_call_ms"] +
                             row["timings"]["external_verifier_ms"]) / 1000,
        "guard_peak_footprint_bytes": memory["guard_peak_footprint_bytes"],
        "pressure_level": memory["pressure_level"],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for po2 in (14, 18, 20):
        parser.add_argument(f"--po2-{po2}", type=Path, required=True)
    parser.add_argument("--lifecycle", type=Path, required=True)
    parser.add_argument("--overlap-cancel", type=Path, required=True)
    parser.add_argument("--diagnostic-enabled", type=Path, required=True)
    parser.add_argument("--diagnostic-disabled", type=Path, required=True)
    parser.add_argument("--stretch", type=Path, required=True)
    parser.add_argument("--failed-lifecycle", type=Path)
    parser.add_argument("--linux", type=Path, required=True)
    parser.add_argument("--cpu-build-log", type=Path, required=True)
    parser.add_argument("--engine", type=Path, required=True)
    args = parser.parse_args()
    worker = verify_worker("native-rv32im-metal", args.engine.resolve())
    verifier = verify_verifier("verifier")
    checks = [differential(getattr(args, f"po2_{po2}").resolve(strict=True), po2,
                           worker["binary_sha256"], verifier["binary_sha256"])
              for po2 in (14, 18, 20)]
    life = lifecycle(args.lifecycle.resolve(strict=True), worker["binary_sha256"],
                     verifier["binary_sha256"])
    cancelled = overlap_cancellation(args.overlap_cancel.resolve(strict=True),
                                     worker["binary_sha256"], verifier["binary_sha256"])
    diagnostics = [switch_diagnostic(args.diagnostic_enabled.resolve(strict=True),
                                     worker["binary_sha256"], verifier["binary_sha256"], True),
                   switch_diagnostic(args.diagnostic_disabled.resolve(strict=True),
                                     worker["binary_sha256"], verifier["binary_sha256"], False)]
    stretch_result = stretch(args.stretch.resolve(strict=True), worker["binary_sha256"],
                             verifier["binary_sha256"])
    linux = args.linux.resolve(strict=True)
    linux_result = read(linux)
    assert linux_result["status"] == "passed"
    assert linux_result["engine_commit"] == worker["source"]["engine_head"]
    cpu_worker = verify_worker("cpu", args.engine.resolve())
    assert cpu_worker["source"]["engine_head"] == worker["source"]["engine_head"]
    cpu_log = args.cpu_build_log.resolve(strict=True)
    cpu_text = cpu_log.read_text()
    assert "test result: ok. 5 passed; 0 failed" in cpu_text
    assert "worker sealed to exact source" in cpu_text
    failed_lifecycle = None
    if args.failed_lifecycle:
        failed_run = args.failed_lifecycle.resolve(strict=True)
        failed_result = read(failed_run / "result.json")
        assert failed_result["status"] == "failed"
        failed_verifications = [check_verification(
            failed_run / "acceptance" / f"proof-{index}" / "verification.json")
            for index in range(20)]
        failed_lifecycle = {
            "run": str(failed_run),
            "result_sha256": sha(failed_run / "result.json"),
            "test_log_sha256": sha(failed_run / "test.log"),
            "verified_steady_proofs": len(failed_verifications),
            "tamper_rejections": 3 * len(failed_verifications),
            "reason": "The 20-second watchdog fired during recursion, before the helper had started; the harness expected complete recursion fields in the partial sidecar. All 20 steady proofs completed.",
            "failure_timeout_seconds": 20,
        }
    report = {
        "schema_version": 1,
        "status": "passed" if life["idle_growth_at_most_5_percent"] else "memory_gate_failed",
        "source_spec_sha256": SPEC_SHA256,
        "engine_commit": worker["source"]["engine_head"],
        "worker_sha256": worker["binary_sha256"],
        "verifier_sha256": verifier["binary_sha256"],
        "collector_sha256": sha(Path(__file__)),
        "cpu_only_feature_build": {
            "status": "passed", "worker_sha256": cpu_worker["binary_sha256"],
            "manifest_sha256": sha(ROOT / "target/macos/worker-build.json"),
            "tests_passed": 5, "log_path": str(cpu_log), "log_sha256": sha(cpu_log),
        },
        "linux_feature_check": {
            "source_revision": linux_result["engine_commit"],
            "result_sha256": sha(linux),
            "checks": linux_result["checks"],
        },
        "real_witness_differentials": checks,
        "lifecycle": life,
        "overlap_cancellation": cancelled,
        "same_binary_pipeline_switch_diagnostics": diagnostics,
        "diagnostic_complete_saving_seconds": diagnostics[1]["complete_seconds"] - diagnostics[0]["complete_seconds"],
        "arithmetic_46m_stretch": stretch_result,
        "failed_lifecycle_attempt": failed_lifecycle,
    }
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    output = EVIDENCE / "phase2-wp2-validation.json"
    output.write_text(json.dumps(report, indent=2) + "\n")
    print(output)
    print(report["status"])


if __name__ == "__main__":
    main()
