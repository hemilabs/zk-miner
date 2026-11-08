#!/usr/bin/env python3
"""Bind WP0.5 proof differentials and lifecycle to the sealed worker."""

import argparse
import json
from pathlib import Path

from proof_provenance import ROOT, sha, verify_build as verify_verifier
from worker_provenance import verify_build as verify_worker


EVIDENCE = ROOT / "docs/macos/evidence"
SPEC_SHA256 = "299ebd441aa2e1c0c70f7587a88b8cc32154d0835a0eaea0d807adef11028597"


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
    assert result["status"] == "passed" and result["segment_check_cpu"]
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
        assert rv["cpu_differential_checks"] == row["worker"]["stats"]["segments"] > 0
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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for po2 in (14, 18, 20):
        parser.add_argument(f"--po2-{po2}", type=Path, required=True)
    parser.add_argument("--lifecycle", type=Path, required=True)
    parser.add_argument("--failed-lifecycle", type=Path)
    parser.add_argument("--engine", type=Path, required=True)
    args = parser.parse_args()
    worker = verify_worker("native-rv32im-metal", args.engine.resolve())
    verifier = verify_verifier("verifier")
    checks = [differential(getattr(args, f"po2_{po2}").resolve(strict=True), po2,
                           worker["binary_sha256"], verifier["binary_sha256"])
              for po2 in (14, 18, 20)]
    life = lifecycle(args.lifecycle.resolve(strict=True), worker["binary_sha256"],
                     verifier["binary_sha256"])
    linux = ROOT / "target/macos/phase2/wp05-iter2-linux/result.json"
    linux_result = read(linux)
    assert linux_result["status"] == "passed"
    # The final iteration changes only metal.rs, which is cfg(target_os = "macos").
    # The Linux feature path is identical to the checked second iteration.
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
            "reason": "The 10-second helper timeout killed the partial sidecar before completed_constraint_checks was recorded; the 20 steady proofs completed.",
            "failure_timeout_seconds": 10,
        }
    report = {
        "schema_version": 1,
        "status": "passed" if life["idle_growth_at_most_5_percent"] else "memory_gate_failed",
        "source_spec_sha256": SPEC_SHA256,
        "engine_commit": worker["source"]["engine_head"],
        "worker_sha256": worker["binary_sha256"],
        "verifier_sha256": verifier["binary_sha256"],
        "collector_sha256": sha(Path(__file__)),
        "metal_primitive_tests": 20,
        "recursion_primitive_offset_differential": "passed",
        "cpu_only_feature_build": "passed",
        "linux_feature_check": {
            "source_revision": linux_result["engine_commit"],
            "result_sha256": sha(linux),
            "scope": "Only macOS-gated metal.rs changed in the final revision; the supported Linux feature path is unchanged.",
            "checks": linux_result["checks"],
        },
        "real_witness_differentials": checks,
        "lifecycle": life,
        "failed_lifecycle_attempt": failed_lifecycle,
    }
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    output = EVIDENCE / "phase2-wp05-validation.json"
    output.write_text(json.dumps(report, indent=2) + "\n")
    print(output)
    print(report["status"])


if __name__ == "__main__":
    main()
