#!/usr/bin/env python3
"""Bind WP3's transform, lifecycle, feature-path and stretch checks to the worker."""

import argparse
import json
from pathlib import Path
import re
from statistics import median

from proof_provenance import ROOT, sha, verify_build as verify_verifier
from worker_provenance import verify_build as verify_worker


EVIDENCE = ROOT / "docs/macos/evidence"
SPEC_SHA256 = "07467098c3493a0bbc0f543b0960676ba3a3e21ebd1fb7a65d10bb8dec40dc97"
MAIN_COMMIT_BYTES_PER_SEGMENT = (211 + 103) * (1 << 20) * 4 * 113
PROFILE = re.compile(
    r"\[metal_gpu\] kernel=batch_transforms segment=(\d+) count=(\d+) "
    r"gpu_ms=([\d.]+) dispatch_wall_ms=([\d.]+)")


def read(path):
    return json.loads(path.read_text())


def checked_proof(run, worker_sha, verifier_sha):
    result = read(run / "result.json")
    assert result["status"] == "passed"
    assert result["worker_build"]["binary_sha256"] == worker_sha
    assert result["verifier_build"]["binary_sha256"] == verifier_sha
    assert result["results"]["verified_proofs"] >= 1
    checks = []
    for path in sorted((run / "acceptance").glob("*/verification.json")):
        row = read(path)
        assert row["verification"] == "passed"
        assert set(row["negative_tests"]) == {
            "wrong_image", "modified_journal", "corrupt_seal"}
        checks.append({"path": str(path), "sha256": sha(path)})
    assert len(checks) == result["results"]["verified_proofs"]
    return result, checks


def isolated(run, worker_sha, verifier_sha):
    result, checks = checked_proof(run, worker_sha, verifier_sha)
    assert result["po2"] == 20 and result["results"]["verified_proofs"] == 1
    entries = [(int(seg), int(count), float(gpu), float(wall))
               for seg, count, gpu, wall in PROFILE.findall((run / "test.log").read_text())]
    assert entries and set(seg for seg, _, _, _ in entries) == set(range(10))
    segments = []
    for seg in range(10):
        commands = [(count, gpu, wall) for s, count, gpu, wall in entries if s == seg]
        assert 7 <= len(commands) <= 9
        segments.append({"segment": seg, "command_buffers": len(commands),
                         "gpu_seconds": sum(gpu for _, gpu, _ in commands) / 1000,
                         "dispatch_wall_seconds": sum(wall for _, _, wall in commands) / 1000})
    wall = median(item["dispatch_wall_seconds"] for item in segments[1:])
    gpu = median(item["gpu_seconds"] for item in segments[1:])
    return {"run": str(run), "result_sha256": sha(run / "result.json"),
            "test_log_sha256": sha(run / "test.log"), "verifications": checks,
            "pipeline_disabled": True, "segments": segments,
            "steady_transform_dispatch_wall_seconds_median": wall,
            "steady_transform_gpu_seconds_median": gpu,
            "wall_gate_at_most_0_8_seconds": wall <= 0.8,
            "main_commit_requested_bytes_per_segment": MAIN_COMMIT_BYTES_PER_SEGMENT,
            "modeled_bandwidth_decimal_gb_per_second":
                MAIN_COMMIT_BYTES_PER_SEGMENT / gpu / 1e9,
            "bandwidth_model_scope": "main DATA and ACCUM buffer reads/writes only; excludes cache behavior, twiddle traffic and smaller groups"}


def lifecycle(run, worker_sha, verifier_sha):
    result, checks = checked_proof(run, worker_sha, verifier_sha)
    assert result["results"]["verified_proofs"] == 21
    rows = [json.loads(line) for line in (run / "acceptance/requests.jsonl").read_text().splitlines()]
    complete = [row for row in rows if row.get("status") == "complete_independently_verified"]
    assert len(complete) == 21
    steady = complete[:20]
    assert len({row["worker"]["worker_pid"] for row in steady}) == 1
    idle = [row["resources"]["idle_after_verification_and_settle"]["native_memory"]
            ["group"]["worker"]["footprint_bytes"] for row in steady]
    growth = idle[-1] / idle[0] - 1
    assert all(result["results"][name] for name in
               ("helper_cancel", "worker_timeout", "restart", "shutdown"))
    return {"run": str(run), "result_sha256": sha(run / "result.json"),
            "request_ledger_sha256": sha(run / "acceptance/requests.jsonl"),
            "verifications": len(checks), "tamper_rejections": 3 * len(checks),
            "idle_first_bytes": idle[0], "idle_last_bytes": idle[-1],
            "idle_first_to_last_fraction": growth,
            "idle_growth_at_most_5_percent": growth <= 0.05}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("isolated", "lifecycle", "lifecycle-attempt", "stretch",
                 "primitive-log", "fallback-log", "merkle-log",
                 "cpu-build-log", "linux"):
        parser.add_argument("--" + name, type=Path, required=True)
    for po2 in (14, 18, 20):
        parser.add_argument(f"--differential-po2-{po2}", type=Path, required=True)
    parser.add_argument("--isolated-driver", type=Path, required=True)
    parser.add_argument("--engine", type=Path, required=True)
    args = parser.parse_args()
    worker = verify_worker("native-rv32im-metal", args.engine.resolve())
    verifier = verify_verifier("verifier")
    worker_sha = worker["binary_sha256"]
    verifier_sha = verifier["binary_sha256"]
    primitive_log = args.primitive_log.resolve(strict=True)
    primitive_text = primitive_log.read_text()
    assert "test result: ok. 21 passed; 0 failed" in primitive_text
    fallback_log = args.fallback_log.resolve(strict=True)
    assert "test result: ok. 21 passed; 0 failed" in fallback_log.read_text()
    merkle_log = args.merkle_log.resolve(strict=True)
    merkle_text = merkle_log.read_text()
    for po2, count in ((12, 3), (14, 7), (18, 3)):
        assert (f"po2={po2} count={count}: witness, coefficients, LDE and "
                "Merkle nodes match") in merkle_text
    cpu_log = args.cpu_build_log.resolve(strict=True)
    assert "test result: ok. 5 passed; 0 failed" in cpu_log.read_text()
    cpu = verify_worker("cpu", args.engine.resolve())
    assert cpu["source"]["engine_head"] == worker["source"]["engine_head"]
    linux = args.linux.resolve(strict=True)
    linux_result = read(linux)
    assert linux_result["status"] == "passed"
    assert linux_result["engine_commit"] == worker["source"]["engine_head"]
    assert all(value == "passed" for value in linux_result["checks"].values())
    iso = isolated(args.isolated.resolve(strict=True), worker_sha, verifier_sha)
    isolated_driver = args.isolated_driver.resolve(strict=True)
    isolated_driver_result = read(isolated_driver / "result.json")
    assert isolated_driver_result["status"] == "passed"
    assert isolated_driver_result["pipeline_disabled"]
    assert isolated_driver_result["run"] == iso["run"]
    assert isolated_driver_result["run_result_sha256"] == iso["result_sha256"]
    assert isolated_driver_result["candidate_worker_sha256"] == worker_sha
    assert isolated_driver_result["verifier_sha256"] == verifier_sha
    assert isolated_driver_result["driver_sha256"] == sha(
        ROOT / "scripts/macos/phase2-run-wp3-isolated.py")
    for name in ("host_before", "host_after"):
        host = isolated_driver_result[name]
        assert sha(Path(host["path"])) == host["sha256"]
    iso["driver_result"] = str(isolated_driver / "result.json")
    iso["driver_result_sha256"] = sha(isolated_driver / "result.json")
    iso["host_before"] = isolated_driver_result["host_before"]
    iso["host_after"] = isolated_driver_result["host_after"]
    life = lifecycle(args.lifecycle.resolve(strict=True), worker_sha, verifier_sha)
    attempt_run = args.lifecycle_attempt.resolve(strict=True)
    attempt_result = read(attempt_run / "result.json")
    attempt_log = (attempt_run / "test.log").read_text()
    assert attempt_result["status"] == "failed"
    assert "deadline should stop a real proof" in attempt_log
    attempt_rows = [json.loads(line) for line in
                    (attempt_run / "acceptance/requests.jsonl").read_text().splitlines()]
    attempt_complete = [row for row in attempt_rows
                        if row.get("status") == "complete_independently_verified"]
    assert len(attempt_complete) == 20
    assert len({row["worker"]["worker_pid"] for row in attempt_complete}) == 1
    attempt_idle = [row["resources"]["idle_after_verification_and_settle"]["native_memory"]
                    ["group"]["worker"]["footprint_bytes"] for row in attempt_complete]
    stretch_run = args.stretch.resolve(strict=True)
    stretch, checks = checked_proof(stretch_run, worker_sha, verifier_sha)
    assert stretch["iterations"] == 4_600_000
    assert stretch["results"]["verified_proofs"] == 1
    stretch_rows = [json.loads(line) for line in
                    (stretch_run / "acceptance/requests.jsonl").read_text().splitlines()]
    stretch_complete = [row for row in stretch_rows
                        if row.get("status") == "complete_independently_verified"]
    assert len(stretch_complete) == 1
    stretch_row = stretch_complete[0]
    assert stretch_row["worker"]["stats"]["user_cycles"] >= 46_000_000
    stretch_seconds = (stretch_row["timings"]["prove_call_ms"] +
                       stretch_row["timings"]["external_verifier_ms"]) / 1000
    stretch_memory = stretch_row["resources"]["idle_after_verification_and_settle"]["native_memory"]
    differentials = {}
    for po2 in (14, 18, 20):
        run = getattr(args, f"differential_po2_{po2}").resolve(strict=True)
        differential, verifications = checked_proof(run, worker_sha, verifier_sha)
        assert differential["po2"] == po2 and differential["segment_check_cpu"]
        assert differential["results"]["verified_proofs"] == 1
        differential_log = run / "test.log"
        differential_rows = [json.loads(line) for line in
                             (run / "acceptance/requests.jsonl").read_text().splitlines()]
        differential_complete = [row for row in differential_rows
                                 if row.get("status") == "complete_independently_verified"]
        assert len(differential_complete) == 1
        worker_row = differential_complete[0]["worker"]
        segment_count = worker_row["stats"]["segments"]
        cpu_checks = worker_row["observed_stages"]["rv32im_metal"]["cpu_differential_checks"]
        assert cpu_checks >= segment_count > 0
        differentials[str(po2)] = {"run": str(run),
                                  "result_sha256": sha(run / "result.json"),
                                  "test_log_sha256": sha(differential_log),
                                  "verification_sha256": verifications[0]["sha256"],
                                  "segments": segment_count,
                                  "cpu_differential_checks": cpu_checks}
    report = {"schema_version": 1, "status": "passed" if
              iso["wall_gate_at_most_0_8_seconds"] and
              iso["modeled_bandwidth_decimal_gb_per_second"] >= 180 and
              life["idle_growth_at_most_5_percent"] else "gate_failed",
              "source_spec_sha256": SPEC_SHA256,
              "engine_commit": worker["source"]["engine_head"],
              "worker_sha256": worker_sha, "verifier_sha256": verifier_sha,
              "collector_sha256": sha(Path(__file__)),
              "primitive_suite": {"log": str(primitive_log), "sha256": sha(primitive_log),
                                  "passed_tests": 21},
              "radix2_fallback_suite": {"log": str(fallback_log),
                                        "sha256": sha(fallback_log), "passed_tests": 21},
              "merkle_differential": {"log": str(merkle_log), "sha256": sha(merkle_log),
                                      "source_sha256": sha(ROOT / "tools/macos-wp3-merkle/src/main.rs"),
                                      "cases": [[12, 3], [14, 7], [18, 3]]},
              "cpu_only_build": {"log": str(cpu_log), "sha256": sha(cpu_log),
                                 "worker_sha256": cpu["binary_sha256"]},
              "linux_feature_path": {"result": str(linux), "sha256": sha(linux),
                                     "checks": linux_result["checks"]},
              "isolated_transforms": iso, "lifecycle": life,
              "real_witness_cpu_differentials": differentials,
              "lifecycle_failed_attempt": {
                  "run": str(attempt_run), "result_sha256": sha(attempt_run / "result.json"),
                  "test_log_sha256": sha(attempt_run / "test.log"),
                  "request_ledger_sha256": sha(attempt_run / "acceptance/requests.jsonl"),
                  "verified_proofs_before_harness_failure": 20,
                  "idle_first_to_last_fraction": attempt_idle[-1] / attempt_idle[0] - 1,
                  "failure": "60-second helper-timeout control exceeded the tiny proof's completion time"},
              "arithmetic_46m_stretch": {"run": str(stretch_run),
                  "result_sha256": sha(stretch_run / "result.json"),
                  "request_ledger_sha256": sha(stretch_run / "acceptance/requests.jsonl"),
                  "verification_sha256": checks[0]["sha256"],
                  "complete_seconds": stretch_seconds,
                  "guest_cycles": stretch_row["worker"]["stats"]["user_cycles"],
                  "segments": stretch_row["worker"]["stats"]["segments"],
                  "guard_peak_footprint_bytes": stretch_memory["guard_peak_footprint_bytes"],
                  "pressure_level": stretch_memory["pressure_level"]}}
    output = EVIDENCE / "phase2-wp3-validation.json"
    output.write_text(json.dumps(report, indent=2) + "\n")
    print(output, report["status"])


if __name__ == "__main__":
    main()
