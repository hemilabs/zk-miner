#!/usr/bin/env python3
"""Bind WP4 differentials, lifecycle and feature checks to the paired worker."""

import json
from pathlib import Path
import subprocess

from proof_provenance import ROOT, sha
from worker_provenance import paths, verify_build as verify_worker


ENGINE = Path("/Users/dbur/dev/risc0")
PHASE = ROOT / "target/macos/phase2"
EVIDENCE = ROOT / "docs/macos/evidence"
COMMIT = "bca7044c5480d0efddcb2a035dd569035d0c8cde"
SPEC_SHA256 = "a8627ca24baec008b140a4bb75f9ef8bb75fd67281e9a8e628c328afb6542a09"
NEGATIVE = {"wrong_image", "modified_journal", "corrupt_seal"}


def read(path):
    return json.loads(path.read_text())


def run_from_log(name):
    log = PHASE / name
    run = Path(log.read_text().splitlines()[0])
    result = read(run / "result.json")
    assert result["status"] == "passed", (name, result.get("error"))
    return run, result, {"run": str(run), "result_sha256": sha(run / "result.json"),
                         "log_sha256": sha(log)}


def check_proof(proof):
    verification = read(proof / "verification.json")
    assert verification["verification"] == "passed"
    assert set(verification["negative_tests"]) == NEGATIVE
    return {"worker_sidecar_sha256": sha(proof / "worker.json"),
            "verification_sha256": sha(proof / "verification.json")}


def differential(name, cycles):
    run, result, record = run_from_log(name)
    assert result["worker_build"]["source"]["engine_head"] == COMMIT
    assert result["recursion_check_cpu"]
    proof = run / "acceptance/proof-0"
    record.update(check_proof(proof))
    worker = read(proof / "worker.json")
    stage = worker["observed_stages"]["recursion_metal"]
    assert worker["stats"]["user_cycles"] == cycles
    assert worker["po2"] == 20 and worker["stats"]["segments"] == 10
    assert stage["eval_check_split"]
    assert stage["completed_constraint_checks"] == stage["cpu_differential_checks"] == 19
    record.update(user_cycles=cycles, recursion_cpu_checks=19,
                  recursion_shader_sha256=stage["kernel_source_sha256"])
    return record


def main():
    assert subprocess.check_output(["git", "-C", str(ENGINE), "rev-parse", "HEAD"],
                                   text=True).strip() == COMMIT
    assert subprocess.check_output(["git", "-C", str(ENGINE), "status", "--porcelain"],
                                   text=True).strip() == ""
    spec = Path("/Users/dbur/Downloads/Phase 2 spec Metal proving performance on macOS.md")
    assert sha(spec) == SPEC_SHA256
    worker = verify_worker("native-rv32im-metal", ENGINE)
    paired_path = EVIDENCE / "phase2-wp4-paired.json"
    paired = read(paired_path)
    assert paired["status"] == "complete" and paired["recursion_gate_10m"]
    assert paired["engine_commit"] == COMMIT
    assert paired["candidate_worker_sha256"] == worker["binary_sha256"]
    assert paired["verified_proofs"] == 36 and paired["tamper_rejections"] == 108
    assert paired["all_peaks_below_32_gib"] and paired["normal_pressure_all_rows"]
    assert sha(EVIDENCE / "phase2-wp4-paired.csv") == paired["csv_sha256"]
    generator_log = PHASE / "wp4-final-generator-check.log"
    assert "groups 6 max leaf 2049; lazy REDC: chain terms 1060, folds 400" in generator_log.read_text()
    arithmetic = differential("wp4-final-differential-arithmetic-10m.log", 10_003_116)
    hashing = differential("wp4-final-differential-hash-10m.log", 10_003_440)
    assert arithmetic["recursion_shader_sha256"] == hashing["recursion_shader_sha256"]
    assert arithmetic["recursion_shader_sha256"] == next(
        row["recursion_shader_sha256"] for row in paired["fixtures"][0]["rows"]
        if row["arm"] == "wp4_split_lazy")

    run, result, lifecycle = run_from_log("wp4-final-lifecycle.log")
    assert result["results"]["verified_proofs"] == 21
    assert result["results"]["unique_completed_requests"] == 21
    assert all(result["results"][name] for name in
               ("helper_cancel", "worker_timeout", "restart", "shutdown"))
    for proof in [run / "acceptance" / f"proof-{i}" for i in range(20)] + [
        run / "acceptance/proof-after-restart"]:
        check_proof(proof)
    def idle(index):
        resource = read(run / "acceptance" / f"proof-{index}/resource.json")
        return resource["idle_after_verification_and_settle"]["native_memory"]["group"]["worker"]["footprint_bytes"]
    first, last = idle(0), idle(19)
    drift = (last - first) / first
    assert drift <= 0.05
    lifecycle.update(verified_proofs=21, tamper_rejections=63,
                     idle_first_bytes=first, idle_after_request_20_bytes=last,
                     idle_drift_fraction=drift, idle_growth_at_most_5_percent=True)

    run, result, fallback = run_from_log("wp4-final-fallback-proof.log")
    fallback.update(check_proof(run / "acceptance/proof-0"))
    assert read(run / "acceptance/proof-0/worker.json")["observed_stages"]["recursion_metal"]["eval_check_split"] is False
    run, result, limits = run_from_log("wp4-final-limit-controls.log")
    assert result["results"]["status"] == "workload_limit_controls_passed"
    assert {case.get("po2") for case in result["results"]["cases"] if case.get("outcome") == "input_rejected"} >= {13, 22}

    cpu_log = PHASE / "wp4-final-cpu-build.log"
    assert "test result: ok. 5 passed" in cpu_log.read_text()
    cpu_manifest = paths("cpu")["manifest"]
    cpu = read(cpu_manifest)
    assert cpu["source"]["engine_head"] == COMMIT
    linux_path = PHASE / "wp4-linux/result.json"
    linux = read(linux_path)
    assert linux["status"] == "passed" and linux["engine_commit"] == COMMIT
    assert set(linux["checks"].values()) == {"passed"}
    report = {
        "schema_version": 1, "status": "passed", "source_spec_sha256": SPEC_SHA256,
        "engine_commit": COMMIT, "candidate_worker_sha256": worker["binary_sha256"],
        "verifier_sha256": paired["verifier_sha256"],
        "collector_sha256": sha(Path(__file__)),
        "generator_check_log_sha256": sha(generator_log),
        "metal_port_sha256": sha(ENGINE / "risc0/circuit/recursion-sys/kernels/metal/port_eval_check_split.py"),
        "paired_evidence_sha256": sha(paired_path),
        "split_iteration_evidence_sha256": sha(EVIDENCE / "phase2-wp4-split-paired.json"),
        "differentials": {"arithmetic_10m": arithmetic, "hash_10m": hashing},
        "lifecycle": lifecycle, "fallback_proof": fallback, "limit_controls": limits,
        "cpu_only_build": {"log_sha256": sha(cpu_log),
                           "manifest_sha256": sha(cpu_manifest), "unit_tests_passed": 5},
        "linux_feature_paths": {"result_sha256": sha(linux_path),
                                "checks": linux["checks"]},
    }
    path = EVIDENCE / "phase2-wp4-validation.json"
    path.write_text(json.dumps(report, indent=2) + "\n")
    print(path)


if __name__ == "__main__":
    main()
