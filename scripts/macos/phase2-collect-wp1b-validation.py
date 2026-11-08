#!/usr/bin/env python3
"""Bind WP1b differentials, fallback, lifecycle and feature checks to one worker."""

import json
from pathlib import Path
import subprocess

from proof_provenance import ROOT, sha
from worker_provenance import paths, verify_build as verify_worker


ENGINE = Path("/Users/dbur/dev/risc0")
PHASE = ROOT / "target/macos/phase2"
EVIDENCE = ROOT / "docs/macos/evidence"
COMMIT = "7222459e351a81ecb55ac75f8804edc4c51e08d9"
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


def differential(po2, worker_sha, shader_sha):
    run, result, record = run_from_log(f"wp1b-final-real-po2-{po2}.log")
    assert result["worker_build"]["source"]["engine_head"] == COMMIT
    assert result["worker_build"]["binary_sha256"] == worker_sha
    assert result["segment_check_cpu"] and result["po2"] == po2
    proof = run / "acceptance/proof-0"
    record.update(check_proof(proof))
    sidecar = read(proof / "worker.json")
    stage = sidecar["observed_stages"]["rv32im_metal"]
    assert sidecar["po2"] == po2
    assert stage["evalfast_phase_split"] and stage["threads_per_threadgroup"] == 256
    assert stage["kernel_source_sha256"] == shader_sha
    assert stage["completed_constraint_checks"] == stage["cpu_differential_checks"] == sidecar["stats"]["segments"]
    record.update(po2=po2, segments=sidecar["stats"]["segments"],
                  cpu_differential_checks=stage["cpu_differential_checks"])
    return record


def main():
    assert subprocess.check_output(["git", "-C", str(ENGINE), "rev-parse", "HEAD"],
                                   text=True).strip() == COMMIT
    assert subprocess.check_output(["git", "-C", str(ENGINE), "status", "--porcelain"],
                                   text=True).strip() == ""
    spec = Path("/Users/dbur/Downloads/Phase 2 spec Metal proving performance on macOS.md")
    assert sha(spec) == SPEC_SHA256
    worker = verify_worker("native-rv32im-metal", ENGINE)
    paired_path = EVIDENCE / "phase2-wp1b-paired.json"
    paired = read(paired_path)
    assert paired["status"] == "complete" and paired["evalfast_gpu_gate_10m"]
    assert paired["complete_saving_gate_10m"] and paired["engine_commit"] == COMMIT
    assert paired["candidate_worker_sha256"] == worker["binary_sha256"]
    assert paired["verified_proofs"] == 36 and paired["tamper_rejections"] == 108
    assert paired["all_peaks_below_32_gib"] and paired["normal_pressure_all_rows"]
    assert sha(EVIDENCE / "phase2-wp1b-paired.csv") == paired["csv_sha256"]
    shader_sha = next(row["shader_sha256"] for row in paired["fixtures"][0]["rows"]
                      if row["arm"] == "wp1b_evalfast")
    sweep_path = EVIDENCE / "phase2-wp1b-sweep.json"
    sweep = read(sweep_path)
    assert sweep["status"] == "passed" and sweep["selected_threads"] == 256
    assert sweep["shader_sha256"] == shader_sha
    assert sha(EVIDENCE / "phase2-wp1b-sweep.csv") == sweep["csv_sha256"]
    generator_log = PHASE / "wp1b-final-generator-check.log"
    assert "regen: kernels/cuda/eval_check_ef.cu is up to date" in generator_log.read_text()
    differentials = {str(po2): differential(po2, worker["binary_sha256"], shader_sha)
                     for po2 in (14, 18, 20)}

    run, result, lifecycle = run_from_log("wp1b-final-lifecycle.log")
    assert result["worker_build"]["binary_sha256"] == worker["binary_sha256"]
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

    run, result, fallback = run_from_log("wp1b-final-fallback-proof.log")
    fallback.update(check_proof(run / "acceptance/proof-0"))
    sidecar = read(run / "acceptance/proof-0/worker.json")
    assert sidecar["observed_stages"]["rv32im_metal"]["evalfast_phase_split"] is False
    run, result, limits = run_from_log("wp1b-final-limit-controls.log")
    assert result["results"]["status"] == "workload_limit_controls_passed"
    assert {case.get("po2") for case in result["results"]["cases"]
            if case.get("outcome") == "input_rejected"} >= {13, 22}

    cpu_log = PHASE / "wp1b-final-cpu-build.log"
    assert "test result: ok. 5 passed" in cpu_log.read_text()
    cpu_manifest = paths("cpu")["manifest"]
    assert read(cpu_manifest)["source"]["engine_head"] == COMMIT
    linux_path = PHASE / "wp1b-linux/result.json"
    linux = read(linux_path)
    assert linux["status"] == "passed" and linux["engine_commit"] == COMMIT
    assert set(linux["checks"].values()) == {"passed"}
    report = {
        "schema_version": 1, "status": "passed", "source_spec_sha256": SPEC_SHA256,
        "engine_commit": COMMIT, "candidate_worker_sha256": worker["binary_sha256"],
        "verifier_sha256": paired["verifier_sha256"],
        "collector_sha256": sha(Path(__file__)),
        "generator_check_log_sha256": sha(generator_log),
        "metal_port_sha256": sha(ENGINE / "risc0/circuit/rv32im/metal/port_evalfast.py"),
        "paired_evidence_sha256": sha(paired_path),
        "sweep_evidence_sha256": sha(sweep_path),
        "differentials": differentials,
        "lifecycle": lifecycle, "fallback_proof": fallback, "limit_controls": limits,
        "cpu_only_build": {"log_sha256": sha(cpu_log),
                           "manifest_sha256": sha(cpu_manifest), "unit_tests_passed": 5},
        "linux_feature_paths": {"result_sha256": sha(linux_path),
                                "checks": linux["checks"]},
    }
    path = EVIDENCE / "phase2-wp1b-validation.json"
    path.write_text(json.dumps(report, indent=2) + "\n")
    print(path)


if __name__ == "__main__":
    main()
