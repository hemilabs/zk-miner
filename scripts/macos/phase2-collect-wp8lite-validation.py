#!/usr/bin/env python3
"""Bind WP8-lite real proofs, lifecycle and feature checks to one worker."""

import json
from pathlib import Path
import re
import subprocess

from proof_provenance import ROOT, sha
from worker_provenance import paths, verify_build as verify_worker


ENGINE = Path("/Users/dbur/dev/risc0")
PHASE = ROOT / "target/macos/phase2"
EVIDENCE = ROOT / "docs/macos/evidence"
COMMIT = "6521f87c2daf873c54d011a33d48fee8097db924"
SPEC_SHA256 = "a7ab34ce1697757bcb73622aebe0b503d42b38e3a601942f76e90fd5744f581c"
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


def main():
    assert subprocess.check_output(["git", "-C", str(ENGINE), "rev-parse", "HEAD"],
                                   text=True).strip() == COMMIT
    assert subprocess.check_output(["git", "-C", str(ENGINE), "status", "--porcelain"],
                                   text=True).strip() == ""
    spec = Path("/Users/dbur/Downloads/Phase 2 spec Metal proving performance on macOS.md")
    assert sha(spec) == SPEC_SHA256
    worker = verify_worker("native-rv32im-metal", ENGINE)
    paired_path = EVIDENCE / "phase2-wp8lite-paired.json"
    paired = read(paired_path)
    assert paired["status"] == "complete" and paired["engine_commit"] == COMMIT
    assert paired["candidate_worker_sha256"] == worker["binary_sha256"]
    assert paired["verified_proofs"] == 36 and paired["tamper_rejections"] == 108
    assert sha(EVIDENCE / "phase2-wp8lite-paired.csv") == paired["csv_sha256"]
    differentials = {}
    for po2 in (14, 18, 20):
        run, result, record = run_from_log(f"wp8lite-real-po2-{po2}.log")
        assert result["worker_build"]["binary_sha256"] == worker["binary_sha256"]
        assert result["segment_check_cpu"] and result["po2"] == po2
        proof = run / "acceptance/proof-0"
        record.update(check_proof(proof))
        sidecar = read(proof / "worker.json")
        stage = sidecar["observed_stages"]["rv32im_metal"]
        assert sidecar["po2"] == po2
        assert stage["completed_constraint_checks"] == stage["cpu_differential_checks"] == sidecar["stats"]["segments"]
        record.update(segments=sidecar["stats"]["segments"],
                      cpu_differential_checks=stage["cpu_differential_checks"])
        differentials[str(po2)] = record

    run, result, lifecycle = run_from_log("wp8lite-lifecycle.log")
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
    ledger = [json.loads(line) for line in (run / "acceptance/requests.jsonl").read_text().splitlines()]
    cancellations = {}
    for name in ("helper-cancel", "helper-timeout"):
        events = [entry for entry in ledger if entry.get("case") == name]
        assert events[-1]["status"] == "expected_failure"
        assert events[-1]["observed_running_helper"]["phase"] == "wrapping"
        cancellations[name] = {"ledger_event": events[-1], "worker_group_gone": True,
                               "no_owned_helper_after": True}
    identity_times = [float(value) / 1000 for value in re.findall(
        r"identity_p254=([0-9.]+)ms", (run / "test.log").read_text())]
    assert len(identity_times) >= 20
    recent_identity_max = max(identity_times[15:20])
    timeout = cancellations["helper-timeout"]["ledger_event"]
    timeout_after_wrapping_start = (timeout["timeout_seconds"] -
                                    timeout["observed_running_helper"]["total_ms"] / 1000)
    assert timeout_after_wrapping_start > recent_identity_max
    cancellations["helper-timeout"]["phase_evidence"] = {
        "timeout_after_wrapping_start_seconds": timeout_after_wrapping_start,
        "maximum_recent_identity_seconds": recent_identity_max,
        "conclusion": "watchdog reached the wrap after identity_p254",
    }
    lifecycle.update(verified_proofs=21, tamper_rejections=63,
                     idle_first_bytes=first, idle_after_request_20_bytes=last,
                     idle_drift_fraction=drift, idle_growth_at_most_5_percent=True,
                     cancellations=cancellations)

    run, result, limits = run_from_log("wp8lite-limit-controls.log")
    assert result["results"]["status"] == "workload_limit_controls_passed"
    assert {case.get("po2") for case in result["results"]["cases"]
            if case.get("outcome") == "input_rejected"} >= {13, 22}
    parent_log = PHASE / "wp8lite-parent-death.log"
    parent_run = Path(parent_log.read_text().splitlines()[0])
    parent_death = read(parent_run / "result.json")
    assert parent_death["status"] == "passed"
    assert [case["stage"] for case in parent_death["cases"]] == ["identity", "prove"]
    assert all(case["result"] == "helper_exited_without_proof" for case in parent_death["cases"])
    cpu_log = PHASE / "wp8lite-cpu-build.log"
    assert "test result: ok. 5 passed" in cpu_log.read_text()
    cpu_manifest = paths("cpu")["manifest"]
    assert read(cpu_manifest)["source"]["engine_head"] == COMMIT
    linux_path = PHASE / "wp8lite-linux/result.json"
    linux = read(linux_path)
    assert linux["status"] == "passed" and linux["engine_commit"] == COMMIT
    assert set(linux["checks"].values()) == {"passed"}
    report = {
        "schema_version": 1, "status": "passed", "source_spec_sha256": SPEC_SHA256,
        "engine_commit": COMMIT, "candidate_worker_sha256": worker["binary_sha256"],
        "verifier_sha256": paired["verifier_sha256"], "collector_sha256": sha(Path(__file__)),
        "paired_evidence_sha256": sha(paired_path), "differentials": differentials,
        "lifecycle": lifecycle, "limit_controls": limits,
        "parent_death": {"run": str(parent_run), "result_sha256": sha(parent_run / "result.json"),
                         "log_sha256": sha(parent_log), "cases": parent_death["cases"]},
        "cpu_only_build": {"log_sha256": sha(cpu_log), "manifest_sha256": sha(cpu_manifest),
                           "unit_tests_passed": 5},
        "linux_feature_paths": {"result_sha256": sha(linux_path), "checks": linux["checks"]},
    }
    path = EVIDENCE / "phase2-wp8lite-validation.json"
    path.write_text(json.dumps(report, indent=2) + "\n")
    print(path)


if __name__ == "__main__":
    main()
