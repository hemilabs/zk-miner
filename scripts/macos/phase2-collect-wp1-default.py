#!/usr/bin/env python3
"""Bind the default-evalfast worker and tail-split override to verified proofs."""

import argparse
import json
from pathlib import Path

from proof_provenance import ROOT, sha
from worker_provenance import verify_build


def read(path):
    return json.loads(path.read_text())


def proof(run, selected, shader, worker_sha):
    result = read(run / "result.json")
    assert result["status"] == "passed"
    assert result["worker_build"]["binary_sha256"] == worker_sha
    assert result["results"]["verified_proofs"] == 1
    sidecar_path = run / "acceptance/proof-0/worker.json"
    verification_path = run / "acceptance/proof-0/verification.json"
    sidecar, verification = read(sidecar_path), read(verification_path)
    rv = sidecar["observed_stages"]["rv32im_metal"]
    assert rv["evalfast_phase_split"] is selected
    assert rv["kernel_source_sha256"] == shader
    assert rv["cpu_differential_checks"] == sidecar["stats"]["segments"] == 5
    assert verification["verification"] == "passed"
    assert set(verification["negative_tests"]) == {
        "wrong_image", "modified_journal", "corrupt_seal"}
    return {"run": str(run), "result_sha256": sha(run / "result.json"),
            "worker_sidecar_sha256": sha(sidecar_path),
            "verification_sha256": sha(verification_path),
            "selected_evalfast": selected, "cpu_differential_checks": 5}


def lifecycle(run, worker_sha, shader):
    result = read(run / "result.json")
    assert result["status"] == "passed"
    assert result["worker_build"]["binary_sha256"] == worker_sha
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
        assert rv["evalfast_phase_split"] and rv["kernel_source_sha256"] == shader
        assert rv["cpu_differential_checks"] == row["worker"]["stats"]["segments"] > 0
        verification = read(run / "acceptance" / f"proof-{index}" / "verification.json")
        assert verification["verification"] == "passed"
        assert set(verification["negative_tests"]) == {
            "wrong_image", "modified_journal", "corrupt_seal"}
    recovery = read(run / "acceptance/proof-after-restart/verification.json")
    assert recovery["verification"] == "passed"
    assert set(recovery["negative_tests"]) == {
        "wrong_image", "modified_journal", "corrupt_seal"}
    controls = result["results"]
    assert all(controls[key] for key in ("helper_cancel", "worker_timeout", "restart", "shutdown"))
    assert all(any(row.get("case") == case and row.get("status") == "expected_failure"
                   for row in requests) for case in ("helper-cancel", "helper-timeout"))
    drift = idle[-1] / idle[0] - 1
    settled_range = max(idle[7:]) / min(idle[7:]) - 1
    return {"run": str(run), "result_sha256": sha(run / "result.json"),
            "request_ledger_sha256": sha(run / "acceptance/requests.jsonl"),
            "verified_proofs": 21, "tamper_rejections": 63,
            "idle_first_bytes": idle[0], "idle_last_bytes": idle[-1],
            "idle_first_to_last_fraction": drift,
            "idle_post_settle_range_fraction": settled_range,
            "idle_growth_at_most_5_percent": drift <= 0.05,
            "pressure_levels": pressure, "helper_cancel": controls["helper_cancel"],
            "helper_timeout_control_observed": True,
            "worker_timeout": controls["worker_timeout"],
            "restart": controls["restart"], "shutdown": controls["shutdown"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--default", type=Path, required=True)
    parser.add_argument("--fallback", type=Path, required=True)
    parser.add_argument("--lifecycle", type=Path, required=True)
    args = parser.parse_args()
    args.default = args.default.resolve(strict=True)
    args.fallback = args.fallback.resolve(strict=True)
    args.lifecycle = args.lifecycle.resolve(strict=True)
    worker = verify_build("native-rv32im-metal", ROOT.parent / "risc0")
    paired = read(ROOT / "docs/macos/evidence/phase2-wp1-paired.json")
    assert paired["status"] == "passed"
    prior = read(ROOT / "docs/macos/evidence/phase2-wp1-evalfast.json")
    assert worker["source"]["engine_head"] != prior["engine_commit"]
    selected = proof(args.default, True, prior["shader_sha256"], worker["binary_sha256"])
    fallback = proof(args.fallback, False, prior["fallback"]["shader_sha256"], worker["binary_sha256"])
    life = lifecycle(args.lifecycle, worker["binary_sha256"], prior["shader_sha256"])
    report = {"schema_version": 1,
              "status": "passed" if life["idle_growth_at_most_5_percent"] else "memory_gate_failed",
              "source_spec_sha256": "299ebd441aa2e1c0c70f7587a88b8cc32154d0835a0eaea0d807adef11028597",
              "engine_commit": worker["source"]["engine_head"],
              "worker_sha256": worker["binary_sha256"],
              "verifier_sha256": paired["verifier_sha256"],
              "paired_evidence_sha256": sha(ROOT / "docs/macos/evidence/phase2-wp1-paired.json"),
              "collector_sha256": sha(Path(__file__)),
              "default": selected,
              "fallback": {"selector": "RISC0_RV32IM_TAIL_SPLIT=1", **fallback},
              "lifecycle": life}
    output = ROOT / "docs/macos/evidence/phase2-wp1-default.json"
    output.write_text(json.dumps(report, indent=2) + "\n")
    print(output)
    print(report["status"])


if __name__ == "__main__":
    main()
