#!/usr/bin/env python3
"""Preserve the bounded first WP8-lite iteration and its stopped campaign."""

import json
from pathlib import Path
from statistics import median

from proof_provenance import ROOT, sha


RUN = ROOT / "target/macos/phase2/wp8lite-pairs/b74efa16cabe4f758032dcc13998c79a"
EVIDENCE = ROOT / "docs/macos/evidence/phase2-wp8lite-iteration1.json"


def main():
    campaign = json.loads((RUN / "result.json").read_text())
    assert campaign["status"] == "failed" and len(campaign["cases"]) == 2
    arithmetic, hashing = campaign["cases"]
    assert arithmetic["fixture"] == "arithmetic-10m" and arithmetic["status"] == "passed"
    assert hashing["fixture"] == "hash-10m" and hashing["status"] == "failed"
    assert campaign["engine_commit"] == "cd018ee7281d58ab529d04b1ee8c4ce8a9cfa8d2"
    assert sha(ROOT / "target/macos/phase2/wp8lite-iter1-worker") == campaign["candidate_worker_sha256"]
    assert sha(ROOT / "target/macos/phase2/wp8lite-iter1-prover") == json.loads((
        Path(arithmetic["run"]) / "result.json").read_text())["bundle"]["files"]["prover"]
    result = json.loads((Path(arithmetic["run"]) / "result.json").read_text())
    assert result["status"] == "passed" and len(result["results"]["rows"]) == 12
    times = {}
    for arm in (0, 1):
        values = [(row["timings"]["prove_call_ms"] + row["timings"]["external_verifier_ms"]) / 1000
                  for row in result["results"]["rows"] if row["case"] == arm and not row["warmup"]]
        assert len(values) == 5
        times["wp1b_baseline" if arm == 0 else "wp8lite_first"] = values
    saving = median(times["wp1b_baseline"]) - median(times["wp8lite_first"])
    report = {
        "schema_version": 1,
        "status": "diagnostic_stopped_after_arithmetic_gate_miss",
        "reason": "The five-pair arithmetic median saved less than the required 1.5 seconds; the hash harness was stopped before completing its fixture.",
        "source_spec_sha256": "a7ab34ce1697757bcb73622aebe0b503d42b38e3a601942f76e90fd5744f581c",
        "engine_commit": campaign["engine_commit"],
        "campaign_run": str(RUN), "campaign_result_sha256": sha(RUN / "result.json"),
        "arithmetic_result_sha256": sha(Path(arithmetic["run"]) / "result.json"),
        "baseline_worker_sha256": campaign["baseline_worker_sha256"],
        "candidate_worker_sha256": campaign["candidate_worker_sha256"],
        "helper_manifest_sha256": campaign["helper_manifest_sha256"],
        "verified_arithmetic_proofs": 12,
        "arithmetic_median_complete_seconds": {arm: median(values) for arm, values in times.items()},
        "arithmetic_saving_seconds": saving,
        "arithmetic_complete_seconds": times,
        "hash_fixture_status": hashing["status"],
    }
    EVIDENCE.write_text(json.dumps(report, indent=2) + "\n")
    print(EVIDENCE)


if __name__ == "__main__":
    main()
