#!/usr/bin/env python3
"""Seal validation of the retired fold-only path removal on Phase 2 branches."""

import hashlib
import json
from pathlib import Path
import subprocess

from proof_provenance import ROOT, sha
from worker_provenance import verify_build


ENGINE = Path("/Users/dbur/dev/risc0")
BASE = ROOT / "target/macos/phase2/wp1"
EVIDENCE = ROOT / "docs/macos/evidence/phase2-fold-cleanup.json"
ENGINE_COMMIT = "fca0c099582f15729f98af0743f45bc56c217705"
REMOVED_PROBE = ("tools/macos-hybrid/Cargo.toml", "tools/macos-hybrid/Cargo.lock",
                 "scripts/macos/build-hybrid.sh")
TAMPERS = {"wrong_image", "modified_journal", "corrupt_seal"}


def read(path):
    return json.loads(path.read_text())


def run_from_log(name):
    run = Path((BASE / name).read_text().splitlines()[0])
    result = read(run / "result.json")
    assert result["status"] == "passed", (name, result.get("error"))
    return run, result


def checked_proof(run, name):
    location = run / "acceptance" / name
    verification = read(location / "verification.json")
    assert verification["verification"] == "passed"
    assert set(verification["negative_tests"]) == TAMPERS
    return {"worker_sidecar_sha256": sha(location / "worker.json"),
            "verification_sha256": sha(location / "verification.json")}


def main():
    assert subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ENGINE, text=True).strip() == ENGINE_COMMIT
    assert not subprocess.check_output(["git", "diff", "HEAD", "--binary"], cwd=ENGINE)
    assert all(not (ROOT / path).exists() for path in REMOVED_PROBE)
    assert not (ENGINE / "risc0/zkp/src/hal/metal_fold.rs").exists()
    for name in ("risc0/zkvm/Cargo.toml", "risc0/circuit/rv32im/Cargo.toml"):
        assert "metal-hybrid" not in (ENGINE / name).read_text()
    assert "pub fn new_metal(" not in (ENGINE / "risc0/zkvm/src/host/client/prove/local.rs").read_text()
    worker = verify_build("native-rv32im-metal", ENGINE)
    cpu_worker = verify_build("cpu", ENGINE)
    assert worker["source"]["engine_head"] == ENGINE_COMMIT
    assert worker["source"]["engine_working_diff_sha256"] == hashlib.sha256(b"").hexdigest()
    assert worker["binary_sha256"] == "c5f369bb7f76d6bdb61823149997e850bbb47299981be58cde17ae7aff31b7f5"
    old = read(ROOT / "docs/macos/evidence/phase2-wp1-iteration.json")
    assert old["engine_commit"] == "afd4342f90160c60829818dca953bcfe952a5639"
    assert old["worker_sha256"] != worker["binary_sha256"]
    for name in ("fold-cleanup-worker-committed.log", "fold-cleanup-cpu-build.log"):
        assert "test result: ok. 5 passed;" in (BASE / name).read_text()
    controls_log = BASE / "fold-cleanup-proof-controls.log"
    assert "Ran 8 tests" in controls_log.read_text() and "OK" in controls_log.read_text()
    proof_run, proof = run_from_log("fold-cleanup-proof.log")
    assert proof["results"]["verified_proofs"] == 1
    sidecar = read(proof_run / "acceptance/proof-0/worker.json")
    assert sidecar["observed_stages"]["rv32im_metal"]["cpu_differential_checks"] == 1
    assert sidecar["observed_stages"]["rv32im_metal"]["kernel_source_sha256"] == old["shader_sha256"]
    verified = checked_proof(proof_run, "proof-0")
    lifecycle_run, lifecycle = run_from_log("fold-cleanup-lifecycle.log")
    assert lifecycle["results"]["verified_proofs"] == 21
    requests = [json.loads(line) for line in
                (lifecycle_run / "acceptance/requests.jsonl").read_text().splitlines()]
    completed = [row for row in requests if row.get("status") == "complete_independently_verified"]
    assert len(completed) == 21
    for name in [*(f"proof-{index}" for index in range(20)), "proof-after-restart"]:
        checked_proof(lifecycle_run, name)
    steady = completed[:20]
    assert len({row["worker"]["worker_pid"] for row in steady}) == 1
    idle = [row["resources"]["idle_after_verification_and_settle"]["native_memory"]["group"]["worker"]["footprint_bytes"]
            for row in steady]
    drift = idle[-1] / idle[0] - 1
    assert abs(drift) <= 0.05
    pressure = sorted({sample["native_memory"]["pressure_level"] for row in steady
                       for sample in row["resources"]["observations"] if sample.get("native_memory")})
    assert pressure == [1]
    verifier = read(ROOT / "target/macos/verifier-build.json")
    assert verifier["binary_sha256"] == old["verifier_sha256"]
    assert sha(ROOT / "target/macos/verifier/release/hemi-macos-proof") == old["verifier_sha256"]
    report = {
        "schema_version": 1,
        "collector_sha256": sha(Path(__file__)),
        "engine_commit": ENGINE_COMMIT,
        "previous_wp1_engine_commit": old["engine_commit"],
        "worker_sha256": worker["binary_sha256"],
        "cpu_worker_sha256": cpu_worker["binary_sha256"],
        "previous_wp1_worker_sha256": old["worker_sha256"],
        "unchanged_verifier_sha256": old["verifier_sha256"],
        "shader_sha256": old["shader_sha256"],
        "removed_probe_paths": list(REMOVED_PROBE),
        "removed_engine_paths": ["risc0/zkp/src/hal/metal_fold.rs"],
        "retained_verifier_source": "tools/macos-proof/src/main.rs remains pinned to preserve the unchanged external verifier",
        "native_unit_tests": 5,
        "cpu_unit_tests": 5,
        "proof_control_unit_tests": 8,
        "proof_control_log_sha256": sha(controls_log),
        "proof_run": str(proof_run),
        "proof_result_sha256": sha(proof_run / "result.json"),
        "proof": verified,
        "proof_cpu_differential_checks": 1,
        "lifecycle_run": str(lifecycle_run),
        "lifecycle_result_sha256": sha(lifecycle_run / "result.json"),
        "lifecycle_verified_proofs": 21,
        "lifecycle_negative_checks": 63,
        "lifecycle_idle_first_bytes": idle[0],
        "lifecycle_idle_last_bytes": idle[-1],
        "lifecycle_idle_drift_fraction": drift,
        "pressure_levels_observed": pressure,
        "helper_cancel": bool(lifecycle["results"]["helper_cancel"]),
        "worker_timeout": bool(lifecycle["results"]["worker_timeout"]),
        "restart": bool(lifecycle["results"]["restart"]),
        "shutdown": bool(lifecycle["results"]["shutdown"]),
        "linux_feature_compile": "not run: only aarch64-apple-darwin installed in the pinned local toolchain",
        "new_dependencies_or_version_bumps": [],
    }
    EVIDENCE.write_text(json.dumps(report, indent=2) + "\n")
    print(EVIDENCE)


if __name__ == "__main__":
    main()
