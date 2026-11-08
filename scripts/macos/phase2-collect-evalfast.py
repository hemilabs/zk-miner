#!/usr/bin/env python3
"""Collect the reopened WP1 evalfast port's exact and diagnostic evidence."""

import json
from pathlib import Path
from statistics import median

from proof_provenance import ROOT, sha
from worker_provenance import verify_build


BASE = ROOT / "target/macos/phase2/wp1-reopen"
EVIDENCE = ROOT / "docs/macos/evidence"


def read(path):
    return json.loads(path.read_text())


def run_from_log(name):
    path = BASE / name
    run = Path(path.read_text().splitlines()[0])
    result = read(run / "result.json")
    assert result["status"] == "passed", (name, result.get("error"))
    return run, result


def synthetic(name, po2, seed, threads, shader):
    path = BASE / name
    phases = [json.loads(line) for line in path.read_text().splitlines()]
    assert phases[0]["phase"] == "device"
    assert phases[0]["data"]["source_sha256"] == sha(shader)
    compiled = [row["data"] for row in phases if row["phase"] == "compiled"]
    assert [row["entry_point"] for row in compiled] == ["ef_prep", "ef_eval_split", "ef_combine"]
    assert all(row["max_threads_per_threadgroup"] >= threads for row in compiled)
    result = phases[-1]
    assert result["phase"] == "result" and result["data"]["status"] == "passed"
    assert len(result["data"]["cases"]) == 1
    case = result["data"]["cases"][0]
    assert case["po2"] == po2 and case["seed"] == seed
    assert case["status"] == "matched" and case["reuse_matched"]
    assert case["guards_preserved"] and case["inputs_unchanged"]
    assert case["compared_field_elements"] == case["domain"] * 4
    assert case["command"]["split"]["threads_per_threadgroup"] == threads
    assert case["reuse_command"]["gpu_seconds"] > 0
    return {"po2": po2, "seed": seed, "threads": threads,
            "gpu_seconds": case["reuse_command"]["gpu_seconds"],
            "output_sha256": case["output_sha256"], "raw_log_sha256": sha(path)}


def proof(name, shader_hash):
    run, result = run_from_log(name)
    sidecar = read(run / "acceptance/proof-0/worker.json")
    verification = read(run / "acceptance/proof-0/verification.json")
    assert verification["verification"] == "passed"
    assert set(verification["negative_tests"]) == {
        "wrong_image", "modified_journal", "corrupt_seal"}
    assert result["results"]["verified_proofs"] == 1
    rv = sidecar["observed_stages"]["rv32im_metal"]
    assert rv["evalfast_phase_split"] and rv["threads_per_threadgroup"] == 256
    assert rv["kernel_source_sha256"] == shader_hash
    assert rv["cpu_differential_checks"] == sidecar["stats"]["segments"] > 0
    assert all(rv["gpu_kernels"][f"segment/{kernel}"]["commands"] == sidecar["stats"]["segments"]
               for kernel in ("ef_prep", "ef_eval_split", "ef_combine"))
    return {"po2": result["po2"], "run": str(run),
            "segments": sidecar["stats"]["segments"],
            "cpu_differential_checks": rv["cpu_differential_checks"],
            "result_sha256": sha(run / "result.json"),
            "worker_sidecar_sha256": sha(run / "acceptance/proof-0/worker.json"),
            "verification_sha256": sha(run / "acceptance/proof-0/verification.json")}


def complete_request(run):
    rows = [json.loads(line) for line in (run / "acceptance/requests.jsonl").read_text().splitlines()]
    complete = [row for row in rows if row["status"] == "complete_independently_verified"]
    assert len(complete) == 1
    return complete[0]


def main():
    engine = ROOT.parent / "risc0"
    worker = verify_build("native-rv32im-metal", engine)
    shader = BASE / "evalfast-phase-split-wide.metal"
    metadata = read(shader.with_suffix(".json"))
    assert metadata["phase_split"] and not metadata["proof_eligible"]
    assert metadata["entry_points"] == ["ef_prep", "ef_eval_split", "ef_combine"]
    shader_hash = sha(shader)
    assert shader_hash == metadata["source_sha256"]
    built_shaders = list((ROOT / "target/macos/worker-native-rv32im-metal/release/build").glob(
        "risc0-circuit-rv32im-*/out/rv32im-evalfast.metal"))
    assert len(built_shaders) == 1 and sha(built_shaders[0]) == shader_hash
    tool_source = ROOT / "tools/macos-rv32im-metal/src/main.rs"
    assert sha(tool_source) == sha(ROOT / "target/macos/phase2/wp1/prototype-tool/src/main.rs")
    tool_binary = ROOT / "target/macos/phase2/wp1/prototype-build/release/hemi-macos-rv32im-metal-prototype"
    original = read(EVIDENCE / "phase2-wp1-iteration.json")
    prior = {row["fixture"]: row for row in original["diagnostic_profiles"]}
    synthetic_rows = [synthetic(name, po2, seed, threads, shader) for name, po2, seed, threads in (
        ("evalfast-wide-po2-12.jsonl", 12, 1, 256),
        ("evalfast-wide-po2-20.jsonl", 20, 1, 256),
        ("evalfast-wide-po2-20-512-s2.jsonl", 20, 2, 512))]
    assert synthetic_rows[1]["gpu_seconds"] <= 2.0
    assert synthetic_rows[1]["output_sha256"] == original["prototype"]["variants"]["candidate-all"]["cases"][-1]["output_sha256"]
    real = [proof(f"real-po2-{po2}.log", shader_hash) for po2 in (14, 18, 20)]
    fallback_run, fallback_result = run_from_log("fallback-po2-14.log")
    fallback_sidecar = read(fallback_run / "acceptance/proof-0/worker.json")
    fallback_rv = fallback_sidecar["observed_stages"]["rv32im_metal"]
    assert fallback_result["results"]["verified_proofs"] == 1
    assert not fallback_rv["evalfast_phase_split"]
    assert fallback_rv["kernel_source_sha256"] == original["shader_sha256"]
    assert fallback_rv["cpu_differential_checks"] == fallback_sidecar["stats"]["segments"] > 0
    fallback_verification = read(fallback_run / "acceptance/proof-0/verification.json")
    assert fallback_verification["verification"] == "passed"
    assert set(fallback_verification["negative_tests"]) == {
        "wrong_image", "modified_journal", "corrupt_seal"}
    limit_run, limit_result = run_from_log("limit-controls.log")
    assert limit_result["results"]["status"] == "workload_limit_controls_passed"
    assert len(limit_result["results"]["cases"]) == 9
    profile_path = Path((BASE / "profile-10m.log").read_text().splitlines()[0]) / "result.json"
    profile = read(profile_path)
    assert profile["status"] == "completed" and profile["worker_build"] == worker
    comparisons = []
    for case in profile["cases"]:
        assert case["status"] == "passed"
        run = Path(case["run"])
        result = read(run / "result.json")
        assert result["status"] == "passed" and result["results"]["verified_proofs"] == 1
        sidecar = read(run / "acceptance/proof-0/worker.json")
        rv = sidecar["observed_stages"]["rv32im_metal"]
        assert rv["kernel_source_sha256"] == shader_hash and rv["evalfast_phase_split"]
        assert sidecar["stats"]["segments"] == 10
        verification = read(run / "acceptance/proof-0/verification.json")
        assert verification["verification"] == "passed"
        assert set(verification["negative_tests"]) == {
            "wrong_image", "modified_journal", "corrupt_seal"}
        stage = case["gpu_profile"]["by_stage"]["constraint_evaluation"]
        assert stage["commands"] == 30
        split_gpu = [row["gpu_ms"] / 1000 for row in case["gpu_profile"]["commands"]
                     if row["kernel"] == "ef_eval_split" and row["segment"] >= 0]
        assert len(split_gpu) == 10 and max(split_gpu) <= 2.0
        earlier = prior[case["name"]]
        wall = case["wall_seconds"]["constraint_evaluation"]
        request = complete_request(run)
        timing = request["timings"]
        total = (timing["prove_call_ms"] + timing["external_verifier_ms"]) / 1000
        reserve = request["resources"]["idle_after_verification_and_settle"]["native_memory"]["reserve_bytes"]
        assert reserve == earlier["host_reserve_bytes"] == 12 * 1024**3
        comparisons.append({"fixture": case["name"], "run": str(run),
            "result_sha256": sha(run / "result.json"),
            "worker_sidecar_sha256": sha(run / "acceptance/proof-0/worker.json"),
            "constraint_wall_seconds": wall, "constraint_gpu_seconds": stage["gpu_seconds"],
            "evalfast_segment_gpu_median_seconds": median(split_gpu),
            "evalfast_segment_gpu_min_seconds": min(split_gpu),
            "evalfast_segment_gpu_max_seconds": max(split_gpu),
            "complete_seconds": total,
            "tail_split_constraint_wall_seconds": earlier["constraint_wall_seconds"],
            "tail_split_complete_seconds": earlier["complete_seconds"],
            "constraint_wall_saved_seconds": earlier["constraint_wall_seconds"] - wall,
            "complete_saved_seconds": earlier["complete_seconds"] - total})
    assert {row["fixture"] for row in comparisons} == {"arithmetic-10m", "hash-10m"}
    assert all(row["complete_saved_seconds"] >= 25 for row in comparisons)
    lifecycle_run, lifecycle_result = run_from_log("lifecycle-20.log")
    assert lifecycle_result["results"]["verified_proofs"] == 21
    requests = [json.loads(line) for line in
                (lifecycle_run / "acceptance/requests.jsonl").read_text().splitlines()]
    completed = [row for row in requests if row.get("status") == "complete_independently_verified"]
    assert len(completed) == 21
    steady = completed[:20]
    assert len({row["worker"]["worker_pid"] for row in steady}) == 1
    idle = [row["resources"]["idle_after_verification_and_settle"]["native_memory"]
            ["group"]["worker"]["footprint_bytes"] for row in steady]
    pressure = sorted({sample["native_memory"]["pressure_level"] for row in steady
                       for sample in row["resources"]["observations"] if sample.get("native_memory")})
    assert pressure == [1]
    assert idle[-1] <= idle[0]
    assert max(idle[7:]) / min(idle[7:]) - 1 <= 0.05
    proof_dirs = [lifecycle_run / "acceptance" / f"proof-{index}" for index in range(20)]
    proof_dirs.append(lifecycle_run / "acceptance/proof-after-restart")
    for directory in proof_dirs:
        verification = read(directory / "verification.json")
        assert verification["verification"] == "passed"
        assert set(verification["negative_tests"]) == {
            "wrong_image", "modified_journal", "corrupt_seal"}
        sidecar = read(directory / "worker.json")
        rv = sidecar["observed_stages"]["rv32im_metal"]
        assert rv["evalfast_phase_split"] and rv["kernel_source_sha256"] == shader_hash
        assert rv["cpu_differential_checks"] == sidecar["stats"]["segments"] > 0
    controls = lifecycle_result["results"]
    assert all(controls[key] for key in ("helper_cancel", "worker_timeout", "restart", "shutdown"))
    assert all(any(row.get("case") == case and row.get("status") == "expected_failure"
                   for row in requests) for case in ("helper-cancel", "helper-timeout"))
    first_run = Path((BASE / "lifecycle-20-timeout10.log").read_text().splitlines()[0])
    first_result = read(first_run / "result.json")
    assert first_result["status"] == "failed"
    first_requests = [json.loads(line) for line in
                      (first_run / "acceptance/requests.jsonl").read_text().splitlines()]
    assert len([row for row in first_requests if row.get("status") == "complete_independently_verified"]) == 20
    calibration_run = Path((BASE / "lifecycle-timeout-calibration.log").read_text().splitlines()[0])
    calibration = read(calibration_run / "result.json")
    assert calibration["status"] == "passed" and calibration["results"]["verified_proofs"] == 4
    lifecycle = {"run": str(lifecycle_run),
        "result_sha256": sha(lifecycle_run / "result.json"),
        "verified_proofs": 21, "negative_checks": 63,
        "idle_first_bytes": idle[0], "idle_last_bytes": idle[-1],
        "idle_min_bytes": min(idle), "idle_max_bytes": max(idle),
        "first_to_last_drift_fraction": idle[-1] / idle[0] - 1,
        "post_settle_max_to_min_fraction": max(idle[7:]) / min(idle[7:]) - 1,
        "pressure_levels_observed": pressure,
        "helper_cancel": controls["helper_cancel"],
        "helper_timeout": controls["helper_timeout"],
        "helper_timeout_control_observed": True,
        "worker_timeout": controls["worker_timeout"],
        "restart": controls["restart"], "shutdown": controls["shutdown"],
        "timeout_calibration": {"run": str(calibration_run),
            "result_sha256": sha(calibration_run / "result.json"), "verified_proofs": 4},
        "initial_control_failure": {
            "run": str(first_run), "result_sha256": sha(first_run / "result.json"),
            "steady_verified_proofs": 20,
            "cause": "10-second watchdog captured a segments_complete sidecar before RV32IM counters were populated; the harness validation panicked"}}
    report = {"schema_version": 1, "status": "measured",
        "scope": "isolated exact CPU differentials plus single verified 10M diagnostics; not a warm median",
        "engine_commit": worker["source"]["engine_head"],
        "worker_sha256": worker["binary_sha256"],
        "shader_sha256": shader_hash, "shader_metadata_sha256": sha(shader.with_suffix(".json")),
        "worker_embedded_shader_path": str(built_shaders[0]),
        "generator_sha256": sha(engine / "risc0/circuit/rv32im/metal/port_evalfast.py"),
        "acceptance_runner_sha256": sha(ROOT / "scripts/macos/test-native-worker.py"),
        "prototype_source_sha256": sha(tool_source),
        "prototype_binary_sha256": sha(tool_binary),
        "collector_sha256": sha(Path(__file__)), "synthetic": synthetic_rows,
        "real_witness_differentials": real, "diagnostic_profiles": comparisons,
        "lifecycle": lifecycle,
        "limit_controls": {"run": str(limit_run),
                           "result_sha256": sha(limit_run / "result.json"),
                           "rejections": 9},
        "profile_result_sha256": sha(profile_path),
        "gate": {"po2_20_synthetic_under_2_seconds": True,
                 "both_10m_savings_over_25_seconds": True,
                 "real_witness_differential": True,
                 "lifecycle": True},
        "fallback": {"selector": "leave RISC0_RV32IM_EVALFAST unset",
                     "shader_sha256": fallback_rv["kernel_source_sha256"],
                     "run": str(fallback_run),
                     "result_sha256": sha(fallback_run / "result.json"),
                     "worker_sidecar_sha256": sha(fallback_run / "acceptance/proof-0/worker.json"),
                     "cpu_differential_checks": fallback_rv["cpu_differential_checks"]}}
    EVIDENCE.mkdir(exist_ok=True)
    output = EVIDENCE / "phase2-wp1-evalfast.json"
    output.write_text(json.dumps(report, indent=2) + "\n")
    print(output)


if __name__ == "__main__":
    main()
