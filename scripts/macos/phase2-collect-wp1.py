#!/usr/bin/env python3
"""Bind the bounded WP1 evaluator trials to exact proofs and GPU timings."""

import argparse
import csv
import hashlib
import json
from pathlib import Path
import subprocess

from proof_provenance import ROOT, sha
from worker_provenance import verify_build


BASE = ROOT / "target/macos/phase2/wp1"
EVIDENCE = ROOT / "docs/macos/evidence"
TAMPERS = {"wrong_image", "modified_journal", "corrupt_seal"}


def read(path):
    return json.loads(path.read_text())


def from_log(name):
    run = Path((BASE / f"{name}.log").read_text().splitlines()[0])
    result = read(run / "result.json")
    assert result["status"] == "passed", (name, result.get("error"))
    return run, result


def check_proof(run):
    verification = read(run / "acceptance/proof-0/verification.json")
    assert verification["verification"] == "passed"
    assert set(verification["negative_tests"]) == TAMPERS
    return read(run / "acceptance/proof-0/worker.json")


def prototype(name):
    shader = BASE / f"{name}.metal"
    lines = BASE / f"{name}-matrix-t256.jsonl"
    phases = [json.loads(line) for line in lines.read_text().splitlines()]
    assert phases[-1]["phase"] == "result" and phases[-1]["data"]["status"] == "passed"
    cases = phases[-1]["data"]["cases"]
    assert [case["po2"] for case in cases] == [4, 8, 14, 18, 20]
    assert all(case["status"] == "matched" and case["reuse_matched"] and
               case["guards_preserved"] for case in cases)
    assert phases[0]["data"]["source_sha256"] == sha(shader)
    compiled = next(phase["data"] for phase in phases if phase["phase"] == "compiled")
    return {"shader_sha256": sha(shader), "metadata_sha256": sha(shader.with_suffix(".json")),
            "raw_log_sha256": sha(lines), "stderr_sha256": sha(BASE / f"{name}-matrix-t256.err"),
            "compiler": compiled,
            "cases": [{key: case[key] for key in ("po2", "domain", "compared_field_elements",
                                           "gpu_dispatch_seconds", "reuse_dispatch_seconds",
                                           "output_sha256", "status")}
                      for case in cases]}


def sweep(prefix, shader):
    rows = []
    for threads in (32, 64, 128, 256):
        path = BASE / "sweep" / f"{prefix}po2-20-t{threads}.jsonl"
        phases = [json.loads(line) for line in path.read_text().splitlines()]
        assert phases[-1]["phase"] == "result" and phases[-1]["data"]["status"] == "passed"
        assert phases[0]["data"]["source_sha256"] == sha(shader)
        case = phases[-1]["data"]["cases"][0]
        assert case["po2"] == 20 and case["status"] == "matched" and case["reuse_matched"]
        assert case["command"]["threads_per_threadgroup"] == threads
        rows.append({"variant": "split" if prefix else "original", "threads": threads,
                     "first_dispatch_seconds": case["gpu_dispatch_seconds"],
                     "repeat_dispatch_seconds": case["reuse_dispatch_seconds"],
                     "output_sha256": case["output_sha256"], "log_sha256": sha(path)})
    assert len({row["output_sha256"] for row in rows}) == 1
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--engine", type=Path, required=True)
    parser.add_argument("--profile", type=Path, required=True)
    parser.add_argument("--cpu-build-log", type=Path, required=True)
    args = parser.parse_args()
    engine = args.engine.resolve()
    worker = verify_build("native-rv32im-metal", engine)
    assert worker["source"]["engine_working_diff_sha256"] == hashlib.sha256(b"").hexdigest()
    shader = BASE / "default.metal"
    assert sha(shader) == sha(BASE / "candidate-all.metal")
    variants = {name: prototype(name) for name in
                ("candidate-all", "candidate-fast-all", "candidate-fast-fp-all")}
    for index in range(5):
        assert len({entry["cases"][index]["output_sha256"] for entry in variants.values()}) == 1
    original_shader = ROOT / "target/macos/rv32im-metal/evaluator.metal"
    baseline_profile = read(EVIDENCE / "phase2-wp0-gpu-profile.json")
    baseline_sidecar = read(Path(baseline_profile["profiles"][0]["run"]) /
                            "acceptance/proof-0/worker.json")
    assert baseline_sidecar["observed_stages"]["rv32im_metal"]["kernel_source_sha256"] == sha(original_shader)
    sweep_rows = sweep("", original_shader)
    sweep_rows += sweep("split-", shader)
    assert len({row["output_sha256"] for row in sweep_rows}) == 1
    assert sweep_rows[-1]["repeat_dispatch_seconds"] == min(
        row["repeat_dispatch_seconds"] for row in sweep_rows if row["variant"] == "split")
    assert variants["candidate-all"]["cases"][-1]["reuse_dispatch_seconds"] < \
        variants["candidate-fast-all"]["cases"][-1]["reuse_dispatch_seconds"]
    assert variants["candidate-all"]["cases"][-1]["reuse_dispatch_seconds"] < \
        variants["candidate-fast-fp-all"]["cases"][-1]["reuse_dispatch_seconds"]
    parent = "09c2f4d2836cbcd88cd29e65b6a6bdd8db262416"
    changed = subprocess.check_output(["git", "diff", parent, worker["source"]["engine_head"],
                                       "--name-only"], cwd=engine, text=True).splitlines()
    tracked = ["risc0/circuit/rv32im/metal/generate.py",
               "risc0/circuit/rv32im/src/prove/hal/metal.rs"]
    added = ["risc0/circuit/rv32im/metal/fast-ext.metal",
             "risc0/circuit/rv32im/metal/split.py"]
    assert set(changed) == set(tracked + added)
    delta = subprocess.check_output(["git", "diff", parent, worker["source"]["engine_head"],
                                     "--binary", "--", *tracked], cwd=engine)
    differential = []
    for po2 in (14, 18, 20):
        run, result = from_log(f"real-po2-{po2}")
        measured = result["worker_build"]
        assert all(measured[key] == worker[key] for key in
                   ("binary_sha256", "metadata_sha256", "local_lock_sha256"))
        assert measured["source"]["engine_head"] == parent
        assert measured["source"]["engine_working_diff_sha256"] == hashlib.sha256(delta).hexdigest()
        assert measured["source"]["engine_untracked_files"] == {
            name: sha(engine / name) for name in added}
        assert result["po2"] == po2 and result["results"]["verified_proofs"] == 1
        sidecar = check_proof(run)
        checks = sidecar["observed_stages"]["rv32im_metal"]["cpu_differential_checks"]
        assert checks == sidecar["stats"]["segments"] > 0
        assert sidecar["observed_stages"]["rv32im_metal"]["kernel_source_sha256"] == sha(shader)
        differential.append({"po2": po2, "run": str(run), "result_sha256": sha(run / "result.json"),
                             "sidecar_sha256": sha(run / "acceptance/proof-0/worker.json"),
                             "verification_sha256": sha(run / "acceptance/proof-0/verification.json"),
                             "segments": checks, "cpu_differential_checks": checks})
    profile = read(args.profile / "result.json")
    assert profile["status"] == "completed" and profile["worker_build"] == worker
    assert len(profile["cases"]) == 2
    baseline = baseline_profile
    profile_rows = []
    for case in profile["cases"]:
        assert case["status"] == "passed"
        run = Path(case["run"])
        result = read(run / "result.json")
        assert result["status"] == "passed" and result["results"]["verified_proofs"] == 1
        sidecar = check_proof(run)
        assert sidecar["stats"]["segments"] == 10
        assert sidecar["observed_stages"]["rv32im_metal"]["kernel_source_sha256"] == sha(shader)
        segment = case["gpu_profile"]["by_stage"]["constraint_evaluation"]
        assert segment["commands"] == 10
        previous = next(item for item in baseline["profiles"] if item["fixture"] == case["name"])
        previous_stage = next(stage for stage in previous["stages"] if stage["stage"] == "constraint_evaluation")
        previous_requests = [json.loads(line) for line in
                             (Path(previous["run"]) / "acceptance/requests.jsonl").read_text().splitlines()]
        previous_completed = [row for row in previous_requests if row["status"] == "complete_independently_verified"]
        assert len(previous_completed) == 1
        previous_elapsed = (previous_completed[0]["timings"]["prove_call_ms"] +
                            previous_completed[0]["timings"]["external_verifier_ms"]) / 1000
        request = [json.loads(line) for line in (run / "acceptance/requests.jsonl").read_text().splitlines()]
        completed = [row for row in request if row["status"] == "complete_independently_verified"]
        assert len(completed) == 1
        elapsed = (completed[0]["timings"]["prove_call_ms"] +
                   completed[0]["timings"]["external_verifier_ms"]) / 1000
        memory = completed[0]["resources"]["idle_after_verification_and_settle"]["native_memory"]
        profile_rows.append({"fixture": case["name"], "run": str(run),
                             "result_sha256": sha(run / "result.json"),
                             "worker_sidecar_sha256": sha(run / "acceptance/proof-0/worker.json"),
                             "complete_seconds": elapsed,
                             "baseline_diagnostic_complete_seconds": previous_elapsed,
                             "constraint_wall_seconds": case["wall_seconds"]["constraint_evaluation"],
                             "constraint_gpu_seconds": segment["gpu_seconds"],
                             "constraint_dispatch_wall_seconds": segment["dispatch_wall_seconds"],
                             "constraint_commands": segment["commands"],
                             "guard_peak_footprint_bytes": memory["guard_peak_footprint_bytes"],
                             "host_reserve_bytes": memory["reserve_bytes"],
                             "pressure_level_after": memory["pressure_level"],
                             "baseline_constraint_wall_seconds": previous_stage["wall_seconds"],
                             "baseline_constraint_gpu_seconds": previous_stage["gpu_seconds"]})
    assert len(profile_rows) == 2
    limit_run, limit = from_log("limits")
    assert limit["results"]["status"] == "workload_limit_controls_passed"
    assert len(limit["results"]["cases"]) == 9
    lifecycle_run, lifecycle = from_log("lifecycle")
    assert lifecycle["results"]["verified_proofs"] == 21
    records = [json.loads(line) for line in (lifecycle_run / "acceptance/requests.jsonl").read_text().splitlines()]
    completed = [row for row in records if row.get("status") == "complete_independently_verified"]
    assert len(completed) == 21
    proof_dirs = [lifecycle_run / "acceptance" / f"proof-{index}" for index in range(20)]
    proof_dirs.append(lifecycle_run / "acceptance/proof-after-restart")
    for proof_dir in proof_dirs:
        verification = read(proof_dir / "verification.json")
        assert verification["verification"] == "passed"
        assert set(verification["negative_tests"]) == TAMPERS
    steady = completed[:20]
    assert len({row["worker"]["worker_pid"] for row in steady}) == 1
    idle = [row["resources"]["idle_after_verification_and_settle"]["native_memory"]["group"]["worker"]["footprint_bytes"]
            for row in steady]
    drift = idle[-1] / idle[0] - 1
    assert abs(drift) <= 0.05
    pressure = sorted({sample["native_memory"]["pressure_level"] for row in steady
                       for sample in row["resources"]["observations"] if sample.get("native_memory")})
    assert pressure == [1]
    assert "test result: ok. 5 passed;" in args.cpu_build_log.read_text()
    assert "test result: ok. 5 passed;" in (BASE / "worker-build-committed.log").read_text()
    tested_source = BASE / "prototype-tool-tested.rs"
    formatted_source = BASE / "prototype-tool-tested-formatted.rs"
    tool_binary = BASE / "prototype-build/release/hemi-macos-rv32im-metal-prototype"
    assert sha(tested_source) == sha(BASE / "prototype-tool/src/main.rs")
    assert sha(formatted_source) == sha(ROOT / "tools/macos-rv32im-metal/src/main.rs")
    assert sha(tool_binary) == "00826db1d6ce1fd5e82aea662d070f19e780f8df2ff68e9fe6ecdd420ad3a08b"
    EVIDENCE.mkdir(exist_ok=True)
    csv_path = EVIDENCE / "phase2-wp1-threadgroups.csv"
    with csv_path.open("w", newline="") as output:
        writer = csv.DictWriter(output, fieldnames=list(sweep_rows[0]), lineterminator="\n")
        writer.writeheader()
        writer.writerows(sweep_rows)
    report = {
        "schema_version": 1, "status": "performance_gate_missed",
        "scope": "bounded WP1 split, reduction, and threadgroup iterations; one diagnostic 10M proof per fixture, not a five-pair campaign",
        "engine_commit": worker["source"]["engine_head"],
        "worker_sha256": worker["binary_sha256"],
        "verifier_sha256": profile["verifier_build"]["binary_sha256"],
        "shader_sha256": sha(shader), "shader_metadata_sha256": sha(shader.with_suffix(".json")),
        "collector_sha256": sha(Path(__file__)),
        "original_baseline": {"worker_sha256": read(EVIDENCE / "phase2-wp0-baseline.json")["worker_sha256"],
                              "profile_sha256": sha(EVIDENCE / "phase2-wp0-gpu-profile.json")},
        "prototype": {"tested_tool_source_sha256": sha(tested_source),
                      "committed_tool_source_sha256": sha(ROOT / "tools/macos-rv32im-metal/src/main.rs"),
                      "tested_tool_binary_sha256": sha(tool_binary),
                      "tested_source_rustfmt_matches_committed": True,
                      "variants": variants, "threadgroups": sweep_rows, "threadgroup_csv_sha256": sha(csv_path)},
        "real_witness_differentials": differential,
        "precommit_tracked_diff_sha256": hashlib.sha256(delta).hexdigest(),
        "precommit_untracked_files": {name: sha(engine / name) for name in added},
        "diagnostic_profiles": profile_rows, "profile_result_sha256": sha(args.profile / "result.json"),
        "hash_profile_host_snapshot": {"sha256": sha(BASE / "host-snapshot-hash.json"),
                                       "observation": read(BASE / "host-snapshot-hash.json")},
        "validation": {"native_unit_tests": 5, "cpu_unit_tests": 5,
                       "limit_rejections": len(limit["results"]["cases"]),
                       "limits_run": str(limit_run), "limits_result_sha256": sha(limit_run / "result.json"),
                       "lifecycle_run": str(lifecycle_run),
                       "lifecycle_result_sha256": sha(lifecycle_run / "result.json"),
                       "lifecycle_verified_proofs": 21, "lifecycle_negative_checks": 63,
                       "lifecycle_idle_first_bytes": idle[0], "lifecycle_idle_last_bytes": idle[-1],
                       "lifecycle_idle_min_bytes": min(idle), "lifecycle_idle_max_bytes": max(idle),
                       "lifecycle_idle_drift_fraction": drift, "pressure_levels_observed": pressure,
                       "helper_cancel": bool(lifecycle["results"]["helper_cancel"]),
                       "helper_timeout": bool(lifecycle["results"]["helper_timeout"]),
                       "worker_timeout": bool(lifecycle["results"]["worker_timeout"]),
                       "restart": bool(lifecycle["results"]["restart"]),
                       "shutdown": bool(lifecycle["results"]["shutdown"])},
        "gate": {"segment_wall_limit_seconds": 2.0,
                 "observed_arithmetic_per_segment_seconds": profile_rows[0]["constraint_wall_seconds"] / 10,
                 "observed_hash_per_segment_seconds": profile_rows[1]["constraint_wall_seconds"] / 10,
                 "paired_10m_saving_gate_seconds": 25.0,
                 "paired_campaign": "not run: per-segment gate already missed in the bounded iteration"},
        "linux_feature_compile": "not run: only aarch64-apple-darwin installed in the pinned local toolchain",
        "new_dependencies_or_version_bumps": [],
    }
    assert all(row["constraint_wall_seconds"] / 10 > 2.0 for row in profile_rows)
    out = EVIDENCE / "phase2-wp1-iteration.json"
    out.write_text(json.dumps(report, indent=2) + "\n")
    print(out)
    print(csv_path)


if __name__ == "__main__":
    main()
