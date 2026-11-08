#!/usr/bin/env python3
"""Collect the CPU-checked po2-20 Metal evalfast threadgroup sweep."""

import csv
import json
from pathlib import Path

from proof_provenance import ROOT, sha


ENGINE = Path("/Users/dbur/dev/risc0")
PHASE = ROOT / "target/macos/phase2"
EVIDENCE = ROOT / "docs/macos/evidence"
SHADER = PHASE / "wp1b-sweep.metal"
SIZES = (32, 64, 128, 256)


def events(path):
    return [json.loads(line) for line in path.read_text().splitlines()
            if line.startswith("{")]


def main():
    metadata = json.loads(SHADER.with_suffix(".json").read_text())
    assert metadata["source_sha256"] == sha(SHADER)
    assert metadata["evalfast_stage"] == "through mksm2.py (32 words per phase) and mksub.py"
    assert metadata["threadgroup_bytes"] == 32768
    rows = []
    for size in SIZES:
        path = PHASE / f"wp1b-sweep-{size}.jsonl"
        messages = events(path)
        device = next(item["data"] for item in messages if item["phase"] == "device")
        compiled = next(item["data"] for item in messages
                        if item["phase"] == "compiled" and item["data"]["entry_point"] == "ef_eval_split")
        case = next(item["data"] for item in messages if item["phase"] == "case_complete")
        result = next(item["data"] for item in messages if item["phase"] == "result")
        assert device["source_sha256"] == sha(SHADER)
        assert compiled["static_threadgroup_bytes"] == 32768
        assert case["po2"] == 20 and case["seed"] == 7
        assert case["status"] == "matched" and case["reuse_matched"]
        assert case["guards_preserved"] and case["inputs_unchanged"]
        assert case["command"]["split"]["threads_per_threadgroup"] == size
        assert case["reuse_command"]["split"]["threads_per_threadgroup"] == size
        assert result["status"] == "passed"
        rows.append({
            "threads": size,
            "po2": 20,
            "seed": 7,
            "shader_sha256": sha(SHADER),
            "log_sha256": sha(path),
            "first_split_gpu_seconds": case["command"]["split"]["gpu_seconds"],
            "reuse_split_gpu_seconds": case["reuse_command"]["split"]["gpu_seconds"],
            "output_sha256": case["output_sha256"],
            "static_threadgroup_bytes": compiled["static_threadgroup_bytes"],
            "cpu_matched": True,
            "reuse_matched": True,
        })
    assert len({row["output_sha256"] for row in rows}) == 1
    best = min(rows, key=lambda row: row["reuse_split_gpu_seconds"])
    assert best["threads"] == 256
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    csv_path = EVIDENCE / "phase2-wp1b-sweep.csv"
    with csv_path.open("w", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=list(rows[0]), lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
    report = {
        "schema_version": 1,
        "status": "passed",
        "scope": "po2-20 synthetic CPU oracle and reuse, same shader and seed, 32/64/128/256 threads",
        "engine_commit": "7222459e351a81ecb55ac75f8804edc4c51e08d9",
        "shader_sha256": sha(SHADER),
        "shader_metadata_sha256": sha(SHADER.with_suffix(".json")),
        "generator_sha256": sha(ENGINE / "risc0/circuit/rv32im/metal/port_evalfast.py"),
        "collector_sha256": sha(Path(__file__)),
        "csv_sha256": sha(csv_path),
        "selected_threads": best["threads"],
        "rows": rows,
    }
    path = EVIDENCE / "phase2-wp1b-sweep.json"
    path.write_text(json.dumps(report, indent=2) + "\n")
    print(path)


if __name__ == "__main__":
    main()
