#!/usr/bin/env python3
"""Collect the timing-only LogUp removal diagnosis; never treat it as proof evidence."""

import csv
import json
from pathlib import Path
from statistics import median

from proof_provenance import ROOT, sha


BASE = ROOT / "target/macos/phase2/wp1-reopen"
EVIDENCE = ROOT / "docs/macos/evidence"
ORDER = ("fallback", "main-only", "fallback", "main-only", "fallback",
         "main-only", "main-only", "fallback", "main-only", "fallback")


def phases(path):
    return [json.loads(line) for line in path.read_text().splitlines()]


def main():
    fallback = BASE / "fallback-timing.metal"
    main_only = BASE / "main-only-timing.metal"
    assert sha(fallback) == sha(ROOT / "target/macos/phase2/wp1/candidate-all.metal")
    assert json.loads(main_only.with_suffix(".json").read_text())["parent_source_sha256"] == sha(fallback)
    assert json.loads(main_only.with_suffix(".json").read_text())["proof_eligible"] is False
    rows = []
    for index, variant in enumerate(ORDER, 1):
        path = BASE / f"{index}-{variant}.jsonl"
        items = phases(path)
        assert items[0]["phase"] == "device"
        assert items[0]["data"]["source_sha256"] == sha(fallback if variant == "fallback" else main_only)
        compiled = next(item["data"] for item in items if item["phase"] == "compiled")
        result = items[-1]["data"]
        assert items[-1]["phase"] == "result" and result["status"] == "timing_only"
        assert "never use for proofs" in result["scope"]
        assert len(result["cases"]) == 1
        case = result["cases"][0]
        assert case["status"] == "timing_only" and case["proof_eligible"] is False
        assert case["cpu_oracle_checked"] is False and case["reuse_deterministic"]
        assert case["guards_preserved"] and case["inputs_unchanged"]
        assert case["po2"] == 20 and case["seed"] == 1
        assert case["command"]["threads_per_threadgroup"] == 256
        assert case["reuse_command"]["threads_per_threadgroup"] == 256
        assert case["command"]["gpu_seconds"] > 0 and case["reuse_command"]["gpu_seconds"] > 0
        rows.append({"order": index, "variant": variant,
                     "first_gpu_seconds": case["command"]["gpu_seconds"],
                     "repeat_gpu_seconds": case["reuse_command"]["gpu_seconds"],
                     "first_wall_seconds": case["gpu_dispatch_seconds"],
                     "repeat_wall_seconds": case["reuse_dispatch_seconds"],
                     "output_sha256": case["output_sha256"],
                     "thread_execution_width": compiled["thread_execution_width"],
                     "max_threads_per_threadgroup": compiled["max_threads_per_threadgroup"],
                     "static_threadgroup_bytes": compiled["static_threadgroup_bytes"],
                     "raw_log_sha256": sha(path)})
    hashes = {variant: {row["output_sha256"] for row in rows if row["variant"] == variant}
              for variant in ("fallback", "main-only")}
    assert all(len(value) == 1 for value in hashes.values()) and hashes["fallback"] != hashes["main-only"]
    pairs = []
    for i in range(0, len(rows), 2):
        pair = rows[i:i+2]
        assert {row["variant"] for row in pair} == {"fallback", "main-only"}
        old = next(row for row in pair if row["variant"] == "fallback")
        new = next(row for row in pair if row["variant"] == "main-only")
        pairs.append({"pair": i // 2 + 1, "order": [row["variant"] for row in pair],
                      "fallback_repeat_gpu_seconds": old["repeat_gpu_seconds"],
                      "main_only_repeat_gpu_seconds": new["repeat_gpu_seconds"],
                      "ratio": old["repeat_gpu_seconds"] / new["repeat_gpu_seconds"],
                      "saved_gpu_seconds": old["repeat_gpu_seconds"] - new["repeat_gpu_seconds"]})
    fallback_median = median(row["repeat_gpu_seconds"] for row in rows if row["variant"] == "fallback")
    main_only_median = median(row["repeat_gpu_seconds"] for row in rows if row["variant"] == "main-only")
    assert max(pair["ratio"] for pair in pairs) < 1.5
    EVIDENCE.mkdir(exist_ok=True)
    csv_path = EVIDENCE / "phase2-wp1-logup-probe.csv"
    with csv_path.open("w", newline="") as output:
        writer = csv.DictWriter(output, fieldnames=list(rows[0]), lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
    report = {
        "schema_version": 1,
        "scope": "timing-only synthetic po2-20 dispatch; never used for proofs; CPU oracle intentionally not checked",
        "fallback_shader_sha256": sha(fallback),
        "main_only_shader_sha256": sha(main_only),
        "main_only_metadata_sha256": sha(main_only.with_suffix(".json")),
        "transform_script_sha256": sha(ROOT / "scripts/macos/phase2-logup-probe.py"),
        "prototype_source_sha256": sha(BASE / "logup-probe-main.rs"),
        "prototype_binary_sha256": sha(BASE / "logup-probe-binary"),
        "threadgroup_size": 256, "po2": 20, "seed": 1,
        "samples": rows, "sample_csv_sha256": sha(csv_path), "pairs": pairs,
        "fallback_repeat_gpu_median_seconds": fallback_median,
        "main_only_repeat_gpu_median_seconds": main_only_median,
        "median_ratio": fallback_median / main_only_median,
        "median_gpu_seconds_saved": fallback_median - main_only_median,
        "diagnosis": "percent-scale improvement; removing LogUp does not confirm a multiples-scale live-state hypothesis",
        "proof_eligible": False,
    }
    out = EVIDENCE / "phase2-wp1-logup-probe.json"
    out.write_text(json.dumps(report, indent=2) + "\n")
    print(out)
    print(csv_path)


if __name__ == "__main__":
    main()
