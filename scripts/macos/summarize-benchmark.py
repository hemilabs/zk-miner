#!/usr/bin/env python3
"""Validate and summarize a finalized paired CPU/Metal complete-proof campaign."""
import argparse
from collections import Counter
import csv
from datetime import datetime, timezone
import fcntl
import hashlib
import io
import json
import math
from pathlib import Path
import re
import statistics
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
BASE = ROOT / "target/macos"
COMPLETE = "complete_independently_verified"
TIME_METRICS = ("execution_and_segment_ms", "recursion_ms", "identity_and_emulated_wrap_ms",
                "worker_verification_ms", "worker_total_ms", "prove_call_ms", "external_verifier_ms",
                "identity_p254_diagnostic_ms", "shrink_wrap_diagnostic_ms")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def read_json(path):
    return json.loads(Path(path).read_text())


def read_rows(path):
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def artifact(path):
    return {"path": str(path.resolve()), "sha256": sha(path), "bytes": path.stat().st_size}


def finite(value, label, positive=False):
    require(type(value) in (int, float) and math.isfinite(value) and (value > 0 if positive else value >= 0),
            f"{label} must be finite and {'positive' if positive else 'nonnegative'}")
    return value


def validate_schedule(plan, rows, result):
    require(plan["schema_version"] == 1, "unsupported benchmark plan schema")
    expected_fixed = {"worker_kind": "metal", "workload": "fibonacci", "po2": 18, "staging_bytes": 524288,
                      "repeat": 1, "proof_only": True, "context": "colima-hemi-macos-cpu", "rayon_threads": 6,
                      "helper_cpus": 6, "helper_memory_bytes": 24 * 1024**3, "vm_cpus": 6, "vm_memory_bytes": 32 * 1024**3}
    require(plan["fixed_settings"] == expected_fixed, "benchmark fixed settings differ from the reviewed comparison")
    slots = plan["trials"]
    require(len(slots) % 2 == 0, "unpaired trial plan")
    samples = len(slots) // 2 - 1
    require(5 <= samples <= 20, "benchmark requires 5..20 measured pairs plus one warmup per mode")
    expected = [{"index": index, "phase": "warmup" if sample == 0 else "measured", "mode": mode, "sample": sample}
                for index, (sample, mode) in enumerate((sample, mode) for sample in range(samples + 1) for mode in ("cpu", "metal"))]
    require(slots == expected, "trial order differs from declared warmups and alternating CPU/Metal pairs")
    require(len(rows) <= len(slots), "unexpected extra trial or retry")
    seen = set()
    for index, row in enumerate(rows):
        require(all(row.get(key) == value for key, value in slots[index].items()), "trial ledger is not an ordered prefix of the plan")
        require(row.get("status") in (COMPLETE, "failed"), "trial is not terminal")
        finite(row["elapsed_seconds"], "trial elapsed seconds")
        if row.get("run_id") is not None:
            require(re.fullmatch(r"[a-f0-9]{32}", row["run_id"]) and row["run_id"] not in seen, "invalid or duplicate acceptance run ID")
            seen.add(row["run_id"])
        if row["status"] == COMPLETE:
            require(row.get("returncode") == 0 and row.get("error") is None and row.get("run_id") is not None,
                    "successful trial has a failure or missing acceptance run")
        else:
            require(index == len(rows) - 1, "campaign continued or retried after a failed trial")
    completed = sum(row["status"] == COMPLETE for row in rows)
    failed = len(rows) - completed
    require(result["status"] in ("complete", "failed")
            and result["completed_trials"] == completed and result["failed_trials"] == failed
            and result["unattempted_trials"] == len(slots) - len(rows), "final campaign counts differ from trial ledger")
    if result["status"] == "complete":
        require(len(rows) == len(slots) and failed == 0 and result["source_inputs_unchanged"] is True
                and result.get("error") is None, "incomplete or changed-source campaign claims completion")
    return samples


def describe(values):
    require(values, "cannot summarize an empty sample")
    for value in values:
        finite(value, "statistical sample", positive=True)
    return {"n": len(values), "median": statistics.median(values), "mean": statistics.mean(values),
            "minimum": min(values), "maximum": max(values),
            "sample_standard_deviation": statistics.stdev(values) if len(values) > 1 else None}


def paired_statistics(measurements, sample_count):
    require(len(measurements) == 2 * sample_count + 2, "missing or extra campaign measurements")
    warmups = [row for row in measurements if row["phase"] == "warmup"]
    require(len(warmups) == 2 and {(row["sample"], row["mode"]) for row in warmups} == {(0, "cpu"), (0, "metal")},
            "warmup identity/count differs from the plan")
    measured = [row for row in measurements if row["phase"] == "measured"]
    require(len(measured) == 2 * sample_count, "missing measured trials; no complete benchmark statistics")
    lookup = {}
    for row in measured:
        key = (row["sample"], row["mode"])
        require(key not in lookup, "duplicate measured sample/mode")
        lookup[key] = row
    require(set(lookup) == {(sample, mode) for sample in range(1, sample_count + 1) for mode in ("cpu", "metal")},
            "measured samples do not form the planned mode pairs")
    by_mode = {mode: {metric: describe([lookup[(sample, mode)][metric] for sample in range(1, sample_count + 1)])
                     for metric in TIME_METRICS + ("request_peak_rss_bytes",)} for mode in ("cpu", "metal")}
    pairs = []
    for sample in range(1, sample_count + 1):
        cpu, metal = lookup[(sample, "cpu")], lookup[(sample, "metal")]
        ratios = {}
        for metric in TIME_METRICS:
            a, b = finite(cpu[metric], metric, True), finite(metal[metric], metric, True)
            ratios[metric] = {"cpu_over_metal": a / b, "metal_change_percent_vs_cpu": (b - a) / a * 100.0}
        pairs.append({"sample": sample, "cpu_run_id": cpu["run_id"], "metal_run_id": metal["run_id"], "timing_comparison": ratios})
    return {"measured_samples_per_mode": sample_count, "warmups_excluded": 2, "by_mode": by_mode, "pairs": pairs,
            "paired_cpu_over_metal": {metric: describe([pair["timing_comparison"][metric]["cpu_over_metal"] for pair in pairs]) for metric in TIME_METRICS},
            "interpretation": "descriptive statistics only; CPU/Metal ratio above one means shorter Metal time; no significance, energy, profitability or broad workload claim"}


def telemetry_summary(rows):
    require(rows and rows[0]["label"] == "before" and rows[-1]["label"] == "after", "trial lacks before/after telemetry")
    states, powers, unavailable, observed_cpu = Counter(), Counter(), Counter(), {}
    unparsed_process_lines = 0
    previous = -1.0
    for row in rows:
        elapsed = finite(row["elapsed_seconds"], "telemetry elapsed seconds")
        require(elapsed >= previous, "telemetry order is not monotonic")
        previous = elapsed
        require(row["label"] in ("before", "periodic", "after"), "unknown telemetry label")
        thermal = row.get("thermal", {})
        try:
            require(thermal.get("returncode") == 0, "thermal helper failed")
            value = json.loads(thermal["stdout"])
            require(type(value.get("low_power_mode_enabled")) is bool, "invalid low-power value")
            require(value.get("thermal_nominal_may_mean_unknown") is True
                    and value.get("low_power_false_may_mean_unknown") is True, "thermal caveats missing")
            states[value["thermal_state_name"]] += 1
            powers[str(value["low_power_mode_enabled"]).lower()] += 1
        except (ValueError, TypeError, KeyError):
            unavailable["thermal"] += 1
        for key in ("thermal_history", "power_source", "load_average"):
            if row.get(key, {}).get("returncode") != 0:
                unavailable[key] += 1
        process = row.get("processes", {})
        unparsed_process_lines += process.get("unparsed_count", 0)
        if process.get("returncode") != 0:
            unavailable["processes"] += 1
        for value in process.get("top_cpu", []):
            if type(value.get("pcpu")) in (int, float) and math.isfinite(value["pcpu"]):
                name = value["executable_basename"]
                observed_cpu[name] = max(observed_cpu.get(name, 0), value["pcpu"])
    return {"observation_count": len(rows), "labels": dict(Counter(row["label"] for row in rows)),
            "thermal_state_observations": dict(states), "low_power_mode_observations": dict(powers),
            "unavailable_observation_counts": dict(unavailable),
            "unparsed_process_lines": unparsed_process_lines,
            "maximum_observed_ps_pcpu_by_executable_basename": observed_cpu,
            "scope": "coarse categories and ps decaying CPU averages; includes proving, VM and unrelated apps; unknown thermal state may appear nominal; no wattage, interval CPU utilization or throttle-free claim"}


def bind_timing(attempt, proof, ledger_row):
    directory = attempt / "acceptance" / proof["case"]
    timing = read_json(directory / "timing.json")
    worker, resource = proof["worker"], proof["resource"]
    require(timing == ledger_row["timings"], "saved proof timing differs from the acceptance ledger")
    require(timing["schema_version"] == 1 and timing["worker_pid"] == worker["worker_pid"]
            and timing["request_id"] == worker["request_id"]
            and timing["worker_start_time_us"] == resource["worker_start_time_us"], "proof timing has the wrong worker identity")
    finite(timing["prove_call_ms"], "prove call", True)
    finite(timing["external_verifier_ms"], "external verifier", True)
    require(timing["prove_call_ms"] == resource["prove_call_ms"], "proof/resource call timings differ")
    baseline = resource["baseline_before_prove_call"]
    require(timing["worker_pid_before_prove"] == baseline["worker_pid"]
            and timing["worker_start_time_us_before_prove"] == baseline.get("worker_start_time_us")
            and timing["same_worker_as_before_prove"] == resource["baseline_matches_request_worker"], "baseline timing identity differs")
    run_timing = read_json(attempt / "acceptance/timing.json")
    require(run_timing["schema_version"] == 1 and isinstance(run_timing["cleanup"], dict), "missing finalized setup/cleanup timing")
    for phase, fields in {"setup": ("pool_new_ms", "pool_discover_and_spawn_ms", "worker_warmup_ms", "valid_execute_cycles_ms", "invalid_execute_cycles_ms", "total_ms"),
                          "cleanup": ("shutdown_all_ms", "drop_pool_ms", "post_cleanup_checks_ms", "total_ms")}.items():
        for field in fields:
            finite(run_timing[phase][field], phase + "." + field)
    return timing, run_timing


def wrap_diagnostics(path):
    pattern = re.compile(r"\[succinct_to_groth16\] identity_p254=([0-9]+\.[0-9])ms get_seal=([0-9]+\.[0-9])ms "
                         r"shrink_wrap=([0-9]+\.[0-9])ms total=([0-9]+\.[0-9])ms")
    lines = [line for line in path.read_text().splitlines() if "[succinct_to_groth16]" in line and "identity_p254=" in line]
    require(len(lines) == 1, "single-proof trial needs exactly one production Groth16 stage diagnostic")
    match = pattern.search(lines[0])
    require(match is not None, "production Groth16 diagnostic format differs")
    values = dict(zip(("identity_p254_ms", "get_seal_ms", "shrink_wrap_ms", "total_ms"), map(float, match.groups())))
    for name, value in values.items():
        finite(value, name)
    return {"values": values, "raw_line": lines[0], "source_artifact": artifact(path), "rounding_ms": 0.1,
            "scope": "rounded production stderr diagnostics, not separate benchmark instrumentation; identity_p254 includes helper prestart and preparation, shrink_wrap includes the helper call and buffer release"}


def measurements_from_evidence(plan, rows, acceptance, seals):
    runs = {run["id"]: run for run in acceptance["runs"]}
    measurements, baseline_identity = [], None
    for trial in rows:
        if trial["status"] != COMPLETE:
            continue
        run = runs[trial["run_id"]]
        report = run["report"]
        require(report["status"] == COMPLETE and report["requested_mode"] == trial["mode"]
                and report["expected_mode"] == trial["mode"] and report["worker_kind"] == "metal"
                and report["runner_command"] == trial["command"]
                and report["repeat"] == 1 and report["lifecycle"] is False and report["admission_pressure"] is False,
                "trial and accepted proof command/mode differ")
        require(report["miner_head_at_acceptance"] == plan["miner_sha"], "miner revision changed across benchmark")
        manifests = {kind: acceptance["build_seals_by_sha256"][digest]["manifest"] for kind, digest in run["build_seals"].items()}
        require(manifests["worker"] == seals["metal"] and manifests["verifier"] == seals["verifier"], "worker or verifier build differs from campaign seal")
        require(manifests["worker"]["source"]["engine_head"] == plan["engine_sha"]
                and manifests["acceptance"]["source_inputs"] == plan["source_inputs"], "engine or acceptance sources differ from plan")
        require(len(run["proofs"]) == 1 and run["proofs"][0]["case"] == "proof-0", "trial does not contain exactly one complete proof")
        proof = run["proofs"][0]
        worker, resource = proof["worker"], proof["resource"]
        require(run["fixture"]["workload"] == "fibonacci" and run["fixture"]["po2"] == 18
                and worker["staging_limit_bytes"] == 524288 and worker["requested_mode"] == trial["mode"]
                and worker["observed_mode"] == trial["mode"] and not worker.get("fallback_reason"), "proof settings/fallback differ from benchmark")
        identity = {"fixture": run["fixture"], "worker_binary_sha256": report["worker_binary_sha256"],
                    "verifier_binary_sha256": report["verifier_binary_sha256"], "acceptance_build": run["build_seals"]["acceptance"],
                    "helper_image": report["helper_image"], "helper_arch": report["helper_arch"], "helper_context": report["helper_context"],
                    "helper_endpoint": report["helper_endpoint"], "image_id": worker["image_id"], "stats": worker["stats"],
                    "journal_hex": worker["journal_hex"]}
        if baseline_identity is None:
            baseline_identity = identity
        require(identity == baseline_identity, "comparison changed a binary, fixture, helper, cycle/segment count or public output")
        successes = [row for row in run["request_ledger"] if row["status"] == COMPLETE]
        require(len(successes) == 1, "trial has unexpected successful request count")
        timing, setup = bind_timing(BASE / "worker-runs" / run["id"], proof, successes[0])
        diagnostics = wrap_diagnostics(BASE / "worker-runs" / run["id"] / "test.log")
        stage = worker["stage_ms"]
        metal_stage = worker["observed_stages"].get("metal_stage")
        require((metal_stage is None) == (trial["mode"] == "cpu"), "CPU/Metal stage selection differs")
        measurement = {key: trial[key] for key in ("index", "phase", "mode", "sample", "run_id")}
        measurement.update(worker_pid=worker["worker_pid"], worker_start_time_us=resource["worker_start_time_us"], request_id=worker["request_id"],
            execution_and_segment_ms=stage["execution_and_segment"], recursion_ms=stage["recursion"],
            identity_and_emulated_wrap_ms=stage["identity_and_wrap"], worker_verification_ms=stage["verification"],
            worker_total_ms=worker["total_ms"], prove_call_ms=timing["prove_call_ms"], external_verifier_ms=timing["external_verifier_ms"],
            identity_p254_diagnostic_ms=diagnostics["values"]["identity_p254_ms"],
            shrink_wrap_diagnostic_ms=diagnostics["values"]["shrink_wrap_ms"], rounded_wrap_diagnostics=diagnostics,
            supervisor_and_ipc_residual_ms=timing["prove_call_ms"] - worker["total_ms"],
            request_observation_window_ms=resource["request_elapsed_ms"], request_peak_rss_bytes=resource["peak_rss_bytes"],
            idle_rss_bytes=resource["idle_after_verification_and_settle"].get("rss_bytes"),
            periodic_host_memory=resource["periodic_host_memory"], metal_dispatches=metal_stage["completed_dispatches"] if metal_stage else 0,
            run_elapsed_seconds=report["elapsed_seconds"], trial_elapsed_seconds=trial["elapsed_seconds"],
            proof_call_timing=timing, setup_and_cleanup_timing=setup, stats=worker["stats"])
        for metric in TIME_METRICS:
            finite(measurement[metric], metric, True)
        finite(measurement["supervisor_and_ipc_residual_ms"], "supervisor residual")
        measurements.append(measurement)
    return measurements, baseline_identity


def csv_text(measurements, rows, slots):
    columns = ("index", "phase", "mode", "sample", "run_id", "status", "error", "worker_pid", "worker_start_time_us", "request_id",
               *TIME_METRICS, "supervisor_and_ipc_residual_ms", "request_observation_window_ms", "request_peak_rss_bytes",
               "idle_rss_bytes", "metal_dispatches", "run_elapsed_seconds", "trial_elapsed_seconds")
    stream = io.StringIO()
    writer = csv.DictWriter(stream, columns, lineterminator="\n", extrasaction="ignore")
    writer.writeheader()
    measured = {row["index"]: row for row in measurements}
    attempted = {row["index"]: row for row in rows}
    for slot in slots:
        trial = attempted.get(slot["index"], {})
        row = dict(slot, run_id=trial.get("run_id"), status=trial.get("status", "unattempted"), error=trial.get("error"))
        row.update(measured.get(slot["index"], {}))
        writer.writerow(row)
    return stream.getvalue()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--benchmark", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--csv", type=Path, required=True)
    args = parser.parse_args()
    directory = args.benchmark.resolve()
    acceptance_json = args.output.with_name(args.output.stem + "-acceptance.json")
    acceptance_csv = args.output.with_name(args.output.stem + "-acceptance.csv")
    outputs = (args.output, args.csv, acceptance_json, acceptance_csv)
    require(len(set(path.resolve() for path in outputs)) == len(outputs), "output paths collide")
    for path in outputs:
        require(not path.exists() and path.parent.is_dir(), f"output exists or parent missing: {path}")
        require(not path.resolve().is_relative_to(directory), "output would mutate the benchmark archive")
    with (directory.parent / "active.lock").open("r") as lock:
        fcntl.flock(lock, fcntl.LOCK_SH | fcntl.LOCK_NB)
        plan, result = read_json(directory / "plan.json"), read_json(directory / "result.json")
        require(result["plan_sha256"] == sha(directory / "plan.json"), "finalized plan hash differs")
        rows = read_rows(directory / "trials.jsonl") if (directory / "trials.jsonl").is_file() else []
        sample_count = validate_schedule(plan, rows, result)
        require(all(sha(path) == digest for path, digest in plan["sources"].items()), "benchmark orchestrator/telemetry inputs changed")
        require(all(sha(ROOT / path) == digest for path, digest in plan["source_inputs"].items()), "acceptance source inputs changed")
        seals = read_json(directory / "build-seals.json")
        telemetry = {}
        for row in rows:
            trial_dir = directory / f"trial-{row['index']:02}"
            for name, field in (("command.log", "log_sha256"), ("telemetry.jsonl", "telemetry_sha256")):
                require(sha(trial_dir / name) == row[field], f"trial {row['index']} {name} hash differs")
            readings = read_rows(trial_dir / "telemetry.jsonl")
            telemetry[str(row["index"])] = {"raw_artifact": artifact(trial_dir / "telemetry.jsonl"),
                "observations": readings, "summary": telemetry_summary(readings) if row["status"] == COMPLETE else None}
        ids = [row["run_id"] for row in rows if row.get("run_id") is not None
               and (BASE / "worker-runs" / row["run_id"] / "result.json").is_file()]
        require(all(row["run_id"] in ids for row in rows if row["status"] == COMPLETE), "successful trial has no finalized run")
        collector = ROOT / "scripts/macos/summarize-worker.py"
        command = None
        with tempfile.TemporaryDirectory(prefix="hemi-benchmark-evidence-") as temporary:
            temp_json, temp_csv = Path(temporary) / "acceptance.json", Path(temporary) / "acceptance.csv"
            if ids:
                command = [sys.executable, str(collector), "--runs", *ids, "--output", str(temp_json), "--csv", str(temp_csv)]
                process = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=120)
                require(process.returncode == 0, "source-bound acceptance collector refused: " + process.stderr.strip())
                acceptance = read_json(temp_json)
                acceptance_bytes, acceptance_csv_bytes = temp_json.read_bytes(), temp_csv.read_bytes()
            else:
                acceptance = {"runs": [], "build_seals_by_sha256": {}, "totals": {}, "scope": "no finalized acceptance run exists"}
                acceptance_bytes = (json.dumps(acceptance, indent=2) + "\n").encode()
                acceptance_csv_bytes = b"run_id,status\n"
            measurements, comparison_identity = measurements_from_evidence(plan, rows, acceptance, seals)
            stats = paired_statistics(measurements, sample_count) if result["status"] == "complete" else None
            inventory = {str(path.relative_to(directory)): artifact(path) for path in sorted(directory.rglob("*")) if path.is_file()}
            summary = {"schema_version": 1, "generated_at_utc": datetime.now(timezone.utc).isoformat(), "status": result["status"],
                "command": [sys.executable, str(Path(__file__).resolve()), *sys.argv[1:]], "collector": artifact(Path(__file__)),
                "acceptance_collector": artifact(collector), "acceptance_collection_command": command,
                "plan": plan, "campaign_result": result, "trial_ledger": rows,
                "unattempted_trials": plan["trials"][len(rows):], "baseline": read_json(directory / "baseline.json"),
                "comparison_identity": comparison_identity, "measurements": measurements, "statistics": stats,
                "telemetry": telemetry, "benchmark_artifacts": inventory,
                "acceptance_evidence": {"path": str(acceptance_json.resolve()), "sha256": hashlib.sha256(acceptance_bytes).hexdigest(),
                    "csv_path": str(acceptance_csv.resolve()), "csv_sha256": hashlib.sha256(acceptance_csv_bytes).hexdigest(), "totals": acceptance["totals"]},
                "interpretation": {
                    "primary_metric": "execution_and_segment_ms: witness/execution plus all segment operations and per-request backend initialization; no isolated Metal-kernel timing",
                    "wrap": "identity_and_emulated_wrap_ms combines native identity p254 and the local emulated linux/amd64 helper; not native ARM Groth16",
                    "wrap_diagnostics": "identity_p254_diagnostic_ms and shrink_wrap_diagnostic_ms come from exactly one production stderr line per trial, rounded to 0.1 ms; identity includes helper prestart overhead",
                    "startup": "setup discovery/spawn times the validation worker, which can be retired before proving; actual prove_call includes admission/replacement/IPC; residual is not pure startup",
                    "verification": "worker verification is the final SDK check; external_verifier_ms includes unchanged verifier process startup, positive and three negative checks",
                    "warmup": "first complete CPU and Metal proofs are retained but excluded; each trial uses a fresh pool, with no cold-boot or persistent warmed worker claim",
                    "statistics": "all planned measured trials retained; paired descriptive ratios and per-mode median/range/sample deviation; no outlier removal or causal/significance claim",
                    "telemetry": "nonprivileged coarse thermal/power categories and decaying ps CPU averages; nominal/low-power false can mean unknown; no wattage/energy measurement",
                }}
            for saved in inventory.values():
                require(sha(saved["path"]) == saved["sha256"], "benchmark artifact changed during collection")
            serialized = (json.dumps(summary, indent=2, allow_nan=False) + "\n").encode()
            csv_bytes = csv_text(measurements, rows, plan["trials"]).encode()
            for path, data in ((acceptance_json, acceptance_bytes), (acceptance_csv, acceptance_csv_bytes), (args.output, serialized), (args.csv, csv_bytes)):
                with path.open("xb") as stream:
                    stream.write(data)
        print(json.dumps({"status": summary["status"], "accepted_proofs": len(measurements),
                          "measured_samples_per_mode": sample_count if stats else 0, "failed_trials": result["failed_trials"],
                          "unattempted_trials": result["unattempted_trials"]}))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        raise SystemExit(f"benchmark summary refused: {error}")
