#!/usr/bin/env python3
"""Consolidate explicit finalized local worker runs without proving or rebuilding.

The source-bound acceptance validator is re-run against each accepted run. Raw
artifacts stay in their run directories; this report hashes them and summarizes
RSS observations, retaining complete worker/verifier records and every ledger row.
"""
import argparse
from collections import Counter, defaultdict
import csv
from datetime import datetime, timezone
import fcntl
import hashlib
import importlib.util
import io
import json
import math
from pathlib import Path
import re
import subprocess
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
BASE = ROOT / "target/macos"
RUNS = BASE / "worker-runs"
PIN = "f8dcbdf8124a3f1528146bb01d539c55545cbb3d"
COMPLETE = "complete_independently_verified"
RSS_LIMIT = 32 * 1024**3


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


def git(*args):
    return subprocess.check_output(["git", "-C", str(ROOT), *args], timeout=15)


def repository_state():
    return {
        "scope": "collection-time miner checkout; does not identify historical worker build HEAD",
        "head": git("rev-parse", "HEAD").decode().strip(),
        "parents": git("show", "-s", "--format=%P", "HEAD").decode().split(),
        "branch": git("branch", "--show-current").decode().strip(),
        "status_porcelain": git("status", "--porcelain").decode().splitlines(),
        "working_diff_sha256": hashlib.sha256(git("diff", "HEAD", "--binary")).hexdigest(),
    }


def saved_args(report):
    command = report["runner_command"]
    require(len(command) >= 2 and Path(command[1]).resolve() == ROOT / "scripts/macos/test-worker.py",
            "run command does not name the expected acceptance runner")
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--engine", required=True)
    parser.add_argument("--worker-kind", required=True)
    parser.add_argument("--mode", required=True)
    parser.add_argument("--context", default="colima-hemi-macos-cpu")
    parser.add_argument("--repeat", type=int, default=3)
    parser.add_argument("--workload", default="fibonacci")
    parser.add_argument("--po2", type=int)
    parser.add_argument("--admission-pressure", action="store_true")
    parser.add_argument("--proof-only", action="store_true")
    parser.add_argument("--timeout", type=int, default=3600)
    parser.add_argument("--failure-timeout", type=int, default=70)
    parser.add_argument("--staging-bytes", type=int, default=524288)
    args = parser.parse_args(command[2:])
    if args.po2 is None:
        args.po2 = 16 if args.workload == "segment-boundary" else 18
    require(args.repeat == report["repeat"] and args.mode == report["requested_mode"]
            and args.worker_kind == report["worker_kind"] and args.proof_only == (not report["lifecycle"])
            and args.admission_pressure == report["admission_pressure"], "run command and report disagree")
    return args


def validator(build):
    # Check all imported local validator modules before importing any of them.
    for name in ("test-worker.py", "smoke.py", "proof_provenance.py", "worker_provenance.py"):
        relative = "scripts/macos/" + name
        require(build["source_inputs"].get(relative) == sha(ROOT / relative),
                f"archived acceptance validator differs from current {relative}")
    spec = importlib.util.spec_from_file_location("sealed_worker_acceptance", ROOT / "scripts/macos/test-worker.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def resource_summary(resource, worker):
    pid, start = resource["worker_pid"], resource["worker_start_time_us"]
    require(pid == worker["worker_pid"] and isinstance(start, int) and start > 0,
            "resource record has the wrong worker identity")
    observations = resource["observations"]
    samples = [row for row in observations if row.get("worker_pid") == pid
               and row.get("worker_start_time_us") == start and "rss_bytes" in row]
    require(samples and all(type(row["rss_bytes"]) is int and 0 < row["rss_bytes"] <= RSS_LIMIT for row in samples),
            "missing or out-of-bounds request RSS observations")
    require(resource["sample_count"] == len(samples)
            and resource["periodic_sample_count"] == sum(row.get("phase") == "periodic_during_prove_call" for row in samples)
            and resource["periodic_sample_count"] > 0
            and resource["peak_rss_bytes"] == max(row["rss_bytes"] for row in samples)
            and resource["first_sample"] == samples[0] and resource["last_sample"] == samples[-1],
            "resource summary does not match its raw observations")
    idle = resource["idle_after_verification_and_settle"]
    if "unavailable_reason" not in idle:
        require(idle.get("worker_pid") == pid and idle.get("worker_start_time_us") == start
                and type(idle.get("rss_bytes")) is int and 0 < idle["rss_bytes"] <= RSS_LIMIT,
                "idle observation is not bound to the request worker or exceeds RSS bound")
    summary = {key: value for key, value in resource.items() if key != "observations"}
    summary["observation_count_including_unavailable"] = len(observations)
    summary["unavailable_observation_count"] = sum("rss_bytes" not in row for row in observations)
    periodic = [row for row in samples if row.get("phase") == "periodic_during_prove_call"]
    for row in periodic:
        for field in ("host_available_bytes", "host_total_bytes"):
            require(row.get(field) is None or (type(row[field]) is int and row[field] >= 0),
                    f"invalid periodic {field}")
    available = [row["host_available_bytes"] for row in periodic if row.get("host_available_bytes") is not None]
    totals = [row["host_total_bytes"] for row in periodic if row.get("host_total_bytes") is not None]
    summary["periodic_host_memory"] = {
        "scope": "host observations accompanying identity-matched periodic native worker RSS samples",
        "sample_count": len(periodic), "host_available_min_bytes": min(available) if available else None,
        "host_available_max_bytes": max(available) if available else None,
        "host_available_unknown_count": len(periodic) - len(available),
        "host_total_observed_bytes": sorted(set(totals)), "host_total_unknown_count": len(periodic) - len(totals),
    }
    return summary


def compare_worker_records(left, right, left_source, right_source):
    """Bind every field exactly, except adjacent finite diagnostic timing floats.

    Worker JSON is parsed and serialized again by the Rust acceptance test.
    Its serde_json float round trip can change a timing by one IEEE-754 step.
    This exception is confined to top-level total_ms and direct stage_ms values;
    hashes, counters, identities, resource observations and all other fields stay
    exact. Raw artifacts and both original timing values are retained.
    """
    differences = []

    def compare(a, b, path):
        field = ".".join(map(str, path))
        timing = path == ("total_ms",) or (len(path) == 2 and path[0] == "stage_ms")
        if timing:
            require(type(a) in (int, float) and type(b) in (int, float)
                    and math.isfinite(a) and math.isfinite(b) and a >= 0 and b >= 0,
                    f"invalid nonnegative finite diagnostic timing at {field}")
            if a == b:
                return
            require(type(a) is float and type(b) is float and math.nextafter(a, b) == b,
                    f"diagnostic timing differs by more than one ULP at {field}")
            differences.append({"field": field, "left_source": left_source, "right_source": right_source,
                "left_value": a, "right_value": b, "left_float_hex": a.hex(), "right_float_hex": b.hex(),
                "absolute_difference": abs(a - b), "ulp_distance": 1})
            return
        require(type(a) is type(b), f"worker evidence type differs at {field}")
        if isinstance(a, dict):
            require(a.keys() == b.keys(), f"worker evidence keys differ at {field}")
            for key in a:
                compare(a[key], b[key], path + (key,))
        elif isinstance(a, list):
            require(len(a) == len(b), f"worker evidence list length differs at {field}")
            for index, (first, second) in enumerate(zip(a, b)):
                compare(first, second, path + (index,))
        else:
            require(a == b, f"worker evidence differs at {field}")

    require(isinstance(left, dict) and isinstance(right, dict), "worker evidence must be an object")
    compare(left, right, ())
    return differences


def bind_proof(attempt, row, fixture):
    case = row["case"]
    require(re.fullmatch(r"proof-(?:[0-9]+|after-restart)", case), "invalid completed proof case")
    directory = attempt / "acceptance" / case
    worker = read_json(directory / "worker.json")
    verification = read_json(directory / "verification.json")
    resource = read_json(directory / "resource.json")
    timing_differences = compare_worker_records(worker, row["worker"], str(directory / "worker.json"),
                                                str(attempt / "acceptance/requests.jsonl") + ":" + case)
    require(resource == row["resources"], f"{case}: ledger and saved resource evidence differ")
    journal = (directory / "journal.bin").read_bytes()
    seal = (directory / "seal.bin").read_bytes()
    require(journal.hex() == fixture["expected_journal_hex"] == worker["journal_hex"]
            and hashlib.sha256(journal).hexdigest() == worker["journal_sha256"], "raw journal binding failed")
    require(len(seal) == 256 and hashlib.sha256(seal).hexdigest() == worker["seal_sha256"], "raw seal binding failed")
    require((directory / "receipt.bin").stat().st_size > len(seal), "missing serialized Groth16 receipt")
    require(worker["phase"] == "complete" and worker["proof_kind"] == "groth16"
            and worker["elf_sha256"] == fixture["elf_sha256"] and worker["input_sha256"] == fixture["input_sha256"]
            and verification["verification"] == "passed" and verification["image_id"] == worker["image_id"]
            and verification["journal_hex"] == journal.hex() and verification["elf_sha256"] == fixture["elf_sha256"]
            and verification["negative_tests"] == ["wrong_image", "modified_journal", "corrupt_seal"],
            "saved proof and unchanged verifier identities differ")
    sidecar = attempt / "requests" / f"{worker['worker_pid']}-{worker['request_id']}.json"
    timing_differences += compare_worker_records(worker, read_json(sidecar), str(directory / "worker.json"), str(sidecar))
    for name in ("verifier.stdout", "verifier.stderr"):
        require((directory / name).is_file(), f"missing {name}")
    return {"case": case, "worker": worker, "verifier": verification,
            "resource": resource_summary(resource, worker),
            "diagnostic_timing_serialization_differences": timing_differences,
            "artifacts": {path.name: artifact(path) for path in sorted(directory.iterdir()) if path.is_file()},
            "terminal_sidecar": artifact(sidecar)}


def idle_trends(proofs):
    groups = defaultdict(list)
    for proof in proofs:
        resource = proof["resource"]
        groups[(resource["worker_pid"], resource["worker_start_time_us"])].append(proof)
    output = []
    for (pid, start), values in groups.items():
        idle = [{"case": value["case"], "rss_bytes": value["resource"]["idle_after_verification_and_settle"].get("rss_bytes"),
                 "unavailable_reason": value["resource"]["idle_after_verification_and_settle"].get("unavailable_reason")}
                for value in values]
        available = [row for row in idle if row["rss_bytes"] is not None]
        item = {"worker_pid": pid, "worker_start_time_us": start, "proof_count": len(values), "idle_observations": idle,
                "request_peaks": [{"case": value["case"], "rss_bytes": value["resource"]["peak_rss_bytes"]} for value in values],
                "idle_first_to_last_delta_bytes": available[-1]["rss_bytes"] - available[0]["rss_bytes"] if len(available) > 1 else None}
        output.append(item)
    return output


def archive_builds(attempt, report, builds, required):
    refs = {}
    for kind in ("worker", "verifier", "acceptance", "guest"):
        path = attempt / f"{kind}-build.json"
        if not path.is_file():
            require(not required, f"missing archived {kind} build")
            continue
        value = read_json(path)
        digest = sha(path)
        if required and kind in ("worker", "verifier"):
            require(value["source"]["pinned_engine_revision"] == PIN, "archived engine pin changed")
            require(value["binary_sha256"] == report[f"{kind}_binary_sha256"], "report binary differs from build seal")
        entry = builds.setdefault(digest, {"kind": kind, "sha256": digest, "archived_paths": [], "manifest": value})
        require(entry["kind"] == kind and entry["manifest"] == value, "build manifest SHA collision or kind mismatch")
        entry["archived_paths"].append(str(path))
        refs[kind] = digest
    return refs


def check_rss_series(attempt, report):
    path = attempt / "rss-samples.jsonl"
    peaks, counts, positive_counts = {}, Counter(), Counter()
    unavailable = []
    for row in read_rows(path):
        require(type(row.get("worker_pid")) is int and type(row.get("request_id")) is int
                and type(row.get("rss_bytes")) is int and 0 <= row["rss_bytes"] <= RSS_LIMIT
                and isinstance(row.get("elapsed_seconds"), (int, float)) and math.isfinite(row["elapsed_seconds"])
                and row["elapsed_seconds"] >= 0, "invalid outer RSS sample")
        pid = str(row["worker_pid"])
        require((attempt / "requests" / f"{pid}-{row['request_id']}.json").is_file(), "RSS sample has no request sidecar")
        counts[pid] += 1
        if row["rss_bytes"] == 0:
            unavailable.append(dict(row, classification="unavailable_nonpositive_rss"))
        else:
            peaks[pid] = max(peaks.get(pid, 0), row["rss_bytes"])
            positive_counts[pid] += 1
    require(peaks and peaks == report["worker_peak_rss_bytes"], "outer RSS peaks differ from run report")
    return {"artifact": artifact(path), "sample_count": sum(counts.values()), "sample_count_by_pid": dict(counts),
            "positive_sample_count": sum(positive_counts.values()), "positive_sample_count_by_pid": dict(positive_counts),
            "peak_by_pid_bytes": peaks, "unavailable_nonpositive_rss_observations": unavailable,
            "limitation": "outer ps sampling may report zero RSS; these are unavailable observations, excluded from positive counts and peaks; their cause is not established"}


def summarize_run(identifier, final_rows, builds):
    require(re.fullmatch(r"[a-f0-9]{32}", identifier), f"invalid run ID: {identifier}")
    attempt = RUNS / identifier
    report = read_json(attempt / "result.json")
    require(report.get("id") == identifier and report.get("status") in (COMPLETE, "failed"), "run is not finalized")
    matching = [row for row in final_rows if row.get("id") == identifier]
    require(len(matching) == 1 and matching[0] == report, "run report differs from finalized append-only ledger")
    accepted = report["status"] == COMPLETE
    require(not accepted or (report.get("test_exit_code") == 0 and not report.get("cleanup_errors") and not report.get("error")),
            "accepted run records test or cleanup failure")
    refs = archive_builds(attempt, report, builds, accepted)
    ledger_path = attempt / "acceptance/requests.jsonl"
    rows = read_rows(ledger_path) if ledger_path.is_file() else []
    fixture = read_json(attempt / "fixture.json") if (attempt / "fixture.json").is_file() else report.get("fixture")
    validated_summary = None
    if accepted:
        for name in ("test.log", "test-build.jsonl", "test-build.stderr", "miner-acceptance.patch"):
            require((attempt / name).is_file(), f"missing accepted run artifact: {name}")
        args = saved_args(report)
        expected_mode = "metal" if args.worker_kind == "metal" and args.mode != "cpu" else "cpu"
        require(report["expected_mode"] == expected_mode, "run expected mode differs from selected build/mode")
        test_build = builds[refs["acceptance"]]["manifest"]
        module = validator(test_build)
        require(module.test_sources() == test_build["source_inputs"], "acceptance source inputs changed since the archived run")
        require(sha(Path(test_build["binary_path"])) == test_build["binary_sha256"], "acceptance executable changed since the archived run")
        require(fixture == report["fixture"], "fixture and run report differ")
        input_bytes, expected_hex, _, minimum_segments = module.workload(args.workload)
        require(fixture["workload"] == args.workload and fixture["expected_journal_hex"] == expected_hex
                and fixture["min_segments"] == minimum_segments and fixture["po2"] == args.po2
                and (attempt / "input.bin").read_bytes() == input_bytes
                and sha(attempt / "input.bin") == fixture["input_sha256"]
                and sha(Path(fixture["program_path"])) == fixture["elf_sha256"] == report["program_sha256"],
                "fixture differs from independently computed workload or authentic program")
        require((attempt / "acceptance/input.bin").read_bytes() == input_bytes, "verifier input differs from fixture")
        guest = builds[refs["guest"]]["manifest"]
        require(all(sha(Path(path)) == digest for path, digest in guest["inputs"].items()), "authentic guest build inputs changed")
        require(guest["provenance"]["packing"]["program_sha256"] == fixture["elf_sha256"], "guest packing differs from selected fixture")
        validated_summary = module.validate_results(attempt, args, report["expected_mode"], fixture)
        require(validated_summary == report["results"], "revalidated acceptance summary differs from finalized report")
        patch = attempt / "miner-acceptance.patch"
        require(sha(patch) == report["miner_working_diff_sha256"], "acceptance source patch hash differs from report")
        require(re.fullmatch(r"[a-f0-9]{40}", report["miner_head_at_acceptance"]), "missing acceptance-time miner HEAD")
    successes = [row for row in rows if row.get("status") == COMPLETE]
    proofs, proof_errors = [], []
    for row in successes:
        try:
            proofs.append(bind_proof(attempt, row, fixture))
        except (OSError, ValueError, KeyError, TypeError) as error:
            if accepted:
                raise
            proof_errors.append({"case": row.get("case"), "error": str(error)})
    if accepted:
        require(len(proofs) == validated_summary["verified_proofs"], "successful ledger/proof count differs")
    proof_by_case = {proof["case"]: proof for proof in proofs}
    compact_rows = []
    for row in rows:
        compact = dict(row)
        if "resources" in compact:
            compact["resources"] = {key: value for key, value in compact["resources"].items() if key != "observations"}
        if row.get("case") in proof_by_case and row.get("status") == COMPLETE:
            compact["verifier"] = proof_by_case[row["case"]]["verifier"]
            compact["resources"] = proof_by_case[row["case"]]["resource"]
        compact_rows.append(compact)
    terminal = Counter(row.get("case") for row in rows if row.get("status") != "started")
    unfinished = [row["case"] for row in rows if row.get("status") == "started" and not terminal[row["case"]]]
    unexpected = [row for row in compact_rows if row.get("status") not in ("started", COMPLETE, "expected_failure", "expected_admission_refusal")]
    files = {str(path.relative_to(attempt)): artifact(path) for path in sorted(attempt.rglob("*"))
             if path.is_file() and "shared-work" not in path.relative_to(attempt).parts}
    return {"id": identifier, "report": report, "fixture": fixture, "build_seals": refs,
            "revalidated_acceptance": validated_summary, "proofs": proofs, "request_ledger": compact_rows,
            "failed_proof_artifact_checks": proof_errors, "unexpected_terminal_rows": unexpected,
            "unterminated_cases": unfinished, "idle_rss_trends": idle_trends(proofs), "artifacts": files,
            "outer_rss": check_rss_series(attempt, report) if accepted else None}


def csv_text(runs):
    fields = ["run_id", "run_status", "ledger_index", "case", "status", "workload", "requested_mode", "observed_mode",
              "worker_pid", "request_id", "worker_start_time_us", "po2", "segments", "user_cycles", "total_cycles",
              "staging_limit_bytes", "metal_dispatches", "worker_total_ms", "request_elapsed_ms", "request_peak_rss_bytes",
              "idle_rss_bytes", "host_available_min_bytes", "host_available_max_bytes", "host_available_unknown_count",
              "seal_sha256", "journal_sha256", "negative_rejections", "error"]
    stream = io.StringIO()
    writer = csv.DictWriter(stream, fields, lineterminator="\n")
    writer.writeheader()
    for run in runs:
        rows = run["request_ledger"] or [{"case": "run", "status": run["report"]["status"], "error": run["report"].get("error")}]
        for index, row in enumerate(rows):
            worker, resource = row.get("worker", {}), row.get("resources", {})
            stats = worker.get("stats", {})
            stage = worker.get("observed_stages", {}).get("metal_stage") or {}
            writer.writerow({"run_id": run["id"], "run_status": run["report"]["status"], "ledger_index": index,
                "case": row.get("case"), "status": row.get("status"), "workload": (run["fixture"] or {}).get("workload"),
                "requested_mode": worker.get("requested_mode"), "observed_mode": worker.get("observed_mode"),
                "worker_pid": worker.get("worker_pid"), "request_id": worker.get("request_id"),
                "worker_start_time_us": resource.get("worker_start_time_us"), "po2": worker.get("po2"),
                "segments": stats.get("segments"), "user_cycles": stats.get("user_cycles"), "total_cycles": stats.get("total_cycles"),
                "staging_limit_bytes": worker.get("staging_limit_bytes"), "metal_dispatches": stage.get("completed_dispatches"),
                "worker_total_ms": worker.get("total_ms"), "request_elapsed_ms": resource.get("request_elapsed_ms"),
                "request_peak_rss_bytes": resource.get("peak_rss_bytes"),
                "idle_rss_bytes": resource.get("idle_after_verification_and_settle", {}).get("rss_bytes"),
                "host_available_min_bytes": resource.get("periodic_host_memory", {}).get("host_available_min_bytes"),
                "host_available_max_bytes": resource.get("periodic_host_memory", {}).get("host_available_max_bytes"),
                "host_available_unknown_count": resource.get("periodic_host_memory", {}).get("host_available_unknown_count"),
                "seal_sha256": worker.get("seal_sha256"), "journal_sha256": worker.get("journal_sha256"),
                "negative_rejections": len(row.get("verifier", {}).get("negative_tests", [])) if row.get("status") == COMPLETE else None,
                "error": row.get("error")})
    return stream.getvalue()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runs", nargs="+", required=True, help="explicit finalized run IDs, in reporting order")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--csv", type=Path, required=True)
    args = parser.parse_args()
    require(len(args.runs) == len(set(args.runs)), "duplicate run IDs would double-count proofs")
    require(args.output.resolve() != args.csv.resolve(), "JSON and CSV outputs must differ")
    for path in (args.output, args.csv):
        require(not path.resolve().is_relative_to(RUNS.resolve()), "summary outputs must not mutate archived run evidence")
        require(not path.exists(), f"refusing to overwrite existing output: {path}")
        require(path.parent.is_dir(), f"output parent does not exist: {path.parent}")
    with (BASE / "runs/active.lock").open("r") as lock:
        # Refuse to collect while any local proving runner holds the exclusive lock.
        fcntl.flock(lock, fcntl.LOCK_SH | fcntl.LOCK_NB)
        final_rows = read_rows(RUNS / "results.jsonl")
        builds = {}
        runs = [summarize_run(identifier, final_rows, builds) for identifier in args.runs]
        accepted = [run for run in runs if run["report"]["status"] == COMPLETE]
        proofs = [proof for run in accepted for proof in run["proofs"]]
        statuses = Counter(row.get("status", "missing_status") for run in runs for row in run["request_ledger"])
        hardware_path, baseline_path = BASE / "hardware-native.json", ROOT / "docs/macos/BASELINE.md"
        value = {"schema_version": 1, "generated_at_utc": datetime.now(timezone.utc).isoformat(),
            "collector": artifact(Path(__file__)), "run_ids": args.runs, "pinned_engine_revision": PIN,
            "collection_repository": repository_state(), "hardware": {"artifact": artifact(hardware_path), "discovery": read_json(hardware_path)},
            "prior_baseline": {"artifact": artifact(baseline_path), "text": baseline_path.read_text()},
            "scope": {"verification": "revalidated source-bound saved acceptance evidence; no new proving, rebuilding, or verifier execution",
                "raw_receipts": "hashes retain saved serialized receipts; raw journal and seal are bound to accepted worker/verifier records",
                "worker_build_revision": "historical miner HEAD/dirty status absent from original worker seal; exact source-input hashes and engine HEAD/diff are retained",
                "worker_record_binding": "all non-timing fields exact; only total_ms and direct stage_ms values allow one adjacent finite nonnegative float step, with both originals and raw artifact hashes retained",
                "rss": "sampled native worker RSS, grouped by PID and start identity; excludes helper VM and unmeasured Metal driver allocations; no leak-free claim",
                "helper": "local linux/amd64 Groth16 helper under emulation; times are observations, not native performance benchmarks",
                "pressure": "logical production in-flight admission reservations; no physical memory exhaustion"},
            "totals": {"selected_runs": len(runs), "accepted_runs": len(accepted), "failed_runs": len(runs) - len(accepted),
                "accepted_full_groth16_proofs": len(proofs), "accepted_negative_rejections": sum(len(proof["verifier"]["negative_tests"]) for proof in proofs),
                "diagnostic_timing_one_ulp_differences": sum(len(proof["diagnostic_timing_serialization_differences"]) for proof in proofs),
                "expected_admission_refusals": statuses["expected_admission_refusal"],
                "unexpected_failed_request_rows": statuses["failed"],
                "validated_saved_proofs_in_failed_runs": sum(len(run["proofs"]) for run in runs if run["report"]["status"] != COMPLETE),
                "ledger_status_counts": dict(statuses), "unexpected_terminal_rows": sum(len(run["unexpected_terminal_rows"]) for run in runs),
                "unterminated_cases": sum(len(run["unterminated_cases"]) for run in runs),
                "failed_proof_artifact_checks": sum(len(run["failed_proof_artifact_checks"]) for run in runs)},
            "build_seals_by_sha256": builds, "runs": runs}
        # Check all run evidence again before writing, so concurrent mutation fails closed.
        for run in runs:
            for saved in run["artifacts"].values():
                require(sha(saved["path"]) == saved["sha256"], "run artifact changed during collection")
        output = json.dumps(value, indent=2, allow_nan=False) + "\n"
        csv_output = csv_text(runs)
        with args.output.open("x") as stream:
            stream.write(output)
        with args.csv.open("x", newline="") as stream:
            stream.write(csv_output)
        print(json.dumps(value["totals"], sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        raise SystemExit(f"evidence summary refused: {error}")
