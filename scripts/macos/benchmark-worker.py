#!/usr/bin/env python3
"""Fixed-setting local CPU/Metal trials; real acceptance, no retries or installation."""
import argparse
from datetime import datetime, timezone
import fcntl
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[2]
BASE = ROOT / "target/macos"
COMPLETE = "complete_independently_verified"


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def now():
    return datetime.now(timezone.utc).isoformat()


def save(path, value):
    with path.open("x") as stream:
        stream.write(json.dumps(value, indent=2, allow_nan=False) + "\n")


def command_result(command):
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=15, cwd=ROOT)
        return {"command": command, "returncode": result.returncode,
                "stdout": result.stdout, "stderr": result.stderr}
    except (OSError, subprocess.TimeoutExpired) as error:
        return {"command": command, "error": str(error)}


def telemetry(thermal, label, started):
    record = {"at_utc": now(), "elapsed_seconds": time.monotonic() - started, "label": label}
    for key, command in {
        "thermal": [str(thermal)], "thermal_history": ["pmset", "-g", "therm"],
        "power_source": ["pmset", "-g", "batt"], "load_average": ["sysctl", "vm.loadavg"],
    }.items():
        record[key] = command_result(command)
    # Never archive command arguments or full executable paths from other apps.
    ps = command_result(["ps", "-A", "-o", "pid=,ppid=,pcpu=,rss=,comm="])
    rows, unparsed = [], 0
    if ps.get("returncode") == 0:
        for line in ps["stdout"].splitlines():
            fields = line.split(None, 4)
            if len(fields) == 5:
                try:
                    if not math.isfinite(float(fields[2])):
                        raise ValueError("nonfinite pcpu")
                    rows.append({"pid": int(fields[0]), "ppid": int(fields[1]),
                                 "pcpu": float(fields[2]), "rss_bytes": int(fields[3]) * 1024,
                                 "executable_basename": Path(fields[4]).name})
                except ValueError:
                    unparsed += 1
            else:
                unparsed += 1
    record["processes"] = {"command": ps["command"], "returncode": ps.get("returncode"),
                           "error": ps.get("error"), "observed_count": len(rows), "unparsed_count": unparsed,
                           "top_cpu": sorted(rows, key=lambda row: row["pcpu"], reverse=True)[:12],
                           "method": "ps pcpu is a decaying average, not an interval CPU counter; top 12 names only"}
    return record


def schedule(samples):
    return [{"index": index, "phase": "warmup" if sample == 0 else "measured", "mode": mode, "sample": sample}
            for index, (sample, mode) in enumerate((sample, mode) for sample in range(samples + 1) for mode in ("cpu", "metal"))]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--engine", required=True, type=Path)
    parser.add_argument("--context", default="colima-hemi-macos-cpu")
    parser.add_argument("--samples", type=int, default=5)
    args = parser.parse_args()
    if not 5 <= args.samples <= 20:
        parser.error("5..20 measured trials per mode required after one complete warmup per mode")
    if args.context != "colima-hemi-macos-cpu":
        parser.error("use the existing dedicated local helper context")
    if os.environ.get("RAYON_NUM_THREADS") != "6":
        parser.error("source scripts/macos/env.sh first (six Rayon threads)")
    os.environ["LC_ALL"] = "C"
    engine = args.engine.resolve()
    thermal = BASE / "benchmark-tools/thermal"
    source = ROOT / "scripts/macos/benchmark-thermal.m"
    if not thermal.is_file():
        parser.error("compile benchmark-thermal.m as documented; this script never installs tools")
    spec = importlib.util.spec_from_file_location("worker_acceptance", ROOT / "scripts/macos/test-worker.py")
    acceptance = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(acceptance)
    # Verify both paths, including the preserved standalone CPU build, before any proof.
    from worker_provenance import verify_build as verify_worker
    from proof_provenance import verify_build as verify_verifier
    seals = {kind: verify_worker(kind, engine) for kind in ("cpu", "metal")}
    seals["verifier"] = verify_verifier("verifier", BASE / "verifier/release/hemi-macos-proof")
    original_sources = acceptance.test_sources()
    sources = {str(path): sha(path) for path in (Path(__file__).resolve(), source, thermal)}
    directory = BASE / "benchmarks" / uuid.uuid4().hex
    directory.parent.mkdir(parents=True, exist_ok=True)
    with (directory.parent / "active.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        directory.mkdir()
        started = time.monotonic()
        start_utc = now()
        plan = {"schema_version": 1, "created_at_utc": start_utc,
                "command": [sys.executable, str(Path(__file__).resolve()), *sys.argv[1:]],
                "miner_sha": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
                "engine_sha": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=engine, text=True).strip(),
                "engine_path": str(engine), "sources": sources, "source_inputs": original_sources,
                "fixed_settings": {"worker_kind": "metal", "workload": "fibonacci", "po2": 18,
                    "staging_bytes": 524288, "repeat": 1, "proof_only": True, "context": args.context,
                    "rayon_threads": 6, "helper_cpus": 6, "helper_memory_bytes": 24 * 1024**3,
                    "vm_cpus": 6, "vm_memory_bytes": 32 * 1024**3},
                "methodology": {
                    "comparison": "same sealed Metal-capable executable, explicit CPU versus forced Metal",
                    "warmup": "one complete verified Groth16 proof per mode excluded from measured summaries",
                    "process_state": "fresh supervised pool per trial; readiness and execute validation precede proving; no persistent warm-process claim",
                    "order": "CPU then Metal warmups, then alternating CPU/Metal measured pairs; no automatic retries or selective exclusions",
                    "cold_start": "pool startup measured separately; OS, runtime and helper caches warmed, never flushed; no cold-boot claim",
                    "telemetry": "before/after and about every 10 seconds; nonprivileged thermal category, power source, load average, top ps CPU names",
                    "thermal_limit": "Foundation nominal may also mean unsupported/unknown; pmset absence of warnings is not temperature measurement",
                    "power_limit": "power source and low-power-mode only, no wattage/energy or profitability measurement",
                    "resources": "existing admission and worker/helper limits retained; RSS excludes helper/VM and unmeasured Metal driver allocations",
                    "background": "existing applications and default VM left running; no compilation or unrelated tests scheduled during measured trials"},
                "trials": schedule(args.samples)}
        save(directory / "plan.json", plan)
        save(directory / "build-seals.json", seals)
        baseline = {key: command_result(cmd) for key, cmd in {
            "hardware": ["sysctl", "hw.model", "hw.ncpu", "hw.memsize", "machdep.cpu.brand_string"],
            "os": ["sw_vers"], "sdk": ["xcrun", "--show-sdk-version"],
            "vms": ["colima", "list", "--json"],
            "helper_image": ["docker", "--context", args.context, "image", "inspect", "risczero/risc0-groth16-prover:v2025-04-03.1"],
            "helper_limits": ["docker", "--context", args.context, "info", "--format", "{{json .NCPU}} {{json .MemTotal}}"],
            "helper_containers": ["docker", "--context", args.context, "ps", "-a", "--format", "{{.Names}}"],
        }.items()}
        save(directory / "baseline.json", baseline)
        print(directory, flush=True)
        completed, failed, error = 0, 0, None
        try:
            if any(row.get("returncode") != 0 for row in baseline.values()):
                raise RuntimeError("baseline command failed; see baseline.json")
            if baseline["helper_containers"]["stdout"].strip():
                raise RuntimeError("dedicated helper VM has existing containers")
            vms = [json.loads(line) for line in baseline["vms"]["stdout"].splitlines()]
            vm = next(row for row in vms if row["name"] == "hemi-macos-cpu")
            if (vm["status"], vm["cpus"], vm["memory"]) != ("Running", 6, 32 * 1024**3):
                raise RuntimeError("dedicated helper VM does not match the fixed resource envelope")
            for trial in plan["trials"]:
                trial_dir = directory / f"trial-{trial['index']:02}"
                trial_dir.mkdir()
                command = [sys.executable, str(ROOT / "scripts/macos/test-worker.py"), "--engine", str(engine),
                           "--worker-kind", "metal", "--mode", trial["mode"], "--context", args.context,
                           "--proof-only", "--repeat", "1", "--workload", "fibonacci", "--po2", "18",
                           "--staging-bytes", "524288", "--timeout", "900"]
                row = dict(trial, command=command, started_at_utc=now(), status="failed", error=None, run_id=None)
                trial_started = time.monotonic()
                proc = None
                with (trial_dir / "telemetry.jsonl").open("x") as readings, (trial_dir / "command.log").open("x") as log:
                    def sample(label):
                        readings.write(json.dumps(telemetry(thermal, label, trial_started), allow_nan=False) + "\n")
                        readings.flush()
                    try:
                        sample("before")
                        proc = subprocess.Popen(command, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
                        while proc.poll() is None:
                            try:
                                proc.wait(timeout=10)
                            except subprocess.TimeoutExpired:
                                sample("periodic")
                        sample("after")
                    except (Exception, KeyboardInterrupt) as failure:
                        row["error"] = f"{type(failure).__name__}: {failure}"
                    finally:
                        if proc is not None and proc.poll() is None:
                            # SIGINT lets the existing runner perform identity-scoped
                            # worker/helper cleanup. Never signal unrelated processes.
                            proc.send_signal(signal.SIGINT)
                            try:
                                proc.wait(timeout=45)
                            except subprocess.TimeoutExpired:
                                row["cleanup_pending_pid"] = proc.pid
                                row["error"] = (row["error"] or "") + "; acceptance cleanup did not finish in 45 seconds; no further trials launched"
                row.update(returncode=proc.returncode if proc is not None else None, ended_at_utc=now(), elapsed_seconds=time.monotonic() - trial_started,
                           log_sha256=sha(trial_dir / "command.log"), telemetry_sha256=sha(trial_dir / "telemetry.jsonl"))
                matches = re.findall(r"^" + re.escape(str(BASE / "worker-runs")) + r"/([a-f0-9]{32})$",
                                     (trial_dir / "command.log").read_text(), re.MULTILINE)
                if len(matches) == 1:
                    row["run_id"] = matches[0]
                    result_path = BASE / "worker-runs" / matches[0] / "result.json"
                    if result_path.is_file():
                        result = json.loads(result_path.read_text())
                        if row["returncode"] == 0 and result["status"] == COMPLETE and row["error"] is None:
                            row["status"] = COMPLETE
                        else:
                            row["error"] = result.get("error", "worker acceptance failed")
                if row["status"] != COMPLETE:
                    row["error"] = row["error"] or "runner failed or did not produce exactly one finalized accepted run"
                with (directory / "trials.jsonl").open("a") as ledger:
                    ledger.write(json.dumps(row, allow_nan=False) + "\n")
                print(json.dumps({key: row[key] for key in ("index", "phase", "mode", "sample", "run_id", "status", "elapsed_seconds", "error")}), flush=True)
                if row["status"] != COMPLETE:
                    failed += 1
                    raise RuntimeError(row["error"])
                completed += 1
                if acceptance.test_sources() != original_sources or any(sha(path) != value for path, value in sources.items()):
                    raise RuntimeError("sealed benchmark sources changed during campaign")
            for kind in ("cpu", "metal"):
                if verify_worker(kind, engine) != seals[kind]:
                    raise RuntimeError(f"{kind} worker seal changed")
            if verify_verifier("verifier", BASE / "verifier/release/hemi-macos-proof") != seals["verifier"]:
                raise RuntimeError("verifier seal changed")
        except (Exception, KeyboardInterrupt) as failure:
            error = f"{type(failure).__name__}: {failure}"
        unchanged = acceptance.test_sources() == original_sources and all(sha(path) == value for path, value in sources.items())
        result = {"status": "complete" if error is None and unchanged and completed == len(plan["trials"]) else "failed",
                  "plan_sha256": sha(directory / "plan.json"), "source_inputs_unchanged": unchanged,
                  "completed_trials": completed, "failed_trials": failed,
                  "unattempted_trials": len(plan["trials"]) - completed - failed,
                  "started_at_utc": start_utc, "ended_at_utc": now(), "elapsed_seconds": time.monotonic() - started, "error": error}
        save(directory / "result.json", result)
        print(json.dumps(result), flush=True)
        return 0 if result["status"] == "complete" else 1


if __name__ == "__main__":
    raise SystemExit(main())
