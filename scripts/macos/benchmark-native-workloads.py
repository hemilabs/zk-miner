#!/usr/bin/env python3
"""Serial step-4 acceptance: boundary proofs, fixed 10M fixtures, and lifecycle."""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import statistics
import subprocess
import sys
import threading
import time
import uuid
from proof_provenance import ROOT, sha, verify_build
from worker_provenance import verify_build as verify_worker


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--engine", type=Path, required=True)
    parser.add_argument("--stretch", action="store_true", help="also prove 46M guest cycles once")
    parser.add_argument("--worker-kind", choices=["native", "native-recursion-metal"], default="native")
    parser.add_argument("--recursion-hal", choices=["cpu", "metal"], default="cpu")
    parser.add_argument("--recursion-comparison", action="store_true", help="five warm CPU/Metal pairs on the same worker binary")
    parser.add_argument("--large-repeats", type=int, choices=[1,5], default=5,
                        help="one first-process observation or the five-proof warm acceptance set")
    args = parser.parse_args()
    if args.recursion_comparison and args.worker_kind != "native-recursion-metal":
        parser.error("recursion comparison requires the native-recursion-metal worker")
    worker, verifier = verify_worker(args.worker_kind, args.engine), verify_build("verifier")
    directory = ROOT / "target/macos/native-wrap/workload-campaigns" / uuid.uuid4().hex
    directory.mkdir(parents=True)
    common = [sys.executable, str(ROOT / "scripts/macos/test-native-worker.py"), "--engine", str(args.engine),
              "--worker-kind",args.worker_kind,"--recursion-hal",args.recursion_hal]
    cases = [
        ("limits", ["--limit-controls", "--repeat", "1", "--proof-only"]),
        ("tiny-tail", ["--workload", "segment-boundary", "--iterations", "0", "--po2", "14", "--repeat", "1", "--proof-only"]),
        ("segment-boundary", ["--workload", "segment-boundary", "--repeat", "1", "--proof-only"]),
        ("arithmetic-10m", ["--workload", "fibonacci", "--iterations", "1000000", "--min-guest-cycles", "10000000", "--repeat", "5", "--warmup", "--proof-only", "--timeout-seconds", "1800"]),
        ("hash-10m", ["--workload", "sha256-chain", "--iterations", "2262", "--min-guest-cycles", "10000000", "--repeat", "5", "--warmup", "--proof-only", "--timeout-seconds", "1800"]),
    ]
    if args.large_repeats == 1:
        for name, options in cases:
            if name in ["arithmetic-10m", "hash-10m"]:
                options[options.index("--repeat")+1] = "1"
                options.remove("--warmup")
    if args.recursion_comparison:
        cases.insert(3, ("recursion-cpu-metal-pairs", ["--recursion-cases","cpu,metal","--samples","5",
            "--iterations","150000","--po2","20","--proof-only"]))
    if args.stretch:
        cases.append(("arithmetic-46m", ["--workload", "fibonacci", "--iterations", "4600000", "--min-guest-cycles", "46000000", "--repeat", "1", "--proof-only", "--timeout-seconds", "3600"]))
    cases.append(("twenty-request-lifecycle", ["--repeat", "20"]))
    for name, options in cases:
        if name in ["arithmetic-10m", "hash-10m", "arithmetic-46m", "twenty-request-lifecycle"]:
            options.extend(["--po2", "20"])
    report = {"status":"running", "started":datetime.now(timezone.utc).isoformat(),
              "worker_build":worker,"verifier_build":verifier,"script_sha256":sha(Path(__file__)),
              "worker_kind":args.worker_kind,"recursion_hal":args.recursion_hal,"large_repeats":args.large_repeats,
              "cases":[{"name":name,"command":common+options,"status":"pending"} for name,options in cases]}
    (directory / "plan.json").write_text(json.dumps(report, indent=2)+"\n")
    (directory / "driver-source.py").write_bytes(Path(__file__).read_bytes())
    if args.recursion_comparison:
        criterion = {"recorded_at_utc":datetime.now(timezone.utc).isoformat(),"phase":"before any case starts",
            "fixture":"Fibonacci(150000), po2 20, 18 Rayon / 18 Go",
            "primary_metric":"WorkerPool prove call plus unchanged independent verification",
            "measured_pairs":5,"excluded_first_process_warmups_per_case":1,
            "required_median_speedup":1.05,"required_faster_pairs":4,
            "scope":"Repeatable complete-job improvement on the fixed paired fixture; 10M observations remain single proofs when large-repeats=1."}
        (directory / "performance-criterion.json").write_text(json.dumps(criterion,indent=2)+"\n")
    print(directory, flush=True)
    stop = threading.Event()
    def thermal():
        binary = ROOT / "target/macos/benchmark-tools/thermal"
        with (directory / "thermal.jsonl").open("w") as out:
            while not stop.is_set():
                row = {"time":datetime.now(timezone.utc).isoformat()}
                try:
                    sample = subprocess.run([str(binary)], capture_output=True, text=True, check=True, timeout=5)
                    row["observation"] = json.loads(sample.stdout)
                except Exception as error:
                    row["error"] = str(error)
                out.write(json.dumps(row)+"\n");out.flush()
                stop.wait(15)
    thread = threading.Thread(target=thermal, daemon=True)
    thread.start()
    try:
        for row in report["cases"]:
            row.update(status="running", started=datetime.now(timezone.utc).isoformat())
            (directory / "result.json").write_text(json.dumps(report,indent=2)+"\n")
            started = time.monotonic()
            with (directory / (row["name"]+".log")).open("w") as out:
                subprocess.run(row["command"], cwd=ROOT, stdout=out, stderr=subprocess.STDOUT, check=True)
            run = Path((directory / (row["name"]+".log")).read_text().splitlines()[0])
            result = json.loads((run / "result.json").read_text())
            if result["status"] != "passed": raise RuntimeError(f"case did not pass: {row['name']}")
            row.update(status="passed", seconds=time.monotonic()-started, run=str(run), result_sha256=sha(run / "result.json"))
            if row["name"] in ["arithmetic-10m", "hash-10m"]:
                ledger = [json.loads(line) for line in (run / "acceptance/requests.jsonl").read_text().splitlines()]
                proofs = [r for r in ledger if r.get("status")=="complete_independently_verified" and r.get("warmup") is False]
                if len(proofs) != args.large_repeats: raise RuntimeError("missing measured proofs")
                seconds = [(p["timings"]["prove_call_ms"]+p["timings"]["external_verifier_ms"])/1000 for p in proofs]
                row.update(measured_complete_seconds=seconds, median_complete_seconds=statistics.median(seconds),
                           warm_acceptance=args.large_repeats==5,
                           useful_target_passed=statistics.median(seconds)<=600 if args.large_repeats==5 else None)
            if row["name"] == "recursion-cpu-metal-pairs":
                rows = result["results"]["rows"]
                assert len(rows)==12 and result["results"]["samples_per_case"]==5
                medians = {}
                for hal in ["cpu","metal"]:
                    proofs = [p for p in rows if not p['warmup'] and p['worker']['recursion_hal']==hal]
                    assert len(proofs)==5
                    medians[hal] = statistics.median((p['timings']['prove_call_ms']+p['timings']['external_verifier_ms'])/1000 for p in proofs)
                row.update(median_complete_seconds=medians, speedup=medians['cpu']/medians['metal'])
            (directory / "result.json").write_text(json.dumps(report,indent=2)+"\n")
            print(row["name"], "passed", flush=True)
        if verify_worker(args.worker_kind, args.engine) != worker or verify_build("verifier") != verifier:
            raise RuntimeError("build provenance changed during campaign")
        report.update(status="completed", useful_target_passed=all(r["useful_target_passed"] for r in report["cases"] if "useful_target_passed" in r) if args.large_repeats==5 else None)
    except BaseException as error:
        report.update(status="failed", error=str(error))
        for row in report["cases"]:
            if row["status"] == "running": row["status"] = "failed"
        raise
    finally:
        stop.set();thread.join(timeout=6)
        report["finished"] = datetime.now(timezone.utc).isoformat()
        (directory / "result.json").write_text(json.dumps(report,indent=2)+"\n")


if __name__ == "__main__": main()
