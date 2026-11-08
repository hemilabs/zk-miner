#!/usr/bin/env python3
"""Bounded local WorkerPool acceptance with real proofs and preserved failure evidence."""
import argparse
import fcntl
import hashlib
import json
import os
import re
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import time
import uuid

from proof_provenance import sha, verify_build as verify_verifier
from worker_provenance import verify_build as verify_worker, paths as worker_paths
from smoke import DIGEST, IMAGE, validate_proof_evidence

ROOT = Path(__file__).resolve().parents[2]
BASE = ROOT / "target/macos"


def workload(name, iterations=None):
    """Expected public output is computed independently of all generated receipts."""
    if name == "fibonacci":
        n = 20 if iterations is None else iterations
        if not 0 <= n <= 10_000_000: raise ValueError("Fibonacci iterations must be 0..10000000")
        mask = (1 << 64) - 1
        def fib(k):
            if not k: return 0, 1
            a, b = fib(k // 2)
            c, d = a * (2*b-a) & mask, (a*a+b*b) & mask
            return (d, (c+d) & mask) if k & 1 else (c, d)
        return n.to_bytes(4, "little"), fib(n)[0].to_bytes(8, "little").hex(), 18, 1
    if name == "sha256-chain":
        digest = bytes(32)
        n = 10 if iterations is None else iterations
        if not 0 <= n <= 20_000: raise ValueError("hash iterations must be 0..20000")
        for i in range(n):
            digest = hashlib.sha256(digest + i.to_bytes(4, "little")).digest()
        return n.to_bytes(4, "little"), digest.hex(), 18, 1
    if name == "segment-boundary":
        n = 8 if iterations is None else iterations
        if not 0 <= n <= 4096: raise ValueError("boundary units must be 0..4096")
        return ((1).to_bytes(4, "little") + n.to_bytes(4, "little"),
                (0x123456789ABCDEF0 + n*1024).to_bytes(8, "little").hex(), 16, 5 if iterations is None else 1)
    raise ValueError("unknown workload")


def test_sources():
    files = [ROOT / "Cargo.toml", ROOT / "Cargo.lock", Path(__file__).resolve()]
    files += [ROOT / "scripts/macos" / name for name in ("smoke.py", "proof_provenance.py", "worker_provenance.py")]
    for crate in ("zkminer-prover", "zkminer-prover-protocol", "zkminer-config"):
        for path in (ROOT / "crates" / crate).rglob("*"):
            if path.is_file() and "target" not in path.relative_to(ROOT).parts:
                files.append(path)
    return {str(path.relative_to(ROOT)): sha(path) for path in sorted(set(files))}


def build_acceptance(attempt, env):
    before = test_sources()
    command = ["cargo", "+1.93.0", "test", "--locked", "-p", "zkminer-prover", "--test", "macos_worker",
               "--no-run", "--message-format=json", "--target-dir", str(BASE / "worker-acceptance-build")]
    if env.get("ZKMINER_MACOS_THREAD_CASES"):
        command += ["--features", "testing"]
    with (attempt / "test-build.jsonl").open("w") as out, (attempt / "test-build.stderr").open("w") as err:
        subprocess.run(command, cwd=ROOT, env=env, stdout=out, stderr=err, timeout=600, check=True)
    if test_sources() != before:
        raise RuntimeError("WorkerPool acceptance source inputs changed during the test build")
    binaries = set()
    for line in (attempt / "test-build.jsonl").read_text().splitlines():
        record = json.loads(line)
        if record.get("reason") == "compiler-artifact" and record.get("target", {}).get("name") == "macos_worker" and record.get("executable"):
            binaries.add(record["executable"])
    if len(binaries) != 1:
        raise RuntimeError("build did not identify exactly one real macOS acceptance test executable")
    binary = Path(binaries.pop())
    manifest = {"source_inputs": before, "binary_path": str(binary), "binary_sha256": sha(binary), "command": command}
    (attempt / "acceptance-build.json").write_text(json.dumps(manifest, indent=2) + "\n")
    return binary, manifest


def read_sidecars(directory, tolerate_errors=False):
    records = []
    for path in sorted(directory.glob("*.json")):
        try:
            records.append(json.loads(path.read_text()))
        except (ValueError, OSError):
            if not tolerate_errors:
                raise
    return records


def owned_process(pid, parent):
    result = subprocess.run(["ps", "-o", "ppid=,pgid=", "-p", str(pid)], capture_output=True, text=True, timeout=5)
    parts = result.stdout.split()
    return result.returncode == 0 and parts == [str(parent), str(pid)]


def validate_results(attempt, args, expected, fixture):
    acceptance = attempt / "acceptance"
    summary = json.loads((acceptance / "complete.json").read_text())
    count = args.repeat + (0 if args.proof_only else 1)
    if (summary.get("status") != "complete_independently_verified" or summary.get("verified_proofs") != count
            or summary.get("requested_mode") != args.mode or summary.get("observed_mode") != expected
            or summary.get("shutdown") is not True):
        raise RuntimeError("missing completed real-proof acceptance summary")
    records = [json.loads(path.read_text()) for path in sorted(acceptance.glob("proof-*/worker.json"))]
    if len(records) != count:
        raise RuntimeError("verified proof count differs from saved worker evidence")
    for path in sorted(acceptance.glob("proof-*/worker.json")):
        record = json.loads(path.read_text())
        verification = json.loads(path.with_name("verification.json").read_text())
        if (record.get("phase") != "complete" or record.get("requested_mode") != args.mode
                or record.get("observed_mode") != expected or record.get("seal_sha256") != sha(path.with_name("seal.bin"))
                or record.get("journal_hex") != fixture["expected_journal_hex"]
                or record.get("elf_sha256") != fixture["elf_sha256"]
                or record.get("input_sha256") != fixture["input_sha256"]
                or record.get("po2") != args.po2
                or record.get("staging_limit_bytes") is not None
                or record.get("stats", {}).get("segments", 0) < fixture["min_segments"]
                or verification.get("image_id") != record.get("image_id") or verification.get("verification") != "passed"
                or verification.get("journal_hex") != fixture["expected_journal_hex"]
                or verification.get("elf_sha256") != fixture["elf_sha256"]
                or set(verification.get("negative_tests", [])) != {"wrong_image", "modified_journal", "corrupt_seal"}):
            raise RuntimeError("worker proof binding or unchanged independent verification evidence is incomplete")
        validate_proof_evidence(dict(record, requested_mode=expected), expected)
        if args.mode == "auto" and expected == "cpu" and not record.get("fallback_reason"):
            raise RuntimeError("auto CPU fallback lacks a recorded reason")
        resource = json.loads(path.with_name("resource.json").read_text())
        if (resource.get("worker_pid") != record.get("worker_pid")
                or resource.get("worker_start_time_us", 0) <= 0
                or resource.get("periodic_sample_count", 0) <= 0
                or not (0 < resource.get("peak_rss_bytes", 0) <= 32 * 1024**3)):
            raise RuntimeError("missing owned-worker periodic RSS evidence for completed proof")
        idle = resource.get("idle_after_verification_and_settle", {})
        if "unavailable_reason" not in idle and (idle.get("rss_bytes", 0) <= 0
                or idle.get("worker_pid") != record.get("worker_pid")
                or idle.get("worker_start_time_us") != resource.get("worker_start_time_us")):
            raise RuntimeError("idle resource evidence has the wrong worker identity")
    ledger = [json.loads(line) for line in (acceptance / "requests.jsonl").read_text().splitlines()]
    successes = [row for row in ledger if row.get("status") == "complete_independently_verified"]
    expected_cases = [f"proof-{i}" for i in range(args.repeat)]
    if not args.proof_only:
        expected_cases.append("proof-after-restart")
    if [row.get("case") for row in successes] != expected_cases:
        raise RuntimeError("ordered successful request ledger is incomplete")
    identities = [(row["worker"]["worker_pid"], row["worker"]["request_id"]) for row in successes]
    if len(set(identities)) != count:
        raise RuntimeError("successful worker request identity was reused")
    if any(row["worker"]["stats"] != successes[0]["worker"]["stats"] for row in successes):
        raise RuntimeError("same guest/input produced inconsistent cycle or segment statistics")
    permitted = {"started", "complete_independently_verified"}
    if args.admission_pressure:
        permitted.add("expected_admission_refusal")
    if args.proof_only and any(row.get("status") not in permitted for row in ledger):
        raise RuntimeError("proof-only stability ledger contains a failed or retried request")
    pressure_entries = [row for row in ledger if row.get("case") == "admission-pressure"]
    pressure_rows = [row for row in pressure_entries if row.get("status") == "expected_admission_refusal"]
    if args.admission_pressure:
        pressure = json.loads((acceptance / "pressure.json").read_text())
        if (len(pressure_entries) != 2 or pressure_entries[0].get("status") != "started"
                or len(pressure_rows) != 1 or pressure_rows[0].get("status") != "expected_admission_refusal"
                or pressure_rows[0].get("pressure") != pressure
                or pressure.get("kind") != "in_flight_reservation_admission"
                or pressure.get("attempted") is not False or pressure.get("reserved_after_bytes") != 0
                or pressure.get("reserved_before_bytes") != 0 or pressure.get("reserved_held_bytes", 0) <= 0
                or pressure.get("reserved_held_bytes", 0) + pressure.get("needed_bytes", 0) + pressure.get("host_reserve_bytes", 0) <= pressure.get("host_total_bytes", 0)
                or pressure.get("sidecar_count_before") != pressure.get("sidecar_count_after")
                or pressure.get("helper_count_after") != 0 or summary.get("admission_pressure") is not True):
            raise RuntimeError("controlled admission pressure lacks production refusal/release evidence")
    elif pressure_entries or summary.get("admission_pressure") is not False:
        raise RuntimeError("unexpected admission-pressure case")
    streak = longest = 0
    previous = None
    for pid, _ in identities[:args.repeat]:
        streak = streak + 1 if pid == previous else 1
        longest, previous = max(longest, streak), pid
    summary.update(consecutive_verified_requests=args.repeat, worker_pids=list(dict.fromkeys(pid for pid, _ in identities)),
                   longest_same_pid_success_streak=longest)
    if not args.proof_only:
        ledger = [json.loads(line) for line in (acceptance / "requests.jsonl").read_text().splitlines()]
        for case in ("helper-cancel", "helper-timeout"):
            results = [entry for entry in ledger if entry.get("case") == case and entry.get("status") == "expected_failure"]
            if len(results) != 1 or not isinstance(results[0].get("observed_running_helper"), dict):
                raise RuntimeError(f"{case} lacks a failure after observing its owned running helper")
            partial = results[0]["observed_running_helper"]
            pid = partial.get("worker_pid")
            log = (attempt / "test.log").read_text()
            if case == "helper-timeout":
                if (results[0].get("elapsed_seconds", 0) < args.failure_timeout
                        or not re.search(r"Proving timeout \([^)]*\) exceeded for risc0:generic, killing worker PID " + str(pid) + r"\b", log)):
                    raise RuntimeError("helper timeout lacks the production watchdog's exact worker-PID evidence")
            elif f"Cancelling proof on risc0:generic by killing worker PID {pid}" not in log:
                raise RuntimeError("helper cancellation lacks the supervisor's exact worker-PID evidence")
            if f"not killing PID {pid} for risc0:generic" in log:
                raise RuntimeError("supervisor declined the worker identity check during the lifecycle case")
            if (partial.get("phase") != "wrapping" or partial.get("proof_kind") != "succinct"
                    or partial.get("observed_mode") != expected or partial.get("requested_mode") != args.mode):
                raise RuntimeError(f"{case} was not observed during the selected request's wrapping phase")
            stage = partial.get("observed_stages", {}).get("metal_stage")
            if expected == "metal":
                if (not isinstance(stage, dict) or stage.get("completed_dispatches", 0) <= 0
                        or len(stage.get("segments", [])) != partial.get("stats", {}).get("segments")):
                    raise RuntimeError(f"{case} lacks completed Metal stage evidence before wrapping")
            elif stage is not None:
                raise RuntimeError("CPU lifecycle case unexpectedly reports Metal work")
        if not all(summary.get(key) is True for key in ("helper_cancel", "helper_timeout", "restart")):
            raise RuntimeError("lifecycle completion evidence is missing")
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--engine", required=True, type=Path)
    parser.add_argument("--worker-kind", choices=["cpu", "metal"], required=True)
    parser.add_argument("--mode", choices=["cpu", "metal", "auto"], required=True)
    parser.add_argument("--context", required=True)
    parser.add_argument("--repeat", type=int, default=3)
    parser.add_argument("--workload", choices=["fibonacci", "sha256-chain", "segment-boundary"], default="fibonacci")
    parser.add_argument("--iterations", type=int, help="guest iteration count for the selected workload")
    parser.add_argument("--po2", type=int, choices=range(14, 19), help="defaults to 16 for boundary, 18 otherwise")
    parser.add_argument("--admission-pressure", action="store_true", help="exercise bounded logical in-flight reservation pressure; does not exhaust physical RAM")
    parser.add_argument("--proof-only", action="store_true", help="verify selected mode without the separate cancellation/timeout/restart cases")
    parser.add_argument("--timeout", type=int, default=3600, help="total acceptance runtime bound, excluding test compilation")
    parser.add_argument("--failure-timeout", type=int, default=70)
    parser.add_argument("--staging-bytes", type=int, default=524288)
    args = parser.parse_args()
    if args.worker_kind == "metal":
        parser.error("the fold-only worker is retired; use test-native-worker.py --worker-kind native-rv32im-metal --segment-hal metal")
    input_data, expected_journal, default_po2, minimum_segments = workload(args.workload, args.iterations)
    args.po2 = default_po2 if args.po2 is None else args.po2
    if not (1 <= args.repeat <= 100 and 1 <= args.timeout <= 14400 and 1 <= args.failure_timeout <= 300
            and 4096 <= args.staging_bytes <= 16777216):
        parser.error("repeat 1..100, timeout 1..14400, failure timeout 1..300, staging bytes 4096..16777216 required")
    if not args.proof_only and args.repeat < 3:
        parser.error("lifecycle acceptance requires at least three complete repeat proofs")
    if args.admission_pressure and not args.proof_only:
        parser.error("admission pressure requires --proof-only; first real proof verifies recovery")
    if args.mode == "metal" and args.worker_kind != "metal":
        parser.error("forced Metal proving requires a Metal-capable worker build")
    for name in ("RISC0_DEV_MODE", "RISC0_SKIP_BUILD", "RISC0_SKIP_BUILD_KERNELS", "RISC0_SKIP_VERIFY", "DOCS_RS",
                 "RISC0_PROVER", "RISC0_EXECUTOR", "RISC0_SERVER_PATH", "RISC0_API_URL", "BONSAI_API_KEY", "BONSAI_API_URL", "RISC0_TEST_INJECT_INVALID"):
        if name in os.environ:
            parser.error(f"unset {name}; real acceptance rejects proving overrides")
    expected = "metal" if args.worker_kind == "metal" and args.mode != "cpu" else "cpu"
    docker = shutil.which("docker")
    if not docker:
        parser.error("Docker is required for the dedicated local wrapping helper")
    docker_cmd = [docker, "--context", args.context]
    endpoint = subprocess.check_output([docker, "context", "inspect", args.context, "--format", "{{.Endpoints.docker.Host}}"], text=True, timeout=10).strip()
    if not endpoint.startswith("unix://"):
        parser.error("only a dedicated local Unix Docker endpoint is supported")
    info = json.loads(subprocess.check_output(docker_cmd + ["image", "inspect", IMAGE], timeout=10))[0]
    if not any(value.endswith("@" + DIGEST) for value in info.get("RepoDigests", [])):
        parser.error("required pinned helper image digest is absent")
    runs = BASE / "worker-runs"
    runs.mkdir(parents=True, exist_ok=True)
    (BASE / "runs").mkdir(exist_ok=True)
    with (BASE / "runs/active.lock").open("w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        attempt = runs / uuid.uuid4().hex
        attempt.mkdir()
        sidecars = attempt / "requests"
        work = attempt / "shared-work"
        sidecars.mkdir()
        work.mkdir()
        worker = worker_paths(args.worker_kind)["binary"]
        verifier = BASE / "verifier/release/hemi-macos-proof"
        program = BASE / "guest-build/riscv32im-risc0-zkvm-elf/release" / (args.workload + ".bin")
        fixture = {"workload":args.workload, "iterations":args.iterations, "program_path":str(program), "elf_sha256":sha(program),
                   "input_sha256":hashlib.sha256(input_data).hexdigest(), "expected_journal_hex":expected_journal,
                   "po2":args.po2, "min_segments":minimum_segments}
        guest = BASE / "guests" / args.workload
        guest_build = json.loads((guest / "provenance.json").read_text())
        guest_source = ROOT / "crates/zkminer-prover/guests/risc0" / args.workload / "src/main.rs"
        if (guest_build.get("packing", {}).get("program_sha256") != fixture["elf_sha256"]
                or guest_build.get("source_sha256") != sha(guest_source)
                or guest_build.get("elf_sha256") != sha(program.with_suffix(""))):
            raise RuntimeError("selected guest differs from its authentic source/build provenance")
        guest_inputs = {str(path):sha(path) for path in [guest / "provenance.json", guest / "Cargo.toml",
                        guest / "Cargo.lock", guest / "metadata.json", guest_source, program.with_suffix("")]}
        (attempt / "guest-build.json").write_text(json.dumps({"provenance":guest_build, "inputs":guest_inputs}, indent=2) + "\n")
        (attempt / "input.bin").write_bytes(input_data)
        (attempt / "fixture.json").write_text(json.dumps(fixture, indent=2) + "\n")
        report = {"id":attempt.name, "status":"failed", "requested_mode":args.mode, "expected_mode":expected,
                  "worker_kind":args.worker_kind, "repeat":args.repeat, "lifecycle":not args.proof_only,
                  "fixture":fixture, "admission_pressure":args.admission_pressure, "runner_command":[sys.executable, str(Path(__file__).resolve()), *sys.argv[1:]],
                  "helper_arch":"linux/amd64", "helper_image":DIGEST, "helper_context":args.context,
                  "helper_endpoint":endpoint, "worker_peak_rss_bytes":{},
                  "rss_method":"owned native worker RSS sampled once per second with latest observed request phase; excludes helper VM and unmeasured driver allocations"}
        proc = None
        started = time.monotonic()
        print(attempt, flush=True)
        try:
            miner_diff = subprocess.check_output(["git", "diff", "HEAD", "--binary"], cwd=ROOT)
            (attempt / "miner-acceptance.patch").write_bytes(miner_diff)
            report.update(miner_head_at_acceptance=subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
                          miner_working_diff_sha256=hashlib.sha256(miner_diff).hexdigest(),
                          miner_revision_scope="acceptance source snapshot; worker build inputs are independently sealed")
            worker_build = verify_worker(args.worker_kind, args.engine, worker)
            verifier_build = verify_verifier("verifier", verifier)
            for name, value in (("worker-build", worker_build), ("verifier-build", verifier_build)):
                (attempt / f"{name}.json").write_text(json.dumps(value, indent=2) + "\n")
            report.update(worker_binary_sha256=sha(worker), verifier_binary_sha256=sha(verifier), program_sha256=sha(program))
            env = os.environ.copy()
            env.update(ZKMINER_MACOS_WORKER=str(worker), ZKMINER_MACOS_WORKER_KIND=args.worker_kind,
                       ZKMINER_MACOS_PROGRAM=str(program), ZKMINER_MACOS_VERIFIER=str(verifier),
                       ZKMINER_MACOS_WORKLOAD=args.workload, ZKMINER_MACOS_INPUT=str(attempt / "input.bin"),
                       ZKMINER_MACOS_EXPECTED_JOURNAL_HEX=expected_journal, ZKMINER_MACOS_PO2=str(args.po2),
                       ZKMINER_MACOS_MIN_SEGMENTS=str(minimum_segments),
                       ZKMINER_MACOS_ADMISSION_PRESSURE="1" if args.admission_pressure else "0",
                       ZKMINER_MACOS_EVIDENCE_DIR=str(attempt / "acceptance"), ZKMINER_RISC0_EVIDENCE_DIR=str(sidecars),
                       ZKMINER_RISC0_WORK_ROOT=str(work), ZKMINER_RISC0_DOCKER_CONTEXT=args.context,
                       ZKMINER_RISC0_MODE=args.mode, ZKMINER_MACOS_EXPECT_MODE=expected,
                       ZKMINER_MACOS_REPEAT=str(args.repeat), ZKMINER_MACOS_LIFECYCLE="0" if args.proof_only else "1",
                       ZKMINER_MACOS_FAILURE_TIMEOUT_SECS=str(args.failure_timeout),
                       RAYON_NUM_THREADS="6")
            binary, test_build = build_acceptance(attempt, env)
            report["command"] = [str(binary), "native_worker_proofs_failure_restart_and_shutdown",
                                 "--exact", "--ignored", "--nocapture"]
            test_started = time.monotonic()
            with (attempt / "test.log").open("w") as log:
                proc = subprocess.Popen(report["command"], cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
                while proc.poll() is None:
                    if time.monotonic() - test_started > args.timeout:
                        raise TimeoutError("native worker acceptance deadline exceeded")
                    latest = {}
                    for record in read_sidecars(sidecars):
                        pid = record.get("worker_pid")
                        if type(pid) is int and record.get("request_id", -1) > latest.get(pid, {}).get("request_id", -2):
                            latest[pid] = record
                    for record in latest.values():
                        pid = record.get("worker_pid")
                        if type(pid) is int and owned_process(pid, proc.pid):
                            rss = subprocess.run(["ps", "-o", "rss=", "-p", str(pid)], capture_output=True, text=True, timeout=5)
                            if rss.returncode == 0 and rss.stdout.strip():
                                value = int(rss.stdout.strip()) * 1024
                                with (attempt / "rss-samples.jsonl").open("a") as samples:
                                    samples.write(json.dumps({"elapsed_seconds":time.monotonic()-test_started,
                                        "worker_pid":pid,"request_id":record.get("request_id"),
                                        "phase":record.get("phase"),"rss_bytes":value}) + "\n")
                                key = str(pid)
                                report["worker_peak_rss_bytes"][key] = max(report["worker_peak_rss_bytes"].get(key, 0), value)
                                if value > 32 * 1024**3:
                                    raise RuntimeError("owned native worker exceeded the 32 GiB RSS ceiling")
                    try:
                        proc.wait(timeout=1)
                    except subprocess.TimeoutExpired:
                        pass
            report["test_exit_code"] = proc.returncode
            if proc.returncode:
                raise RuntimeError(f"real native worker acceptance failed ({proc.returncode}); see test.log")
            if verify_worker(args.worker_kind, args.engine, worker) != worker_build or verify_verifier("verifier", verifier) != verifier_build:
                raise RuntimeError("worker/verifier sealed build changed during acceptance")
            if test_sources() != test_build["source_inputs"] or sha(binary) != test_build["binary_sha256"]:
                raise RuntimeError("acceptance test source or executable changed during the run")
            if (sha(program) != fixture["elf_sha256"] or sha(attempt / "input.bin") != fixture["input_sha256"]
                    or any(sha(Path(path)) != digest for path, digest in guest_inputs.items())):
                raise RuntimeError("selected guest or input changed during acceptance")
            report["results"] = validate_results(attempt, args, expected, fixture)
            report["status"] = "complete_independently_verified"
        except (Exception, KeyboardInterrupt) as error:
            report["error"] = str(error)
        finally:
            errors = []
            if proc is not None:
                cleanup_records = read_sidecars(sidecars, tolerate_errors=True)
                if proc.poll() is None:
                    # Signal only direct children whose process group matches their PID.
                    for record in cleanup_records:
                        pid = record.get("worker_pid")
                        try:
                            if type(pid) is int and owned_process(pid, proc.pid):
                                os.killpg(pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                        except Exception as error:
                            errors.append(f"worker cleanup: {error}")
                    try:
                        os.killpg(proc.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    try:
                        proc.wait(timeout=15)
                    except Exception as error:
                        errors.append(f"test process cleanup: {error}")
                prefix = f"zkminer-macos-{proc.pid}-"
                names = {path.name for path in work.iterdir() if path.is_dir() and path.name.startswith(prefix)}
                names |= {record.get("helper_container") for record in cleanup_records
                          if isinstance(record.get("helper_container"), str) and record["helper_container"].startswith(prefix)}
                for name in sorted(names):
                    try:
                        cleanup = subprocess.run(docker_cmd + ["rm", "-f", name], capture_output=True, text=True, timeout=15)
                        if cleanup.returncode and "No such container" not in cleanup.stderr:
                            errors.append(cleanup.stderr.strip())
                    except Exception as error:
                        errors.append(str(error))
            if errors:
                report.update(cleanup_errors=errors, status="failed")
            report["elapsed_seconds"] = time.monotonic() - started
            (attempt / "result.json").write_text(json.dumps(report, indent=2) + "\n")
            with (runs / "results.jsonl").open("a") as ledger:
                ledger.write(json.dumps(report) + "\n")
            print(json.dumps({key:report.get(key) for key in ("id", "status", "elapsed_seconds", "error")}))
        return 0 if report["status"] == "complete_independently_verified" else 1


if __name__ == "__main__":
    raise SystemExit(main())
