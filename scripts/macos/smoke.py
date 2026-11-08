#!/usr/bin/env python3
"""Bounded, local-only Groth16 smoke test; each failed attempt stays in the ledger."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import signal
import subprocess
import sys
import time
import uuid
from proof_provenance import sha, verify_build

IMAGE = "risczero/risc0-groth16-prover:v2025-04-03.1"
DIGEST = "sha256:a4f80ce2e0b8e2bb7637a93c37136a6776ac00ec843a3fdf1c67b1d5ffea64ee"


def validate_proof_evidence(proof, mode):
    if proof.get("proof_kind") != "groth16" or proof.get("requested_mode") != mode:
        raise RuntimeError("proof report is not a complete Groth16 proof in the requested mode")
    count = proof.get("stats", {}).get("segments")
    if type(count) is not int or count < 1:
        raise RuntimeError("proof report has no positive segment count")
    stage = proof.get("observed_stages", {}).get("metal_stage")
    if mode == "cpu":
        if stage is not None:
            raise RuntimeError("CPU baseline unexpectedly reports Metal work")
        return
    if not isinstance(stage, dict) or stage.get("name") != "segment_poseidon2_merkle_fold":
        raise RuntimeError("forced Metal proof is missing the declared Merkle fold stage")
    segments = stage.get("segments")
    if not isinstance(segments, list) or len(segments) != count:
        raise RuntimeError("Metal stage evidence does not cover every proved segment")
    indices = []
    dispatches = 0
    positive = ("po2", "completed_dispatches", "fold_calls", "input_digests", "output_digests",
                "peak_staging_bytes", "staging_limit_bytes")
    for segment in segments:
        if not isinstance(segment, dict) or any(type(segment.get(key)) is not int or segment[key] <= 0 for key in positive):
            raise RuntimeError("segment has no positive Metal work or staging evidence")
        index = segment.get("segment_index")
        if type(index) is not int:
            raise RuntimeError("invalid Metal segment index")
        indices.append(index)
        if (segment["input_digests"] != 2 * segment["output_digests"]
                or segment["completed_dispatches"] < segment["fold_calls"]
                or not 4096 <= segment["staging_limit_bytes"] <= 16 * 1024**2
                or segment["peak_staging_bytes"] > segment["staging_limit_bytes"]):
            raise RuntimeError("inconsistent Metal fold work or exceeded staging budget")
        dispatches += segment["completed_dispatches"]
    if sorted(indices) != list(range(count)) or stage.get("completed_dispatches") != dispatches:
        raise RuntimeError("Metal segment indices or completed dispatch total are inconsistent")

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--context", required=True, help="dedicated local Docker context")
    parser.add_argument("--mode", choices=["cpu", "metal"], default="cpu")
    parser.add_argument("--engine", type=Path, help="exact local engine checkout; required in Metal mode")
    parser.add_argument("--repeat", type=int, default=2)
    parser.add_argument("--timeout", type=int, default=1800, help="seconds per complete proof")
    parser.add_argument("--rss-gib", type=int, default=32, help="native prover RSS watchdog ceiling")
    parser.add_argument("--po2", type=int, default=18)
    parser.add_argument("--workload", choices=["fibonacci", "sha256-chain", "segment-boundary"], default="fibonacci")
    args = parser.parse_args()
    if args.mode == "metal":
        parser.error("the fold-only smoke path is retired; use test-native-worker.py with the resident Metal worker")
    if args.mode == "metal" and args.engine is None:
        parser.error("--engine is required for a source-bound Metal proof")
    if not (1 <= args.repeat <= 100 and 1 <= args.timeout <= 7200 and 1 <= args.rss_gib <= 48 and 13 <= args.po2 <= 20):
        parser.error("repeat 1..100, timeout 1..7200, RSS GiB 1..48, po2 13..20 required")
    root = Path(__file__).resolve().parents[2]
    base = root / "target/macos"
    for name in ("RISC0_DEV_MODE", "RISC0_SKIP_BUILD", "RISC0_SKIP_BUILD_KERNELS", "RISC0_SKIP_VERIFY", "DOCS_RS", "RISC0_PROVER",
                 "RISC0_EXECUTOR", "RISC0_SERVER_PATH", "RISC0_API_URL", "BONSAI_API_KEY", "BONSAI_API_URL", "RISC0_TEST_INJECT_INVALID"):
        if name in os.environ:
            parser.error(f"unset {name}; acceptance does not mask unsafe overrides")
    docker = shutil.which("docker")
    if not docker:
        parser.error("Docker is required for this explicitly emulated wrapping bootstrap")
    endpoint = subprocess.check_output([docker, "context", "inspect", args.context, "--format",
                                        "{{.Endpoints.docker.Host}}"], text=True).strip()
    if not endpoint.startswith("unix://"):
        parser.error("only a dedicated local Docker socket is supported")
    docker_cmd = [docker, "--context", args.context]
    info = json.loads(subprocess.check_output(docker_cmd + ["image", "inspect", IMAGE]))[0]
    if not any(d.endswith("@" + DIGEST) for d in info.get("RepoDigests", [])):
        parser.error("helper image digest differs from recorded pinned bootstrap image")
    elf = base / "guest-build/riscv32im-risc0-zkvm-elf/release" / (args.workload + ".bin")
    prover = base / ("cpu/release/hemi-macos-proof" if args.mode == "cpu"
                     else "hybrid/release/hemi-macos-hybrid-proof")
    verifier = base / "verifier/release/hemi-macos-proof"
    for path in (elf, prover, verifier):
        if not path.is_file():
            parser.error(f"required artifact missing: {path}")
    runs = base / "runs"
    runs.mkdir(parents=True, exist_ok=True)
    with (runs / "active.lock").open("w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        for _ in range(args.repeat):
            run_id = uuid.uuid4().hex
            attempt = runs / run_id
            attempt.mkdir()
            (attempt / "wrap").mkdir()
            wrapper = attempt / "bin"
            wrapper.mkdir()
            container = "hemi-macos-" + run_id
            # Every SDK docker invocation is pinned to this dedicated context.
            # Only this request's named container can be removed on cancellation.
            script = "#!/bin/sh\nset -eu\ncase \"$1\" in\nrun) shift; exec " + shlex.join(docker_cmd + [
                "run", "--platform", "linux/amd64", "--pull", "never", "--network", "none",
                "--memory", "24g", "--cpus", "6", "--name", container,
            ]) + ' "$@" ;;\n--version) exec ' + shlex.join(docker_cmd) + ' "$@" ;;\n*) echo "unexpected Docker operation" >&2; exit 2 ;;\nesac\n'
            (wrapper / "docker").write_text(script)
            (wrapper / "docker").chmod(0o755)
            # Independent expected public outputs, never taken from a receipt.
            if args.workload == "fibonacci":
                input_data = (20).to_bytes(4, "little")
                a, b = 0, 1
                for _ in range(20):
                    a, b = b, a + b
                expected = a.to_bytes(8, "little").hex()
            elif args.workload == "sha256-chain":
                input_data = (10).to_bytes(4, "little")
                digest = bytes(32)
                for i in range(10):
                    digest = hashlib.sha256(digest + i.to_bytes(4, "little")).digest()
                expected = digest.hex()
            else:
                # 8192 non-elidable u64 additions. Use --po2 16 for this pinned guest.
                input_data = (1).to_bytes(4, "little") + (8).to_bytes(4, "little")
                expected = (0x123456789ABCDEF0 + 8192).to_bytes(8, "little").hex()
            (attempt / "input.bin").write_bytes(input_data)
            env = os.environ.copy()
            env.update(PATH=str(wrapper) + os.pathsep + env["PATH"], RAYON_NUM_THREADS="6",
                       RISC0_WORK_DIR=str(attempt / "wrap"))
            common = [str(elf), str(attempt / "input.bin"), expected, str(attempt / "proof"), str(args.po2)]
            started = time.monotonic()
            report = {"run_id": run_id, "workload": args.workload, "helper_image": DIGEST,
                      "helper_arch": "linux/amd64", "helper_context": args.context,
                      "requested_mode": args.mode, "status": "failed", "native_peak_rss_bytes": 0,
                      "prover_binary_sha256": sha(prover), "verifier_binary_sha256": sha(verifier),
                      "runner_sha256": sha(Path(__file__).resolve()), "elf_sha256": sha(elf),
                      "input_sha256": hashlib.sha256(input_data).hexdigest(), "expected_journal_hex": expected,
                      "helper_endpoint": endpoint,
                      "rss_method": "ps RSS of owned native prover, sampled every 5s; excludes VM/helper", "command": [str(prover), "prove", *common]}
            proc = None
            print(f"attempt {run_id}: {attempt}", flush=True)
            try:
                verifier_build = verify_build("verifier", verifier)
                (attempt / "verifier-build.json").write_text(json.dumps(verifier_build, indent=2) + "\n")
                report["verifier_build"] = verifier_build
                if args.mode == "metal":
                    hybrid_build = verify_build("hybrid", prover, args.engine)
                    (attempt / "hybrid-build.json").write_text(json.dumps(hybrid_build, indent=2) + "\n")
                    report["hybrid_build"] = hybrid_build
                with (attempt / "prover.log").open("w") as log:
                    proc = subprocess.Popen(report["command"], env=env, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
                    while proc.poll() is None:
                        if time.monotonic() - started > args.timeout:
                            raise TimeoutError("complete proof deadline exceeded")
                        rss = subprocess.run(["ps", "-o", "rss=", "-p", str(proc.pid)], capture_output=True, text=True)
                        if rss.returncode == 0 and rss.stdout.strip():
                            value = int(rss.stdout.strip()) * 1024
                            report["native_peak_rss_bytes"] = max(report["native_peak_rss_bytes"], value)
                            if value > args.rss_gib * 1024**3:
                                raise RuntimeError("native prover RSS ceiling exceeded")
                        elif proc.poll() is None:
                            raise RuntimeError("cannot observe owned prover RSS")
                        try:
                            proc.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            pass
                    if proc.returncode:
                        raise RuntimeError(f"prover exited {proc.returncode}; see prover.log")
                proof_info = json.loads((attempt / "proof/proof.json").read_text())
                report["proof"] = proof_info
                validate_proof_evidence(proof_info, args.mode)
                if args.mode == "metal" and verify_build("hybrid", prover, args.engine) != hybrid_build:
                    raise RuntimeError("sealed hybrid build changed during proving")
                if verify_build("verifier", verifier) != verifier_build:
                    raise RuntimeError("sealed verifier build changed before independent verification")
                with (attempt / "verifier.log").open("w") as log:
                    subprocess.run([str(verifier), "verify", *common], env=env, stdout=log,
                                   stderr=subprocess.STDOUT, check=True, timeout=60)
                if verify_build("verifier", verifier) != verifier_build:
                    raise RuntimeError("sealed verifier build changed during independent verification")
                verification = json.loads((attempt / "proof/verification.json").read_text())
                if (verification.get("verification") != "passed"
                        or verification.get("journal_hex") != expected
                        or verification.get("image_id") != proof_info.get("image_id")
                        or set(verification.get("negative_tests", [])) != {"wrong_image", "modified_journal", "corrupt_seal"}):
                    raise RuntimeError("independent verifier report is missing expected identity, output, or negative tests")
                report["verification"] = verification
                if args.workload == "segment-boundary":
                    if proof_info["stats"]["segments"] < 2:
                        raise RuntimeError("multi-segment workload produced fewer than two segments; lower po2")
                report["status"] = "complete_independently_verified"
            except (Exception, KeyboardInterrupt) as error:
                report["error"] = str(error)
            finally:
                if proc is not None and proc.poll() is None:
                    os.killpg(proc.pid, signal.SIGKILL)
                    proc.wait()
                # --rm normally removed it already; cleanup is exact-name only.
                try:
                    cleanup = subprocess.run(docker_cmd + ["rm", "-f", container], capture_output=True, text=True, timeout=30)
                    if cleanup.returncode and "No such container" not in cleanup.stderr:
                        raise RuntimeError(cleanup.stderr)
                except Exception as error:
                    report["cleanup_error"] = str(error)
                    report["status"] = "failed"
                report["total_ms"] = (time.monotonic() - started) * 1000
                (attempt / "result.json").write_text(json.dumps(report, indent=2) + "\n")
                with (runs / "results.jsonl").open("a") as ledger:
                    ledger.write(json.dumps(report) + "\n")
                print(json.dumps(report), flush=True)
            if report["status"] != "complete_independently_verified":
                return 1
    return 0

if __name__ == "__main__":
    sys.exit(main())
