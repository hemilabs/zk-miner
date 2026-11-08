#!/usr/bin/env python3
"""Rewrap an archived identity input and verify with the sealed unchanged verifier."""
import argparse
from datetime import datetime, timezone
import fcntl
import json
from pathlib import Path
import shutil
import subprocess
import time
import uuid

from proof_provenance import ROOT, sha, verify_build

BASE = ROOT / "target/macos"
VERIFIER = BASE / "verifier/release/hemi-macos-proof"
NEGATIVES = {"wrong_image", "modified_journal", "corrupt_seal"}


def save(path, value):
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2) + "\n")
    temporary.replace(path)


def proof_seal(proof):
    """Pinned risc0-groth16 ProofJson -> Seal::to_vec, including G2 limb order."""
    if proof.get("protocol") != "groth16" or proof.get("curve") != "bn254":
        raise ValueError("expected Groth16 BN254 proof JSON")
    a, b, c = proof["pi_a"], proof["pi_b"], proof["pi_c"]
    if len(a) != 3 or len(c) != 3 or len(b) != 3 or any(len(row) != 2 for row in b):
        raise ValueError("invalid proof coordinate lengths")
    if a[2] != "1" or c[2] != "1" or b[2] != ["1", "0"]:
        raise ValueError("expected normalized affine proof coordinates")
    values = [a[0], a[1], b[0][1], b[0][0], b[1][1], b[1][0], c[0], c[1]]
    if any(not isinstance(v, str) or not v.isascii() or not v.isdecimal() for v in values):
        raise ValueError("expected unsigned decimal proof coordinates")
    return b"".join(int(value).to_bytes(32, "big") for value in values)


def verify(directory, elf, source, expected):
    command = [str(VERIFIER), "verify-seal", str(elf), str(source / "input.bin"),
               expected, str(directory), "18"]
    with (directory / "verifier.log").open("w") as log:
        subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, check=True, timeout=60)
    result = json.loads((directory / "verification.json").read_text())
    if result["verification"] != "passed" or set(result["negative_tests"]) != NEGATIVES:
        raise RuntimeError("independent verification or negative checks are incomplete")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", type=Path, required=True, help="successful arm64-wrap-builds directory")
    parser.add_argument("--source", type=Path, required=True, help="previous independently verified run")
    parser.add_argument("--layout", choices=["serial", "pipeline"], default="serial")
    parser.add_argument("--threads", type=int, default=6)
    parser.add_argument("--timeout", type=int, default=1800)
    args = parser.parse_args()
    if not 1 <= args.threads <= 6 or not 1 <= args.timeout <= 3600:
        parser.error("initial feasibility requires 1..6 threads and a 1..3600 second timeout")
    build_dir, source = args.build.resolve(), args.source.resolve()
    build = json.loads((build_dir / "result.json").read_text())
    if build.get("status") != "built" or build.get("platform") != "linux/arm64":
        raise RuntimeError("a successful ARM64 build is required")
    for name, digest in build["source_files"].items():
        if sha(build_dir / "context" / name) != digest:
            raise RuntimeError(f"build input changed: {name}")
    docker = ["docker", "--context", build["context"]]
    endpoint = subprocess.check_output(docker + ["context", "inspect", build["context"],
                                      "--format", "{{.Endpoints.docker.Host}}"], text=True, timeout=30)
    if not endpoint.strip().startswith("unix://"):
        raise RuntimeError("only the local Docker socket is supported")
    image = json.loads(subprocess.check_output(docker + ["image", "inspect", build["image_id"]], timeout=30))[0]
    if (image["Os"], image["Architecture"], image["Id"]) != ("linux", "arm64", build["image_id"]):
        raise RuntimeError("helper image identity or architecture mismatch")
    verifier_build = verify_build("verifier")
    prior = json.loads((source / "result.json").read_text())
    proof = json.loads((source / "proof/proof.json").read_text())
    if prior["status"] != "complete_independently_verified":
        raise RuntimeError("source run did not complete independent verification")
    elf = Path(prior["command"][2])
    if sha(elf) != proof["elf_sha256"] or sha(source / "input.bin") != proof["input_sha256"]:
        raise RuntimeError("source program or input hash mismatch")
    expected = proof["journal_hex"]
    if (source / "proof/journal.bin").read_bytes().hex() != expected:
        raise RuntimeError("source journal mismatch")
    if proof_seal(json.loads((source / "wrap/proof.json").read_text())) != (source / "proof/seal.bin").read_bytes():
        raise RuntimeError("JSON seal conversion disagrees with archived SDK output")
    runs = BASE / "wrap-runs"
    runs.mkdir(parents=True, exist_ok=True)
    with (runs / "active.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        run_id = uuid.uuid4().hex
        directory = runs / run_id
        directory.mkdir()
        reference = directory / "reference"
        reference.mkdir()
        for name in ("seal.bin", "journal.bin"):
            shutil.copyfile(source / "proof" / name, reference / name)
        verify(reference, elf, source, expected)
        for name in ("input.json", "seal.r0"):
            shutil.copyfile(source / "wrap" / name, directory / name)
        shutil.copyfile(source / "proof/journal.bin", directory / "journal.bin")
        script = ROOT / "scripts/macos/wrap-stages.sh"
        shutil.copyfile(script, directory / "wrap-stages.sh")
        container = "zkminer-wrap-feasibility-" + run_id
        command = docker + ["run", "--rm", "--name", container, "--pull", "never",
                            "--network", "none", "--platform", "linux/arm64", "--memory", "24g",
                            "--cpus", "6", "--env", f"GOMAXPROCS={args.threads}",
                            "--mount", f"type=bind,source={directory},target=/mnt",
                            "--entrypoint", "timeout", build["image_id"], str(args.timeout),
                            "/bin/bash", "/mnt/wrap-stages.sh" if args.layout == "serial" else "/app/prover.sh"]
        report = {"schema_version": 1, "run_id": run_id, "status": "running",
                  "started_at_utc": datetime.now(timezone.utc).isoformat(),
                  "source_run": str(source), "workload": prior["workload"], "stats": proof["stats"],
                  "build_result_sha256": sha(build_dir / "result.json"), "build_directory": str(build_dir),
                  "image_id": build["image_id"], "helper_arch": "linux/arm64",
                  "runner_sha256": sha(Path(__file__).resolve()), "timing_script_sha256": sha(script),
                  "elf_sha256": sha(elf), "input_json_sha256": sha(directory / "input.json"),
                  "identity_seal_sha256": sha(directory / "seal.r0"), "verifier_build": verifier_build,
                  "layout": args.layout, "gomaxprocs": args.threads, "helper_cpus": 6,
                  "helper_memory_bytes": 24 * 1024**3, "command": command,
                  "timing_method": "host monotonic includes container launch/exit; serial stage times use VM wall clock; prover includes key/CS loading"}
        save(directory / "result.json", report)
        print(directory, flush=True)
        start = time.monotonic()
        try:
            with (directory / "helper.log").open("w") as log:
                subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, check=True, timeout=args.timeout + 30)
            report["wrap_call_seconds"] = time.monotonic() - start
            if args.layout == "serial":
                stages = json.loads((directory / "stages.json").read_text())
                if any(type(n) is not int or n <= 0 for n in stages.values()):
                    raise RuntimeError("invalid stage timings")
                if stages["serial_total_ns"] != stages["witness_ns"] + stages["prover_including_load_ns"]:
                    raise RuntimeError("stage timings do not sum")
                report["stage_seconds"] = {k.removesuffix("_ns"): v / 1e9 for k, v in stages.items()}
            seal = proof_seal(json.loads((directory / "proof.json").read_text()))
            (directory / "seal.bin").write_bytes(seal)
            report["verification"] = verify(directory, elf, source, expected)
            report["seal_sha256"] = sha(directory / "seal.bin")
            report["status"] = "complete_independently_verified"
        except BaseException as error:
            report.update(status="failed", error=str(error))
            raise
        finally:
            # Remove only this invocation's exact helper if timeout/interrupt left it alive.
            try:
                subprocess.run(docker + ["rm", "-f", container], stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, timeout=20)
            except subprocess.TimeoutExpired:
                report["cleanup_error"] = "Docker cleanup timed out; container has an internal deadline"
            report["attempt_seconds"] = time.monotonic() - start
            save(directory / "result.json", report)


if __name__ == "__main__":
    main()
