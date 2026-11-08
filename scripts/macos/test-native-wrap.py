#!/usr/bin/env python3
"""Native witness parity, real wraps, independent verification, and helper guards."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import signal
import shutil
import subprocess
import sys
import time
import uuid
from proof_provenance import ROOT, sha, verify_build

BASE = ROOT / "target/macos/native-wrap"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--guards-only", action="store_true")
    options = parser.parse_args()
    verify_build("verifier")
    run = BASE / "runs" / uuid.uuid4().hex
    run.mkdir(parents=True)
    poison = run / "bin"
    poison.mkdir()
    docker = poison / "docker"
    docker.write_text("#!/bin/sh\nexit 99\n")
    docker.chmod(0o755)
    env = dict(os.environ, RISC0_GROTH16_NATIVE_DIR=str(BASE / "assets"),
               PATH=str(poison) + os.pathsep + os.environ["PATH"])
    binary = BASE / "rust/release/hemi-native-wrap"
    report = {"schema_version": 1, "status": "running", "directory": str(run),
              "binary_sha256": sha(binary), "bundle": json.loads((BASE / "assets/manifest.json").read_text()),
              "cases": []}
    print(run, flush=True)
    started = time.monotonic()
    spec = importlib.util.spec_from_file_location("worker_acceptance", ROOT / "scripts/macos/test-worker.py")
    acceptance = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(acceptance)
    fixtures = [("fibonacci", "08b5cca54b024b9ca9d3400f41b23b1b", "14b53d756f8347a9abd00af61a6b4c1d"),
                ("sha256-chain", "d811a606185449119e0563797f4aaeef", "57360d2f575f473bb3507d37c5ae5610"),
                ("segment-boundary", "a519537bdfd14f90afa0c536ea5d8ae5", "2a40d8aa0b6f4e7181d52842f3ad1e64")]
    try:
        for name, source_id, reference_id in ([] if options.guards_only else fixtures):
            source = ROOT / "target/macos/runs" / source_id
            reference = ROOT / "target/macos/wrap-runs" / reference_id / "witness.wtns"
            directory = run / name
            directory.mkdir()
            with (directory / "native.log").open("w") as log:
                subprocess.run([str(binary), "witness", str(source / "wrap/seal.r0"), str(directory / "witness.wtns")],
                               env=env, stdout=log, stderr=subprocess.STDOUT, timeout=120, check=True)
                witness_hash = sha(directory / "witness.wtns")
                if witness_hash != sha(reference):
                    raise RuntimeError(f"{name}: witness differs from C++ generator")
                wrap_started = time.monotonic()
                subprocess.run([str(binary), "wrap", str(source / "wrap/seal.r0"), str(directory / "seal.bin")],
                               env=env, stdout=log, stderr=subprocess.STDOUT, timeout=120, check=True)
                wrap_seconds = time.monotonic() - wrap_started
            (directory / "journal.bin").write_bytes((source / "proof/journal.bin").read_bytes())
            previous = json.loads((source / "result.json").read_text())
            command = [str(ROOT / "target/macos/verifier/release/hemi-macos-proof"), "verify-seal",
                       previous["command"][2], str(source / "input.bin"), previous["command"][4], str(directory), "18"]
            with (directory / "verifier.log").open("w") as log:
                subprocess.run(command, env=env, stdout=log, stderr=subprocess.STDOUT, timeout=30, check=True)
            report["cases"].append({"workload": name, "status": "independently_verified",
                                     "witness_sha256": witness_hash, "reference": str(reference),
                                     "wrap_seconds": wrap_seconds, "seal_sha256": sha(directory / "seal.bin"),
                                     "verification": json.loads((directory / "verification.json").read_text())})
        # Missing and corrupted bundles must fail before a child is admitted.
        for kind in ("missing", "corrupt"):
            bundle = run / kind
            bundle.mkdir()
            if kind == "corrupt":
                (bundle / "manifest.json").write_text((BASE / "assets/manifest.json").read_text())
                (bundle / "prover").write_bytes(b"corrupt")
            result = subprocess.run([str(binary), "preflight"], env=dict(env, RISC0_GROTH16_NATIVE_DIR=str(bundle)),
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
            if result.returncode == 0: raise RuntimeError(f"{kind} bundle admitted")
        # Cancel the real witness path before it can launch a prover child.
        witness_work = run / "witness-cancel"
        witness_work.mkdir()
        source = ROOT / "target/macos/runs/08b5cca54b024b9ca9d3400f41b23b1b/wrap/seal.r0"
        process = subprocess.Popen([str(binary), "wrap", str(source), str(run / "cancelled-seal.bin")],
                                   env=dict(env, RISC0_WORK_DIR=str(witness_work)),
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
        deadline = time.monotonic() + 30
        try:
            while time.monotonic() < deadline and process.poll() is None:
                witnesses = list(witness_work.glob("*/witness.wtns"))
                if witnesses and witnesses[0].stat().st_size < 180349836:
                    break
                time.sleep(0.01)
            else:
                raise RuntimeError("did not observe active native witness generation")
        finally:
            if process.poll() is None: os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)
        if (run / "cancelled-seal.bin").exists():
            raise RuntimeError("cancelled witness unexpectedly produced a proof")
        shutil.rmtree(witness_work)
        # Real Go child blocked on a FIFO lets guards be observed without a fake prover.
        fifo = run / "blocked.wtns"
        os.mkfifo(fifo)
        helper = BASE / "assets/prover"
        args = [str(helper), str(BASE / "assets/stark_verify.cs"), str(BASE / "assets/stark_verify_final.pk.dmp"),
                str(fifo), str(run / "unused-proof.json")]
        child = subprocess.Popen([str(helper), "--native-timeout=100ms", *args[1:]],
                                 env={"GOMAXPROCS": "6"}, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if child.wait(timeout=10) != 124: raise RuntimeError("native helper deadline guard failed")
        controller = run / "parent.py"
        controller.write_text("import os,subprocess,sys,time\n"
                              "p=subprocess.Popen([sys.argv[1],'--native-parent='+str(os.getpid()),*sys.argv[2:]],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)\n"
                              "print(p.pid,flush=True)\ntime.sleep(60)\n")
        parent = subprocess.Popen([sys.executable, str(controller), *args], stdout=subprocess.PIPE, text=True)
        pid = int(parent.stdout.readline())
        time.sleep(0.3)
        os.kill(parent.pid, signal.SIGKILL)
        parent.wait(timeout=5)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            state = subprocess.run(["ps", "-o", "stat=", "-p", str(pid)], capture_output=True, text=True)
            if state.returncode != 0 or state.stdout.strip().startswith("Z"): break
            time.sleep(0.05)
        else:
            os.kill(pid, signal.SIGKILL)
            raise RuntimeError("native helper survived parent death")
        report.update(status="passed", guards=["missing_bundle", "corrupt_bundle", "witness_cancel", "helper_deadline", "parent_death"])
    except BaseException as error:
        report.update(status="failed", error=str(error))
        raise
    finally:
        report["elapsed_seconds"] = time.monotonic() - started
        (run / "result.json").write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
