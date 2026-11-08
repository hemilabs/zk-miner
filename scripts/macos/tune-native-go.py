#!/usr/bin/env python3
"""Counterbalanced Go-concurrency screening using one fixed, verified witness."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import time
import uuid
from proof_provenance import ROOT, sha, verify_build


def main():
    base = ROOT / "target/macos/native-wrap"
    assets = base / "assets"
    manifest = json.loads((assets / "manifest.json").read_text())
    for name, digest in manifest["files"].items():
        if sha(assets / name) != digest: raise RuntimeError(f"artifact changed: {name}")
    verify_build("verifier")
    directory = base / "go-tuning" / uuid.uuid4().hex
    directory.mkdir(parents=True)
    print(directory, flush=True)
    witness = ROOT / "target/macos/wrap-runs/14b53d756f8347a9abd00af61a6b4c1d/witness.wtns"
    source = ROOT / "target/macos/runs/08b5cca54b024b9ca9d3400f41b23b1b"
    expected = json.loads((source / "result.json").read_text())["command"]
    spec = importlib.util.spec_from_file_location("wrap", Path(__file__).with_name("measure-wrap.py"))
    wrap = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(wrap)
    report = {"status":"running", "witness_sha256":sha(witness), "manifest":manifest,
              "method":"one warmup per Go setting; five measured rounds, reversing setting order each round; includes loading and child startup", "rows":[]}
    try:
        for round_index in range(6):
            order = [6,12,18] if round_index % 2 == 0 else [18,12,6]
            for threads in order:
                trial = directory / f"round-{round_index}-go-{threads}"
                trial.mkdir()
                command = [str(assets / "prover"), f"--native-parent={os.getpid()}", "--native-timeout=60s",
                           str(assets / "stark_verify.cs"), str(assets / "stark_verify_final.pk.dmp"),
                           str(witness), str(trial / "proof.json")]
                started = time.monotonic()
                with (trial / "prover.log").open("w") as log:
                    subprocess.run(command, env={"GOMAXPROCS":str(threads)}, stdout=log, stderr=subprocess.STDOUT,
                                   check=True, timeout=70)
                seconds = time.monotonic() - started
                (trial / "seal.bin").write_bytes(wrap.proof_seal(json.loads((trial / "proof.json").read_text())))
                (trial / "journal.bin").write_bytes((source / "proof/journal.bin").read_bytes())
                with (trial / "verifier.log").open("w") as log:
                    subprocess.run([str(ROOT / "target/macos/verifier/release/hemi-macos-proof"), "verify-seal",
                                    expected[2], str(source / "input.bin"), expected[4], str(trial), "18"],
                                   stdout=log, stderr=subprocess.STDOUT, check=True, timeout=30)
                report["rows"].append({"round":round_index,"warmup":round_index==0,"gomaxprocs":threads,
                    "seconds":seconds,"seal_sha256":sha(trial / "seal.bin"),
                    "verification":json.loads((trial / "verification.json").read_text())})
                (directory / "result.json").write_text(json.dumps(report,indent=2)+"\n")
        report["status"] = "passed"
    except BaseException as error:
        report.update(status="failed",error=str(error))
        raise
    finally:
        (directory / "result.json").write_text(json.dumps(report,indent=2)+"\n")


if __name__ == "__main__": main()
