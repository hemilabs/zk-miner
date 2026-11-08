#!/usr/bin/env python3
"""Kill the native helper's parent during key load and during a real wrap."""

import json
import os
from pathlib import Path
import select
import signal
import subprocess
import sys
import time
import uuid

from proof_provenance import ROOT, sha


BASE = ROOT / "target/macos/native-wrap/assets"
WITNESS = ROOT / "target/macos/wrap-runs/14b53d756f8347a9abd00af61a6b4c1d/witness.wtns"
OUT = ROOT / "target/macos/phase2/wp8lite-parent-death"


def line(pipe, timeout):
    ready, _, _ = select.select([pipe], [], [], timeout)
    if not ready:
        raise TimeoutError("controller did not report the helper stage")
    value = pipe.readline().strip()
    if not value:
        raise RuntimeError("controller exited before reporting the helper stage")
    return value


def gone(pid):
    result = subprocess.run(["ps", "-o", "stat=", "-p", str(pid)], capture_output=True, text=True)
    return result.returncode != 0 or result.stdout.strip().startswith("Z")


def case(directory, stage):
    controller = directory / "controller.py"
    controller.write_text(
        "import os,subprocess,sys,time\n"
        "stage,helper,cs,pk,witness,output=sys.argv[1:]\n"
        "source=open(witness,'rb',buffering=0) if stage=='prove' else subprocess.PIPE\n"
        "child=subprocess.Popen([helper,'--native-parent='+str(os.getpid()),"
        "'--native-timeout=120s','--native-no-gc-setup',cs,pk,'-',output],stdin=source,"
        "stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)\n"
        "print(child.pid,flush=True)\n"
        "if stage=='prove':\n"
        "  size=os.fstat(source.fileno()).st_size\n"
        "  while os.lseek(source.fileno(),0,os.SEEK_CUR)<size: time.sleep(0.02)\n"
        "  print('witness-read',flush=True)\n"
        "time.sleep(60)\n"
    )
    output = directory / f"{stage}-proof.json"
    parent = subprocess.Popen(
        [sys.executable, str(controller), stage, str(BASE / "prover"),
         str(BASE / "stark_verify.cs"), str(BASE / "stark_verify_final.pk.dmp"),
         str(WITNESS), str(output)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    pid = None
    try:
        pid = int(line(parent.stdout, 10))
        if stage == "prove":
            assert line(parent.stdout, 30) == "witness-read"
            time.sleep(1.5)
            assert not output.exists(), "proof finished before cancellation"
        else:
            time.sleep(0.5)
        assert not gone(pid), "helper exited before cancellation"
        os.kill(parent.pid, signal.SIGKILL)
        parent.wait(timeout=5)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and not gone(pid):
            time.sleep(0.05)
        assert gone(pid), f"helper {pid} survived parent death during {stage}"
        assert not output.exists(), "cancelled helper wrote a proof"
        return {"stage": stage, "helper_pid": pid, "parent_pid": parent.pid,
                "result": "helper_exited_without_proof"}
    finally:
        if parent.poll() is None:
            parent.kill()
            parent.wait(timeout=5)
        if pid is not None and not gone(pid):
            os.kill(pid, signal.SIGKILL)


def main():
    assert WITNESS.is_file()
    manifest = json.loads((BASE / "manifest.json").read_text())
    assert sha(BASE / "prover") == manifest["files"]["prover"]
    directory = OUT / uuid.uuid4().hex
    directory.mkdir(parents=True)
    report = {"schema_version": 1, "status": "running", "helper_manifest_sha256": sha(BASE / "manifest.json"),
              "witness_sha256": sha(WITNESS), "cases": []}
    try:
        for stage in ("identity", "prove"):
            report["cases"].append(case(directory, stage))
        report["status"] = "passed"
    except BaseException as error:
        report.update(status="failed", error=str(error))
        raise
    finally:
        (directory / "result.json").write_text(json.dumps(report, indent=2) + "\n")
        print(directory)


if __name__ == "__main__":
    main()
