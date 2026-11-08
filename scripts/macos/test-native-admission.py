#!/usr/bin/env python3
"""Warm the real key's filesystem cache, then exercise refusal and recovery."""
import json
import argparse
from pathlib import Path
import subprocess
import sys
import time
from proof_provenance import ROOT


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--engine", type=Path)
    args = parser.parse_args()
    base = ROOT / "target/macos/native-wrap"
    engine = args.engine or Path(json.loads((ROOT / "target/macos/worker-native-build.json").read_text())["source"]["engine_path"])
    key = base / "assets/stark_verify_final.pk.dmp"
    start = time.monotonic()
    count = 0
    with key.open("rb") as file:
        while chunk := file.read(4 * 1024 * 1024): count += len(chunk)
    record = {"cache_warmed_bytes":count,"read_seconds":time.monotonic()-start,
              "physical_pressure_forced":False,"allocation_buffer_bytes":4*1024*1024,
              "kernel_pressure":subprocess.check_output(["sysctl","-n","kern.memorystatus_vm_pressure_level"],text=True).strip()}
    (base / "admission-cache-warm.json").write_text(json.dumps(record,indent=2)+"\n")
    subprocess.run([sys.executable,str(ROOT / "scripts/macos/test-native-worker.py"),
        "--engine",str(engine),"--admission-pressure",
        "--repeat","1","--proof-only","--rayon-threads","18","--go-threads","18"],check=True)


if __name__ == "__main__": main()
