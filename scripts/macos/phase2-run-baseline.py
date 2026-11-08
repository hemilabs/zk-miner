#!/usr/bin/env python3
"""Finish the fixed Phase 2 baseline campaign, serially, and collect evidence."""

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import time

from proof_provenance import ROOT


def run_path(log):
    return Path(log.read_text().splitlines()[0])


def wait_for_existing(log):
    directory = run_path(log)
    result = directory / "result.json"
    deadline = time.monotonic() + 3600
    while not result.exists() and time.monotonic() < deadline:
        time.sleep(5)
    if not result.exists():
        raise TimeoutError(f"first baseline campaign did not finish: {directory}")
    data = json.loads(result.read_text())
    if data["status"] != "passed":
        raise RuntimeError(f"first baseline campaign failed: {directory}: {data.get('error')}")
    return directory


def run_case(name, extra, engine, base, reserve_gib):
    suffix = f"-reserve{reserve_gib}" if reserve_gib is not None else ""
    log = base / f"{name}{suffix}.log"
    command = [sys.executable, str(ROOT / "scripts/macos/test-native-worker.py"),
        "--engine", str(engine), "--worker-kind", "native-rv32im-metal",
        "--segment-hal", "metal", "--recursion-hal", "metal", "--po2", "20",
        "--min-guest-cycles", "10000000" if name == "hash-10m" else "46000000",
        "--proof-only", "--timeout-seconds", "1800", *extra]
    environment = dict(os.environ, CARGO_NET_OFFLINE="true")
    if reserve_gib is not None:
        environment["ZKMINER_MACOS_HOST_RESERVE_GIB"] = str(reserve_gib)
    (base / f"{name}{suffix}.command.json").write_text(json.dumps({
        "command": command, "host_reserve_gib": reserve_gib,
    }, indent=2) + "\n")
    with log.open("w") as output:
        subprocess.run(command, cwd=ROOT, env=environment,
                       stdout=output, stderr=subprocess.STDOUT, check=True)
    directory = run_path(log)
    if json.loads((directory / "result.json").read_text())["status"] != "passed":
        raise RuntimeError(f"baseline campaign failed: {name}: {directory}")
    print(f"{name}: {directory}", flush=True)
    return directory


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--engine", type=Path, required=True)
    parser.add_argument("--after-arithmetic-log", type=Path, required=True)
    parser.add_argument("--reserve-gib", type=int, choices=range(8, 65),
                        help="host reserve override for hashing and stretch; arithmetic remains as recorded")
    args = parser.parse_args()
    base = ROOT / "target/macos/phase2/baseline"
    arithmetic = wait_for_existing(args.after_arithmetic_log)
    print(f"arithmetic-10m: {arithmetic}", flush=True)
    hashing = run_case("hash-10m", ["--workload", "sha256-chain", "--iterations", "2262",
                                  "--repeat", "5", "--warmup"], args.engine, base, args.reserve_gib)
    stretch = run_case("arithmetic-46m", ["--workload", "fibonacci", "--iterations", "4600000",
                                          "--repeat", "1"], args.engine, base, args.reserve_gib)
    with (base / "collect.log").open("w") as output:
        subprocess.run([sys.executable, str(ROOT / "scripts/macos/phase2-baseline.py"),
            "--arithmetic", str(arithmetic), "--hash", str(hashing), "--stretch", str(stretch)],
            cwd=ROOT, stdout=output, stderr=subprocess.STDOUT, check=True)
    print((base / "collect.log").read_text(), flush=True)


if __name__ == "__main__":
    main()
