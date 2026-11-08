#!/usr/bin/env python3
"""Invalid production thread settings must fail startup before admitting work."""
import json
import os
from pathlib import Path
import subprocess
from proof_provenance import ROOT


def main():
    binary = ROOT / "target/macos/worker-native/release/zkminer-prove-risc0"
    cases = []
    for name in ("ZKMINER_RISC0_CPU_THREADS", "RISC0_GROTH16_NATIVE_THREADS"):
        for value in ("0", "19", "-1", "invalid"):
            env = dict(os.environ, ZKMINER_RISC0_CPU_THREADS="6", RISC0_GROTH16_NATIVE_THREADS="6")
            env[name] = value
            result = subprocess.run([str(binary)], env=env, input=b"", capture_output=True, timeout=10)
            if result.returncode != 1 or b"thread count" not in result.stderr:
                raise RuntimeError(f"invalid {name}={value} did not fail thread preflight")
            cases.append({"variable":name,"value":value,"status":"rejected_before_admission"})
    report = {"status":"passed","cases":cases}
    (ROOT / "target/macos/native-wrap/thread-controls.json").write_text(json.dumps(report,indent=2)+"\n")
    print(f"{len(cases)} invalid production thread settings rejected")


if __name__ == "__main__": main()
