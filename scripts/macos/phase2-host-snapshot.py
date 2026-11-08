#!/usr/bin/env python3
"""Record coarse desktop load and thermal state for a local Metal campaign."""

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import subprocess

from proof_provenance import ROOT


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    processes = subprocess.check_output(["ps", "-axo", "comm="], text=True)
    vm = subprocess.check_output(["vm_stat"], text=True)
    counters = {key: int(value.replace(".", "")) for key, value in
                re.findall(r"^([^:\n]+):\s+([0-9.]+)", vm, re.M)}
    page_size = int(re.search(r"page size of (\d+) bytes", vm).group(1))
    available = (counters["Pages free"] + min(counters["File-backed pages"],
                                                  counters["Pages inactive"]) / 2) * page_size
    thermal = json.loads(subprocess.check_output(
        [str(ROOT / "target/macos/benchmark-tools/thermal")], text=True))
    pressure = subprocess.check_output(["memory_pressure", "-Q"], text=True)
    free_percent = int(re.search(r"System-wide memory free percentage: (\d+)%", pressure).group(1))
    report = {
        "observed_utc": datetime.now(timezone.utc).isoformat(),
        "estimated_available_bytes": int(available),
        "estimated_available_method": "free pages plus half of the lesser of file-backed and inactive pages",
        "kernel_memory_free_percent": free_percent,
        "kernel_memory_free_percent_method": "memory_pressure -Q; a pressure metric, not free physical pages",
        "thermal": thermal,
        "background_process_present": {
            "brave": "Brave Browser" in processes,
            "chatgpt_codex": "/Applications/ChatGPT.app/" in processes,
            "claude": "/Applications/Claude.app/" in processes or "/claude-code/" in processes,
            "colima": ".colima/" in processes,
            "vscode": "/Visual Studio Code.app/" in processes,
            "xcode": "/Xcode.app/" in processes,
            "zed": "/Zed.app/" in processes,
        },
        "scope": "instantaneous host observation; process changes are recorded by the campaign driver",
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(args.output)


if __name__ == "__main__":
    main()
