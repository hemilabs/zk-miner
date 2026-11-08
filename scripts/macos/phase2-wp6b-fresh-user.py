#!/usr/bin/env python3
"""Run the source-bound WP6b cold-driver proof from a newly logged-in macOS user."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import uuid

SCRIPT = Path(__file__).resolve()
ROOT = SCRIPT.parents[2]
sys.path.insert(0, str(SCRIPT.parent))
from proof_provenance import sha, verify_build  # noqa: E402
from worker_provenance import paths, verify_build as verify_worker  # noqa: E402


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--engine", type=Path, default=ROOT.parent / "risc0")
    parser.add_argument("--acceptance-build", type=Path,
                        help="defaults to the acceptance executable recorded by the final build-time proof")
    parser.add_argument("--dry-run-warm", action="store_true", help="validate this driver in the current user's warm cache; do not label it cold")
    parser.add_argument("--output-root", type=Path, help="parent for run artifacts; defaults to this user's home")
    args = parser.parse_args()
    if os.environ.get("ZKMINER_MACOS_HOST_RESERVE_GIB"):
        raise RuntimeError("unset the host-reserve override for the cold reading")
    engine = args.engine.resolve(strict=True)
    # The reviewed checkout belongs to the original user, so tell Git it is
    # safe for this read-only provenance check without changing global config.
    os.environ.update(GIT_CONFIG_COUNT="1", GIT_CONFIG_KEY_0="safe.directory",
                      GIT_CONFIG_VALUE_0=str(engine))
    worker = verify_worker("native-rv32im-metal", engine)
    verifier = verify_build("verifier")
    acceptance_path = args.acceptance_build or Path(worker["first_proof_warmup"]["run_dir"]) / "acceptance-build.json"
    acceptance_build = json.loads(acceptance_path.read_text())
    test_binary = Path(acceptance_build["binary_path"])
    if sha(test_binary) != acceptance_build["binary_sha256"]:
        raise RuntimeError("acceptance executable differs from the recorded source build")
    spec = importlib.util.spec_from_file_location("worker_acceptance", SCRIPT.with_name("test-worker.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    if module.test_sources() != acceptance_build["source_inputs"]:
        raise RuntimeError("acceptance sources changed after compilation")

    run = (args.output_root or Path.home()) / ("wp6b-cold-reading-" + uuid.uuid4().hex)
    for name in ("sidecars", "work", "bin", "acceptance"):
        (run / name).mkdir(parents=True, exist_ok=True)
    docker = run / "bin/docker"
    docker.write_text("#!/bin/sh\nexit 99\n")
    docker.chmod(0o755)
    input_bytes = (1).to_bytes(4, "little") + (1).to_bytes(4, "little")
    (run / "input.bin").write_bytes(input_bytes)
    guest = ROOT / "target/macos/guest-build/riscv32im-risc0-zkvm-elf/release/segment-boundary.bin"
    assets = ROOT / "target/macos/native-wrap/assets"
    env = dict(os.environ, ZKMINER_RISC0_WRAP="native", ZKMINER_RISC0_NATIVE_DIR=str(assets),
               ZKMINER_RISC0_WORK_ROOT=str(run / "work"),
               ZKMINER_RISC0_EVIDENCE_DIR=str(run / "sidecars"),
               ZKMINER_MACOS_WORKER=str(paths("native-rv32im-metal")["binary"]),
               ZKMINER_MACOS_WORKER_KIND="native", ZKMINER_MACOS_EVIDENCE_DIR=str(run / "acceptance"),
               ZKMINER_MACOS_PROGRAM=str(guest), ZKMINER_MACOS_VERIFIER=str(ROOT / "target/macos/verifier/release/hemi-macos-proof"),
               ZKMINER_MACOS_INPUT=str(run / "input.bin"), ZKMINER_MACOS_WORKLOAD="segment-boundary",
               ZKMINER_MACOS_EXPECTED_JOURNAL_HEX=(0x123456789ABCDEF0 + 1024).to_bytes(8, "little").hex(),
               ZKMINER_MACOS_PO2="14", ZKMINER_MACOS_MIN_SEGMENTS="1", ZKMINER_MACOS_EXPECT_MODE="metal",
               RISC0_SEGMENT_HAL="metal", RISC0_RECURSION_HAL="metal", RAYON_NUM_THREADS="18",
               ZKMINER_RISC0_CPU_THREADS="18", RISC0_GROTH16_NATIVE_THREADS="18",
               PATH=str(run / "bin") + os.pathsep + os.environ["PATH"])
    report = {"status": "running", "method": "warm-cache driver validation only" if args.dry_run_warm else
              "newly logged-in standard macOS user with its own unpopulated Metal driver cache",
              "run_dir": str(run), "user": os.environ["USER"], "worker_build": worker,
              "verifier_build": verifier, "acceptance_build": acceptance_build,
              "script_sha256": sha(SCRIPT), "guest_sha256": sha(guest), "input_sha256": sha(run / "input.bin"),
              "assets_manifest_sha256": sha(assets / "manifest.json")}
    cache_base = Path(os.environ.get("TMPDIR", "/private/tmp")).resolve().parent / "C/com.apple.gpuarchiver"
    report["driver_cache_directory"] = str(cache_base)
    report["driver_cache_entries_before"] = len(list(cache_base.iterdir())) if cache_base.is_dir() else 0
    print(run, flush=True)
    try:
        host = run / "host-before.json"
        subprocess.run([sys.executable, str(SCRIPT.with_name("phase2-host-snapshot.py")),
                        "--output", str(host)], check=True, capture_output=True, text=True)
        report["host_before"] = json.loads(host.read_text())
        processes = subprocess.check_output(["ps", "-axo", "comm="], text=True)
        report["safari_open"] = "/Safari.app/Contents/MacOS/Safari" in processes
        if report["host_before"]["background_process_present"]["brave"] or report["safari_open"]:
            raise RuntimeError("close Brave and Safari before the cold reading")
        if report["host_before"]["thermal"]["thermal_state_name"] != "nominal":
            raise RuntimeError("thermal state is not nominal")
        with (run / "test.log").open("w") as log:
            subprocess.run([str(test_binary), "native_worker_cold_timing", "--exact", "--ignored", "--nocapture"],
                           cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT, check=True, timeout=600)
        if verify_worker("native-rv32im-metal", engine) != worker:
            raise RuntimeError("worker source or binary changed during cold reading")
        report.update(status="passed", spans=json.loads((run / "acceptance/complete.json").read_text()))
        host = run / "host-after.json"
        subprocess.run([sys.executable, str(SCRIPT.with_name("phase2-host-snapshot.py")),
                        "--output", str(host)], check=True, capture_output=True, text=True)
        report["host_after"] = json.loads(host.read_text())
    except BaseException as error:
        report.update(status="failed", error=str(error))
        raise
    finally:
        (run / "result.json").write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
