#!/usr/bin/env python3
"""Exercise the native helper through the real supervised WorkerPool."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import uuid
from proof_provenance import ROOT, sha, verify_build
from worker_provenance import verify_build as verify_worker, paths


def suite_budget(args):
    """Bound the whole sequence, including each comparison warm-up and wait."""
    if args.limit_controls:
        requests, admission_waits = 0, 0
    elif args.thread_cases:
        requests = len(args.thread_cases.split(',')) * (args.samples + 1)
        admission_waits = requests
    else:
        requests = args.repeat + int(args.warmup) + int(args.pipeline_cancel) + (4 if not args.proof_only else 0)
        admission_waits = 0
    return requests, requests * args.timeout_seconds + admission_waits * 600 + 600


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--engine", type=Path, required=True)
    parser.add_argument("--worker-kind", choices=["native", "native-recursion-metal", "native-rv32im-metal"], default="native")
    parser.add_argument("--segment-hal", choices=["cpu", "metal"], default="cpu")
    parser.add_argument("--segment-check-cpu", action="store_true", help="compare every Metal constraint output with the CPU oracle on the same valid witness")
    parser.add_argument("--recursion-hal", choices=["cpu", "metal"], default="cpu")
    parser.add_argument("--recursion-check-cpu", action="store_true",
                        help="compare each Metal recursion constraint output with the CPU oracle")
    parser.add_argument("--recursion-cases", help="counterbalanced warm-worker comparison, e.g. cpu,metal")
    parser.add_argument("--workload", choices=["fibonacci", "sha256-chain", "segment-boundary"], default="fibonacci")
    parser.add_argument("--repeat", type=int, default=3)
    parser.add_argument("--proof-only", action="store_true")
    parser.add_argument("--pipeline-cancel", action="store_true",
                        help="cancel a po2-20 Metal proof while the next CPU segment overlaps prior GPU work")
    parser.add_argument("--rayon-threads", type=int, choices=range(1,19), default=18)
    parser.add_argument("--go-threads", type=int, choices=range(1,19), default=18)
    parser.add_argument("--admission-pressure", action="store_true")
    parser.add_argument("--kernel-pressure", action="store_true",
                        help="apply real macOS warning pressure and check refusal before dispatch and recovery")
    parser.add_argument("--held-memory-gib", type=int,
                        help="hold incompressible sibling memory through one proof; requires a 20..30 GiB normal-pressure admission estimate")
    parser.add_argument("--calibration", type=Path, help="load a measured DeviceBenchmark for native host-memory admission")
    parser.add_argument("--limit-controls", action="store_true", help="run input rejection controls without completing a proof")
    parser.add_argument("--handshake-only", action="store_true", help="time three process launch to HelloAck spans without proving")
    parser.add_argument("--invalid-bundle", action="store_true", help="clone and corrupt the native bundle; require proof failure before helper spawn")
    parser.add_argument("--thread-cases", help="comparison settings, e.g. 6:6,12:6,18:6")
    parser.add_argument("--samples", type=int, choices=range(1,6), default=3)
    parser.add_argument("--iterations", type=int, help="guest loop/hash count; boundary uses units of 1024 additions")
    parser.add_argument("--po2", type=int, choices=range(14,22))
    parser.add_argument("--session-limit", type=int, default=67_108_864, help="maximum guest cycles, 1..67108864")
    parser.add_argument("--timeout-seconds", type=int, default=600, help="per-proof watchdog, 30..3600 seconds")
    parser.add_argument("--failure-timeout-seconds", type=int, default=10,
                        help="lifecycle watchdog while a real helper is running, 1..300 seconds")
    parser.add_argument("--min-guest-cycles", type=int, default=1)
    parser.add_argument("--warmup", action="store_true", help="one extra complete proof before the measured repeats")
    parser.add_argument("--paired-baseline", type=Path, help="frozen step-5 worker for a counterbalanced CPU-segment/resident-Metal comparison")
    parser.add_argument("--paired-metal-baseline", type=Path,
                        help="sealed WP0 worker for a counterbalanced Metal/Metal comparison")
    parser.add_argument("--paired-po2-baseline", type=int, choices=range(14,22),
                        help="segment po2 for the sealed paired Metal arm; --po2 selects the candidate arm")
    parser.add_argument("--paired-pipeline-candidate-off", action="store_true",
                        help="keep WP2 enabled in the sealed Metal arm and disable it in the candidate arm")
    parser.add_argument("--paired-start-case", type=int, choices=(0, 1), default=0,
                        help="which paired arm runs first in round zero")
    parser.add_argument("--prebuilt-acceptance-manifest", type=Path,
                        help="source-bound acceptance binary built before the controlled idle interval")
    args = parser.parse_args()
    if args.paired_baseline and args.paired_metal_baseline:
        parser.error("select one paired baseline")
    if args.paired_metal_baseline:
        if args.worker_kind != "native-rv32im-metal" or args.segment_hal != "metal" or args.recursion_hal != "metal":
            parser.error("paired Metal baseline requires resident segment and recursion Metal")
        args.paired_metal_baseline = args.paired_metal_baseline.resolve(strict=True)
        args.thread_cases = "18:18,18:18"
        if args.paired_po2_baseline is not None and args.po2 is None:
            parser.error("paired po2 comparison requires --po2 for the candidate arm")
    elif args.paired_start_case:
        parser.error("--paired-start-case requires --paired-metal-baseline")
    elif args.paired_po2_baseline is not None:
        parser.error("--paired-po2-baseline requires --paired-metal-baseline")
    if args.paired_pipeline_candidate_off and not args.paired_metal_baseline:
        parser.error("--paired-pipeline-candidate-off requires --paired-metal-baseline")
    if args.paired_baseline:
        if args.worker_kind != "native-rv32im-metal" or args.segment_hal != "metal" or args.recursion_hal != "metal":
            parser.error("paired baseline requires the resident worker with segment and recursion Metal")
        args.paired_baseline = args.paired_baseline.resolve(strict=True)
        args.thread_cases = "18:18,18:18"
    if args.segment_hal == "metal" and args.worker_kind != "native-rv32im-metal":
        parser.error("segment Metal requires the native-rv32im-metal worker")
    if args.segment_check_cpu and args.segment_hal != "metal":parser.error("CPU differential requires segment Metal")
    if args.recursion_check_cpu and args.recursion_hal != "metal":
        parser.error("recursion CPU differential requires recursion Metal")
    if args.pipeline_cancel and (not args.proof_only or args.po2 != 20 or
                                 args.segment_hal != "metal" or args.recursion_hal != "metal"):
        parser.error("pipeline cancellation requires proof-only po2-20 Metal segment and recursion")
    if args.kernel_pressure and not args.proof_only:
        parser.error("kernel pressure requires proof-only acceptance")
    if args.held_memory_gib is not None and (not args.proof_only or args.repeat != 1 or
                                              not 1 <= args.held_memory_gib <= 100):
        parser.error("held memory requires proof-only, one repeat, and 1..100 GiB")
    if args.recursion_cases:
        cases = args.recursion_cases.split(',')
        if args.worker_kind != "native-recursion-metal" or sorted(cases) != ["cpu", "metal"]:
            parser.error("recursion comparison requires native-recursion-metal and the two cases cpu,metal")
        args.thread_cases = args.thread_cases or "18:18,18:18"
    if not 1 <= args.repeat <= 20 or (not args.proof_only and args.repeat < 3):
        parser.error("use 1..20 repeats; lifecycle acceptance requires at least three")
    if not 1 <= args.session_limit <= 67_108_864 or not 30 <= args.timeout_seconds <= 3600:
        parser.error("invalid session limit or watchdog")
    if not 1 <= args.failure_timeout_seconds <= 300:
        parser.error("invalid lifecycle failure watchdog")
    if not 1 <= args.min_guest_cycles <= args.session_limit:
        parser.error("minimum guest cycles must fit session limit")
    planned_requests, suite_timeout = suite_budget(args)
    worker_manifest = verify_worker(args.worker_kind, args.engine)
    verifier_manifest = verify_build("verifier")
    spec = importlib.util.spec_from_file_location("worker_acceptance", Path(__file__).with_name("test-worker.py"))
    acceptance = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(acceptance)
    base = ROOT / "target/macos/native-wrap"
    directory = base / "worker-runs" / uuid.uuid4().hex
    directory.mkdir(parents=True)
    for name in ("sidecars", "work", "bin"):
        (directory / name).mkdir()
    docker = directory / "bin/docker"
    docker.write_text("#!/bin/sh\nexit 99\n")
    docker.chmod(0o755)
    data, expected, po2, segments = acceptance.workload(args.workload, args.iterations)
    po2 = (16 if args.workload == "segment-boundary" else 20) if args.po2 is None else args.po2
    (directory / "input.bin").write_bytes(data)
    program = ROOT / "target/macos/guest-build/riscv32im-risc0-zkvm-elf/release" / (args.workload + ".bin")
    env = dict(os.environ, ZKMINER_RISC0_WRAP="native", ZKMINER_RISC0_NATIVE_DIR=str(base / "assets"),
               ZKMINER_RISC0_WORK_ROOT=str(directory / "work"),
               ZKMINER_RISC0_EVIDENCE_DIR=str(directory / "sidecars"),
               ZKMINER_MACOS_WORKER=str(paths(args.worker_kind)["binary"]), ZKMINER_MACOS_WORKER_KIND="native",
               RISC0_RECURSION_HAL=args.recursion_hal,
               RISC0_RECURSION_METAL_CHECK_CPU="1" if args.recursion_check_cpu else "0",
               RISC0_SEGMENT_HAL=args.segment_hal,
               RISC0_RV32IM_METAL_CHECK_CPU="1" if args.segment_check_cpu else "0",
               ZKMINER_MACOS_PROGRAM=str(program), ZKMINER_MACOS_VERIFIER=str(ROOT / "target/macos/verifier/release/hemi-macos-proof"),
               ZKMINER_MACOS_WORKLOAD=args.workload, ZKMINER_MACOS_INPUT=str(directory / "input.bin"),
               ZKMINER_MACOS_EXPECTED_JOURNAL_HEX=expected, ZKMINER_MACOS_PO2=str(po2),
               ZKMINER_MACOS_MIN_SEGMENTS=str(segments), ZKMINER_MACOS_EXPECT_MODE=args.segment_hal,
               ZKMINER_MACOS_EVIDENCE_DIR=str(directory / "acceptance"), ZKMINER_MACOS_REPEAT=str(args.repeat + int(args.warmup)),
               ZKMINER_MACOS_WARMUP_COUNT=str(int(args.warmup)),
               ZKMINER_MACOS_PROOF_TIMEOUT_SECS=str(args.timeout_seconds),
               ZKMINER_MACOS_MIN_GUEST_CYCLES=str(args.min_guest_cycles),
               ZKMINER_RISC0_MAX_GUEST_CYCLES=str(args.session_limit),
               ZKMINER_MACOS_LIFECYCLE="0" if args.proof_only else "1",
               ZKMINER_MACOS_PIPELINE_CANCEL="1" if args.pipeline_cancel else "0",
               ZKMINER_MACOS_FAILURE_TIMEOUT_SECS=str(args.failure_timeout_seconds), RAYON_NUM_THREADS=str(args.rayon_threads),
               ZKMINER_RISC0_CPU_THREADS=str(args.rayon_threads), RISC0_GROTH16_NATIVE_THREADS=str(args.go_threads),
               ZKMINER_MACOS_ADMISSION_PRESSURE="1" if args.admission_pressure else "0",
               ZKMINER_MACOS_KERNEL_PRESSURE="1" if args.kernel_pressure else "0",
               PATH=str(directory / "bin") + os.pathsep + os.environ["PATH"])
    if args.held_memory_gib is not None:
        env["ZKMINER_MACOS_HELD_MEMORY_GIB"] = str(args.held_memory_gib)
    if args.thread_cases:
        env.update(ZKMINER_MACOS_THREAD_CASES=args.thread_cases, ZKMINER_MACOS_THREAD_SAMPLES=str(args.samples))
    if args.paired_baseline:
        env.update(ZKMINER_RISC0_MODE="cpu", ZKMINER_MACOS_SEGMENT_CASES="cpu,metal",
            ZKMINER_MACOS_WORKER_BINARIES=json.dumps([str(args.paired_baseline), str(paths(args.worker_kind)["binary"])]))
    if args.paired_metal_baseline:
        env.update(ZKMINER_MACOS_SEGMENT_CASES="metal,metal",
            ZKMINER_MACOS_WORKER_BINARIES=json.dumps([str(args.paired_metal_baseline), str(paths(args.worker_kind)["binary"])]),
            ZKMINER_MACOS_PAIRED_START_CASE=str(args.paired_start_case))
        if args.paired_po2_baseline is not None:
            env["ZKMINER_MACOS_PO2_CASES"] = f"{args.paired_po2_baseline},{po2}"
        if args.paired_pipeline_candidate_off:
            env["ZKMINER_MACOS_PIPELINE_CASES"] = "1,0"
    if args.recursion_cases:
        env["ZKMINER_MACOS_RECURSION_CASES"] = args.recursion_cases
    if args.calibration:
        args.calibration = args.calibration.resolve(strict=True)
        env["ZKMINER_MACOS_CALIBRATION"] = str(args.calibration)
    report = {"status": "running", "worker_build": worker_manifest, "verifier_build": verifier_manifest,
              "bundle": json.loads((base / "assets/manifest.json").read_text()), "workload": args.workload, "rayon_threads":args.rayon_threads, "gomaxprocs":args.go_threads,
              "iterations":args.iterations,"po2":po2,"session_guest_cycle_limit":args.session_limit,
              "proof_watchdog_seconds":args.timeout_seconds,"warmup_count":int(args.warmup),"measured_repeats":args.repeat,
              "planned_proof_requests":planned_requests,"suite_timeout_seconds":suite_timeout,
              "min_guest_cycles":args.min_guest_cycles,"program_sha256":sha(program),"input_sha256":sha(directory / "input.bin")}
    report.update(worker_kind=args.worker_kind, segment_hal=args.segment_hal,
                  segment_check_cpu=args.segment_check_cpu, recursion_hal=args.recursion_hal,
                  recursion_check_cpu=args.recursion_check_cpu, recursion_cases=args.recursion_cases)
    report["pipeline_cancel"] = args.pipeline_cancel
    if args.prebuilt_acceptance_manifest:
        report["prebuilt_acceptance_manifest"] = str(args.prebuilt_acceptance_manifest.resolve(strict=True))
    if args.paired_baseline:
        report["paired_baseline"] = {"path":str(args.paired_baseline), "sha256":sha(args.paired_baseline)}
    if args.paired_metal_baseline:
        report["paired_metal_baseline"] = {"path":str(args.paired_metal_baseline), "sha256":sha(args.paired_metal_baseline)}
        report["paired_start_case"] = args.paired_start_case
        if args.paired_po2_baseline is not None:
            report["paired_po2_cases"] = [args.paired_po2_baseline, po2]
        if args.paired_pipeline_candidate_off:
            report["paired_pipeline_cases"] = [True, False]
    if args.calibration:
        report["calibration"] = {"path":str(args.calibration), "sha256":sha(args.calibration)}
    print(directory, flush=True)
    try:
        if args.prebuilt_acceptance_manifest:
            build = json.loads(args.prebuilt_acceptance_manifest.read_text())
            binary = Path(build["binary_path"]).resolve(strict=True)
            if build["source_inputs"] != acceptance.test_sources() or sha(binary) != build["binary_sha256"]:
                raise RuntimeError("prebuilt acceptance binary or source inputs changed")
            (directory / "acceptance-build.json").write_text(json.dumps(build, indent=2) + "\n")
        else:
            binary, build = acceptance.build_acceptance(directory, env)
        with (directory / "test.log").open("w") as log:
            test = "native_bundle_corrupt_hash_rejected" if args.invalid_bundle else "native_worker_handshake_timing" if args.handshake_only else "native_workload_limit_controls" if args.limit_controls else "native_thread_comparison" if args.thread_cases else "native_worker_proofs_failure_restart_and_shutdown"
            subprocess.run([str(binary), test, "--exact", "--ignored", "--nocapture"],
                           env=env, stdout=log, stderr=subprocess.STDOUT, check=True,
                           timeout=suite_timeout)
        if verify_worker(args.worker_kind, args.engine) != worker_manifest:
            raise RuntimeError("native worker build changed during acceptance")
        if args.paired_baseline and sha(args.paired_baseline) != report["paired_baseline"]["sha256"]:
            raise RuntimeError("baseline worker changed during acceptance")
        if args.paired_metal_baseline and sha(args.paired_metal_baseline) != report["paired_metal_baseline"]["sha256"]:
            raise RuntimeError("Metal baseline worker changed during acceptance")
        if sha(binary) != build["binary_sha256"] or acceptance.test_sources() != build["source_inputs"]:
            raise RuntimeError("WorkerPool acceptance sources changed during the run")
        if args.calibration and sha(args.calibration) != report["calibration"]["sha256"]:
            raise RuntimeError("admission calibration changed during acceptance")
        report.update(status="passed", results=json.loads((directory / "acceptance/complete.json").read_text()))
    except BaseException as error:
        report.update(status="failed", error=str(error))
        raise
    finally:
        (directory / "result.json").write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
