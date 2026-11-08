#!/usr/bin/env python3
"""Diagnostic-only RV32IM breakdown on the verified native recursion Metal worker."""
import argparse
from datetime import datetime, timezone
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import uuid
from proof_provenance import ROOT, sha, verify_build
from worker_provenance import verify_build as verify_worker


GPU_FIELDS = {"kernel", "segment", "count", "gpu_ms", "dispatch_wall_ms", "pipeline_ms",
              "thread_execution_width", "max_total_threads_per_threadgroup", "static_threadgroup_memory_length"}


def gpu_stage(row):
    if row["segment"] < 0:
        return "recursion"
    kernel = row["kernel"]
    if kernel in {"eval_check", "ef_prep", "ef_eval_split", "ef_combine"}:
        return "constraint_evaluation"
    if kernel.startswith("multi_ntt") or kernel in {"multi_bit_reverse", "zk_shift", "batch_expand", "batch_transforms"}:
        return "polynomial_transforms"
    if kernel in {"poseidon2_rows", "poseidon2_fold", "sha_rows", "sha_fold", "batch_merkle"}:
        return "merkle_commitments"
    return "other_segment_gpu"


def gpu_profile(log):
    rows = []
    for line in log.read_text().splitlines():
        if "[metal_gpu] " not in line:
            continue
        payload = line.split("[metal_gpu] ", 1)[1]
        row = dict(token.split("=", 1) for token in payload.split())
        assert set(row) == GPU_FIELDS, row
        row["segment"] = int(row["segment"])
        row["count"] = int(row["count"])
        for key in ("gpu_ms", "dispatch_wall_ms", "pipeline_ms"):
            row[key] = float(row[key])
        for key in ("thread_execution_width", "max_total_threads_per_threadgroup", "static_threadgroup_memory_length"):
            row[key] = int(row[key])
        assert row["gpu_ms"] > 0 and row["dispatch_wall_ms"] > 0, row
        row["stage"] = gpu_stage(row)
        rows.append(row)
    if not rows:
        raise RuntimeError("Metal GPU command timing records are missing")
    by_stage = {}
    by_kernel = {}
    for row in rows:
        for key, target in ((row["stage"], by_stage), (row["stage"] + "/" + row["kernel"], by_kernel)):
            summary = target.setdefault(key, {"commands": 0, "gpu_seconds": 0.0,
                                              "dispatch_wall_seconds": 0.0, "pipeline_seconds": 0.0})
            summary["commands"] += 1
            for field, source in (("gpu_seconds", "gpu_ms"), ("dispatch_wall_seconds", "dispatch_wall_ms"),
                                  ("pipeline_seconds", "pipeline_ms")):
                summary[field] += row[source] / 1000
    return {"commands": rows, "by_stage": by_stage, "by_kernel": by_kernel,
            "gpu_seconds": sum(row["gpu_ms"] for row in rows) / 1000,
            "dispatch_wall_seconds": sum(row["dispatch_wall_ms"] for row in rows) / 1000,
            "overlap_seconds": 0.0,
            "overlap_scope": "Synchronous Metal stages; each command buffer completes before CPU buffer access"}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--engine',type=Path,required=True)
    parser.add_argument('--worker-kind',choices=['native-recursion-metal','native-rv32im-metal'],default='native-recursion-metal')
    args=parser.parse_args()
    worker=verify_worker(args.worker_kind,args.engine)
    verifier=verify_build('verifier')
    directory=ROOT/'target/macos/step6-assessment/profile-runs'/uuid.uuid4().hex
    directory.mkdir(parents=True)
    common=[sys.executable,str(ROOT/'scripts/macos/test-native-worker.py'),'--engine',str(args.engine),
        '--worker-kind',args.worker_kind,'--segment-hal','metal' if args.worker_kind=='native-rv32im-metal' else 'cpu','--recursion-hal','metal','--po2','20',
        '--repeat','1','--proof-only','--min-guest-cycles','10000000','--timeout-seconds','1800']
    cases=[('arithmetic-10m',['--workload','fibonacci','--iterations','1000000']),
           ('hash-10m',['--workload','sha256-chain','--iterations','2262'])]
    report={'status':'running','scope':'RISC0_VERBOSE=1 diagnostic timings; not a controlled speedup comparison or warm median',
        'started':datetime.now(timezone.utc).isoformat(),'worker_build':worker,'verifier_build':verifier,
        'script_sha256':sha(Path(__file__)),'runner_sha256':sha(ROOT/'scripts/macos/test-native-worker.py'),
        'cases':[dict(name=name,command=common+options,status='pending') for name,options in cases]}
    (directory/'plan.json').write_text(json.dumps(report,indent=2)+'\n')
    (directory/'driver-source.py').write_bytes(Path(__file__).read_bytes())
    print(directory,flush=True)
    try:
        for case in report['cases']:
            case.update(status='running',started=datetime.now(timezone.utc).isoformat())
            (directory/'result.json').write_text(json.dumps(report,indent=2)+'\n')
            with (directory/(case['name']+'.log')).open('w') as out:
                subprocess.run(case['command'],cwd=ROOT,env=dict(os.environ,RISC0_VERBOSE='1',RISC0_METAL_GPU_PROFILE='1'),
                    stdout=out,stderr=subprocess.STDOUT,check=True)
            run=Path((directory/(case['name']+'.log')).read_text().splitlines()[0])
            result=json.loads((run/'result.json').read_text());assert result['status']=='passed'
            assert result['worker_build']==worker and result['verifier_build']==verifier
            assert result['results']['verified_proofs']==1
            spec=importlib.util.spec_from_file_location('assessment',ROOT/'scripts/macos/assess-rv32im-metal.py')
            module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
            wall=module.profile(run)
            gpu=gpu_profile(run/'test.log')
            case.update(status='passed',run=str(run),result_sha256=sha(run/'result.json'),
                        wall_seconds=wall['exclusive_segment_seconds'],
                        recursion_wall_seconds=wall['worker']['stage_ms']['recursion']/1000,
                        gpu_profile=gpu,
                        stage_residual_seconds={stage:seconds-gpu['by_stage'].get(stage,{}).get('gpu_seconds',0)
                                                for stage,seconds in wall['exclusive_segment_seconds'].items()})
            print(case['name'],'passed',flush=True)
        assert verify_worker(args.worker_kind,args.engine)==worker
        assert verify_build('verifier')==verifier
        report['status']='completed'
    except BaseException as error:
        report.update(status='failed',error=str(error))
        for case in report['cases']:
            if case['status']=='running':case['status']='failed'
        raise
    finally:
        report['finished']=datetime.now(timezone.utc).isoformat()
        (directory/'result.json').write_text(json.dumps(report,indent=2)+'\n')


if __name__=='__main__':main()
