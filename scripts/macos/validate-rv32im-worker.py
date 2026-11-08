#!/usr/bin/env python3
"""Serial complete-proof validation of the opt-in resident RV32IM Metal worker."""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import shutil
import subprocess
import sys
import uuid
from proof_provenance import ROOT, sha, verify_build as verify_verifier
from worker_provenance import verify_build, paths


def read(path):return json.loads(path.read_text())


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--engine',type=Path,required=True)
    parser.add_argument('--smoke',type=Path,required=True,help='completed final-binary integrated smoke run')
    args=parser.parse_args();engine=args.engine.resolve()
    worker=verify_build('native-rv32im-metal',engine);verifier=verify_verifier('verifier')
    smoke=read(args.smoke/'result.json')
    assert smoke['status']=='passed' and smoke['worker_build']==worker and smoke['verifier_build']==verifier
    assert smoke['segment_hal']=='metal' and smoke['segment_check_cpu']
    directory=ROOT/'target/macos/rv32im-worker/campaigns'/uuid.uuid4().hex
    directory.mkdir(parents=True)
    common=[sys.executable,str(ROOT/'scripts/macos/test-native-worker.py'),'--engine',str(engine),
        '--worker-kind','native-rv32im-metal','--segment-hal','metal','--recursion-hal','metal']
    cases=[
        ('tiny-tail',['--workload','segment-boundary','--iterations','0','--po2','14','--segment-check-cpu','--repeat','1','--proof-only']),
        ('valid-witness-full-domain',['--iterations','150000','--po2','20','--min-guest-cycles','1000000','--segment-check-cpu','--repeat','1','--proof-only']),
        ('segment-boundary',['--workload','segment-boundary','--po2','16','--repeat','1','--proof-only']),
        ('cpu-segment-control',['--segment-hal','cpu','--po2','20','--repeat','1','--proof-only']),
        ('arithmetic-10m',['--workload','fibonacci','--iterations','1000000','--min-guest-cycles','10000000','--po2','20','--repeat','1','--proof-only','--timeout-seconds','1800']),
        ('hash-10m',['--workload','sha256-chain','--iterations','2262','--min-guest-cycles','10000000','--po2','20','--repeat','1','--proof-only','--timeout-seconds','1800']),
        ('twenty-request-lifecycle',['--repeat','20','--po2','20']),
    ]
    report={'status':'running','started':datetime.now(timezone.utc).isoformat(),
        'worker_build':worker,'verifier_build':verifier,'script_sha256':sha(Path(__file__)),
        'smoke':{'run':str(args.smoke.resolve()),'result_sha256':sha(args.smoke/'result.json')},
        'scope':'correctness, real-witness differential, lifecycle, memory and single full-job observations; not a controlled performance comparison',
        'cases':[{'name':name,'command':common+options,'status':'pending'} for name,options in cases]}
    (directory/'plan.json').write_text(json.dumps(report,indent=2)+'\n')
    (directory/'driver-source.py').write_bytes(Path(__file__).read_bytes())
    print(directory,flush=True)
    try:
        for case in report['cases']:
            assert verify_build('native-rv32im-metal',engine)==worker and verify_verifier('verifier')==verifier
            case.update(status='running',started=datetime.now(timezone.utc).isoformat())
            (directory/'result.json').write_text(json.dumps(report,indent=2)+'\n')
            with (directory/(case['name']+'.log')).open('w') as log:
                subprocess.run(case['command'],cwd=ROOT,stdout=log,stderr=subprocess.STDOUT,check=True,timeout=15000)
            run=Path((directory/(case['name']+'.log')).read_text().splitlines()[0])
            result=read(run/'result.json')
            assert result['status']=='passed' and result['worker_build']==worker and result['verifier_build']==verifier
            assert result['results']['verified_proofs']>0
            # Keep the actual acceptance executable even if the shared Cargo
            # target later builds another feature configuration.
            acceptance=read(run/'acceptance-build.json');binary=Path(acceptance['binary_path'])
            assert sha(binary)==acceptance['binary_sha256']
            frozen=directory/'acceptance-binaries'/acceptance['binary_sha256']
            if not frozen.exists():frozen.parent.mkdir(exist_ok=True);shutil.copy2(binary,frozen)
            assert sha(frozen)==acceptance['binary_sha256']
            case.update(status='passed',run=str(run),result_sha256=sha(run/'result.json'),
                acceptance_binary=str(frozen),finished=datetime.now(timezone.utc).isoformat())
            print(case['name'],'passed',flush=True)
        assert verify_build('native-rv32im-metal',engine)==worker and verify_verifier('verifier')==verifier
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
