#!/usr/bin/env python3
"""Serial exact-tip correctness, warm speed/usefulness gates, stretch and Metal profiles."""
import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import statistics
import subprocess
import sys
import uuid
from proof_provenance import ROOT, sha, verify_build as verifier_build
from worker_provenance import verify_build


def read(path):
    return json.loads(path.read_text())


def baseline_bridge(directory, engine):
    archive=ROOT/'target/macos/recursion-metal-final-build'
    manifest=read(archive/'worker-native-recursion-metal-build.json')
    binary=archive/'zkminer-prove-risc0'
    assert sha(binary)==manifest['binary_sha256']=='d157305ba0e0830671c6b8f6238dc68e59ae8a68dc3454865c2084c21bc347b9'
    miner='55b6d877124926847cb27c5885e4b222603b5e94'
    parent='28d0e7b936877ac5e60ea1ff4c2eac35b2b38ad7'
    step5='1f6eb352d366edc0cfad6f17a76ce41387d48f36'
    matched={}
    for name,digest in manifest['source']['inputs'].items():
        if name.startswith(('crates/','scripts/')) or name in ['Cargo.toml','Cargo.lock']:
            blob=subprocess.check_output(['git','show',miner+':'+name],cwd=ROOT)
            assert hashlib.sha256(blob).hexdigest()==digest,name
            matched[name]=digest
    assert len(matched)==18
    delta=subprocess.check_output(['git','diff',parent,step5,'--binary'],cwd=engine)
    assert hashlib.sha256(delta).hexdigest()==manifest['source']['engine_working_diff_sha256']
    result={'binary':str(binary),'binary_sha256':sha(binary),'manifest_sha256':sha(archive/'worker-native-recursion-metal-build.json'),
        'miner_commit':miner,'engine_commit':step5,'matched_miner_inputs':matched,'engine_patch_sha256':hashlib.sha256(delta).hexdigest()}
    (directory/'baseline-bridge.json').write_text(json.dumps(result,indent=2)+'\n')
    return result


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--engine',type=Path,required=True)
    parser.add_argument('--scope',choices=['correctness','performance','paired','usefulness','profiles','all'],default='all')
    args=parser.parse_args();engine=args.engine.resolve()
    worker=verify_build('native-rv32im-metal',engine);verifier=verifier_build('verifier')
    out=ROOT/'target/macos/review-rv32im'/uuid.uuid4().hex;out.mkdir(parents=True)
    (out/'driver-source.py').write_bytes(Path(__file__).read_bytes())
    baseline=baseline_bridge(out,engine)
    common=[sys.executable,str(ROOT/'scripts/macos/test-native-worker.py'),'--engine',str(engine),
        '--worker-kind','native-rv32im-metal','--segment-hal','metal','--recursion-hal','metal','--proof-only']
    single=['--repeat','1'];large=['--po2','20','--timeout-seconds','1800']
    cases=[]
    if args.scope in ['correctness','all']:
        cases += [
            ('tip-smoke',common+single+['--workload','segment-boundary','--iterations','0','--po2','14','--segment-check-cpu']),
            ('tip-full-domain-differential',common+single+['--iterations','150000','--po2','20','--min-guest-cycles','1000000','--segment-check-cpu']),
            ('tip-hash-10m',common+single+large+['--workload','sha256-chain','--iterations','2262','--min-guest-cycles','10000000']),
            ('stretch-46m',common+single+large+['--iterations','4600000','--min-guest-cycles','46000000']),
        ]
    if args.scope in ['performance','paired','all']:
        cases.append(('five-pair-arithmetic-10m',common+large+['--paired-baseline',baseline['binary'],'--iterations','1000000','--min-guest-cycles','10000000','--samples','5','--repeat','1']))
    if args.scope in ['performance','usefulness','all']:
        cases.append(('warm-hash-10m',common+large+['--workload','sha256-chain','--iterations','2262','--min-guest-cycles','10000000','--repeat','5','--warmup']))
    criterion={'recorded_before_any_proof':True,'metric':'WorkerPool prove_call_ms + unchanged independent verifier elapsed_ms',
        'paired_fixture':'Fibonacci(1000000), >=10M guest cycles, po2 20, 18 Rayon/18 Go',
        'measured_pairs':5,'excluded_first_process_warmups_per_case':1,'order':'A/B then B/A alternating each round',
        'required_median_speedup':2.0,'required_faster_pairs':4,'usefulness_seconds':600,
        'comparison_scope':'Committed step-5 stack versus current parent-refreshed stack; includes upstream changes and is not an isolated Metal-only attribution.',
        'speedup_formula':'median(baseline complete time) / median(candidate complete time)',
        'stretch_fixture':'Fibonacci(4600000), >=46M guest cycles, po2 20; one complete observation',
        'proposed_stretch_seconds':600,'failures_excluded':False,
        'admission_wait_policy':'Only typed before-dispatch host-memory refusals wait for approximately ten minutes at most per request. Waits are recorded separately and excluded from successful prove-call timing. Dispatched proof failures are never retried.'}
    (out/'criterion.json').write_text(json.dumps(criterion,indent=2)+'\n')
    report={'status':'running','started':datetime.now(timezone.utc).isoformat(),'scope':args.scope,
        'worker_build':worker,'verifier_build':verifier,'baseline':baseline,'criterion':criterion,
        'driver_sha256':sha(Path(__file__)),'runner_sha256':sha(ROOT/'scripts/macos/test-native-worker.py'),
        'cases':[dict(name=name,command=cmd,status='pending') for name,cmd in cases]}
    def save(): (out/'result.json').write_text(json.dumps(report,indent=2)+'\n')
    save();print(out,flush=True)
    try:
        for case in report['cases']:
            assert verify_build('native-rv32im-metal',engine)==worker
            assert sha(Path(baseline['binary']))==baseline['binary_sha256']
            case.update(status='running',started=datetime.now(timezone.utc).isoformat());save()
            with (out/(case['name']+'.log')).open('w') as log:
                subprocess.run(case['command'],cwd=ROOT,stdout=log,stderr=subprocess.STDOUT,check=True)
            run=Path((out/(case['name']+'.log')).read_text().splitlines()[0]);result=read(run/'result.json')
            assert result['status']=='passed' and result['worker_build']==worker and result['verifier_build']==verifier
            case.update(status='passed',run=str(run),result_sha256=sha(run/'result.json'))
            if case['name']=='five-pair-arithmetic-10m':
                rows=result['results']['rows'];assert len(rows)==12
                measured=[r for r in rows if not r['warmup']];assert len(measured)==10
                seconds=lambda r:(r['timings']['prove_call_ms']+r['timings']['external_verifier_ms'])/1000
                medians={str(i):statistics.median(seconds(r) for r in measured if r['case']==i) for i in [0,1]}
                faster=sum(seconds(next(r for r in measured if r['round']==round and r['case']==1)) < seconds(next(r for r in measured if r['round']==round and r['case']==0)) for round in range(1,6))
                ratio=medians['0']/medians['1']
                case.update(median_complete_seconds=medians,speedup=ratio,faster_pairs=faster,
                    speed_gate_passed=ratio>=2 and faster>=4,arithmetic_usefulness_passed=medians['1']<=600)
            else:
                ledger=[json.loads(line) for line in (run/'acceptance/requests.jsonl').read_text().splitlines()]
                verified=[r for r in ledger if r.get('status')=='complete_independently_verified' and not r.get('warmup',False)]
                times=[(r['timings']['prove_call_ms']+r['timings']['external_verifier_ms'])/1000 for r in verified]
                case.update(verified_proofs=result['results']['verified_proofs'],complete_seconds=times)
                if case['name']=='warm-hash-10m':
                    assert len(times)==5;case.update(median_complete_seconds=statistics.median(times),usefulness_passed=statistics.median(times)<=600)
                if case['name']=='stretch-46m':
                    assert len(times)==1;case.update(stretch_time_target_passed=times[0]<=600,stats=verified[0]['worker']['stats'])
            print(case['name'],'passed',flush=True);save()
        if args.scope in ['profiles','all']:
            cmd=[sys.executable,str(ROOT/'scripts/macos/profile-rv32im.py'),'--engine',str(engine),'--worker-kind','native-rv32im-metal']
            with (out/'metal-profiles.log').open('w') as log:subprocess.run(cmd,cwd=ROOT,stdout=log,stderr=subprocess.STDOUT,check=True)
            profiles=Path((out/'metal-profiles.log').read_text().splitlines()[0]);pr=read(profiles/'result.json');assert pr['status']=='completed'
            spec=importlib.util.spec_from_file_location('assessment',ROOT/'scripts/macos/assess-rv32im-metal.py')
            module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
            report['metal_profiles']=[module.profile(Path(c['run'])) for c in pr['cases']]
            report['profile_scope']='Synchronous Metal dispatch wall time plus CPU/shared-buffer stages; diagnostic observations, not hardware occupancy counters or warm timing samples.'
        assert verify_build('native-rv32im-metal',engine)==worker and verifier_build('verifier')==verifier
        assert sha(ROOT/'scripts/macos/test-native-worker.py')==report['runner_sha256']
        report['status']='completed'
    except BaseException as error:
        report.update(status='failed',error=str(error))
        for case in report['cases']:
            if case['status']=='running':case['status']='failed'
        raise
    finally:
        report['finished']=datetime.now(timezone.utc).isoformat();save()


if __name__=='__main__':main()
