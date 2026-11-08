#!/usr/bin/env python3
"""Compact completed Poseidon2 recursion Metal acceptance without excluding trials."""
import argparse
import csv
from datetime import datetime
import json
from pathlib import Path
import statistics
from proof_provenance import ROOT, sha


def read(path):
    return json.loads(path.read_text())


def distribution(values):
    return dict(n=len(values), median=statistics.median(values), minimum=min(values), maximum=max(values))


def proof(run, directory, record, expected_hal, shader):
    worker = read(directory / 'worker.json')
    verified = read(directory / 'verification.json')
    assert worker == record['worker'] and worker['phase'] == 'complete'
    assert worker['error'] is None and worker['proof_kind'] == 'groth16'
    assert worker['recursion_hal'] == expected_hal and worker['observed_mode'] == 'cpu'
    assert worker['observed_stages']['identity'] == 'cpu'
    assert worker['helper_arch'] == 'darwin/arm64'
    assert worker['rayon_threads'] == worker['gomaxprocs'] == 18
    stats = worker['stats']
    assert stats['total_cycles'] == sum(stats[k] for k in ['user_cycles','paging_cycles','reserved_cycles'])
    if expected_hal == 'metal':
        stage = worker['observed_stages']['recursion_metal']
        assert stage['completed_constraint_checks'] >= 2*stats['segments']-1
        assert stage['evaluation_points'] > 0 and stage['kernel_source_sha256'] == shader
    else:
        assert not worker['observed_stages'].get('recursion_metal')
    assert verified['verification'] == 'passed'
    assert set(verified['negative_tests']) == {'wrong_image','modified_journal','corrupt_seal'}
    assert verified['elf_sha256'] == worker['elf_sha256'] and verified['image_id'] == worker['image_id']
    assert verified['journal_hex'] == worker['journal_hex']
    assert sha(directory / 'seal.bin') == worker['seal_sha256']
    assert sha(directory / 'journal.bin') == worker['journal_sha256']
    resources = read(directory / 'resource.json')
    samples = [s['native_memory'] for s in resources['observations'] if s.get('native_memory',{}).get('group')]
    assert samples
    memory = {
        'worker_peak_bytes':max(s['group']['worker']['footprint_bytes'] for s in samples),
        'helper_peak_bytes':max(s['group']['helper_footprint_bytes'] for s in samples),
        'group_peak_bytes':max(s['group']['worker']['footprint_bytes']+s['group']['helper_footprint_bytes'] for s in samples),
        'guard_lifetime_peak_bytes':max(s['guard_peak_footprint_bytes'] or 0 for s in samples),
        'host_available_minimum_bytes':min(s['estimated_available_bytes'] for s in samples),
        'pressure_levels':sorted(set(s['pressure_level'] for s in samples)),
        'idle_worker_footprint_bytes':resources['idle_after_verification_and_settle']['native_memory']['group']['worker']['footprint_bytes'],
    }
    return dict(path=str(directory),worker=worker,timings=record['timings'],memory=memory,
                artifacts={p.name:sha(p) for p in sorted(directory.iterdir()) if p.is_file()})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('campaign',type=Path)
    parser.add_argument('--buffers',type=Path,required=True,help='completed isolated shared-buffer controls run')
    parser.add_argument('--admission',type=Path,required=True,help='final 20-GiB Metal admission refusal/recovery run')
    args = parser.parse_args()
    campaign = read(args.campaign / 'result.json')
    assert campaign['status'] == 'completed' and campaign['worker_kind'] == 'native-recursion-metal'
    assert campaign['recursion_hal'] == 'metal'
    assert sha(args.campaign / 'driver-source.py') == campaign['script_sha256']
    criterion = read(args.campaign / 'performance-criterion.json')
    paired_case = next(c for c in campaign['cases'] if c['name']=='recursion-cpu-metal-pairs')
    assert datetime.fromisoformat(criterion['recorded_at_utc']) < datetime.fromisoformat(paired_case['started'])
    report = dict(schema_version=1,status='completed',campaign=str(args.campaign.resolve()),
        campaign_sha256=sha(args.campaign / 'result.json'),plan_sha256=sha(args.campaign / 'plan.json'),
        collector_sha256=sha(Path(__file__)),driver_sha256=campaign['script_sha256'],
        thermal_log_sha256=sha(args.campaign/'thermal.jsonl'),
        worker_runner_sha256=sha(args.campaign/'worker-runner-source.py'),
        criterion=criterion,criterion_sha256=sha(args.campaign / 'performance-criterion.json'),
        worker_binary_sha256=campaign['worker_build']['binary_sha256'],
        verifier_binary_sha256=campaign['verifier_build']['binary_sha256'],cases=[],verified_proofs=0,negative_rejections=0)
    shader = None
    measured = []
    for case in campaign['cases']:
        assert case['status'] == 'passed'
        run=Path(case['run']);result=read(run / 'result.json')
        assert result['status']=='passed' and sha(run / 'result.json')==case['result_sha256']
        for key in ['worker_build','verifier_build']:
            assert result[key]['binary_sha256']==campaign[key]['binary_sha256']
        row=dict(case,proofs=[],run_hashes={name:sha(run/name) for name in ['result.json','acceptance-build.json','test.log','acceptance/complete.json']})
        paired = case['name']=='recursion-cpu-metal-pairs'
        if paired:
            records=result['results']['rows'];assert len(records)==12
        else:
            ledger=run/'acceptance/requests.jsonl'
            entries=[json.loads(line) for line in ledger.read_text().splitlines()] if ledger.exists() else []
            assert not any(r.get('status')=='failed' for r in entries)
            records=[r for r in entries if r.get('status')=='complete_independently_verified']
            assert len(records)==result['results']['verified_proofs']
        for record in records:
            hal=record['worker']['recursion_hal']
            if hal=='metal':
                current=record['worker']['observed_stages']['recursion_metal']['kernel_source_sha256']
                shader=shader or current;assert shader==current
            directory=run/'acceptance'/(f"round-{record['round']}-case-{record['case']}" if paired else record['case'])
            verified=proof(run,directory,record,hal if paired else 'metal',shader)
            row['proofs'].append(verified)
            report['verified_proofs']+=1;report['negative_rejections']+=3
            if paired and not record['warmup']:
                w,t=verified['worker'],verified['timings']
                measured.append(dict(round=record['round'],recursion_hal=hal,
                    guest_cycles=w['stats']['user_cycles'],total_cycles=w['stats']['total_cycles'],
                    segments=w['stats']['segments'],po2=w['po2'],worker_body_seconds=w['total_ms']/1000,
                    complete_seconds=(t['prove_call_ms']+t['external_verifier_ms'])/1000,
                    **{k+'_seconds':v/1000 for k,v in w['stage_ms'].items()},**verified['memory']))
        if paired:
            assert len(measured)==10
            assert len({(p['guest_cycles'],p['total_cycles'],p['segments'],p['po2']) for p in measured})==1
            for hal in ['cpu','metal']:
                assert len([p for p in measured if p['recursion_hal']==hal])==5
            rounds=sorted(set(p['round'] for p in measured));assert len(rounds)==5
            speedups=[]
            for n in rounds:
                times={p['recursion_hal']:p['complete_seconds'] for p in measured if p['round']==n}
                speedups.append(times['cpu']/times['metal'])
            report['comparison']={hal:{metric:distribution([p[metric] for p in measured if p['recursion_hal']==hal])
                for metric in ['complete_seconds','worker_body_seconds','execution_and_segment_seconds','recursion_seconds','identity_and_wrap_seconds']} for hal in ['cpu','metal']}
            medians=report['comparison'];ratio=medians['cpu']['complete_seconds']['median']/medians['metal']['complete_seconds']['median']
            report['performance']={'median_complete_speedup':ratio,'paired_speedups':speedups,
                'faster_pairs':sum(s>1 for s in speedups),'gate_passed':ratio>=criterion['required_median_speedup'] and sum(s>1 for s in speedups)>=criterion['required_faster_pairs']}
        if case['name']=='twenty-request-lifecycle':
            complete=result['results']
            assert complete['verified_proofs']==21 and all(complete[k] for k in ['helper_cancel','worker_timeout','restart','shutdown'])
            assert len({p['worker']['worker_pid'] for p in row['proofs'][:20]})==1
            row['twenty_request_idle_footprints_bytes']=[p['memory']['idle_worker_footprint_bytes'] for p in row['proofs'][:20]]
        report['cases'].append(row)
    report['kernel_source_sha256']=shader
    base=ROOT/'target/macos'
    report['validation']={
        'logs':{name:sha(base/name) for name in ['recursion-metal-hal-locked-online-tests.log','recursion-metal-evaluator-final-tests.log','recursion-metal-worker-pools-build.log','recursion-metal-benchmark-unit-tests.log','recursion-metal-cli-check.log','recursion-metal-memory-tests.log','recursion-metal-final-cli-check.log']},
        'linux_recursion':read(base/'linux-recursion-check/result.json'),
        'linux_zkvm':read(base/'linux-recursion-check/zkvm-result.json'),
        'linux_logs':{name:sha(base/'linux-recursion-check'/name) for name in ['source.json','command.json','check.stderr','zkvm-command.json','zkvm-check.stderr']},
        'legacy_accumulation_audit':read(base/'recursion-metal-legacy-audit.json'),
        'engine_patch_sha256':sha(ROOT/'docs/macos/evidence/recursion-metal-engine.patch'),
    }
    buffers=read(args.buffers/'result.json')
    assert buffers['status']=='passed' and buffers['worker_build']['binary_sha256']==report['worker_binary_sha256']
    assert sha(Path(buffers['binary_path']))==buffers['binary_sha256']
    report['validation']['shared_buffers']={'path':str(args.buffers.resolve()),'result':buffers,
        'hashes':{name:sha(args.buffers/name) for name in ['result.json','test.log','build.jsonl','build.stderr']}}
    admission=read(args.admission/'result.json');pressure=read(args.admission/'acceptance/pressure.json')
    assert admission['status']=='passed' and admission['results']['verified_proofs']==1
    assert admission['worker_build']['binary_sha256']==report['worker_binary_sha256']
    assert admission['verifier_build']['binary_sha256']==report['verifier_binary_sha256']
    assert pressure['needed_bytes']==20*1024**3 and pressure['attempted'] is False
    assert pressure['reserved_after_bytes']==0 and pressure['sidecar_count_after']==pressure['sidecar_count_before']
    ledger=[json.loads(line) for line in (args.admission/'acceptance/requests.jsonl').read_text().splitlines()]
    record=next(r for r in ledger if r.get('status')=='complete_independently_verified')
    report['post_campaign_admission']={'path':str(args.admission.resolve()),'refusal':pressure,
        'proof':proof(args.admission,args.admission/'acceptance/proof-0',record,'metal',shader),
        'verified_proofs':1,'negative_rejections':3,
        'scope':'After timing, raised initial Metal admission budget from 16 to 20 GiB based on the observed 17.3-GiB startup group peak. CPU budget stays 16 GiB. Proving worker binary unchanged.',
        'hashes':{name:sha(args.admission/name) for name in ['result.json','test.log','acceptance-build.json','acceptance/complete.json','acceptance/pressure.json']}}
    archive=base/'recursion-metal-final-build'
    assert sha(archive/'zkminer-prove-risc0')==report['worker_binary_sha256']
    assert sha(archive/'recursion.metal')==shader
    report['validation']['build_archive']={'path':str(archive),
        'files':{p.name:sha(p) for p in sorted(archive.iterdir()) if p.is_file()}}
    for case in report['cases']:
        archived=archive/'acceptance'/case['name'];build=read(archived/'acceptance-build.json')
        binary=archived/Path(build['binary_path']).name
        assert sha(binary)==build['binary_sha256']
        assert sha(archived/'acceptance-build.json')==case['run_hashes']['acceptance-build.json']
        case['acceptance_binary_archive']={'path':str(binary),'sha256':sha(binary)}
    preliminary=base/'native-wrap/workload-campaigns/ac530c478a9047daa7a424c43b76de8d'
    report['retained_preliminary']={'path':str(preliminary),'status':read(preliminary/'result.json')['status'],
        'replan':read(preliminary/'replan.json'),'result_sha256':sha(preliminary/'result.json'),
        'source_archive':str(base/'recursion-metal-before-pools'),'verified_artifacts':[]}
    for case in read(preliminary/'result.json')['cases']:
        log=preliminary/(case['name']+'.log')
        if not log.exists() or not log.read_text().splitlines():continue
        run=Path(log.read_text().splitlines()[0])
        for verified in sorted((run/'acceptance').glob('*/verification.json')):
            directory=verified.parent;w=read(directory/'worker.json');v=read(verified)
            assert v['verification']=='passed' and sha(directory/'seal.bin')==w['seal_sha256']
            report['retained_preliminary']['verified_artifacts'].append({'path':str(directory),
                'artifacts':{p.name:sha(p) for p in directory.iterdir() if p.is_file()}})
    pilot=base/'native-wrap/worker-runs/71684d3b53884fc2bc4fb3b3cfe654ee'
    report['retained_pilot']={'path':str(pilot),'status':read(pilot/'result.json')['status'],
        'verified_proofs':3,'negative_rejections':9,'result_sha256':sha(pilot/'result.json'),
        'scope':'pre-pool-correction correctness observations, excluded from final comparison'}
    state=base/'recursion-metal-final-state.json'
    if state.exists():
        report['validation']['final_state']=read(state)
        report['validation']['final_state_sha256']=sha(state)
    report['limitations']=['Five warm measured pairs on Fibonacci(150000) at po2 20; one excluded first-process warmup per mode.',
        '10M arithmetic and hashing are single first-process proofs, not new five-sample usefulness medians.',
        'Witness generation, accumulation, RV32IM segments, identity-p254 and Groth16 use CPU.',
        'Process footprints and thermal state are sampled; no energy or marketplace competitiveness claim.',
        'The step-4 CPU 46M proof was not repeated with Metal.']
    out=ROOT/'docs/macos/evidence'
    with (out/'recursion-metal-comparison.csv').open('w') as file:
        writer=csv.DictWriter(file,fieldnames=list(measured[0]));writer.writeheader();writer.writerows(measured)
    report['comparison_csv_sha256']=sha(out/'recursion-metal-comparison.csv')
    (out/'recursion-metal-validation.json').write_text(json.dumps(report,indent=2)+'\n')
    print(f"Verified {report['verified_proofs']} proofs / {report['negative_rejections']} tamper rejections; performance={report['performance']}")


if __name__=='__main__':main()
