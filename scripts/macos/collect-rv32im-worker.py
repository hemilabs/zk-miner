#!/usr/bin/env python3
"""Bind completed resident-Metal worker proofs, negative checks and resource observations."""
import argparse
import csv
import json
from pathlib import Path
import statistics
from proof_provenance import ROOT, sha
from worker_provenance import verify_build


def read(path):return json.loads(path.read_text())


def proof(run, row, result, shader):
    directory=run/'acceptance'/row['case'];worker=read(directory/'worker.json')
    assert worker==row['worker'] and worker['phase']=='complete' and worker['error'] is None
    assert worker['proof_kind']=='groth16' and worker['helper_arch']=='darwin/arm64'
    assert worker['segment_hal']==result['segment_hal'] and worker['recursion_hal']=='metal'
    assert worker['rayon_threads']==worker['gomaxprocs']==18
    stats=worker['stats'];assert stats['total_cycles']==sum(stats[k] for k in ['user_cycles','paging_cycles','reserved_cycles'])
    assert stats['user_cycles']>=result['min_guest_cycles']
    stages=worker['observed_stages'];recursion=stages['recursion_metal']
    assert recursion['completed_constraint_checks']>=2*stats['segments']-1 and recursion['evaluation_points']>0
    assert stages['identity']=='cpu' and stages['groth16']=='native_darwin_arm64_helper'
    if worker['segment_hal']=='metal':
        rv=stages['rv32im_metal'];assert worker['observed_mode']=='metal'
        assert rv['completed_constraint_checks']==rv['cpu_witness_calls']==rv['cpu_accumulation_calls']==stats['segments']
        assert rv['evaluation_points']>=stats['segments']*(1<<16)
        assert rv['completed_dispatches']>rv['completed_constraint_checks']
        assert rv['threads_per_threadgroup']==32 and rv['normalization']=='period_four_table'
        assert rv['kernel_source_sha256']==shader
        assert rv['cpu_differential_checks']==(stats['segments'] if result['segment_check_cpu'] else 0)
    else:
        assert worker['observed_mode']=='cpu' and stages['segment']=='cpu' and 'rv32im_metal' not in stages
    verification=read(directory/'verification.json')
    assert verification['verification']=='passed'
    assert set(verification['negative_tests'])=={'wrong_image','modified_journal','corrupt_seal'}
    assert verification['journal_hex']==worker['journal_hex']
    assert verification['image_id']==worker['image_id'] and verification['elf_sha256']==worker['elf_sha256']
    assert sha(directory/'seal.bin')==worker['seal_sha256'] and sha(directory/'journal.bin')==worker['journal_sha256']
    resources=read(directory/'resource.json')
    samples=[s['native_memory'] for s in resources['observations'] if s.get('native_memory',{}).get('group')]
    assert samples
    memory={
        'sampled_group_peak_bytes':max(s['group']['worker']['footprint_bytes']+s['group']['helper_footprint_bytes'] for s in samples),
        'guard_lifetime_group_peak_bytes':max(s['guard_peak_footprint_bytes'] or 0 for s in samples),
        'worker_kernel_lifetime_peak_bytes':max(s['group']['worker']['lifetime_peak_footprint_bytes'] for s in samples),
        'host_available_minimum_bytes':min(s['estimated_available_bytes'] for s in samples),
        'pressure_levels':sorted(set(s['pressure_level'] for s in samples)),
        'idle_worker_footprint_bytes':resources['idle_after_verification_and_settle']['native_memory']['group']['worker']['footprint_bytes'],
    }
    assert memory['guard_lifetime_group_peak_bytes']<=32*1024**3
    timings=row['timings'];complete=(timings['prove_call_ms']+timings['external_verifier_ms'])/1000
    return {'path':str(directory),'worker':worker,'complete_seconds':complete,'timings':timings,'memory':memory,
        'artifacts':{p.name:sha(p) for p in sorted(directory.iterdir()) if p.is_file()}}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('campaign',type=Path)
    parser.add_argument('--engine',type=Path,required=True)
    parser.add_argument('--limits',type=Path,required=True)
    parser.add_argument('--cpu-regression-log',type=Path,required=True)
    args=parser.parse_args();campaign=read(args.campaign/'result.json')
    assert campaign['status']=='completed'
    assert sha(args.campaign/'driver-source.py')==campaign['script_sha256']
    current=verify_build('native-rv32im-metal',args.engine)
    continuity_path=ROOT/'target/macos/rv32im-worker/lock-continuity.json'
    continuity=None
    if current!=campaign['worker_build']:
        continuity=read(continuity_path)
        assert continuity['validated_worker_build']==campaign['worker_build']
        assert continuity['resealed_worker_build']==current
        for key in ['only_engine_workspace_lock_changed','worker_binary_unchanged','cpu_binary_unchanged',
                    'worker_metadata_and_local_lock_unchanged','all_source_inputs_except_engine_workspace_lock_unchanged']:
            assert continuity[key]
        for key in ['binary_sha256','metadata_sha256','local_lock_sha256','build_environment','host_toolchain']:
            assert campaign['worker_build'][key]==current[key]
    entries=[{'name':'smoke',**campaign['smoke']}]+campaign['cases']
    report={'schema_version':1,'status':'complete','collector_sha256':sha(Path(__file__)),
        'campaign':str(args.campaign),'campaign_plan_sha256':sha(args.campaign/'plan.json'),
        'campaign_result_sha256':sha(args.campaign/'result.json'),
        'worker_build':campaign['worker_build'],'verifier_build':campaign['verifier_build'],
        'cases':[],'scope':campaign['scope'],'all_work_uncommitted':True}
    if continuity is not None:
        report['post_lock_resealed_worker_build']=current
        report['source_continuity']={'path':str(continuity_path),'sha256':sha(continuity_path),
            'reason':continuity['reason'],'code_diff_sha256_before_and_after':continuity['code_diff_sha256_before_and_after'],
            'engine_lock_before_sha256':continuity['engine_lock_before_sha256'],'engine_lock_after_sha256':continuity['engine_lock_after_sha256'],
            'worker_binary_unchanged':True,'cpu_binary_unchanged':True,'worker_metadata_and_local_lock_unchanged':True}
    limits=read(args.limits/'result.json')
    assert limits['status']=='passed' and limits['worker_build']==campaign['worker_build']
    assert limits['verifier_build']==campaign['verifier_build']
    assert limits['results']['status']=='workload_limit_controls_passed' and limits['results']['verified_proofs']==0
    report['limit_controls']={'run':str(args.limits),'result_sha256':sha(args.limits/'result.json'),'summary':limits['results']}
    cpu=verify_build('native',args.engine)
    assert 'test result: ok. 5 passed; 0 failed;' in args.cpu_regression_log.read_text()
    report['cpu_feature_regression']={'build':cpu,'log':str(args.cpu_regression_log),'log_sha256':sha(args.cpu_regression_log),'unit_tests_passed':5}
    base=ROOT/'target/macos/rv32im-worker'
    unit_log=base/'build-final.log'
    assert 'test result: ok. 5 passed; 0 failed;' in unit_log.read_text()
    report['resident_worker_unit_tests']={'passed':5,'log':str(unit_log),'log_sha256':sha(unit_log)}
    for name in ['device.json','final-state.json']:
        path=base/name
        if path.exists():report[name]={'path':str(path),'sha256':sha(path),'contents':read(path)}
    if 'final-state.json' in report:
        assert report['final-state.json']['contents']['vm_state_unchanged']
        assert not report['final-state.json']['contents']['proof_or_evaluator_processes']
    patch=ROOT/'docs/macos/evidence/rv32im-worker-engine.patch'
    if patch.exists():report['engine_patch']={'path':str(patch),'sha256':sha(patch),'scope':'includes tracked changes and all new engine implementation files; reverse-apply check passed'}
    archive=base/'archive/final/manifest.json'
    if archive.exists():
        frozen=read(archive)
        assert frozen['worker_binary_sha256']==current['binary_sha256']
        for name,digest in frozen['files'].items():assert sha(archive.parent/name)==digest
        report['archive']={'manifest':str(archive),'sha256':sha(archive),'files':len(frozen['files'])}
    shader=None
    for entry in entries:
        run=Path(entry['run']);result=read(run/'result.json')
        assert result['status']=='passed' and sha(run/'result.json')==entry['result_sha256']
        assert result['worker_build']==campaign['worker_build'] and result['verifier_build']==campaign['verifier_build']
        rows=[json.loads(line) for line in (run/'acceptance/requests.jsonl').read_text().splitlines()]
        if shader is None:
            first=next(r for r in rows if r['status']=='complete_independently_verified')
            shader=first['worker']['observed_stages']['rv32im_metal']['kernel_source_sha256']
        verified=[proof(run,row,result,shader) for row in rows if row['status']=='complete_independently_verified']
        assert len(verified)==result['results']['verified_proofs']
        assert result['results']['shutdown']
        case={'name':entry['name'],'run':str(run),'result_sha256':sha(run/'result.json'),
            'summary':result['results'],'segment_hal':result['segment_hal'],
            'segment_check_cpu':result['segment_check_cpu'],'proofs':verified,
            'artifact_hashes':{name:sha(run/name) for name in ['acceptance-build.json','test.log','acceptance/complete.json','acceptance/requests.jsonl','acceptance/timing.json']}}
        if entry['name']=='valid-witness-full-domain':
            assert any(p['worker']['observed_stages']['rv32im_metal']['evaluation_points']>=1<<22 for p in verified)
        if entry['name']=='tiny-tail':assert all(p['worker']['po2']==14 for p in verified)
        if entry['name']=='segment-boundary':assert all(p['worker']['stats']['segments']>=5 for p in verified)
        if entry['name'].endswith('-10m'):assert all(p['worker']['stats']['user_cycles']>=10_000_000 for p in verified)
        if entry['name']=='twenty-request-lifecycle':
            assert len(verified)==21 and all(case['summary'][k] for k in ['helper_cancel','worker_timeout','restart','shutdown'])
            for name in ['helper-cancel','helper-timeout']:
                failures=[r for r in rows if r.get('case')==name and r['status']=='expected_failure']
                assert len(failures)==1
            steady=verified[:20]
            assert len({p['worker']['worker_pid'] for p in steady})==1
            assert len({(p['worker']['worker_pid'],p['worker']['request_id']) for p in verified})==21
            case['twenty_request_idle_footprints_bytes']=[p['memory']['idle_worker_footprint_bytes'] for p in steady]
            case['twenty_request_complete_seconds']=[p['complete_seconds'] for p in steady]
            case['lifecycle_failures']=[r for r in rows if r.get('status')=='expected_failure']
        report['cases'].append(case)
    all_proofs=[p for c in report['cases'] for p in c['proofs']]
    report['totals']={'complete_independently_verified_proofs':len(all_proofs),
        'negative_verifier_checks':3*len(all_proofs),
        'metal_segment_proofs':sum(p['worker']['segment_hal']=='metal' for p in all_proofs),
        'valid_witness_cpu_checked_proofs':sum(p['worker']['observed_stages'].get('rv32im_metal',{}).get('cpu_differential_checks',0)>0 for p in all_proofs),
        'maximum_guard_lifetime_group_peak_bytes':max(p['memory']['guard_lifetime_group_peak_bytes'] for p in all_proofs)}
    report['limitations']=['Complete latency observations are not a controlled five-pair comparison or new warm-median baseline.',
        'Arithmetic, hashing and boundaries do not establish marketplace or BigInt/ECDSA workload performance.',
        'Sampled process-group peaks are guarded, not a kernel-enforced hard cap; GPU compiler services are outside the group.',
        'CPU scatter, prefix products and zeroization remain alongside CPU witness, accumulation and identity-p254.',
        'A separate preliminary candidate was stopped for an FFI raw-pointer review; its three verified proofs are excluded from these totals.']
    out=ROOT/'docs/macos/evidence';csv_path=out/'rv32im-worker-proofs.csv'
    with csv_path.open('w') as file:
        writer=csv.DictWriter(file,fieldnames=['case','proof','segment_hal','guest_cycles','segments','complete_seconds','execution_and_segment_seconds','recursion_seconds','identity_and_wrap_seconds','guard_group_peak_gib'])
        writer.writeheader()
        for case in report['cases']:
            for p in case['proofs']:
                w=p['worker'];writer.writerow({'case':case['name'],'proof':Path(p['path']).name,'segment_hal':w['segment_hal'],
                    'guest_cycles':w['stats']['user_cycles'],'segments':w['stats']['segments'],'complete_seconds':p['complete_seconds'],
                    **{k+'_seconds':w['stage_ms'][k]/1000 for k in ['execution_and_segment','recursion','identity_and_wrap']},
                    'guard_group_peak_gib':p['memory']['guard_lifetime_group_peak_bytes']/1024**3})
    report['proof_csv_sha256']=sha(csv_path)
    (out/'rv32im-worker-validation.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({'totals':report['totals'],'cases':[{k:c[k] for k in ['name','summary']} for c in report['cases']]},indent=2))


if __name__=='__main__':main()
