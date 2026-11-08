#!/usr/bin/env python3
"""Validate and compact a completed native workload campaign, retaining all trials."""
import argparse
import csv
from collections import defaultdict
import json
from pathlib import Path
import statistics
from proof_provenance import ROOT, sha


def read(path):
    return json.loads(path.read_text())


def summary(values):
    return dict(n=len(values), median=statistics.median(values), minimum=min(values), maximum=max(values))


def memory(resources):
    samples = [s['native_memory'] for s in resources['observations'] if s.get('native_memory', {}).get('group')]
    return {
        'sampled_worker_footprint_peak_bytes':max(s['group']['worker']['footprint_bytes'] for s in samples),
        'sampled_helper_footprint_peak_bytes':max(s['group']['helper_footprint_bytes'] for s in samples),
        'sampled_group_footprint_peak_bytes':max(s['group']['worker']['footprint_bytes']+s['group']['helper_footprint_bytes'] for s in samples),
        'guard_lifetime_group_peak_bytes':max(s['guard_peak_footprint_bytes'] or 0 for s in samples),
        'estimated_host_available_minimum_bytes':min(s['estimated_available_bytes'] for s in samples),
        'pressure_levels':sorted(set(s['pressure_level'] for s in samples)),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('campaign', type=Path)
    parser.add_argument('--calibrated-admission', type=Path, help='separate final po2-19 refusal/recovery acceptance run')
    parser.add_argument('--acceptance-archive', type=Path, help='retained campaign acceptance binary and build manifest')
    args = parser.parse_args()
    campaign = read(args.campaign / 'result.json')
    if campaign['status'] != 'completed': raise RuntimeError('campaign incomplete; retain its failed/pending slots')
    report = {'schema_version':1, 'status':'campaign_completed', 'campaign':str(args.campaign.resolve()),
              'collector_sha256':sha(Path(__file__)),
              'campaign_sha256':sha(args.campaign / 'result.json'), 'plan_sha256':sha(args.campaign / 'plan.json'),
              'worker_binary_sha256':campaign['worker_build']['binary_sha256'],
              'verifier_binary_sha256':campaign['verifier_build']['binary_sha256'],
              'useful_target_passed':campaign['useful_target_passed'], 'cases':[], 'verified_proofs':0,'negative_rejections':0}
    stages = []
    throughputs = defaultdict(list)
    peak = 0
    for case in campaign['cases']:
        assert case['status'] == 'passed'
        run = Path(case['run']);result = read(run / 'result.json')
        assert result['status'] == 'passed' and sha(run / 'result.json') == case['result_sha256']
        assert result['worker_build']['binary_sha256'] == report['worker_binary_sha256']
        assert result['verifier_build']['binary_sha256'] == report['verifier_binary_sha256']
        row = dict(case)
        row['run_hashes'] = {name:sha(run / name) for name in ['result.json','acceptance-build.json','test.log','acceptance/complete.json']}
        row['proofs'] = []
        ledger = run / 'acceptance/requests.jsonl'
        records = [json.loads(line) for line in ledger.read_text().splitlines()] if ledger.exists() else []
        assert not any(r.get('status') == 'failed' for r in records)
        if ledger.exists(): row['run_hashes']['acceptance/requests.jsonl'] = sha(ledger)
        warm = []
        for record in records:
            if record.get('status') != 'complete_independently_verified': continue
            directory = run / 'acceptance' / record['case']
            worker, verified = read(directory / 'worker.json'), read(directory / 'verification.json')
            assert worker == record['worker']
            assert worker['phase'] == 'complete' and worker['error'] is None
            assert worker['po2'] == result['po2'] and worker['rayon_threads'] == result['rayon_threads']
            assert worker['gomaxprocs'] == result['gomaxprocs'] and worker['observed_mode'] == 'cpu'
            assert verified['verification'] == 'passed'
            assert set(verified['negative_tests']) == {'wrong_image','modified_journal','corrupt_seal'}
            assert sha(directory / 'seal.bin') == worker['seal_sha256']
            assert sha(directory / 'journal.bin') == worker['journal_sha256']
            assert verified['journal_hex'] == worker['journal_hex']
            assert verified['image_id'] == worker['image_id'] and verified['elf_sha256'] == worker['elf_sha256']
            assert worker['stats']['user_cycles'] >= result['min_guest_cycles']
            assert worker['stats']['user_cycles'] <= worker['max_guest_cycles']
            stats = worker['stats'];assert stats['total_cycles'] == stats['user_cycles']+stats['paging_cycles']+stats['reserved_cycles']
            m = memory(record['resources']);peak = max(peak,m['guard_lifetime_group_peak_bytes'])
            proof = {'case':record['case'],'warmup':record.get('warmup',False),'worker':worker,'timings':record['timings'],'memory':m,
                     'artifact_hashes':{p.name:sha(p) for p in sorted(directory.iterdir()) if p.is_file()}}
            row['proofs'].append(proof);report['verified_proofs'] += 1;report['negative_rejections'] += 3
            if record.get('warmup') is False and case['name'] in ['arithmetic-10m','hash-10m']:
                warm.append(proof)
                stage = worker['stage_ms'];stark = (stage['execution_and_segment']+stage['recursion'])/1000
                stages.append({'program_name':result['workload'],'cycles':stats['total_cycles'],'stark_secs':stark,'wrap_secs':stage['identity_and_wrap']/1000})
                throughputs[result['workload']].append(stats['total_cycles']/stark)
        assert len(row['proofs']) == result['results']['verified_proofs']
        if case['name'] in ['arithmetic-10m','hash-10m']:
            assert len(warm) == 5 and len(row['proofs']) == 6
            row['worker_body_seconds'] = summary([p['worker']['total_ms']/1000 for p in warm])
            row['complete_seconds'] = summary([(p['timings']['prove_call_ms']+p['timings']['external_verifier_ms'])/1000 for p in warm])
            row['stages_seconds'] = {k:summary([p['worker']['stage_ms'][k]/1000 for p in warm]) for k in warm[0]['worker']['stage_ms']}
            assert row['complete_seconds']['median'] == case['median_complete_seconds']
        if case['name'] == 'twenty-request-lifecycle':
            complete = read(run / 'acceptance/complete.json')
            assert complete['verified_proofs'] == 21 and all(complete[k] for k in ['helper_cancel','worker_timeout','restart','shutdown'])
        report['cases'].append(row)
    profile = {'device_id':'cpu','device_label':'Mac native CPU','prover_backend':'risc0',
               'throughput':statistics.mean(statistics.median(v) for v in throughputs.values()),
               'power_watts':0.0,'optimal_po2':20,'memory_usage_bytes':0,'max_feasible_po2':20,
               'program_throughputs':{k:statistics.median(v) for k,v in throughputs.items()},
               'po2_samples':[],'program_stages':stages,'pci_bus_id':'','host_peak_bytes':peak}
    rate = sum(s['cycles'] for s in stages)/sum(s['stark_secs'] for s in stages)
    fixed = statistics.median(s['wrap_secs'] for s in stages)
    report['timing_model'] = {'fixed_identity_wrap_seconds':fixed,'padded_cycles_per_stark_second':rate,
                              'scope':'po2 20 native CPU; segment/recursion scaling from ten measured 10M proofs; fixed identity and wrapping retained'}
    frozen_path = args.campaign / 'frozen-prediction.json'
    if frozen_path.exists():
        frozen = read(frozen_path)
        assert frozen['padded_cycles_per_stark_second'] == rate
        assert frozen['fixed_identity_wrap_seconds'] == fixed
        report['frozen_stretch_forecast'] = frozen
        report['frozen_stretch_forecast_sha256'] = sha(frozen_path)
    for case in report['cases']:
        if case['name'] == 'arithmetic-46m':
            p = case['proofs'][0];predicted = fixed+p['worker']['stats']['total_cycles']/rate
            report['stretch_prediction'] = {'predicted_body_seconds':predicted,'observed_body_seconds':p['worker']['total_ms']/1000}
    base = ROOT / 'target/macos/native-wrap'
    report['validation'] = {
        'linux':read(ROOT / 'target/macos/linux-padding/result.json'),
        'linux_result_sha256':sha(ROOT / 'target/macos/linux-padding/result.json'),
        'linux_test_log_sha256':sha(ROOT / 'target/macos/linux-padding/tests.log'),
        'boundary_before_sha256':sha(base / 'workload-sizing-before/summary.json'),
        'boundary_after_sha256':sha(base / 'workload-sizing-after/summary.json'),
        'logs':{name:sha(base / name) for name in ['workload-engine-tests.log','workload-po220-limits-tests.log','workload-po220-benchmark-tests.log','workload-po220-cli-check.log','workload-po220-worker-build.log']}}
    report['campaign_source_archive'] = {
        'engine_patch_sha256':sha(ROOT / 'docs/macos/evidence/native-workloads-engine.patch'),
    }
    driver = args.campaign / 'driver-source.py'
    if driver.exists():
        assert sha(driver) == campaign['script_sha256']
        report['campaign_source_archive'].update(driver_path=str(driver), driver_sha256=sha(driver))
    if args.acceptance_archive:
        archive = args.acceptance_archive.resolve()
        build = read(archive / 'acceptance-build.json')
        binary = archive / Path(build['binary_path']).name
        assert sha(binary) == build['binary_sha256']
        assert sha(archive / 'acceptance-build.json') == sha(Path(campaign['cases'][-1]['run']) / 'acceptance-build.json')
        report['campaign_source_archive'].update(
            acceptance_binary=str(binary),acceptance_binary_sha256=sha(binary),
            acceptance_build_sha256=sha(archive / 'acceptance-build.json'))
    if args.calibrated_admission:
        run = args.calibrated_admission.resolve()
        result = read(run / 'result.json')
        assert result['status'] == 'passed' and result['po2'] == 19
        assert result['results']['verified_proofs'] == 1 and result['results']['admission_pressure']
        assert result['worker_build']['binary_sha256'] == report['worker_binary_sha256']
        assert result['verifier_build']['binary_sha256'] == report['verifier_binary_sha256']
        calibration = read(run / 'acceptance/calibration.json')
        pressure = read(run / 'acceptance/pressure.json')
        assert calibration['profile_sha256'] == result['calibration']['sha256']
        assert pressure['needed_bytes'] == calibration['expected_host_budget_bytes']
        assert pressure['attempted'] is False and pressure['reserved_after_bytes'] == 0
        assert pressure['sidecar_count_after'] == pressure['sidecar_count_before']
        directory = run / 'acceptance/proof-0'
        worker, verified = read(directory / 'worker.json'), read(directory / 'verification.json')
        assert verified['verification'] == 'passed'
        assert set(verified['negative_tests']) == {'wrong_image','modified_journal','corrupt_seal'}
        assert sha(directory / 'seal.bin') == worker['seal_sha256']
        assert sha(directory / 'journal.bin') == worker['journal_sha256']
        report['post_campaign_validation'] = {
            'path':str(run),'verified_proofs':1,'negative_rejections':3,
            'calibration':calibration,'refusal':pressure,'worker':worker,
            'artifact_hashes':{p.name:sha(p) for p in sorted(directory.iterdir()) if p.is_file()},
            'run_hashes':{name:sha(run / name) for name in ['result.json','acceptance-build.json','test.log','acceptance/complete.json','acceptance/calibration.json','acceptance/pressure.json']},
        }
        archive = base / 'step4-final-acceptance'
        if archive.exists():
            build = read(archive / 'acceptance-build.json')
            binary = archive / Path(build['binary_path']).name
            assert sha(archive / 'acceptance-build.json') == sha(run / 'acceptance-build.json')
            assert sha(binary) == build['binary_sha256']
            report['post_campaign_validation']['acceptance_binary_archive'] = {'path':str(binary),'sha256':sha(binary)}
        report['validation']['final_logs'] = {name:sha(base / name) for name in ['workload-final-engine-tests.log','workload-final-cli-check.log']}
    final_state = base / 'workload-final-state.json'
    if final_state.exists():
        report['validation']['final_state'] = read(final_state)
        report['validation']['final_state_sha256'] = sha(final_state)
    preliminary = base / 'workload-campaigns/a90a508b35fc4e9d926e9582781284bf'
    report['retained_po218_screen'] = {
        'path':str(preliminary),'status':read(preliminary / 'result.json')['status'],
        'result_sha256':sha(preliminary / 'result.json'),'plan_sha256':sha(preliminary / 'plan.json'),
        'intentional_cancellation':read(preliminary / 'replan.json'),
        'replan_sha256':sha(preliminary / 'replan.json'),
        'verified_proofs':[],
    }
    old = read(preliminary / 'result.json')
    for case in old['cases']:
        log = preliminary / (case['name']+'.log')
        if not log.exists() or not log.read_text().splitlines(): continue
        run = Path(log.read_text().splitlines()[0])
        for verified_path in sorted((run / 'acceptance').glob('*/verification.json')):
            directory = verified_path.parent;worker = read(directory / 'worker.json');verified = read(verified_path)
            assert verified['verification'] == 'passed' and len(verified['negative_tests']) == 3
            assert sha(directory / 'seal.bin') == worker['seal_sha256']
            report['retained_po218_screen']['verified_proofs'].append({
                'case':case['name'],'path':str(directory),'worker':worker,
                'artifacts':{p.name:sha(p) for p in sorted(directory.iterdir()) if p.is_file()}})
    report['limitations'] = ['Five measured warm proofs per fixed 10M fixture; one excluded first-process warmup each, not cold-boot timing.',
        'One arithmetic stretch proof only; hashing stretch sized but not proved in this campaign.',
        'Physical footprints are sampled, not an exact peak or a kernel-enforced memory cap.',
        'Thermal nominal can mean unavailable; no energy or frequency measurements.',
        'Deadline scaling is workload-dependent and does not establish marketplace feasibility.',
        'Linux execution tests passed; Linux GPU proving runtime was not tested.']
    out = ROOT / 'docs/macos/evidence'
    measured = []
    for case in report['cases']:
        if case['name'] not in ['arithmetic-10m','hash-10m']: continue
        for p in case['proofs']:
            if p['warmup']: continue
            w, t = p['worker'], p['timings']
            measured.append({'workload':case['name'],'sample':p['case'],
                'guest_cycles':w['stats']['user_cycles'],'total_cycles':w['stats']['total_cycles'],
                'segments':w['stats']['segments'],'po2':w['po2'],
                'rayon_threads':w['rayon_threads'],'gomaxprocs':w['gomaxprocs'],
                'worker_body_seconds':w['total_ms']/1000,
                'complete_seconds':(t['prove_call_ms']+t['external_verifier_ms'])/1000,
                **{k+'_seconds':v/1000 for k,v in w['stage_ms'].items()},
                **p['memory']})
    assert len(measured) == 10
    csv_path = out / 'native-workloads-comparison.csv'
    with csv_path.open('w') as file:
        writer = csv.DictWriter(file, fieldnames=list(measured[0]))
        writer.writeheader();writer.writerows(measured)
    report['measured_csv_sha256'] = sha(csv_path)
    (out / 'native-workloads-validation.json').write_text(json.dumps(report,indent=2)+'\n')
    (out / 'native-workloads-calibration.json').write_text(json.dumps(profile,indent=2)+'\n')
    if args.calibrated_admission:
        assert sha(out / 'native-workloads-calibration.json') == result['calibration']['sha256']
    print(f"Saved {report['verified_proofs']} full proofs and {report['negative_rejections']} negative checks; useful target={report['useful_target_passed']}")


if __name__ == '__main__': main()
