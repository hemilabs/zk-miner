#!/usr/bin/env python3
"""Validate paired upstream-diagnosis proof evidence and compute lift gaps."""

import argparse
import csv
import json
import re
from pathlib import Path
from statistics import median

from proof_provenance import ROOT, sha

SPEC_SHA256 = '9a0e052f6c1e72a1a8a31d3081fe3a3604bbfe11cb9fd661e30109c21c12f6f1'
EVIDENCE = ROOT / 'docs/macos/evidence'
EXPECTED_CYCLES = {'arithmetic-10m': 10_003_116, 'hash-10m': 10_003_440,
                   'arithmetic-46m': 46_003_116}
EXPECTED_SEGMENTS = {'arithmetic-10m': 10, 'hash-10m': 10, 'arithmetic-46m': 46}


def read(path):
    return json.loads(Path(path).read_text())


def collect_fixture(fixture, campaign, archive):
    run = Path(fixture['run'])
    raw = read(run / 'result.json')
    assert fixture['status'] == raw['status'] == 'passed'
    assert sha(run / 'result.json') == fixture['result_sha256']
    assert raw['worker_build']['binary_sha256'] == campaign['merged_worker_sha256']
    assert raw['verifier_build']['binary_sha256'] == campaign['verifier_sha256']
    assert raw['paired_metal_baseline']['sha256'] == campaign['baseline_worker_sha256']
    assert raw['bundle'] == read(archive / 'helper-manifest.json')
    assert raw['po2'] == 20
    assert raw['program_sha256'] and raw['input_sha256']
    assert raw['results']['samples_per_case'] == fixture['measured_pairs']
    assert raw['results']['settings'] == [[18, 18], [18, 18]]
    assert raw['results']['segment_cases'] == ['metal', 'metal']
    assert raw['results']['worker_binaries'] == [
        str(archive / 'zkminer-prove-risc0'),
        str(ROOT / 'target/macos/worker-native-rv32im-metal/release/zkminer-prove-risc0')]
    assert raw['paired_start_case'] == fixture['start_case']
    rows = raw['results']['rows']
    submit_events = []
    diagnostics = []
    for line in (run / 'test.log').read_text().splitlines():
        if '[paired_worker]' not in line:
            continue
        diagnostics.append(line)
        match = re.search(r'\[paired_worker\] pid=(\d+) observed_epoch_ns=(\d+) .*gpu_submit', line)
        if match:
            submit_events.append((int(match.group(1)), int(match.group(2)), line))
    assert submit_events, 'paired worker GPU submit logs missing'
    pairs = fixture['measured_pairs']
    assert len(rows) == 2 * (pairs + 1)
    for host in (fixture['host_before'], fixture['host_after']):
        assert sha(Path(host['path'])) == host['sha256']
        assert host['observation']['background_process_present']['brave'] is False
    output = []
    for index, row in enumerate(rows):
        round_index = index // 2
        order = [0, 1] if (round_index + fixture['start_case']) % 2 == 0 else [1, 0]
        assert row['round'] == round_index and row['case'] == order[index % 2]
        assert row['warmup'] == (round_index == 0)
        assert row['rayon_threads'] == row['gomaxprocs'] == 18
        arm = 'baseline' if row['case'] == 0 else 'merged'
        worker = row['worker']
        assert worker['rayon_threads'] == worker['gomaxprocs'] == 18
        assert worker['segment_hal'] == worker['recursion_hal'] == 'metal'
        assert worker['elf_sha256'] == raw['program_sha256']
        assert worker['input_sha256'] == raw['input_sha256']
        assert worker['po2'] == 20
        assert worker['stats']['user_cycles'] == EXPECTED_CYCLES[fixture['fixture']]
        assert worker['stats']['segments'] == EXPECTED_SEGMENTS[fixture['fixture']]
        proof = run / 'acceptance' / f'round-{round_index}-case-{row["case"]}'
        verification = read(proof / 'verification.json')
        assert verification['verification'] == 'passed'
        assert set(verification['negative_tests']) == {'wrong_image', 'modified_journal', 'corrupt_seal'}
        assert verification['elf_sha256'] == raw['program_sha256']
        rv = worker['observed_stages']['rv32im_metal']
        recursion = worker['observed_stages']['recursion_metal']
        assert rv['completed_constraint_checks'] == EXPECTED_SEGMENTS[fixture['fixture']]
        assert recursion['completed_constraint_checks'] > 0
        memory = row['resources']['idle_after_verification_and_settle']['native_memory']
        assert memory['reserve_bytes'] == 8 * 1024**3
        request_epoch_ns = row['resources']['proof_request_epoch_ns']
        end_epoch_ns = request_epoch_ns + int(row['timings']['prove_call_ms'] * 1_000_000)
        first_submit = next((event for event in submit_events
            if event[0] == worker['worker_pid'] and request_epoch_ns <= event[1] <= end_epoch_ns), None)
        assert first_submit is not None, f'first gpu_submit missing for {arm} round {round_index}'
        output.append({
            'fixture': fixture['fixture'], 'round': round_index, 'arm': arm,
            'warmup': row['warmup'],
            'complete_seconds': (row['timings']['prove_call_ms'] + row['timings']['external_verifier_ms']) / 1000,
            'prove_call_seconds': row['timings']['prove_call_ms'] / 1000,
            'external_verifier_seconds': row['timings']['external_verifier_ms'] / 1000,
            'admission_wait_seconds': row['admission_wait_ms'] / 1000,
            'request_to_first_gpu_submit_seconds': (first_submit[1] - request_epoch_ns) / 1_000_000_000,
            'first_gpu_submit_epoch_ns': first_submit[1],
            'execution_and_segment_seconds': worker['stage_ms']['execution_and_segment'] / 1000,
            'recursion_seconds': worker['stage_ms']['recursion'] / 1000,
            'identity_and_wrap_seconds': worker['stage_ms']['identity_and_wrap'] / 1000,
            'segment_gpu_seconds': sum(item['gpu_seconds'] for item in rv['gpu_kernels'].values()),
            'recursion_gpu_seconds': sum(item['gpu_seconds'] for item in recursion['gpu_kernels'].values()),
            'segment_gpu_kernel_seconds': json.dumps({k: v['gpu_seconds'] for k, v in rv['gpu_kernels'].items()}, sort_keys=True),
            'recursion_gpu_kernel_seconds': json.dumps({k: v['gpu_seconds'] for k, v in recursion['gpu_kernels'].items()}, sort_keys=True),
            'guard_peak_footprint_bytes': memory['guard_peak_footprint_bytes'],
            'idle_worker_footprint_bytes': memory['group']['worker']['footprint_bytes'],
            'pressure_level': memory['pressure_level'],
            'rayon_threads': worker['rayon_threads'], 'go_threads': worker['gomaxprocs'],
            'worker_pid': worker['worker_pid'],
            'program_sha256': raw['program_sha256'], 'input_sha256': raw['input_sha256'],
            'journal_sha256': worker['journal_sha256'], 'seal_sha256': worker['seal_sha256'],
            'worker_sidecar_sha256': sha(proof / 'worker.json'),
            'verification_sha256': sha(proof / 'verification.json'),
        })
    ledger = [json.loads(x) for x in (run / 'acceptance/requests.jsonl').read_text().splitlines()]
    startups = [x for x in ledger if x.get('event') == 'worker_started']
    assert len(startups) == 2 and {x['case'] for x in startups} == {0, 1}
    for startup in startups:
        assert startup['rayon_threads'] == startup['gomaxprocs'] == 18
        assert startup['process_priority']
    assert len([x for x in ledger if 'worker' in x and x.get('warmup') is not None]) == len(rows)
    assert len({x['journal_sha256'] for x in output}) == 1
    for arm in ('baseline', 'merged'):
        assert len({x['worker_pid'] for x in output if x['arm'] == arm}) == 1
    measured = [x for x in output if not x['warmup']]
    times = {arm: [x['complete_seconds'] for x in measured if x['arm'] == arm]
             for arm in ('baseline', 'merged')}
    assert len(times['baseline']) == len(times['merged']) == pairs
    gaps = []
    ratios = []
    for pair in range(1, pairs + 1):
        by_arm = {x['arm']: x['complete_seconds'] for x in output[2*pair:2*pair+2]}
        gaps.append(by_arm['merged'] - by_arm['baseline'])
        ratios.append(by_arm['merged'] / by_arm['baseline'])
    stage_names = ('request_to_first_gpu_submit_seconds', 'execution_and_segment_seconds',
                   'recursion_seconds', 'identity_and_wrap_seconds',
                   'segment_gpu_seconds', 'recursion_gpu_seconds')
    return {
        'fixture': fixture['fixture'], 'run': str(run), 'result_sha256': sha(run / 'result.json'),
        'request_ledger_sha256': sha(run / 'acceptance/requests.jsonl'),
        'warmups_per_arm': 1, 'measured_pairs': pairs,
        'median_complete_seconds': {arm: median(values) for arm, values in times.items()},
        'range_complete_seconds': {arm: [min(values), max(values)] for arm, values in times.items()},
        'median_of_pair_gaps_seconds': median(gaps), 'within_pair_gaps_seconds': gaps,
        'within_pair_merged_over_baseline_ratios': ratios,
        'median_of_arm_medians_gap_seconds': median(times['merged']) - median(times['baseline']),
        'median_stage_seconds': {stage: {arm: median(x[stage] for x in measured if x['arm'] == arm)
                                        for arm in ('baseline', 'merged')} for stage in stage_names},
        'max_guard_peak_footprint_bytes': max(x['guard_peak_footprint_bytes'] for x in output),
        'pressure_levels': sorted({x['pressure_level'] for x in output}),
        'rows': output, 'host_before': fixture['host_before'], 'host_after': fixture['host_after'],
        'worker_startups': startups,
        'worker_diagnostic_lines': diagnostics,
        'test_log_sha256': sha(run / 'test.log'),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('run', type=Path)
    args = parser.parse_args()
    campaign = read(args.run / 'result.json')
    assert campaign['status'] == 'passed' and campaign['source_spec_sha256'] == SPEC_SHA256
    archive = Path(campaign['baseline_archive'])
    manifest = read(archive / 'manifest.json')
    assert sha(archive / 'manifest.json') == campaign['baseline_manifest_sha256']
    assert manifest['files']['zkminer-prove-risc0'] == campaign['baseline_worker_sha256']
    for name, digest in manifest['files'].items():
        assert sha(archive / name) == digest
    assert campaign['merged_worker_sha256'] == 'c3428c3717c331c452e3621736e779ae1f06311003dfd65b50f292d39877e5f9'
    assert campaign['idle_gap_seconds'] >= 900
    assert campaign['host_start']['observation']['thermal']['thermal_state_name'] == 'nominal'
    assert campaign['host_start']['observation']['background_process_present']['brave'] is False
    fixtures = [collect_fixture(f, campaign, archive) for f in campaign['fixtures']]
    assert [x['fixture'] for x in fixtures] == list(EXPECTED_CYCLES)
    threshold = {'arithmetic-10m': 1.0, 'hash-10m': 1.0, 'arithmetic-46m': 3.0}
    lift = all(x['median_of_pair_gaps_seconds'] <= threshold[x['fixture']] for x in fixtures)
    report = {
        'schema_version': 1, 'status': 'complete', 'label': campaign['label'],
        'source_spec_sha256': SPEC_SHA256,
        'campaign_run': str(args.run), 'campaign_result_sha256': sha(args.run / 'result.json'),
        'driver_sha256': campaign['driver_sha256'], 'collector_sha256': sha(Path(__file__)),
        'acceptance_runner_sha256': campaign['acceptance_runner_sha256'],
        'idle_gap_seconds': campaign['idle_gap_seconds'],
        'baseline_manifest_sha256': campaign['baseline_manifest_sha256'],
        'baseline_worker_sha256': campaign['baseline_worker_sha256'],
        'merged_worker_sha256': campaign['merged_worker_sha256'],
        'verifier_sha256': campaign['verifier_sha256'],
        'helper_manifest_sha256': campaign['helper_manifest_sha256'],
        'merged_engine_commit': campaign['merged_engine_commit'],
        'miner_commit': campaign['miner_commit'],
        'conditions': campaign['conditions'], 'host_start': campaign['host_start'],
        'all_lift_gaps_within_threshold': lift,
        'threshold_seconds': threshold,
        'verified_proofs': sum(2*(x['measured_pairs']+1) for x in fixtures),
        'tamper_rejections': 3*sum(2*(x['measured_pairs']+1) for x in fixtures),
        'fixtures': fixtures,
    }
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    csv_path = EVIDENCE / f'phase2-upstream-diagnosis-{campaign["label"]}.csv'
    with csv_path.open('w', newline='') as file:
        writer = csv.DictWriter(file, fieldnames=list(fixtures[0]['rows'][0]), lineterminator='\n')
        writer.writeheader()
        for fixture in fixtures:
            writer.writerows(fixture['rows'])
    report['csv_sha256'] = sha(csv_path)
    out = EVIDENCE / f'phase2-upstream-diagnosis-{campaign["label"]}.json'
    out.write_text(json.dumps(report, indent=2) + '\n')
    print(out)
    print(csv_path)


if __name__ == '__main__':
    main()
