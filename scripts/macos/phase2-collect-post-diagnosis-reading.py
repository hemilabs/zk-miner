#!/usr/bin/env python3
"""Validate the controlled absolute reading after the paired lift decision."""

import argparse
import csv
import importlib.util
import json
from pathlib import Path

from proof_provenance import ROOT, sha

SPEC_SHA256 = '9a0e052f6c1e72a1a8a31d3081fe3a3604bbfe11cb9fd661e30109c21c12f6f1'
ARCHIVE = ROOT / 'target/macos/phase2/upstream-merge-checkpoint'
EVIDENCE = ROOT / 'docs/macos/evidence'


def read(path):
    return json.loads(Path(path).read_text())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('run', type=Path)
    args = parser.parse_args()
    campaign = read(args.run / 'result.json')
    assert campaign['status'] == 'passed' and campaign['source_spec_sha256'] == SPEC_SHA256
    assert campaign['idle_gap_seconds'] >= 900
    assert campaign['host_start']['observation']['thermal']['thermal_state_name'] == 'nominal'
    assert campaign['host_start']['observation']['background_process_present']['brave'] is False
    paired = read(campaign['paired_evidence'])
    assert sha(Path(campaign['paired_evidence'])) == campaign['paired_evidence_sha256']
    assert paired['all_lift_gaps_within_threshold'] is True
    manifest_path = ARCHIVE / 'manifest.json'
    manifest = read(manifest_path)
    assert sha(manifest_path) == campaign['checkpoint_manifest_sha256']
    for name, digest in manifest['files'].items():
        assert sha(ARCHIVE / name) == digest
    assert manifest['files']['zkminer-prove-risc0'] == campaign['worker_sha256']
    assert manifest['files']['hemi-macos-proof'] == campaign['verifier_sha256']
    assert manifest['files']['helper-manifest.json'] == campaign['helper_manifest_sha256']
    assert campaign['conditions'] == {
        'browser_closed': True, 'host_reserve_gib': 8, 'reserve_override': False,
        'initial_thermal': 'nominal', 'rayon_threads': 18, 'go_threads': 18,
        'po2': 20, 'segment_pipeline': True,
        'warmups_per_fixture': 1, 'measured_per_fixture': 5,
    }
    source = Path(__file__).with_name('phase2-collect-upstream-merge.py')
    spec = importlib.util.spec_from_file_location('upstream_merge_collector', source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    fixtures = [module.collect_fixture(row, campaign) for row in campaign['fixtures']]
    assert [row['fixture'] for row in fixtures] == ['arithmetic-10m', 'hash-10m', 'arithmetic-46m']
    medians = {row['fixture']: row['median_complete_seconds'] for row in fixtures}
    report = {
        'schema_version': 1, 'status': 'complete',
        'scope': 'post-paired-lift controlled absolute reading; this is a line reading, not the code-cost gate',
        'source_spec_sha256': SPEC_SHA256,
        'campaign_run': str(args.run), 'campaign_result_sha256': sha(args.run / 'result.json'),
        'paired_evidence_sha256': campaign['paired_evidence_sha256'],
        'checkpoint_manifest_sha256': campaign['checkpoint_manifest_sha256'],
        'worker_sha256': campaign['worker_sha256'], 'verifier_sha256': campaign['verifier_sha256'],
        'helper_manifest_sha256': campaign['helper_manifest_sha256'],
        'engine_commit': campaign['engine_commit'],
        'miner_checkpoint_commit': campaign['miner_checkpoint_commit'],
        'acceptance_build_manifest_sha256': campaign['acceptance_build_manifest_sha256'],
        'driver_sha256': campaign['driver_sha256'],
        'acceptance_runner_sha256': campaign['acceptance_runner_sha256'],
        'collector_sha256': sha(Path(__file__)),
        'reused_fixture_collector_sha256': sha(source),
        'idle_gap_seconds': campaign['idle_gap_seconds'],
        'host_start': campaign['host_start'], 'conditions': campaign['conditions'],
        'verified_proofs': 18, 'tamper_rejections': 54,
        'minimum_line_met': medians['arithmetic-10m'] <= 55 and
                            medians['hash-10m'] <= 55 and medians['arithmetic-46m'] <= 220,
        'desirable_line_met': medians['arithmetic-10m'] <= 45 and
                              medians['hash-10m'] <= 45 and medians['arithmetic-46m'] <= 180,
        'all_peaks_below_32_gib': all(row['max_guard_peak_footprint_bytes'] < 32 * 1024**3
                                      for row in fixtures),
        'normal_pressure_all_rows': all(row['pressure_levels'] == [1] for row in fixtures),
        'fixtures': fixtures,
    }
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    csv_path = EVIDENCE / 'phase2-post-diagnosis-controlled.csv'
    with csv_path.open('w', newline='') as file:
        writer = csv.DictWriter(file, fieldnames=list(fixtures[0]['rows'][0]), lineterminator='\n')
        writer.writeheader()
        for fixture in fixtures:
            writer.writerows(fixture['rows'])
    report['csv_sha256'] = sha(csv_path)
    out = EVIDENCE / 'phase2-post-diagnosis-controlled.json'
    out.write_text(json.dumps(report, indent=2) + '\n')
    print(out)
    print(csv_path)


if __name__ == '__main__':
    main()
