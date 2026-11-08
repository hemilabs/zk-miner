#!/usr/bin/env python3
"""Controlled absolute reading after the paired upstream-merge stop lifts."""

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess
import sys
import uuid

from proof_provenance import ROOT, sha, verify_build as verify_verifier
from worker_provenance import paths, verify_build as verify_worker

ENGINE = Path('/Users/dbur/dev/risc0')
ARCHIVE = ROOT / 'target/macos/phase2/upstream-merge-checkpoint'
PAIRED = ROOT / 'docs/macos/evidence/phase2-upstream-diagnosis-a.json'
SPEC_SHA256 = '9a0e052f6c1e72a1a8a31d3081fe3a3604bbfe11cb9fd661e30109c21c12f6f1'
FIXTURES = (
    ('arithmetic-10m', 'fibonacci', '1000000', '10000000'),
    ('hash-10m', 'sha256-chain', '2262', '10000000'),
    ('arithmetic-46m', 'fibonacci', '4600000', '46000000'),
)


def stamp():
    return datetime.now(timezone.utc).isoformat()


def snapshot(directory, name):
    path = directory / f'host-{name}.json'
    subprocess.run([sys.executable, str(ROOT / 'scripts/macos/phase2-host-snapshot.py'),
                    '--output', str(path)], check=True, capture_output=True, text=True)
    return {'path': str(path), 'sha256': sha(path), 'observation': json.loads(path.read_text())}


def browser_closed(host):
    assert host['observation']['background_process_present']['brave'] is False
    for browser in ('Safari', 'Google Chrome', 'Firefox', 'Microsoft Edge', 'Brave Browser'):
        assert subprocess.run(['pgrep', '-x', browser], capture_output=True).returncode == 1, browser


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--last-campaign-result', type=Path, required=True)
    parser.add_argument('--acceptance-build-manifest', type=Path, required=True)
    args = parser.parse_args()
    prior = args.last_campaign_result.resolve(strict=True)
    acceptance_path = args.acceptance_build_manifest.resolve(strict=True)
    acceptance = json.loads(acceptance_path.read_text())
    assert sha(Path(acceptance['binary_path'])) == acceptance['binary_sha256']
    paired = json.loads(PAIRED.read_text())
    assert paired['all_lift_gaps_within_threshold'] is True
    assert prior == (Path(paired['campaign_run']) / 'result.json').resolve(strict=True)
    assert sha(prior) == paired['campaign_result_sha256']
    assert os.environ.get('ZKMINER_MACOS_HOST_RESERVE_GIB') is None
    for name in ('RISC0_SEGMENT_PIPELINE', 'RISC0_RV32IM_TAIL_SPLIT',
                 'RISC0_RECURSION_METAL_SPLIT', 'RISC0_METAL_NTT_LEGACY_GRID'):
        assert os.environ.get(name) is None, name
    manifest_path = ARCHIVE / 'manifest.json'
    manifest = json.loads(manifest_path.read_text())
    assert manifest['status'] == 'sealed'
    for name, digest in manifest['files'].items():
        assert sha(ARCHIVE / name) == digest, name
    worker = verify_worker('native-rv32im-metal', ENGINE)
    verifier = verify_verifier('verifier')
    assert worker['binary_sha256'] == manifest['files']['zkminer-prove-risc0']
    assert verifier['binary_sha256'] == manifest['files']['hemi-macos-proof']
    assert worker['source']['engine_head'] == manifest['engine_commit']
    assert sha(ROOT / 'target/macos/native-wrap/assets/manifest.json') == manifest['files']['helper-manifest.json']
    directory = ROOT / 'target/macos/phase2/controlled-post-diagnosis' / uuid.uuid4().hex
    directory.mkdir(parents=True)
    first_host = snapshot(directory, 'campaign-start')
    browser_closed(first_host)
    assert first_host['observation']['thermal']['thermal_state_name'] == 'nominal'
    prior_end = datetime.fromtimestamp(prior.stat().st_mtime, timezone.utc)
    started = datetime.now(timezone.utc)
    idle_gap = (started - prior_end).total_seconds()
    assert idle_gap >= 900, f'idle gap {idle_gap:.1f}s is below 15 minutes'
    report = {
        'schema_version': 1, 'status': 'running', 'started_utc': started.isoformat(),
        'source_spec_sha256': SPEC_SHA256,
        'paired_evidence': str(PAIRED), 'paired_evidence_sha256': sha(PAIRED),
        'last_campaign_result': str(prior), 'last_campaign_result_sha256': sha(prior),
        'last_campaign_end_utc': prior_end.isoformat(), 'idle_gap_seconds': idle_gap,
        'host_start': first_host, 'checkpoint_manifest_sha256': sha(manifest_path),
        'worker_sha256': worker['binary_sha256'], 'verifier_sha256': verifier['binary_sha256'],
        'helper_manifest_sha256': manifest['files']['helper-manifest.json'],
        'engine_commit': manifest['engine_commit'], 'miner_checkpoint_commit': manifest['miner_commit'],
        'acceptance_build_manifest': str(acceptance_path),
        'acceptance_build_manifest_sha256': sha(acceptance_path),
        'driver_sha256': sha(Path(__file__)),
        'acceptance_runner_sha256': sha(ROOT / 'scripts/macos/test-native-worker.py'),
        'conditions': {'browser_closed': True, 'host_reserve_gib': 8, 'reserve_override': False,
                       'initial_thermal': 'nominal', 'rayon_threads': 18, 'go_threads': 18,
                       'po2': 20, 'segment_pipeline': True,
                       'warmups_per_fixture': 1, 'measured_per_fixture': 5},
        'fixtures': [],
    }
    result_path = directory / 'result.json'
    def save():
        result_path.write_text(json.dumps(report, indent=2) + '\n')
    save()
    print(directory, flush=True)
    toolchain = ROOT / 'target/macos/toolchain'
    env = dict(os.environ, CARGO_NET_OFFLINE='true', RUSTUP_TOOLCHAIN='1.93.0',
               CARGO_HOME=str(toolchain / 'cargo'), RUSTUP_HOME=str(toolchain / 'rustup'),
               RISC0_HOME=str(toolchain / 'risc0'), RAYON_NUM_THREADS='18',
               PATH=str(toolchain / 'cargo/bin') + os.pathsep + os.environ['PATH'])
    env.pop('ZKMINER_MACOS_HOST_RESERVE_GIB', None)
    try:
        for fixture, workload, iterations, min_cycles in FIXTURES:
            row = {'fixture': fixture, 'status': 'running', 'started_utc': stamp()}
            report['fixtures'].append(row)
            row['host_before'] = snapshot(directory, fixture + '-before')
            browser_closed(row['host_before'])
            command = [sys.executable, str(ROOT / 'scripts/macos/test-native-worker.py'),
                       '--engine', str(ENGINE), '--worker-kind', 'native-rv32im-metal',
                       '--segment-hal', 'metal', '--recursion-hal', 'metal',
                       '--prebuilt-acceptance-manifest', str(acceptance_path),
                       '--workload', workload, '--iterations', iterations,
                       '--min-guest-cycles', min_cycles, '--po2', '20',
                       '--rayon-threads', '18', '--go-threads', '18',
                       '--repeat', '5', '--warmup', '--proof-only', '--timeout-seconds', '1800']
            row['command'] = command
            save()
            with (directory / f'{fixture}.log').open('w') as log:
                process = subprocess.run(command, cwd=ROOT, env=env,
                                         stdout=log, stderr=subprocess.STDOUT)
            row['exit_code'] = process.returncode
            row['host_after'] = snapshot(directory, fixture + '-after')
            lines = (directory / f'{fixture}.log').read_text().splitlines()
            if lines:
                row['run'] = lines[0]
                raw = Path(lines[0]) / 'result.json'
                if raw.exists():
                    row['result_sha256'] = sha(raw)
            row['finished_utc'] = stamp()
            row['status'] = 'passed' if process.returncode == 0 and row.get('run') and json.loads((Path(row['run']) / 'result.json').read_text())['status'] == 'passed' else 'failed'
            save()
            print(f'{fixture}: {row["status"]}: {row.get("run")}', flush=True)
            if row['status'] != 'passed':
                raise RuntimeError(f'{fixture} failed; evidence preserved at {row.get("run")}')
        report['status'] = 'passed'
    except BaseException as error:
        report.update(status='failed', error=str(error))
        raise
    finally:
        report['finished_utc'] = stamp()
        save()


if __name__ == '__main__':
    main()
