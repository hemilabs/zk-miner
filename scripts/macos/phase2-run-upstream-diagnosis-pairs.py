#!/usr/bin/env python3
"""Run sealed, alternating Phase 2 upstream-diagnosis proof pairs."""

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import uuid
from datetime import datetime, timezone

from proof_provenance import ROOT, sha, verify_build as verify_verifier
from worker_provenance import paths, verify_build as verify_worker

ENGINE = Path('/Users/dbur/dev/risc0')
SPEC_SHA256 = '9a0e052f6c1e72a1a8a31d3081fe3a3604bbfe11cb9fd661e30109c21c12f6f1'
MERGED_SHA256 = 'c3428c3717c331c452e3621736e779ae1f06311003dfd65b50f292d39877e5f9'
FIXTURES = (
    ('arithmetic-10m', 'fibonacci', '1000000', '10000000', 5),
    ('hash-10m', 'sha256-chain', '2262', '10000000', 5),
    ('arithmetic-46m', 'fibonacci', '4600000', '46000000', 3),
)


def stamp():
    return datetime.now(timezone.utc).isoformat()


def snapshot(directory, name):
    path = directory / f'host-{name}.json'
    subprocess.run([sys.executable, str(ROOT / 'scripts/macos/phase2-host-snapshot.py'),
                    '--output', str(path)], check=True, capture_output=True, text=True)
    return {'path': str(path), 'sha256': sha(path), 'observation': json.loads(path.read_text())}


def require_browser_closed(host):
    assert host['observation']['background_process_present']['brave'] is False
    for browser in ('Safari', 'Google Chrome', 'Firefox', 'Microsoft Edge', 'Brave Browser'):
        assert subprocess.run(['pgrep', '-x', browser], capture_output=True).returncode == 1, browser


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline-archive', type=Path, required=True)
    parser.add_argument('--expected-baseline-sha256', required=True)
    parser.add_argument('--label', choices=('a', 'b'), required=True)
    parser.add_argument('--last-activity-file', type=Path, required=True)
    parser.add_argument('--acceptance-build-manifest', type=Path, required=True)
    args = parser.parse_args()
    archive = args.baseline_archive.resolve(strict=True)
    prior_activity = args.last_activity_file.resolve(strict=True)
    acceptance_manifest_path = args.acceptance_build_manifest.resolve(strict=True)
    acceptance_manifest = json.loads(acceptance_manifest_path.read_text())
    assert sha(Path(acceptance_manifest['binary_path'])) == acceptance_manifest['binary_sha256']
    assert os.environ.get('ZKMINER_MACOS_HOST_RESERVE_GIB') is None, 'use default reserve, no override'
    for key in ('RISC0_SEGMENT_PIPELINE', 'RISC0_RV32IM_TAIL_SPLIT',
                'RISC0_RECURSION_METAL_SPLIT', 'RISC0_METAL_NTT_LEGACY_GRID'):
        assert os.environ.get(key) is None, key
    manifest_path = archive / 'manifest.json'
    manifest = json.loads(manifest_path.read_text())
    assert manifest['status'] == 'sealed'
    for name, digest in manifest['files'].items():
        assert sha(archive / name) == digest, name
    assert manifest['files']['zkminer-prove-risc0'] == args.expected_baseline_sha256
    merged = verify_worker('native-rv32im-metal', ENGINE)
    verifier = verify_verifier('verifier')
    assert merged['binary_sha256'] == MERGED_SHA256
    assert manifest['files']['hemi-macos-proof'] == verifier['binary_sha256']
    assert manifest['files']['helper-manifest.json'] == sha(ROOT / 'target/macos/native-wrap/assets/manifest.json')
    directory = ROOT / 'target/macos/phase2/upstream-diagnosis-pairs' / (args.label + '-' + uuid.uuid4().hex)
    directory.mkdir(parents=True)
    first_host = snapshot(directory, 'campaign-start')
    require_browser_closed(first_host)
    assert first_host['observation']['thermal']['thermal_state_name'] == 'nominal'
    prior_end = datetime.fromtimestamp(prior_activity.stat().st_mtime, timezone.utc)
    started = datetime.now(timezone.utc)
    idle_gap = (started - prior_end).total_seconds()
    assert idle_gap >= 900, f'idle gap {idle_gap:.1f}s is below 15 minutes'
    report = {
        'schema_version': 1, 'status': 'running', 'label': args.label,
        'started_utc': started.isoformat(), 'source_spec_sha256': SPEC_SHA256,
        'last_build_or_campaign_file': str(prior_activity),
        'last_build_or_campaign_file_sha256': sha(prior_activity),
        'last_build_or_campaign_end_utc': prior_end.isoformat(), 'idle_gap_seconds': idle_gap,
        'host_start': first_host,
        'conditions': {'browser_closed': True, 'default_reserve_gib': 8,
                       'reserve_override': False, 'thermal_nominal_at_start': True,
                       'one_proof_in_flight': True, 'arms_resident_per_fixture': True,
                       'rayon_threads': 18, 'go_threads': 18, 'po2': 20,
                       'warmup_per_arm': 1, 'measured_pairs_10m': 5,
                       'measured_pairs_46m': 3, 'failures_excluded': False},
        'baseline_archive': str(archive), 'baseline_manifest_sha256': sha(manifest_path),
        'baseline_worker_sha256': args.expected_baseline_sha256,
        'merged_worker_sha256': merged['binary_sha256'],
        'merged_engine_commit': merged['source']['engine_head'],
        'merged_worker_manifest_sha256': sha(paths('native-rv32im-metal')['manifest']),
        'verifier_sha256': verifier['binary_sha256'],
        'helper_manifest_sha256': manifest['files']['helper-manifest.json'],
        'driver_sha256': sha(Path(__file__)),
        'acceptance_runner_sha256': sha(ROOT / 'scripts/macos/test-native-worker.py'),
        'acceptance_build_manifest': str(acceptance_manifest_path),
        'acceptance_build_manifest_sha256': sha(acceptance_manifest_path),
        'miner_commit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
        'fixtures': [],
    }
    result_path = directory / 'result.json'
    def save():
        result_path.write_text(json.dumps(report, indent=2) + '\n')
    save()
    print(directory, flush=True)
    toolchain = ROOT / 'target/macos/toolchain'
    env = dict(os.environ, CARGO_NET_OFFLINE='true', CARGO_HOME=str(toolchain / 'cargo'),
               RUSTUP_HOME=str(toolchain / 'rustup'), RISC0_HOME=str(toolchain / 'risc0'),
               CARGO_BUILD_JOBS='6', RAYON_NUM_THREADS='18',
               ZKMINER_MACOS_LEGACY_BASELINE_PROTOCOL='5',
               ZKMINER_MACOS_PAIRED_DIAGNOSTICS='1',
               PATH=str(toolchain / 'cargo/bin') + os.pathsep + os.environ['PATH'])
    env.pop('ZKMINER_MACOS_HOST_RESERVE_GIB', None)
    try:
        for fixture_index, (name, workload, iterations, min_cycles, pairs) in enumerate(FIXTURES):
            row = {'fixture': name, 'status': 'running', 'started_utc': stamp(),
                   'measured_pairs': pairs, 'start_case': fixture_index % 2}
            report['fixtures'].append(row)
            row['host_before'] = snapshot(directory, name + '-before')
            require_browser_closed(row['host_before'])
            cmd = [sys.executable, str(ROOT / 'scripts/macos/test-native-worker.py'),
                   '--engine', str(ENGINE), '--worker-kind', 'native-rv32im-metal',
                   '--segment-hal', 'metal', '--recursion-hal', 'metal',
                   '--paired-metal-baseline', str(archive / 'zkminer-prove-risc0'),
                   '--paired-start-case', str(row['start_case']),
                   '--prebuilt-acceptance-manifest', str(acceptance_manifest_path),
                   '--workload', workload, '--iterations', iterations,
                   '--min-guest-cycles', min_cycles, '--po2', '20',
                   '--rayon-threads', '18', '--go-threads', '18',
                   '--samples', str(pairs), '--repeat', '1', '--proof-only',
                   '--timeout-seconds', '1800']
            row['command'] = cmd
            save()
            with (directory / f'{name}.log').open('w') as log:
                process = subprocess.run(cmd, cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT)
            row['exit_code'] = process.returncode
            row['host_after'] = snapshot(directory, name + '-after')
            lines = (directory / f'{name}.log').read_text().splitlines()
            if lines:
                row['run'] = lines[0]
                raw = Path(lines[0]) / 'result.json'
                if raw.exists():
                    row['result_sha256'] = sha(raw)
            row['finished_utc'] = stamp()
            row['status'] = 'passed' if process.returncode == 0 and row.get('run') and json.loads((Path(row['run']) / 'result.json').read_text())['status'] == 'passed' else 'failed'
            save()
            print(f'{name}: {row["status"]}: {row.get("run")}', flush=True)
            if row['status'] != 'passed':
                raise RuntimeError(f'{name} failed; evidence preserved at {row.get("run")}')
        report['status'] = 'passed'
    except BaseException as error:
        report.update(status='failed', error=str(error))
        raise
    finally:
        report['finished_utc'] = stamp()
        save()


if __name__ == '__main__':
    main()
