#!/usr/bin/env python3
"""Collect local proof outcomes and hashes; never infer success from absent files."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess


def sha(path):
    with path.open('rb') as file:
        return hashlib.file_digest(file, 'sha256').hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--engine', type=Path, required=True)
    parser.add_argument('--worker-evidence', type=Path, required=True)
    parser.add_argument('--worker-log', type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    base = root / 'target/macos'
    dest = root / 'docs/macos/evidence'
    dest.mkdir(parents=True, exist_ok=True)
    report = {'note': 'Correctness runs, not a controlled performance comparison.',
              'hardware': json.loads((base / 'hardware-native.json').read_text()),
              'harness_attempts': [], 'worker_proofs': [], 'artifacts': {}}
    for line in (base / 'runs/results.jsonl').read_text().splitlines():
        run = json.loads(line)
        directory = base / 'runs' / run['run_id'] / 'proof'
        for name in ('proof', 'verification'):
            path = directory / (name + '.json')
            if path.exists():
                run[name + '_report'] = json.loads(path.read_text())
        report['harness_attempts'].append(run)
    worker_log = args.worker_log.read_text()
    for directory in sorted(args.worker_evidence.glob('proof-*')):
        match = re.search(re.escape(str(directory)) + r' \((\d+) cycles, ([0-9.]+)s\)', worker_log)
        proof = {'directory': str(directory),
                 'verification': json.loads((directory / 'verification.json').read_text()),
                 'seal_sha256': sha(directory / 'seal.bin'),
                 'journal_sha256': sha(directory / 'journal.bin')}
        if match:
            proof.update(cycles=int(match[1]), seconds=float(match[2]))
        report['worker_proofs'].append(proof)
    report['worker_suite_completion'] = (args.worker_evidence / 'complete.txt').read_text()
    report['worker_suite_log_sha256'] = sha(args.worker_log)
    report['worker_suite_log'] = str(args.worker_log)
    initial = base / 'test-worker-acceptance.log'
    report['other_failures'] = [{
        'status': 'failed', 'stage': 'initial_worker_startup',
        'reason': 'free-only memory guard killed startup; corrected estimate tested subsequently',
        'log': str(initial), 'log_sha256': sha(initial),
    }]
    report['test_logs'] = []
    for path in sorted(base.glob('test-*.log')):
        result_lines = [line for line in path.read_text(errors='replace').splitlines()
                        if line.startswith('test result:') or 'could not compile' in line]
        report['test_logs'].append({'path': str(path), 'sha256': sha(path), 'results': result_lines})
    report['helper_artifacts'] = (base / 'helper-artifacts.log').read_text()
    for name, path in {
        'miner_lock': root / 'Cargo.lock', 'harness_lock': root / 'tools/macos-proof/Cargo.lock',
        'worker_local_lock': base / 'worker-local-Cargo.lock',
        'verifier_lock': base / 'unchanged-verifier/Cargo.lock',
        'worker_metadata': base / 'worker-metadata.json', 'verifier_metadata': base / 'verifier-metadata.json',
        'worker_binary': base / 'worker/release/zkminer-prove-risc0',
        'miner_binary': base / 'miner/release/zkminer',
        'prover_binary': base / 'cpu/release/hemi-macos-proof',
        'verifier_binary': base / 'verifier/release/hemi-macos-proof',
    }.items():
        report['artifacts'][name] = {'path': str(path), 'sha256': sha(path)}
    report['guests'] = {p.parent.name: json.loads(p.read_text()) for p in sorted((base / 'guests').glob('*/provenance.json'))}
    report['revisions'] = {}
    for name, path in {'miner': root, 'engine': args.engine, 'supplied_hemi': Path('/Users/dbur/dev/risc0'),
                       'upstream_read_only': Path('/Users/dbur/dev/risc0-parent')}.items():
        report['revisions'][name] = {'path': str(path), 'head': subprocess.check_output(
            ['git', '-C', str(path), 'rev-parse', 'HEAD'], text=True).strip()}
    engine_diff = subprocess.check_output(['git', '-C', str(args.engine), 'diff', '--binary'])
    (dest / 'hemi-engine.patch').write_bytes(engine_diff)
    report['engine_patch_sha256'] = hashlib.sha256(engine_diff).hexdigest()
    (dest / 'validation.json').write_text(json.dumps(report, indent=2) + '\n')
    print(f'wrote {dest / "validation.json"}: {len(report["harness_attempts"])} harness attempts, {len(report["worker_proofs"])} worker proofs')


if __name__ == '__main__':
    main()
