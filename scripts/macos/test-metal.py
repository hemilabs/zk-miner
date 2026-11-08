#!/usr/bin/env python3
"""Bounded native Metal differential run; preserve failures and actual GPU evidence."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import time
import uuid
from metal_provenance import verify_build


def sha(path):
    with path.open('rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--engine', type=Path, required=True)
    parser.add_argument('--mode', choices=['basic', 'boundaries', 'arithmetic', 'ntt', 'sha256', 'poseidon2', 'hybrid-fold', 'all'], default='all')
    parser.add_argument('--timeout', type=int, default=180)
    args = parser.parse_args()
    if not 1 <= args.timeout <= 600:
        parser.error('timeout must be 1..600 seconds')
    root = Path(__file__).resolve().parents[2]
    binary = root / 'target/macos/metal/release/hemi-macos-metal-tests'
    if not binary.is_file():
        parser.error('build the runtime Metal harness first')
    out = root / 'target/macos/metal-runs' / uuid.uuid4().hex
    out.mkdir(parents=True)
    command = [str(binary), args.mode]
    def git(path, *args):
        return subprocess.check_output(['git', '-C', str(path), *args])
    report = {'id': out.name, 'mode': args.mode, 'command': command, 'status': 'failed',
              'binary_sha256': sha(binary), 'engine_head': git(args.engine, 'rev-parse', 'HEAD').decode().strip(),
              'engine_working_diff_sha256': hashlib.sha256(git(args.engine, 'diff', 'HEAD', '--binary')).hexdigest(),
              'miner_head': git(root, 'rev-parse', 'HEAD').decode().strip(),
              'full_proof_acceleration': False, 'max_sampled_native_rss_bytes': None,
              'rss_method': 'ps RSS of this native harness, sampled at up to 1-second intervals; not a Metal allocation peak'}
    print(out, flush=True)
    start = time.monotonic()
    proc = None
    try:
        report['verified_build'] = verify_build(args.engine, binary)
        with (out / 'stdout.json').open('w') as stdout, (out / 'stderr.log').open('w') as stderr:
            proc = subprocess.Popen(command, stdout=stdout, stderr=stderr, start_new_session=True)
            while proc.poll() is None:
                if time.monotonic() - start > args.timeout:
                    raise TimeoutError('Metal differential deadline exceeded')
                ps = subprocess.run(['ps', '-o', 'rss=', '-p', str(proc.pid)], text=True, capture_output=True)
                if ps.returncode == 0 and ps.stdout.strip():
                    rss = int(ps.stdout.strip()) * 1024
                    report['max_sampled_native_rss_bytes'] = max(report['max_sampled_native_rss_bytes'] or 0, rss)
                    if rss > 4 * 1024**3:
                        raise RuntimeError('native test harness exceeded 4 GiB RSS bound')
                try:
                    proc.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    pass
            report['exit_code'] = proc.returncode
            if proc.returncode != 0:
                raise RuntimeError(f'harness failed ({proc.returncode}); see stderr.log')
        results = json.loads((out / 'stdout.json').read_text())
        if (results.get('status') != 'passed' or results.get('case_count', 0) <= 0
                or results['completed_dispatches'] <= 0
                or results['completed_dispatches'] != results.get('successful_case_dispatches')):
            raise RuntimeError('missing passing cases or consistent actual GPU completion evidence')
        report['results'] = results
        report['status'] = 'passed_cpu_metal_differential'
    except Exception as error:
        report['error'] = str(error)
        raw = out / 'stdout.json'
        if raw.exists():
            try:
                report['partial_results'] = json.loads(raw.read_text())
            except (ValueError, OSError):
                pass
    finally:
        if proc is not None and proc.poll() is None:
            os.killpg(proc.pid, signal.SIGKILL)
            proc.wait(timeout=10)
        report['elapsed_seconds'] = time.monotonic() - start
        (out / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
        with (out.parent / 'results.jsonl').open('a') as ledger:
            ledger.write(json.dumps(report) + '\n')
    print(json.dumps({key: report[key] for key in ('id', 'status', 'elapsed_seconds')}))
    return 0 if report['status'] == 'passed_cpu_metal_differential' else 1


if __name__ == '__main__':
    raise SystemExit(main())
