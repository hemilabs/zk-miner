#!/usr/bin/env python3
"""Seal the lifted upstream-merged worker with paired and absolute evidence."""

import json
from pathlib import Path
import shutil
import subprocess

from proof_provenance import ROOT, sha
from worker_provenance import verify_build as verify_worker

ENGINE = Path('/Users/dbur/dev/risc0')
SOURCE = ROOT / 'target/macos/phase2/upstream-merge-checkpoint'
ARCHIVE = ROOT / 'target/macos/phase2/post-diagnosis-final-checkpoint'
PAIRED = ROOT / 'docs/macos/evidence/phase2-upstream-diagnosis-a.json'
CONTROLLED = ROOT / 'docs/macos/evidence/phase2-post-diagnosis-controlled.json'
SPEC = Path('/Users/dbur/Downloads/Phase 2 spec Metal proving performance on macOS.md')
SPEC_SHA256 = '9a0e052f6c1e72a1a8a31d3081fe3a3604bbfe11cb9fd661e30109c21c12f6f1'


def main():
    if ARCHIVE.exists():
        raise RuntimeError(f'final checkpoint already exists: {ARCHIVE}')
    assert sha(SPEC) == SPEC_SHA256
    source = json.loads((SOURCE / 'manifest.json').read_text())
    assert source['status'] == 'sealed'
    for name, digest in source['files'].items():
        assert sha(SOURCE / name) == digest, name
    paired = json.loads(PAIRED.read_text())
    controlled = json.loads(CONTROLLED.read_text())
    assert paired['all_lift_gaps_within_threshold'] is True
    assert controlled['status'] == 'complete' and controlled['minimum_line_met'] is True
    assert controlled['worker_sha256'] == source['files']['zkminer-prove-risc0']
    assert paired['merged_worker_sha256'] == controlled['worker_sha256']
    worker = verify_worker('native-rv32im-metal', ENGINE)
    assert worker['binary_sha256'] == controlled['worker_sha256']
    assert worker['source']['engine_head'] == source['engine_commit']
    ARCHIVE.mkdir(parents=True)
    for name in source['files']:
        shutil.copy2(SOURCE / name, ARCHIVE / name)
    branch_commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
    manifest = {
        'schema_version': 1, 'status': 'sealed',
        'checkpoint': 'Phase 2 post-diagnosis final merged Metal worker',
        'source_spec_sha256': SPEC_SHA256,
        'engine_commit': source['engine_commit'],
        'worker_source_miner_commit': source['miner_commit'],
        'branch_commit_at_seal': branch_commit,
        'paired_evidence_sha256': sha(PAIRED),
        'controlled_evidence_sha256': sha(CONTROLLED),
        'files': {name: sha(ARCHIVE / name) for name in source['files']},
    }
    path = ARCHIVE / 'manifest.json'
    path.write_text(json.dumps(manifest, indent=2) + '\n')
    for name, digest in manifest['files'].items():
        assert sha(ARCHIVE / name) == digest
    print(path)
    print(sha(path))


if __name__ == '__main__':
    main()
