#!/usr/bin/env python3
"""Bind the experimental Metal executable to its reviewed local source inputs."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[2]
BASE = ROOT / 'target/macos'


def sha(path):
    with path.open('rb') as file:
        return hashlib.file_digest(file, 'sha256').hexdigest()


def source_state(engine):
    engine = engine.resolve()
    def git(*args):
        return subprocess.check_output(['git', '-C', str(engine), *args])
    if git('ls-files', '--others', '--exclude-standard', '-z'):
        raise RuntimeError('stage new engine source files before building, so the source diff records them')
    return {
        'engine_path': str(engine),
        'engine_head': git('rev-parse', 'HEAD').decode().strip(),
        'engine_working_diff_sha256': hashlib.sha256(git('diff', 'HEAD', '--binary')).hexdigest(),
        'harness_inputs': {str(path.relative_to(ROOT)): sha(path) for path in [
            ROOT / 'tools/macos-metal/Cargo.toml', ROOT / 'tools/macos-metal/Cargo.lock',
            ROOT / 'tools/macos-metal/src/main.rs',
        ]},
        'override_config_sha256': sha(BASE / 'metal-engine.toml'),
    }


def verify_build(engine, binary):
    manifest_path = BASE / 'metal-build.json'
    manifest = json.loads(manifest_path.read_text())
    if source_state(engine) != manifest['source']:
        raise RuntimeError('Metal source inputs changed since the recorded build; rebuild before testing')
    if sha(binary) != manifest['binary_sha256']:
        raise RuntimeError('Metal executable differs from the recorded build; rebuild before testing')
    if sha(BASE / 'metal-metadata.json') != manifest['metadata_sha256']:
        raise RuntimeError('Metal source metadata differs from the recorded build')
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['snapshot', 'seal'])
    parser.add_argument('engine', type=Path)
    args = parser.parse_args()
    snapshot_path = BASE / 'metal-build-inputs.json'
    state = source_state(args.engine)
    if args.action == 'snapshot':
        snapshot_path.write_text(json.dumps(state, indent=2) + '\n')
        return
    if state != json.loads(snapshot_path.read_text()):
        raise RuntimeError('source inputs changed during the Metal build; refusing provenance seal')
    manifest = {
        'source': state,
        'binary_sha256': sha(BASE / 'metal/release/hemi-macos-metal-tests'),
        'metadata_sha256': sha(BASE / 'metal-metadata.json'),
        'host_toolchain': '1.93.0',
        'build_environment': {key: os.environ.get(key) for key in
                              ['RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'DEVELOPER_DIR', 'TOOLCHAINS', 'SDKROOT']},
    }
    (BASE / 'metal-build.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print('Metal binary sealed to exact engine diff, harness inputs, lock, and source metadata')


if __name__ == '__main__':
    main()
