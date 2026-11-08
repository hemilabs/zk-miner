#!/usr/bin/env python3
"""Run shared-buffer controls in a frozen engine copy, preserving candidate seals."""
import argparse
import json
from pathlib import Path
import shutil
import subprocess
import uuid
from proof_provenance import ROOT, sha
from worker_provenance import verify_build


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--engine',type=Path,required=True)
    args=parser.parse_args()
    engine=args.engine.resolve()
    worker=verify_build('native-recursion-metal',engine)
    directory=ROOT/'target/macos/metal-buffer-controls'/uuid.uuid4().hex
    source=directory/'source';source.mkdir(parents=True)
    files=subprocess.check_output(['git','ls-files','-z'],cwd=engine).decode().split('\0')
    for name in files:
        if not name or not (engine/name).is_file():continue
        path=source/name;path.parent.mkdir(parents=True,exist_ok=True)
        shutil.copy2(engine/name,path)
    test=Path(__file__).with_name('metal-buffer-controls.rs')
    destination=source/'risc0/zkp/tests/step5_metal_buffers.rs'
    destination.parent.mkdir(exist_ok=True);shutil.copy2(test,destination)
    command=['cargo','+1.93.0','test','--locked','--manifest-path',str(source/'Cargo.toml'),
             '-p','risc0-zkp','--features','metal-runtime','--release','--test','step5_metal_buffers',
             '--target-dir',str(ROOT/'target/macos/metal-buffer-controls/build'),'--no-run','--message-format=json']
    report={'status':'running','worker_build':worker,'test_source_sha256':sha(test),
            'script_sha256':sha(Path(__file__)),'command':command,
            'snapshot_metal_hal_sha256':sha(source/'risc0/zkp/src/hal/metal.rs')}
    print(directory,flush=True)
    try:
        with (directory/'build.jsonl').open('w') as out,(directory/'build.stderr').open('w') as err:
            subprocess.run(command,cwd=ROOT,stdout=out,stderr=err,check=True,timeout=600)
        binaries=set()
        for line in (directory/'build.jsonl').read_text().splitlines():
            row=json.loads(line)
            if row.get('reason')=='compiler-artifact' and row.get('target',{}).get('name')=='step5_metal_buffers' and row.get('executable'):
                binaries.add(row['executable'])
        assert len(binaries)==1
        binary=Path(binaries.pop());report.update(binary_path=str(binary),binary_sha256=sha(binary))
        with (directory/'test.log').open('w') as out:
            subprocess.run([str(binary),'--nocapture'],cwd=ROOT,stdout=out,stderr=subprocess.STDOUT,check=True,timeout=120)
        assert 'test result: ok. 1 passed;' in (directory/'test.log').read_text()
        assert sha(binary)==report['binary_sha256']
        assert verify_build('native-recursion-metal',engine)==worker
        assert sha(test)==report['test_source_sha256']
        report['status']='passed'
    except BaseException as error:
        report.update(status='failed',error=str(error));raise
    finally:
        (directory/'result.json').write_text(json.dumps(report,indent=2)+'\n')


if __name__=='__main__':main()
