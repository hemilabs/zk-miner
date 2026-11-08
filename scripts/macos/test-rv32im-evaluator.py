#!/usr/bin/env python3
"""Build and run a source-bound, guarded RV32IM Metal evaluator prototype."""
import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
import uuid
from worker_provenance import ROOT, sha, verify_build

BASE=ROOT/'target/macos/rv32im-metal'
TOOL=ROOT/'tools/macos-rv32im-metal'
BINARY=BASE/'build/release/hemi-macos-rv32im-metal-prototype'


def source_state(engine):
    assert not subprocess.check_output(['git','-C',str(engine),'status','--porcelain']), 'prototype requires a clean engine'
    files=list(TOOL.rglob('*.rs'))+list(TOOL.glob('*.metal'))+[TOOL/'Cargo.toml',TOOL/'Cargo.lock',
        ROOT/'scripts/macos/generate-rv32im-metal.py',Path(__file__),ROOT/'scripts/macos/env.sh',
        BASE/'engine.toml',BASE/'evaluator.metal',BASE/'evaluator.json']
    generated=json.loads((BASE/'evaluator.json').read_text())
    assert sha(BASE/'evaluator.metal')==generated['source_sha256']
    assert sha(ROOT/'scripts/macos/generate-rv32im-metal.py')==generated['generator_sha256']
    for name,digest in generated['source_files'].items():assert sha(Path(name))==digest
    commit=subprocess.check_output(['git','-C',str(engine),'rev-parse','HEAD'],text=True).strip()
    assert commit==generated['engine_commit']
    return {'engine_commit':commit,'inputs':{str(p):sha(p) for p in files}}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--engine',type=Path,required=True)
    parser.add_argument('--case',choices=['compile']+[str(i) for i in range(4,21)],default='compile')
    parser.add_argument('--seed',type=int,default=1)
    parser.add_argument('--threads',type=int,choices=[32,64,128,256,512,1024],default=32)
    parser.add_argument('--timeout',type=int,default=600)
    parser.add_argument('--build',action='store_true')
    args=parser.parse_args();engine=args.engine.resolve()
    assert 1<=args.timeout<=900 and 0<=args.seed<2**31
    BASE.mkdir(parents=True,exist_ok=True)
    if args.build:
        revision=subprocess.check_output(['git','-C',str(engine),'rev-parse','HEAD'],text=True).strip()
        subprocess.run([sys.executable,str(ROOT/'scripts/macos/local-engine.py'),str(engine),str(BASE/'engine.toml'),
            '--revision',revision],check=True)
        subprocess.run([sys.executable,str(ROOT/'scripts/macos/generate-rv32im-metal.py'),'--engine',str(engine),
            '--output',str(BASE/'evaluator.metal')],check=True,stdout=(BASE/'generate.log').open('w'))
        before=source_state(engine)
        common=['cargo','+1.93.0','--offline','--locked','--manifest-path',str(TOOL/'Cargo.toml'),
                '--config',str(BASE/'engine.toml')]
        with (BASE/'build.log').open('w') as log:
            subprocess.run([common[0],common[1],'build']+common[2:]+['--release','--target-dir',str(BASE/'build')],
                cwd=ROOT,stdout=log,stderr=subprocess.STDOUT,check=True,timeout=900)
        with (BASE/'metadata.json').open('w') as out,(BASE/'metadata.stderr').open('w') as err:
            subprocess.run([common[0],common[1],'metadata']+common[2:]+['--filter-platform','aarch64-apple-darwin','--format-version','1'],
                cwd=ROOT,stdout=out,stderr=err,check=True)
        subprocess.run([sys.executable,str(ROOT/'scripts/macos/check-source.py'),str(BASE/'metadata.json'),
            '--engine',str(engine),'--metal-runtime'],check=True)
        assert source_state(engine)==before, 'source changed during build'
        build={'source':before,'binary_sha256':sha(BINARY),'metadata_sha256':sha(BASE/'metadata.json'),
            'toolchain':'1.93.0','environment':{k:os.environ.get(k) for k in ['RUSTFLAGS','CARGO_ENCODED_RUSTFLAGS','CARGO_HOME','RUSTUP_HOME','SDKROOT','DEVELOPER_DIR']}}
        (BASE/'build.json').write_text(json.dumps(build,indent=2)+'\n')
    build=json.loads((BASE/'build.json').read_text())
    assert source_state(engine)==build['source']
    assert sha(BINARY)==build['binary_sha256'] and sha(BASE/'metadata.json')==build['metadata_sha256']
    worker=verify_build('native-recursion-metal',engine)
    directory=BASE/'runs'/uuid.uuid4().hex;directory.mkdir(parents=True)
    command=[str(BINARY),str(BASE/'evaluator.metal'),args.case,str(args.seed)]
    report={'status':'running','build':build,'command':command,'runner_sha256':sha(Path(__file__)),
        'verified_worker_build':worker,'timeout_seconds':args.timeout,
        'guard':'self physical-footprint <=32 GiB; available estimate >=8 GiB; normal/warning pressure; 16+16 GiB admission; 500 ms sampling',
        'rayon_threads':18,'threads_per_threadgroup':args.threads,
        'scope':'synthetic evaluator differential, not a complete proof or throughput result'}
    (directory/'plan.json').write_text(json.dumps(report,indent=2)+'\n')
    print(directory,flush=True)
    started=time.monotonic();proc=None
    try:
        with (directory/'stdout.jsonl').open('w') as out,(directory/'stderr.log').open('w') as err:
            proc=subprocess.Popen(command,cwd=ROOT,stdout=out,stderr=err,start_new_session=True,
                env=dict(os.environ,RAYON_NUM_THREADS='18',RV32IM_METAL_THREADS=str(args.threads)))
            proc.wait(timeout=args.timeout)
        report['exit_code']=proc.returncode
        if proc.returncode:raise RuntimeError(f'evaluator failed ({proc.returncode}); see stderr.log')
        phases=[json.loads(line) for line in (directory/'stdout.jsonl').read_text().splitlines()]
        assert phases[-1]['phase']=='result' and phases[-1]['data']['status']=='passed'
        if args.case!='compile':
            assert phases[-1]['data']['completed_dispatches']>0
            assert all(c['status']=='matched' for c in phases[-1]['data']['cases'])
        report['phases']=phases
        assert source_state(engine)==build['source'] and sha(BINARY)==build['binary_sha256']
        assert verify_build('native-recursion-metal',engine)==worker
        report['status']='passed'
    except BaseException as error:
        report.update(status='failed',error=str(error));raise
    finally:
        if proc is not None and proc.poll() is None:
            os.killpg(proc.pid,signal.SIGKILL);proc.wait(timeout=10)
        report['elapsed_seconds']=time.monotonic()-started
        report['artifact_hashes']={name:sha(directory/name) for name in ['plan.json','stdout.jsonl','stderr.log']}
        (directory/'result.json').write_text(json.dumps(report,indent=2)+'\n')
        print(json.dumps({'status':report['status'],'elapsed_seconds':report['elapsed_seconds']}),flush=True)


if __name__=='__main__':main()
