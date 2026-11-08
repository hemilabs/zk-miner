#!/usr/bin/env python3
"""Bind RV32IM port assessment arithmetic to verified profiles and pinned source."""
import argparse
import csv
import json
from pathlib import Path
import re
import subprocess
from proof_provenance import ROOT, sha


def read(path):
    return json.loads(path.read_text())


def timers(text, tag):
    result=[]
    for line in text.splitlines():
        if '['+tag+']' in line:
            result.append({k:float(v) for k,v in re.findall(r'(\w+)=([0-9.]+)ms',line)})
    return result


def sum_ms(rows,key):
    return sum(row[key] for row in rows)/1000


def scenarios(total,acceleratable):
    floor=total-acceleratable
    assert floor>=0
    return {
        'acceleratable_seconds':acceleratable,'remaining_floor_seconds':floor,
        'ideal_speedup_ceiling':total/floor if floor else None,
        'phase_speedup_needed_for_2x_complete':acceleratable/(acceleratable-total/2) if acceleratable>total/2 else None,
        'conditional_seconds':{str(k):floor+acceleratable/k for k in [1.5,2,3,5,10]},
        'scope':'Amdahl what-if with all other time unchanged; not a measured or predicted Metal speedup',
    }


def profile(run):
    result=read(run/'result.json');assert result['status']=='passed'
    worker=read(run/'acceptance/proof-0/worker.json')
    verification=read(run/'acceptance/proof-0/verification.json')
    assert verification['verification']=='passed'
    assert set(verification['negative_tests'])=={'wrong_image','modified_journal','corrupt_seal'}
    assert sha(run/'acceptance/proof-0/seal.bin')==worker['seal_sha256']
    assert sha(run/'acceptance/proof-0/journal.bin')==worker['journal_sha256']
    text=(run/'test.log').read_text()
    assert '[composite_to_succinct] starting' in text
    segment_text=text.split('[composite_to_succinct] starting',1)[0]
    begin=timers(segment_text,'prove_begin')
    start=timers(segment_text,'start_finalize')
    final=timers(segment_text,'finalize')
    segments=worker['stats']['segments']
    assert len(begin)==len(start)==len(final)==segments
    assert segments==10 and worker['po2']==20 and worker['recursion_hal']=='metal'
    rows=[json.loads(line) for line in (run/'acceptance/requests.jsonl').read_text().splitlines()]
    verified=next(r for r in rows if r.get('status')=='complete_independently_verified')
    assert verified['worker']==worker
    complete=(verified['timings']['prove_call_ms']+verified['timings']['external_verifier_ms'])/1000
    groups={name:timers(segment_text,'poly_group('+name+')') for name in ['code','data','accum','check']}
    assert all(len(groups[name])==segments for name in ['data','accum','check'])
    coeffs=timers(segment_text,'make_coeffs')
    polynomial=sum(sum_ms(rows,'ntt')+sum_ms(rows,'bitrev') for rows in groups.values())
    polynomial+=sum_ms(coeffs,'intt_zk')+sum_ms(final,'check_intt')
    merkle=sum(sum_ms(rows,'merkle') for rows in groups.values())
    exclusive={
        'constraint_evaluation':sum_ms(start,'eval_check_launch'),
        'merkle_commitments':merkle,
        'polynomial_transforms':polynomial,
        'witness_generation':sum_ms(begin,'witgen'),
        'accumulation':sum_ms(begin,'accum'),
    }
    segment_total=sum_ms(begin,'total')
    exclusive['other_segment_protocol']=segment_total-sum(exclusive.values())
    assert exclusive['other_segment_protocol']>=-0.1
    stage=worker['stage_ms']['execution_and_segment']/1000
    assert stage>=segment_total-0.1
    generic=polynomial+merkle;constraint=exclusive['constraint_evaluation']
    return {
        'run':str(run),'worker':worker,'complete_seconds':complete,
        'execution_and_segment_seconds':stage,'summed_segment_prover_seconds':segment_total,
        'execution_preflight_and_caller_residual_seconds':stage-segment_total,
        'exclusive_segment_seconds':exclusive,
        'exclusive_segment_percent':{k:v/segment_total*100 for k,v in exclusive.items()},
        'timers':{'begin':begin,'start_finalize':start,'finalize':final,'groups':groups,'make_coeffs':coeffs},
        'conditional_scenarios':{
            'transforms_and_merkle_only':scenarios(complete,generic),
            'constraint_only':scenarios(complete,constraint),
            'constraint_transforms_merkle':scenarios(complete,generic+constraint),
            'witness_and_accumulation_only':scenarios(complete,exclusive['witness_generation']+exclusive['accumulation']),
        },
        'artifact_hashes':{name:sha(run/name) for name in ['result.json','test.log','acceptance-build.json','acceptance/complete.json','acceptance/proof-0/worker.json','acceptance/proof-0/verification.json']},
    }


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--engine',type=Path,required=True)
    parser.add_argument('--profiles',type=Path,required=True)
    parser.add_argument('--device',type=Path,required=True)
    args=parser.parse_args();engine=args.engine.resolve()
    raw=read(args.profiles/'result.json');assert raw['status']=='completed'
    assert sha(args.profiles/'driver-source.py')==raw['script_sha256']
    baseline=ROOT/'docs/macos/evidence/recursion-metal-validation.json';latest=read(baseline)
    assert raw['worker_build']['binary_sha256']==latest['worker_binary_sha256']
    assert raw['verifier_build']['binary_sha256']==latest['verifier_binary_sha256']
    report={'schema_version':1,'status':'complete','source_engine_commit':subprocess.check_output(['git','rev-parse','HEAD'],cwd=engine,text=True).strip(),
        'source_miner_commit':subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),
        'latest_profile_sha256':sha(baseline),'diagnostic_plan_sha256':sha(args.profiles/'plan.json'),
        'diagnostic_result_sha256':sha(args.profiles/'result.json'),'assessment_script_sha256':sha(Path(__file__)),
        'worker_binary_sha256':raw['worker_build']['binary_sha256'],'verifier_binary_sha256':raw['verifier_build']['binary_sha256'],
        'device':read(args.device),'device_sha256':sha(args.device),'latest_observations':[],'diagnostics':[]}
    checkpoint=ROOT/'target/macos/step6-assessment/step5-after-commit.json'
    continuity=read(checkpoint)
    assert continuity['binary_unchanged'] and continuity['compiled_inputs_unchanged'] and continuity['engine_commit_matches_measured_patch']
    assert continuity['worker_build']==raw['worker_build']
    report['checkpoint_continuity']={'path':str(checkpoint),'sha256':sha(checkpoint),'result':continuity}
    for case in latest['cases']:
        if case['name'] not in ['arithmetic-10m','hash-10m']:continue
        p=case['proofs'][0];w=p['worker'];total=(p['timings']['prove_call_ms']+p['timings']['external_verifier_ms'])/1000
        stage=w['stage_ms']['execution_and_segment']/1000
        report['latest_observations'].append({'fixture':case['name'],'complete_seconds':total,'stage_seconds':stage,
            'stage_share_percent':stage/total*100,'optimistic_combined_stage_scenarios':scenarios(total,stage)})
    for case in raw['cases']:
        assert case['status']=='passed'
        run=Path(case['run']);result=read(run/'result.json')
        assert sha(run/'result.json')==case['result_sha256']
        assert result['worker_build']==raw['worker_build'] and result['verifier_build']==raw['verifier_build']
        p=profile(run);p['fixture']=case['name'];report['diagnostics'].append(p)
    base=engine/'risc0/circuit/rv32im-sys/kernels'
    files=[p for p in base.rglob('*') if p.is_file()]
    parts=sorted((base/'cuda').glob('eval_check_[0-9].cu'))
    functions=set()
    for p in parts:functions.update(re.findall(r'__device__\s+FpExt\s+(rv32im_v2_\d+)\(',p.read_text()))
    defs=(engine/'risc0/circuit/rv32im/src/zirgen/defs.rs.inc').read_text()
    counts={name:int(n) for name,n in re.findall(r'define_tap_buffer!\s*\{\s*(\w+),\s*/\*count=\*/(\d+),',defs)}
    assert counts=={'accum':103,'code':1,'data':211}
    entry=(base/'cuda/eval_check_0.cu').read_text().split('__device__ FpExt poly_fp(',1)[1]
    scratch=[{'type':kind,'entries':int(n)} for kind,n in re.findall(r'\b(Fp(?:Ext)?)\s+\w+\[(\d+)\]',entry)]
    assert scratch
    report['port_inventory']={
        'existing_rv32im_metal_files':len([p for p in files if 'metal' in p.relative_to(base).parts]),
        'generated_constraint_chunks':len(parts),'generated_constraint_functions':len(functions),
        'generated_constraint_chunk_lines':sum(len(p.read_bytes().splitlines()) for p in parts),
        'generated_cuda_steps_lines':len((base/'cuda/steps.cu').read_bytes().splitlines()),
        'declared_poly_scratch_arrays':scratch,
        'declared_poly_scratch_bytes_per_invocation':sum(s['entries']*({'Fp':4,'FpExt':16}[s['type']]) for s in scratch),
        'scratch_scope':'Declared arrays in CUDA poly_fp; not measured registers/spill allocation or Metal peak memory',
        'tap_group_columns':counts,
    }
    report['memory_lower_bounds']=[]
    for po2 in [18,20]:
        steps=1<<po2;domain=steps*4
        allocation={k:{'coeff_bytes':n*steps*4,'evaluated_bytes':n*domain*4,'merkle_nodes_bytes':domain*2*32} for k,n in counts.items()}
        largest=allocation['data']['evaluated_bytes'];device_max=report['device']['max_buffer_bytes']
        report['memory_lower_bounds'].append({'po2':po2,'groups':allocation,
            'committed_groups_and_trees_bytes':sum(sum(a.values()) for a in allocation.values()),
            'largest_buffer_bytes':largest,'fits_observed_device_single_buffer_limit':largest<=device_max,
            'scope':'Simultaneously retained group allocations only; excludes check group, raw witness, trace, scratch, driver allocations, helper and allocator retention; not a peak forecast'})
    sources=['risc0/circuit/rv32im/src/prove/hal/mod.rs','risc0/circuit/rv32im/src/prove/hal/cpu.rs',
        'risc0/circuit/rv32im/src/prove/hal/cuda.rs','risc0/circuit/rv32im/src/prove/witgen/mod.rs',
        'risc0/circuit/rv32im/src/zirgen/defs.rs.inc','risc0/zkp/src/hal/metal.rs',
        'risc0/zkp/src/prove/prover.rs','risc0/zkp/src/prove/poly_group.rs','risc0/zkp/src/prove/merkle.rs',
        'risc0/circuit/rv32im-sys/kernels/cuda/eval_check.cuh','risc0/circuit/rv32im-sys/kernels/cuda/eval_check_kernel.cu']
    report['source_hashes']={p:sha(engine/p) for p in sources}
    report['source_hashes'].update({str(p.relative_to(engine)):sha(p) for p in parts})
    report['decision']={'original_usefulness_target':'already met by five-sample native CPU acceptance',
        'full_port':'not required for the agreed target; separate scalability investment',
        'proposed_next_gate':'First de-risk full-domain Metal constraint evaluation; then integrate existing Metal transforms/Merkle with shared CPU witness/accumulation. Require measured complete-proof gain before a full port commitment.',
        'proposed_scalability_gate':'If a new 2x complete-throughput objective is selected, roughly 2.42..2.44x effective speedup of the combined constraint/transform/Merkle phases is necessary under the constant-other-cost model; measure the whole job to confirm.',
        'gate_scope':'Proposed follow-up criterion, not a user-approved replacement for the original 10M/10-minute goal',
        'defer':'GPU witness/accumulation until measured workloads justify them',
        'implementation_started':False}
    report['limitations']=['Two single verbose diagnostic proofs, not new warm medians; log timing rounds to 0.1 ms.',
        'CPU eval_check is synchronous: eval_check_launch measures its work, not just GPU launch latency.',
        'Merkle timers combine leaf hashing and tree folding; no measured split is available.',
        'Do not sum nested timers; exclusive categories reconcile to segment totals.',
        'Conditional speedups require unmeasured Metal compiler/occupancy/bandwidth behavior; no guaranteed port speedup.',
        'Arithmetic and hashing do not establish BigInt/ECDSA or marketplace workload performance.']
    out=ROOT/'docs/macos/evidence';csv_path=out/'rv32im-metal-profile.csv'
    with csv_path.open('w') as file:
        writer=csv.DictWriter(file,fieldnames=['fixture','category','seconds','segment_percent'])
        writer.writeheader()
        for p in report['diagnostics']:
            for k,v in p['exclusive_segment_seconds'].items():writer.writerow({'fixture':p['fixture'],'category':k,'seconds':v,'segment_percent':p['exclusive_segment_percent'][k]})
    report['profile_csv_sha256']=sha(csv_path)
    (out/'rv32im-metal-assessment.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({'latest':report['latest_observations'],'diagnostics':[{k:p[k] for k in ['fixture','exclusive_segment_seconds','conditional_scenarios']} for p in report['diagnostics']]},indent=2))


if __name__=='__main__':main()
