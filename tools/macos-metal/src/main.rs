//! Retained Metal HAL differentials, with real dispatch evidence and bounded inputs.
//! Differential evidence only; complete hybrid proofs have a separate acceptance harness.
use anyhow::{ensure, Context, Result};
use risc0_core::field::{
    baby_bear::{BabyBear, BabyBearElem as E, P},
    Elem,
};
use risc0_zkp::{
    core::digest::Digest,
    hal::{
        cpu::CpuHal,
        metal::{runtime_kernel_source, MetalHal, MetalHalPoseidon2, MetalHalSha256, MetalHash},
        metal_fold::MetalPoseidon2Fold,
        tracker, Buffer, Hal,
    },
};
use serde_json::{json, Value};
use sha2::{Digest as _, Sha256};

const GUARD: usize = 5;
const ELEMENT_EDGES: [u32; 9] = [0, 1, 2, P / 2, P - 2, P - 1, P, P + 1, u32::MAX];

fn elements(n: usize) -> Vec<E> {
    (0..n)
        .map(|i| {
            E::new(if i < ELEMENT_EDGES.len() {
                ELEMENT_EDGES[i]
            } else {
                (i as u32).wrapping_mul(1664525).wrapping_add(1013904223)
            })
        })
        .collect()
}

// CpuBuffer::to_vec also copies its full allocation at this engine pin. Read
// through the Buffer view contract so the CPU oracle does not repeat that bug.
fn read<T: Clone, B: Buffer<T>>(buffer: &B) -> Vec<T> {
    let mut result = Vec::new();
    buffer.view(|slice| result.extend_from_slice(slice));
    result
}

fn padded<T: Clone>(values: &[T], offset: usize, guard: usize, sentinel: T) -> Vec<T> {
    let mut out = vec![sentinel; offset + values.len() + guard];
    out[offset..offset + values.len()].clone_from_slice(values);
    out
}

fn dispatch_delta<M: MetalHash>(gpu: &MetalHal<M>, start: u64, expected: u64) -> Result<u64> {
    let count = gpu.completed_dispatches() - start;
    ensure!(
        count == expected,
        "expected {expected} completed GPU dispatches, got {count}"
    );
    Ok(count)
}

fn add_case<M: MetalHash>(
    gpu: &MetalHal<M>,
    cpu: &CpuHal<BabyBear>,
    n: usize,
    offsets: [usize; 3],
    guard: usize,
) -> Result<Value> {
    let [ao, bo, oo] = offsets;
    let av = elements(n);
    let mut bv = elements(n);
    bv.reverse();
    let a = padded(&av, ao, guard, E::new(73));
    let b = padded(&bv, bo, guard, E::new(89));
    let initial = vec![E::new(17); oo + n + guard];
    let mut golden = initial.clone();
    for i in 0..n {
        golden[oo + i] =
            E::new(((av[i].as_u32() as u64 + bv[i].as_u32() as u64) % P as u64) as u32);
    }
    let ca = cpu.copy_from_elem("add_a", &a);
    let cb = cpu.copy_from_elem("add_b", &b);
    let co = cpu.copy_from_elem("add_out", &initial);
    let ga = gpu.copy_from_elem("add_a", &a);
    let gb = gpu.copy_from_elem("add_b", &b);
    let go = gpu.copy_from_elem("add_out", &initial);
    let start = gpu.completed_dispatches();
    cpu.eltwise_add_elem(&co.slice(oo, n), &ca.slice(ao, n), &cb.slice(bo, n));
    gpu.eltwise_add_elem(&go.slice(oo, n), &ga.slice(ao, n), &gb.slice(bo, n));
    ensure!(
        read(&co) == golden,
        "CPU add differs from independent modular-u64 oracle"
    );
    ensure!(
        read(&go) == golden,
        "GPU add/sentinel mismatch: n={n}, offsets={offsets:?}"
    );
    ensure!(
        go.slice(oo, n).to_vec() == golden[oo..oo + n],
        "Metal sliced to_vec mismatch after add"
    );
    ensure!(
        read(&ga) == a && read(&gb) == b,
        "addition modified an input"
    );
    let dispatches = dispatch_delta(gpu, start, u64::from(n != 0))?;
    Ok(json!({"operation":"add", "elements":n, "offsets":offsets,
        "completed_dispatches":dispatches, "oracle":"CPU HAL and independent modular u64", "result":"matched"}))
}

fn copy_case<M: MetalHash>(
    gpu: &MetalHal<M>,
    cpu: &CpuHal<BabyBear>,
    n: usize,
    offsets: [usize; 2],
) -> Result<Value> {
    let [input_offset, output_offset] = offsets;
    let values = elements(n);
    let input = padded(&values, input_offset, GUARD, E::new(73));
    let initial = vec![E::new(17); output_offset + n + GUARD];
    let golden = padded(&values, output_offset, GUARD, E::new(17));
    let ci = cpu.copy_from_elem("copy_in", &input);
    let co = cpu.copy_from_elem("copy_out", &initial);
    let gi = gpu.copy_from_elem("copy_in", &input);
    let go = gpu.copy_from_elem("copy_out", &initial);
    let start = gpu.completed_dispatches();
    cpu.eltwise_copy_elem(&co.slice(output_offset, n), &ci.slice(input_offset, n));
    gpu.eltwise_copy_elem(&go.slice(output_offset, n), &gi.slice(input_offset, n));
    ensure!(
        read(&co) == golden && read(&go) == golden,
        "copy/sentinel mismatch: n={n}, offsets={offsets:?}"
    );
    ensure!(
        go.slice(output_offset, n).to_vec() == values,
        "Metal slice copy read differs from known source range"
    );
    ensure!(read(&gi) == input, "copy modified input");
    let dispatches = dispatch_delta(gpu, start, u64::from(n != 0))?;
    Ok(json!({"operation":"copy", "elements":n, "offsets":offsets,
        "completed_dispatches":dispatches, "result":"matched"}))
}

fn multiply_case<M: MetalHash>(gpu: &MetalHal<M>, n: usize, factor_value: u32) -> Result<Value> {
    let offset = 3;
    let values = elements(n);
    let initial = padded(&values, offset, GUARD, E::new(17));
    let mut golden = initial.clone();
    let factor = E::new(factor_value);
    for i in 0..n {
        let expected =
            E::new(((values[i].as_u32() as u64 * factor.as_u32() as u64) % P as u64) as u32);
        ensure!(
            values[i] * factor == expected,
            "Rust field multiplication differs from modular-u64 oracle"
        );
        golden[offset + i] = expected;
    }
    let io = gpu.copy_from_elem("multiply_io", &initial);
    let factor_buf = gpu.copy_from_elem("multiply_factor", &[factor]);
    let slice = io.slice(offset, n);
    let start = gpu.completed_dispatches();
    // The Hal trait has no multiply-by-factor operation. Invoke its retained
    // public kernel dispatch API; do not manufacture a replacement kernel.
    gpu.dispatch_by_name(
        "eltwise_mul_factor_fp",
        &[slice.as_arg(), factor_buf.as_arg()],
        n as u64,
    );
    ensure!(
        read(&io) == golden,
        "multiply/sentinel mismatch: n={n}, factor={factor_value}"
    );
    ensure!(
        slice.to_vec() == golden[offset..offset + n],
        "multiply slice read mismatch"
    );
    let dispatches = dispatch_delta(gpu, start, u64::from(n != 0))?;
    Ok(
        json!({"operation":"multiply_factor", "elements":n, "offset":offset,
        "factor_input":factor_value, "factor_reduced":factor.as_u32(), "completed_dispatches":dispatches,
        "oracle":"Rust field multiplication and independent modular u64", "result":"matched"}),
    )
}

fn empty_buffers<M: MetalHash>(gpu: &MetalHal<M>, cpu: &CpuHal<BabyBear>) -> Result<Value> {
    let start = gpu.completed_dispatches();
    let ga = gpu.alloc_elem("empty_alloc", 0);
    let gb = gpu.copy_from_elem("empty_copy", &[]);
    let go = gpu.alloc_elem("empty_out", 0);
    let ca = cpu.alloc_elem("empty_alloc", 0);
    let cb = cpu.copy_from_elem("empty_copy", &[]);
    let co = cpu.alloc_elem("empty_out", 0);
    cpu.eltwise_add_elem(&co, &ca, &cb);
    gpu.eltwise_add_elem(&go, &ga, &gb);
    cpu.eltwise_copy_elem(&co, &ca);
    gpu.eltwise_copy_elem(&go, &ga);
    ensure!(
        ga.size() == 0 && gb.size() == 0 && go.size() == 0,
        "empty logical size changed"
    );
    ensure!(
        ga.to_vec().is_empty() && gb.to_vec().is_empty() && go.to_vec().is_empty(),
        "empty allocation exposed backing storage"
    );
    ensure!(read(&co).is_empty(), "CPU empty output is not empty");
    let dispatches = dispatch_delta(gpu, start, 0)?;
    Ok(
        json!({"operation":"direct_empty_alloc_copy_add", "completed_dispatches":dispatches,
        "result":"no-op", "note":"empty work is not counted as GPU execution"}),
    )
}

fn expect_rejection(action: impl FnOnce()) -> Result<()> {
    // Expected host-contract panics must not be confused with a GPU fault.
    // This standalone acceptance binary executes these checks serially.
    let hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(action));
    std::panic::set_hook(hook);
    ensure!(
        result.is_err(),
        "invalid host-side buffer range was accepted"
    );
    Ok(())
}

fn ranges_and_reuse<M: MetalHash>(gpu: &MetalHal<M>) -> Result<Value> {
    let original = elements(16);
    let buffer = gpu.copy_from_elem("range_parent", &original);
    let slice = buffer.slice(3, 8).slice(2, 3); // Parent indices 5..8.
    ensure!(
        slice.to_vec() == original[5..8],
        "nested slice to_vec mismatch"
    );
    for i in 0..3 {
        ensure!(
            slice.get_at(i) == original[5 + i],
            "nested slice get_at mismatch"
        );
    }
    let start = gpu.completed_dispatches();
    expect_rejection(|| {
        let _ = slice.get_at(3);
    })?;
    expect_rejection(|| {
        let _ = slice.slice(4, 0);
    })?;
    expect_rejection(|| {
        let _ = slice.slice(2, 2);
    })?;
    expect_rejection(|| {
        let _ = slice.slice(usize::MAX, 1);
    })?;
    expect_rejection(|| {
        let _ = slice.as_arg_with_offset(4);
    })?;
    ensure!(
        gpu.completed_dispatches() == start,
        "invalid host ranges dispatched GPU work"
    );
    slice.view_mut(|values| values[1] = E::new(91));
    let mut golden = original.clone();
    golden[6] = E::new(91);
    ensure!(
        read(&buffer) == golden,
        "nested slice mutation touched wrong range"
    );
    let output = gpu.copy_from_elem("range_reuse", &[E::new(17); 9]);
    gpu.eltwise_copy_elem(&output.slice(2, 3), &slice);
    let mut copied = vec![E::new(17); 9];
    copied[2..5].copy_from_slice(&golden[5..8]);
    ensure!(
        read(&output) == copied,
        "valid work failed after rejected ranges"
    );
    let dispatches = dispatch_delta(gpu, start, 1)?;
    Ok(
        json!({"operation":"nested_slice_ranges_and_reuse", "rejected_host_ranges":5,
        "completed_dispatches":dispatches, "result":"matched"}),
    )
}

fn allocation_tracking<M: MetalHash>(gpu: &MetalHal<M>) -> Result<Value> {
    let before = tracker().lock().unwrap().total;
    let start = gpu.completed_dispatches();
    let buffer = gpu.alloc_elem("tracking", 64);
    let allocated = tracker().lock().unwrap().total;
    ensure!(
        allocated > before,
        "allocation did not enter memory tracker"
    );
    let clone = buffer.clone();
    let slice = buffer.slice(7, 11);
    ensure!(
        tracker().lock().unwrap().total == allocated,
        "clone/slice double-counts allocation"
    );
    drop(buffer);
    drop(clone);
    ensure!(
        tracker().lock().unwrap().total == allocated,
        "allocation released while slice still owns it"
    );
    drop(slice);
    ensure!(
        tracker().lock().unwrap().total == before,
        "last slice drop did not release tracked allocation"
    );
    let dispatches = dispatch_delta(gpu, start, 0)?;
    Ok(
        json!({"operation":"shared_allocation_lifetime", "tracked_bytes":allocated-before,
        "completed_dispatches":dispatches, "result":"matched", "note":"host ownership contract; no GPU work"}),
    )
}

fn ntt_roundtrip<M: MetalHash>(
    gpu: &MetalHal<M>,
    cpu: &CpuHal<BabyBear>,
    n: usize,
    count: usize,
) -> Result<Value> {
    let size = n * count;
    let input_offset = 1;
    let output_offset = 3;
    let values = elements(size);
    let initial = padded(&values, input_offset, GUARD, E::new(17));
    let ci = cpu.copy_from_elem("ntt_in", &initial);
    let gi = gpu.copy_from_elem("ntt_in", &initial);
    let cs = ci.slice(input_offset, size);
    let gs = gi.slice(input_offset, size);
    let start = gpu.completed_dispatches();
    cpu.batch_interpolate_ntt(&cs, count);
    gpu.batch_interpolate_ntt(&gs, count);
    ensure!(
        read(&ci) == read(&gi),
        "inverse NTT differs: n={n}, count={count}"
    );
    ensure!(
        read(&gi)[..input_offset] == initial[..input_offset]
            && read(&gi)[input_offset + size..] == initial[input_offset + size..],
        "inverse NTT changed sentinels"
    );
    let inverse_dispatches = gpu.completed_dispatches() - start;
    ensure!(
        inverse_dispatches > 0,
        "inverse NTT performed no GPU dispatch"
    );
    let output_initial = vec![E::new(19); output_offset + size + GUARD];
    let co = cpu.copy_from_elem("ntt_out", &output_initial);
    let go = gpu.copy_from_elem("ntt_out", &output_initial);
    cpu.batch_expand_into_evaluate_ntt(&co.slice(output_offset, size), &cs, count, 0);
    gpu.batch_expand_into_evaluate_ntt(&go.slice(output_offset, size), &gs, count, 0);
    let golden = padded(&values, output_offset, GUARD, E::new(19));
    ensure!(
        read(&co) == golden && read(&go) == golden,
        "NTT roundtrip/sentinel mismatch: n={n}, count={count}"
    );
    ensure!(
        go.slice(output_offset, size).to_vec() == values,
        "NTT output slice mismatch"
    );
    let dispatches = gpu.completed_dispatches() - start;
    ensure!(
        dispatches > inverse_dispatches,
        "forward NTT performed no GPU dispatch"
    );
    Ok(
        json!({"operation":"ntt_roundtrip", "row_elements":n, "polynomials":count,
        "input_offset":input_offset, "output_offset":output_offset, "completed_dispatches":dispatches,
        "inverse_dispatches":inverse_dispatches, "forward_dispatches":dispatches-inverse_dispatches,
        "result":"CPU intermediates and original input matched"}),
    )
}

fn ntt_expand<M: MetalHash>(
    gpu: &MetalHal<M>,
    cpu: &CpuHal<BabyBear>,
    n: usize,
    count: usize,
    expand_bits: usize,
) -> Result<Value> {
    let input_size = n * count;
    let output_size = input_size << expand_bits;
    let initial = padded(&elements(input_size), 2, GUARD, E::new(17));
    let output_initial = vec![E::new(19); output_size + 3 + GUARD];
    let ci = cpu.copy_from_elem("expand_in", &initial);
    let gi = gpu.copy_from_elem("expand_in", &initial);
    let co = cpu.copy_from_elem("expand_out", &output_initial);
    let go = gpu.copy_from_elem("expand_out", &output_initial);
    let start = gpu.completed_dispatches();
    cpu.batch_expand_into_evaluate_ntt(
        &co.slice(3, output_size),
        &ci.slice(2, input_size),
        count,
        expand_bits,
    );
    gpu.batch_expand_into_evaluate_ntt(
        &go.slice(3, output_size),
        &gi.slice(2, input_size),
        count,
        expand_bits,
    );
    let golden = read(&co);
    ensure!(
        read(&go) == golden,
        "expanded NTT mismatch: n={n}, count={count}, expand_bits={expand_bits}"
    );
    ensure!(
        golden[..3] == output_initial[..3]
            && golden[3 + output_size..] == output_initial[3 + output_size..],
        "expanded NTT changed sentinels"
    );
    ensure!(
        read(&gi) == initial && read(&ci) == initial,
        "expanded NTT modified coefficients"
    );
    ensure!(
        go.slice(3, output_size).to_vec() == golden[3..3 + output_size],
        "expanded NTT slice mismatch"
    );
    let dispatches = gpu.completed_dispatches() - start;
    ensure!(dispatches > 0, "expanded NTT performed no GPU dispatch");
    Ok(
        json!({"operation":"expanded_ntt", "row_elements":n, "polynomials":count,
        "expand_bits":expand_bits, "completed_dispatches":dispatches, "result":"matched"}),
    )
}

fn hash_rows<M: MetalHash>(
    gpu: &MetalHal<M>,
    cpu: &CpuHal<BabyBear>,
    suite: &str,
    rows: usize,
    columns: usize,
) -> Result<Value> {
    let values = elements(rows * columns);
    let input = padded(&values, 2, GUARD, E::new(73));
    let sentinel = Digest::from([E::new(17).as_u32_montgomery(); 8]);
    let initial = vec![sentinel; rows + 3 + GUARD];
    let ci = cpu.copy_from_elem("hash_matrix", &input);
    let gi = gpu.copy_from_elem("hash_matrix", &input);
    let co = cpu.copy_from_digest("hash_rows", &initial);
    let go = gpu.copy_from_digest("hash_rows", &initial);
    let start = gpu.completed_dispatches();
    cpu.hash_rows(&co.slice(3, rows), &ci.slice(2, values.len()));
    gpu.hash_rows(&go.slice(3, rows), &gi.slice(2, values.len()));
    let mut golden = initial.clone();
    for row in 0..rows {
        let column: Vec<E> = (0..columns).map(|col| values[col * rows + row]).collect();
        golden[3 + row] = *cpu.get_hash_suite().hashfn.hash_elem_slice(&column);
    }
    ensure!(
        read(&co) == golden && read(&go) == golden,
        "{suite} hash rows/sentinel mismatch: rows={rows}, columns={columns}"
    );
    ensure!(
        go.slice(3, rows).to_vec() == golden[3..3 + rows],
        "{suite} hash rows slice mismatch"
    );
    ensure!(read(&gi) == input, "hash rows modified input");
    let dispatches = dispatch_delta(gpu, start, 1)?;
    Ok(
        json!({"operation":"hash_rows", "suite":suite, "rows":rows, "columns":columns,
        "matrix_layout":"column-major", "input_offset":2, "output_offset":3,
        "completed_dispatches":dispatches, "result":"matched"}),
    )
}

fn hash_fold<M: MetalHash>(
    gpu: &MetalHal<M>,
    cpu: &CpuHal<BabyBear>,
    suite: &str,
    outputs: usize,
    offset: usize,
) -> Result<Value> {
    let inputs = 2 * outputs;
    let size = 2 * inputs;
    let sentinel = Digest::from([E::new(17).as_u32_montgomery(); 8]);
    let mut initial = vec![sentinel; offset + size + GUARD];
    // Leaves are genuine hashes from the matching CPU suite; Poseidon digests
    // must contain reduced Montgomery field words, not arbitrary SHA digests.
    for i in 0..inputs {
        let values = [
            E::new(i as u32),
            E::new(P - 1),
            E::new((i * 37 + 11) as u32),
        ];
        initial[offset + inputs + i] = *cpu.get_hash_suite().hashfn.hash_elem_slice(&values);
    }
    let mut golden = initial.clone();
    for i in 0..outputs {
        golden[offset + outputs + i] = *cpu.get_hash_suite().hashfn.hash_pair(
            &initial[offset + inputs + 2 * i],
            &initial[offset + inputs + 2 * i + 1],
        );
    }
    let ci = cpu.copy_from_digest("fold_tree", &initial);
    let gi = gpu.copy_from_digest("fold_tree", &initial);
    let start = gpu.completed_dispatches();
    cpu.hash_fold(&ci.slice(offset, size), inputs, outputs);
    gpu.hash_fold(&gi.slice(offset, size), inputs, outputs);
    ensure!(
        read(&ci) == golden && read(&gi) == golden,
        "{suite} hash fold/tree/sentinel mismatch: outputs={outputs}, offset={offset}"
    );
    ensure!(
        gi.slice(offset + outputs, outputs).to_vec()
            == golden[offset + outputs..offset + 2 * outputs],
        "{suite} fold output slice mismatch"
    );
    let dispatches = dispatch_delta(gpu, start, 1)?;
    Ok(
        json!({"operation":"hash_fold", "suite":suite, "inputs":inputs, "outputs":outputs,
        "buffer_offset":offset, "completed_dispatches":dispatches, "result":"matched"}),
    )
}

fn hash_cases<M: MetalHash>(
    gpu: &MetalHal<M>,
    cpu: &CpuHal<BabyBear>,
    suite: &str,
    cases: &mut Vec<Value>,
) -> Result<()> {
    for rows in [1, 3, 33] {
        for columns in [0, 1, 15, 16, 17, 31, 32, 33] {
            cases.push(hash_rows(gpu, cpu, suite, rows, columns)?);
        }
    }
    for outputs in [1, 2, 3, 16, 33] {
        for offset in [0, 3] {
            cases.push(hash_fold(gpu, cpu, suite, outputs, offset)?);
        }
    }
    Ok(())
}

fn run_sha_cases(
    gpu: &MetalHalSha256,
    cpu: &CpuHal<BabyBear>,
    mode: &str,
    cases: &mut Vec<Value>,
) -> Result<()> {
    if mode == "basic" {
        cases.push(add_case(gpu, cpu, 257, [0, 0, 0], 0)?);
    }
    if mode == "boundaries" || mode == "all" {
        cases.push(empty_buffers(gpu, cpu)?);
        cases.push(ranges_and_reuse(gpu)?);
        cases.push(allocation_tracking(gpu)?);
        for n in [
            0, 1, 2, 7, 31, 32, 33, 255, 256, 257, 1023, 1024, 1025, 4096,
        ] {
            for offsets in [[0, 0, 0], [1, 3, 2], [7, 2, 5]] {
                cases.push(add_case(gpu, cpu, n, offsets, GUARD)?);
                cases.push(copy_case(gpu, cpu, n, [offsets[0], offsets[2]])?);
            }
        }
    }
    if mode == "arithmetic" || mode == "all" {
        cases.push(add_case(gpu, cpu, ELEMENT_EDGES.len(), [1, 3, 2], GUARD)?);
        for n in [1, 33, 257, 1025] {
            for factor in ELEMENT_EDGES {
                cases.push(multiply_case(gpu, n, factor)?);
            }
        }
    }
    if mode == "ntt" || mode == "all" {
        for n in [1, 2, 4, 16, 128, 256, 1024] {
            for count in [1, 3] {
                cases.push(ntt_roundtrip(gpu, cpu, n, count)?);
            }
        }
        for n in [1, 2, 16, 128] {
            for count in [1, 3] {
                for expand_bits in [1, 2] {
                    cases.push(ntt_expand(gpu, cpu, n, count, expand_bits)?);
                }
            }
        }
    }
    if mode == "sha256" || mode == "all" {
        hash_cases(gpu, cpu, "sha256", cases)?;
    }
    Ok(())
}

fn hybrid_fold_case(
    hybrid: &CpuHal<BabyBear, MetalPoseidon2Fold>,
    cpu: &CpuHal<BabyBear>,
    outputs: usize,
    offset: usize,
    full_tree: bool,
) -> Result<Value> {
    let tracked_before = tracker().lock().unwrap().total;
    let inputs = outputs * 2;
    let sentinel = Digest::from([E::new(17).as_u32_montgomery(); 8]);
    let mut initial = vec![sentinel; offset + 4 * outputs + GUARD];
    for i in 0..inputs {
        // Every word is a valid reduced Montgomery field value.
        initial[offset + inputs + i] = Digest::from(std::array::from_fn(|j| {
            E::new((i as u32).wrapping_mul(37).wrapping_add(j as u32 * 73)).as_u32_montgomery()
        }));
    }
    let expected = cpu.copy_from_digest("hybrid_expected", &initial);
    let actual = hybrid.copy_from_digest("hybrid_actual", &initial);
    let before = hybrid.metal_stats().context("hybrid stats absent")?;
    let mut count = outputs;
    let mut expected_dispatches = 0;
    let chunk_outputs = before.staging_limit_bytes / (4 * std::mem::size_of::<Digest>());
    loop {
        cpu.hash_fold(&expected.slice(offset, outputs * 4), count * 2, count);
        hybrid.hash_fold(&actual.slice(offset, outputs * 4), count * 2, count);
        ensure!(
            read(&actual) == read(&expected),
            "hybrid fold differs or changed sentinel: outputs={outputs}, layer={count}"
        );
        expected_dispatches += count.div_ceil(chunk_outputs) as u64;
        if !full_tree || count == 1 {
            break;
        }
        count /= 2;
    }
    let after = hybrid.metal_stats().context("hybrid stats absent")?;
    let completed = after.completed_dispatches - before.completed_dispatches;
    ensure!(
        completed == expected_dispatches && completed > 0,
        "hybrid dispatch accounting mismatch"
    );
    ensure!(
        after.peak_staging_bytes <= after.staging_limit_bytes,
        "hybrid exceeded staging budget"
    );
    ensure!(
        after.input_digests - before.input_digests
            == 2 * (after.output_digests - before.output_digests),
        "hybrid work accounting mismatch"
    );
    drop(expected);
    drop(actual);
    ensure!(
        tracker().lock().unwrap().total == tracked_before,
        "hybrid staging allocation was retained"
    );
    Ok(
        json!({"operation":"hybrid_poseidon2_fold", "outputs":outputs, "buffer_offset":offset,
        "full_tree":full_tree, "completed_dispatches":completed,
        "fold_calls":after.fold_calls-before.fold_calls,
        "output_digests":after.output_digests-before.output_digests,
        "input_digests":after.input_digests-before.input_digests,
        "peak_staging_bytes":after.peak_staging_bytes,"staging_limit_bytes":after.staging_limit_bytes,
        "result":"matched"}),
    )
}

fn main() -> Result<()> {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<CpuHal<BabyBear>>();
    for key in [
        "RISC0_DEV_MODE",
        "RISC0_SKIP_BUILD",
        "RISC0_SKIP_BUILD_KERNELS",
    ] {
        ensure!(std::env::var_os(key).is_none(), "unset {key}");
    }
    let mode = std::env::args().nth(1).unwrap_or_else(|| "basic".into());
    ensure!(
        [
            "basic",
            "boundaries",
            "arithmetic",
            "ntt",
            "sha256",
            "poseidon2",
            "hybrid-fold",
            "all"
        ]
        .contains(&mode.as_str()),
        "expected basic, boundaries, arithmetic, ntt, sha256, poseidon2, hybrid-fold, or all"
    );
    let gpu = MetalHalSha256::new();
    let cpu = CpuHal::new(gpu.get_hash_suite().clone());
    let poseidon = if mode == "poseidon2" || mode == "all" {
        Some(MetalHalPoseidon2::new())
    } else {
        None
    };
    let hybrid = if mode == "hybrid-fold" || mode == "all" {
        Some(CpuHal::<BabyBear, _>::with_hash_fold(
            risc0_zkp::core::hash::poseidon2::Poseidon2HashSuite::new_suite(),
            MetalPoseidon2Fold::new(512 * 1024)?,
        ))
    } else {
        None
    };
    let hybrid_small = if hybrid.is_some() {
        ensure!(
            MetalPoseidon2Fold::new(4095).is_err(),
            "too-small budget was accepted"
        );
        ensure!(
            MetalPoseidon2Fold::new(16 * 1024 * 1024 + 1).is_err(),
            "too-large budget was accepted"
        );
        Some(CpuHal::<BabyBear, _>::with_hash_fold(
            risc0_zkp::core::hash::poseidon2::Poseidon2HashSuite::new_suite(),
            MetalPoseidon2Fold::new(4096)?,
        ))
    } else {
        None
    };
    let mut cases = Vec::new();
    let outcome = (|| -> Result<()> {
        run_sha_cases(&gpu, &cpu, &mode, &mut cases).context("SHA/arithmetic HAL differential")?;
        if let Some(ref poseidon) = poseidon {
            let cpu = CpuHal::new(poseidon.get_hash_suite().clone());
            hash_cases(poseidon, &cpu, "poseidon2", &mut cases)
                .context("Poseidon2 HAL differential")?;
        }
        if let Some(ref hybrid) = hybrid {
            let cpu = CpuHal::new(hybrid.get_hash_suite().clone());
            for outputs in [1, 31, 32, 33, 4095, 4096, 4097, 65537] {
                cases.push(hybrid_fold_case(hybrid, &cpu, outputs, 13, false)?);
            }
            cases.push(hybrid_fold_case(hybrid, &cpu, 8192, 13, true)?);
        }
        if let Some(ref hybrid) = hybrid_small {
            let cpu = CpuHal::new(hybrid.get_hash_suite().clone());
            for outputs in [31, 32, 33, 65] {
                cases.push(hybrid_fold_case(hybrid, &cpu, outputs, 3, false)?);
            }
        }
        ensure!(!cases.is_empty(), "no differential cases executed");
        Ok(())
    })();
    let completed = gpu.completed_dispatches()
        + poseidon.as_ref().map_or(0, |p| p.completed_dispatches())
        + hybrid
            .as_ref()
            .map_or(0, |h| h.metal_stats().unwrap().completed_dispatches)
        + hybrid_small
            .as_ref()
            .map_or(0, |h| h.metal_stats().unwrap().completed_dispatches);
    let accounted: u64 = cases
        .iter()
        .map(|c| c["completed_dispatches"].as_u64().unwrap())
        .sum();
    let error = outcome.as_ref().err().map(|error| format!("{error:#}"));
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "mode":mode, "status":if outcome.is_ok() { "passed" } else { "failed" }, "error":error,
            "device":gpu.device.name(), "compiler":"runtime source",
            "kernel_source_sha256":hex::encode(Sha256::digest(runtime_kernel_source().as_bytes())),
            "completed_dispatches":completed, "successful_case_dispatches":accounted,
            "case_count":cases.len(), "cases":cases,
            "proof_acceleration":"differential-only; see separate hybrid proof evidence", "verification":"CPU/Metal primitive equality only",
            "limits":"at most 4096 arithmetic elements; hybrid fold uses <=512KiB staging and <=65537 outputs; no invalid GPU accesses"
        }))?
    );
    outcome?;
    ensure!(
        completed > 0 && completed == accounted,
        "GPU dispatch accounting mismatch"
    );
    Ok(())
}
