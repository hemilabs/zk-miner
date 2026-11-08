//! Isolated evaluator feasibility gate. This never produces or submits a proof.
use anyhow::{bail, ensure, Context, Result};
use metal::CompileOptions;
use objc::{msg_send, sel, sel_impl};
use rayon::prelude::*;
use risc0_circuit_rv32im_sys::risc0_circuit_rv32im_cpu_poly_fp;
use risc0_core::field::{
    baby_bear::{BabyBearElem as E, BabyBearExtElem as X, P},
    map_pow, Elem, ExtElem, RootsOfUnity,
};
use risc0_zkp::hal::{
    metal::{BufferImpl, KernelArg, MetalHalPoseidon2},
    Buffer, Hal,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

const GUARD: usize = 7;
const SENTINEL: E = E::new(42);
const GIB: u64 = 1024 * 1024 * 1024;

unsafe extern "C" {
    fn mach_port_deallocate(
        task: libc::mach_port_t,
        name: libc::mach_port_t,
    ) -> libc::kern_return_t;
}

fn memory() -> Result<Value> {
    let mut r = std::mem::MaybeUninit::<libc::rusage_info_v4>::uninit();
    ensure!(
        unsafe {
            libc::proc_pid_rusage(
                std::process::id() as i32,
                libc::RUSAGE_INFO_V4,
                r.as_mut_ptr().cast(),
            )
        } == 0,
        "physical footprint unavailable"
    );
    let r = unsafe { r.assume_init() };
    let mut pressure = 0u32;
    let mut len = std::mem::size_of_val(&pressure);
    ensure!(
        unsafe {
            libc::sysctlbyname(
                c"kern.memorystatus_vm_pressure_level".as_ptr(),
                (&mut pressure as *mut u32).cast(),
                &mut len,
                std::ptr::null_mut(),
                0,
            )
        } == 0
            && len == 4,
        "memory pressure unavailable"
    );
    let mut vm = std::mem::MaybeUninit::<libc::vm_statistics64>::uninit();
    let mut count = libc::HOST_VM_INFO64_COUNT;
    let host = unsafe { libc::mach_host_self() };
    let status = unsafe {
        libc::host_statistics64(
            host,
            libc::HOST_VM_INFO64,
            vm.as_mut_ptr().cast(),
            &mut count,
        )
    };
    unsafe {
        mach_port_deallocate(libc::mach_task_self(), host);
    }
    ensure!(
        status == libc::KERN_SUCCESS && count == libc::HOST_VM_INFO64_COUNT,
        "free memory unavailable"
    );
    let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    ensure!(page > 0, "invalid page size");
    let vm = unsafe { vm.assume_init() };
    let available = (vm.free_count as u64
        + vm.external_page_count.min(vm.inactive_count) as u64 / 2)
        * page as u64;
    ensure!(
        r.ri_phys_footprint <= 32 * GIB && available >= 8 * GIB && [1, 2].contains(&pressure),
        "resource guard: footprint={}, available={available}, pressure={pressure}",
        r.ri_phys_footprint
    );
    Ok(json!({"physical_footprint_bytes":r.ri_phys_footprint,
        "lifetime_peak_physical_footprint_bytes":r.ri_lifetime_max_phys_footprint,
        "rss_bytes":r.ri_resident_size,"available_estimate_bytes":available,"pressure_level":pressure}))
}

struct Guard {
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}
impl Guard {
    fn new() -> Result<Self> {
        ensure!(
            memory()?["available_estimate_bytes"].as_u64().unwrap() >= 32 * GIB,
            "prototype admission requires 16 GiB budget plus 16 GiB host reserve"
        );
        let stop = Arc::new(AtomicBool::new(false));
        let cancel = stop.clone();
        let thread = std::thread::spawn(move || {
            while !cancel.load(Ordering::Acquire) {
                if let Err(error) = memory() {
                    eprintln!("{error:#}");
                    std::process::exit(2);
                }
                std::thread::sleep(Duration::from_millis(500));
            }
        });
        Ok(Self {
            stop,
            thread: Some(thread),
        })
    }
}
impl Drop for Guard {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn emit(phase: &str, value: Value) -> Result<()> {
    println!("{}", json!({"phase":phase,"data":value,"memory":memory()?}));
    Ok(())
}

fn sample(i: usize, seed: u32) -> E {
    let edges = [0, 1, 2, P / 2, P - 2, P - 1, P, P + 1, u32::MAX];
    if i < edges.len() {
        return E::new(edges[(i + seed as usize) % edges.len()]);
    }
    // Stateless deterministic scrambling includes index high bits at full size.
    let mut x = (i as u64)
        .wrapping_add((seed as u64) << 32)
        .wrapping_add(0x9e3779b97f4a7c15);
    x = (x ^ (x >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94d049bb133111eb);
    E::new((x ^ (x >> 31)) as u32)
}

fn pow_mod(mut value: u64, mut exponent: usize) -> u64 {
    let mut result = 1;
    while exponent != 0 {
        if exponent & 1 != 0 {
            result = result * value % P as u64;
        }
        value = value * value % P as u64;
        exponent >>= 1;
    }
    result
}

fn storage(gpu: &MetalHalPoseidon2, name: &'static str, n: usize) -> BufferImpl<E> {
    let buffer = gpu.alloc_elem(name, n + 2 * GUARD);
    buffer.view_mut(|v| v.fill(SENTINEL));
    buffer
}

fn hash(buffer: &BufferImpl<E>) -> String {
    let mut h = Sha256::new();
    buffer.view(|v| {
        // BabyBearElem is repr(transparent) u32; hash its exact mapped bytes.
        let bytes = unsafe {
            std::slice::from_raw_parts(v.as_ptr().cast::<u8>(), std::mem::size_of_val(v))
        };
        h.update(bytes);
    });
    hex::encode(h.finalize())
}

// Preserve command-error text during feasibility work. Reuse the HAL's buffers,
// queue and synchronous completion; count only successfully completed commands.
fn dispatch(
    gpu: &MetalHalPoseidon2,
    pipeline: &metal::ComputePipelineState,
    args: &[KernelArg<'_>],
    count: usize,
) -> Result<Value> {
    metal::objc::rc::autoreleasepool(|| -> Result<Value> {
        let command = gpu.cmd_queue.new_command_buffer();
        let encoder = command.new_compute_command_encoder();
        encoder.set_compute_pipeline_state(pipeline);
        for (index, arg) in args.iter().enumerate() {
            match arg {
                KernelArg::Buffer { buffer, offset } => {
                    encoder.set_buffer(index as u64, Some(buffer), *offset)
                }
                KernelArg::Integer(value) => {
                    encoder.set_bytes(index as u64, 4, (value as *const u32).cast())
                }
                KernelArg::Null => encoder.set_buffer(index as u64, None, 0),
            }
        }
        let threads: u64 = std::env::var("RV32IM_METAL_THREADS")
            .unwrap_or("32".into())
            .parse()?;
        ensure!(
            threads > 0 && threads <= pipeline.max_total_threads_per_threadgroup(),
            "invalid threadgroup size"
        );
        encoder.dispatch_threads(
            metal::MTLSize::new(count as u64, 1, 1),
            metal::MTLSize::new(threads, 1, 1),
        );
        encoder.end_encoding();
        command.commit();
        command.wait_until_completed();
        if command.status() != metal::MTLCommandBufferStatus::Completed {
            let error: *mut objc::runtime::Object = unsafe { msg_send![command, error] };
            if !error.is_null() {
                let code: i64 = unsafe { msg_send![error, code] };
                let description: *mut objc::runtime::Object =
                    unsafe { msg_send![error, localizedDescription] };
                let chars: *const std::ffi::c_char = unsafe { msg_send![description, UTF8String] };
                let text = if chars.is_null() {
                    String::new()
                } else {
                    unsafe {
                        std::ffi::CStr::from_ptr(chars)
                            .to_string_lossy()
                            .into_owned()
                    }
                };
                bail!("Metal command failed: code={code}, {text}");
            }
            bail!("Metal command failed: {:?}", command.status());
        }
        let gpu_start: f64 = unsafe { msg_send![command, GPUStartTime] };
        let gpu_end: f64 = unsafe { msg_send![command, GPUEndTime] };
        ensure!(
            gpu_start > 0.0 && gpu_end > gpu_start,
            "Metal GPU timestamps unavailable"
        );
        Ok(
            json!({"status":"Completed","threads_per_threadgroup":threads,
            "gpu_seconds":gpu_end - gpu_start}),
        )
    })
}

fn run_case(
    gpu: &MetalHalPoseidon2,
    kernels: &[metal::ComputePipelineState],
    po2: usize,
    seed: u32,
    exponents: &[usize],
    timing_only: bool,
    phase_split: bool,
) -> Result<Value> {
    let start = Instant::now();
    let domain = (1usize << po2) * 4;
    let ds = storage(gpu, "rv32im_data", domain * 211);
    let acs = storage(gpu, "rv32im_accum", domain * 103);
    let os = storage(gpu, "rv32im_out", 90);
    let ms = storage(gpu, "rv32im_mix", 36);
    let cs = storage(gpu, "rv32im_check", domain * 4);
    let data = ds.slice(GUARD, domain * 211);
    let accum = acs.slice(GUARD, domain * 103);
    let out = os.slice(GUARD, 90);
    let mix = ms.slice(GUARD, 36);
    let check = cs.slice(GUARD, domain * 4);
    for (i, buffer) in [&data, &accum, &out, &mix].iter().enumerate() {
        buffer.view_mut(|v| {
            v.par_iter_mut()
                .enumerate()
                .for_each(|(j, e)| *e = sample(j, seed + i as u32 * 7919))
        });
    }
    let before = [&ds, &acs, &os, &ms].map(hash);
    let poly_mix = X::from_subelems((0..4).map(|i| sample(i + 100, seed + 17)));
    let powers = map_pow(poly_mix, exponents);
    let power_buf = gpu.copy_from_extelem("rv32im_poly_mix", &powers);
    let rou = E::ROU_FWD[po2 + 2];
    let normalization: Vec<_> = (0..4)
        .map(|cycle| {
            let x = rou.pow(cycle);
            ((E::new(3) * x).pow(1usize << po2) - E::ONE).inv()
        })
        .collect();
    ensure!(
        pow_mod(rou.as_u32() as u64, domain) == 1 && pow_mod(rou.as_u32() as u64, domain / 2) != 1,
        "incorrect domain root"
    );
    for (cycle, factor) in normalization.iter().enumerate() {
        let x = pow_mod(rou.as_u32() as u64, cycle);
        let y = pow_mod(3 * x % P as u64, 1usize << po2);
        let inverse = pow_mod((y + P as u64 - 1) % P as u64, (P - 2) as usize);
        ensure!(
            factor.as_u32() as u64 == inverse,
            "normalization differs from modular-u64 oracle"
        );
    }
    let normalization_buffer = gpu.copy_from_elem("rv32im_normalization", &normalization);
    let table = phase_split.then(|| gpu.alloc_extelem("rv32im_evalfast_table", 627));
    let scratch = phase_split.then(|| storage(gpu, "rv32im_evalfast_scratch", domain * 4));
    let scratch_slice = scratch
        .as_ref()
        .map(|buffer| buffer.slice(GUARD, domain * 4));
    emit(
        "inputs_ready",
        json!({"po2":po2,"seed":seed,"domain":domain,"setup_seconds":start.elapsed().as_secs_f64()}),
    )?;
    let gpu_start = Instant::now();
    // CODE is not read by this circuit's polynomial; pass a valid small buffer.
    let arguments = &[
        check.as_arg(),
        out.as_arg(),
        data.as_arg(),
        accum.as_arg(),
        mix.as_arg(),
        out.as_arg(),
        power_buf.as_arg(),
        normalization_buffer.as_arg(),
        KernelArg::Integer(po2 as u32),
        KernelArg::Integer(domain as u32),
    ];
    let execute = || -> Result<Value> {
        if phase_split {
            let table = table.as_ref().unwrap();
            let scratch = scratch_slice.as_ref().unwrap();
            let prep = dispatch(
                gpu,
                &kernels[0],
                &[
                    power_buf.as_arg(),
                    out.as_arg(),
                    mix.as_arg(),
                    table.as_arg(),
                ],
                1,
            )?;
            let split = dispatch(
                gpu,
                &kernels[1],
                &[
                    check.as_arg(),
                    data.as_arg(),
                    accum.as_arg(),
                    mix.as_arg(),
                    out.as_arg(),
                    table.as_arg(),
                    scratch.as_arg(),
                    KernelArg::Integer(domain as u32),
                ],
                2 * domain,
            )?;
            let combine = dispatch(
                gpu,
                &kernels[2],
                &[
                    check.as_arg(),
                    scratch.as_arg(),
                    normalization_buffer.as_arg(),
                    KernelArg::Integer(domain as u32),
                ],
                domain,
            )?;
            return Ok(json!({"status":"Completed","gpu_seconds":
                prep["gpu_seconds"].as_f64().unwrap() + split["gpu_seconds"].as_f64().unwrap()
                + combine["gpu_seconds"].as_f64().unwrap(),
                "prep":prep,"split":split,"combine":combine}));
        }
        dispatch(gpu, &kernels[0], arguments, domain)
    };
    let command = execute()?;
    let gpu_seconds = gpu_start.elapsed().as_secs_f64();
    emit(
        "gpu_complete",
        json!({"po2":po2,"seed":seed,"gpu_seconds":gpu_seconds}),
    )?;
    if timing_only {
        let first_output_sha256 = hash(&check);
        check.view_mut(|values| values.fill(SENTINEL));
        let reuse_started = Instant::now();
        let reuse_command = execute()?;
        let reuse_seconds = reuse_started.elapsed().as_secs_f64();
        ensure!(
            hash(&check) == first_output_sha256,
            "timing-only dispatch was not deterministic"
        );
        ensure!(
            [&ds, &acs, &os, &ms].map(hash) == before,
            "evaluator modified input storage"
        );
        cs.view(|v| {
            assert!(v[..GUARD]
                .iter()
                .chain(&v[v.len() - GUARD..])
                .all(|e| *e == SENTINEL))
        });
        let result = json!({"po2":po2,"domain":domain,"seed":seed,
            "gpu_dispatch_seconds":gpu_seconds,"reuse_dispatch_seconds":reuse_seconds,
            "first_output_sha256":first_output_sha256,"output_sha256":hash(&check),
            "completed_dispatches":2,"reuse_command":reuse_command,
            "reuse_deterministic":true,"cpu_oracle_checked":false,"proof_eligible":false,
            "guards_preserved":true,"inputs_unchanged":true,"command":command,
            "case_seconds":start.elapsed().as_secs_f64(),"memory":memory()?,
            "status":"timing_only"});
        emit("case_complete", result.clone())?;
        return Ok(result);
    }
    let mut expected = vec![X::ZERO; domain];
    // Synchronous Metal completion precedes these shared immutable CPU reads.
    let slice =
        |b: &BufferImpl<E>| unsafe { std::slice::from_raw_parts(b.as_ptr().cast::<E>(), b.size()) };
    let (d, a, o, m) = (slice(&data), slice(&accum), slice(&out), slice(&mix));
    let cpu_start = Instant::now();
    expected
        .par_iter_mut()
        .enumerate()
        .try_for_each(|(cycle, dest)| -> Result<()> {
            let args = [a.as_ptr(), d.as_ptr(), o.as_ptr(), m.as_ptr()];
            let err = unsafe {
                risc0_circuit_rv32im_cpu_poly_fp(
                    cycle,
                    domain,
                    powers.as_ptr(),
                    args.as_ptr(),
                    dest,
                )
            };
            if !err.is_null() {
                let text = unsafe { std::ffi::CStr::from_ptr(err).to_string_lossy().into_owned() };
                unsafe {
                    libc::free(err.cast_mut().cast());
                }
                bail!("CPU polynomial failed: {text}");
            }
            let x = rou.pow(cycle);
            let y = (E::new(3) * x).pow(1usize << po2);
            *dest *= (y - E::ONE).inv();
            Ok(())
        })?;
    let cpu_seconds = cpu_start.elapsed().as_secs_f64();
    let compare = || -> Result<()> {
        let actual = slice(&check);
        expected
            .par_iter()
            .enumerate()
            .try_for_each(|(cycle, expected)| -> Result<()> {
                for i in 0..4 {
                    ensure!(actual[i * domain + cycle] == expected.elems()[i],
            "CPU/Metal mismatch po2={po2} seed={seed} cycle={cycle} component={i}: {:?} != {:?}",
            actual[i * domain + cycle], expected.elems()[i]);
                }
                Ok(())
            })
    };
    if let Err(error) = compare() {
        let actual = slice(&check);
        let mut mismatches = 0usize;
        let mut examples = Vec::new();
        for (cycle, expected) in expected.iter().enumerate() {
            if (0..4).any(|i| actual[i * domain + cycle] != expected.elems()[i]) {
                mismatches += 1;
                if examples.len() < 12 {
                    let got = X::from_subelems((0..4).map(|i| actual[i * domain + cycle]));
                    let ratio = got * expected.inv();
                    examples.push(json!({"cycle":cycle,"actual":got.elems().iter().map(E::as_u32).collect::<Vec<_>>(),
                        "expected":expected.elems().iter().map(E::as_u32).collect::<Vec<_>>(),
                        "ratio":ratio.elems().iter().map(E::as_u32).collect::<Vec<_>>()}));
                }
            }
        }
        emit(
            "comparison_failed",
            json!({"mismatched_cycles":mismatches,"domain":domain,"examples":examples}),
        )?;
        return Err(error);
    }
    check.view_mut(|values| values.fill(SENTINEL));
    let reuse_started = Instant::now();
    let reuse_command = execute()?;
    let reuse_seconds = reuse_started.elapsed().as_secs_f64();
    compare()?;
    ensure!(
        [&ds, &acs, &os, &ms].map(hash) == before,
        "evaluator modified input storage"
    );
    cs.view(|v| {
        assert!(v[..GUARD]
            .iter()
            .chain(&v[v.len() - GUARD..])
            .all(|e| *e == SENTINEL))
    });
    let result = json!({"po2":po2,"domain":domain,"seed":seed,"compared_field_elements":domain * 4,
        "gpu_dispatch_seconds":gpu_seconds,"cpu_evaluation_seconds":cpu_seconds,
        "isolated_evaluation_ratio_cpu_over_gpu":cpu_seconds/gpu_seconds,
        "input_hashes":before,"output_sha256":hash(&check),"completed_dispatches":2,
        "reuse_dispatch_seconds":reuse_seconds,"reuse_command":reuse_command,"reuse_matched":true,
        "normalization":normalization.iter().map(E::as_u32).collect::<Vec<_>>(),
        "offset_elements":GUARD,"guards_preserved":true,"inputs_unchanged":true,"command":command,
        "case_seconds":start.elapsed().as_secs_f64(),"memory":memory()?,"status":"matched"});
    emit("case_complete", result.clone())?;
    Ok(result)
}

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    ensure!(
        args.len() >= 3,
        "usage: prototype SHADER [compile|PO2[,PO2...]] [SEED]"
    );
    let source = std::fs::read_to_string(&args[1])?;
    let metadata: Value = serde_json::from_slice(&std::fs::read(
        std::path::Path::new(&args[1]).with_extension("json"),
    )?)?;
    let timing_only = metadata["timing_only"].as_bool().unwrap_or(false);
    let phase_split = metadata["phase_split"].as_bool().unwrap_or(false);
    ensure!(
        !timing_only || std::env::var("RV32IM_TIMING_ONLY").as_deref() == Ok("1"),
        "timing-only shader requires explicit RV32IM_TIMING_ONLY=1"
    );
    let exponents: Vec<usize> = serde_json::from_value(metadata["poly_mix_exponents"].clone())?;
    ensure!(exponents.len() == 458, "invalid pinned mixing powers");
    let _guard = Guard::new()?;
    metal::objc::rc::autoreleasepool(|| -> Result<()> {
        let start = Instant::now();
        let gpu = MetalHalPoseidon2::new();
        ensure!(
            gpu.device.has_unified_memory(),
            "shared-memory prototype requires unified memory"
        );
        emit(
            "device",
            json!({"name":gpu.device.name(),"max_buffer_bytes":gpu.device.max_buffer_length(),
            "hal_init_seconds":start.elapsed().as_secs_f64(),"source_sha256":hex::encode(Sha256::digest(source.as_bytes()))}),
        )?;
        let options = CompileOptions::new();
        options.set_fast_math_enabled(false);
        let start = Instant::now();
        let library = gpu
            .device
            .new_library_with_source(&source, &options)
            .map_err(|e| anyhow::anyhow!("RV32IM MSL compilation: {e}"))?;
        let library_seconds = start.elapsed().as_secs_f64();
        let entries: Vec<&str> = if phase_split {
            vec!["ef_prep", "ef_eval_split", "ef_combine"]
        } else {
            vec![metadata["entry_point"].as_str().unwrap_or("eval_check")]
        };
        let mut pipelines = Vec::new();
        for entry in entries {
            let function = library
                .get_function(entry, None)
                .map_err(|e| anyhow::anyhow!(e))?;
            let start = Instant::now();
            let pipeline = gpu
                .device
                .new_compute_pipeline_state_with_function(&function)
                .map_err(|e| anyhow::anyhow!(e))?;
            emit(
                "compiled",
                json!({"entry_point":entry,"library_seconds":library_seconds,
            "pipeline_seconds":start.elapsed().as_secs_f64(),
            "max_threads_per_threadgroup":pipeline.max_total_threads_per_threadgroup(),
            "thread_execution_width":pipeline.thread_execution_width(),
            "static_threadgroup_bytes":pipeline.static_threadgroup_memory_length()}),
            )?;
            pipelines.push(pipeline);
        }
        let mut cases = Vec::new();
        if args[2] != "compile" {
            let seed: u32 = args.get(3).map(String::as_str).unwrap_or("1").parse()?;
            for value in args[2].split(',') {
                let po2: usize = value.parse().context("invalid po2")?;
                ensure!((4..=20).contains(&po2), "po2 must be 4..20");
                ensure!(
                    !cases
                        .iter()
                        .any(|case: &Value| case["po2"].as_u64() == Some(po2 as u64)),
                    "duplicate po2"
                );
                cases.push(run_case(
                    &gpu,
                    &pipelines,
                    po2,
                    seed,
                    &exponents,
                    timing_only,
                    phase_split,
                )?);
            }
        }
        emit(
            "result",
            json!({"status":if timing_only { "timing_only" } else { "passed" },
            "completed_dispatches":cases.iter().map(|c| c["completed_dispatches"].as_u64().unwrap()).sum::<u64>(),"cases":cases,
            "scope":if timing_only { "diagnostic timing only; CPU oracle not checked; never use for proofs" }
                else { "isolated synthetic evaluator; no complete-proof acceleration claim" }}),
        )?;
        Ok(())
    })
}
