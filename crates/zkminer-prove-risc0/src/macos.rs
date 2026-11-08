//! Local macOS CPU / resident Metal worker selection and proof diagnostics.
use anyhow::{bail, ensure, Context, Result};
use risc0_zkvm::{LocalProver, Prover, ProverOpts};
use serde_json::{json, Value};
use sha2::{Digest as _, Sha256};
use std::{
    path::PathBuf,
    process::Command,
    sync::{
        atomic::{AtomicU64, Ordering},
        OnceLock,
    },
    time::{Duration, Instant},
};

const HELPER_PROBE_TIMEOUT: Duration = Duration::from_millis(1500);
#[cfg(feature = "macos-recursion-metal")]
const METAL_PROBE_TIMEOUT: Duration = Duration::from_secs(3);

struct Config {
    requested: String,
    probe: Option<Value>,
    evidence_dir: Option<PathBuf>,
    helper_container: String,
    cpu_threads: usize,
    go_threads: usize,
    limits: zkminer_prover_protocol::macos::Risc0Limits,
    recursion_hal: &'static str,
    recursion_probe: Option<Value>,
    segment_hal: &'static str,
}
static CONFIG: OnceLock<Config> = OnceLock::new();
fn config() -> &'static Config {
    CONFIG.get().expect("macOS preflight precedes worker loop")
}

fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn legacy_mode(requested: &str) -> Result<()> {
    match requested {
        "cpu" | "auto" => Ok(()),
        "metal" => bail!("ZKMINER_RISC0_MODE=metal selected the retired fold-only backend; build macos-rv32im-metal and use RISC0_SEGMENT_HAL=metal"),
        other => bail!("unknown ZKMINER_RISC0_MODE {other:?}; remove this deprecated selector and use RISC0_SEGMENT_HAL=cpu or metal"),
    }
}

pub fn capabilities() -> (bool, Option<String>) {
    let c = config();
    (
        c.segment_hal == "metal" || c.recursion_hal == "metal",
        c.probe
            .as_ref()
            .or(c.recursion_probe.as_ref())
            .and_then(|p| p["device_name"].as_str().map(str::to_owned)),
    )
}

pub fn warmup_summary() -> String {
    let c = config();
    if cfg!(feature = "macos-native-wrap") {
        return format!("Native helper verification pending; segments {}; Poseidon2 recursion {}; witness, accumulation and identity-p254 CPU", c.segment_hal, c.recursion_hal);
    }
    format!(
        "CPU ready; emulated Groth16 helper preflight passed; requested={}",
        c.requested
    )
}

fn recursion_mode(value: Option<&str>) -> Result<&'static str> {
    match value {
        None | Some("cpu") => Ok("cpu"),
        Some("metal") if cfg!(feature = "macos-recursion-metal") => Ok("metal"),
        Some("metal") => bail!("worker was compiled without macos-recursion-metal"),
        _ => bail!("RISC0_RECURSION_HAL must be cpu or metal"),
    }
}

fn segment_mode(value: Option<&str>) -> Result<&'static str> {
    match value {
        None | Some("cpu") => Ok("cpu"),
        Some("metal") if cfg!(feature = "macos-rv32im-metal") => Ok("metal"),
        Some("metal") => bail!("worker was compiled without macos-rv32im-metal"),
        _ => bail!("RISC0_SEGMENT_HAL must be cpu or metal"),
    }
}

#[cfg(feature = "macos-recursion-metal")]
pub fn recursion_device_probe() -> Result<Value> {
    metal::objc::rc::autoreleasepool(|| {
        let device = metal::Device::system_default().context("Metal device unavailable")?;
        ensure!(
            device.has_unified_memory(),
            "recursion Metal requires unified memory"
        );
        Ok(json!({"device_name":device.name(),"unified_memory":true,
            "max_buffer_bytes":device.max_buffer_length(),"scope":"device only; shader compilation is on the proof path"}))
    })
}

fn probe_recursion(hal: &str) -> Result<Option<Value>> {
    if hal == "cpu" {
        return Ok(None);
    }
    #[cfg(feature = "macos-recursion-metal")]
    {
        let (status, stdout) = zkminer_prover_protocol::proc::output_with_timeout_capturing_stdout(
            Command::new(std::env::current_exe()?).arg("--macos-recursion-probe"),
            METAL_PROBE_TIMEOUT,
            64 * 1024,
        );
        ensure!(
            matches!(
                status,
                zkminer_prover_protocol::proc::Outcome::Ran { success: true, .. }
            ),
            "forced recursion Metal device probe failed: {}",
            status.describe()
        );
        let probe: Value = serde_json::from_str(&stdout)?;
        ensure!(
            probe["unified_memory"] == true
                && probe["device_name"].as_str().is_some_and(|s| !s.is_empty()),
            "invalid recursion Metal device probe"
        );
        return Ok(Some(probe));
    }
    #[cfg(not(feature = "macos-recursion-metal"))]
    bail!("worker was compiled without macos-recursion-metal")
}

fn prover() -> LocalProver {
    if config().segment_hal == "metal" {
        return LocalProver::new("macos-rv32im-metal-worker");
    }
    LocalProver::new("macos-cpu-worker")
}

const IMAGE: &str = "risczero/risc0-groth16-prover:v2025-04-03.1";
const DIGEST: &str = "sha256:a4f80ce2e0b8e2bb7637a93c37136a6776ac00ec843a3fdf1c67b1d5ffea64ee";

fn output(command: &mut Command) -> Result<String> {
    let (status, stdout) = zkminer_prover_protocol::proc::output_with_timeout_capturing_stdout(
        command,
        HELPER_PROBE_TIMEOUT,
        64 * 1024,
    );
    ensure!(
        matches!(
            status,
            zkminer_prover_protocol::proc::Outcome::Ran { success: true, .. }
        ),
        "helper preflight failed: {}",
        status.describe()
    );
    Ok(stdout.trim().to_owned())
}

fn thread_count(value: Option<String>, default: usize) -> Result<usize> {
    let n = value
        .map(|s| s.parse())
        .unwrap_or(Ok(default))
        .context("invalid macOS thread count")?;
    ensure!(
        (1..=18).contains(&n),
        "macOS thread count must be in 1..=18"
    );
    Ok(n)
}

pub fn preflight() -> Result<()> {
    let limits = zkminer_prover_protocol::macos::Risc0Limits::from_environment(cfg!(
        feature = "macos-native-wrap"
    ))
    .map_err(anyhow::Error::msg)?;
    let cpu_threads = thread_count(
        std::env::var("ZKMINER_RISC0_CPU_THREADS")
            .ok()
            .or_else(|| std::env::var("RAYON_NUM_THREADS").ok()),
        if cfg!(feature = "macos-native-wrap") {
            18
        } else {
            6
        },
    )?;
    let go_threads = thread_count(
        std::env::var("RISC0_GROTH16_NATIVE_THREADS").ok(),
        if cfg!(feature = "macos-native-wrap") {
            18
        } else {
            6
        },
    )?;
    std::env::set_var("RAYON_NUM_THREADS", cpu_threads.to_string());
    #[cfg(feature = "macos-native-wrap")]
    std::env::set_var("RISC0_GROTH16_NATIVE_THREADS", go_threads.to_string());
    #[cfg(feature = "macos-native-wrap")]
    ensure!(
        risc0_groth16::prove::native::rayon_threads() == cpu_threads,
        "Rayon thread pool was initialized with different settings"
    );
    for key in [
        "RISC0_DEV_MODE",
        "RISC0_SKIP_VERIFY",
        "RISC0_SERVER_PATH",
        "RISC0_API_URL",
        "DOCS_RS",
        "RISC0_PROVER",
        "RISC0_EXECUTOR",
        "BONSAI_API_URL",
        "BONSAI_API_KEY",
        "RISC0_SKIP_BUILD",
        "RISC0_SKIP_BUILD_KERNELS",
        "RISC0_TEST_INJECT_INVALID",
    ] {
        ensure!(
            std::env::var_os(key).is_none(),
            "unset {key} for native worker acceptance"
        );
    }
    let requested = std::env::var("ZKMINER_RISC0_MODE").unwrap_or_else(|_| "cpu".into());
    legacy_mode(&requested)?;
    if std::env::var_os("ZKMINER_RISC0_MODE").is_some() {
        tracing::warn!("ZKMINER_RISC0_MODE is deprecated; select segments with RISC0_SEGMENT_HAL");
    }
    ensure!(
        std::env::var_os("ZKMINER_RISC0_METAL_STAGING_BYTES").is_none(),
        "ZKMINER_RISC0_METAL_STAGING_BYTES belongs to the retired fold-only backend; unset it"
    );
    #[cfg(feature = "macos-native-wrap")]
    let (context, name) = {
        ensure!(
            std::env::var("ZKMINER_RISC0_WRAP").as_deref() == Ok("native"),
            "native worker requires ZKMINER_RISC0_WRAP=native"
        );
        risc0_groth16::prove::native::start_verification()?;
        (
            String::new(),
            std::env::var("RISC0_GROTH16_CONTAINER_NAME")
                .context("native worker requires supervisor lease")?,
        )
    };
    #[cfg(not(feature = "macos-native-wrap"))]
    let (context, name) = {
        ensure!(
            std::env::var("ZKMINER_RISC0_WRAP").as_deref() != Ok("native"),
            "this worker was built without native wrapping"
        );
        let context = std::env::var("ZKMINER_RISC0_DOCKER_CONTEXT")
            .context("set a dedicated local Docker context")?;
        let endpoint = output(Command::new("docker").args([
            "context",
            "inspect",
            &context,
            "--format",
            "{{.Endpoints.docker.Host}}",
        ]))?;
        ensure!(
            endpoint.starts_with("unix://"),
            "only a local Docker socket is supported"
        );
        let digest = output(Command::new("docker").args([
            "--context",
            &context,
            "image",
            "inspect",
            IMAGE,
            "--format",
            "{{json .RepoDigests}}",
        ]))?;
        ensure!(
            digest.contains(DIGEST),
            "the pinned Groth16 helper image is missing or has a different digest"
        );
        let name = std::env::var("RISC0_GROTH16_CONTAINER_NAME")
            .context("start the worker through WorkerHandle for helper ownership")?;
        ensure!(
            name.starts_with("zkminer-macos-"),
            "invalid supervisor helper identity"
        );
        let _dir = PathBuf::from(
            std::env::var_os("RISC0_WORK_DIR")
                .context("supervisor must supply a shared work directory")?,
        );
        ensure!(_dir.is_dir(), "shared helper work directory does not exist");
        (context, name)
    };
    let mut probe = None;
    let recursion_value = match std::env::var("RISC0_RECURSION_HAL") {
        Ok(value) => Some(value),
        Err(std::env::VarError::NotPresent) => None,
        Err(error) => bail!("invalid RISC0_RECURSION_HAL: {error}"),
    };
    let recursion_hal = recursion_mode(recursion_value.as_deref())?;
    let recursion_probe = probe_recursion(recursion_hal)?;
    let segment_value = match std::env::var("RISC0_SEGMENT_HAL") {
        Ok(value) => Some(value),
        Err(std::env::VarError::NotPresent) => None,
        Err(error) => bail!("invalid RISC0_SEGMENT_HAL: {error}"),
    };
    let segment_hal = segment_mode(segment_value.as_deref())?;
    let differential = std::env::var("RISC0_RV32IM_METAL_CHECK_CPU").unwrap_or_else(|_| "0".into());
    ensure!(
        ["0", "1"].contains(&differential.as_str()),
        "RISC0_RV32IM_METAL_CHECK_CPU must be 0 or 1"
    );
    ensure!(
        differential == "0" || segment_hal == "metal",
        "CPU differential requires RV32IM Metal"
    );
    if segment_hal == "metal" {
        probe = probe_recursion("metal")?;
    }
    let evidence_dir = std::env::var_os("ZKMINER_RISC0_EVIDENCE_DIR").map(PathBuf::from);
    if let Some(path) = &evidence_dir {
        std::fs::create_dir_all(path).context("create worker evidence directory")?;
    }
    let state = Config {
        requested,
        probe,
        evidence_dir,
        helper_container: name.clone(),
        cpu_threads,
        go_threads,
        limits,
        recursion_hal,
        recursion_probe,
        segment_hal,
    };
    tracing::info!(
        "macos_mode {}",
        json!({"requested_mode":state.requested,"observed_mode":if segment_hal == "metal" {"metal"} else {"cpu"},
        "fallback_reason":null,"probe":state.probe,"staging_limit_bytes":null,
        "segment_hal":segment_hal,"poseidon2_recursion":recursion_hal,"recursion_probe":state.recursion_probe,
        "witness_accumulation":"cpu","identity_p254":if recursion_hal == "metal" { "metal" } else { "cpu" },
        "groth16":if cfg!(feature = "macos-native-wrap") { "native_darwin_arm64_helper" } else { "local_linux_amd64_helper" }})
    );
    CONFIG
        .set(state)
        .map_err(|_| anyhow::anyhow!("macOS mode already initialized"))?;
    if !context.is_empty() {
        std::env::set_var("DOCKER_CONTEXT", &context);
    }
    std::env::set_var("RISC0_PROVER", "local");
    std::env::set_var("RISC0_EXECUTOR", "local");

    // macOS has no Linux PDEATHSIG. This thread exits the worker and cleans only
    // its leased helper if the parent disappears. The parent's lease handles a
    // SIGKILL of this worker (which cannot execute a destructor).
    let parent = unsafe { libc::getppid() };
    std::thread::Builder::new()
        .name("macos-parent-watch".into())
        .spawn(move || loop {
            std::thread::sleep(Duration::from_secs(1));
            if unsafe { libc::getppid() } != parent {
                // Cleanup keeps its own deadline; the shorter startup probes must
                // not truncate parent-death removal of an already-running helper.
                if !context.is_empty() {
                    let _ = zkminer_prover_protocol::proc::output_with_timeout(
                        Command::new("docker").args(["--context", &context, "rm", "-f", &name]),
                        Duration::from_secs(10),
                        64 * 1024,
                    );
                }
                std::process::exit(1);
            }
        })?;
    Ok(())
}

pub fn bound_env(builder: &mut risc0_zkvm::ExecutorEnvBuilder<'_>, po2: Option<u8>) -> Result<()> {
    let limits = config().limits;
    limits.validate_po2(po2).map_err(anyhow::Error::msg)?;
    builder
        .segment_limit_po2(po2.unwrap_or(limits.default_segment_po2) as u32)
        .session_limit(Some(limits.max_guest_cycles));
    Ok(())
}

pub fn check_guest_cycles(cycles: u64) -> Result<()> {
    config()
        .limits
        .validate_guest_cycles(cycles)
        .map_err(anyhow::Error::msg)
}

pub fn benchmarks() -> &'static [(&'static str, &'static [u8], &'static [u8], f64, bool)] {
    if cfg!(feature = "macos-native-wrap") {
        // Fixed arithmetic/hash fixtures each execute just over 10M guest cycles.
        return &[
            (
                "fibonacci",
                super::FIBONACCI_ELF,
                &[0x40, 0x42, 0x0f, 0],
                1.0,
                false,
            ),
            (
                "sha256-chain",
                super::SHA256_CHAIN_ELF,
                &[0xd6, 0x08, 0, 0],
                1.0,
                true,
            ),
        ];
    }
    &[
        (
            "fibonacci",
            super::FIBONACCI_ELF,
            &[20, 0, 0, 0],
            1.0,
            false,
        ),
        (
            "sha256-chain",
            super::SHA256_CHAIN_ELF,
            &[10, 0, 0, 0],
            1.0,
            true,
        ),
    ]
}

fn write_report(report: &Value, filename: &str) -> Result<()> {
    tracing::info!("macos_proof {}", report);
    if let Some(dir) = &config().evidence_dir {
        let path = dir.join(filename);
        let temporary = path.with_extension("json.tmp");
        std::fs::write(&temporary, serde_json::to_vec_pretty(report)?)?;
        std::fs::rename(temporary, path)?;
    }
    Ok(())
}

struct Completed {
    journal: Vec<u8>,
    seal: Vec<u8>,
    total_secs: f64,
    cycles: u64,
    stark_secs: f64,
    wrap_secs: f64,
}

fn prove_staged(
    request_id: u64,
    operation: &str,
    elf: &[u8],
    input: &[u8],
    po2: Option<u8>,
) -> Result<Completed> {
    let c = config();
    let total = Instant::now();
    #[cfg(feature = "macos-recursion-metal")]
    let recursion_before = risc0_zkvm::metal_recursion_stats();
    #[cfg(feature = "macos-rv32im-metal")]
    let segment_before = risc0_zkvm::metal_rv32im_stats();
    #[cfg(feature = "macos-rv32im-metal")]
    let gpu_before = risc0_zkp::hal::metal::metal_gpu_stats();
    let filename = if operation == "prove" {
        format!("{}-{request_id}.json", std::process::id())
    } else {
        format!("{}-benchmark-{request_id}.json", std::process::id())
    };
    let mut report = json!({"schema_version":1,"worker_pid":std::process::id(),"request_id":request_id,
        "operation":operation,"requested_mode":c.requested,"observed_mode":if c.segment_hal == "metal" {"metal"} else {"cpu"},
        "fallback_reason":null,"phase":"started","proof_kind":null,"image_id":null,
        "elf_sha256":hash(elf),"input_sha256":hash(input),"po2":po2.unwrap_or(c.limits.default_segment_po2),
        "helper_container":c.helper_container,"helper_arch":if cfg!(feature = "macos-native-wrap") { "darwin/arm64" } else { "linux/amd64 (emulated)" },
        "rayon_threads":c.cpu_threads,"gomaxprocs":if cfg!(feature = "macos-native-wrap") { Some(c.go_threads) } else { None },
        "max_guest_cycles":c.limits.max_guest_cycles,"minimum_segment_po2":14,
        "segment_hal":c.segment_hal,"recursion_hal":c.recursion_hal,
        "recursion_cpu_stages":if c.recursion_hal == "metal" { vec!["witness","accumulation"] } else { vec!["witness","accumulation","identity_p254"] },
        "staging_limit_bytes":null,"stage_ms":{},"error":null});
    write_report(&report, &filename)?;
    let result = (|| -> Result<Completed> {
        let image = risc0_zkvm::compute_image_id(elf).context("invalid program binary")?;
        report["image_id"] = json!(image.to_string());
        let mut builder = risc0_zkvm::ExecutorEnv::builder();
        builder.write_slice(input);
        let image_bytes: [u8; 32] = image.as_bytes().try_into().expect("image ID is 32 bytes");
        builder.random_seed(super::sys_rand_seed(&super::sys_rand_key(), &image_bytes, input));
        bound_env(&mut builder, po2)?;
        let env = builder.build()?;
        let prover = prover();
        let started = Instant::now();
        let info = prover.prove_with_opts(env, elf, &ProverOpts::composite())?;
        check_guest_cycles(info.stats.user_cycles)?;
        let segment_secs = started.elapsed().as_secs_f64();
        info.receipt
            .verify(image)
            .context("verify composite receipt")?;
        report["stats"] = serde_json::to_value(&info.stats)?;
        let mut observed = json!({"other_segment_operations":"cpu","recursion":c.recursion_hal,
            "identity":if c.recursion_hal == "metal" { "metal" } else { "cpu" },
            "groth16":if cfg!(feature = "macos-native-wrap") { "native_darwin_arm64_helper" } else { "local_linux_amd64_helper" }});
        #[cfg(feature = "macos-rv32im-metal")]
        {
            let after = risc0_zkvm::metal_rv32im_stats();
            let checks =
                after.completed_constraint_checks - segment_before.completed_constraint_checks;
            let dispatches = after.completed_dispatches - segment_before.completed_dispatches;
            let command_buffers = after.completed_command_buffers - segment_before.completed_command_buffers;
            let points = after.evaluation_points - segment_before.evaluation_points;
            let witness = after.cpu_witness_calls - segment_before.cpu_witness_calls;
            let accumulation = after.cpu_accumulation_calls - segment_before.cpu_accumulation_calls;
            let cpu_checks = after.cpu_differential_checks - segment_before.cpu_differential_checks;
            if c.segment_hal == "metal" {
                ensure!(
                    checks == info.stats.segments as u64
                        && points > 0
                        && dispatches > checks
                        && command_buffers > 0
                        && command_buffers <= dispatches
                        && witness == checks
                        && accumulation == checks,
                    "missing RV32IM Metal segment execution evidence"
                );
                observed["segment"] = json!("metal");
                observed["other_segment_operations"] = json!("metal_shared_buffers");
                observed["rv32im_metal"] = json!({"completed_constraint_checks":checks,"evaluation_points":points,
                    "completed_dispatches":dispatches,"completed_command_buffers":command_buffers,
                    "first_completed_gpu_dispatch_epoch_ns":risc0_zkp::hal::metal::first_completed_dispatch_epoch_ns(),
                    "cpu_witness_calls":witness,"cpu_accumulation_calls":accumulation,
                    "threads_per_threadgroup":256,"evalfast_phase_split":std::env::var("RISC0_RV32IM_TAIL_SPLIT").as_deref()!=Ok("1"),
                    "kernel_source_sha256":hash(risc0_zkvm::metal_rv32im_kernel_source().as_bytes()),
                    "hal_kernel_source_sha256":hash(risc0_zkp::hal::metal::runtime_kernel_source().as_bytes()),
                    "cpu_differential_checks":cpu_checks,
                    "cpu_stages":["witness","accumulation","scatter","prefix_products","zeroize"],"normalization":"period_four_table"});
                observed["rv32im_metal"]["gpu_kernels"] = json!(
                    risc0_zkp::hal::metal::metal_gpu_stats_since(&gpu_before, "segment/")
                );
            } else {
                ensure!(
                    checks == 0 && dispatches == 0 && points == 0,
                    "CPU segment mode unexpectedly used Metal"
                );
            }
        }
        if c.segment_hal == "cpu" {
            observed["segment"] = json!("cpu");
        }
        report["observed_stages"] = observed;
        report["phase"] = json!("segments_complete");
        report["proof_kind"] = json!("composite");
        report["stage_ms"]["execution_and_segment"] = json!(segment_secs * 1000.0);
        report["total_ms"] = json!(total.elapsed().as_secs_f64() * 1000.0);
        write_report(&report, &filename)?;

        let started = Instant::now();
        let succinct = prover.compress(&ProverOpts::succinct(), &info.receipt)?;
        #[cfg(feature = "macos-recursion-metal")]
        {
            let after = risc0_zkvm::metal_recursion_stats();
            let checks =
                after.completed_constraint_checks - recursion_before.completed_constraint_checks;
            let points = after.evaluation_points - recursion_before.evaluation_points;
            let cpu_checks = after.cpu_differential_checks - recursion_before.cpu_differential_checks;
            if c.recursion_hal == "metal" {
                ensure!(
                    checks >= 2 * info.stats.segments as u64 - 1 && points > 0,
                    "missing Metal lift/join constraint checks"
                );
                report["observed_stages"]["recursion_metal"] = json!({
                    "completed_constraint_checks":checks,"evaluation_points":points,
                    "cpu_differential_checks":cpu_checks,
                    "eval_check_split":after.eval_check_split,
                    "kernel_source_sha256":hash(risc0_zkvm::metal_recursion_kernel_source().as_bytes()),
                    "cpu_stages":["witness","accumulation"],
                });
                #[cfg(feature = "macos-rv32im-metal")]
                {
                    report["observed_stages"]["recursion_metal"]["gpu_kernels"] = json!(
                        risc0_zkp::hal::metal::metal_gpu_stats_since(&gpu_before, "recursion/")
                    );
                }
            } else {
                ensure!(
                    checks == 0 && points == 0,
                    "CPU recursion unexpectedly dispatched Metal"
                );
            }
        }
        let recursion_secs = started.elapsed().as_secs_f64();
        succinct.verify(image).context("verify succinct receipt")?;
        report["stage_ms"]["recursion"] = json!(recursion_secs * 1000.0);
        report["phase"] = json!("wrapping");
        report["proof_kind"] = json!("succinct");
        report["total_ms"] = json!(total.elapsed().as_secs_f64() * 1000.0);
        write_report(&report, &filename)?;

        #[cfg(feature = "macos-recursion-metal")]
        let identity_recursion_before = risc0_zkvm::metal_recursion_stats();
        #[cfg(feature = "macos-rv32im-metal")]
        let identity_gpu_before = risc0_zkp::hal::metal::metal_gpu_stats();
        let started = Instant::now();
        let receipt = prover.compress(&ProverOpts::groth16(), &succinct)?;
        let wrap_secs = started.elapsed().as_secs_f64();
        #[cfg(feature = "macos-recursion-metal")]
        if c.recursion_hal == "metal" {
            let after = risc0_zkvm::metal_recursion_stats();
            let checks = after.completed_constraint_checks
                - identity_recursion_before.completed_constraint_checks;
            let points = after.evaluation_points - identity_recursion_before.evaluation_points;
            let cpu_checks = after.cpu_differential_checks
                - identity_recursion_before.cpu_differential_checks;
            ensure!(checks > 0 && points > 0, "missing Metal identity constraint check");
            report["observed_stages"]["identity_metal"] = json!({
                "completed_constraint_checks":checks,
                "evaluation_points":points,
                "cpu_differential_checks":cpu_checks,
                "eval_check_split":after.eval_check_split,
                "kernel_source_sha256":hash(risc0_zkvm::metal_recursion_kernel_source().as_bytes()),
                "cpu_stages":["witness","accumulation"],
            });
            #[cfg(feature = "macos-rv32im-metal")]
            {
                report["observed_stages"]["identity_metal"]["gpu_kernels"] = json!(
                    risc0_zkp::hal::metal::metal_gpu_stats_since(
                        &identity_gpu_before, "recursion/"));
            }
        }
        let started = Instant::now();
        receipt
            .verify(image)
            .context("final Groth16 receipt verification failed")?;
        let seal = receipt
            .inner
            .groth16()
            .context("expected complete Groth16 receipt")?
            .seal
            .clone();
        ensure!(seal.len() == 256, "unexpected Groth16 seal size");
        let journal = receipt.journal.bytes.clone();
        report["stage_ms"]["identity_and_wrap"] = json!(wrap_secs * 1000.0);
        report["stage_ms"]["verification"] = json!(started.elapsed().as_secs_f64() * 1000.0);
        report["phase"] = json!("complete");
        report["proof_kind"] = json!("groth16");
        // Bound diagnostics even if a guest produces a large public journal.
        report["journal_hex"] = if journal.len() <= 4096 {
            json!(journal
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>())
        } else {
            Value::Null
        };
        report["journal_sha256"] = json!(hash(&journal));
        report["seal_sha256"] = json!(hash(&seal));
        report["total_ms"] = json!(total.elapsed().as_secs_f64() * 1000.0);
        write_report(&report, &filename)?;
        Ok(Completed {
            journal,
            seal,
            total_secs: total.elapsed().as_secs_f64(),
            cycles: info.stats.total_cycles,
            stark_secs: segment_secs + recursion_secs,
            wrap_secs,
        })
    })();
    if let Err(error) = &result {
        report["phase"] = json!("failed");
        report["error"] = json!(format!("{error:#}"));
        report["total_ms"] = json!(total.elapsed().as_secs_f64() * 1000.0);
        if let Err(write_error) = write_report(&report, &filename) {
            tracing::error!("failed to save proof error diagnostic: {write_error:#}");
        }
    }
    result
}

pub fn prove(
    request_id: u64,
    elf: &[u8],
    input: &[u8],
    po2: Option<u8>,
) -> Result<(Vec<u8>, Vec<u8>, f64, u64)> {
    let proof = prove_staged(request_id, "prove", elf, input, po2)?;
    Ok((proof.journal, proof.seal, proof.total_secs, proof.cycles))
}

pub fn benchmark(
    name: &str,
    elf: &[u8],
    input: &[u8],
    weight: f64,
    precompile: bool,
) -> Result<zkminer_prover_protocol::BenchmarkEntry> {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let proof = prove_staged(
        NEXT.fetch_add(1, Ordering::Relaxed),
        "benchmark",
        elf,
        input,
        None,
    )?;
    Ok(zkminer_prover_protocol::BenchmarkEntry {
        program_name: name.into(),
        prover_backend: "risc0".into(),
        cycles: proof.cycles,
        duration_secs: proof.stark_secs,
        throughput: proof.cycles as f64 / proof.stark_secs,
        weight,
        precompile,
        wrap_secs: Some(proof.wrap_secs),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn thread_configuration_is_bounded() {
        for value in ["1", "6", "12", "18"] {
            assert_eq!(
                thread_count(Some(value.into()), 6).unwrap(),
                value.parse::<usize>().unwrap()
            );
        }
        for value in ["0", "19", "-1", "invalid"] {
            assert!(thread_count(Some(value.into()), 6).is_err());
        }
        assert_eq!(thread_count(None, 6).unwrap(), 6);
    }

    #[test]
    fn retired_fold_selector_is_rejected_with_migration_guidance() {
        let message = legacy_mode("metal").unwrap_err().to_string();
        assert!(message.contains("RISC0_SEGMENT_HAL=metal"));
        assert!(legacy_mode("cpu").is_ok());
        assert!(legacy_mode("auto").is_ok());
        assert!(legacy_mode("invalid").is_err());
    }

    #[test]
    fn recursion_mode_requires_an_explicit_supported_build() {
        assert_eq!(recursion_mode(None).unwrap(), "cpu");
        assert_eq!(recursion_mode(Some("cpu")).unwrap(), "cpu");
        assert!(recursion_mode(Some("auto")).is_err());
        assert_eq!(
            recursion_mode(Some("metal")).is_ok(),
            cfg!(feature = "macos-recursion-metal")
        );
    }

    #[test]
    fn segment_mode_requires_an_explicit_supported_build() {
        assert_eq!(segment_mode(None).unwrap(), "cpu");
        assert_eq!(segment_mode(Some("cpu")).unwrap(), "cpu");
        assert_eq!(
            segment_mode(Some("metal")).is_ok(),
            cfg!(feature = "macos-rv32im-metal")
        );
        assert!(segment_mode(Some("auto")).is_err());
        assert!(segment_mode(Some("invalid")).is_err());
    }

    #[test]
    fn startup_probe_budgets_fit_the_existing_handshake() {
        use zkminer_prover_protocol::proc::{max_overhead, HANDSHAKE_TIMEOUT};
        let probes = 2 * (HELPER_PROBE_TIMEOUT + max_overhead());
        #[cfg(feature = "macos-recursion-metal")]
        let probes = probes + METAL_PROBE_TIMEOUT + max_overhead();
        assert!(probes + Duration::from_millis(500) < HANDSHAKE_TIMEOUT);
    }
}
