use anyhow::Result;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;
use zkminer_config::ZkMinerConfig;
use zkminer_prover::benchmark;
use zkminer_prover::dispatcher::WorkerPool;
use zkminer_prover::engine::{init_worker_pool, worker_pool};

pub async fn run(config_path: Option<&Path>, json: bool, calibrate: bool) -> Result<()> {
    // Spawn the prover workers BEFORE benchmarking. `benchmark::run_benchmark`
    // sources every per-device (GPU) result from `engine::worker_pool()`; when the
    // pool is uninitialized it silently degrades to simulated CPU numbers with an
    // empty "Device Benchmarks" section — no GPU is ever enumerated. The pool was
    // previously initialized only by `run`/`mock`, so `zkminer benchmark` could
    // never measure a GPU regardless of which workers were installed.
    //
    // Benchmarking deliberately needs NO wallet and NO chain access, so unlike
    // `status`/`run` this must not call `validate_for_chain()` / `load_signer()`:
    // benchmarking has to keep working on a box that has no wallet key at all.
    // `ZkMinerConfig::load` returns defaults when the file is absent, so a missing
    // config degrades to the default worker search paths rather than failing.
    let config = ZkMinerConfig::load(config_path)?;
    let benchmark_timeout = if config.prover.benchmark_timeout_secs > 0 {
        Some(Duration::from_secs(config.prover.benchmark_timeout_secs))
    } else {
        None
    };
    let mut pool = WorkerPool::new(
        config
            .prover
            .worker_binaries
            .iter()
            .map(|(k, v)| (k.clone(), PathBuf::from(v)))
            .collect::<HashMap<_, _>>(),
        config
            .prover
            .worker_search_paths
            .iter()
            .map(PathBuf::from)
            .collect(),
        benchmark_timeout,
    );
    let connected = pool.discover_and_spawn();
    init_worker_pool(pool);

    if !json {
        println!("zkminer benchmark");
        println!("══════════════════════════════════════════════════════════════════════════");

        let cpu_info = benchmark::get_cpu_info();
        let cores = benchmark::get_cpu_cores();
        println!("CPU:    {}", cpu_info);
        println!("Cores:  {}", cores);
        if connected.is_empty() {
            println!("Workers: none — install prover binaries in ~/.zkminer/provers (CPU/simulated only)");
        } else {
            println!("Workers: {}", connected.join(", "));
        }
        println!();

        println!("Running benchmarks...");
        println!("──────────────────────────────────────────────────────────────────────────");
    }

    // Run on a blocking thread to avoid nested tokio runtime conflicts
    // (SP1's blocking prover internally uses block_on).
    //
    // Race it against SIGINT/SIGTERM. This is NOT optional hygiene: now that this
    // command spawns real workers, an interrupt would otherwise leave SP1's
    // `sp1-gpu-server` GRANDCHILD orphaned holding VRAM. The worker itself dies
    // with the CLI (PR_SET_PDEATHSIG), but that signal targets only the worker —
    // its forked GPU server survives and keeps allocating (measured: 11.5 GB still
    // held after the parent exited). `shutdown_all` fixes this because its Phase 3
    // SIGKILLs the whole process group (`kill(-pid)`), and the worker calls
    // `setpgid(0,0)` at spawn, so the whole group goes with it.
    let bench = tokio::task::spawn_blocking(benchmark::run_benchmark);
    tokio::pin!(bench);

    let interrupted;
    #[cfg(unix)]
    let results = {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sigterm = signal(SignalKind::terminate())?;
        tokio::select! {
            r = &mut bench => { interrupted = false; Some(r) }
            _ = tokio::signal::ctrl_c() => { interrupted = true; None }
            _ = sigterm.recv() => { interrupted = true; None }
        }
    };
    #[cfg(not(unix))]
    let results = {
        tokio::select! {
            r = &mut bench => { interrupted = false; Some(r) }
            _ = tokio::signal::ctrl_c() => { interrupted = true; None }
        }
    };

    // Optional po2 calibration. MUST run before the workers are torn down, since it
    // issues real proofs over the same IPC. Skipped when interrupted.
    //
    // Not raced against signals: each step is bounded by `benchmark_timeout_secs`, and
    // an interrupt during a step simply waits for that step before tearing down. The
    // sweep is discarded unless it actually exercised segmentation — see
    // `benchmark::calibration_is_usable`.
    let mut results = results;
    if !interrupted && calibrate {
        match results.take() {
            Some(Ok(suite)) => {
                let out = tokio::task::spawn_blocking(move || {
                    let mut suite = suite;
                    if let Some(pool) = worker_pool() {
                        benchmark::calibrate_po2_for_suite(&mut suite, pool);
                    }
                    suite
                })
                .await;
                results = Some(out);
            }
            other => results = other,
        }
    }

    // Tear the workers down before returning — on the interrupt and error paths
    // too. The pool lives in a `OnceLock` static, whose `Drop` never runs at
    // process exit, so without this the workers survive as orphans after the
    // command finishes. `shutdown_all` sleeps ~2.2s across its SIGTERM/SIGKILL
    // phases, so keep it off the async runtime. It is idempotent (it zeroes each
    // PID), so the normal path calling it once is safe.
    if let Err(e) = tokio::task::spawn_blocking(|| {
        if let Some(pool) = worker_pool() {
            pool.shutdown_all();
        }
    })
    .await
    {
        // Never mask the benchmark's own result with a teardown failure.
        tracing::warn!("Worker shutdown task failed: {e}");
    }

    if interrupted {
        // The blocking benchmark task cannot be cancelled; it is abandoned here and
        // dies with the process. Workers are already reaped above.
        anyhow::bail!("benchmark interrupted by signal");
    }
    let results = results.expect("results present when not interrupted")?;

    // Persist only when calibration was requested. A calibration sweep is expensive
    // and useless unless the miner can load it (`load_cached_benchmark`), whereas a
    // plain `zkminer benchmark` stays a read-only measurement that writes no state.
    if calibrate {
        benchmark::save_benchmark(&results);
        if !json {
            let calibrated = results
                .device_benchmarks
                .iter()
                .filter(|d| !d.po2_samples.is_empty())
                .count();
            println!(
                "Saved benchmarks to {} ({calibrated} device(s) with usable po2 calibration)",
                benchmark::benchmark_cache_path().display()
            );
        }
    }

    if json {
        println!("{}", serde_json::to_string_pretty(&results)?);
        return Ok(());
    }

    println!();
    println!(
        "{:<18} {:<10} {:<10} {:>8} {:>12} {:>10} {:>15}",
        "Program", "Backend", "Precompile", "Weight", "Cycles", "Time", "Throughput"
    );
    println!("{}", "─".repeat(86));

    for r in &results.results {
        let precompile = if r.precompile { "yes" } else { "-" };
        let weight = if r.weight > 0.0 {
            format!("{:.0}%", r.weight * 100.0)
        } else {
            "-".to_string()
        };
        println!(
            "{:<18} {:<10} {:<10} {:>8} {:>12} {:>9.2}s {:>12.0} c/s",
            r.program_name,
            r.prover_backend,
            precompile,
            weight,
            r.cycles,
            r.duration.as_secs_f64(),
            r.throughput,
        );
    }

    println!("{}", "─".repeat(86));
    println!();
    println!(
        "  zkOP/s: {:.0}  (3970X baseline = 100,000)",
        results.zkops
    );
    println!();

    // Device benchmarks summary
    if !results.device_benchmarks.is_empty() {
        println!("Device Benchmarks");
        println!("──────────────────────────────────────────────────────────────────────────");
        println!(
            "{:<26} {:<10} {:>5} {:>10} {:>10} {:>15}",
            "Device", "Backend", "po2", "Segment", "Memory", "Throughput"
        );
        println!("{}", "─".repeat(80));

        for d in &results.device_benchmarks {
            let rows_count = 1u64 << d.optimal_po2;
            let segment_str = if rows_count >= 1_000_000 {
                format!("{}M rows", rows_count / 1_000_000)
            } else {
                format!("{}K rows", rows_count / 1_000)
            };
            let mem_gb = d.memory_usage_bytes as f64 / (1024.0 * 1024.0 * 1024.0);
            let mem_str = if mem_gb >= 1.0 {
                format!("{:.1} GB", mem_gb)
            } else {
                format!("{:.0} MB", mem_gb * 1024.0)
            };
            let tp_str = if d.throughput >= 1_000_000.0 {
                format!("{:.1}M c/s", d.throughput / 1_000_000.0)
            } else if d.throughput >= 1_000.0 {
                format!("{:.1}K c/s", d.throughput / 1_000.0)
            } else {
                format!("{:.0} c/s", d.throughput)
            };

            // Truncate device label to fit column
            let label = if d.device_label.len() > 25 {
                format!("{}...", &d.device_label[..22])
            } else {
                d.device_label.clone()
            };

            println!(
                "{:<26} {:<10} {:>5} {:>10} {:>10} {:>15}",
                label, d.prover_backend, d.optimal_po2, segment_str, mem_str, tp_str
            );
        }
        println!("{}", "─".repeat(80));
        println!();
    }

    Ok(())
}
