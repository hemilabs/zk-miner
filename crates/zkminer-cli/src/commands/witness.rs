//! `zkminer witness …`: operator commands for witness-construction jobs
//! (docs/witness-construction-jobs.md §10.3, §15.1, §20.1).
//!
//! - `init-store`: initialises the retention store in an empty directory and prints the
//!   `store_uuid` that `[retention] store_uuid` must name. The miner never creates a store itself,
//!   so a disk that failed to mount reads as unavailable, never as an empty store.
//! - `self-test`: the sandbox self-test the miner runs at startup and hourly (every profile's
//!   properties, by the probe binary next to `zkminer`), then, with a `[broker]` section, the broker
//!   started in its sandbox and its own self-test. Exits non-zero when any check fails.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use zkminer_config::ZkMinerConfig;

/// The prover address the store is bound to: `[witness] prover_address` (non-secret), else the
/// configured key's address.
#[cfg(target_os = "linux")]
fn prover_address(config: &ZkMinerConfig) -> Result<alloy::primitives::Address> {
    match config.witness.prover_address {
        Some(a) => Ok(a),
        None => Ok(zkminer_config::wallet::load_signer(&config.wallet)
            .context("no [witness] prover_address, and the prover key is unavailable")?
            .address()),
    }
}

/// `zkminer witness init-store`.
#[cfg(target_os = "linux")]
pub fn init_store(
    config_path: Option<&Path>,
    dir: Option<PathBuf>,
    require_dedicated_mount: bool,
    allow_any_filesystem: bool,
) -> Result<()> {
    let config = ZkMinerConfig::load(config_path)?;
    config.validate_network()?;
    let dir = match dir.or_else(|| config.retention.as_ref().map(|r| r.dir.clone())) {
        Some(d) => d,
        None => bail!("name the store directory with --dir, or set [retention] dir"),
    };
    let router: alloy::primitives::Address = config
        .contracts
        .hemi_prove
        .parse()
        .with_context(|| format!("contracts.hemi_prove {:?} is not an address", config.contracts.hemi_prove))?;
    let prover = prover_address(&config)?;
    if !dir.exists() {
        std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    }
    let require = require_dedicated_mount || config.retention.as_ref().is_some_and(|r| r.require_dedicated_mount);
    let any_fs = allow_any_filesystem || config.retention.as_ref().is_some_and(|r| r.allow_any_filesystem);
    let id = zkminer_witness_host::store_open::init_store(&dir, config.chain.chain_id, router, prover, require, any_fs)
        .map_err(|e| anyhow::anyhow!("initialising the retention store at {}: {e}", dir.display()))?;
    println!("Retention store initialised at {}", dir.display());
    println!("  chain id {}, router {}, prover {}", id.chain_id, id.router, id.prover);
    println!("Put this in the [retention] section of the miner's config:");
    println!("store_uuid = \"{}\"", id.store_uuid);
    Ok(())
}

/// `zkminer witness self-test`.
#[cfg(target_os = "linux")]
pub async fn self_test(config_path: Option<&Path>, probe: Option<PathBuf>) -> Result<()> {
    use zkminer_config::witness::SandboxModeConfig;
    use zkminer_witness_host::{broker_proc::BrokerProcess, paths, spawner::Spawner};
    let config = ZkMinerConfig::load(config_path)?;
    config.validate_network()?;
    let secret = config_path.map(PathBuf::from).unwrap_or_else(ZkMinerConfig::default_path);
    if !secret.is_file() {
        bail!(
            "the self-test checks that no sandbox can read the miner's config, so it needs one: {} does not exist",
            secret.display()
        );
    }
    let probe = match probe {
        Some(p) => p,
        None => paths::binary(None, zkminer_witness_sandbox::probe::PROBE_BINARY)?,
    };
    let root = zkminer_witness_sandbox::delegated_root().context(
        "the delegated cgroup (run it as `systemd-run --user --scope -p Delegate=yes -- zkminer witness self-test`)",
    )?;
    let mode = match config.witness.sandbox_mode {
        SandboxModeConfig::System => zkminer_witness_sandbox::SandboxMode::System,
        SandboxModeConfig::Rootless => zkminer_witness_sandbox::SandboxMode::Rootless,
    };
    let spawner = Spawner::new()?;
    let (p, s) = (probe.clone(), secret.clone());
    let report = spawner.run_async(move || zkminer_witness_sandbox::self_test(mode, &p, &s)).await?;
    for c in &report.checks {
        println!("{} {}: {}", if c.passed { "PASS" } else { "FAIL" }, c.name, c.detail);
    }
    let mut failed = !report.passed();
    println!(
        "sandbox ({:?}): {} of {} checks passed",
        report.mode,
        report.checks.iter().filter(|c| c.passed).count(),
        report.checks.len()
    );
    if let Some(b) = &config.broker {
        let binary = paths::binary(b.binary.as_deref(), paths::BROKER_BINARY)?;
        let broker = BrokerProcess::start(&spawner, &binary, &b.config, &root, b.memory_bytes, &config)?;
        match broker.client.self_test().await {
            Ok(r) => {
                for (check, ok) in &r.checks {
                    println!("{} broker/{check:?}", if *ok { "PASS" } else { "FAIL" });
                }
                println!("broker: {}", if r.ok { "passed" } else { "FAILED" });
                failed |= !r.ok;
            }
            Err(e) => {
                println!("FAIL broker: {e}");
                failed = true;
            }
        }
    } else {
        println!("broker: not configured ([broker] section absent), not tested");
    }
    if failed {
        bail!("the witness self-test failed");
    }
    println!("witness self-test passed");
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn init_store(_: Option<&Path>, _: Option<PathBuf>, _: bool, _: bool) -> Result<()> {
    bail!("witness-construction jobs are served on Linux only")
}

#[cfg(not(target_os = "linux"))]
pub async fn self_test(_: Option<&Path>, _: Option<PathBuf>) -> Result<()> {
    bail!("witness-construction jobs are served on Linux only")
}
