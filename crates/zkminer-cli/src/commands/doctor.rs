//! `zkminer doctor`: will this miner claim and prove jobs, and if not, why not.
//!
//! Each check the miner makes before it claims, run once and printed with a verdict: the config and
//! key, the chain and the deployment, gas and stake, and card by card what this host can prove (the
//! same table `zkminer run` prints at startup). Signs and sends nothing, and starts no worker, so it
//! is safe beside a running miner.

use anyhow::Result;
use std::path::{Path, PathBuf};
use std::time::Duration;
use zkminer_config::ZkMinerConfig;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Level {
    Pass,
    Info,
    Warn,
    Fail,
}

#[derive(Default)]
struct Report {
    warnings: usize,
    failures: usize,
}

impl Report {
    fn say(&mut self, level: Level, what: &str, detail: impl AsRef<str>) {
        let tag = match level {
            Level::Pass => "  ok  ",
            Level::Info => "  --  ",
            Level::Warn => " WARN ",
            Level::Fail => " FAIL ",
        };
        match level {
            Level::Warn => self.warnings += 1,
            Level::Fail => self.failures += 1,
            _ => {}
        }
        println!("[{tag}] {what}: {}", detail.as_ref());
    }

    fn section(&self, title: &str) {
        println!("\n{title}");
        println!("{}", "─".repeat(title.chars().count().max(20)));
    }
}

/// The host of an RPC URL, without the path or query (where API keys live).
fn rpc_host(url: &str) -> String {
    let rest = url.split_once("://").map_or(url, |(_, r)| r);
    let host = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    // Drop any userinfo too.
    host.rsplit_once('@').map_or(host, |(_, h)| h).to_string()
}

/// An error's text with any URL in it reduced to its host: transport errors quote the request URL,
/// and providers put API keys in its path or query.
fn redact(e: &anyhow::Error) -> String {
    super::simulate::redact_urls(&format!("{e:#}"))
}

/// Free bytes on the filesystem holding `path`.
fn free_bytes(path: &Path) -> Option<u64> {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        extern "system" {
            fn GetDiskFreeSpaceExW(
                dir: *const u16,
                free_to_caller: *mut u64,
                total: *mut u64,
                total_free: *mut u64,
            ) -> i32;
        }
        let wide: Vec<u16> = path.as_os_str().encode_wide().chain([0]).collect();
        let (mut free, mut total, mut total_free) = (0u64, 0u64, 0u64);
        // SAFETY: a NUL-terminated path and three out-pointers to locals.
        let ok =
            unsafe { GetDiskFreeSpaceExW(wide.as_ptr(), &mut free, &mut total, &mut total_free) };
        (ok != 0).then_some(free)
    }
    #[cfg(not(windows))]
    {
        // POSIX `df -P`: the fourth field of the second line is the free space in 1024-byte blocks.
        let out = std::process::Command::new("df")
            .arg("-Pk")
            .arg(path)
            .output()
            .ok()?;
        let text = String::from_utf8_lossy(&out.stdout);
        // Available is the field before Capacity (`NN%`); counted from there, not from the left,
        // because the filesystem name may contain spaces.
        let fields: Vec<&str> = text.lines().nth(1)?.split_whitespace().collect();
        let cap = fields.iter().rposition(|f| f.ends_with('%'))?;
        let kb: u64 = fields.get(cap.checked_sub(1)?)?.parse().ok()?;
        Some(kb * 1024)
    }
}

const GIB: f64 = 1024.0 * 1024.0 * 1024.0;

/// The prover's first run downloads RISC Zero's Groth16 artifacts into `~/.risc0` and SP1's circuit
/// artifacts into `~/.sp1`: about 16-20 GB unpacked between them.
const FIRST_RUN_DOWNLOAD_BYTES: u64 = 20 * 1024 * 1024 * 1024;

fn fmt_eth(wei: u128) -> String {
    format!("{:.5} ETH", wei as f64 / 1e18)
}

async fn chain_checks(report: &mut Report, config: &ZkMinerConfig) {
    report.section("Chain and funds");
    let signer = match zkminer_config::wallet::load_signer(&config.wallet) {
        Ok(s) => s,
        Err(e) => {
            report.say(Level::Fail, "key", redact(&e));
            return;
        }
    };
    report.say(
        Level::Pass,
        "key",
        format!("{} ({})", signer.address(), config.wallet.key_source),
    );
    let host = rpc_host(&config.chain.rpc_url);
    let client = match tokio::time::timeout(
        Duration::from_secs(60),
        zkminer_chain::client::ChainClient::new(config, signer),
    )
    .await
    {
        Ok(Ok(c)) => c,
        Ok(Err(e)) => {
            report.say(Level::Fail, "RPC", format!("{host}: {}", redact(&e)));
            return;
        }
        Err(_) => {
            report.say(Level::Fail, "RPC", format!("{host}: no answer in 60 s"));
            return;
        }
    };
    match client.get_block_number().await {
        Ok(b) => report.say(
            Level::Pass,
            "RPC",
            format!("{host}, chain {}, block {b}", client.chain_id),
        ),
        Err(e) => report.say(Level::Fail, "RPC", format!("{host}: {}", redact(&e))),
    }
    // Reads the latest header, which also sets the clock comparison below.
    let (_, max_fee) = client.base_fees().await;
    match zkminer_chain::client::chain_clock_skew_secs() {
        Some(skew) if skew.unsigned_abs() > super::run::MAX_CLAIM_CLOCK_SKEW_SECS => report.say(
            Level::Fail,
            "clock",
            format!(
                "this host's clock is {} s {} the chain's; the miner claims nothing past {} s. Sync \
                 it (NTP).",
                skew.unsigned_abs(),
                if skew < 0 { "ahead of" } else { "behind" },
                super::run::MAX_CLAIM_CLOCK_SKEW_SECS
            ),
        ),
        Some(skew) => report.say(
            Level::Pass,
            "clock",
            format!("within {} s of the chain's", skew.unsigned_abs().max(1)),
        ),
        None => report.say(Level::Warn, "clock", "could not read a block header to compare"),
    }
    match client.verify_deployment().await {
        Ok(_) => report.say(Level::Pass, "deployment", "verified"),
        Err(e) => report.say(
            Level::Fail,
            "deployment",
            format!(
                "NOT verified, so `zkminer run` claims nothing and `stake` refuses: {}",
                redact(&e)
            ),
        ),
    }
    // What the miner's own gas gate needs for one claim and its fulfil (see its ETH funds gate).
    let max_fee = max_fee.max(zkminer_chain::client::MIN_PRIORITY_FEE_WEI);
    let need = (client.fulfill_gas_limit as u128)
        .saturating_mul(max_fee)
        .saturating_add(300_000u128.saturating_mul(max_fee));
    match client.get_eth_balance().await {
        Ok(b) => {
            let have: u128 = b.try_into().unwrap_or(u128::MAX);
            let addr = client.address;
            if have < need {
                report.say(
                    Level::Fail,
                    "gas",
                    format!(
                        "{} on {addr}; one claim and its fulfil need {} at today's fees (more per \
                         job held at once). Send ETH to {addr}.",
                        fmt_eth(have),
                        fmt_eth(need)
                    ),
                )
            } else {
                report.say(
                    Level::Pass,
                    "gas",
                    format!(
                        "{} (one claim and its fulfil need {} at today's fees; about {} at once)",
                        fmt_eth(have),
                        fmt_eth(need),
                        have / need.max(1)
                    ),
                )
            }
        }
        Err(e) => report.say(
            Level::Warn,
            "gas",
            format!("balance unreadable: {}", redact(&e)),
        ),
    }
    let min_claim = client.get_min_collateral_amount().await.unwrap_or(0);
    match client.get_stake_info(client.address).await {
        Ok(stake) if stake.total_staked == 0 => report.say(
            Level::Fail,
            "stake",
            "nothing staked, so nothing can be claimed: `zkminer stake <HEMI>`",
        ),
        // All of it in locks the miner holds: busy, not short.
        Ok(stake)
            if stake.available_collateral < min_claim.max(1) && stake.locked_collateral > 0 =>
        {
            report.say(
                Level::Warn,
                "stake",
                format!(
                    "{} HEMI staked, all but {} HEMI locked in jobs held: no new claim fits until \
                     one settles. More stake (`zkminer stake <HEMI>`) lets it take more at once.",
                    super::stake::fmt_hemi(stake.total_staked),
                    super::stake::fmt_hemi(stake.available_collateral),
                ),
            )
        }
        Ok(stake) if stake.available_collateral < min_claim.max(1) => report.say(
            Level::Fail,
            "stake",
            format!(
                "{} HEMI staked, {} HEMI free: not enough for even the {} HEMI contract minimum \
                 (a real claim locks more). `zkminer stake <HEMI>`",
                super::stake::fmt_hemi(stake.total_staked),
                super::stake::fmt_hemi(stake.available_collateral),
                super::stake::fmt_hemi(min_claim)
            ),
        ),
        Ok(stake) => report.say(
            Level::Pass,
            "stake",
            format!(
                "{} HEMI staked, {} HEMI free (a claim locks at least {} HEMI, usually much more)",
                super::stake::fmt_hemi(stake.total_staked),
                super::stake::fmt_hemi(stake.available_collateral),
                super::stake::fmt_hemi(min_claim)
            ),
        ),
        Err(e) => report.say(Level::Warn, "stake", format!("unreadable: {}", redact(&e))),
    }
    if let Ok(exit) = client.get_exit_state(client.address).await {
        for line in super::unstake::describe_exit(&exit) {
            // `status` aligns these in columns; here they follow a label.
            let line = line.split_whitespace().collect::<Vec<_>>().join(" ");
            report.say(Level::Info, "exit", line);
        }
    }
}

fn host_checks(report: &mut Report, config: &ZkMinerConfig) {
    report.section("This host");
    let home = super::run::zkminer_home();
    // Read-only probes: whether a miner holds the instance lock, what it left in the journal.
    // (Taking the lock to probe it holds it for an instant: a miner started in that instant would
    // be told another one is running.)
    let lock = home.join("miner.lock");
    let running = match std::fs::OpenOptions::new().write(true).open(&lock) {
        Ok(f) => match f.try_lock() {
            Ok(()) => Some(false),
            Err(std::fs::TryLockError::WouldBlock) => Some(true),
            Err(std::fs::TryLockError::Error(_)) => None,
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Some(false),
        Err(_) => None,
    };
    report.say(
        Level::Info,
        "miner",
        match running {
            Some(true) => {
                "a zkminer is running under this home (miner, benchmark, or a stake prompt)".into()
            }
            Some(false) => "none running under this home".to_string(),
            None => format!("unknown: cannot open {} to check", lock.display()),
        },
    );
    let running = running.unwrap_or(false);
    if super::run::stop_request_path().exists() {
        report.say(
            Level::Warn,
            "stop request",
            format!(
                "{} is waiting: a miner still starting up acts on it, the next start removes it \
                 unread, and `rm` withdraws it",
                super::run::stop_request_path().display()
            ),
        );
    }
    let journal = crate::journal::JobJournal::load();
    // Only locks a start can still finish or release: a breadcrumb past its cutoff is kept until a
    // keeper slashes it, and nothing the operator does changes it.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let live: Vec<u64> = journal
        .iter()
        .filter(|e| e.lock_deadline == 0 || e.lock_deadline > now)
        .map(|e| e.lock_deadline)
        .collect();
    if !live.is_empty() {
        report.say(
            if running { Level::Info } else { Level::Warn },
            "locks",
            format!(
                "{} recorded in the job journal{}",
                live.len(),
                if running {
                    String::new()
                } else {
                    format!(
                        " — start the miner {} so it finishes or releases them",
                        super::run::start_by(live.iter().copied())
                            .map(|t| format!("by {t}"))
                            .unwrap_or_else(|| "soon".into())
                    )
                }
            ),
        );
    }

    // Disk: the first proof downloads the zkVMs' artifacts.
    let user_home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
    let fetched = |dir: &str| user_home.join(dir).is_dir();
    let missing: Vec<&str> = [".risc0", ".sp1"]
        .into_iter()
        .filter(|d| !fetched(d))
        .collect();
    match free_bytes(&user_home) {
        // A warning: a host that proves only one zkVM downloads less.
        Some(free) if !missing.is_empty() && free < FIRST_RUN_DOWNLOAD_BYTES => report.say(
            Level::Warn,
            "disk",
            format!(
                "{:.1} GiB free in {}; the first run downloads about 16-20 GB into {}",
                free as f64 / GIB,
                user_home.display(),
                missing.join(" and ")
            ),
        ),
        Some(free) => report.say(
            Level::Pass,
            "disk",
            format!(
                "{:.1} GiB free in {}{}",
                free as f64 / GIB,
                user_home.display(),
                if missing.is_empty() {
                    String::new()
                } else {
                    format!(
                        " (the first run downloads about 16-20 GB into {})",
                        missing.join(" and ")
                    )
                }
            ),
        ),
        None => report.say(Level::Info, "disk", "free space unreadable"),
    }

    // Card by card, as `zkminer run` would start them (nothing is started here).
    let explicit = config
        .prover
        .worker_binaries
        .iter()
        .map(|(k, v)| (k.clone(), PathBuf::from(v)))
        .collect();
    let search: Vec<PathBuf> = config
        .prover
        .worker_search_paths
        .iter()
        .map(PathBuf::from)
        .collect();
    let survey = zkminer_prover::dispatcher::check_workers(&explicit, &search);
    let sizes: super::capability::Risc0Sizes = config
        .prover
        .risc0_job_po2
        .iter()
        .map(|(k, v)| (k.clone(), *v))
        .collect();
    let suite = zkminer_prover::benchmark::load_cached_benchmark();
    let rows = super::capability::rows(
        &survey,
        &super::run::served_backends(),
        &sizes,
        suite.as_ref(),
    );
    for row in &rows {
        let (level, word, why) = match &row.verdict {
            super::capability::Verdict::Ready(w) => (Level::Pass, "proves", w),
            super::capability::Verdict::Risky(w) => (Level::Warn, "proves, at a risk", w),
            super::capability::Verdict::Idle(w) => (Level::Warn, "idle", w),
            super::capability::Verdict::Missing(w) => (Level::Warn, "not available", w),
        };
        let what = format!("{} · {}", row.card, row.zkvm);
        if why.is_empty() {
            report.say(level, &what, word);
        } else {
            report.say(level, &what, format!("{word} — {why}"));
        }
    }
    if !super::capability::anything_proves(&rows) {
        report.say(
            Level::Fail,
            "proving",
            "nothing on this host can prove a job the miner claims, so it will claim none",
        );
    }
    #[cfg(windows)]
    if survey.gpus.iter().any(|g| g.gpu_tag == "cuda") {
        sysmem_fallback_check(report);
    }
    sp1_shard_caps_check(report, zkminer_prover::sp1_shard_caps::default_path());
    report.say(
        Level::Info,
        "workers",
        "found and matched to the cards above; whether each one's build matches this miner is \
         checked when the miner starts it (rebuild or reinstall them all together)",
    );
    if suite.is_none() {
        report.say(
            Level::Info,
            "benchmark",
            "no saved benchmark for this hardware: `zkminer run` measures the cards first (or run \
             `zkminer benchmark --calibrate` beforehand; a plain `zkminer benchmark` saves \
             nothing)",
        );
    }
}

/// The cards whose SP1 shard size is capped because a proof there ran out of GPU memory
/// (`zkminer_prover::sp1_shard_caps`), each on a line of its own. Nothing when there are none.
fn sp1_shard_caps_check(report: &mut Report, path: std::path::PathBuf) {
    let store = match zkminer_prover::sp1_shard_caps::Store::load_checked(path.clone()) {
        Ok(store) => store,
        Err(e) => {
            report.say(
                Level::Warn,
                "SP1 shard size",
                format!("{e}: no card's cap is applied, and none is recorded until it is fixed or removed"),
            );
            return;
        }
    };
    for card in store.cards() {
        report.say(
            Level::Info,
            "SP1 shard size",
            format!(
                "{} ({}), if it is still this card, is capped at {} elements: an SP1 job ran \
                 out of GPU memory at a larger size there and proved at this one, so every run \
                 since sizes it no larger. To lift it, stop the miner and remove the card's entry \
                 from {} (or the file)",
                card.gpu_name,
                card.pci_bus_id,
                card.max_element_threshold,
                path.display(),
            ),
        );
    }
}

/// What the NVIDIA driver does, under Windows, when a CUDA worker's allocation finds its card full:
/// its CUDA - Sysmem Fallback Policy, for the programs that allocate on the card. Information, not a
/// verdict: falling back keeps a proof going, slowly, where failing ends it at once.
#[cfg(windows)]
fn sysmem_fallback_check(report: &mut Report) {
    use zkminer_prover::windows_nvapi::cuda_sysmem_fallback_policy;
    const PROGRAMS: [&str; 3] = [
        "zkminer-prove-risc0-cuda.exe",
        "zkminer-prove-sp1.exe",
        "sp1-gpu-server.exe",
    ];
    let what = "CUDA sysmem fallback";
    let Some(policy) = cuda_sysmem_fallback_policy(&PROGRAMS) else {
        report.say(
            Level::Info,
            what,
            "unknown: the NVIDIA driver's settings could not be read",
        );
        return;
    };
    let own: Vec<String> = policy
        .programs
        .iter()
        .filter(|(_, v)| *v != policy.global)
        .map(|(name, v)| format!("{v} for {name}"))
        .collect();
    let setting = if own.is_empty() {
        format!("{} for the workers", policy.global)
    } else {
        format!("{} globally, {}", policy.global, own.join(", "))
    };
    let falls_back: Vec<Option<bool>> = policy
        .programs
        .iter()
        .map(|(_, v)| v.falls_back())
        .collect();
    let detail = if falls_back.contains(&None) {
        format!("{setting}: a value this build does not know, so what it does is not said here")
    } else if falls_back.contains(&Some(true)) {
        format!(
            "{setting}. A proof that outgrows its card (something took VRAM after it started) then \
             moves into system memory and runs several times slower: it may still finish, or miss \
             its deadline. \"Prefer No Sysmem Fallback\" (NVIDIA Control Panel → Manage 3D \
             settings → CUDA - Sysmem Fallback Policy, globally or for {}) makes it fail at once, \
             and the job is retried or released (a release costs 5% of its collateral): which is \
             better depends on how much slack your jobs' deadlines leave",
            PROGRAMS.join(", ")
        )
    } else {
        format!(
            "{setting}: a proof that outgrows its card fails at once and the job is retried or \
             released, rather than slowing down in system memory"
        )
    };
    report.say(Level::Info, what, detail);
}

pub async fn run(config_path: Option<&Path>) -> Result<()> {
    let mut report = Report::default();
    println!("zkminer doctor — signs and sends nothing, starts no worker");
    report.section("Config");
    let config = match ZkMinerConfig::load(config_path) {
        Ok(c) => {
            let path = config_path
                .map(Path::to_path_buf)
                .unwrap_or_else(|| ZkMinerConfig::default_dir().join("config.toml"));
            // A missing file loads as defaults: often the wrong user or home (a service's config
            // lives in the service account's home).
            let level = if path.exists() {
                Level::Pass
            } else {
                Level::Warn
            };
            if !path.exists() {
                report.say(
                    Level::Warn,
                    "config",
                    format!(
                        "no file at {}: using defaults. Running as the right user (a service's \
                         config is in its own home)?",
                        path.display()
                    ),
                );
            }
            report.say(
                level,
                "config",
                format!(
                    "{} (chain {}, {})",
                    path.display(),
                    c.chain.chain_id,
                    match zkminer_chain::deployment::known_deployment(c.chain.chain_id) {
                        Some(_) if c.chain.chain_id == zkminer_chain::staking::TESTNET_CHAIN_ID =>
                            "Hemi testnet",
                        Some(_) => "a known deployment",
                        None => "no known deployment",
                    }
                ),
            );
            Some(c)
        }
        Err(e) => {
            report.say(Level::Fail, "config", redact(&e));
            None
        }
    };
    if let Some(c) = &config {
        match c.validate_for_chain() {
            Ok(()) => chain_checks(&mut report, c).await,
            Err(e) => report.say(Level::Fail, "config", redact(&e)),
        }
    }
    let host_config = config.clone().unwrap_or_default();
    // Blocking probes (nvidia-smi, sysfs, the disk), off the runtime.
    let mut host_report = Report::default();
    let host_report = tokio::task::spawn_blocking(move || {
        host_checks(&mut host_report, &host_config);
        host_report
    })
    .await?;
    report.warnings += host_report.warnings;
    report.failures += host_report.failures;

    println!();
    match (report.failures, report.warnings) {
        (0, 0) => println!("All checks passed."),
        (0, w) => println!("{w} warning(s), nothing blocking."),
        (f, w) => println!("{f} problem(s) that stop the miner, {w} warning(s)."),
    }
    if report.failures > 0 {
        std::process::exit(1);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The RPC URL is shown by host only: providers put API keys in the path or query.
    #[test]
    fn rpc_urls_lose_their_secrets() {
        assert_eq!(
            rpc_host("https://rpc.example.com/v2/SECRETKEY"),
            "rpc.example.com"
        );
        assert_eq!(
            rpc_host("https://rpc.example.com?apikey=SECRET"),
            "rpc.example.com"
        );
        assert_eq!(
            rpc_host("https://user:pass@rpc.example.com:8545/x"),
            "rpc.example.com:8545"
        );
        assert_eq!(rpc_host("http://127.0.0.1:8546"), "127.0.0.1:8546");
    }

    #[test]
    fn free_space_is_readable_here() {
        let here = std::env::temp_dir();
        assert!(free_bytes(&here).is_some_and(|b| b > 0));
    }
}
