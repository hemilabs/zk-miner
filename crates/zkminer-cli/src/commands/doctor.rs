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
    /// Tests only: every line said, as (level, what, detail).
    #[cfg(test)]
    lines: Vec<(Level, String, String)>,
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
        #[cfg(test)]
        self.lines
            .push((level, what.to_string(), detail.as_ref().to_string()));
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

/// Windows: the key in a file (`key_source = "file"`, or `<home>/.env` beside an `env` key source,
/// which is only checked for, never read). Windows has no owner-only file a process of the same
/// user cannot read, so any process run as this user can read it; with Low-integrity workers
/// (`low_il`) at least the prover workers cannot.
#[cfg(any(windows, test))]
fn key_on_disk_warning(
    wallet: &zkminer_config::config::WalletConfig,
    home: &Path,
    low_il: bool,
) -> Option<String> {
    let what = match wallet.key_source.as_str() {
        "file" => format!(
            "the key file {}",
            wallet.key_file_path.as_deref().unwrap_or("(unset)")
        ),
        "env" if home.join(".env").exists() => {
            format!("{}, if it holds the key,", home.join(".env").display())
        }
        _ => return None,
    };
    Some(if low_il {
        format!(
            "{what} can be read by any process run as this user; the prover workers cannot (they              run at Low integrity)"
        )
    } else {
        format!(
            "{what} can be read by any process run as this user, a prover worker included (and the              guest programs it runs, should one break out). Set ZKMINER_WINDOWS_LOW_IL_WORKERS=1 to              keep the workers from it"
        )
    })
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
    #[cfg(windows)]
    if let Some(warning) = key_on_disk_warning(
        &config.wallet,
        &ZkMinerConfig::default_dir(),
        zkminer_prover::windows_sandbox::low_il_workers(),
    ) {
        report.say(Level::Warn, "key", warning);
    }
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
    let journal = crate::journal::JobJournal::peek();
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
    #[cfg(windows)]
    if let Some(figures) = zkminer_prover::memory::commit_figures() {
        let learned = zkminer_prover::host_peaks::load(&zkminer_prover::host_peaks::default_path());
        commit_check(report, figures, |backend| {
            learned
                .values()
                .filter(|c| c.card.split('@').next() == Some(backend))
                .flat_map(|c| c.commit.values().copied())
                .max()
        });
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

/// Windows: whether this host can commit what a proof of each zkVM commits (`memory::CommitFigures`):
/// the most its proofs here took (`learned`, raw, with an eighth added as the miner charges it), else
/// the default. A host that cannot is never given that zkVM's jobs, and says nothing about it
/// unless asked: on a ~100 GB commit limit an SP1 proof (63 GB at once on a 5090) fits only with most
/// of it free, so the page file decides.
#[cfg_attr(not(windows), allow(dead_code))]
fn commit_check(
    report: &mut Report,
    figures: zkminer_prover::memory::CommitFigures,
    learned: impl Fn(&str) -> Option<u64>,
) {
    const GIB: f64 = (1u64 << 30) as f64;
    let gib = |b: u64| b as f64 / GIB;
    let reserve = zkminer_prover::memory::DEFAULT_HOST_RESERVE_BYTES;
    report.say(
        Level::Info,
        "commit",
        format!(
            "limit {:.0} GiB now, at most {:.0} GiB as the page files grow; {:.0} GiB free now",
            gib(figures.limit),
            gib(figures.total),
            gib(figures.free_now),
        ),
    );
    for (backend, name) in [("sp1", "SP1"), ("risc0", "RISC Zero")] {
        let need = learned(backend)
            .map(|peak| peak / 8 * 9)
            .unwrap_or_else(|| zkminer_prover::memory::unmeasured_commit_for(backend));
        // What the miner charges a proof is capped to what this host can admit at all
        // (`memory::max_admissible_budget`): past it, the job is still claimed, charged the cap.
        let charged = need.min(zkminer_prover::memory::max_admissible_budget(figures.total));
        if need.saturating_add(reserve) > figures.total {
            report.say(
                Level::Warn,
                "commit",
                format!(
                    "a {name} proof commits about {:.0} GiB, more than this host can ever \
                     commit ({:.0} GiB with {:.0} GiB kept for Windows): its jobs are claimed, \
                     charged {:.0} GiB, and their proofs can fail for want of commit. A larger \
                     page file fixes it (System Properties -> Advanced -> Performance -> Virtual \
                     memory): {:.0} GB more at least",
                    gib(need),
                    gib(figures.total),
                    gib(reserve),
                    gib(charged),
                    (gib(need.saturating_add(reserve) - figures.total) + 1.0).ceil(),
                ),
            );
        } else if charged.saturating_add(reserve) > figures.available {
            report.say(
                Level::Info,
                "commit",
                format!(
                    "a {name} proof commits about {:.0} GiB, more than is free now ({:.0} GiB \
                     with page-file growth): its jobs wait until programs give memory back",
                    gib(need),
                    gib(figures.available),
                ),
            );
        }
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

/// What happens, under Windows, when an SP1 proof on an NVIDIA card runs short of video memory, and
/// what NVIDIA's CUDA - Sysmem Fallback Policy changes. Measured on an RTX 4070 (driver 621.24): at
/// the default, an SP1 server that outgrew the card spilled into system memory (408 s instead of
/// 33); with "Prefer No Sysmem Fallback" it ran out at once and the proof was retried one shard
/// size smaller. Memory another program took mid-proof slowed it either way (336 s), as Windows
/// pages between the two. The setting's value is hidden from NVAPI's reads (only the driver's own
/// export shows it), so doctor states what it does rather than a value it cannot see.
#[cfg(windows)]
fn sysmem_fallback_check(report: &mut Report) {
    report.say(Level::Info, "CUDA sysmem fallback", SYSMEM_BEHAVIOUR);
}

#[cfg(windows)]
const SYSMEM_BEHAVIOUR: &str = "not readable here (the NVIDIA driver hides its CUDA - Sysmem \
     Fallback Policy). At the default, a proof that outgrows its card moves into system memory and \
     runs many times slower, which can cost a lock. The SP1 server refuses that memory itself, so \
     an SP1 proof fails at once and is retried one shard size smaller whatever the setting; for \
     RISC Zero, \"Prefer No Sysmem Fallback\" (NVIDIA Control Panel → Manage 3D settings, globally \
     or for zkminer-prove-risc0-cuda.exe) does that. Memory another program takes while a proof \
     runs is paged by Windows either way: the miner sees it, shows it on the dashboard, and runs \
     the proof again where it fits";

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

    /// Windows' warning on a key in a file: a key file always, `.env` only if there is one, and
    /// a plain `env` source never.
    #[test]
    fn doctor_warns_of_a_key_any_process_of_the_user_can_read() {
        let home = TempDir::new("key-on-disk");
        let mut wallet = zkminer_config::config::WalletConfig {
            key_source: "file".into(),
            key_file_path: Some(r"C:\keys\miner.key".into()),
            ..Default::default()
        };
        let w = key_on_disk_warning(&wallet, &home.0, false).unwrap();
        assert!(
            w.contains("miner.key") && w.contains("ZKMINER_WINDOWS_LOW_IL_WORKERS=1"),
            "{w}"
        );
        let w = key_on_disk_warning(&wallet, &home.0, true).unwrap();
        assert!(w.contains("workers cannot"), "{w}");
        wallet.key_source = "env".into();
        assert_eq!(key_on_disk_warning(&wallet, &home.0, false), None);
        std::fs::write(home.0.join(".env"), "").unwrap();
        let w = key_on_disk_warning(&wallet, &home.0, false).unwrap();
        assert!(w.contains(".env, if it holds the key,"), "{w}");
    }

    #[test]
    fn free_space_is_readable_here() {
        let here = std::env::temp_dir();
        assert!(free_bytes(&here).is_some_and(|b| b > 0));
    }

    /// A temporary directory, removed when dropped.
    struct TempDir(PathBuf);

    impl TempDir {
        fn new(name: &str) -> Self {
            let dir = std::env::temp_dir().join(format!("zkminer-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// doctor lists each capped card, qualified as "if it is still this card", says nothing when
    /// there is no record, and warns on a record that cannot be read (no cap applies then).
    #[test]
    fn doctor_lists_each_capped_card_and_warns_on_an_unreadable_record() {
        let dir = TempDir::new("doctor-caps");
        let path = dir.0.join(zkminer_prover::sp1_shard_caps::FILE_NAME);
        let said = |path: &Path| {
            let mut report = Report::default();
            sp1_shard_caps_check(&mut report, path.to_path_buf());
            report
        };
        let none = said(&path);
        assert!(none.lines.is_empty());
        assert_eq!(none.warnings, 0);

        let mut store = zkminer_prover::sp1_shard_caps::Store::load(path.clone());
        store
            .lower(
                "0000:03:00.0",
                "NVIDIA GeForce RTX 4070",
                12_282 << 20,
                134_217_728,
                1,
            )
            .unwrap();
        store
            .lower(
                "0000:04:00.0",
                "NVIDIA GeForce RTX 4070",
                12_282 << 20,
                134_217_728,
                2,
            )
            .unwrap();
        let capped = said(&path);
        assert_eq!(capped.lines.len(), 2);
        for (level, what, detail) in &capped.lines {
            assert_eq!(*level, Level::Info);
            assert_eq!(what, "SP1 shard size");
            assert!(detail.contains("if it is still this card"), "{detail}");
            assert!(detail.contains("capped at 134217728 elements"), "{detail}");
            assert!(detail.contains("stop the miner"), "{detail}");
        }
        assert!(capped.lines[0].2.contains("0000:03:00.0"));

        std::fs::write(&path, "not a record").unwrap();
        let unreadable = said(&path);
        assert_eq!(unreadable.warnings, 1);
        assert_eq!(unreadable.lines.len(), 1);
        assert!(unreadable.lines[0].2.contains("no card's cap is applied"));
    }

    /// A host that can never commit what a zkVM's proof commits is told so, with the page file to set.
    #[test]
    fn doctor_says_when_a_proof_cannot_ever_be_committed() {
        const G: u64 = 1 << 30;
        let figures = zkminer_prover::memory::CommitFigures {
            available: 90 * G,
            total: 100 * G,
            free_now: 60 * G,
            limit: 100 * G,
        };
        // A learned SP1 peak of 96 GiB is charged 108: past the 100 GiB limit.
        let mut report = Report::default();
        commit_check(&mut report, figures, |b| (b == "sp1").then_some(96 * G));
        let warned: Vec<&String> = report
            .lines
            .iter()
            .filter(|(l, w, _)| *l == Level::Warn && w == "commit")
            .map(|(_, _, d)| d)
            .collect();
        assert_eq!(warned.len(), 1);
        assert!(warned[0].contains("SP1 proof commits about 108 GiB"));
        assert!(warned[0].contains("claimed, charged 72 GiB"));
        assert!(warned[0].contains("12 GB more at least"));
        // RISC Zero's 30 GiB default fits.
        assert!(!report.lines.iter().any(|(_, _, d)| d.contains("RISC Zero")));
    }

    /// What doctor says of GPU memory under Windows: the measured behaviour, not a driver setting
    /// it cannot read.
    #[cfg(windows)]
    #[test]
    fn doctor_says_how_windows_handles_a_proof_short_of_gpu_memory() {
        assert!(SYSMEM_BEHAVIOUR.starts_with("not readable here"));
        assert!(SYSMEM_BEHAVIOUR.contains("system memory"));
        assert!(SYSMEM_BEHAVIOUR.contains("\"Prefer No Sysmem Fallback\""));
        assert!(SYSMEM_BEHAVIOUR.contains("retried one shard size smaller"));
        assert!(SYSMEM_BEHAVIOUR.contains("another program"));
        assert!(!SYSMEM_BEHAVIOUR.contains("  "), "{SYSMEM_BEHAVIOUR}");
    }
}
