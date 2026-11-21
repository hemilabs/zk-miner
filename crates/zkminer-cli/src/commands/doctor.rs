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

/// Windows, an `env` key source: what to say of each copy of the key's variable kept in the
/// registry (`zkminer_config::wallet_win`), given as (where, readable by every user of this PC).
#[cfg(any(windows, test))]
fn key_env_copy_findings(copies: &[(String, bool)]) -> Vec<(Level, String)> {
    copies
        .iter()
        .map(|(place, machine_wide)| {
            if *machine_wide {
                (
                    Level::Fail,
                    format!(
                        "{place} holds the key's variable: every user of this PC can read it \
                         there, and so can any process of theirs, Low-integrity ones included. \
                         Move the key to a key file only the miner's account can read \
                         (key_source = \"file\"; README: Windows service), then delete that value"
                    ),
                )
            } else {
                (
                    Level::Warn,
                    format!(
                        "{place} holds the key's variable (setx or System Properties): every \
                         process of this user can read it there, Low-integrity workers included. \
                         Move the key to a key file (key_source = \"file\"), then delete that \
                         value"
                    ),
                )
            }
        })
        .collect()
}

async fn chain_checks(report: &mut Report, config: &ZkMinerConfig) {
    report.section("Chain and funds");
    // Before the key is loaded: a copy kept in the registry is there whether or not this
    // process was given the variable.
    #[cfg(windows)]
    if config.wallet.key_source == "env" {
        let copies: Vec<(String, bool)> =
            zkminer_config::wallet_win::persisted_key_env_copies(&config.wallet.key_env_var)
                .into_iter()
                .map(|c| (c.location, c.machine_wide))
                .collect();
        for (level, finding) in key_env_copy_findings(&copies) {
            report.say(level, "key", finding);
        }
    }
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

/// Windows: what to say of the account this runs as (`windows_sandbox::account_risk`), as `run`
/// would treat it: a service account fails (`run` refuses it, unless `allowed`), an elevated token
/// warns.
#[cfg(windows)]
fn account_finding(
    risk: Option<zkminer_prover::windows_sandbox::AccountRisk>,
    allowed: bool,
) -> (Level, String) {
    use zkminer_prover::windows_sandbox::{AccountRisk, ALLOW_PRIVILEGED_ACCOUNT_ENV};
    match risk {
        Some(AccountRisk::ServiceAccount(account)) => (
            Level::Fail,
            format!(
                "{account}: `zkminer run` {} as it: every prover worker would run as {account} \
                 too, and the miner could keep none of them from its key. Run the miner as a \
                 dedicated standard user (README: Windows service)",
                if allowed {
                    format!("runs ({ALLOW_PRIVILEGED_ACCOUNT_ENV}=1), paged,")
                } else {
                    "refuses to run".to_string()
                }
            ),
        ),
        Some(AccountRisk::Elevated) => (
            Level::Warn,
            "elevated (administrator rights): the prover workers would be too, so a requester's \
             guest that broke out of one would be an administrator of this PC. Run the miner \
             from a console that is not elevated, or as a dedicated standard user"
                .to_string(),
        ),
        None => (Level::Pass, "a standard account, not elevated".to_string()),
    }
}

/// Windows: what to say of the Low-integrity workers (`windows_sandbox`): whether they are on
/// (`on`), the flag's value if it is set to something other than `1` (`misset`), and the Low
/// directories found to be a file or a link (`tampered`).
#[cfg(any(windows, test))]
fn low_il_findings(on: bool, misset: Option<&str>, tampered: &[String]) -> Vec<(Level, String)> {
    let mut findings = Vec::new();
    if let Some(value) = misset {
        findings.push((
            Level::Warn,
            format!(
                "ZKMINER_WINDOWS_LOW_IL_WORKERS is {value:?}, not 1: the workers run at Medium \
                 integrity"
            ),
        ));
    } else if on {
        findings.push((
            Level::Pass,
            "on: the workers run at Low integrity. A worker that cannot start there is not \
             started at Medium instead: its slot proves nothing (PAGE: LOW-IL-WORKER-FAILED) \
             until one starts at Low, tried again with back-off"
                .to_string(),
        ));
    } else {
        findings.push((
            Level::Info,
            "off: the workers run at Medium integrity, able to read this user's files. \
             ZKMINER_WINDOWS_LOW_IL_WORKERS=1 runs them at Low"
                .to_string(),
        ));
    }
    if on {
        for dir in tampered {
            findings.push((
                Level::Warn,
                format!(
                    "{dir}, not a directory: only a Low-integrity process (a worker) or this \
                     account puts one there. The miner replaces it with a directory before its \
                     next Low worker"
                ),
            ));
        }
    }
    findings
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
    #[cfg(target_os = "linux")]
    {
        let (level, detail) = root_verdict(super::run::privilege::root_run_here());
        report.say(level, "user", detail);
        let (level, detail) = worker_memory_verdict();
        report.say(level, "worker memory", detail);
    }
    #[cfg(windows)]
    {
        use zkminer_prover::windows_sandbox as sandbox;
        let (level, detail) = match sandbox::account_risk() {
            Ok(risk) => account_finding(risk, sandbox::privileged_account_allowed()),
            Err(e) => (
                Level::Warn,
                format!("could not be read from this process's token ({e})"),
            ),
        };
        report.say(level, "account", detail);
        let on = sandbox::low_il_workers();
        let tampered = if on {
            sandbox::low_dirs_tampered()
        } else {
            Vec::new()
        };
        for (level, detail) in
            low_il_findings(on, sandbox::low_il_workers_misset().as_deref(), &tampered)
        {
            report.say(level, "Low-integrity workers", detail);
        }
    }
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

/// Linux: what running as this user means for the workers (review r4 LD2). Root on a bare host is
/// a warning: the workers drop every capability, but as uid 0 they can still read root's files
/// (`run::privilege`).
#[cfg(target_os = "linux")]
fn root_verdict(run: super::run::privilege::RootRun) -> (Level, String) {
    use super::run::privilege::RootRun;
    match run {
        RootRun::NotRoot => (Level::Pass, "not root".to_string()),
        RootRun::Container => (
            Level::Info,
            "root in a container: the workers drop every capability; `--user` or `--cap-drop=ALL \
             --security-opt no-new-privileges` narrows it further"
                .to_string(),
        ),
        RootRun::BareHost => (
            Level::Warn,
            "root on this host: the workers drop every capability, but as uid 0 they could still \
             read root's files (/etc/shadow, SSH host keys, a service's environment file) after an \
             executor escape. Run the miner as an unprivileged user in the render and video groups \
             (contrib/zkminer.service); only the dashboard's GPU tuning needs root"
                .to_string(),
        ),
    }
}

/// The systemd unit the miner is documented to run as (`contrib/zkminer.service`).
#[cfg(target_os = "linux")]
const SERVICE: &str = "zkminer.service";

/// Linux: whether workers get a memory ceiling and a cgroup of their own (review r4 LD1). When
/// [`SERVICE`] is installed, its settings answer (doctor itself runs from a shell, not in it): it
/// needs `Delegate=` with `cpu memory pids`, and `OOMPolicy=continue`, or a worker's OOM kill stops
/// the whole miner. Otherwise, as run from here: a delegated cgroup, else the user's systemd
/// manager, which caps each worker in a scope of its own.
#[cfg(target_os = "linux")]
fn worker_memory_verdict() -> (Level, String) {
    let mut cmd = std::process::Command::new("systemctl");
    cmd.args([
        "show",
        "--property=LoadState,Delegate,DelegateControllers,OOMPolicy",
        "--",
        SERVICE,
    ])
    .stdin(std::process::Stdio::null());
    let (outcome, props) = zkminer_prover_protocol::proc::output_with_timeout_capturing_stdout(
        &mut cmd,
        Duration::from_secs(5),
        16 * 1024,
    );
    let ran = matches!(
        outcome,
        zkminer_prover_protocol::proc::Outcome::Ran { success: true, .. }
    );
    if ran && unit_property(&props, "LoadState") == Some("loaded") {
        return unit_verdict(SERVICE, &props);
    }
    match zkminer_witness_sandbox::delegation_status() {
        Ok(dir) => (
            Level::Pass,
            format!(
                "this cgroup is delegated ({}): each worker gets a cgroup of its own, with a \
                 memory ceiling",
                dir.display()
            ),
        ),
        Err(why) if zkminer_prover::containment::user_bus_reachable() => (
            Level::Info,
            format!(
                "not in a delegated cgroup ({why}); run from here, each worker is capped in a \
                 scope of your systemd user manager"
            ),
        ),
        Err(why) => (
            Level::Warn,
            format!(
                "not in a delegated cgroup ({why}), and no systemd user manager: run from here, \
                 workers would have no memory ceiling. Run it as contrib/zkminer.service \
                 (Delegate=cpu memory pids, OOMPolicy=continue) or under `systemd-run --user \
                 --scope -p Delegate=yes`"
            ),
        ),
    }
}

/// The value of `key` in `systemctl show` output (`Key=Value` lines).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn unit_property<'a>(props: &'a str, key: &str) -> Option<&'a str> {
    props
        .lines()
        .find_map(|l| l.strip_prefix(key)?.strip_prefix('='))
        .map(str::trim)
}

/// What a loaded unit's `Delegate`, `DelegateControllers` and `OOMPolicy` mean for its workers.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn unit_verdict(unit: &str, props: &str) -> (Level, String) {
    let mut problems = Vec::new();
    if unit_property(props, "Delegate") != Some("yes") {
        problems.push(
            "no Delegate=, so workers get no memory ceiling and no cgroup of their own".to_string(),
        );
    } else if let Some(given) =
        unit_property(props, "DelegateControllers").filter(|c| !c.is_empty())
    {
        let missing: Vec<&str> = ["cpu", "memory", "pids"]
            .into_iter()
            .filter(|c| !given.split_whitespace().any(|g| g == *c))
            .collect();
        if !missing.is_empty() {
            problems.push(format!(
                "Delegate= leaves out {}, without which the miner uses no delegation",
                missing.join(" ")
            ));
        }
    }
    // systemd before 243 has neither the property nor the stop.
    if unit_property(props, "OOMPolicy") == Some("stop") {
        problems.push(
            "OOMPolicy=stop, so a worker's OOM kill stops the whole miner (a drain, then a \
             restart)"
                .to_string(),
        );
    }
    if problems.is_empty() {
        (
            Level::Pass,
            format!(
                "{unit} delegates its cgroup (each worker gets one of its own, with a memory \
                 ceiling) and keeps running when one is OOM-killed"
            ),
        )
    } else {
        (
            Level::Warn,
            format!(
                "{unit}: {}. Add Delegate=cpu memory pids and OOMPolicy=continue to it \
                 (contrib/zkminer.service has both), then `systemctl daemon-reload` and restart it",
                problems.join("; ")
            ),
        )
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

    #[cfg(target_os = "linux")]
    #[test]
    fn doctor_warns_of_root_on_a_bare_host_only() {
        use super::super::run::privilege::RootRun;
        assert_eq!(root_verdict(RootRun::NotRoot).0, Level::Pass);
        assert_eq!(root_verdict(RootRun::Container).0, Level::Info);
        let (level, detail) = root_verdict(RootRun::BareHost);
        assert_eq!(level, Level::Warn);
        assert!(detail.contains("unprivileged user"), "{detail}");
        assert!(!detail.contains("  "), "{detail}");
    }

    /// Review r4 LD1: a unit without delegation, or with `OOMPolicy=stop`, is a warning naming the
    /// fix; the shipped unit's settings pass.
    #[test]
    fn doctor_checks_the_units_delegation_and_oom_policy() {
        let shipped = "LoadState=loaded\nDelegate=yes\nDelegateControllers=cpu memory pids\n\
                       OOMPolicy=continue\n";
        assert_eq!(unit_verdict("zkminer.service", shipped).0, Level::Pass);
        // Delegate=yes alone delegates every controller.
        let all = "LoadState=loaded\nDelegate=yes\nDelegateControllers=cpu cpuacct cpuset io \
                   blkio memory devices pids bpf-firewall bpf-devices\nOOMPolicy=continue\n";
        assert_eq!(unit_verdict("zkminer.service", all).0, Level::Pass);
        // The unit as it was: no delegation, systemd's default OOMPolicy.
        let old = "LoadState=loaded\nDelegate=no\nDelegateControllers=\nOOMPolicy=stop\n";
        let (level, detail) = unit_verdict("zkminer.service", old);
        assert_eq!(level, Level::Warn);
        assert!(detail.contains("no Delegate="), "{detail}");
        assert!(detail.contains("OOMPolicy=stop"), "{detail}");
        assert!(
            detail.contains("Delegate=cpu memory pids and OOMPolicy=continue"),
            "{detail}"
        );
        let partial = "Delegate=yes\nDelegateControllers=memory\nOOMPolicy=continue\n";
        let (level, detail) = unit_verdict("zkminer.service", partial);
        assert_eq!(level, Level::Warn);
        assert!(detail.contains("leaves out cpu pids"), "{detail}");
        let only_oom = "Delegate=yes\nDelegateControllers=cpu memory pids\nOOMPolicy=stop\n";
        assert_eq!(unit_verdict("zkminer.service", only_oom).0, Level::Warn);
        // systemd before 243: no OOMPolicy at all, and nothing to warn about there.
        assert_eq!(
            unit_verdict("zkminer.service", "Delegate=yes\nDelegateControllers=\n").0,
            Level::Pass
        );
        for (_, d) in [unit_verdict("u", old), unit_verdict("u", shipped)] {
            assert!(!d.contains("  "), "{d}");
        }
        assert_eq!(unit_property("DelegateControllers=cpu\n", "Delegate"), None);
        assert_eq!(
            unit_property(" \nLoadState=loaded\n", "LoadState"),
            Some("loaded")
        );
    }

    /// The shipped unit keeps what the miner relies on: a delegated cgroup with the controllers the
    /// worker cgroups need, OOM kills of workers not stopping the unit, and a stop that drains.
    #[test]
    fn the_shipped_systemd_unit_delegates_and_drains() {
        let unit = include_str!("../../../../contrib/zkminer.service");
        let service: Vec<(&str, &str)> = unit
            .lines()
            .skip_while(|l| l.trim() != "[Service]")
            .take_while(|l| l.trim() != "[Install]")
            .filter(|l| !l.trim_start().starts_with('#'))
            .filter_map(|l| l.split_once('='))
            .map(|(k, v)| (k.trim(), v.trim()))
            .collect();
        let value = |key: &str| {
            service
                .iter()
                .filter(|(k, _)| *k == key)
                .map(|(_, v)| *v)
                .next_back()
        };
        let delegate = value("Delegate").expect("Delegate= in [Service]");
        for c in ["cpu", "memory", "pids"] {
            assert!(
                delegate == "yes" || delegate.split_whitespace().any(|d| d == c),
                "Delegate={delegate} leaves out {c}"
            );
        }
        assert_eq!(value("OOMPolicy"), Some("continue"));
        assert_eq!(value("KillMode"), Some("mixed"));
        assert_eq!(value("KillSignal"), Some("SIGINT"));
        // A private /tmp would hide the Docker Groth16 helper's work directory from the daemon.
        assert_ne!(value("PrivateTmp"), Some("yes"));
        // Each of these would put the GPU nodes or the delegated cgroup out of reach.
        for key in ["PrivateDevices", "ProtectControlGroups", "DevicePolicy"] {
            assert_eq!(value(key), None, "{key}");
        }
    }

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

    /// Windows, an `env` key: a copy in the machine's or a service's environment fails (every user
    /// reads it), one in the user's own environment warns, and each names where it is and what to
    /// do instead.
    #[test]
    fn doctor_flags_a_key_kept_in_a_readable_environment() {
        assert!(key_env_copy_findings(&[]).is_empty());
        let found = key_env_copy_findings(&[
            (
                r"HKLM\SYSTEM\CurrentControlSet\Services\zkminer\Parameters (AppEnvironmentExtra)"
                    .into(),
                true,
            ),
            (r"HKCU\Environment (ZKMINER_PRIVATE_KEY)".into(), false),
        ]);
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].0, Level::Fail);
        assert!(
            found[0].1.contains("AppEnvironmentExtra")
                && found[0].1.contains("every user of this PC")
                && found[0].1.contains("key file"),
            "{}",
            found[0].1
        );
        assert_eq!(found[1].0, Level::Warn);
        assert!(
            found[1].1.contains(r"HKCU\Environment") && found[1].1.contains("Low-integrity"),
            "{}",
            found[1].1
        );
    }

    /// Windows: a service account fails (refused, or run paged with the override), an elevated
    /// token warns, a standard one passes.
    #[cfg(windows)]
    #[test]
    fn doctor_reports_a_privileged_account() {
        use zkminer_prover::windows_sandbox::{AccountRisk, ALLOW_PRIVILEGED_ACCOUNT_ENV};
        let (level, text) =
            account_finding(Some(AccountRisk::ServiceAccount("LocalSystem")), false);
        assert_eq!(level, Level::Fail);
        assert!(
            text.contains("LocalSystem")
                && text.contains("refuses")
                && text.contains("standard user"),
            "{text}"
        );
        let (level, text) =
            account_finding(Some(AccountRisk::ServiceAccount("NetworkService")), true);
        assert_eq!(level, Level::Fail);
        assert!(text.contains(ALLOW_PRIVILEGED_ACCOUNT_ENV), "{text}");
        let (level, text) = account_finding(Some(AccountRisk::Elevated), false);
        assert_eq!(level, Level::Warn);
        assert!(text.contains("elevated"), "{text}");
        assert_eq!(account_finding(None, false).0, Level::Pass);
    }

    /// Windows' Low-integrity workers as doctor reports them: on (failing closed), off, a flag
    /// set to something other than 1 (which is off), and a Low directory that was tampered with.
    #[test]
    fn doctor_reports_the_low_integrity_workers_as_they_are() {
        let on = low_il_findings(true, None, &[]);
        assert_eq!(on.len(), 1);
        assert_eq!(on[0].0, Level::Pass);
        assert!(
            on[0].1.contains("not started at Medium") && on[0].1.contains("LOW-IL-WORKER-FAILED"),
            "{}",
            on[0].1
        );
        let off = low_il_findings(false, None, &["ignored".into()]);
        assert_eq!(off.len(), 1, "{off:?}");
        assert_eq!(off[0].0, Level::Info);
        assert!(off[0].1.contains("Medium"), "{}", off[0].1);
        let misset = low_il_findings(false, Some("true"), &[]);
        assert_eq!(misset[0].0, Level::Warn);
        assert!(misset[0].1.contains("\"true\""), "{}", misset[0].1);
        let tampered = low_il_findings(true, None, &[r"C:\x\worker\neo is a file".into()]);
        assert_eq!(tampered.len(), 2);
        assert_eq!(tampered[1].0, Level::Warn);
        assert!(tampered[1].1.contains("neo is a file"), "{}", tampered[1].1);
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
