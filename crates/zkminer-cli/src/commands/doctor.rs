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
            "{what} can be read by any process run as this user; the prover workers cannot (they \
             run at Low integrity)"
        )
    } else {
        format!(
            "{what} can be read by any process run as this user, a prover worker included (and the \
             guest programs it runs, should one break out): ZKMINER_WINDOWS_LOW_IL_WORKERS=0 runs \
             the workers at Medium. Unset it to keep them from it"
        )
    })
}

/// Windows, Low-integrity workers on: what to say of the key file, `.env` and the journal found
/// without a label that keeps the workers from reading them
/// (`windows_sandbox::secrets_unlabelled`), given as (file, whether this account can label it).
#[cfg(any(windows, test))]
fn secret_label_findings(unlabelled: &[(PathBuf, bool)]) -> Vec<(Level, String)> {
    unlabelled
        .iter()
        .map(|(file, labellable)| {
            if *labellable {
                (
                    Level::Info,
                    format!(
                        "{} is not labelled yet: the miner labels it unreadable to its \
                         Low-integrity workers when it starts",
                        file.display()
                    ),
                )
            } else {
                (
                    Level::Fail,
                    format!(
                        "{} cannot be labelled unreadable to Low-integrity workers by this account \
                         (it is private to it without the right to change its owner), so the \
                         miner starts no worker (PAGE: SECRETS-UNLABELLED). As an administrator, \
                         run `icacls \"{}\" /grant <account>:(WO)`, or make the account its owner",
                        file.display(),
                        file.display()
                    ),
                )
            }
        })
        .collect()
}

/// Windows, an `env` key source: what to say of each copy of the key's variable `var` kept in the
/// registry (`zkminer_config::wallet_win`), given as (where, readable by every user of this PC).
/// Both fail: a machine-wide copy is readable by every user, and with a copy in the user's own
/// environment no Low worker starts (`windows_sandbox::other_key_copies`). Each gives the steps
/// that keep the key: import, check the address, then delete (`wallet::key_env_move_steps`).
#[cfg(any(windows, test))]
fn key_env_copy_findings(var: &str, copies: &[(String, bool)]) -> Vec<(Level, String)> {
    copies
        .iter()
        .map(|(place, machine_wide)| {
            let steps = zkminer_config::wallet::key_env_move_steps(var, place);
            let what = if *machine_wide {
                "every user of this PC can read it there, and so can any process of theirs, \
                 Low-integrity ones included"
            } else {
                "every process of this user can read it there, Low-integrity workers included, so \
                 no Low worker starts while it exists (PAGE: SECRETS-UNLABELLED)"
            };
            (
                Level::Fail,
                format!("{place} holds the key's variable: {what}. Move the key: {steps}"),
            )
        })
        .collect()
}

/// A key file inside a folder a sync client uploads (review 7 HT-1): it has left this PC, and old
/// versions stay in the service's history and recycle bin.
fn cloud_key_file_finding(key_file: &str, folder: Option<String>) -> Option<String> {
    folder.map(|folder| {
        format!(
            "the key file {key_file} is inside {folder}, which a sync client uploads: the key is \
             in that cloud account and its version history, reachable from any device of whoever \
             holds the account. Consider it exposed: rotate it (`zkminer init --generate-key` with \
             a config outside that folder, then unstake, withdraw and move the funds from the old \
             address), and delete the copy and its old versions from the service"
        )
    })
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
        for (level, finding) in key_env_copy_findings(&config.wallet.key_env_var, &copies) {
            report.say(level, "key", finding);
        }
    }
    if config.wallet.key_source == "file" {
        if let Some(key_file) = config.wallet.key_file_path.as_deref() {
            let folder = zkminer_config::wallet::cloud_synced_folder(Path::new(key_file));
            if let Some(finding) = cloud_key_file_finding(key_file, folder) {
                report.say(Level::Fail, "key", finding);
            }
        }
    }
    // Linux: the key's files that other users can read or change (review r6 LS1). Before the key
    // is loaded: the unit's environment file is there whether or not this shell has the variable.
    #[cfg(target_os = "linux")]
    for finding in linux_key_file_findings(&config.wallet).await {
        report.say(Level::Fail, "key", finding);
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
    // With Low-integrity workers, the label that keeps them from the key: there, or settable.
    #[cfg(windows)]
    if zkminer_prover::windows_sandbox::low_il_workers() {
        let key_file = (config.wallet.key_source == "file")
            .then(|| config.wallet.key_file_path.as_deref().map(Path::new))
            .flatten();
        let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
        let unlabelled = zkminer_prover::windows_sandbox::secrets_unlabelled(
            key_file,
            &home,
            &crate::journal::JobJournal::default_path(),
        );
        for (level, finding) in secret_label_findings(&unlabelled) {
            report.say(level, "key", finding);
        }
        // Old unlabelled copies in Volume Shadow Copies: the miner refuses Low workers on an
        // exposure (SECRETS-IN-SNAPSHOT), and only warns of what it could not check.
        let snapshots = zkminer_prover::windows_snapshots::inspect(
            key_file,
            (config.wallet.key_source == "env").then_some(config.wallet.key_env_var.as_str()),
            Some(&home),
            dirs::config_dir().as_deref(),
        );
        if let Some(refusal) = snapshots.refusal() {
            report.say(
                Level::Fail,
                "key",
                format!("{refusal} (PAGE: SECRETS-IN-SNAPSHOT)"),
            );
        }
        if let Some(warning) = snapshots.warning() {
            report.say(Level::Warn, "key", warning);
        }
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
    // The slash latch: tripped, `run` takes no new work until `zkminer resume-claims`.
    let (latched, lines) = super::run::slash_latch::describe(client.chain_id, client.address);
    let slashed = client
        .get_prover_stats(client.address)
        .await
        .map_or_else(|_| "unreadable".to_string(), |s| s.jobs_slashed.to_string());
    report.say(
        if latched { Level::Fail } else { Level::Pass },
        "slash latch",
        format!("{} (jobsSlashed on chain: {slashed})", lines.join("; ")),
    );
    if let Ok(exit) = client.get_exit_state(client.address).await {
        for line in super::unstake::describe_exit(&exit) {
            // `status` aligns these in columns; here they follow a label.
            let line = line.split_whitespace().collect::<Vec<_>>().join(" ");
            report.say(Level::Info, "exit", line);
        }
    }
}

/// Windows: what to say of the account this runs as (`windows_sandbox::account_risk`), as `run`
/// would treat it: a service account or an administrator's service logon fails (`run` refuses it,
/// unless `allowed`), an administrator's console warns, elevated or not.
#[cfg(windows)]
fn account_finding(
    risk: Option<zkminer_prover::windows_sandbox::AccountRisk>,
    allowed: bool,
) -> (Level, String) {
    use zkminer_prover::windows_sandbox::{AccountRisk, ALLOW_PRIVILEGED_ACCOUNT_ENV};
    let run = if allowed {
        format!("runs ({ALLOW_PRIVILEGED_ACCOUNT_ENV}=1), paged,")
    } else {
        "refuses to run".to_string()
    };
    match risk {
        Some(AccountRisk::ServiceAccount(account)) => (
            Level::Fail,
            format!(
                "{account}: `zkminer run` {run} as it: every prover worker would run as {account} \
                 too, and the miner could keep none of them from its key. Run the miner as a \
                 dedicated standard user (README: Windows service)"
            ),
        ),
        Some(AccountRisk::AdminService) => (
            Level::Fail,
            format!(
                "an administrator under a service logon: `zkminer run` {run} as it: every prover \
                 worker would be an administrator of this PC. Run the miner as a dedicated \
                 standard user (README: Windows service)"
            ),
        ),
        Some(AccountRisk::Elevated) => (
            Level::Warn,
            "an administrator, elevated: the prover workers would be too, so a requester's \
             guest that broke out of one would be an administrator of this PC. Run the miner \
             from a console that is not elevated, or as a dedicated standard user"
                .to_string(),
        ),
        Some(AccountRisk::FilteredAdmin) => (
            Level::Warn,
            "an administrator, not elevated: UAC is not a security boundary, so a requester's \
             guest that broke out of a prover worker could become an administrator of this PC. \
             Run the miner as a dedicated standard user, or with \
             ZKMINER_WINDOWS_LOW_IL_WORKERS=1"
                .to_string(),
        ),
        None => (
            Level::Pass,
            "a standard account, not an administrator".to_string(),
        ),
    }
}

/// Windows: what to say of the privileges this account's token holds (`held`), and of a dry run of
/// the strip `run` does at start-up (`strip`: the names it removes, or why it failed).
#[cfg(windows)]
fn privilege_finding(held: &[String], strip: Result<Vec<String>, String>) -> (Level, String) {
    use zkminer_prover::windows_account::{dangerous, KEPT_PRIVILEGES};
    use zkminer_prover::windows_sandbox::ALLOW_PRIVILEGED_ACCOUNT_ENV;
    let dangerous = dangerous(held);
    match strip {
        Err(e) => (
            Level::Fail,
            format!(
                "they could not be removed from a copy of this token ({e}): `zkminer run` refuses \
                 to start (unless {ALLOW_PRIVILEGED_ACCOUNT_ENV}=1), as its workers would keep \
                 them{}",
                if dangerous.is_empty() {
                    String::new()
                } else {
                    format!(", {} among them", dangerous.join(", "))
                }
            ),
        ),
        Ok(_) if !dangerous.is_empty() => (
            Level::Warn,
            format!(
                "held by this account: {}. `zkminer run` removes them from itself and its workers \
                 at start-up; for a service, `sc privs <service> {}` removes them from the service \
                 wrapper too (README: Windows service)",
                dangerous.join(", "),
                KEPT_PRIVILEGES.join("/")
            ),
        ),
        Ok(_) => (
            Level::Pass,
            format!(
                "none that would make a worker an administrator; `zkminer run` keeps only {}",
                KEPT_PRIVILEGES.join(", ")
            ),
        ),
    }
}

/// Windows: what to say of the Low-integrity workers (`windows_sandbox`): whether they are on
/// (`on`; the default, off only with the flag at `0`), the flag's value if it is set to something
/// other than `0` or `1` (`misset`), and the Low directories found to be a file or a link
/// (`tampered`).
#[cfg(any(windows, test))]
fn low_il_findings(on: bool, misset: Option<&str>, tampered: &[String]) -> Vec<(Level, String)> {
    let mut findings = Vec::new();
    if on {
        findings.push((
            Level::Pass,
            "on (the default): the workers run at Low integrity, kept from the key file, .env and \
             the job journal. A worker that cannot start there is not started at Medium instead: \
             its slot proves nothing (PAGE: LOW-IL-WORKER-FAILED) until one starts at Low, tried \
             again with back-off"
                .to_string(),
        ));
        if let Some(value) = misset {
            findings.push((
                Level::Info,
                format!(
                    "ZKMINER_WINDOWS_LOW_IL_WORKERS is {value:?}, which is not 0: the workers run \
                     at Low integrity all the same"
                ),
            ));
        }
    } else {
        findings.push((
            Level::Warn,
            "off (ZKMINER_WINDOWS_LOW_IL_WORKERS=0): the workers run at Medium integrity, able to \
             read every file of this user's, the key file and .env included, should a guest \
             program break out of one (PAGE: MEDIUM-WORKERS at every start). Unset it to run \
             them at Low"
                .to_string(),
        ));
    }
    if on {
        for dir in tampered {
            findings.push((
                Level::Warn,
                format!(
                    "{dir}, not a directory: only a Low-integrity process (a worker) or this \
                     account puts one there. The miner replaces it with a directory before each \
                     Low worker it starts"
                ),
            ));
        }
    }
    findings
}

/// Windows: what to say of who can replace what the miner runs. `checked`: each file or directory
/// (the miner's program, its configuration, its workers, a service wrapper, and their
/// directories) with the principals other than SYSTEM, Administrators, TrustedInstaller and this
/// account that can write it (`windows_account::writers_of`), or why its ACL could not be read.
/// `service`: the miner runs as a service (one runs this program, or this is a service logon),
/// where any of them fails; on a console they warn. `services`: each service that runs this
/// program, with its wrapper's path, whether that `ImagePath` is unquoted with a space, and
/// whether `sc privs` was set.
#[cfg(windows)]
fn replaceable_findings(
    checked: &[(PathBuf, Result<Vec<String>, String>)],
    service: bool,
    services: &[(String, PathBuf, bool, bool)],
) -> Vec<(Level, String)> {
    use zkminer_prover::windows_account::{principal_name, KEPT_PRIVILEGES};
    let mut findings = Vec::new();
    let level = if service { Level::Fail } else { Level::Warn };
    for (path, writers) in checked {
        match writers {
            Ok(writers) if !writers.is_empty() => {
                findings.push((
                    level,
                    format!(
                    "{} can be written by {}: another user of this PC could replace it and run \
                     code as the miner's account, its key included. Keep the miner, its \
                     workers{}, and its configuration in a directory only administrators can \
                     write (C:\\Program Files\\zkminer, README: Windows service)",
                    path.display(),
                    writers
                        .iter()
                        .map(|s| principal_name(s))
                        .collect::<Vec<_>>()
                        .join(", "),
                    if services.is_empty() { "" } else { ", nssm.exe" }
                ),
                ))
            }
            Ok(_) => {}
            Err(e) => findings.push((
                Level::Info,
                format!("{}: its ACL could not be read ({e})", path.display()),
            )),
        }
    }
    for (name, image, unquoted, privs) in services {
        if *unquoted {
            findings.push((
                Level::Fail,
                format!(
                    "service {name} starts {} from an unquoted path with a space in it: Windows \
                     tries each prefix up to a space first. Quote it (`sc config {name} binPath= \
                     \"\\\"{}\\\"\"`)",
                    image.display(),
                    image.display()
                ),
            ));
        }
        if !privs {
            findings.push((
                Level::Warn,
                format!(
                    "service {name} has no required privileges set: its logon gets \
                     SeImpersonatePrivilege (SERVICE group), which `zkminer run` removes from \
                     itself and its workers but not from {}. `sc privs {name} {}`",
                    image.display(),
                    KEPT_PRIVILEGES.join("/")
                ),
            ));
        }
    }
    if !findings.iter().any(|(level, _)| *level >= Level::Warn) {
        findings.insert(
            0,
            (
                Level::Pass,
                format!(
                    "only SYSTEM, Administrators, TrustedInstaller and this account can write the \
                     miner, its workers and configuration{}",
                    if services.is_empty() {
                        String::new()
                    } else {
                        format!(
                            ", and the service wrapper ({})",
                            services
                                .iter()
                                .map(|(_, image, ..)| image.display().to_string())
                                .collect::<Vec<_>>()
                                .join(", ")
                        )
                    }
                ),
            ),
        );
    }
    findings
}

/// Windows: who can replace what the miner runs ([`replaceable_findings`]): this program, the
/// configuration file `config_file`, the worker binaries configured and those in the directories
/// searched for them, the wrapper of any service that runs this program, and each one's directory.
#[cfg(windows)]
fn replaceable_checks(report: &mut Report, config: &ZkMinerConfig, config_file: &Path) {
    use zkminer_prover::windows_account as account;
    let Ok(exe) = std::env::current_exe() else {
        return;
    };
    let own = match zkminer_config::wallet::current_user_sid() {
        Ok(sid) => sid,
        Err(e) => {
            report.say(
                Level::Info,
                "who can replace the miner",
                format!("this account could not be read ({e})"),
            );
            return;
        }
    };
    let services = account::services_running(&exe);
    let mut paths: Vec<PathBuf> = vec![exe.clone(), config_file.to_path_buf()];
    paths.extend(services.iter().map(|s| s.image.clone()));
    paths.extend(config.prover.worker_binaries.values().map(PathBuf::from));
    let searched = zkminer_prover::discovery::worker_search_dirs(
        &config
            .prover
            .worker_search_paths
            .iter()
            .map(PathBuf::from)
            .collect::<Vec<_>>(),
    );
    for dir in &searched {
        if let Ok(entries) = std::fs::read_dir(dir) {
            paths.extend(entries.flatten().map(|e| e.path()).filter(|p| {
                p.file_name().and_then(|n| n.to_str()).is_some_and(|n| {
                    let n = n.to_ascii_lowercase();
                    n.starts_with("zkminer-prove") && n.ends_with(".exe")
                })
            }));
        }
    }
    let mut all: Vec<PathBuf> = Vec::new();
    for path in paths {
        let parent = path.parent().map(Path::to_path_buf);
        all.push(path);
        all.extend(parent);
    }
    all.extend(searched);
    // Once each, and only what is there: a missing file is said elsewhere.
    let mut seen = std::collections::BTreeSet::new();
    all.retain(|p| p.exists() && seen.insert(p.to_string_lossy().to_lowercase()));
    let checked: Vec<(PathBuf, Result<Vec<String>, String>)> = all
        .into_iter()
        .map(|p| {
            let writers = account::writers_of(&p, &own).map_err(|e| e.to_string());
            (p, writers)
        })
        .collect();
    let service = !services.is_empty() || account::is_service_logon().unwrap_or(false);
    let services: Vec<(String, PathBuf, bool, bool)> = services
        .into_iter()
        .map(|s| {
            (
                s.name,
                s.image,
                s.unquoted_with_spaces,
                s.required_privileges.is_some(),
            )
        })
        .collect();
    for (level, detail) in replaceable_findings(&checked, service, &services) {
        report.say(level, "who can replace the miner", detail);
    }
}

/// Linux: [`super::run::file_access::key_file_findings`], with the installed unit's environment
/// files (`systemctl show`, off the runtime).
#[cfg(target_os = "linux")]
async fn linux_key_file_findings(wallet: &zkminer_config::config::WalletConfig) -> Vec<String> {
    let wallet = wallet.clone();
    tokio::task::spawn_blocking(move || {
        use super::run::file_access as access;
        access::key_file_findings(&wallet, access::installed_service().as_deref())
    })
    .await
    .unwrap_or_default()
}

/// Linux: who can replace what the miner runs (review r6 LS3, `run::file_access`): the Windows
/// check's counterpart. Each finding fails where the miner runs as the installed unit, as a Windows
/// service's do; run by hand, it warns.
#[cfg(target_os = "linux")]
fn linux_replaceable_checks(report: &mut Report, config: &ZkMinerConfig, config_file: &Path) {
    use super::run::file_access as access;
    let service = access::installed_service();
    let targets = access::replace_targets(config, config_file, service.as_deref());
    let problems = access::replace_problems(&targets);
    let level = if service.is_some() || std::env::var_os("INVOCATION_ID").is_some() {
        Level::Fail
    } else {
        Level::Warn
    };
    if problems.is_empty() {
        report.say(
            Level::Pass,
            "who can replace the miner",
            "only root and this user can write the miner, its workers, its configuration and \
             ~/.sp1/bin, and the directories above them",
        );
    }
    for (path, why) in problems {
        report.say(
            level,
            "who can replace the miner",
            format!(
                "{} {why}: another user could replace it and run code as the miner's account, its \
                 key included. Make it root's or this user's, writable by its owner only (`chmod \
                 go-w`)",
                path.display()
            ),
        );
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
            // `run` refuses to start then (unless overridden): it fails closed.
            Err(e) => (
                Level::Fail,
                format!(
                    "could not be read from this process's token ({e}): `zkminer run` refuses to \
                     start unless {}=1",
                    sandbox::ALLOW_PRIVILEGED_ACCOUNT_ENV
                ),
            ),
        };
        report.say(level, "account", detail);
        let (level, detail) = match zkminer_prover::windows_account::this_process_privileges() {
            Ok(held) => privilege_finding(
                &held,
                zkminer_prover::windows_account::strip_check().map_err(|e| e.to_string()),
            ),
            Err(e) => (
                Level::Warn,
                format!("could not be read from this process's token ({e})"),
            ),
        };
        report.say(level, "privileges", detail);
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
    // A Mac proves risc0 only (Metal): nothing is fetched into ~/.sp1 there.
    let missing: Vec<&str> = [".risc0", ".sp1"]
        .into_iter()
        .filter(|d| !(cfg!(target_os = "macos") && *d == ".sp1"))
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
    if let Some((level, detail)) = near_hop_finding(
        config.dev.private_network,
        zkminer_chain::programs::near_hop_supported(),
    ) {
        report.say(level, "network guard", detail);
    }
}

/// Whether the network guard's near-hop check can work here (public mode only: developer mode
/// does not run it). Where it cannot (Windows), every requester connection is refused: ELF, IPFS
/// and Arweave downloads and `artifact publish`.
fn near_hop_finding(
    private_network: bool,
    supported: Result<(), String>,
) -> Option<(Level, String)> {
    match supported {
        Ok(()) => None,
        Err(_) if private_network => None,
        Err(why) => Some((
            Level::Warn,
            format!(
                "public mode refuses every requester connection on this host (ELF, IPFS and \
                 Arweave downloads, artifact publish): {why}"
            ),
        )),
    }
}

/// Windows: the services that run this miner, as a service logon will find them (review 6 OJ-1):
/// their account's password; and whether NSSM stops when the miner does and waits for a drain
/// (OJ-2). See `windows_service`.
#[cfg(windows)]
fn service_checks(report: &mut Report) {
    use super::windows_service as service;
    let mut findings = service::service_password_findings();
    findings.extend(service::service_nssm_findings());
    if findings.is_empty() {
        return;
    }
    report.section("Windows service");
    for (finding, what, text) in findings {
        let level = match finding {
            service::Finding::Pass => Level::Pass,
            service::Finding::Info => Level::Info,
            service::Finding::Warn => Level::Warn,
            service::Finding::Fail => Level::Fail,
        };
        report.say(level, &what, text);
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
    #[cfg(any(windows, target_os = "linux"))]
    let config_file = config_path
        .map(Path::to_path_buf)
        .unwrap_or_else(|| ZkMinerConfig::default_dir().join("config.toml"));
    // Blocking probes (nvidia-smi, sysfs, the disk), off the runtime.
    let mut host_report = Report::default();
    let host_report = tokio::task::spawn_blocking(move || {
        host_checks(&mut host_report, &host_config);
        #[cfg(windows)]
        replaceable_checks(&mut host_report, &host_config, &config_file);
        #[cfg(target_os = "linux")]
        linux_replaceable_checks(&mut host_report, &host_config, &config_file);
        #[cfg(windows)]
        service_checks(&mut host_report);
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
    fn doctor_says_when_public_mode_refuses_every_requester_connection() {
        assert!(near_hop_finding(false, Ok(())).is_none());
        assert!(near_hop_finding(true, Err("no".into())).is_none());
        let (level, detail) = near_hop_finding(false, Err("why".into())).unwrap();
        assert!(matches!(level, Level::Warn));
        assert!(
            detail.contains("refuses every requester connection"),
            "{detail}"
        );
        assert!(detail.ends_with(": why"), "{detail}");
        // This host's own answer: Windows cannot run public mode.
        let here = near_hop_finding(false, zkminer_chain::programs::near_hop_supported());
        assert_eq!(here.is_some(), cfg!(windows));
    }

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
            w.contains("miner.key") && w.contains("ZKMINER_WINDOWS_LOW_IL_WORKERS=0"),
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

    /// Windows, Low-integrity workers: an unlabelled secret the miner can label is only noted; one
    /// it cannot fails, with the icacls remedy naming the file.
    #[test]
    fn doctor_fails_a_secret_the_miner_cannot_label() {
        assert!(secret_label_findings(&[]).is_empty());
        let found = secret_label_findings(&[
            (PathBuf::from(r"C:\keys\miner.key"), false),
            (PathBuf::from(r"C:\Users\z\.zkminer\.env"), true),
        ]);
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].0, Level::Fail);
        assert!(
            found[0]
                .1
                .contains(r#"icacls "C:\keys\miner.key" /grant <account>:(WO)"#),
            "{}",
            found[0].1
        );
        assert_eq!(found[1].0, Level::Info);
        assert!(found[1].1.contains("labels it"), "{}", found[1].1);
    }

    /// Windows, an `env` key: a copy in the machine's or a service's environment fails (every user
    /// reads it), and so does one in the user's own environment (no Low worker starts beside it,
    /// review 7 VWI-1); each names where it is and gives the steps that keep the key, import
    /// before delete.
    #[test]
    fn doctor_flags_a_key_kept_in_a_readable_environment() {
        assert!(key_env_copy_findings("ZKMINER_PRIVATE_KEY", &[]).is_empty());
        let found = key_env_copy_findings(
            "ZKMINER_PRIVATE_KEY",
            &[
                (
                    r"HKLM\SYSTEM\CurrentControlSet\Services\zkminer\Parameters (AppEnvironmentExtra)"
                        .into(),
                    true,
                ),
                (r"HKCU\Environment (ZKMINER_PRIVATE_KEY)".into(), false),
            ],
        );
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].0, Level::Fail);
        assert!(
            found[0].1.contains("AppEnvironmentExtra")
                && found[0].1.contains("every user of this PC")
                && found[0].1.contains("key file"),
            "{}",
            found[0].1
        );
        assert_eq!(found[1].0, Level::Fail);
        assert!(
            found[1].1.contains(r"HKCU\Environment")
                && found[1].1.contains("Low-integrity")
                && found[1]
                    .1
                    .contains("SetEnvironmentVariable('ZKMINER_PRIVATE_KEY', $null, 'User')"),
            "{}",
            found[1].1
        );
        for (_, text) in &found {
            let import = text.find("--import-env-key").expect("names the import");
            let delete = text.find("only then delete").expect("names the delete");
            assert!(import < delete, "{text}");
            assert!(!text.contains("--generate-key"), "{text}");
        }
    }

    /// HT-1: a key file in a cloud-synced folder fails, naming the folder; elsewhere nothing.
    #[test]
    fn doctor_fails_a_key_file_in_a_cloud_synced_folder() {
        assert!(cloud_key_file_finding("/k", None).is_none());
        let f = cloud_key_file_finding(
            r"C:\Users\me\OneDrive\key",
            Some(r"OneDrive (C:\Users\me\OneDrive)".into()),
        )
        .unwrap();
        assert!(f.contains("OneDrive (") && f.contains("exposed"), "{f}");
    }

    /// Windows: a service account fails (refused, or run paged with the override), an elevated
    /// token warns, a standard one passes. An administrator under a service logon fails; an
    /// administrator's console warns, elevated or not.
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
        let (level, text) = account_finding(Some(AccountRisk::AdminService), false);
        assert_eq!(level, Level::Fail);
        assert!(
            text.contains("administrator under a service logon") && text.contains("refuses"),
            "{text}"
        );
        let (level, text) = account_finding(Some(AccountRisk::Elevated), false);
        assert_eq!(level, Level::Warn);
        assert!(text.contains("administrator, elevated"), "{text}");
        // An administrator's console that is not elevated is said to be one, not a standard account.
        let (level, text) = account_finding(Some(AccountRisk::FilteredAdmin), false);
        assert_eq!(level, Level::Warn);
        assert!(
            text.contains("administrator, not elevated") && !text.contains("standard account,"),
            "{text}"
        );
        let (level, text) = account_finding(None, false);
        assert_eq!(level, Level::Pass);
        assert!(text.contains("not an administrator"), "{text}");
    }

    /// Windows: SeImpersonate (a service logon's) warns, naming `sc privs`; a strip that fails
    /// fails; a token with none of the dangerous privileges passes.
    #[cfg(windows)]
    #[test]
    fn doctor_reports_dangerous_privileges() {
        let held: Vec<String> = ["SeChangeNotifyPrivilege", "SeImpersonatePrivilege"]
            .map(String::from)
            .to_vec();
        let (level, text) = privilege_finding(&held, Ok(vec!["SeImpersonatePrivilege".into()]));
        assert_eq!(level, Level::Warn);
        assert!(
            text.contains("SeImpersonatePrivilege") && text.contains("sc privs"),
            "{text}"
        );
        let (level, text) = privilege_finding(&held, Err("denied".into()));
        assert_eq!(level, Level::Fail);
        assert!(
            text.contains("refuses") && text.contains("SeImpersonate"),
            "{text}"
        );
        let (level, text) = privilege_finding(&held[..1], Ok(Vec::new()));
        assert_eq!(level, Level::Pass);
        assert!(text.contains("SeChangeNotifyPrivilege"), "{text}");
    }

    /// Windows: a file another user can write fails under a service and warns on a console; a
    /// service's unquoted path fails and a missing `sc privs` warns; nothing found passes.
    #[cfg(windows)]
    #[test]
    fn doctor_reports_who_can_replace_the_miner() {
        let nssm = PathBuf::from(r"C:\tools\nssm.exe");
        let writable = vec![
            (nssm.clone(), Ok(vec!["S-1-5-11".to_string()])),
            (PathBuf::from(r"C:\Program Files\zkminer"), Ok(Vec::new())),
            (PathBuf::from(r"C:\gone"), Err("denied".to_string())),
        ];
        let service = vec![("zkminer".to_string(), nssm.clone(), false, true)];
        let found = replaceable_findings(&writable, true, &service);
        assert_eq!(found.len(), 2, "{found:?}");
        assert_eq!(found[0].0, Level::Fail);
        assert!(
            found[0].1.contains(r"C:\tools\nssm.exe")
                && found[0].1.contains("Authenticated Users")
                && found[0].1.contains("nssm.exe, and its configuration"),
            "{}",
            found[0].1
        );
        assert_eq!(found[1].0, Level::Info);
        // On a console, with no service, the same file only warns.
        let found = replaceable_findings(&writable[..1], false, &[]);
        assert_eq!(found[0].0, Level::Warn);
        let clean = vec![(PathBuf::from(r"C:\Program Files\zkminer"), Ok(Vec::new()))];
        let unquoted = vec![(
            "zkminer".to_string(),
            PathBuf::from(r"C:\Program Files\zkminer\nssm.exe"),
            true,
            false,
        )];
        let found = replaceable_findings(&clean, true, &unquoted);
        assert_eq!(found.len(), 2, "{found:?}");
        assert_eq!(found[0].0, Level::Fail);
        assert!(found[0].1.contains("unquoted"), "{}", found[0].1);
        assert_eq!(found[1].0, Level::Warn);
        assert!(found[1].1.contains("sc privs zkminer"), "{}", found[1].1);
        let found = replaceable_findings(&clean, true, &service);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].0, Level::Pass);
        assert!(found[0].1.contains("service wrapper"), "{}", found[0].1);
    }

    /// Windows, live: this test binary and its directory are read, no service runs it, and the
    /// check says something.
    #[cfg(windows)]
    #[test]
    fn doctor_reads_who_can_replace_this_binary() {
        let mut report = Report::default();
        let config_file = std::env::temp_dir().join("zkminer-doctor-no-config.toml");
        replaceable_checks(&mut report, &ZkMinerConfig::default(), &config_file);
        assert!(!report.lines.is_empty());
        assert!(
            report
                .lines
                .iter()
                .all(|(_, what, _)| what == "who can replace the miner"),
            "{:?}",
            report.lines
        );
        // Not under a service (a CI runner may be one): a writable directory only warns.
        if !zkminer_prover::windows_account::is_service_logon().unwrap_or(true) {
            assert_eq!(report.failures, 0, "{:?}", report.lines);
        }
    }

    /// Windows' Low-integrity workers as doctor reports them: on by default (failing closed), the
    /// opt-out (a warning), a flag set to something other than 0 or 1 (still on), and a Low
    /// directory that was tampered with.
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
        assert_eq!(off[0].0, Level::Warn);
        assert!(
            off[0].1.contains("Medium") && off[0].1.contains("MEDIUM-WORKERS"),
            "{}",
            off[0].1
        );
        let misset = low_il_findings(true, Some("true"), &[]);
        assert_eq!(misset[0].0, Level::Pass);
        assert_eq!(misset[1].0, Level::Info);
        assert!(misset[1].1.contains("\"true\""), "{}", misset[1].1);
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
