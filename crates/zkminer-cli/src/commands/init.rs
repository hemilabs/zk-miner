use alloy::primitives::Address;
use anyhow::Result;
use std::path::Path;
use zkminer_config::wallet::{KeyFile, Zeroizing};
use zkminer_config::ZkMinerConfig;

/// The live Hemi testnet deployment (743111, 2026-11-16). Every older 743111 stack is abandoned;
/// `zkminer run` claims nothing on a config that names one (and pages).
use zkminer_chain::deployment::HEMI_TESTNET_743111 as TESTNET;
const TESTNET_RPC: &str = "https://testnet.rpc.hemi.network/rpc";
use zkminer_chain::staking::TESTNET_CHAIN_ID;
const MAINNET_CHAIN_ID: u64 = 43111;
const MAINNET_RPC: &str = "https://rpc.hemi.network";

/// The key options `init` was given.
#[derive(Debug, Clone, Copy, Default)]
pub struct KeyRequest<'a> {
    /// `--generate-key`.
    pub generate_key: bool,
    /// `--import-env-key`.
    pub import_env_key: bool,
    /// `--key-source`.
    pub key_source: Option<&'a str>,
    /// `--key-env-var`.
    pub key_env_var: Option<&'a str>,
}

/// Where `init` takes the miner's key from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KeyPlan {
    /// The variable (`key_source = "env"`).
    Env,
    /// A key file beside the config: a new key, or the key file already there, kept.
    Generate,
    /// The variable's value (from this process or the registry) copied into a key file beside the
    /// config, which then points at it.
    Import,
    /// `--force` over a config with no key option: the config's key settings are kept (a network
    /// change is not a key change).
    KeepExisting,
}

/// What `init` does about the key, given its options, whether it rewrites an existing config, and
/// where a key already given as the variable is (`env_key`: the place, and its address when it
/// could be read). Asked for with `--generate-key`, `--key-source file` or `--import-env-key`; by
/// default on Windows, where a key kept in the environment ends up where Low-integrity workers can
/// read it (a `setx` copy in the registry, PowerShell's command history), a key file. But on
/// Windows a key already given as the variable is never silently replaced by a new one (review 7
/// WR-1): `init` refuses and names both ways on, `--import-env-key` to keep that key and
/// `--generate-key` to leave it behind.
fn key_plan_on(
    windows: bool,
    req: KeyRequest,
    rewrites_config: bool,
    env_key: Option<(&str, Option<Address>)>,
) -> Result<KeyPlan> {
    if req.import_env_key {
        if req.generate_key || req.key_source.is_some() {
            anyhow::bail!(
                "--import-env-key makes the key file from the variable: it goes with neither \
                 --generate-key nor --key-source"
            );
        }
        return Ok(KeyPlan::Import);
    }
    match req.key_source {
        Some("env") if req.generate_key => {
            anyhow::bail!("--generate-key makes a key file: it cannot go with --key-source env")
        }
        Some("env") => return Ok(KeyPlan::Env),
        Some("file") => return Ok(KeyPlan::Generate),
        Some(other) => anyhow::bail!("unknown key source '{other}': use 'file' or 'env'"),
        None => {}
    }
    if req.generate_key {
        return Ok(KeyPlan::Generate);
    }
    if rewrites_config {
        return Ok(KeyPlan::KeepExisting);
    }
    if !windows {
        return Ok(KeyPlan::Env);
    }
    if let Some((place, address)) = env_key {
        let address = address.map_or_else(
            || "its address could not be read here".to_string(),
            |a| format!("address {a:?}"),
        );
        let var_flag = req
            .key_env_var
            .map(|v| format!(" --key-env-var {v}"))
            .unwrap_or_default();
        anyhow::bail!(
            "a key is already given as {place} ({address}). To keep it (its stake and payouts): \
             `zkminer init --import-env-key{var_flag}` copies it into a key file only you can read. \
             To make a new key and leave that address behind: `zkminer init --generate-key` \
             (what is staked or paid to it stays with it). To keep using the variable: \
             `zkminer init --key-source env` (only for a variable set in the miner's own \
             process, such as the shell that starts it: a copy kept with setx stops Low workers \
             from starting, and other users or processes read one kept there or in a service's \
             environment; a service needs the key file)"
        );
    }
    Ok(KeyPlan::Generate)
}

/// Where the key's variable `var` is already set: this process's environment, else (Windows) the
/// first copy kept in the registry; and its address, when the value can be read. The value is
/// read into memory zeroed on drop, and only its address is kept.
fn existing_env_key(var: &str) -> Option<(String, Option<Address>)> {
    if let Some((place, value)) = read_env_key(var) {
        let address = zkminer_config::wallet::address_of_key(&value).ok();
        return Some((place, address));
    }
    #[cfg(windows)]
    if let Some(copy) = zkminer_config::wallet_win::persisted_key_env_copies(var)
        .into_iter()
        .next()
    {
        return Some((copy.location, None));
    }
    None
}

/// The value of the key's variable `var` and where it was found: this process's environment, else
/// (Windows) the first readable copy in the registry (the user's, the machine's, then a service's
/// environment). Never logged.
fn read_env_key(var: &str) -> Option<(String, Zeroizing<String>)> {
    if let Some(v) = std::env::var_os(var) {
        let v = Zeroizing::new(v.to_string_lossy().into_owned());
        if !v.trim().is_empty() {
            return Some((format!("{var} in this process's environment"), v));
        }
    }
    #[cfg(windows)]
    if let Some(found) = zkminer_config::wallet_win::persisted_key_env_values(var)
        .into_iter()
        .find(|(_, v)| !v.trim().is_empty())
    {
        return Some(found);
    }
    None
}

/// Refuse to put a key file in a folder a sync client uploads (review 7 HT-1).
fn refuse_cloud_folder(key_path: &Path) -> Result<()> {
    if let Some(folder) = zkminer_config::wallet::cloud_synced_folder(key_path) {
        anyhow::bail!(
            "{} would be inside {folder}, which a sync client uploads (and keeps old versions of): \
             a key file there leaves this PC. Keep the config and its key outside it: the default \
             ~/.zkminer, or `zkminer -c <a path outside it> init`",
            key_path.display()
        );
    }
    Ok(())
}

pub fn run(config_path: Option<&Path>, force: bool, network: &str, req: KeyRequest) -> Result<()> {
    let path = config_path
        .map(|p| p.to_path_buf())
        .unwrap_or_else(ZkMinerConfig::default_path);
    let exists = path.exists();

    // `--import-env-key` over an existing config without `--force` changes only its key settings.
    let import_only = exists && !force && req.import_env_key;
    if exists && !force && !import_only {
        println!("Config file already exists at {}", path.display());
        println!("Use --force to overwrite (it keeps the config's key settings), or");
        println!("--import-env-key to copy a key given as a variable into a key file.");
        return Ok(());
    }
    // The config being rewritten, for its key settings.
    let existing = if exists {
        match ZkMinerConfig::load(Some(&path)) {
            Ok(c) => Some(c),
            Err(e) if import_only => return Err(e),
            Err(e) => {
                if req.generate_key || req.import_env_key || req.key_source.is_some() {
                    None
                } else {
                    anyhow::bail!(
                        "{e:#}: its key settings cannot be kept. Give --generate-key, \
                         --import-env-key or --key-source to say where the key comes from"
                    );
                }
            }
        }
    } else {
        None
    };
    let key_env_var = req
        .key_env_var
        .map(str::to_string)
        .or_else(|| existing.as_ref().map(|c| c.wallet.key_env_var.clone()))
        .unwrap_or_else(|| zkminer_config::config::WalletConfig::default().key_env_var);
    let env_key = existing_env_key(&key_env_var);
    let plan = key_plan_on(
        cfg!(windows),
        req,
        existing.is_some() && !import_only,
        env_key.as_ref().map(|(p, a)| (p.as_str(), *a)),
    )?;

    let mut config = if import_only {
        existing.clone().unwrap_or_default()
    } else {
        let mut config = ZkMinerConfig::default();
        apply_network(&mut config, network)?;
        config
    };
    config.wallet.key_env_var = key_env_var.clone();

    // The key lives beside the config, readable by this user only (see `generate_key_file`).
    // Absolute, so `zkminer run -c <this config>` finds it from any directory.
    let key_path = std::path::absolute(
        path.parent()
            .map(|d| d.join("key"))
            .unwrap_or_else(|| std::path::PathBuf::from("key")),
    )?;
    let mut imported_from = None;
    let key = match plan {
        KeyPlan::Env => {
            config.wallet.key_source = "env".to_string();
            None
        }
        KeyPlan::KeepExisting => {
            if let Some(old) = &existing {
                config.wallet = old.wallet.clone();
                if req.key_env_var.is_some() {
                    config.wallet.key_env_var = key_env_var.clone();
                }
            }
            None
        }
        KeyPlan::Generate => {
            refuse_cloud_folder(&key_path)?;
            let made = zkminer_config::wallet::generate_key_file(&key_path)?;
            config.wallet.key_source = "file".to_string();
            config.wallet.key_file_path = Some(key_path.to_string_lossy().into_owned());
            Some(made)
        }
        KeyPlan::Import => {
            refuse_cloud_folder(&key_path)?;
            let Some((place, value)) = read_env_key(&key_env_var) else {
                anyhow::bail!(
                    "{key_env_var} is set neither in this process's environment nor in the \
                     registry (the user's, the machine's or a service's environment) that this \
                     account can read: nothing to import. Run this as the miner's account, or name \
                     the variable with --key-env-var"
                );
            };
            let made = zkminer_config::wallet::import_key_file(&key_path, &value)?;
            config.wallet.key_source = "file".to_string();
            config.wallet.key_file_path = Some(key_path.to_string_lossy().into_owned());
            imported_from = Some(place);
            Some(made)
        }
    };

    // What this config no longer uses (a key given as the variable, the key file of the config
    // rewritten), by address where known: its stake and payouts stay with it.
    let mut left_behind = Vec::new();
    if let Some(made) = key {
        if let Some((place, address)) = &env_key {
            if *address != Some(made.address()) && plan != KeyPlan::Import {
                left_behind.push(match address {
                    Some(a) => format!("{place} ({a:?})"),
                    None => place.clone(),
                });
            }
        }
        if let Some(old) = existing.as_ref().map(|c| &c.wallet) {
            let old_file = old
                .key_file_path
                .as_deref()
                .filter(|_| old.key_source == "file");
            if let Some(old_file) = old_file.filter(|f| Path::new(f) != key_path) {
                left_behind.push(format!("the key file {old_file}"));
            }
        }
    }

    config.save(Some(&path))?;

    if import_only {
        println!("Config file at {} now uses the key file.", path.display());
    } else {
        println!("Config file created at {}", path.display());
        println!();
        for line in summary(network) {
            println!("{line}");
        }
    }
    for what in &left_behind {
        println!();
        println!("NOTE: this config no longer uses {what}. Whatever is staked or paid");
        println!("      to that address stays with it: keep that key until it is moved.");
    }
    println!();
    println!("Next steps:");
    match key {
        Some(KeyFile::Created(a)) => {
            println!("  1. A new key was saved to {}.", key_path.display());
            println!("     Its address is {a:?}");
            for line in zkminer_config::wallet::KEY_BACKUP_ADVICE {
                println!("     {line}");
            }
            println!("     Use it only for mining, and fund it with only what the miner needs.");
        }
        Some(made @ (KeyFile::Imported(a) | KeyFile::Kept(a))) if imported_from.is_some() => {
            let place = imported_from.as_deref().unwrap_or_default();
            if matches!(made, KeyFile::Kept(_)) {
                println!("  1. {} already held this key (kept).", key_path.display());
            } else {
                println!("  1. The key was copied into {}.", key_path.display());
            }
            println!("     It holds {a:?}, the same address as {place}.");
            println!("     Check that `zkminer status` shows this address, the one your stake and");
            println!("     payouts belong to. Only then delete the copy:");
            println!(
                "     {}.",
                zkminer_config::wallet::key_env_delete_step(&key_env_var, place)
            );
            println!("     That copy was readable to more than the miner: plan to rotate the key");
            println!("     (unstake --all, withdraw 7 days on, move the funds to a new key).");
            for line in zkminer_config::wallet::KEY_BACKUP_ADVICE {
                println!("     {line}");
            }
        }
        Some(KeyFile::Kept(a)) | Some(KeyFile::Imported(a)) => {
            println!(
                "  1. Using the key already in {} (kept, never",
                key_path.display()
            );
            println!("     overwritten). Its address is {a:?}");
            println!(
                "     This init did not make it ({}): make sure it is yours.",
                origin(&key_path)
            );
        }
        None if config.wallet.key_source == "file" => {
            println!(
                "  1. The miner keeps using the key file {}.",
                config.wallet.key_file_path.as_deref().unwrap_or("(unset)")
            );
        }
        None => {
            println!("  1. Give the miner its key, either:");
            println!(
                "       zkminer init --force --generate-key --network {network}   (a new key in a"
            );
            println!("       private file; this rewrites the config)");
            println!("     or set {key_env_var} in the miner's environment. Type the key at a");
            println!("     prompt rather than on a command line your shell saves to its history.");
            #[cfg(windows)]
            {
                println!("     Not with setx or in a service's environment (NSSM's");
                println!("     AppEnvironmentExtra): other users or processes read it there,");
                println!("     and with a setx copy no prover worker starts. A service needs");
                println!("     the key file (the default without --key-source env).");
            }
        }
    }
    if import_only {
        return Ok(());
    }
    let address_hint = key
        .map(|m| format!(" ({:?})", m.address()))
        .unwrap_or_default();
    for line in funding_steps(network, &address_hint) {
        println!("{line}");
    }
    println!("  4. Check everything:  zkminer status");
    println!("  5. Start mining:      zkminer run   (it benchmarks your GPUs first)");
    println!("  Check it first:       zkminer doctor");
    println!("  Later, to leave:      zkminer stop (let its jobs settle), zkminer unstake --all,");
    println!("                        then zkminer withdraw 7 days on");

    Ok(())
}

/// What `init` prints after writing the config: the network it targets (on testnet the built-in
/// deployment; on mainnet, that none is built in and `[contracts]` must be filled in).
fn summary(network: &str) -> Vec<String> {
    if network != "testnet" {
        return vec![
            format!("Hemi mainnet (chain ID {MAINNET_CHAIN_ID}) has no HemiProve deployment yet:"),
            "  fill in [contracts] in the config before running; `zkminer run` refuses an"
                .to_string(),
            "  unknown deployment unless ZKMINER_ALLOW_UNKNOWN_DEPLOYMENT=1.".to_string(),
        ];
    }
    vec![
        format!("Pre-configured for Hemi Testnet (chain ID {TESTNET_CHAIN_ID})"),
        format!("  RPC:     {TESTNET_RPC}"),
        format!("  Router:  {}", TESTNET.router),
        format!("  Token:   {} (tHEMI — owner-minted)", TESTNET.token),
    ]
}

/// Next steps 2 and 3: funding the key's address and staking. Every step names the command that
/// does it (W10-DOC). On testnet tHEMI is minted only by its owner, and the first claim can come
/// one block after the first stake.
fn funding_steps(network: &str, address_hint: &str) -> Vec<String> {
    let mut lines = if network == "testnet" {
        vec![
            format!("  2. Send testnet ETH (gas) and tHEMI to the address{address_hint}. tHEMI is"),
            "     minted only by its owner: ask the HemiProve team. A claim typically locks"
                .to_string(),
            "     about 150 tHEMI, so stake at least that per job you want to hold at once."
                .to_string(),
        ]
    } else {
        vec![format!(
            "  2. Send ETH (gas) and HEMI to the address{address_hint}."
        )]
    };
    lines.push("  3. Stake it:          zkminer stake 150".to_string());
    if network == "testnet" {
        lines.push(
            "                        (the first claim can come one block after the first stake)"
                .to_string(),
        );
    }
    lines
}

fn apply_network(config: &mut ZkMinerConfig, network: &str) -> Result<()> {
    match network {
        "testnet" => {
            config.chain.rpc_url = TESTNET_RPC.to_string();
            config.chain.chain_id = TESTNET_CHAIN_ID;
            config.contracts.hemi_prove = TESTNET.router.to_string();
            config.contracts.hemi_prove_staking = TESTNET.staking.to_string();
            config.contracts.hemi_prove_registry = TESTNET.registry.to_string();
            config.contracts.hemi_token = TESTNET.token.to_string();
            config.contracts.program_registry = TESTNET.program_registry.to_string();
            config.chain.scan_from_block = Some(TESTNET.scan_from_block);
        }
        "mainnet" => {
            config.chain.rpc_url = MAINNET_RPC.to_string();
            config.chain.chain_id = MAINNET_CHAIN_ID;
            // Mainnet addresses must be filled in by the user.
        }
        other => {
            anyhow::bail!("Unknown network '{other}' — use 'testnet' or 'mainnet'");
        }
    }
    Ok(())
}

/// When a key file kept by `init` was made, and (Windows) by whom, for the operator to check.
fn origin(path: &Path) -> String {
    let created = std::fs::metadata(path)
        .and_then(|m| m.created())
        .map(|t| {
            chrono::DateTime::<chrono::Local>::from(t)
                .format("created %Y-%m-%d %H:%M")
                .to_string()
        })
        .unwrap_or_else(|_| "creation time unknown".to_string());
    #[cfg(windows)]
    {
        let owner =
            zkminer_config::wallet::file_owner_sid(path).unwrap_or_else(|| "unknown".to_string());
        format!("{created}, owner {owner}")
    }
    #[cfg(not(windows))]
    created
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(generate_key: bool, key_source: Option<&str>) -> KeyRequest<'_> {
        KeyRequest {
            generate_key,
            key_source,
            ..KeyRequest::default()
        }
    }

    /// Windows makes a key file unless the variable is asked for; elsewhere the variable stays the
    /// default. A key file cannot be generated for an `env` key.
    #[test]
    fn windows_defaults_to_a_key_file() {
        let plan = |w, r, rewrites| key_plan_on(w, r, rewrites, None);
        assert_eq!(
            plan(true, req(false, None), false).unwrap(),
            KeyPlan::Generate
        );
        assert_eq!(
            plan(true, req(false, Some("env")), false).unwrap(),
            KeyPlan::Env
        );
        assert_eq!(plan(false, req(false, None), false).unwrap(), KeyPlan::Env);
        assert_eq!(
            plan(false, req(true, None), false).unwrap(),
            KeyPlan::Generate
        );
        assert_eq!(
            plan(false, req(false, Some("file")), false).unwrap(),
            KeyPlan::Generate
        );
        assert!(plan(true, req(true, Some("env")), false).is_err());
        assert!(plan(false, req(false, Some("vault")), false).is_err());
    }

    /// WR-1: on Windows a key already given as the variable is never replaced by a new one without
    /// asking: `init` refuses, naming the address and both ways on. `--generate-key` (explicit)
    /// and `--import-env-key` go ahead; elsewhere the variable stays the default anyway.
    #[test]
    fn a_key_given_as_the_variable_is_not_silently_replaced() {
        let a: Address = "0x00000000000000000000000000000000000000aa"
            .parse()
            .unwrap();
        let env = Some(("ZKMINER_PRIVATE_KEY in this process's environment", Some(a)));
        let refused = key_plan_on(true, req(false, None), false, env)
            .unwrap_err()
            .to_string();
        assert!(
            refused.contains("--import-env-key")
                && refused.contains("--generate-key")
                && refused.contains(&format!("{a:?}")),
            "{refused}"
        );
        let unknown = key_plan_on(true, req(false, None), false, Some((r"HKLM\x (K)", None)))
            .unwrap_err()
            .to_string();
        assert!(unknown.contains(r"HKLM\x (K)"), "{unknown}");
        assert_eq!(
            key_plan_on(true, req(true, None), false, env).unwrap(),
            KeyPlan::Generate
        );
        let import = KeyRequest {
            import_env_key: true,
            ..KeyRequest::default()
        };
        assert_eq!(
            key_plan_on(true, import, false, env).unwrap(),
            KeyPlan::Import
        );
        assert_eq!(
            key_plan_on(false, req(false, None), false, env).unwrap(),
            KeyPlan::Env
        );
        // Import goes with no other key option.
        let both = KeyRequest {
            import_env_key: true,
            generate_key: true,
            ..KeyRequest::default()
        };
        assert!(key_plan_on(true, both, false, env).is_err());
        let with_source = KeyRequest {
            import_env_key: true,
            key_source: Some("file"),
            ..KeyRequest::default()
        };
        assert!(key_plan_on(true, with_source, false, None).is_err());
    }

    /// `init --force` over a config keeps its key settings (it changes the network, not the key)
    /// unless a key option is given.
    #[test]
    fn force_keeps_the_configs_key_unless_asked() {
        let a: Address = "0x00000000000000000000000000000000000000aa"
            .parse()
            .unwrap();
        let env = Some(("X", Some(a)));
        for windows in [true, false] {
            assert_eq!(
                key_plan_on(windows, req(false, None), true, env).unwrap(),
                KeyPlan::KeepExisting
            );
            assert_eq!(
                key_plan_on(windows, req(false, None), true, None).unwrap(),
                KeyPlan::KeepExisting
            );
            assert_eq!(
                key_plan_on(windows, req(true, None), true, env).unwrap(),
                KeyPlan::Generate
            );
            assert_eq!(
                key_plan_on(windows, req(false, Some("env")), true, None).unwrap(),
                KeyPlan::Env
            );
        }
    }

    #[test]
    fn testnet_steps_name_the_commands() {
        let text = [summary("testnet"), funding_steps("testnet", " (0xabc)")]
            .concat()
            .join("\n");
        assert!(text.contains("HemiProve team"), "{text}");
        assert!(text.contains("zkminer stake 150"), "{text}");
        assert!(text.contains("one block after the first stake"), "{text}");
        assert!(text.contains("(0xabc)"), "{text}");
        assert!(!text.contains("Wallet screen"), "{text}");
        assert!(text.contains(&TESTNET.router.to_string()), "{text}");
        assert!(text.contains(&TESTNET.token.to_string()), "{text}");
    }

    #[test]
    fn mainnet_is_not_described_as_testnet() {
        let text = [summary("mainnet"), funding_steps("mainnet", "")]
            .concat()
            .join("\n");
        assert!(!text.contains("Testnet"), "{text}");
        assert!(!text.contains("tHEMI"), "{text}");
        assert!(text.contains("43111"), "{text}");
        assert!(text.contains("[contracts]"), "{text}");
    }
}
