use anyhow::Result;
use std::path::Path;
use zkminer_config::ZkMinerConfig;

/// The live Hemi testnet deployment (743111, 2026-10-29). Every older 743111 stack is abandoned;
/// `zkminer run` claims nothing on a config that names one (and pages).
use zkminer_chain::deployment::HEMI_TESTNET_743111 as TESTNET;
const TESTNET_RPC: &str = "https://testnet.rpc.hemi.network/rpc";
use zkminer_chain::staking::TESTNET_CHAIN_ID;
const MAINNET_CHAIN_ID: u64 = 43111;
const MAINNET_RPC: &str = "https://rpc.hemi.network";

pub fn run(
    config_path: Option<&Path>,
    force: bool,
    network: &str,
    generate_key: bool,
) -> Result<()> {
    let path = config_path
        .map(|p| p.to_path_buf())
        .unwrap_or_else(ZkMinerConfig::default_path);

    if path.exists() && !force {
        println!("Config file already exists at {}", path.display());
        println!("Use --force to overwrite.");
        return Ok(());
    }

    let mut config = ZkMinerConfig::default();

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

    // The key lives beside the config, readable by this user only (see `generate_key_file`).
    let key = if generate_key {
        // Absolute, so `zkminer run -c <this config>` finds it from any directory.
        let key_path = std::path::absolute(
            path.parent()
                .map(|d| d.join("key"))
                .unwrap_or_else(|| std::path::PathBuf::from("key")),
        )?;
        let made = zkminer_config::wallet::generate_key_file(&key_path)?;
        config.wallet.key_source = "file".to_string();
        config.wallet.key_file_path = Some(key_path.to_string_lossy().into_owned());
        Some((made, key_path))
    } else {
        None
    };

    config.save(Some(&path))?;

    println!("Config file created at {}", path.display());
    println!();
    if network == "testnet" {
        println!("Pre-configured for Hemi Testnet (chain ID {TESTNET_CHAIN_ID})");
        println!("  RPC:     {TESTNET_RPC}");
        println!("  Router:  {}", TESTNET.router);
        println!("  Token:   {} (tHEMI — owner-minted)", TESTNET.token);
    } else {
        println!("Hemi mainnet (chain ID {MAINNET_CHAIN_ID}) has no HemiProve deployment yet:");
        println!("  fill in [contracts] in the config before running; `zkminer run` refuses an");
        println!("  unknown deployment unless ZKMINER_ALLOW_UNKNOWN_DEPLOYMENT=1.");
    }
    println!();
    println!("Next steps:");
    match &key {
        Some((made, key_path)) => match made {
            zkminer_config::wallet::KeyFile::Created(a) => {
                println!("  1. A new key was saved to {}.", key_path.display());
                println!("     Its address is {a:?}");
                println!("     Back the file up: it is the only copy, and stake and payouts");
                println!("     belong to it. Use it only for mining, and fund it with only");
                println!("     what the miner needs.");
            }
            zkminer_config::wallet::KeyFile::Kept(a) => {
                println!(
                    "  1. Using the key already in {} (kept, never",
                    key_path.display()
                );
                println!("     overwritten). Its address is {a:?}");
            }
        },
        None => {
            println!("  1. Give the miner its key, either:");
            println!(
                "       zkminer init --force --generate-key --network {network}   (a new key in a"
            );
            println!("       private file; this rewrites the config)");
            println!(
                "     or set ZKMINER_PRIVATE_KEY in the miner's environment. Type the key at a"
            );
            println!("     prompt rather than on a command line your shell saves to its history.");
        }
    }
    let address_hint = key
        .as_ref()
        .map(|(m, _)| format!(" ({:?})", m.address()))
        .unwrap_or_default();
    if network == "testnet" {
        println!("  2. Send testnet ETH (gas) and tHEMI to the address{address_hint}. tHEMI is");
        println!("     minted only by its owner: ask the HemiProve team. A claim typically locks");
        println!("     about 150 tHEMI, so stake at least that per job you want to hold at once.");
    } else {
        println!("  2. Send ETH (gas) and HEMI to the address{address_hint}.");
    }
    println!("  3. Stake it:          zkminer stake 150");
    println!("  4. Check everything:  zkminer status");
    println!("  5. Start mining:      zkminer run   (it benchmarks your GPUs first)");
    println!("  Later, to leave:      zkminer unstake --all, then zkminer withdraw 7 days on");

    Ok(())
}
