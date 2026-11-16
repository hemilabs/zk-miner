use anyhow::Result;
use std::path::Path;
use zkminer_config::ZkMinerConfig;

/// The live Hemi testnet deployment (743111, 2026-11-16). Every older 743111 stack is abandoned;
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

    if generate_key {
        println!("--generate-key is not yet implemented; set ZKMINER_PRIVATE_KEY manually.");
    }

    config.save(Some(&path))?;

    println!("Config file created at {}", path.display());
    println!();
    println!("Pre-configured for Hemi Testnet (chain ID {TESTNET_CHAIN_ID})");
    println!("  RPC:     {TESTNET_RPC}");
    println!("  Router:  {}", TESTNET.router);
    println!("  Token:   {} (tHEMI — owner-minted)", TESTNET.token);
    println!();
    println!("Next steps:");
    println!("  1. Set your private key:");
    println!("     export ZKMINER_PRIVATE_KEY=0xYOUR_KEY");
    println!("  2. Get testnet ETH (gas) and tHEMI from the HemiProve team — tHEMI is minted only");
    println!("     by its owner; you need at least 100 tHEMI per lock you want to hold at once");
    println!("  3. Stake it (via the Wallet screen); claims start one block after the first stake");
    println!("  4. Run: zkminer run");

    Ok(())
}
