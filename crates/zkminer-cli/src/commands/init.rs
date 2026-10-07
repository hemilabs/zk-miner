use anyhow::Result;
use std::path::Path;
use zkminer_config::ZkMinerConfig;

/// Hemi Testnet contract addresses (from deployment-hemi-testnet.csv).
const TESTNET_HEMI_PROVE: &str = "0x9c554334629e2f6674a12b5c39aaad41d3bdb86c";
const TESTNET_STAKING: &str = "0x1cf94bb8e30e2afdbb03e1722348b02839e1b625";
const TESTNET_REGISTRY: &str = "0xd6d460b525e61410c2beeb9a43dfcdac1b40da1b";
const TESTNET_TOKEN: &str = "0xc87f3282eb13324dccefeb14369b929428d0e29a";
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
            config.contracts.hemi_prove = TESTNET_HEMI_PROVE.to_string();
            config.contracts.hemi_prove_staking = TESTNET_STAKING.to_string();
            config.contracts.hemi_prove_registry = TESTNET_REGISTRY.to_string();
            config.contracts.hemi_token = TESTNET_TOKEN.to_string();
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
    println!("  Router:  {TESTNET_HEMI_PROVE}");
    println!("  Token:   {TESTNET_TOKEN} (tHEMI — has public mint())");
    println!();
    println!("Next steps:");
    println!("  1. Set your private key:");
    println!("     export ZKMINER_PRIVATE_KEY=0xYOUR_KEY");
    println!("  2. Fund your wallet with testnet ETH (for gas)");
    println!("  3. Mint testnet HEMI tokens (via the Wallet screen)");
    println!("  4. Stake at least 100 HEMI (via the Wallet screen)");
    println!("  5. Run: zkminer run");

    Ok(())
}
