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
    for line in summary(network) {
        println!("{line}");
    }

    Ok(())
}

/// What `init` prints after writing the config: the network it targets and, on testnet, the steps
/// from there to a mining prover. Every step names the command that does it (W10-DOC: step 3 used to
/// point at a "Wallet screen" although `zkminer stake` exists). The testnet facts are the 2026-11-16
/// deployment's (handoff section 12): tHEMI is minted only by its owner, so it comes from the
/// HemiProve team, and each lock needs 100 tHEMI of free stake (the 100 tHEMI minimum collateral).
fn summary(network: &str) -> Vec<String> {
    if network != "testnet" {
        return vec![
            format!("Hemi mainnet (chain ID {MAINNET_CHAIN_ID}), RPC {MAINNET_RPC}."),
            "No HemiProve deployment on mainnet is built in: fill in [contracts] in the config"
                .to_string(),
            "before you run anything.".to_string(),
        ];
    }
    vec![
        format!("Pre-configured for Hemi Testnet (chain ID {TESTNET_CHAIN_ID})"),
        format!("  RPC:     {TESTNET_RPC}"),
        format!("  Router:  {}", TESTNET.router),
        format!("  Token:   {} (tHEMI, owner-minted)", TESTNET.token),
        String::new(),
        "Next steps:".to_string(),
        "  1. Set the prover's private key (a key of your own; zkminer does not make one):".to_string(),
        "       export ZKMINER_PRIVATE_KEY=0xYOUR_KEY".to_string(),
        "  2. Ask the HemiProve team for testnet ETH (gas; a Hemi testnet faucet also works) and".to_string(),
        "     tHEMI for that key's address. tHEMI is minted only by its owner. Each job you hold at".to_string(),
        "     once locks at least 100 tHEMI of stake.".to_string(),
        "  3. Stake it: zkminer stake 100      (approves and stakes; the amount is in tHEMI)".to_string(),
        "     The first claim can come one block after the first stake.".to_string(),
        "  4. Check:    zkminer status".to_string(),
        "  5. Run:      zkminer run".to_string(),
    ]
}

#[cfg(test)]
mod tests {
    use super::summary;

    #[test]
    fn testnet_steps_name_the_commands() {
        let text = summary("testnet").join("\n");
        assert!(text.contains("export ZKMINER_PRIVATE_KEY="), "{text}");
        assert!(text.contains("HemiProve team"), "{text}");
        assert!(text.contains("zkminer stake 100"), "{text}");
        assert!(text.contains("zkminer status"), "{text}");
        assert!(text.contains("zkminer run"), "{text}");
        assert!(!text.contains("Wallet screen"), "{text}");
        assert!(
            text.contains("0xD931725db336B57dBB9A3123F2238A4FE3c6Ed58"),
            "{text}"
        );
        assert!(
            text.contains("0x46955EdCF61b23a8c0b0d71428A9F1C07Bbf36cc"),
            "{text}"
        );
    }

    #[test]
    fn mainnet_is_not_described_as_testnet() {
        let text = summary("mainnet").join("\n");
        assert!(!text.contains("Testnet"), "{text}");
        assert!(text.contains("43111"), "{text}");
        assert!(text.contains("[contracts]"), "{text}");
    }
}
