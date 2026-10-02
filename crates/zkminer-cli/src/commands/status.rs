use anyhow::Result;
use std::path::Path;
use zkminer_chain::client::ChainClient;
use zkminer_config::ZkMinerConfig;
use zkminer_config::wallet::load_signer;

pub async fn run(config_path: Option<&Path>) -> Result<()> {
    let config = ZkMinerConfig::load(config_path)?;
    config.validate_for_chain()?;
    let signer = load_signer(&config.wallet)?;
    let client = ChainClient::new(&config, signer).await?;

    println!("zkminer status");
    println!("══════════════════════════════════════════════════");
    println!("Prover Address: {}", client.address);

    // ETH balance
    match client.get_eth_balance().await {
        Ok(balance) => {
            let eth = format_wei(balance);
            println!("ETH Balance:    {} ETH", eth);
        }
        Err(e) => println!("ETH Balance:    Error: {}", e),
    }

    // HEMI balance
    match client.get_hemi_balance(client.address).await {
        Ok(balance) => {
            let hemi = format_u256_token(balance);
            println!("HEMI Balance:   {} HEMI", hemi);
        }
        Err(e) => println!("HEMI Balance:   Error: {}", e),
    }

    // Floor on what a claim locks. The contract minimum is a LOWER bound (a real claim
    // reserves at the auction's max_price, so it locks more), which keeps the derived
    // "slots fundable" optimistic rather than alarmist — the right bias for a status line.
    let per_claim = client.get_min_collateral_amount().await.unwrap_or(0);

    // Stake info
    match client.get_stake_info(client.address).await {
        Ok(stake) => {
            println!();
            println!("Staking");
            println!("──────────────────────────────────────────────────");
            println!("Total Staked:       {} HEMI", format_token(stake.total_staked));
            println!("Locked Collateral:  {} HEMI", format_token(stake.locked_collateral));
            println!("Available:          {} HEMI", format_token(stake.available_collateral));
            // Derived verdict: `status` printed the three numbers and left the division to
            // the reader, which is how a 4.25 HEMI shortfall idled a GPU unnoticed.
            // Reported as ADDITIONAL slots: from chain alone a live lock is indistinguishable
            // from a stranded one (this operator has 2,955 HEMI permanently stranded), so
            // `locked / per_claim` would print a healthy "2 of 2" on a starving wallet.
            if per_claim > 0 {
                let extra = stake.available_collateral / per_claim;
                // Label the basis explicitly. `per_claim` here is the CONTRACT MINIMUM, a
                // hard lower bound: a real claim reserves at the auction's max_price and in
                // practice locked ~150 HEMI against this 10 HEMI floor — a 15x gap. Printing
                // a bare "48 more" would have looked perfectly healthy on the wallet that was
                // starving, which is the exact failure this line exists to prevent. The
                // realistic figure needs a live auction price; until the brain's
                // `cheapest_collateral_block` is plumbed here, state the bound honestly.
                println!(
                    "Slots fundable:     <= {} more at the {} HEMI contract minimum",
                    extra,
                    format_token(per_claim)
                );
                if extra == 0 {
                    println!("                    [!] cannot fund even a minimum claim — stake more");
                } else {
                    println!(
                        "                    (a real claim locks the auction max_price, so the \
true figure is lower)"
                    );
                }
            }

            if stake.deposit_block > 0 {
                // Contract stores the deposit block number (not a timestamp).
                println!("Deposit Block:      {}", stake.deposit_block);
            }
        }
        Err(e) => println!("\nStaking info:   Error: {}", e),
    }

    // Prover stats
    match client.get_prover_stats(client.address).await {
        Ok(stats) => {
            println!();
            println!("Statistics");
            println!("──────────────────────────────────────────────────");
            println!("Jobs Fulfilled:     {}", stats.jobs_fulfilled);
            println!("Jobs Slashed:       {}", stats.jobs_slashed);
            println!("Jobs Released:      {}", stats.jobs_released);
            println!("Total Earned:       {} HEMI", format_token(stats.total_earned));
        }
        Err(e) => println!("\nProver stats:   Error: {}", e),
    }

    // Block number
    match client.get_block_number().await {
        Ok(block) => println!("\nCurrent Block:      {}", block),
        Err(e) => println!("\nBlock number:   Error: {}", e),
    }

    Ok(())
}

fn format_wei(value: alloy_primitives::U256) -> String {
    let divisor = alloy_primitives::U256::from(1_000_000_000_000_000_000u128);
    let whole = value / divisor;
    let frac = value % divisor;
    let frac_num = frac.to::<u128>();
    let decimals = frac_num / 1_000_000_000_000_000; // 3 decimal places
    format!("{}.{:03}", whole, decimals)
}

fn format_u256_token(value: alloy_primitives::U256) -> String {
    format_wei(value)
}

fn format_token(value: u128) -> String {
    let whole = value / 1_000_000_000_000_000_000;
    let frac = (value % 1_000_000_000_000_000_000) / 1_000_000_000_000_000;
    format!("{}.{:03}", whole, frac)
}
