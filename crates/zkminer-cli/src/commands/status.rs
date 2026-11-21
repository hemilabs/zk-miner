use anyhow::Result;
use std::path::Path;
use zkminer_chain::client::ChainClient;
use zkminer_config::wallet::load_signer;
use zkminer_config::ZkMinerConfig;

/// What this home's own files say, read before (and without) the chain: the locks the journal
/// holds, and whether a miner is running to drive them.
pub(crate) struct Local {
    pub lines: Vec<String>,
    /// Locks held with no miner running to drive them: each is slashed unless one starts in time.
    pub harmful: bool,
}

/// [`Local`] for `journal` (the default path's, or why it could not be read) at `now` (unix
/// seconds), with a miner `running` here or not (`None`: unknown).
pub(crate) fn held_locks(
    journal: &std::result::Result<crate::journal::JobJournal, String>,
    now: u64,
    running: Option<bool>,
) -> Local {
    let journal = match journal {
        Ok(j) => j,
        Err(e) => {
            return Local {
                lines: vec![format!(
                    "Held locks:     unknown: the job journal could not be read ({e})"
                )],
                harmful: false,
            }
        }
    };
    let live: Vec<u64> = journal
        .iter()
        .filter(|e| e.lock_deadline == 0 || e.lock_deadline > now)
        .map(|e| e.lock_deadline)
        .collect();
    let past = journal.iter().count() - live.len();
    let mut lines = Vec::new();
    if live.is_empty() && past == 0 {
        lines.push("Held locks:     none".to_string());
        return Local {
            lines,
            harmful: false,
        };
    }
    let by = super::run::start_by(live.iter().copied())
        .map(|t| format!(", start a miner by {t}"))
        .unwrap_or_default();
    lines.push(format!(
        "Held locks:     {} in the job journal{}",
        live.len(),
        if past > 0 {
            format!(" (and {past} past its cutoff, for the next start to clear up)")
        } else {
            String::new()
        }
    ));
    let harmful = running == Some(false) && !live.is_empty();
    match running {
        Some(true) => lines.push("Miner:          running here, driving them".to_string()),
        Some(false) if live.is_empty() => {
            lines.push("Miner:          not running here".to_string())
        }
        Some(false) => lines.push(format!(
            "Miner:          [!] NOT running here: nothing drives them{by}, or they are slashed"
        )),
        None => lines.push("Miner:          unknown (miner.lock could not be checked)".to_string()),
    }
    Local { lines, harmful }
}

/// [`Local`] for this home now.
pub(crate) fn local() -> Local {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    held_locks(
        &crate::journal::JobJournal::peek_checked(),
        now,
        super::stop::instance_running().ok(),
    )
}

pub async fn run(config_path: Option<&Path>) -> Result<()> {
    println!("zkminer status");
    println!("══════════════════════════════════════════════════");
    // This home's own state first: it needs no chain, and an operator moving a service checks it.
    let local = local();
    for line in &local.lines {
        println!("{line}");
    }
    let config = ZkMinerConfig::load(config_path)?;
    config.validate_for_chain()?;
    let signer = load_signer(&config.wallet)?;
    let client = ChainClient::new(&config, signer).await?;
    if let Some(banner) = config.dev_mode_banner() {
        println!("!! {banner} !!");
        println!("══════════════════════════════════════════════════");
    }
    let guard = client.elf_fetcher().guard_warnings();
    for line in &guard {
        println!("!! {line}");
    }
    if !guard.is_empty() {
        println!("══════════════════════════════════════════════════");
    }
    println!("Prover Address: {}", client.address);
    println!(
        "Network:        {} (chain {})",
        match zkminer_chain::deployment::known_deployment(client.chain_id) {
            Some(_) if client.chain_id == zkminer_chain::staking::TESTNET_CHAIN_ID =>
                "Hemi testnet",
            Some(_) => "a known deployment",
            None => "no known deployment",
        },
        client.chain_id
    );
    // The check `zkminer run` makes before it claims, and `stake` before it sends.
    match client.verify_deployment().await {
        Ok(_) => println!("Deployment:     verified"),
        Err(e) => {
            println!("Deployment:     NOT verified, so `zkminer run` and `stake` refuse it: {e:#}")
        }
    }

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
            println!(
                "Total Staked:       {} HEMI",
                format_token(stake.total_staked)
            );
            println!(
                "Locked Collateral:  {} HEMI",
                format_token(stake.locked_collateral)
            );
            println!(
                "Available:          {} HEMI",
                format_token(stake.available_collateral)
            );
            // What `run` lets every lock it holds come to together (`[prover]
            // max_locked_stake_fraction`): a job that would take them over it waits.
            let lock_cap = super::run::collateral::CapPolicy {
                fraction: config.prover.max_locked_stake_fraction,
                floor: per_claim,
            }
            .cap(stake.total_staked);
            if let Some(cap) = lock_cap {
                println!(
                    "Lock cap:           {} HEMI held at once ({:.0}% of the stake, \
                     [prover] max_locked_stake_fraction)",
                    format_token(cap),
                    config.prover.max_locked_stake_fraction * 100.0
                );
            }
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
                    println!(
                        "                    [!] cannot fund even a minimum claim — stake more"
                    );
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
    // The way out: a pending unstake and payouts the router holds (the stake lines are above).
    match client.get_exit_state(client.address).await {
        Ok(exit) => {
            for line in super::unstake::describe_exit(&exit) {
                println!("{line}");
            }
        }
        Err(e) => println!("Unstake/payouts:    Error: {e:#}"),
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
            println!(
                "Total Earned:       {} HEMI",
                format_token(stats.total_earned)
            );
        }
        Err(e) => println!("\nProver stats:   Error: {}", e),
    }

    // The slash latch: while it is tripped `run` claims nothing new, and this exits 2 so a cron or
    // monitoring check can alert on it.
    let (latched, lines) = super::run::slash_latch::describe(client.chain_id, client.address);
    println!();
    for (i, line) in lines.iter().enumerate() {
        let label = if i == 0 { "Slash latch:" } else { "" };
        println!("{label:<20}{line}");
    }

    // Block number
    match client.get_block_number().await {
        Ok(block) => println!("\nCurrent Block:      {}", block),
        Err(e) => println!("\nBlock number:   Error: {}", e),
    }

    if latched {
        std::process::exit(2);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::journal::JobJournal;
    use alloy_primitives::B256;

    /// The held-locks lines: none, held with a miner running, held with none (harmful), and a
    /// journal that could not be read.
    #[test]
    fn held_locks_are_reported_from_the_journal() {
        let now = 1_900_000_000;
        let empty = held_locks(&Ok(JobJournal::default()), now, Some(false));
        assert_eq!(empty.lines, ["Held locks:     none"]);
        assert!(!empty.harmful);
        let mut j = JobJournal::default();
        j.record_claim_intent(B256::repeat_byte(1), now + 7_200, None);
        j.record_claim_intent(B256::repeat_byte(2), now - 10, None);
        let held = Ok(j);
        let running = held_locks(&held, now, Some(true));
        assert!(
            running.lines[0].contains("1 in the job journal")
                && running.lines[0].contains("1 past")
        );
        assert!(!running.harmful);
        let stopped = held_locks(&held, now, Some(false));
        assert!(stopped.harmful);
        assert!(
            stopped.lines[1].contains("NOT running"),
            "{:?}",
            stopped.lines
        );
        let unread = held_locks(&Err("denied".into()), now, Some(false));
        assert!(unread.lines[0].contains("unknown") && !unread.harmful);
    }
}
