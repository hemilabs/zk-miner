//! `zkminer unstake` and `zkminer withdraw`: getting stake and payouts back out.
//!
//! Leaving takes two transactions a week apart: `unstake <AMOUNT>` requests it (`requestUnstake`),
//! and `withdraw` pays it out once the 7-day cooldown has passed and the prover has settled nothing
//! for an hour. `withdraw` also collects payouts the router credited instead of transferring
//! (`withdrawableBalances`), which nothing else in the miner shows or collects. Each transaction is
//! checked against the contract from this account before it is sent, so a refusal ("not ready until
//! …", "only 12.50 HEMI is free") comes back in words and costs nothing. Both commands take the same
//! key guards as `stake` (see `signer_guard`). The deployment check only warns here: these send no
//! tokens in, and the stacks that fail it are the ones an operator most needs to leave.

use anyhow::{Context, Result};
use std::path::Path;
use zkminer_chain::client::ChainClient;
use zkminer_chain::exit::{fmt_unix, ExitRefused, ExitState, ExitTx};
use zkminer_config::wallet::load_signer;
use zkminer_config::ZkMinerConfig;

use super::signer_guard;
use super::stake::parse_hemi;

/// What `unstake` was asked to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnstakeAction {
    /// Request this many HEMI (decimal text, as typed).
    Amount(String),
    /// Request all free stake.
    All,
    /// Cancel the pending request.
    Cancel,
}

async fn connect(config_path: Option<&Path>) -> Result<ChainClient> {
    let config = ZkMinerConfig::load(config_path)?;
    config.validate_for_chain()?;
    let signer = load_signer(&config.wallet)?;
    let client = ChainClient::new(&config, signer).await?;
    signer_guard::warn_unless_deployment_verified(&client).await;
    Ok(client)
}

/// The stake after this command's own confirmed transaction(s), and the slash latch's baseline moved
/// to it from `before` (review 7 LD-1: a stake or unstake made while the miner is stopped is not an
/// unexplained fall at its next start). The head is read first, so the latch's next event range
/// starts after the transaction.
async fn state_after_own_tx(client: &ChainClient, before: &ExitState) -> Result<ExitState> {
    let block = client.get_block_number().await.ok();
    let after = client.get_exit_state(client.address).await;
    if let Ok(a) = &after {
        super::run::slash_latch::rebaseline_after_own_tx(
            client.chain_id,
            client.address,
            (before.total_staked, before.pending_unstake),
            (a.total_staked, a.pending_unstake),
            block,
        );
    }
    after
}

/// A wei amount in HEMI, exact: at least 3 decimals, more only when the amount has them (so an
/// `--all` of 12.3456 HEMI is shown as that, not rounded up to 12.346).
pub(crate) fn fmt_hemi_exact(wei: u128) -> String {
    const ONE: u128 = 1_000_000_000_000_000_000;
    let frac = format!("{:018}", wei % ONE);
    let trimmed = frac.trim_end_matches('0');
    let shown = if trimmed.len() < 3 {
        &frac[..3]
    } else {
        trimmed
    };
    format!("{}.{shown}", wei / ONE)
}

/// "in 6d 23h" / "in 42m" / "now".
fn fmt_wait(secs: u64) -> String {
    match secs {
        0 => "now".to_string(),
        s if s >= 86_400 => format!("in {}d {}h", s / 86_400, (s % 86_400) / 3_600),
        s if s >= 3_600 => format!("in {}h {}m", s / 3_600, (s % 3_600) / 60),
        s => format!("in {}m", s.div_ceil(60)),
    }
}

/// The stake lines `unstake` and `withdraw` print (`status` has its own).
fn describe_stake(e: &ExitState) -> Vec<String> {
    vec![
        format!(
            "Staked:             {} HEMI",
            fmt_hemi_exact(e.total_staked)
        ),
        format!(
            "Locked in jobs:     {} HEMI",
            fmt_hemi_exact(e.locked_collateral)
        ),
        format!(
            "Free:               {} HEMI",
            fmt_hemi_exact(e.available_collateral)
        ),
    ]
}

/// The way-out lines `unstake`, `withdraw` and `status` print: the pending unstake and the payouts
/// held. Waits count from the chain's time, which the cooldowns run on.
pub(crate) fn describe_exit(e: &ExitState) -> Vec<String> {
    let mut lines = Vec::new();
    match e.unstake_ready_at() {
        Some(ready) => lines.push(format!(
            "Unstake pending:    {} HEMI, withdrawable from {} ({})",
            fmt_hemi_exact(e.pending_unstake),
            fmt_unix(ready),
            fmt_wait(ready.saturating_sub(e.chain_time))
        )),
        None => lines.push("Unstake pending:    none".to_string()),
    }
    match e.withdrawable_payouts {
        Some(p) => {
            let payouts = u128::try_from(p).unwrap_or(u128::MAX);
            lines.push(format!(
                "Payouts held:       {} HEMI{}",
                fmt_hemi_exact(payouts),
                if payouts > 0 {
                    " (collect with `zkminer withdraw`)"
                } else {
                    ""
                }
            ));
        }
        None => lines.push("Payouts held:       unknown (could not be read)".to_string()),
    }
    lines
}

fn print_state(title: &str, client: &ChainClient, e: &ExitState) {
    println!("{title}");
    println!("──────────────────────────────────────────────────");
    println!("Account:            {:?}", client.address);
    for line in describe_stake(e).into_iter().chain(describe_exit(e)) {
        println!("{line}");
    }
}

fn print_after(client_state: Result<ExitState>) {
    match client_state {
        Ok(after) => {
            println!();
            for line in describe_stake(&after)
                .into_iter()
                .chain(describe_exit(&after))
            {
                println!("{line}");
            }
        }
        Err(e) => println!("(sent, but could not re-read the stake: {e:#})"),
    }
}

/// Explain a contract refusal and stop, or pass any other error on.
fn refused(e: anyhow::Error) -> anyhow::Error {
    match e.downcast_ref::<ExitRefused>() {
        Some(r) => anyhow::anyhow!("{r}"),
        None => e,
    }
}

pub async fn run_unstake(
    config_path: Option<&Path>,
    action: UnstakeAction,
    dry_run: bool,
    force: bool,
    yes: bool,
) -> Result<()> {
    let client = connect(config_path).await?;
    let before = client.get_exit_state(client.address).await?;
    print_state("Unstake", &client, &before);

    let (tx, question) = match &action {
        UnstakeAction::Cancel => {
            if before.pending_unstake == 0 {
                anyhow::bail!("there is no pending unstake to cancel");
            }
            (
                ExitTx::CancelUnstake,
                format!(
                    "Cancel the pending unstake of {} HEMI and count it back as stake? (If the \
                     staking cap is nearly full, only part of it may count back; the rest stays \
                     pending.)",
                    fmt_hemi_exact(before.pending_unstake)
                ),
            )
        }
        UnstakeAction::All | UnstakeAction::Amount(_) => {
            let wei = match &action {
                UnstakeAction::Amount(a) => parse_hemi(a)?,
                _ => before.available_collateral,
            };
            if wei == 0 {
                anyhow::bail!(
                    "no stake is free to unstake (all of it is locked in jobs or already pending)"
                );
            }
            if matches!(action, UnstakeAction::All) && before.locked_collateral > 0 {
                // Only one request can be pending: the locked part needs another 7-day round.
                println!(
                    "Note: {} HEMI is locked in jobs the miner holds and is not included. Only one \
                     unstake can be pending, so taking that out later starts another 7-day wait; to \
                     leave entirely, stop the miner (`zkminer stop`) first and let its jobs settle.",
                    super::stake::fmt_hemi(before.locked_collateral)
                );
            }
            (
                ExitTx::RequestUnstake(wei),
                format!(
                    "Request to unstake {} HEMI? It can be withdrawn 7 days from now with `zkminer \
                     withdraw` (and not within an hour of a fulfil, release or slash). Until then \
                     it is not available as collateral, and if the staking cap fills up meanwhile \
                     the request may not be cancellable.",
                    fmt_hemi_exact(wei)
                ),
            )
        }
    };

    // Ask the contract first: a refusal costs nothing and says why.
    client.precheck_exit(tx).await.map_err(refused)?;
    if dry_run {
        println!(
            "\n--dry-run: the contract would accept {}; nothing sent.",
            tx.name()
        );
        return Ok(());
    }
    let key_check = signer_guard::ensure_key_is_free(&client, force).await?;
    signer_guard::confirm(&question, yes)?;
    signer_guard::recheck_after_prompt(&client, &key_check).await?;

    let hash = client.send_exit(tx).await.map_err(refused)?;
    println!("\n{} confirmed: {hash:?}", tx.name());
    let after = state_after_own_tx(&client, &before).await;
    // A cancel counts back only what the staking cap has room for (`UnstakeCancelled`).
    if let (ExitTx::CancelUnstake, Ok(a)) = (tx, &after) {
        if a.pending_unstake > 0 {
            println!(
                "Only part of the request counted back: {} HEMI is still pending (the staking cap \
                 had no room for it). Withdraw it when it is ready.",
                fmt_hemi_exact(a.pending_unstake)
            );
        }
    }
    print_after(after);
    Ok(())
}

pub async fn run_withdraw(
    config_path: Option<&Path>,
    dry_run: bool,
    force: bool,
    yes: bool,
) -> Result<()> {
    let client = connect(config_path).await?;
    let before = client.get_exit_state(client.address).await?;
    print_state("Withdraw", &client, &before);

    // What can go out now, each checked against the contract. Payouts are checked whenever their
    // balance is not known to be zero (an unread balance is checked too).
    let payouts = before.withdrawable_payouts;
    let mut ready = Vec::new();
    let mut notes = Vec::new();
    if before.pending_unstake > 0 {
        match client.precheck_exit(ExitTx::WithdrawUnstaked).await {
            Ok(()) => ready.push((
                ExitTx::WithdrawUnstaked,
                format!(
                    "the unstaked {} HEMI",
                    fmt_hemi_exact(before.pending_unstake)
                ),
            )),
            Err(e) => match e.downcast_ref::<ExitRefused>() {
                Some(r) => notes.push(format!("Unstake not withdrawable yet: {}", r.reason)),
                None => return Err(e),
            },
        }
    }
    if payouts.is_none_or(|p| !p.is_zero()) {
        let label = match payouts {
            Some(p) => format!(
                "{} HEMI of payouts",
                fmt_hemi_exact(u128::try_from(p).unwrap_or(u128::MAX))
            ),
            None => "the payouts held".to_string(),
        };
        match client.precheck_exit(ExitTx::WithdrawPayouts).await {
            Ok(()) => ready.push((ExitTx::WithdrawPayouts, label)),
            Err(e) => match (e.downcast_ref::<ExitRefused>(), payouts) {
                (Some(r), Some(_)) => notes.push(format!("Payouts not withdrawable: {}", r.reason)),
                // Unread and refused: most likely there are none.
                (Some(_), None) => {}
                (None, _) => return Err(e),
            },
        }
    }
    for n in &notes {
        println!("\n{n}");
    }
    if ready.is_empty() {
        // Non-zero either way, so a script can tell "withdrew" from "did nothing".
        if before.pending_unstake == 0 && payouts.is_some_and(|p| p.is_zero()) {
            anyhow::bail!(
                "nothing to withdraw. To take stake out, request it first: `zkminer unstake \
                 <HEMI>` (or `--all`), then run this 7 days later"
            );
        }
        anyhow::bail!("nothing can be withdrawn yet; nothing sent");
    }
    let what: Vec<&str> = ready.iter().map(|(_, w)| w.as_str()).collect();
    if dry_run {
        println!(
            "\n--dry-run: would withdraw {}; nothing sent.",
            what.join(" and ")
        );
        return Ok(());
    }
    let key_check = signer_guard::ensure_key_is_free(&client, force).await?;
    signer_guard::confirm(
        &format!("Withdraw {} to {:?}?", what.join(" and "), client.address),
        yes,
    )?;
    signer_guard::recheck_after_prompt(&client, &key_check).await?;

    let mut done: Vec<&str> = Vec::new();
    for (tx, w) in &ready {
        let hash = client
            .send_exit(*tx)
            .await
            .map_err(refused)
            .with_context(|| {
                if done.is_empty() {
                    format!("withdrawing {w}")
                } else {
                    format!("withdrawing {w} (after withdrawing {})", done.join(" and "))
                }
            })?;
        println!("\nWithdrew {w}: {hash:?}");
        done.push(w);
    }
    print_after(state_after_own_tx(&client, &before).await);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::U256;
    use zkminer_chain::exit::UNSTAKE_COOLDOWN_SECS;

    const HEMI: u128 = 1_000_000_000_000_000_000;

    #[test]
    fn waits_read_like_a_person_would_say_them() {
        assert_eq!(fmt_wait(0), "now");
        assert_eq!(fmt_wait(59), "in 1m");
        assert_eq!(fmt_wait(3 * 3600 + 120), "in 3h 2m");
        assert_eq!(fmt_wait(UNSTAKE_COOLDOWN_SECS - 3600), "in 6d 23h");
    }

    /// An `--all` amount is shown exactly: never rounded up past what is sent.
    #[test]
    fn amounts_are_shown_exactly() {
        assert_eq!(fmt_hemi_exact(0), "0.000");
        assert_eq!(fmt_hemi_exact(50 * HEMI), "50.000");
        assert_eq!(fmt_hemi_exact(5 * HEMI / 2), "2.500");
        assert_eq!(fmt_hemi_exact(12_345_600_000_000_000_000), "12.3456");
        assert_eq!(fmt_hemi_exact(1), "0.000000000000000001");
    }

    #[test]
    fn the_exit_summary_names_the_pending_unstake_and_the_payouts() {
        let now = 1_800_000_000;
        let e = ExitState {
            total_staked: 300 * HEMI,
            locked_collateral: 150 * HEMI,
            available_collateral: 50 * HEMI,
            pending_unstake: 100 * HEMI,
            unstake_requested_at: now - 86_400,
            last_activity_at: 0,
            withdrawable_payouts: Some(U256::from(5 * HEMI / 2)),
            chain_time: now,
        };
        let text = describe_stake(&e)
            .into_iter()
            .chain(describe_exit(&e))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(text.contains("Free:               50.000 HEMI"), "{text}");
        assert!(text.contains("100.000 HEMI, withdrawable from"), "{text}");
        assert!(text.contains("(in 6d 0h)"), "{text}");
        assert!(
            text.contains("Payouts held:       2.500 HEMI (collect with"),
            "{text}"
        );
        let none = ExitState {
            pending_unstake: 0,
            withdrawable_payouts: Some(U256::ZERO),
            ..e.clone()
        };
        let text = describe_exit(&none).join("\n");
        assert!(text.contains("Unstake pending:    none"), "{text}");
        assert!(!text.contains("collect with"), "{text}");
        let unread = ExitState {
            withdrawable_payouts: None,
            ..e
        };
        assert!(describe_exit(&unread).join("\n").contains("unknown"));
    }
}
