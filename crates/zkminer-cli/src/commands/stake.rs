//! `zkminer stake <AMOUNT>` — add collateral so more GPU slots can be funded.
//!
//! WHY THIS EXISTS: on 2026-08-08 this miner ran at half throughput for hours because
//! available collateral was 295.75 HEMI against the 300.00 needed to fund two concurrent
//! claims — short by 4.25, with 444,804 HEMI idle in the wallet. The remedy already existed
//! in the chain layer (`ChainClient::approve_and_stake`) but was reachable only from the TUI
//! first-run wizard, hardcoded to 100 HEMI. Doing it by hand meant knowing that the ABI is
//! `stake(address,uint128)` — passing `uint256` produces a transaction that silently does
//! nothing — and that an ERC-20 approve is needed first because the allowance starts at zero.
//!
//! This command is the whole remedy in one line, with the units handled.

use alloy::providers::Provider;
use anyhow::{Context, Result};
use std::io::Write;
use std::path::Path;
use zkminer_chain::client::ChainClient;
use zkminer_config::wallet::load_signer;
use zkminer_config::ZkMinerConfig;

/// 1 HEMI in wei.
const WEI_PER_HEMI: u128 = 1_000_000_000_000_000_000;

fn fmt_hemi(wei: u128) -> String {
    format!("{:.3}", wei as f64 / WEI_PER_HEMI as f64)
}

/// Balances come back as U256; render them in HEMI like everything else on screen.
fn fmt_u256_hemi(v: alloy::primitives::U256) -> String {
    // Saturate rather than panic: a balance beyond u128 is not representable here, and a
    // display path must never abort a staking command.
    let as_u128 = u128::try_from(v).unwrap_or(u128::MAX);
    fmt_hemi(as_u128)
}

/// Parse a decimal HEMI amount into wei.
///
/// Deliberately takes HEMI, not wei: an operator reading "short 4.25 HEMI" should be able to
/// type `zkminer stake 10`. Accepting wei here would invite `zkminer stake 500` to mean 500
/// wei — a 1e18 error that looks like success and stakes nothing measurable.
fn parse_hemi(s: &str) -> Result<u128> {
    let s = s.trim();
    if s.is_empty() {
        anyhow::bail!("empty amount");
    }
    let (whole, frac) = match s.split_once('.') {
        Some((w, f)) => (w, f),
        None => (s, ""),
    };
    if frac.len() > 18 {
        anyhow::bail!("more than 18 decimal places");
    }
    let whole: u128 = whole
        .parse()
        .with_context(|| format!("not a number: {s:?}"))?;
    let mut wei = whole
        .checked_mul(WEI_PER_HEMI)
        .context("amount too large")?;
    if !frac.is_empty() {
        let padded = format!("{frac:0<18}");
        let frac_wei: u128 = padded.parse().context("bad fractional part")?;
        wei = wei.checked_add(frac_wei).context("amount too large")?;
    }
    if wei == 0 {
        anyhow::bail!("amount must be greater than zero");
    }
    Ok(wei)
}

/// Does this process share our signing key?
///
/// Pure so it can actually be tested: the previous test asserted only that the scan does not
/// match itself, which was vacuous — the test binary's comm is `zkminer-<hash>`, rejected by
/// the name check before the self-skip ever mattered.
fn shares_our_signer(comm: &str, cmdline: &[u8]) -> bool {
    if comm != "zkminer" {
        return false;
    }
    let args: Vec<&[u8]> = cmdline.split(|b| *b == 0).collect();
    // `run --mock` never loads a signer or a provider (main.rs routes it before config load),
    // so it shares no nonce. Refusing on it would teach --force as a habit, which is what
    // makes a real collision likely.
    args.iter().any(|a| *a == b"run") && !args.iter().any(|a| *a == b"--mock")
}

/// PIDs of other live `zkminer run` processes.
///
/// The mempool check below (pending != latest) is necessary but NOT sufficient: it only
/// sees a tx that is in the mempool *right now*. Observed live — the miner confirms a tx
/// in ~13s and claims every ~30-60s, so there are wide windows where pending == latest
/// while the miner is very much running. The guard sailed straight through on the first
/// live test for exactly that reason. Process presence has no such window.
///
/// Scans /proc directly rather than shelling out to pgrep: `pgrep -f zkminer` matches the
/// invoking shell's own command line (this footgun killed the operator's shell twice in
/// this project), and `comm` is the exact executable name, so it cannot self-match a
/// pattern. Own PID is excluded.
fn other_running_miners() -> Vec<i32> {
    let me = std::process::id() as i32;
    let mut found = Vec::new();
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return found; // not Linux, or /proc unavailable: fall through to the mempool check
    };
    for e in entries.flatten() {
        let Ok(pid) = e.file_name().to_string_lossy().parse::<i32>() else {
            continue;
        };
        if pid == me {
            continue;
        }
        // comm is the executable name, NUL/newline-terminated; not attacker-shaped here.
        let Ok(comm) = std::fs::read_to_string(e.path().join("comm")) else {
            continue;
        };
        if comm.trim() != "zkminer" {
            continue;
        }
        // Only `run` shares the signer; a concurrent `status` or `benchmark` sends nothing.
        let Ok(cmdline) = std::fs::read(e.path().join("cmdline")) else {
            continue;
        };
        if shares_our_signer(comm.trim(), &cmdline) {
            found.push(pid);
        }
    }
    found
}

pub async fn run(
    config_path: Option<&Path>,
    amount: String,
    dry_run: bool,
    force: bool,
    yes: bool,
) -> Result<()> {
    let wei = parse_hemi(&amount)?;

    let config = ZkMinerConfig::load(config_path)?;
    config.validate_for_chain()?;
    let signer = load_signer(&config.wallet)?;
    let client = ChainClient::new(&config, signer).await?;

    // Read the before-state so the operator can see the change rather than trust it.
    let before = client.get_stake_info(client.address).await.ok();
    let balance = client.get_hemi_balance(client.address).await?;
    let per_claim = client.get_min_collateral_amount().await.unwrap_or(0);

    println!("Stake");
    println!("──────────────────────────────────────────────────");
    println!("Account:        {:?}", client.address);
    println!("Amount:         {} HEMI", fmt_hemi(wei));
    // Format it: printing raw wei here would be the exact unit confusion this command
    // exists to prevent, in the command's own output.
    println!("Wallet HEMI:    {} HEMI", fmt_u256_hemi(balance));
    if let Some(b) = &before {
        println!("Staked now:     {} HEMI", fmt_hemi(b.total_staked));
        println!("Available now:  {} HEMI", fmt_hemi(b.available_collateral));
    }

    if dry_run {
        println!();
        println!("--dry-run: nothing sent.");
        // Do NOT eth_call the stake as a "check": `stake` is access-controlled, and a call
        // without an explicit `from` is made from the zero address, so it reverts
        // Unauthorized() even when the real transaction would succeed. A pre-flight that
        // fails on every healthy input is worse than none.
        if let Some(b) = &before {
            if per_claim > 0 {
                let now = b.available_collateral / per_claim;
                let after = (b.available_collateral.saturating_add(wei)) / per_claim;
                // Quote this the way `status` does — as a ceiling at the contract floor,
                // never as a bare before->after count. A real claim locks the auction
                // max_price, which has run 5-15x the 10 HEMI minimum, so the bare number
                // reads "healthy" on precisely the wallet that is starving. An operator
                // dry-running before committing would conclude the miner's warning is
                // bogus and under-stake.
                println!(
                    "Fundable claims: <= {now} -> <= {after}, at the {} HEMI contract minimum.",
                    fmt_hemi(per_claim)
                );
                println!(
                    "These are UPPER BOUNDS, not a forecast: a claim locks the auction \
                     max_price, so the real number is lower — often several times lower. \
                     Size the stake from the shortfall the miner reports, not from this line."
                );
            }
        }
        return Ok(());
    }

    // ── D1: cross-process nonce guard ────────────────────────────────────────────
    // The miner and this CLI are separate processes over ONE signer, and the nonce
    // allocator is per-process: each anchors a fresh NonceManager at the node's pending
    // count, so both hand out the SAME nonce (asserted in zkminer-chain's
    // tests/stake_tx_shape.rs). Worse, the staking path never joins the fee-escalation
    // protocol -- it neither records a broadcast fee nor reads the per-nonce floor -- so
    // if this tx outbids an in-flight fulfillJob it REPLACES it, the deadline is missed,
    // and the collateral is locked until a keeper slashes it. That is fund loss, not delay.
    //
    // Second net, for a signer shared with something this box cannot see (another host, a
    // script, a hardware wallet): pending > latest means txs are in the mempool right now.
    // Narrower than the process check above — it misses the gaps between confirmations —
    // but it catches sharers that are not local processes.
    let running = other_running_miners();
    if !running.is_empty() {
        let pids = running
            .iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        if force {
            // Never bypass the PRIMARY fund-loss guard in silence. The weaker mempool check
            // below already warns on its force path; this one held the pid and said nothing.
            eprintln!(
                "WARNING: --force with the miner running (pid {pids}). This tx may replace an \
                 in-flight fulfillJob and get that job's collateral slashed."
            );
        }
    }
    if !running.is_empty() && !force {
        anyhow::bail!(
            "The miner is running (pid {}) and shares this signing key.\n\
             \n\
             Staking now would reuse a nonce the miner has already broadcast on. If this tx \
             outbids an in-flight fulfillJob it replaces it, the job misses its deadline, and \
             the collateral is slashed.\n\
             \n\
             Stop the miner (Ctrl-C drains queued jobs cleanly), stake, then restart it.\n\
             Use --force only if you are certain no other process shares this key.",
            running
                .iter()
                .map(|p| p.to_string())
                .collect::<Vec<_>>()
                .join(", "),
        );
    }

    let latest = client
        .provider
        .get_transaction_count(client.address)
        .await?;
    let pending = client
        .provider
        .get_transaction_count(client.address)
        .pending()
        .await?;
    if pending != latest {
        let in_flight = pending.saturating_sub(latest);
        if !force {
            anyhow::bail!(
                "This account has {in_flight} transaction(s) in flight (nonce {latest} -> \
                 {pending}) — the miner is almost certainly running.\n\
                 \n\
                 Staking now would reuse a nonce the miner has already broadcast on. If this \
                 tx outbids an in-flight fulfillJob it replaces it, the job misses its \
                 deadline, and the collateral is slashed.\n\
                 \n\
                 Stop the miner (Ctrl-C drains cleanly), stake, then restart it.\n\
                 Use --force only if you are certain no other process shares this key."
            );
        }
        eprintln!(
            "WARNING: --force with {in_flight} tx(s) in flight; this may displace a pending \
             transaction and get a job slashed."
        );
    }

    // ── D5: confirm an irreversible commitment ───────────────────────────────────
    // Exit is requestUnstake -> cooldown -> withdrawUnstaked, not immediate, and this
    // operator already has 2,955 HEMI permanently stranded. The only other bound on a
    // fat-fingered extra digit is the wallet balance.
    if !yes {
        print!(
            "\nStake {} HEMI? Unstaking is delayed, not immediate. [y/N] ",
            fmt_hemi(wei)
        );
        std::io::stdout().flush().ok();
        let mut answer = String::new();
        let read = std::io::stdin().read_line(&mut answer)?;
        // R5: decline and EOF must not exit 0. `main` returns Result, so a bare Ok(()) makes
        // "staked" and "did nothing" indistinguishable to any wrapper or `&&` chain — for the
        // very command the miner's warning tells operators to run.
        if read == 0 {
            anyhow::bail!(
                "no input on stdin (not a terminal?) — nothing sent; pass --yes to \
                           skip the confirmation in scripts"
            );
        }
        if !matches!(answer.trim(), "y" | "Y" | "yes" | "Yes") {
            anyhow::bail!("declined; nothing sent");
        }
    }

    // R4: the guard above is check-then-act, and the prompt just put unbounded HUMAN latency
    // inside that window — on the primary fund-loss guard. The window is not hypothetical:
    // this command tells the operator to "stake, then restart it", while the miner's own
    // shutdown tells them to "start the miner again to run recovery", and a restarted miner's
    // FIRST tx is recover_claimed_jobs -> fulfillJob. Re-check before committing.
    if !force {
        let now_running = other_running_miners();
        if !now_running.is_empty() {
            anyhow::bail!(
                "The miner started while the confirmation was pending (pid {}) — nothing sent. \
                 Stop it and re-run.",
                now_running
                    .iter()
                    .map(|p| p.to_string())
                    .collect::<Vec<_>>()
                    .join(", "),
            );
        }
    }

    println!();
    println!("Approving (if needed) and staking...");
    // `approve_and_stake` owns the whole sequence: balance pre-flight before any approval,
    // approve only when the allowance is short, then `stake(address,uint128)`, and — if the
    // stake reverts after an approval landed — revoking the residual allowance so no dangling
    // approval is left behind.
    // Deliberately NOT "no funds moved": on the unobserved-receipt path no receipt is ever
    // printed and the tx may still mine, so that phrasing is the retry invitation that
    // double-stakes behind a delayed unstake. StakeUnobserved carries its own honest
    // "MAY STILL BE PENDING" wording; only genuinely terminal errors (insufficient balance,
    // a mined revert) are definitive, and those say so themselves.
    client
        .approve_and_stake(wei)
        .await
        .context("stake did not complete")?;

    match client.get_stake_info(client.address).await {
        Ok(after) => {
            println!();
            println!("Staked:         {} HEMI", fmt_hemi(after.total_staked));
            println!(
                "Available:      {} HEMI",
                fmt_hemi(after.available_collateral)
            );
            if let Some(b) = &before {
                let delta = after.total_staked.saturating_sub(b.total_staked);
                println!("Change:         +{} HEMI staked", fmt_hemi(delta));
                // Catch the units mistake this command exists to prevent: a stake that lands
                // but moves nothing measurable means the amount was mis-scaled somewhere.
                if delta == 0 {
                    println!(
                        "WARNING: staked total did not change. The transaction succeeded but \
                         moved nothing — check the amount."
                    );
                }
            }
        }
        Err(e) => println!("(staked, but could not re-read stake info: {e:#})"),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_whole_and_fractional_hemi() {
        assert_eq!(parse_hemi("1").unwrap(), WEI_PER_HEMI);
        assert_eq!(parse_hemi("500").unwrap(), 500 * WEI_PER_HEMI);
        assert_eq!(parse_hemi("4.25").unwrap(), 4_250_000_000_000_000_000);
        assert_eq!(parse_hemi(" 10 ").unwrap(), 10 * WEI_PER_HEMI);
    }

    /// The shortfall the miner reports is a decimal like "4.25"; it must round-trip.
    #[test]
    fn parses_a_reported_shortfall() {
        assert_eq!(parse_hemi("4.250").unwrap(), 4_250_000_000_000_000_000);
    }

    #[test]
    fn rejects_junk_and_zero() {
        for bad in ["", "abc", "-1", "1.2.3", "0", "0.0"] {
            assert!(parse_hemi(bad).is_err(), "{bad:?} must be rejected");
        }
        assert!(parse_hemi("1.0000000000000000001").is_err(), ">18 decimals");
    }

    /// THE invariant tying step 1 to step 2: the shortfall the miner PRINTS must, when
    /// typed back into this command verbatim, cover the shortfall. `fmt_hemi` floors, so
    /// it renders S as S-e and staking it leaves the slot unfundable and the warning
    /// repeating with "short ~0.00". Only a ceiling closes the loop.
    #[test]
    fn a_printed_shortfall_typed_back_in_always_covers_it() {
        use zkminer_chain::staking::fmt_hemi_ceil;
        // Real shapes: the historical incident, and wei-granular Dutch-auction remainders
        // (per_claim is a ceil over a wei-granular price, so it is essentially never a
        // clean multiple of 0.01 HEMI — the general case, which is where floor fails).
        let cases = [
            4_250_000_000_000_000_000u128, // the 2026-08-08 incident: exactly 4.25
            1,                             // 1 wei short
            WEI_PER_HEMI - 1,              // just under 1 HEMI
            4_250_000_000_000_000_001,     // 4.25 + 1 wei -> floor says 4.25, short
            149_999_999_999_999_999_999,   // ~150, one wei under
            10_000_000_000_000_000_001,
            333_333_333_333_333_333,
        ];
        for shortfall in cases {
            let printed = fmt_hemi_ceil(shortfall);
            let staked = parse_hemi(&printed)
                .unwrap_or_else(|e| panic!("miner printed {printed:?}, unparseable: {e}"));
            assert!(
                staked >= shortfall,
                "printed {printed:?} = {staked} wei, short of {shortfall} wei — \
                 staking it leaves the slot unfundable and the warning repeating"
            );
        }
    }

    /// The scan must never see the process doing the scanning; `pgrep -f zkminer` would,
    /// and that self-match killed this operator's shell twice.
    #[test]
    fn the_miner_scan_never_matches_itself() {
        let me = std::process::id() as i32;
        assert!(
            !other_running_miners().contains(&me),
            "self-match: the guard would refuse to ever stake"
        );
    }

    fn cmdline(args: &[&str]) -> Vec<u8> {
        let mut v = Vec::new();
        for a in args {
            v.extend_from_slice(a.as_bytes());
            v.push(0);
        }
        v
    }

    /// The predicate the guard actually turns on. Tested directly because the scan test
    /// above cannot reach it — a positive case needs a real `zkminer run` process.
    #[test]
    fn identifies_processes_that_share_the_signer() {
        // MUST refuse: these hold the key and allocate nonces.
        assert!(shares_our_signer("zkminer", &cmdline(&["zkminer", "run"])));
        assert!(shares_our_signer(
            "zkminer",
            &cmdline(&["./target/release/zkminer", "-v", "run", "--headless"])
        ));

        // MUST NOT refuse: no signer, or not our binary.
        assert!(
            !shares_our_signer("zkminer", &cmdline(&["zkminer", "run", "--mock"])),
            "mock mode loads no signer; refusing here breeds a --force habit"
        );
        assert!(!shares_our_signer(
            "zkminer",
            &cmdline(&["zkminer", "status"])
        ));
        assert!(!shares_our_signer(
            "zkminer",
            &cmdline(&["zkminer", "benchmark"])
        ));
        assert!(!shares_our_signer(
            "zkminer",
            &cmdline(&["zkminer", "stake", "10"])
        ));
        assert!(
            !shares_our_signer("zkminer-8852d4a1b", &cmdline(&["...", "run"])),
            "the cargo test binary is named zkminer-<hash> and must not match"
        );
        assert!(
            !shares_our_signer("bash", &cmdline(&["bash", "-c", "zkminer run"])),
            "a shell whose ARGS mention the miner is not the miner — this is the pgrep -f \
             self-match that killed the operator's shell twice"
        );
        assert!(!shares_our_signer("zkminer", &[]));
    }

    /// A whole-HEMI amount must never be mistaken for wei — the 1e18 error that looks like
    /// success and stakes nothing.
    #[test]
    fn treats_the_amount_as_hemi_not_wei() {
        assert_eq!(parse_hemi("500").unwrap(), 500_000_000_000_000_000_000);
        assert_ne!(parse_hemi("500").unwrap(), 500);
    }
}
