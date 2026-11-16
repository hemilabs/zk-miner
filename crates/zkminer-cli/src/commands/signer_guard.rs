//! Checks before a command other than `run` (`stake`, `unstake`, `withdraw`) signs a transaction
//! with the miner's key.
//!
//! The miner and these commands are separate processes over ONE signer, and the nonce allocator is
//! per-process: each anchors a fresh NonceManager at the node's pending count, so both hand out the
//! SAME nonce (asserted in zkminer-chain's tests/stake_tx_shape.rs). If such a transaction outbids an
//! in-flight `fulfillJob` it REPLACES it, the job misses its deadline, and its collateral is slashed.
//! That is fund loss, not delay, so the command refuses while the miner may be running.
//!
//! Three nets, from the strongest:
//! 1. `~/.zkminer/miner.lock`, which `zkminer run` holds for its whole life. The command takes it
//!    too and keeps it until it exits, so a miner started meanwhile refuses to start rather than
//!    racing the transaction. Works on every platform.
//! 2. A scan of `/proc` for a `zkminer run` (Linux): a miner running under another home.
//! 3. The mempool (pending != latest): a sharer of the key this host cannot see.
//!
//! The confirmation prompt puts unbounded human latency between these checks and the send, so
//! nets 2 and 3 run again after it ([`recheck_after_prompt`]); the lock needs no re-check, as this
//! process holds it.

use alloy::providers::Provider;
use anyhow::Result;
use std::io::Write;
use zkminer_chain::client::ChainClient;

/// Refuse a deployment `zkminer run` would refuse: a stale config pointing at an abandoned stack
/// would otherwise approve and stake into it, behind a 7-day exit.
pub(crate) async fn verify_deployment(client: &ChainClient) -> Result<()> {
    match client.verify_deployment().await {
        Ok(_) => Ok(()),
        Err(e) => anyhow::bail!(
            "the configured deployment did not pass the check `zkminer run` makes, so nothing was \
             sent: {e:#}"
        ),
    }
}

/// The same check before an exit (`unstake`, `withdraw`), as a warning only. Those send no tokens
/// in, and the deployments that fail it are exactly the ones an operator needs to get stake back out
/// of (an abandoned stack an old config still names, or one whose code changed).
pub(crate) async fn warn_unless_deployment_verified(client: &ChainClient) {
    if let Err(e) = client.verify_deployment().await {
        eprintln!(
            "WARNING: the configured deployment did not pass the check `zkminer run` makes: {e:#}\n\
             Continuing, as this only takes stake or payouts out of the contracts the config names."
        );
    }
}

/// Does this process share our signing key?
///
/// Pure so it can actually be tested: the previous test asserted only that the scan does not
/// match itself, which was vacuous — the test binary's comm is `zkminer-<hash>`, rejected by
/// the name check before the self-skip ever mattered.
pub(crate) fn shares_our_signer(comm: &str, cmdline: &[u8]) -> bool {
    if comm != "zkminer" {
        return false;
    }
    let args: Vec<&[u8]> = cmdline.split(|b| *b == 0).collect();
    // `run --mock` never loads a signer or a provider (main.rs routes it before config load),
    // and `run --watch-only` signs and sends nothing, so neither shares a nonce. Refusing on them
    // would teach --force as a habit, which is what makes a real collision likely.
    args.iter().any(|a| *a == b"run")
        && !args
            .iter()
            .any(|a| *a == b"--mock" || *a == b"--watch-only")
}

/// PIDs of other live `zkminer run` processes (Linux; empty elsewhere).
///
/// Scans /proc directly rather than shelling out to pgrep: `pgrep -f zkminer` matches the
/// invoking shell's own command line (this footgun killed the operator's shell twice in
/// this project), and `comm` is the exact executable name, so it cannot self-match a
/// pattern. Own PID is excluded.
pub(crate) fn other_running_miners() -> Vec<i32> {
    let me = std::process::id() as i32;
    let mut found = Vec::new();
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return found; // not Linux: the miner lock and the mempool check cover it
    };
    for e in entries.flatten() {
        let Ok(pid) = e.file_name().to_string_lossy().parse::<i32>() else {
            continue;
        };
        if pid == me {
            continue;
        }
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

fn pids(p: &[i32]) -> String {
    p.iter()
        .map(|p| p.to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

/// What [`ensure_key_is_free`] saw, for [`recheck_after_prompt`].
pub(crate) struct KeyCheck {
    force: bool,
    /// Miners already running (accepted with `--force`): only one started since is news.
    running: Vec<i32>,
}

/// Refuse unless no miner can be sending with this key: see the module doc. On success this
/// process holds `~/.zkminer/miner.lock` until it exits (unless `--force` went past another holder).
/// `--force` downgrades each refusal to a warning.
pub(crate) async fn ensure_key_is_free(client: &ChainClient, force: bool) -> Result<KeyCheck> {
    const STOP_FIRST: &str =
        "Sending now would reuse a nonce the miner has already broadcast on. If \
         this transaction outbids an in-flight fulfillJob it replaces it, the job misses its \
         deadline, and the collateral is slashed.\n\nStop the miner (Ctrl-C drains queued jobs \
         cleanly), run this, then start the miner again.\nUse --force only if you are certain no \
         other process sends with this key.";
    if let Err(e) = super::run::hold_instance_lock() {
        // Only a lock HELD by another process says a miner may be sending; failing to open it
        // (permissions, a full disk) is an error of its own.
        if e.downcast_ref::<super::run::InstanceLockBusy>().is_none() {
            return Err(e);
        }
        if !force {
            anyhow::bail!("{e:#}.\n\n{STOP_FIRST}");
        }
        eprintln!(
            "WARNING: --force while another zkminer holds the miner lock ({e:#}). This transaction \
             may replace an in-flight fulfillJob and get that job's collateral slashed."
        );
    }
    let running = other_running_miners();
    if !running.is_empty() {
        if !force {
            anyhow::bail!(
                "The miner is running (pid {}) and shares this signing key.\n\n{STOP_FIRST}",
                pids(&running)
            );
        }
        eprintln!(
            "WARNING: --force with the miner running (pid {}). This transaction may replace an \
             in-flight fulfillJob and get that job's collateral slashed.",
            pids(&running)
        );
    }
    check_mempool(client, force, STOP_FIRST).await?;
    Ok(KeyCheck { force, running })
}

/// Net 3: transactions from this account in the mempool now.
async fn check_mempool(client: &ChainClient, force: bool, stop_first: &str) -> Result<()> {
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
                 {pending}): something else is sending with this key, most likely the miner.\n\n\
                 {stop_first}"
            );
        }
        eprintln!(
            "WARNING: --force with {in_flight} tx(s) in flight; this may displace a pending \
             transaction and get a job slashed."
        );
    }
    Ok(())
}

/// Miners in `after` that were not in `before`.
fn started_since(before: &[i32], after: &[i32]) -> Vec<i32> {
    after
        .iter()
        .copied()
        .filter(|p| !before.contains(p))
        .collect()
}

/// Ask `question [y/N]` unless `yes`. A decline, or no terminal on stdin, is an error, so a script
/// can tell "done" from "did nothing" by the exit status.
pub(crate) fn confirm(question: &str, yes: bool) -> Result<()> {
    if yes {
        return Ok(());
    }
    print!("\n{question} [y/N] ");
    std::io::stdout().flush().ok();
    let mut answer = String::new();
    let read = std::io::stdin().read_line(&mut answer)?;
    if read == 0 {
        anyhow::bail!(
            "no input on stdin (not a terminal?) — nothing sent; pass --yes to skip the \
             confirmation in scripts"
        );
    }
    if !matches!(answer.trim(), "y" | "Y" | "yes" | "Yes") {
        anyhow::bail!("declined; nothing sent");
    }
    Ok(())
}

/// After the prompt: look again (see the module doc). A miner started meanwhile under another home
/// (a container, a service with its own HOME) is not stopped by our lock, and would send its
/// recovery fulfils on the nonce this transaction is about to take. Refused even with `--force`,
/// which accepted only the miners already running when it was given.
pub(crate) async fn recheck_after_prompt(client: &ChainClient, check: &KeyCheck) -> Result<()> {
    let new = started_since(&check.running, &other_running_miners());
    if !new.is_empty() {
        anyhow::bail!(
            "A miner started while the confirmation was pending (pid {}) — nothing sent. Stop it \
             and re-run.",
            pids(&new)
        );
    }
    check_mempool(
        client,
        check.force,
        "Something sent from this account while the confirmation was pending — nothing sent. Stop \
         whatever shares this key and re-run.",
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

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
        for cmd in ["status", "benchmark"] {
            assert!(!shares_our_signer("zkminer", &cmdline(&["zkminer", cmd])));
        }
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
        assert!(
            !shares_our_signer(
                "zkminer",
                &cmdline(&["zkminer", "run", "--watch-only", "--address", "0x1"])
            ),
            "watch-only signs nothing"
        );
    }

    /// After the prompt only a miner that was not already running is news: with --force the
    /// operator accepted the ones before it, and refusing on those made --force unusable.
    #[test]
    fn only_a_miner_started_during_the_prompt_is_new() {
        assert!(started_since(&[], &[]).is_empty());
        assert!(started_since(&[10, 11], &[11, 10]).is_empty());
        assert_eq!(started_since(&[10], &[10, 42]), vec![42]);
        assert_eq!(started_since(&[], &[7]), vec![7]);
    }

    #[test]
    fn yes_skips_the_prompt() {
        assert!(confirm("anything?", true).is_ok());
    }
}
