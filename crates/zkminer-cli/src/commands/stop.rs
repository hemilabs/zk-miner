//! `zkminer stop`: ask the miner running under this home directory to stop, the way its dashboard's
//! quit prompt does — from another terminal, a script, a service manager, or on Windows, where no
//! signal can carry the choice.
//!
//! The request is a file, `~/.zkminer/stop-request`, holding one word (the mode). The miner reads
//! it within a second and removes it; the removal is the acknowledgement. Anyone who can write
//! there can already stop the miner, so the file grants nothing new.

use anyhow::{bail, Context, Result};
use std::time::{Duration, Instant};
use zkminer_tui::state::StopMode;

use super::run::{stop_mode_word, stop_request_path, stop_response_path, zkminer_home};

/// How long to wait for the miner to pick up the request.
const ACK_TIMEOUT: Duration = Duration::from_secs(10);

/// The same with --wait: long enough for a miner still starting up.
const WAIT_ACK_TIMEOUT: Duration = Duration::from_secs(120);

/// Whether a process holds `~/.zkminer/miner.lock` (a miner, a benchmark, or a stake / unstake /
/// withdraw at its prompt). Probes by taking the lock and dropping it at once.
pub(crate) fn instance_running() -> Result<bool> {
    let path = zkminer_home().join("miner.lock");
    let file = match std::fs::OpenOptions::new()
        .create(false)
        .write(true)
        .open(&path)
    {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e).with_context(|| format!("open {}", path.display())),
    };
    match file.try_lock() {
        Ok(()) => Ok(false),
        Err(std::fs::TryLockError::WouldBlock) => Ok(true),
        Err(std::fs::TryLockError::Error(e)) => {
            Err(e).with_context(|| format!("lock {}", path.display()))
        }
    }
}

/// Write the request for `mode`, replacing any earlier one (tmp + rename, so the miner never reads
/// half a word).
fn write_request(mode: StopMode) -> Result<()> {
    let path = stop_request_path();
    // Our own temporary: two `zkminer stop` at once must not rename each other's half-written word.
    let tmp = path.with_extension(format!("tmp{}", std::process::id()));
    std::fs::write(&tmp, stop_mode_word(mode))
        .with_context(|| format!("write {}", tmp.display()))?;
    std::fs::rename(&tmp, &path).with_context(|| format!("write {}", path.display()))
}

fn what_it_does(mode: StopMode) -> &'static str {
    match mode {
        StopMode::Drain => {
            "draining: no new claims; it exits once the proofs in flight are fulfilled (as long as \
             they take, up to ~50 min)"
        }
        StopMode::KeepLocks => {
            "keeping its locks: no new claims; within minutes it exits without releasing (exit \
             code 75), except a lock too close to its deadline for a restart to save it, and the \
             next start finishes the jobs held"
        }
        StopMode::Abandon => {
            "abandoning: it releases every job it holds (each pays a 5-30% release penalty), then \
             exits"
        }
        StopMode::Force => "exiting at once, releasing nothing",
    }
}

/// What the job journal says is still held, for the report after the miner exited.
fn held_report(mode: StopMode) -> String {
    let journal = crate::journal::JobJournal::load();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let live: Vec<u64> = journal
        .iter()
        .filter(|e| e.lock_deadline == 0 || e.lock_deadline > now)
        .map(|e| e.lock_deadline)
        .collect();
    if live.is_empty() {
        return "No locks are recorded as held.".to_string();
    }
    let by = super::run::start_by(live.iter().copied())
        .map(|t| {
            format!(" by {t} at the latest (a service with Restart=on-failure does that itself)")
        })
        .unwrap_or_default();
    let what = if mode == StopMode::KeepLocks {
        "kept for the next start"
    } else {
        "still recorded as held"
    };
    format!(
        "{} lock(s) {what}. Start the miner again{by}: it re-proves each one there is still time \
         for and releases the rest; a lock left past its deadline is slashed.",
        live.len()
    )
}

pub fn run(mode: StopMode, wait: bool, timeout: Option<u64>) -> Result<()> {
    let home = zkminer_home();
    // Windows: a service that starts the miner again once it exits turns this stop into a restart
    // (review 6 OJ-2).
    #[cfg(windows)]
    for warning in super::windows_service::restart_warnings() {
        eprintln!("warning: {warning}");
    }
    if !instance_running()? {
        bail!(
            "no miner is running under {} (its miner.lock is free) — nothing to stop. A miner run \
             as another user (a service account included), or with another HOME on Linux, must \
             be stopped as that user.",
            home.display()
        );
    }
    // An answer left from an earlier request must not be read as this one's.
    let response = stop_response_path();
    let _ = std::fs::remove_file(&response);
    write_request(mode)?;
    let path = stop_request_path();
    let started = Instant::now();
    let deadline = timeout.map(|s| started + Duration::from_secs(s));
    let past_deadline = || deadline.is_some_and(|d| Instant::now() >= d);
    // The miner removes the file when it takes the request.
    let mut last_lock_check = Instant::now();
    while path.exists() {
        // The holder may be a benchmark or a prompt that never takes requests and then exits.
        if last_lock_check.elapsed() >= Duration::from_secs(2) {
            last_lock_check = Instant::now();
            if !instance_running()? {
                let _ = std::fs::remove_file(&path);
                bail!(
                    "the process holding {} exited without taking the request (it was not a miner, \
                     or it stopped on its own); the request is withdrawn.",
                    home.join("miner.lock").display()
                );
            }
        }
        // Without --wait, a few seconds; with it, until --timeout (a miner still starting up
        // takes the request once it is running).
        // Without --wait a few seconds; with it until --timeout, and at most 2 min: a miner still
        // starting up takes it well within that, and one from before `zkminer stop` existed never
        // does (a stop waiting forever on it would hold a systemd stop job for its whole timeout,
        // with the miner still claiming).
        let ack_limit = if wait { WAIT_ACK_TIMEOUT } else { ACK_TIMEOUT };
        if started.elapsed() >= ack_limit || (wait && past_deadline()) {
            bail!(
                "the process holding {} has not taken the request in {}s. A miner still starting \
                 up takes it once it is running; a `zkminer benchmark` or a stake / unstake / \
                 withdraw prompt never will, nor a miner from a version before `zkminer stop` \
                 (stop that one with Ctrl+C / SIGINT, then SIGKILL to keep its locks, or let it \
                 drain). The request stays in {}: a miner that finishes \
                 starting up acts on it, the next miner start removes it unread, and `rm {}` \
                 withdraws it.",
                home.join("miner.lock").display(),
                started.elapsed().as_secs(),
                path.display(),
                path.display()
            );
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    // Then its answer: what it is doing, or why it will not (a keep-locks stop asked for while it
    // releases, an abandon after a keep-locks stop committed).
    let taken = Instant::now();
    let answer = loop {
        match std::fs::read_to_string(&response) {
            Ok(text) => {
                let _ = std::fs::remove_file(&response);
                break text;
            }
            Err(_) if taken.elapsed() < ACK_TIMEOUT => {
                std::thread::sleep(Duration::from_millis(100))
            }
            // With --wait (ExecStop, scripts), a late answer is not a failure: a failed ExecStop
            // would have systemd signal the miner, escalating a drain to an abandon. Wait for
            // the exit instead.
            Err(_) if wait => {
                println!(
                    "The miner took the request but has not answered yet; waiting for it to exit."
                );
                break format!("{} ok: unanswered", stop_mode_word(mode));
            }
            Err(_) => bail!(
                "the miner took the request but has not answered in {}s, so whether it is {} is \
                 unknown: check its dashboard or output.",
                ACK_TIMEOUT.as_secs(),
                what_it_does(mode)
            ),
        }
    };
    // `<mode word> ok: …` / `<mode word> refused: …`; another word is another client's answer.
    let word = stop_mode_word(mode);
    let Some(answer) = answer.strip_prefix(&format!("{word} ")) else {
        bail!(
            "another `zkminer stop` was answered instead ({}); check the miner's dashboard or \
             output for what it is doing.",
            answer.trim()
        );
    };
    if let Some(why) = answer.strip_prefix("refused: ") {
        bail!("the miner refused the request: {why}");
    }
    match answer.strip_prefix("ok: ") {
        Some("already stopping") => {
            println!("The miner is already stopping; this request changes nothing.")
        }
        _ => println!("The miner took the request and is {}.", what_it_does(mode)),
    }
    if !wait && mode == StopMode::KeepLocks {
        // Without --wait the report after the exit never comes: say now by when to start again.
        println!("{}", held_report(mode));
    }
    if !wait {
        println!(
            "Follow it on its dashboard or in its output (a service: its journal); `zkminer stop \
             --wait` waits for it to exit."
        );
        return Ok(());
    }
    let mut last_note = Instant::now();
    while instance_running()? {
        if past_deadline() {
            bail!(
                "the miner is still stopping after {}s (it is {}).",
                started.elapsed().as_secs(),
                what_it_does(mode)
            );
        }
        if last_note.elapsed() >= Duration::from_secs(60) {
            println!(
                "still stopping ({} min so far)...",
                started.elapsed().as_secs() / 60
            );
            last_note = Instant::now();
        }
        std::thread::sleep(Duration::from_secs(1));
    }
    println!("The miner has exited. {}", held_report(mode));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The words the miner parses are the ones `zkminer stop` writes, for every mode.
    #[test]
    fn every_mode_round_trips_through_the_request_word() {
        for mode in [
            StopMode::Drain,
            StopMode::KeepLocks,
            StopMode::Abandon,
            StopMode::Force,
        ] {
            let word = stop_mode_word(mode);
            assert_eq!(
                super::super::run::parse_stop_mode(word),
                Some(mode),
                "{word}"
            );
            assert_eq!(
                super::super::run::parse_stop_mode(&format!("{word}\r\n")),
                Some(mode)
            );
        }
        assert_eq!(super::super::run::parse_stop_mode("restart"), None);
    }
}
