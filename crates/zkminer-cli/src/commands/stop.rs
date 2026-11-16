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

use super::run::{stop_mode_word, stop_request_path, zkminer_home};

/// How long to wait for the miner to pick up the request.
const ACK_TIMEOUT: Duration = Duration::from_secs(10);

/// Whether a process holds `~/.zkminer/miner.lock` (a miner, a benchmark, or a stake / unstake /
/// withdraw at its prompt). Probes by taking the lock and dropping it at once.
fn instance_running() -> Result<bool> {
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
    let tmp = path.with_extension("tmp");
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
            "keeping its locks: no new claims; it exits without releasing (exit code 75), and the \
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
    let earliest = live.iter().copied().filter(|d| *d > 0).min();
    let by = earliest
        .map(|d| {
            format!(
                " before {} (the earliest deadline)",
                zkminer_chain::exit::fmt_unix(d)
            )
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
    if !instance_running()? {
        bail!(
            "no miner is running under {} (its miner.lock is free) — nothing to stop. A miner run \
             as another user, or with another HOME / USERPROFILE, must be stopped as that user.",
            home.display()
        );
    }
    write_request(mode)?;
    let path = stop_request_path();
    let started = Instant::now();
    let deadline = timeout.map(|s| started + Duration::from_secs(s));
    let past_deadline = || deadline.is_some_and(|d| Instant::now() >= d);
    // The miner removes the file when it takes the request.
    while path.exists() {
        if started.elapsed() >= ACK_TIMEOUT && (!wait || past_deadline()) {
            bail!(
                "the process holding {} has not taken the request in {}s. A miner still starting \
                 up takes it once it is running; a `zkminer benchmark` or a stake / unstake / \
                 withdraw prompt never will. The request stays in {} (the next miner start \
                 removes it unread).",
                home.join("miner.lock").display(),
                started.elapsed().as_secs(),
                path.display()
            );
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    println!("The miner took the request and is {}.", what_it_does(mode));
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
