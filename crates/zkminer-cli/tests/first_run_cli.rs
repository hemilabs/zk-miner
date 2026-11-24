//! W10-DOC: what a fresh install sees from `zkminer init` and its first `zkminer run`.
//!
//! - `init` must name the command for every step it lists (it used to say "Stake it (via the Wallet
//!   screen)" although `zkminer stake` exists), and must not call a mainnet config a testnet one.
//! - The first `zkminer run` (TUI mode) on a fresh `HOME` printed "Error reading the log
//!   directory/files: No such file or directory" before its real error (the macOS 26 VM check of the
//!   first release candidate), because `~/.zkminer/logs` did not exist yet.
//!
//! Each test runs the built CLI with its own `HOME` and no key in the environment, so nothing of the
//! user's `~/.zkminer` is read or written and nothing reaches the network: `run` stops at the missing
//! key, before it connects to the chain.

// Windows resolves the home directory through the known-folder API, not `HOME`, so these runs
// would read and write the real `~/.zkminer` (its config, logs and miner.lock.holder).
#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

fn fresh_home(tag: &str) -> PathBuf {
    let home = std::env::temp_dir().join(format!(
        "zkminer-first-run-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&home).unwrap();
    home
}

fn zkminer(home: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_zkminer"))
        .args(args)
        .current_dir(home)
        .env("HOME", home)
        .env_remove("ZKMINER_PRIVATE_KEY")
        .stdin(Stdio::null())
        .output()
        .expect("run zkminer")
}

fn text(out: &Output) -> (String, String) {
    (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn init_names_the_stake_command() {
    let home = fresh_home("init");
    let out = zkminer(&home, &["init"]);
    let (stdout, stderr) = text(&out);
    assert!(out.status.success(), "init failed:\n{stdout}\n{stderr}");
    assert!(home.join(".zkminer/config.toml").is_file());
    for step in [
        "set ZKMINER_PRIVATE_KEY",
        "HemiProve team",
        "zkminer stake 150",
        "zkminer status",
        "zkminer run",
    ] {
        assert!(
            stdout.contains(step),
            "init does not say {step:?}:\n{stdout}"
        );
    }
    assert!(!stdout.contains("Wallet screen"), "{stdout}");
    // A second init keeps the config (an update needs none).
    let again = zkminer(&home, &["init"]);
    let (stdout2, _) = text(&again);
    assert!(again.status.success());
    assert!(stdout2.contains("already exists"), "{stdout2}");
    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn init_mainnet_is_not_called_testnet() {
    let home = fresh_home("mainnet");
    let out = zkminer(&home, &["init", "--network", "mainnet"]);
    let (stdout, stderr) = text(&out);
    assert!(out.status.success(), "init failed:\n{stdout}\n{stderr}");
    assert!(!stdout.contains("Testnet"), "{stdout}");
    assert!(stdout.contains("43111"), "{stdout}");
    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn first_run_has_no_log_directory_error() {
    let home = fresh_home("run");
    assert!(zkminer(&home, &["init"]).status.success());
    assert!(!home.join(".zkminer/logs").exists());
    // TUI mode (no --headless): the mode that logs to ~/.zkminer/logs. Without a key it stops before
    // the chain is contacted.
    let out = zkminer(&home, &["run"]);
    let (stdout, stderr) = text(&out);
    assert!(
        !out.status.success(),
        "run without a key succeeded:\n{stdout}\n{stderr}"
    );
    assert!(
        !stderr.contains("Error reading the log directory"),
        "the first run printed the log-directory error:\n{stderr}"
    );
    assert!(
        stderr.contains("ZKMINER_PRIVATE_KEY"),
        "not the key error:\n{stderr}"
    );
    assert!(home.join(".zkminer/logs").is_dir());
    let _ = std::fs::remove_dir_all(&home);
}
