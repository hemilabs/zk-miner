use anyhow::Result;
use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

mod commands;
mod journal;

/// Forwards each WARN/ERROR event whose message starts with `PAGE` to the dashboard's log (see
/// `commands::run::note_page`).
struct PageToDashboard;

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for PageToDashboard {
    fn on_event(&self, event: &tracing::Event<'_>, _: tracing_subscriber::layer::Context<'_, S>) {
        if *event.metadata().level() > tracing::Level::WARN {
            return;
        }
        struct Message(Option<String>);
        impl tracing::field::Visit for Message {
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                if field.name() == "message" {
                    self.0 = Some(format!("{value:?}"));
                }
            }
        }
        let mut m = Message(None);
        event.record(&mut m);
        if let Some(msg) = m.0.filter(|s| s.starts_with("PAGE")) {
            commands::run::note_page(msg);
        }
    }
}

#[derive(Parser)]
#[command(
    name = "zkminer",
    version,
    about = "ZK Miner — HemiProve proving marketplace client"
)]
struct Cli {
    /// Path to config file (default: ~/.zkminer/config.toml)
    #[arg(long, short, global = true)]
    config: Option<String>,

    /// Verbosity level (-v debug, -vv more, -vvv trace)
    #[arg(long, short, action = clap::ArgAction::Count, global = true)]
    verbose: u8,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Show prover status (balance, stake, stats)
    Status,
    /// Add collateral so more GPU slots can be funded (approve + stake, in HEMI)
    Stake {
        /// Amount in HEMI (e.g. `500`, or `4.25`). NOT wei.
        amount: String,
        /// Print what would happen and send nothing
        #[arg(long)]
        dry_run: bool,
        /// Stake even though this account has transactions in flight (the miner is
        /// running). Risks displacing a pending fulfillJob and getting it slashed.
        #[arg(long)]
        force: bool,
        /// Skip the confirmation prompt
        #[arg(long, short = 'y')]
        yes: bool,
    },
    /// Request stake back out (it can be withdrawn 7 days later with `zkminer withdraw`), or
    /// cancel a pending request
    #[command(group(clap::ArgGroup::new("what").required(true).args(["amount", "all", "cancel"])))]
    Unstake {
        /// Amount in HEMI (e.g. `100`, or `4.25`). NOT wei.
        amount: Option<String>,
        /// Request all free stake (stake locked in jobs stays until they settle)
        #[arg(long)]
        all: bool,
        /// Cancel the pending request, counting it back as stake
        #[arg(long)]
        cancel: bool,
        /// Check it against the contract and send nothing
        #[arg(long)]
        dry_run: bool,
        /// Send even though the miner may be running with this key. Risks displacing a pending
        /// fulfillJob and getting it slashed.
        #[arg(long)]
        force: bool,
        /// Skip the confirmation prompt
        #[arg(long, short = 'y')]
        yes: bool,
    },
    /// Withdraw a matured unstake and any payouts the router holds for this account
    Withdraw {
        /// Check it against the contract and send nothing
        #[arg(long)]
        dry_run: bool,
        /// Send even though the miner may be running with this key. Risks displacing a pending
        /// fulfillJob and getting it slashed.
        #[arg(long)]
        force: bool,
        /// Skip the confirmation prompt
        #[arg(long, short = 'y')]
        yes: bool,
    },
    /// Check whether this miner will claim and prove jobs, and if not, why not: config, key, chain,
    /// gas, stake, and card by card what this host can prove. Sends nothing, starts no worker.
    Doctor,
    /// Stop the miner running under this home directory (from another terminal, a script or a
    /// service manager). By default it drains: no new claims, and it exits once the proofs in
    /// flight are fulfilled.
    #[command(group(clap::ArgGroup::new("mode").args(["keep_locks", "abandon", "force_exit"])))]
    Stop {
        /// Exit within minutes without releasing (exit code 75, so `Restart=on-failure` starts
        /// it again); the next start finishes the jobs held. A lock too close to its deadline
        /// for a restart to save it is released first. For restarts and upgrades.
        #[arg(long)]
        keep_locks: bool,
        /// Release every job held now (each pays a 5-30% release penalty), then exit
        #[arg(long)]
        abandon: bool,
        /// Exit at once, releasing nothing (exit code 130: a service is not restarted; start
        /// it again by the time it prints, ~15 min before the earliest lock's cutoff)
        #[arg(long)]
        force_exit: bool,
        /// Wait until the miner has exited, then say what it left held
        #[arg(long)]
        wait: bool,
        /// With --wait: give up waiting after this many seconds (the miner keeps stopping)
        #[arg(long, requires = "wait", value_name = "SECS")]
        timeout: Option<u64>,
    },
    /// Run benchmarks to measure proving performance
    Benchmark {
        /// Output results as JSON instead of a formatted table
        #[arg(long)]
        json: bool,
        /// Additionally prove at each segment size (po2) on each card whose VRAM is known
        /// (NVIDIA) and save the results: a card then proves risc0 jobs at the fastest
        /// size that fit with a step of headroom, never below 20 if 20 proved. Costs one
        /// extra proof per po2 step per GPU. Run it with the miner stopped.
        #[arg(long)]
        calibrate: bool,
    },
    /// Start the miner
    Run {
        /// Run in headless mode (no TUI, log to console). Chosen automatically when stdout is not a
        /// terminal (a service, `nohup`, or a container started without `-t`).
        #[arg(long)]
        headless: bool,
        /// Run in mock mode (simulated marketplace, no chain/wallet needed)
        #[arg(long)]
        mock: bool,
        /// Watch the live market without taking part: run every check up to the claim, log what
        /// would be claimed, and sign and send nothing. Implies --headless.
        #[arg(long, conflicts_with = "mock")]
        watch_only: bool,
        /// The prover address to watch as (default: the configured key's address; the key itself
        /// is never used)
        #[arg(long, requires = "watch_only")]
        address: Option<alloy::primitives::Address>,
    },
    /// Measure jobs as the miner sizes them before a claim, whatever their state, and print one JSON
    /// line per job: cycles, or why not. Signs and sends nothing; starts measure workers only.
    Simulate {
        /// A job to measure (repeatable).
        #[arg(long = "job", value_name = "JOB_ID")]
        jobs: Vec<alloy::primitives::B256>,
        /// Then read requests from stdin until EOF, one per line: a job id, or
        /// {"jobId": "0x…", "submitTx": "0x…", "publicValues": "0x…", "singleRun": true} (the submitting
        /// tx saves the descriptor's log scan; the fulfil's public values let the report say whether
        /// the measured journal is the proven one; `singleRun` measures a risc0 job once at `--po2`).
        #[arg(long)]
        stdin: bool,
        /// The risc0 segment size run first, reported on a tie, and the only one for `singleRun`.
        /// Otherwise a risc0 job runs at all seven sizes and the lowest figure is reported.
        #[arg(long, default_value_t = zkminer_prover_protocol::RISC0_DEFAULT_JOB_PO2)]
        po2: u8,
        /// Bound on one execution, in seconds: at least 60 (a lower value is raised to it), at most
        /// 86400. An SP1 worker's one-time setup is not part of it.
        #[arg(long, default_value_t = 600)]
        execute_timeout_secs: u64,
        /// Bound on deriving one program's id, in seconds: at least 60, at most 86400 (SP1's setup on
        /// the CPU: seconds for a small guest, minutes for a large one). Requests are served one at a
        /// time, so this also bounds how long one new program can hold the queue.
        #[arg(long, default_value_t = 900)]
        program_id_timeout_secs: u64,
        /// The largest cycle count reported as `measured`; a measurement above it (risc0's keccak
        /// charge included) is reported `too_heavy`, with the count in its reason.
        #[arg(long, default_value_t = commands::simulate::DEFAULT_MAX_CYCLES)]
        max_cycles: u64,
        /// How long, in seconds, a program whose ELF did not bind (refused, a different id, or a
        /// derivation that timed out) is answered from memory instead of downloaded and derived
        /// again; 0 = never remembered.
        #[arg(long, default_value_t = commands::simulate::DEFAULT_PROGRAM_FAILURE_TTL_SECS)]
        program_failure_ttl_secs: u64,
        /// The risc0 worker binary (e.g. zkminer-prove-risc0-cpu); overrides the config.
        #[arg(long)]
        risc0_worker: Option<std::path::PathBuf>,
        /// The SP1 worker binary (zkminer-prove-sp1); overrides the config.
        #[arg(long)]
        sp1_worker: Option<std::path::PathBuf>,
        /// Where to keep the ELF and program-id caches (default ~/.zkminer/simulate).
        #[arg(long)]
        cache_dir: Option<std::path::PathBuf>,
    },
    /// Register fibonacci-sp1-guest and submit a test job (SP1 demo)
    #[cfg(feature = "sp1-demo")]
    Sp1Demo {
        /// Fibonacci N value to prove (input to guest)
        #[arg(long, default_value_t = 42)]
        input: u32,
    },
    /// Initialize config file with defaults
    Init {
        /// Overwrite existing config
        #[arg(long)]
        force: bool,
        /// Target network: "testnet" (default) or "mainnet"
        #[arg(long, default_value = "testnet")]
        network: String,
        /// Generate a private key into ~/.zkminer/key (readable by you only; an existing key there
        /// is kept, never overwritten) and point the config at it
        #[arg(long)]
        generate_key: bool,
    },
}

#[tokio::main(worker_threads = 4)]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Only setup stderr tracing for headless/CLI modes.
    // In TUI mode, any stderr output (from any thread) corrupts the alternate screen.
    let tui_requested = matches!(&cli.command,
        Commands::Run { headless, watch_only, .. } if !headless && !watch_only
    );
    // The TUI draws on stdout. Without a terminal there (a systemd unit, `nohup`, `docker run`
    // without `-t`) it cannot start, and the miner used to come up, fail to enter raw mode, log that
    // to a file and shut down. Run headless instead, and say so.
    let no_terminal = tui_requested && !stdout_is_terminal();
    let is_tui = tui_requested && !no_terminal;
    // Hold the log guard until main() returns so the non-blocking writer flushes on shutdown.
    let mut _log_guard: Option<tracing_appender::non_blocking::WorkerGuard> = None;

    if is_tui {
        // TUI mode: suppress forwarding of worker-process stderr. The worker dup2's each guest's
        // stdout onto the worker stderr pipe, so a malicious guest can emit unbounded output; forwarded
        // to the daily-rotated, size-uncapped log it fills the operator's disk, and its ungated
        // "[WITSUM]" eprintln path would corrupt the alternate screen. The drainer still READS the pipe
        // (so the worker never blocks on a full pipe) — it just does not forward while suppressed.
        // (Headless keeps forwarding, rate-capped in the drainer, to operator-controlled stderr.)
        zkminer_prover::worker::suppress_worker_stderr(true);
        // TUI mode: log to file instead of stderr (stderr output corrupts the alternate screen).
        let log_dir = dirs::home_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("."))
            .join(".zkminer")
            .join("logs");
        // Cap log retention so a submitter who floods log-worthy events (bad jobs, rejected URIs,
        // failed proofs) cannot fill the operator's disk via unbounded daily files. Keep ~2 weeks
        // of daily logs; fall back to the simple appender if the builder errors.
        let file_appender = tracing_appender::rolling::Builder::new()
            .rotation(tracing_appender::rolling::Rotation::DAILY)
            .filename_prefix("zkminer.log")
            .max_log_files(14)
            .build(&log_dir)
            .unwrap_or_else(|_| tracing_appender::rolling::daily(&log_dir, "zkminer.log"));
        let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);
        _log_guard = Some(guard);

        let filter = match cli.verbose {
            0 => "warn,zkminer=info",
            1 => "info,zkminer=debug",
            2 => "debug",
            _ => "trace",
        };
        use tracing_subscriber::layer::SubscriberExt;
        use tracing_subscriber::util::SubscriberInitExt;
        tracing_subscriber::registry()
            .with(EnvFilter::new(filter))
            .with(
                tracing_subscriber::fmt::layer()
                    .with_writer(non_blocking)
                    .with_target(false)
                    .with_ansi(false),
            )
            // PAGE lines (claims stopped, a lock at risk) also reach the dashboard: in this mode the
            // log file is all the operator would otherwise see of them.
            .with(PageToDashboard)
            .init();
    } else {
        let filter = match cli.verbose {
            // `doctor` prints its own report; the probes' INFO lines would only interleave with it.
            0 if matches!(cli.command, Commands::Doctor) => "error",
            0 => "warn,zkminer=info",
            1 => "info,zkminer=debug",
            2 => "debug",
            _ => "trace",
        };
        // Logs go to STDERR so stdout carries only command output. Without this
        // `zkminer benchmark --json` interleaves INFO lines with the JSON document
        // and emits unparseable output (the default `fmt()` writer is stdout).
        tracing_subscriber::fmt()
            .with_env_filter(EnvFilter::new(filter))
            .with_writer(std::io::stderr)
            .with_target(false)
            // Colour codes only for a terminal: journald and `docker logs` show them as text.
            .with_ansi(std::io::IsTerminal::is_terminal(&std::io::stderr()))
            .init();
    }
    if no_terminal {
        tracing::warn!(
            "stdout is not a terminal, so the dashboard cannot start: running headless (logs on \
             stderr). Pass --headless to make this explicit."
        );
    }

    let config_path = cli.config.as_deref().map(std::path::Path::new);

    match cli.command {
        Commands::Status => commands::status::run(config_path).await,
        Commands::Stake {
            amount,
            dry_run,
            force,
            yes,
        } => commands::stake::run(config_path, amount, dry_run, force, yes).await,
        Commands::Unstake {
            amount,
            all,
            cancel,
            dry_run,
            force,
            yes,
        } => {
            let action = match (amount, all, cancel) {
                (_, _, true) => commands::unstake::UnstakeAction::Cancel,
                (_, true, _) => commands::unstake::UnstakeAction::All,
                (Some(a), _, _) => commands::unstake::UnstakeAction::Amount(a),
                (None, false, false) => unreachable!("clap requires one of them"),
            };
            commands::unstake::run_unstake(config_path, action, dry_run, force, yes).await
        }
        Commands::Withdraw {
            dry_run,
            force,
            yes,
        } => commands::unstake::run_withdraw(config_path, dry_run, force, yes).await,
        Commands::Doctor => commands::doctor::run(config_path).await,
        Commands::Stop {
            keep_locks,
            abandon,
            force_exit,
            wait,
            timeout,
        } => {
            use zkminer_tui::state::StopMode;
            let mode = match (keep_locks, abandon, force_exit) {
                (true, _, _) => StopMode::KeepLocks,
                (_, true, _) => StopMode::Abandon,
                (_, _, true) => StopMode::Force,
                _ => StopMode::Drain,
            };
            commands::stop::run(mode, wait, timeout)
        }
        Commands::Benchmark { json, calibrate } => {
            commands::benchmark::run(config_path, json, calibrate).await
        }
        Commands::Run { headless, mock, .. } if mock => {
            commands::mock::run(headless || no_terminal).await
        }
        Commands::Run {
            headless,
            watch_only,
            address,
            ..
        } => {
            let watch = watch_only.then_some(commands::run::WatchOnly { address });
            commands::run::run(config_path, headless || watch_only || no_terminal, watch).await
        }
        Commands::Simulate {
            jobs,
            stdin,
            po2,
            execute_timeout_secs,
            program_id_timeout_secs,
            max_cycles,
            program_failure_ttl_secs,
            risc0_worker,
            sp1_worker,
            cache_dir,
        } => {
            commands::simulate::run(
                config_path,
                commands::simulate::SimulateOptions {
                    jobs,
                    stdin,
                    po2,
                    execute_timeout: simulate_bound("--execute-timeout-secs", execute_timeout_secs),
                    program_id_timeout: simulate_bound(
                        "--program-id-timeout-secs",
                        program_id_timeout_secs,
                    ),
                    max_cycles,
                    program_failure_ttl: std::time::Duration::from_secs(program_failure_ttl_secs),
                    risc0_worker,
                    sp1_worker,
                    cache_dir,
                },
            )
            .await
        }
        #[cfg(feature = "sp1-demo")]
        Commands::Sp1Demo { input } => commands::sp1_demo::run(config_path, input).await,
        Commands::Init {
            force,
            network,
            generate_key,
        } => commands::init::run(config_path, force, &network, generate_key),
    }
}

/// Whether the TUI can draw: it renders on stdout.
fn stdout_is_terminal() -> bool {
    std::io::IsTerminal::is_terminal(&std::io::stdout())
}

/// A `simulate` bound in seconds, clamped to `MIN_BOUND_SECS..=86400`: below the minimum a request's
/// own overhead would fail every request; far above it, the watchdog's deadline arithmetic overflows.
fn simulate_bound(flag: &str, secs: u64) -> std::time::Duration {
    const MAX_BOUND_SECS: u64 = 86_400;
    let min = commands::simulate::MIN_BOUND_SECS;
    let clamped = secs.clamp(min, MAX_BOUND_SECS);
    if clamped != secs {
        tracing::warn!("{flag} {secs} is outside {min}..={MAX_BOUND_SECS}: using {clamped}");
    }
    std::time::Duration::from_secs(clamped)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simulate_bounds_are_clamped_to_their_minimum() {
        let cli = Cli::try_parse_from([
            "zkminer",
            "simulate",
            "--stdin",
            "--max-cycles",
            "12345",
            "--execute-timeout-secs",
            "5",
        ])
        .unwrap();
        match cli.command {
            Commands::Simulate {
                max_cycles,
                execute_timeout_secs,
                program_id_timeout_secs,
                ..
            } => {
                assert_eq!(max_cycles, 12_345);
                assert_eq!(execute_timeout_secs, 5);
                assert_eq!(program_id_timeout_secs, 900);
            }
            _ => panic!("not a simulate command"),
        }
        let min = commands::simulate::MIN_BOUND_SECS;
        assert_eq!(simulate_bound("x", 5).as_secs(), min);
        assert_eq!(simulate_bound("x", 0).as_secs(), min);
        assert_eq!(simulate_bound("x", 600).as_secs(), 600);
        assert_eq!(simulate_bound("x", u64::MAX).as_secs(), 86_400);
    }

    #[test]
    fn watch_only_flags_parse_and_conflict_as_documented() {
        let addr = "0x00000000000000000000000000000000000000a1";
        let cli =
            Cli::try_parse_from(["zkminer", "run", "--watch-only", "--address", addr]).unwrap();
        match cli.command {
            Commands::Run {
                watch_only,
                address,
                ..
            } => {
                assert!(watch_only);
                assert_eq!(address, Some(addr.parse().unwrap()));
            }
            _ => panic!("not a run command"),
        }
        // An address alone would read as "run normally as this address": refused.
        assert!(Cli::try_parse_from(["zkminer", "run", "--address", addr]).is_err());
        assert!(Cli::try_parse_from(["zkminer", "run", "--watch-only", "--mock"]).is_err());
        assert!(
            Cli::try_parse_from(["zkminer", "run", "--watch-only", "--address", "0x12"]).is_err()
        );
    }

    #[test]
    fn unstake_takes_exactly_one_of_an_amount_all_or_cancel() {
        assert!(Cli::try_parse_from(["zkminer", "unstake", "100"]).is_ok());
        assert!(Cli::try_parse_from(["zkminer", "unstake", "--all", "--dry-run"]).is_ok());
        assert!(Cli::try_parse_from(["zkminer", "unstake", "--cancel", "-y"]).is_ok());
        assert!(
            Cli::try_parse_from(["zkminer", "unstake"]).is_err(),
            "nothing to do"
        );
        assert!(Cli::try_parse_from(["zkminer", "unstake", "100", "--all"]).is_err());
        assert!(Cli::try_parse_from(["zkminer", "unstake", "--all", "--cancel"]).is_err());
        assert!(Cli::try_parse_from(["zkminer", "withdraw", "--dry-run"]).is_ok());
    }

    #[test]
    fn global_flags_work_after_the_subcommand() {
        let cli = Cli::try_parse_from(["zkminer", "run", "-v", "-v", "--headless", "-c", "x.toml"])
            .unwrap();
        assert_eq!(cli.verbose, 2);
        assert_eq!(cli.config.as_deref(), Some("x.toml"));
        let cli = Cli::try_parse_from(["zkminer", "-v", "status"]).unwrap();
        assert_eq!(cli.verbose, 1);
        let e = Cli::try_parse_from(["zkminer", "--version"]).err().unwrap();
        assert_eq!(e.kind(), clap::error::ErrorKind::DisplayVersion);
    }

    #[test]
    fn simulate_flags_parse() {
        let a = format!("0x{}", "ab".repeat(32));
        let b = format!("0x{}", "cd".repeat(32));
        let cli = Cli::try_parse_from([
            "zkminer", "simulate", "--job", &a, "--job", &b, "--stdin", "--po2", "21",
        ])
        .unwrap();
        match cli.command {
            Commands::Simulate {
                jobs,
                stdin,
                po2,
                execute_timeout_secs,
                max_cycles,
                program_failure_ttl_secs,
                ..
            } => {
                assert_eq!(
                    jobs,
                    vec![
                        a.parse::<alloy::primitives::B256>().unwrap(),
                        b.parse::<alloy::primitives::B256>().unwrap()
                    ]
                );
                assert!(stdin);
                assert_eq!(po2, 21);
                assert_eq!(execute_timeout_secs, 600);
                assert_eq!(max_cycles, 1_000_000_000);
                assert_eq!(program_failure_ttl_secs, 6 * 3600);
            }
            _ => panic!("not a simulate command"),
        }
        let cli = Cli::try_parse_from([
            "zkminer",
            "simulate",
            "--stdin",
            "--max-cycles",
            "1000",
            "--program-failure-ttl-secs",
            "0",
        ])
        .unwrap();
        match cli.command {
            Commands::Simulate {
                max_cycles,
                program_failure_ttl_secs,
                ..
            } => {
                assert_eq!(max_cycles, 1000);
                assert_eq!(program_failure_ttl_secs, 0);
            }
            _ => panic!("not a simulate command"),
        }
        assert!(Cli::try_parse_from(["zkminer", "simulate", "--job", "0x12"]).is_err());
    }
}
