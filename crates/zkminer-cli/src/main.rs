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
    about = "ZK Miner — HemiProve proving marketplace client"
)]
struct Cli {
    /// Path to config file (default: ~/.zkminer/config.toml)
    #[arg(long, short)]
    config: Option<String>,

    /// Verbosity level
    #[arg(long, short, action = clap::ArgAction::Count)]
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
        /// Run in headless mode (no TUI, log to console)
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
        /// Generate a fresh private key and save to ~/.zkminer/key
        #[arg(long)]
        generate_key: bool,
    },
}

#[tokio::main(worker_threads = 4)]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Only setup stderr tracing for headless/CLI modes.
    // In TUI mode, any stderr output (from any thread) corrupts the alternate screen.
    let is_tui = matches!(&cli.command,
        Commands::Run { headless, watch_only, .. } if !headless && !watch_only
    );
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
            .init();
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
        Commands::Benchmark { json, calibrate } => {
            commands::benchmark::run(config_path, json, calibrate).await
        }
        Commands::Run { headless, mock, .. } if mock => commands::mock::run(headless).await,
        Commands::Run {
            headless,
            watch_only,
            address,
            ..
        } => {
            let watch = watch_only.then_some(commands::run::WatchOnly { address });
            commands::run::run(config_path, headless || watch_only, watch).await
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
