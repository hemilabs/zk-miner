use anyhow::Result;
use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

mod commands;
mod journal;

#[derive(Parser)]
#[command(name = "zkminer", about = "ZK Miner — HemiProve proving marketplace client")]
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
        /// Additionally measure proving throughput at each segment size (po2) and
        /// save the results, so the miner can pick a segment size per job instead
        /// of deferring to the SDK. Costs one extra proof per po2 step per GPU.
        /// A sweep is discarded unless it actually exercises segmentation.
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
        Commands::Run { headless, .. } if !headless
    );
    // Hold the log guard until main() returns so the non-blocking writer flushes on shutdown.
    let mut _log_guard: Option<tracing_appender::non_blocking::WorkerGuard> = None;

    if is_tui {
        // TUI mode: log to file instead of stderr (stderr output corrupts the alternate screen).
        let log_dir = dirs::home_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("."))
            .join(".zkminer")
            .join("logs");
        let file_appender = tracing_appender::rolling::daily(&log_dir, "zkminer.log");
        let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);
        _log_guard = Some(guard);

        let filter = match cli.verbose {
            0 => "warn,zkminer=info",
            1 => "info,zkminer=debug",
            2 => "debug",
            _ => "trace",
        };
        tracing_subscriber::fmt()
            .with_env_filter(EnvFilter::new(filter))
            .with_writer(non_blocking)
            .with_target(false)
            .with_ansi(false)
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
        Commands::Stake { amount, dry_run, force, yes } => {
            commands::stake::run(config_path, amount, dry_run, force, yes).await
        }
        Commands::Benchmark { json, calibrate } => {
            commands::benchmark::run(config_path, json, calibrate).await
        }
        Commands::Run { headless, mock } if mock => commands::mock::run(headless).await,
        Commands::Run { headless, .. } => commands::run::run(config_path, headless).await,
        #[cfg(feature = "sp1-demo")]
        Commands::Sp1Demo { input } => commands::sp1_demo::run(config_path, input).await,
        Commands::Init { force, network, generate_key } => {
            commands::init::run(config_path, force, &network, generate_key)
        }
    }
}
