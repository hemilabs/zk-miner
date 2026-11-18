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
    ///
    /// With --descriptor, simulate a witness-construction job that is not on chain through the
    /// miner's own pre-claim pipeline (sandboxed builder and execute, binding check) and print one
    /// JSON report; --adversarial then attacks its witness and host inputs. Needs a delegated cgroup:
    /// run it under `systemd-run --user --scope -p Delegate=yes`.
    Simulate {
        /// A job to measure (repeatable).
        #[arg(long = "job", value_name = "JOB_ID")]
        jobs: Vec<alloy::primitives::B256>,
        /// A witness-job descriptor file (JSON, or TOML by its extension), as `zkminer witness
        /// envelope encode --descriptor-out` writes it.
        #[arg(long, conflicts_with_all = ["jobs", "stdin"])]
        descriptor: Option<std::path::PathBuf>,
        /// The builder artifact (WASM) instead of fetching it by the envelope's builderURIs; it must
        /// hash to the builderId.
        #[arg(long, requires = "descriptor", conflicts_with_all = ["jobs", "stdin"])]
        builder: Option<std::path::PathBuf>,
        /// The guest ELF instead of reading it from the ProgramRegistry; its image id must be the
        /// programId.
        #[arg(long, requires = "descriptor", conflicts_with_all = ["jobs", "stdin"])]
        elf: Option<std::path::PathBuf>,
        /// The prover address in the journal prefix (default: [witness] prover_address, else zero). A
        /// prefix job is reproduced exactly only with the real jobId and prover.
        #[arg(long, requires = "descriptor", conflicts_with_all = ["jobs", "stdin"])]
        prover: Option<alloy::primitives::Address>,
        /// The risc0 keccak po2 (`RISC0_KECCAK_PO2` of the provers).
        #[arg(long, default_value_t = 17, requires = "descriptor", conflicts_with_all = ["jobs", "stdin"])]
        keccak_po2: u8,
        /// The broker's configuration: the requester's own endpoints (default: [broker] config).
        #[arg(long, requires = "descriptor", conflicts_with_all = ["jobs", "stdin"])]
        broker_config: Option<std::path::PathBuf>,
        /// Write the witness report here instead of stdout.
        #[arg(long, requires = "descriptor", conflicts_with_all = ["jobs", "stdin"])]
        out: Option<std::path::PathBuf>,
        /// Attack the witness: structured mutations of W, re-execution under two sys_rand seeds
        /// (the public rule's and a random one), two po2s and two keccak po2s, and a differential
        /// run against two evm-rpc providers. Exits non-zero unless the verdict is `pass`.
        #[arg(long, requires = "descriptor", conflicts_with_all = ["jobs", "stdin"])]
        adversarial: bool,
        /// The adversarial run's bound, in seconds.
        #[arg(long, default_value_t = commands::simulate_witness::DEFAULT_ADVERSARIAL_SECS, requires = "adversarial")]
        adversarial_secs: u64,
        /// Byte flips at sampled offsets of W.
        #[arg(long, default_value_t = commands::simulate_witness::DEFAULT_FLIPS, requires = "adversarial")]
        flips: usize,
        /// The most mutations executed: the scheme's structured ones first, then the generic ones.
        #[arg(long, default_value_t = commands::simulate_witness::MAX_MUTATIONS, requires = "adversarial")]
        max_mutations: usize,
        /// The scheme id whose structured mutations apply (default: the journal header's first word).
        #[arg(long, requires = "adversarial")]
        scheme: Option<u64>,
        /// The two `[[evm_rpc]]` aliases of the broker configuration for the differential run
        /// (default: the first two serving the job's chain).
        #[arg(long, value_delimiter = ',', requires = "adversarial")]
        providers: Option<Vec<String>>,
        /// The largest W --adversarial attacks, in bytes: it runs in this process, unsandboxed, and
        /// holds W and a few copies of it.
        #[arg(long, default_value_t = commands::simulate_witness::DEFAULT_ADVERSARIAL_MAX_W_BYTES, requires = "adversarial")]
        adversarial_max_w_bytes: u64,
        /// With --descriptor, this host's maxGuestCycles maximum (over [witness] max_guest_cycles). A
        /// miner with neither derives its own from its cards and proving timeout, which simulate
        /// cannot: without one, the job is judged against 2^34 and that check is listed as not done.
        #[arg(long, requires = "descriptor", conflicts_with_all = ["jobs", "stdin"])]
        max_guest_cycles: Option<u64>,
        /// With --descriptor, the journal header's length in bytes, which the binding must pin whole
        /// (a scheme-1 W declares it; give it for a W of another layout, or --adversarial fails).
        #[arg(long, requires = "descriptor", conflicts_with_all = ["jobs", "stdin"])]
        header_bytes: Option<usize>,
        /// Then read requests from stdin until EOF, one per line: a job id, or
        /// {"jobId": "0x…", "submitTx": "0x…", "publicValues": "0x…", "singleRun": true} (the submitting
        /// tx saves the descriptor's log scan; the fulfil's public values let the report say whether
        /// the measured journal is the proven one; `singleRun` measures a risc0 job once at `--po2`).
        #[arg(long)]
        stdin: bool,
        /// The risc0 segment size run first, reported on a tie, and the only one for `singleRun`.
        /// Otherwise a risc0 job runs at all seven sizes and the lowest figure is reported. With
        /// --descriptor, the sizes to execute at and to judge maxGuestCycles at, as a miner whose
        /// cards prove at them does: one (`20`), a range (`16..22`, every size) or a list (`16,20`).
        /// Default: the sizes this configuration's cards prove at (its benchmark cache and
        /// prover.risc0_job_po2), else every job size, 16..=22, each judged on its own: a job over
        /// maxGuestCycles at some sizes only is reported with them, since whether a miner serves it
        /// then depends on the size its cards prove at.
        #[arg(long)]
        po2: Option<String>,
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
        /// The risc0 worker binary (e.g. zkminer-prove-risc0-cpu); overrides the config. With
        /// --descriptor, the execute worker (default: [witness] execute_binary).
        #[arg(long)]
        risc0_worker: Option<std::path::PathBuf>,
        /// The SP1 worker binary (zkminer-prove-sp1); overrides the config.
        #[arg(long)]
        sp1_worker: Option<std::path::PathBuf>,
        /// Where to keep the ELF and program-id caches (default ~/.zkminer/simulate). With
        /// --descriptor, where the run's throwaway retention store, broker spool and broker
        /// configurations go (under witness-runs/, removed at the end): it must be on a real
        /// filesystem, not tmpfs, which the store refuses.
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
    /// Witness-construction jobs: set up and check what serving them needs, and requester tooling
    /// (envelope, binding)
    Witness {
        #[command(subcommand)]
        command: WitnessCommand,
    },
    /// Store a witness builder (or a guest ELF) on the HemiProve chain as contract code
    /// (`hemi-code`), paced so it never pushes the chain's DA backlog toward a router pause
    Artifact {
        #[command(subcommand)]
        command: ArtifactCommand,
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

#[derive(Subcommand)]
enum WitnessCommand {
    /// Initialise the retention store in an empty (or new) directory and print its store_uuid for
    /// `[retention] store_uuid`. The miner never creates a store itself.
    InitStore {
        /// The store directory (default: `[retention] dir`). On its own filesystem, never tmpfs.
        #[arg(long)]
        dir: Option<std::path::PathBuf>,
        /// Refuse a directory that is not a mount point.
        #[arg(long)]
        require_dedicated_mount: bool,
        /// Accept a filesystem other than ext4, xfs, btrfs, zfs or f2fs (never tmpfs).
        #[arg(long)]
        allow_any_filesystem: bool,
    },
    /// Run the sandbox self-test (and, with a `[broker]` section, the broker's), as the miner does
    /// at startup and hourly. Needs a delegated cgroup: run it under
    /// `systemd-run --user --scope -p Delegate=yes`.
    SelfTest {
        /// The sandbox probe binary (default: `zkminer-witness-sandbox-probe` next to zkminer).
        #[arg(long)]
        probe: Option<std::path::PathBuf>,
    },
    /// Requester tooling: write a witness-job envelope (`inputData`) from a spec, or explain one
    Envelope {
        #[command(subcommand)]
        command: EnvelopeCommand,
    },
    /// Requester tooling: compute a job's journal binding from its own parameters, or check which
    /// journal bytes a binding leaves free
    Binding {
        #[command(subcommand)]
        command: BindingCommand,
    },
}

#[derive(Subcommand)]
enum ArtifactCommand {
    /// Publish FILE in the hemi-code format: chunks of at most 24,575 bytes deployed as `0x00`-
    /// prefixed data contracts, then a manifest; prints the locator only after every deployment is
    /// at or below the safe head and the artifact was read back there with the miner's checks.
    /// Paced: one chunk in flight, at most one send per block and per block time of wall clock, and
    /// only while the DA backlog is under 250 KB, the safe-head lag at most 300 s, the router not
    /// paused and the head fresh. About twenty minutes per MiB.
    ///
    /// The key is an encrypted keystore of its own (never the miner's): refused when it is staked
    /// as a prover, authorized as an operator, the configured prover, or has pending transactions
    /// it did not send. Every request goes through the network guard: a node on loopback or the LAN
    /// is reachable only with `[dev] private_network` for this chain in the configuration. The RPC
    /// is trusted for the pacing readings and the key checks (hence https://, and --verify-rpc-url
    /// to check it against a second provider).
    Publish {
        /// The artifact: a WASM builder or a risc0 guest ELF.
        file: std::path::PathBuf,
        /// What FILE is; it must parse as one (publication is permanent).
        #[arg(long, value_parser = ["builder", "elf"])]
        kind: String,
        /// The HemiProve chain's RPC (never the miner's [chain] rpc_url while it runs): https:// unless
        /// the configuration's developer mode is for this chain. The publisher trusts it for the
        /// pacing gate's readings and the key checks. A URL carrying a provider key is better given
        /// by --rpc-url-file or ZKMINER_PUBLISH_RPC_URL (argv is visible to every local user).
        #[arg(long, conflicts_with = "rpc_url_file")]
        rpc_url: Option<String>,
        /// Read the RPC URL from this file (its first line).
        #[arg(long)]
        rpc_url_file: Option<std::path::PathBuf>,
        /// A second RPC of the same chain, from another provider: each deployment's receipt must show
        /// the same block there before the next chunk is signed, and the read-back is repeated
        /// there, so one lying or intercepted RPC cannot collect the chunks unsent.
        #[arg(long, conflicts_with = "verify_rpc_url_file")]
        verify_rpc_url: Option<String>,
        /// Read the second RPC's URL from this file (its first line).
        #[arg(long)]
        verify_rpc_url_file: Option<std::path::PathBuf>,
        /// The HemiProve chain id the RPC must serve.
        #[arg(long)]
        chain_id: u64,
        /// The publisher's encrypted keystore (Web3 Secret Storage JSON).
        #[arg(long)]
        keystore: std::path::PathBuf,
        /// Read the keystore password from this file descriptor instead of the terminal: 3 or above,
        /// a pipe or a regular file the caller opened for this command (`3<file`, or a pipe).
        #[arg(long)]
        password_fd: Option<i32>,
        /// The HemiProve router (default: the known deployment's on --chain-id).
        #[arg(long)]
        router: Option<alloy::primitives::Address>,
        /// The first block of the operator check's log scan (default: the known deployment's).
        #[arg(long)]
        from_block: Option<u64>,
        /// The tip in wei (default: the inclusion floor measured from recent blocks).
        #[arg(long)]
        tip_wei: Option<u128>,
        /// This command's own request rate limit.
        #[arg(long, default_value_t = 4)]
        max_requests_per_sec: u32,
        /// The least wall-clock time between two sends, in milliseconds (default: the chain's block
        /// time: 12 s on Hemi, else measured over the last 64 blocks; at least 1 s outside
        /// developer mode, and never below a known chain's block time). Paces the publisher
        /// whatever the RPC reports.
        #[arg(long)]
        block_time_ms: Option<u64>,
        /// Record each mined deployment in this file, and on a later run of the same file to the
        /// same chain reuse the chunks it lists (their code checked on chain) instead of sending
        /// them again.
        #[arg(long)]
        progress: Option<std::path::PathBuf>,
        /// Send after the cost preview without asking.
        #[arg(long)]
        yes: bool,
        /// Print the preview on stderr and the result on stdout as JSON.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
enum EnvelopeCommand {
    /// Encode `inputData = WITNESS_JOB_TAG_V1 ‖ abi.encode(WitnessJobV1)` from a TOML (`.toml`) or
    /// JSON spec and print it as 0x hex. A bare envelope spec has the envelope's fields; a job spec
    /// has `program_id`, a `[binding]` and an `[envelope]` table and also yields the descriptor file
    /// `zkminer simulate --descriptor` reads. The result is checked with the miner's own decoder.
    Encode {
        /// The spec file.
        spec: std::path::PathBuf,
        /// The builder artifact (WASM): its sha256 is the builderId (and must equal a given one).
        #[arg(long)]
        builder: Option<std::path::PathBuf>,
        /// Write the 0x hex inputData here instead of stdout.
        #[arg(long)]
        out: Option<std::path::PathBuf>,
        /// Write the descriptor file here (job specs only).
        #[arg(long)]
        descriptor_out: Option<std::path::PathBuf>,
        /// Print one JSON document (inputData, its hash, the descriptor and binding).
        #[arg(long)]
        json: bool,
    },
    /// Explain an inputData: what the miner's decoder makes of it, each builderURI as a miner on
    /// `--chain-id` reads it, and the envelope as an editable spec. Exits non-zero when the miner
    /// would skip it.
    Decode {
        /// 0x hex, or a file of 0x hex or raw bytes.
        input: String,
        /// The HemiProve chain the job is on (decides which hemi-code locators are usable).
        #[arg(long, default_value_t = 743111)]
        chain_id: u64,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
enum BindingCommand {
    /// `journalFields` and `expectedJournalHash` from the requester's own parameters: FIELDS over
    /// the whole header (one `--word` per header word, in order), FULL over a statement known in full
    /// at submit (`--full-statement`), or NONE (`--none`, assigned jobs only). Never take these from a
    /// prover's journal.
    Compute {
        /// A header word, `type:value`: uintN, bool, address, bytesN, bytes32, keccak:<text>, word.
        #[arg(long = "word", value_name = "TYPE:VALUE")]
        words: Vec<String>,
        /// FULL: the whole statement (the journal after any prefix), 0x hex.
        #[arg(long, conflicts_with_all = ["words", "none"])]
        full_statement: Option<String>,
        /// NONE: nothing bound (only with an assigned prover: give it with --assigned).
        #[arg(long, conflicts_with = "words")]
        none: bool,
        /// The job's assigned prover: a NONE binding without one fails (the router refuses it).
        #[arg(long)]
        assigned: Option<alloy::primitives::Address>,
        /// Without the journal-prefix marker (the marker is the default for open witness jobs).
        #[arg(long)]
        no_prefix: bool,
        /// FULL hashes the program id.
        #[arg(long)]
        program_id: Option<alloy::primitives::B256>,
        /// `risc0` or a 0x proof-system id.
        #[arg(long, default_value = "risc0")]
        proof_system: String,
        #[arg(long)]
        json: bool,
    },
    /// The mutation check: change each byte of a statement in turn, recompute the router's hash, and
    /// report which bytes the binding leaves free. Non-zero exit when a header byte is free, the
    /// header's length is unknown (FIELDS) or longer than the statement, a range ends past the
    /// statement, the expected hash does not match or is not given, the router would refuse the
    /// binding at submit, or the binding is NONE without --assigned.
    Check {
        /// A descriptor file (its journalFields, expectedJournalHash and programId).
        #[arg(long)]
        descriptor: Option<std::path::PathBuf>,
        #[arg(long)]
        journal_fields: Option<alloy::primitives::B256>,
        #[arg(long)]
        expected_journal_hash: Option<alloy::primitives::B256>,
        #[arg(long)]
        program_id: Option<alloy::primitives::B256>,
        #[arg(long, default_value = "risc0")]
        proof_system: String,
        /// The header words, as `compute` takes them: the statement is their concatenation.
        #[arg(long = "word", value_name = "TYPE:VALUE")]
        words: Vec<String>,
        /// A whole journal (prefix included for a journal-prefix job): 0x hex or a file.
        #[arg(long, conflicts_with = "statement")]
        journal: Option<String>,
        /// The statement (the journal after any prefix): 0x hex or a file.
        #[arg(long)]
        statement: Option<String>,
        /// The header's length in bytes (default: 32 × the words given).
        #[arg(long)]
        header_bytes: Option<usize>,
        /// The job's assigned prover (default: the descriptor's): a NONE binding without one fails.
        #[arg(long)]
        assigned: Option<alloy::primitives::Address>,
        #[arg(long)]
        json: bool,
    },
}

/// What `main` takes from the process before the async runtime starts.
#[derive(Default)]
struct Early {
    /// `artifact publish --password-fd N`, checked and owned.
    #[cfg(target_os = "linux")]
    password_fd: Option<std::os::fd::OwnedFd>,
}

fn main() -> Result<()> {
    // The miner holds the operator's signing key. Non-dumpable, its `/proc/<pid>` entries belong to
    // root, so no other process of this uid can read its memory or environment (`mem`, `environ`,
    // `maps`, `fd`), whatever the host's `ptrace_scope`, and it leaves no core dump. Its own reads of
    // `/proc/self` it needs are world-readable files; the processes it starts are dumpable again
    // once they exec (the workers, whose `/proc` entries the dispatcher reads).
    #[cfg(target_os = "linux")]
    // SAFETY: a plain prctl.
    unsafe {
        libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
    }
    let cli = Cli::parse();
    // `--password-fd N` is taken now, while every open descriptor above 2 is one the caller passed:
    // once the runtime, the network guard or a connection has opened its own, a number the caller
    // did not open could name one of them (and reading it to the end would close it).
    #[allow(unused_mut)]
    let mut early = Early::default();
    #[cfg(target_os = "linux")]
    if let Commands::Artifact {
        command:
            ArtifactCommand::Publish {
                password_fd: Some(fd),
                ..
            },
    } = &cli.command
    {
        early.password_fd = Some(commands::artifact::keys::take_password_fd(*fd)?);
    }
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()?
        .block_on(run(cli, early))
}

#[cfg_attr(not(target_os = "linux"), allow(unused_variables))]
async fn run(cli: Cli, early: Early) -> Result<()> {
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
            descriptor: Some(descriptor),
            builder,
            elf,
            prover,
            keccak_po2,
            broker_config,
            out,
            adversarial,
            adversarial_secs,
            flips,
            max_mutations,
            scheme,
            providers,
            adversarial_max_w_bytes,
            max_guest_cycles,
            header_bytes,
            po2,
            execute_timeout_secs,
            risc0_worker,
            cache_dir,
            ..
        } => {
            // Without --po2: this configuration's cards' sizes when it names them, else every job size,
            // each judged on its own (see `simulate_witness::po2_plan`).
            let po2s = po2
                .as_deref()
                .map(commands::simulate::parse_po2_set)
                .transpose()?;
            anyhow::ensure!((14..=18).contains(&keccak_po2), "--keccak-po2 must be within 14..=18");
            let opts = commands::simulate_witness::WitnessSimOptions {
                descriptor,
                builder,
                elf,
                prover,
                po2s,
                keccak_po2,
                broker_config,
                execute_worker: risc0_worker,
                cache_dir,
                execute_timeout: simulate_bound("--execute-timeout-secs", execute_timeout_secs),
                out,
                max_guest_cycles,
                header_bytes,
                adversarial: adversarial.then(|| commands::simulate_witness::AdversarialOptions {
                    budget: std::time::Duration::from_secs(adversarial_secs),
                    flips,
                    max_mutations,
                    scheme,
                    providers,
                    max_w_bytes: adversarial_max_w_bytes,
                }),
            };
            commands::simulate_witness::run(config_path, opts).await
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
            ..
        } => {
            let po2 = match po2.as_deref() {
                None => zkminer_prover_protocol::RISC0_DEFAULT_JOB_PO2,
                Some(s) => match commands::simulate::parse_po2_set(s)?.as_slice() {
                    [one] => *one,
                    _ => anyhow::bail!("--po2 takes one size for on-chain jobs"),
                },
            };
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
        #[cfg(target_os = "linux")]
        Commands::Artifact {
            command:
                ArtifactCommand::Publish {
                    file,
                    kind,
                    rpc_url,
                    rpc_url_file,
                    verify_rpc_url,
                    verify_rpc_url_file,
                    chain_id,
                    keystore,
                    password_fd: _,
                    router,
                    from_block,
                    tip_wei,
                    max_requests_per_sec,
                    block_time_ms,
                    progress,
                    yes,
                    json,
                },
        } => {
            use commands::artifact::{plan::Kind, rpc_url_from, PublishOptions, RPC_URL_ENV};
            let kind = if kind == "elf" { Kind::Elf } else { Kind::Builder };
            let rpc_url = rpc_url_from(rpc_url, rpc_url_file.as_deref(), Some(RPC_URL_ENV))?
                .ok_or_else(|| {
                    anyhow::anyhow!("name the RPC with --rpc-url, --rpc-url-file or {RPC_URL_ENV}")
                })?;
            let verify_rpc_url =
                rpc_url_from(verify_rpc_url, verify_rpc_url_file.as_deref(), None)?;
            commands::artifact::publish(
                config_path,
                PublishOptions {
                    file,
                    kind,
                    rpc_url,
                    verify_rpc_url,
                    chain_id,
                    keystore,
                    password_fd: early.password_fd,
                    router,
                    from_block,
                    tip_wei,
                    max_requests_per_sec,
                    block_time_ms,
                    progress,
                    yes,
                    json,
                },
            )
            .await
        }
        #[cfg(not(target_os = "linux"))]
        Commands::Artifact { .. } => anyhow::bail!("zkminer artifact publish runs on Linux only"),
        Commands::Init {
            force,
            network,
            generate_key,
        } => commands::init::run(config_path, force, &network, generate_key),
        Commands::Witness { command } => match command {
            WitnessCommand::InitStore {
                dir,
                require_dedicated_mount,
                allow_any_filesystem,
            } => commands::witness::init_store(
                config_path,
                dir,
                require_dedicated_mount,
                allow_any_filesystem,
            ),
            WitnessCommand::SelfTest { probe } => {
                commands::witness::self_test(config_path, probe).await
            }
            WitnessCommand::Envelope { command } => match command {
                EnvelopeCommand::Encode { spec, builder, out, descriptor_out, json } => {
                    commands::witness_tools::envelope_encode(
                        &spec,
                        builder.as_deref(),
                        out.as_deref(),
                        descriptor_out.as_deref(),
                        json,
                    )
                }
                EnvelopeCommand::Decode { input, chain_id, json } => {
                    commands::witness_tools::envelope_decode(&input, chain_id, json)
                }
            },
            WitnessCommand::Binding { command } => match command {
                BindingCommand::Compute {
                    words,
                    full_statement,
                    none,
                    assigned,
                    no_prefix,
                    program_id,
                    proof_system,
                    json,
                } => {
                    let spec = commands::witness_tools::BindingSpec {
                        prefix: !no_prefix,
                        header: (!words.is_empty()).then_some(words),
                        full_statement,
                        none,
                    };
                    commands::witness_tools::binding_compute(&spec, &proof_system, program_id, assigned, json)
                }
                BindingCommand::Check {
                    descriptor,
                    journal_fields,
                    expected_journal_hash,
                    program_id,
                    proof_system,
                    words,
                    journal,
                    statement,
                    header_bytes,
                    assigned,
                    json,
                } => commands::witness_tools::binding_check(commands::witness_tools::CheckArgs {
                    descriptor,
                    journal_fields,
                    expected_journal_hash,
                    program_id,
                    proof_system,
                    words,
                    journal,
                    statement,
                    header_bytes,
                    assigned,
                    json,
                }),
            },
        },
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
    fn witness_subcommands_parse() {
        let cli = Cli::try_parse_from(["zkminer", "witness", "init-store", "--dir", "/srv/r"]).unwrap();
        match cli.command {
            Commands::Witness {
                command:
                    WitnessCommand::InitStore {
                        dir,
                        require_dedicated_mount,
                        allow_any_filesystem,
                    },
            } => {
                assert_eq!(dir, Some(std::path::PathBuf::from("/srv/r")));
                assert!(!require_dedicated_mount && !allow_any_filesystem);
            }
            _ => panic!("not witness init-store"),
        }
        let cli = Cli::try_parse_from(["zkminer", "witness", "self-test"]).unwrap();
        assert!(matches!(
            cli.command,
            Commands::Witness {
                command: WitnessCommand::SelfTest { probe: None }
            }
        ));
        assert!(Cli::try_parse_from(["zkminer", "witness"]).is_err());
        let cli = Cli::try_parse_from([
            "zkminer", "witness", "binding", "compute", "--word", "uint:1", "--word", "uint:2", "--no-prefix",
        ])
        .unwrap();
        match cli.command {
            Commands::Witness {
                command: WitnessCommand::Binding { command: BindingCommand::Compute { words, no_prefix, none, .. } },
            } => {
                assert_eq!(words, ["uint:1", "uint:2"]);
                assert!(no_prefix && !none);
            }
            _ => panic!("not witness binding compute"),
        }
        // One binding form at a time.
        assert!(Cli::try_parse_from(["zkminer", "witness", "binding", "compute", "--word", "uint:1", "--none"]).is_err());
        assert!(Cli::try_parse_from(["zkminer", "witness", "envelope", "encode", "job.toml", "--descriptor-out", "d.json"]).is_ok());
        assert!(Cli::try_parse_from(["zkminer", "witness", "envelope", "decode", "0x00", "--chain-id", "31337"]).is_ok());
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
                assert_eq!(po2.as_deref(), Some("21"));
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
        // Descriptor mode and its flags.
        let cli = Cli::try_parse_from([
            "zkminer", "simulate", "--descriptor", "d.json", "--builder", "b.wasm", "--po2", "16..18", "--adversarial",
            "--adversarial-secs", "60", "--providers", "a,b", "--scheme", "1",
        ])
        .unwrap();
        match cli.command {
            Commands::Simulate { descriptor, builder, po2, adversarial, adversarial_secs, providers, scheme, flips, .. } => {
                assert_eq!(descriptor, Some("d.json".into()));
                assert_eq!(builder, Some("b.wasm".into()));
                assert_eq!(po2.as_deref(), Some("16..18"));
                assert!(adversarial);
                assert_eq!(adversarial_secs, 60);
                assert_eq!(providers, Some(vec!["a".to_string(), "b".to_string()]));
                assert_eq!(scheme, Some(1));
                assert_eq!(flips, commands::simulate_witness::DEFAULT_FLIPS);
            }
            _ => panic!("not a simulate command"),
        }
        // Descriptor mode excludes the on-chain modes; its flags need it.
        assert!(Cli::try_parse_from(["zkminer", "simulate", "--descriptor", "d.json", "--stdin"]).is_err());
        assert!(Cli::try_parse_from(["zkminer", "simulate", "--stdin", "--builder", "b.wasm"]).is_err());
        assert!(Cli::try_parse_from(["zkminer", "simulate", "--descriptor", "d", "--flips", "3"]).is_err());
    }
}
