//! End-to-end tests of zkminer against a local fork of the live Hemi testnet (743111).
//!
//! anvil forks 743111, so the fork runs the real HemiProve v2 deployment that zkminer's startup
//! checks pin. Each test then sets up, on the fork only:
//! - tHEMI for a submitter and a prover, minted as the token's owner;
//! - the prover's stake;
//! - programs in the ProgramRegistry, with storage URIs this test serves over HTTP (an id someone
//!   already registered on 743111 is first cleared, as the registry's owner);
//! - jobs covering the binding, assignment and collateral cases (see [`Case`]): four the miner must
//!   claim (one of them assigned to another prover with no exclusivity window), the rest it must
//!   refuse (among them one inside another prover's exclusivity window, and one whose collateral
//!   exceeds the prover's whole stake). Some are submitted before the miner starts and some after;
//!   the miner's backfill starts at the first one's block, so a backfill that starts a block late
//!   loses it.
//!
//! and runs the `zkminer` binary against the fork. anvil impersonates every sender, so setting up
//! needs no key. Each miner runs with its own HOME and a cleaned environment.
//!
//! The tests:
//! - `watch_only_reports_every_job`: `zkminer run --watch-only`, on the fibonacci guest, as the
//!   staked prover and then as an address with no stake, with `RISC0_EXECUTOR` set to a value
//!   risc0 does not know (the worker must ignore it). Checks each job's verdict, that exactly the
//!   claimable jobs would be claimed, that every measured cycle count is a power of two (the guests
//!   run in one segment), and that nothing was sent. CPU only.
//! - `fulfils_with_a_replayed_receipt`: `zkminer run` with the prover's key on the contract suite's
//!   RISC Zero receipt fixture, which the deployed verifier accepts. The mock worker replays that
//!   receipt instead of proving, so the miner claims and fulfils for real on the fork: every
//!   on-chain step of mining, on a CPU. Checks exactly the claimable jobs are fulfilled, each
//!   dispatched and claimed in an earlier transaction than its fulfil, nothing else is claimed or
//!   released (the prover sends just a claim and a fulfil per job), the exclusive and
//!   over-collateralised jobs are never even dispatched, and no collateral is left locked.
//! - `holds_its_lock_through_a_pause`: a lock held while the router pauses is kept, not released:
//!   its fulfil is held with nothing sent for longer than the nonce-gap watchdog takes to act, and
//!   sent after the lift.
//! - `holds_off_while_the_router_is_paused`, `refuses_to_claim_while_its_adapter_is_disabled`,
//!   `refuses_to_claim_on_a_skewed_clock`: the miner's own gates hold every claim (no claim is
//!   dispatched, nothing is sent); the paused one claims and fulfils after the lift.
//! - `mines_the_claimable_jobs`: the replay test with the real risc0 worker on the fibonacci guest:
//!   real GPU proofs. Runs only with `ZKMINER_LOCALNET_MINE=1`.
//!
//! All are ignored by default: they need anvil (Foundry), the workers, and the testnet RPC, which
//! must serve state at the fork block (it does: it is an archive node). anvil caches what it
//! fetches under `~/.foundry/cache/rpc`, so later runs at the same block are quicker.
//!
//! ```text
//! cargo build --release -p zkminer-prove-risc0 --features cuda --bin zkminer-prove-risc0-cuda
//! cargo build -p zkminer-prover --features testing --bin mock-worker
//! cargo test -p zkminer-cli --test localnet -- --ignored --nocapture --test-threads=1
//! ```
//!
//! Environment:
//! - `ZKMINER_LOCALNET_FORK_URL`: the 743111 RPC to fork (default: the public testnet RPC).
//! - `ZKMINER_LOCALNET_FORK_BLOCK`: the block to fork at (default [`FORK_BLOCK`]; `latest` for the
//!   head).
//! - `ZKMINER_LOCALNET_RISC0_WORKER`: the risc0 worker (default:
//!   `target/release/zkminer-prove-risc0-cuda`).
//! - `ZKMINER_LOCALNET_MOCK_WORKER`: the mock worker (default: `target/debug/mock-worker`).
//! - `ANVIL`: the anvil binary (default: `anvil` on `PATH`).
//! - `ZKMINER_LOCALNET_ZKMINER`: the zkminer binary to test (default: the one cargo built with this
//!   test), and `ZKMINER_LOCALNET_TMPDIR`: where run directories go (default: `target/tmp`). The
//!   release's GPU validation uses both to run a separately built copy of this test.
//! - `ZKMINER_LOCALNET_ECHO=1`: echo zkminer's log while it runs.
//! - `ZKMINER_LOCALNET_KEEP=1`: keep the run directory (under `target/tmp`) after a pass; a failed
//!   run always keeps it.
//! - `ZKMINER_LOCALNET_EXPECT_CLAIMS=0`: in the watch test, don't require the would-claim verdicts
//!   (for a host whose capacity or memory gates refuse every claim).
//! - `ZKMINER_LOCALNET_MINE=1`, `ZKMINER_LOCALNET_MINE_TIMEOUT_SECS` (default 1800): the mining
//!   test. It honours `CUDA_VISIBLE_DEVICES` (see `mines_the_claimable_jobs`).
//! - `ZKMINER_LOCALNET_PROVER_STAKE` (HEMI, default 1000): the prover's stake. Every job here locks at
//!   least 100 HEMI, so the default holds ten jobs at once.
//! - `ZKMINER_LOCALNET_FIB_N` (default 10): the fibonacci jobs' input. A larger one makes each proof
//!   last long enough for several cards to prove at once.
#![cfg(unix)]

use alloy::primitives::aliases::{U40, U96};
use alloy::primitives::{keccak256, Address, Bytes, B256, U256};
use alloy::providers::{DynProvider, Provider, ProviderBuilder};
use alloy::rpc::types::{Filter, TransactionRequest};
use alloy::signers::local::PrivateKeySigner;
use alloy::sol_types::SolEvent;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use zkminer_chain::auction::{is_sp1_id, risc_zero_groth16_v1_id, sp1_groth16_v1_id};
use zkminer_chain::binding::{fields_hash, full_hash};
use zkminer_chain::deployment::HEMI_TESTNET_743111 as DEPLOYMENT;
use zkminer_config::ZkMinerConfig;
use zkminer_contracts::bindings::{
    AuctionConfig, CompetitiveBidConfig, CycleConfig, IHemiProveAux, IHemiProveCore,
    IHemiProveFulfill, IHemiProveStaking, IProgramRegistry, ITestnetToken, JobDescriptor,
    ResourceEstimate, StorageURI, IERC20,
};

/// The 743111 block the fork starts from by default, after the deployment's setup. Move it forward
/// whenever `zkminer_chain::deployment::HEMI_TESTNET_743111` changes: the fork would otherwise run
/// the old deployment, and zkminer's startup checks refuse it. A later block is fine even once
/// someone registers this test's programs on 743111 (their ids are content-derived): setup clears
/// such a registration first (see [`register_program`]).
const FORK_BLOCK: u64 = 7_116_900;
const DEFAULT_FORK_URL: &str = "https://testnet.rpc.hemi.network/rpc";
const HEMI: u128 = 1_000_000_000_000_000_000;
/// The fibonacci guest's jobs prove fibonacci(FIB_N), unless `ZKMINER_LOCALNET_FIB_N` says otherwise
/// (`fib_n`).
const FIB_N: u32 = 10;

/// The fibonacci jobs' input: `ZKMINER_LOCALNET_FIB_N`, or `FIB_N`.
fn fib_n() -> u32 {
    std::env::var("ZKMINER_LOCALNET_FIB_N")
        .ok()
        .and_then(|n| n.trim().parse().ok())
        .unwrap_or(FIB_N)
}
/// The contract suite's RISC Zero Groth16 receipt (zkmarket c8333aa,
/// `test/fixtures/RiscZeroTestReceipt.sol`): risc0 v3.0 Groth16, accepted by the deployed
/// `RiscZeroGroth16Verifier` (SELECTOR 0x73c457ba) for this image id and journal.
const FIXTURE_IMAGE_ID: B256 =
    alloy::primitives::b256!("bc93ea63d7adda6b4e2f0f930c2c9fe53d57e8f4add5aa81af2373949517edfe");
const FIXTURE_JOURNAL: &[u8] = b"zkpool e2e test";
/// The fixture's 260-byte seal: the 4-byte selector, then the proof.
const FIXTURE_SEAL_HEX: &str = concat!(
    "73c457ba24677d214ea29517cc0f883aa3a8b2514eb49f2dc4a36b217d42b5846a230e28278fb944762bb974fe0383a41cf1dc78",
    "58050e64b70a2ffc4503598c41eb12382402e2f159318f290703591d36b097fe07ae8709d72805e5eed3e229d88e713b26d90595",
    "7d4a98702d3dbf19047b05102eb0b9726a70e7f146f2026f272973b222028908b6aa9c6e87b36e63121c601016261f92be7877f7",
    "58475101f64277d40fb8f805de9db44c9ac2e6095f5422599ceb8bf8df9edbb766ab19bb89f2b2a824d17896c55a0487f4172c96",
    "1aba47cd3e0422037fc1bf524fdb01e21dc4f8300bc0f922f535135f8a0a36942ceae7c81d12e0b255cda9eda5d161715ad74d46",
);
/// Every job but [`Case::HighCollateral`]'s is fixed-price at this.
const JOB_PRICE: u128 = 5 * HEMI;
const PROVER_STAKE: u128 = 1_000 * HEMI;
/// How many times `World::submit_job` tries one job before failing the run.
const SUBMIT_TRIES: u32 = 6;

/// The stake the prover is given: `PROVER_STAKE`, or `ZKMINER_LOCALNET_PROVER_STAKE` HEMI. A job on
/// 743111 locks at least its 100 HEMI floor whatever its price, so `PROVER_STAKE` covers ten at once:
/// a run measuring how far ahead the miner claims needs more. The high-collateral case is sized
/// against `PROVER_STAKE` and is not one of the cases such a run submits.
fn prover_stake() -> u128 {
    std::env::var("ZKMINER_LOCALNET_PROVER_STAKE")
        .ok()
        .and_then(|s| s.trim().parse::<u128>().ok())
        .map_or(PROVER_STAKE, |hemi| hemi * HEMI)
}
/// [`Case::HighCollateral`]'s price, and its collateral rate: `MAX_COLLATERAL_BPS` (500%), the most a
/// submitter may ask (zkmarket c8333aa, `src/libraries/Constants.sol`).
const HIGH_COLLATERAL_PRICE: u128 = 250 * HEMI;
const MAX_COLLATERAL_BPS: u64 = 50_000;
// Its claim would lock 1,250 HEMI, more than the whole stake; sized at the 150% default (the miner's
// old sizing), it would fit.
const _: () = assert!(
    HIGH_COLLATERAL_PRICE * MAX_COLLATERAL_BPS as u128 / 10_000 > PROVER_STAKE
        && HIGH_COLLATERAL_PRICE * 15_000 / 10_000 < PROVER_STAKE
);
/// [`Case::FullExclusiveForAnother`]'s exclusivity window, which outlasts any run (the router takes 0
/// or 60 s to 24 h).
const EXCLUSIVITY: Duration = Duration::from_secs(3_600);
/// The prover the `…ForAnother` jobs are assigned to.
const ANOTHER_PROVER: Address = Address::repeat_byte(0x42);
/// How long the watch test waits for every verdict.
const WATCH_TIMEOUT: Duration = Duration::from_secs(420);
/// How long the replay tests wait for their fulfils.
const REPLAY_TIMEOUT: Duration = Duration::from_secs(420);
/// How long the mock proof takes in `holds_its_lock_through_a_pause`: the router's pause, sent once
/// the job is claimed, must land well before the fulfil could.
const PAUSE_PROVE_DELAY: Duration = Duration::from_secs(60);
/// How long that test keeps the router paused once the fulfil is held: longer than the nonce-gap
/// watchdog takes to fill a gap (within ~2 minutes: a probe a minute, filling a gap that has
/// persisted 45 s), so a hold that touched the nonce allocator would show as a sent transaction.
const PAUSE_HOLD: Duration = Duration::from_secs(150);
/// How long a miner with nothing in flight may take to exit after SIGINT.
const STOP_GRACE: Duration = Duration::from_secs(60);
/// How long a mining miner may take to drain and exit after SIGINT.
const DRAIN_GRACE: Duration = Duration::from_secs(120);
/// After the outcome a test waits for, how long it keeps watching before its final checks, so a
/// wrong claim or verdict that lands just after is still seen (several of the brain's 5 s ticks).
const SETTLE: Duration = Duration::from_secs(30);

/// The binding cases. Each is one job.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Case {
    /// FULL: `keccak256(abi.encode(domain, psId, programId, journal))` of the real journal.
    Full,
    /// FIELDS: the journal's first 8 bytes as one range.
    Fields,
    /// FULL over a journal the program does not commit: refused before the claim.
    FullWrongJournal,
    /// FIELDS over bytes the program does not commit: refused before the claim.
    FieldsWrongJournal,
    /// NONE, assigned to the prover.
    NoneForUs,
    /// NONE, assigned to another prover: reserved for it.
    NoneForAnother,
    /// FULL as [`Case::Full`], assigned to another prover with no exclusivity window: the router
    /// holds a FULL job's assignment only within its window, so anyone may claim it.
    FullForAnother,
    /// FULL as [`Case::Full`], assigned to another prover for an [`EXCLUSIVITY`] window that outlasts
    /// the run: only that prover may claim it meanwhile.
    FullExclusiveForAnother,
    /// FULL as [`Case::Full`], at [`HIGH_COLLATERAL_PRICE`] and 500% collateral: its lock would
    /// exceed the prover's whole stake, so the brain's per-job collateral gate must hold it.
    HighCollateral,
    /// FULL with the journal-prefix marker, which this build does not support.
    PrefixMarker,
    /// FULL, for a program whose registry URI serves another program's ELF (this run's): its image
    /// id is not the job's `programId`, so the worker refuses to execute it. Real workers only (the
    /// mock worker checks nothing).
    DecoyElf,
    /// FULL, for a program whose registry URI is unreachable.
    ElfUnreachable,
}

impl Case {
    /// Every case, for a run with a real worker.
    const ALL: [Case; 12] = [
        Case::Full,
        Case::Fields,
        Case::FullWrongJournal,
        Case::FieldsWrongJournal,
        Case::NoneForUs,
        Case::NoneForAnother,
        Case::FullForAnother,
        Case::FullExclusiveForAnother,
        Case::HighCollateral,
        Case::PrefixMarker,
        Case::DecoyElf,
        Case::ElfUnreachable,
    ];
    /// Every case the mock worker can serve.
    const REPLAYABLE: [Case; 11] = [
        Case::Full,
        Case::Fields,
        Case::FullWrongJournal,
        Case::FieldsWrongJournal,
        Case::NoneForUs,
        Case::NoneForAnother,
        Case::FullForAnother,
        Case::FullExclusiveForAnother,
        Case::HighCollateral,
        Case::PrefixMarker,
        Case::ElfUnreachable,
    ];

    fn claimable(self) -> bool {
        matches!(
            self,
            Case::Full | Case::Fields | Case::NoneForUs | Case::FullForAnother
        )
    }

    /// Refused by the brain before it dispatches a claim, on a check a claim would also fail at its
    /// quote, before any transaction (the exclusivity window, the job's own collateral). So only the
    /// missing `CLAIM <job> (` line ([`dispatched`]) shows that the brain's check held.
    fn held_before_dispatch(self) -> bool {
        matches!(self, Case::FullExclusiveForAnother | Case::HighCollateral)
    }

    /// Submitted before the miner starts, so it finds the job in its startup backfill; the others
    /// are submitted once it runs, so its live monitor finds them. Each half has jobs it must claim
    /// and jobs it must refuse.
    fn before_start(self) -> bool {
        matches!(
            self,
            Case::Full
                | Case::FullWrongJournal
                | Case::NoneForAnother
                | Case::FullExclusiveForAnother
                | Case::DecoyElf
        )
    }

    /// The price this case's job is fixed at.
    fn price(self) -> u128 {
        match self {
            Case::HighCollateral => HIGH_COLLATERAL_PRICE,
            _ => JOB_PRICE,
        }
    }

    /// This case's auction: fixed-price, with its exclusivity window and collateral rate.
    fn auction(self) -> AuctionConfig {
        let mut a = fixed_price(self.price());
        match self {
            Case::FullExclusiveForAnother => {
                a.exclusivityDuration = U40::from(EXCLUSIVITY.as_secs());
            }
            Case::HighCollateral => a.lockCollateralBps = U96::from(MAX_COLLATERAL_BPS),
            _ => {}
        }
        a
    }

    /// What submitting this case's job takes from the submitter: its maximum price and its speed
    /// premium.
    fn deposit(self) -> u128 {
        let a = self.auction();
        a.maxPrice.to::<u128>() + a.speedPremium.to::<u128>()
    }

    /// What the watch-only inspector's verdict for this job must contain, watching as the staked
    /// prover or as an address with no stake.
    fn inspector_verdict(self, staked: bool) -> String {
        let quote = if staked {
            format!("claim quote {} HEMI", hemi(self.price()))
        } else {
            "the claim would be refused (StakeShort)".to_string()
        };
        match self {
            Case::Full | Case::Fields | Case::FullForAnother => {
                format!("binding satisfied; {quote}")
            }
            Case::NoneForUs if staked => format!("no journal binding; {quote}"),
            Case::NoneForUs => "reserved for prover".into(),
            Case::FullWrongJournal | Case::FieldsWrongJournal => {
                "the measured journal FAILS its binding".into()
            }
            Case::NoneForAnother => "reserved for prover".into(),
            Case::FullExclusiveForAnother => {
                format!("assigned to prover {ANOTHER_PROVER}, and its exclusivity has not lapsed")
            }
            // Staked or not, the quote's simulated claim reverts: the lock overruns the free stake
            // (the staking contract's assert, Panic(0x01)) or there is no stake at all.
            Case::HighCollateral => {
                "binding satisfied; the claim would be refused (StakeShort)".into()
            }
            Case::PrefixMarker => "its binding marker is not supported".into(),
            Case::DecoyElf | Case::ElfUnreachable => "it cannot be measured".into(),
        }
    }

    /// The `programId` this case's job is for.
    fn program_id(self, program: &Program) -> B256 {
        match self {
            Case::DecoyElf => keccak256(b"zkminer localnet decoy program"),
            Case::ElfUnreachable => keccak256(b"zkminer localnet unreachable program"),
            _ => program.id,
        }
    }
}

fn fib(n: u32) -> u64 {
    let (mut a, mut b) = (0u64, 1u64);
    for _ in 0..n {
        (a, b) = (b, a.wrapping_add(b));
    }
    a
}

/// Where the fork's clock is set.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Clock {
    /// On the wall clock, like a live chain.
    Wall,
    /// This many seconds behind it: this host's clock runs ahead of the chain's.
    Lagging(u64),
}

/// The program a run's jobs are for: what its registry URI serves, and what its jobs bind.
struct Program {
    name: &'static str,
    /// The image id (risc0) or vkey hash (SP1): the jobs' `programId`.
    id: B256,
    /// The jobs' `proofSystemId`, and the one the program is registered under.
    proof_system: B256,
    /// The bytes its storage URI serves.
    elf: Vec<u8>,
    /// Every job's `inputData`.
    input: Vec<u8>,
    /// The journal a proof of `input` commits.
    journal: Vec<u8>,
}

impl Program {
    /// The fibonacci guest, exported by the risc0 worker that runs it. It reads a `u32` and commits
    /// the `u64` result.
    fn fibonacci(worker: &Path, dir: &Path) -> Self {
        let (elf, id) = export_guest(worker, dir);
        Program {
            name: "fibonacci (zkminer localnet)",
            id,
            proof_system: risc_zero_groth16_v1_id(),
            elf,
            input: fib_n().to_le_bytes().to_vec(),
            journal: fib(fib_n()).to_le_bytes().to_vec(),
        }
    }

    /// The receipt fixture's statement. Nothing runs its binary: the mock worker replays the
    /// receipt, so the URI serves a placeholder and the input is arbitrary.
    fn fixture() -> Self {
        Program {
            name: "receipt fixture (zkminer localnet)",
            id: FIXTURE_IMAGE_ID,
            proof_system: risc_zero_groth16_v1_id(),
            elf: b"zkminer localnet: the mock worker replays this program's receipt".to_vec(),
            input: b"zkminer localnet".to_vec(),
            journal: FIXTURE_JOURNAL.to_vec(),
        }
    }

    /// The SP1 fibonacci guest, exported by the SP1 worker (its vkey hash is the `programId`). It reads
    /// a `u32` and commits the `u64` result, as the risc0 one does.
    fn sp1_fibonacci(worker: &Path, dir: &Path) -> Self {
        let (elf, id) = export_guest(worker, &dir.join("sp1"));
        Program {
            name: "fibonacci SP1 (zkminer localnet)",
            id,
            proof_system: sp1_groth16_v1_id(),
            elf,
            input: fib_n().to_le_bytes().to_vec(),
            journal: fib(fib_n()).to_le_bytes().to_vec(),
        }
    }

    /// A journal this program does not commit: its own with the first byte changed (inside the
    /// FIELDS range too).
    fn wrong_journal(&self) -> Vec<u8> {
        let mut j = self.journal.clone();
        j[0] ^= 0x01;
        j
    }
}

/// `fmt_hemi`'s format: whole HEMI and two decimals.
fn hemi(wei: u128) -> String {
    format!("{}.{:02}", wei / HEMI, (wei % HEMI) / (HEMI / 100))
}

fn short_id(id: B256) -> String {
    format!("{id}")[..10].to_string()
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// The miner under test: `ZKMINER_LOCALNET_ZKMINER`, or the one cargo built with this test. The
/// release's GPU validation (scripts/ci/gpu-validate.sh) runs this test, built on its own, against
/// the release's binaries.
fn zkminer_exe() -> PathBuf {
    std::env::var_os("ZKMINER_LOCALNET_ZKMINER").map_or_else(
        || PathBuf::from(env!("CARGO_BIN_EXE_zkminer")),
        PathBuf::from,
    )
}

fn env_flag(name: &str) -> bool {
    matches!(std::env::var(name).as_deref(), Ok("1") | Ok("true"))
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .and_then(|l| l.local_addr())
        .expect("no free local port")
        .port()
}

/// Send `signal` to `child`.
fn signal(child: &Child, signal: libc::c_int) {
    // SAFETY: kill(2) on the pid of a child this process has not yet reaped.
    unsafe {
        libc::kill(child.id() as libc::pid_t, signal);
    }
}

/// Have `cmd`'s process killed if this one dies first (a test killed mid-run must not leave anvil
/// or a miner behind).
fn die_with_parent(cmd: &mut Command) {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::process::CommandExt;
        // SAFETY: prctl is async-signal-safe and touches nothing but the new process.
        unsafe {
            cmd.pre_exec(|| {
                libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM);
                Ok(())
            });
        }
    }
    #[cfg(not(target_os = "linux"))]
    let _ = cmd;
}

/// A directory for one run, under cargo's per-target scratch directory: the miner's HOME, its
/// config and every log.
struct RunDir(PathBuf);

impl RunDir {
    fn new(name: &str) -> Self {
        let root = std::env::var_os("ZKMINER_LOCALNET_TMPDIR")
            .map_or_else(|| PathBuf::from(env!("CARGO_TARGET_TMPDIR")), PathBuf::from);
        let dir = root.join(format!("zkminer-localnet-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join(".zkminer")).expect("create the run directory");
        Self(dir)
    }

    /// Remove the directory after a pass, unless asked to keep it.
    fn finish(self) {
        if env_flag("ZKMINER_LOCALNET_KEEP") {
            eprintln!("localnet: run directory kept at {}", self.0.display());
        } else {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}

/// anvil forking 743111; stopped on drop.
struct Anvil {
    child: Child,
    url: String,
}

impl Drop for Anvil {
    fn drop(&mut self) {
        // SIGINT first: anvil writes its fork cache when it shuts down cleanly.
        signal(&self.child, libc::SIGINT);
        let deadline = Instant::now() + Duration::from_secs(15);
        while Instant::now() < deadline {
            if self.child.try_wait().ok().flatten().is_some() {
                return;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn start_anvil(dir: &Path) -> Anvil {
    let port = free_port();
    let fork_url =
        std::env::var("ZKMINER_LOCALNET_FORK_URL").unwrap_or_else(|_| DEFAULT_FORK_URL.into());
    let fork_block = match std::env::var("ZKMINER_LOCALNET_FORK_BLOCK").as_deref() {
        Ok("latest") => None,
        Ok(b) => Some(
            b.parse::<u64>()
                .expect("ZKMINER_LOCALNET_FORK_BLOCK is a block number"),
        ),
        Err(_) => Some(FORK_BLOCK),
    };
    let log = std::fs::File::create(dir.join("anvil.log")).expect("create anvil.log");
    let mut cmd = Command::new(std::env::var("ANVIL").unwrap_or_else(|_| "anvil".into()));
    cmd.args(["--fork-url", &fork_url])
        .args(["--chain-id", &DEPLOYMENT.chain_id.to_string()])
        // Known, so anvil need not ask the upstream RPC for it before it can start (it failed to,
        // on a flaky RPC, and exited).
        .args(["--fork-chain-id", &DEPLOYMENT.chain_id.to_string()])
        .args(["--host", "127.0.0.1", "--port", &port.to_string()])
        .args(["--block-time", "1"])
        // Every setup transaction is sent from an address anvil signs for.
        .arg("--auto-impersonate")
        // Generous, so a burst of fork reads rides out the upstream RPC's rate limit (HTTP 429, 300
        // requests a window on the Hemi testnet RPC) instead of failing the transaction behind it.
        .args([
            "--retries",
            "60",
            "--fork-retry-backoff",
            "2000",
            "--timeout",
            "60000",
        ])
        .stdin(Stdio::null())
        .stdout(log.try_clone().unwrap())
        .stderr(log);
    if let Some(b) = fork_block {
        cmd.args(["--fork-block-number", &b.to_string()]);
    }
    die_with_parent(&mut cmd);
    let child = cmd
        .spawn()
        .expect("start anvil: install Foundry, or set ANVIL to its path");
    Anvil {
        child,
        url: format!("http://127.0.0.1:{port}"),
    }
}

/// Serve `body` to every GET on a local port; counts the requests.
fn serve_file(body: Vec<u8>) -> (String, Arc<AtomicUsize>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind the ELF server");
    let url = format!("http://{}/program.bin", listener.local_addr().unwrap());
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = hits.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            counter.fetch_add(1, Ordering::SeqCst);
            // Read the request head (bounded) before answering.
            let mut head = Vec::new();
            let mut byte = [0u8; 1];
            while head.len() < 16 * 1024 && !head.ends_with(b"\r\n\r\n") {
                match stream.read(&mut byte) {
                    Ok(1) => head.push(byte[0]),
                    _ => break,
                }
            }
            let _ = write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(&body);
        }
    });
    (url, hits)
}

/// The risc0 worker the miner measures (and in the mining test, proves) with.
fn risc0_worker() -> PathBuf {
    let path = std::env::var("ZKMINER_LOCALNET_RISC0_WORKER")
        .map(PathBuf::from)
        .unwrap_or_else(|_| workspace_root().join("target/release/zkminer-prove-risc0-cuda"));
    assert!(
        path.is_file(),
        "no risc0 worker at {}: build it (cargo build --release -p zkminer-prove-risc0 --features \
         cuda --bin zkminer-prove-risc0-cuda) or set ZKMINER_LOCALNET_RISC0_WORKER",
        path.display()
    );
    path
}

/// The mock worker, which replays the receipt fixture (crates/zkminer-prover/src/bin/mock_worker.rs).
fn mock_worker() -> PathBuf {
    let path = std::env::var("ZKMINER_LOCALNET_MOCK_WORKER")
        .map(PathBuf::from)
        .unwrap_or_else(|_| workspace_root().join("target/debug/mock-worker"));
    assert!(
        path.is_file(),
        "no mock worker at {}: build it (cargo build -p zkminer-prover --features testing --bin \
         mock-worker) or set ZKMINER_LOCALNET_MOCK_WORKER",
        path.display()
    );
    path
}

/// The fibonacci guest and its image id (the jobs' `programId`), from the worker that runs it.
fn export_guest(worker: &Path, dir: &Path) -> (Vec<u8>, B256) {
    std::fs::create_dir_all(dir).expect("create the export directory");
    let path = dir.join("fibonacci.bin");
    let out = Command::new(worker)
        .args(["--export-guest", "fibonacci"])
        .arg(&path)
        .output()
        .expect("run the risc0 worker");
    assert!(
        out.status.success(),
        "--export-guest failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let id: B256 = String::from_utf8_lossy(&out.stdout)
        .trim()
        .parse()
        .expect("--export-guest prints the image id");
    (std::fs::read(&path).expect("read the exported guest"), id)
}

/// How long a setup transaction may take to be sent and mined.
const SETUP_TX_TIMEOUT: Duration = Duration::from_secs(120);

/// Send, wait for the mined receipt, and require success.
macro_rules! mined {
    ($call:expr, $what:expr) => {{
        let what = $what;
        let receipt = tokio::time::timeout(SETUP_TX_TIMEOUT, async {
            // A refused SEND is retried: anvil simulates before it accepts a transaction, and that
            // simulation reads storage it has not cached from the fork's upstream RPC, which can
            // fail (429, a Cloudflare 520). Nothing was sent then. A missing receipt is not retried.
            let mut tries = 0;
            let pending = loop {
                match $call.send().await {
                    Ok(pending) => break pending,
                    Err(e) => {
                        tries += 1;
                        if tries >= SUBMIT_TRIES {
                            panic!("{what} ({tries} tries): {e}");
                        }
                        eprintln!("localnet: {what} was refused, trying again in 10 s: {e}");
                        tokio::time::sleep(Duration::from_secs(10)).await;
                    }
                }
            };
            pending
                .get_receipt()
                .await
                .unwrap_or_else(|e| panic!("{what}: no receipt: {e}"))
        })
        .await
        .unwrap_or_else(|_| panic!("{what}: not mined within {SETUP_TX_TIMEOUT:?}"));
        assert!(
            receipt.status(),
            "{what} reverted ({})",
            receipt.transaction_hash
        );
        receipt
    }};
}

/// A job submitted for one case.
struct Job {
    case: Case,
    /// Which of the world's programs (0: `World::program`, then `World::extra`).
    program: usize,
    id: B256,
    /// The block its submit was mined in.
    block: u64,
}

/// A router event of one job, where it was mined.
struct Logged<E> {
    block: u64,
    tx: B256,
    event: E,
}

/// The fork, set up: a staked prover, the programs registered and served, the jobs.
struct World {
    _anvil: Anvil,
    rpc_url: String,
    provider: DynProvider,
    prover: PrivateKeySigner,
    submitter: Address,
    program: Program,
    /// More programs, each submitted with every case as `program` is (`World::with_programs`).
    extra: Vec<Program>,
    /// How many jobs of each case each program gets: `program`'s first, then each of `extra`'s.
    copies: Vec<usize>,
    /// The cases this run submits.
    cases: Vec<Case>,
    /// The jobs submitted so far.
    jobs: Vec<Job>,
    /// The first block after setup started: every log query of the harness's starts here (the
    /// miner's backfill starts later, at [`World::scan_from_block`]).
    from_block: u64,
    /// Requests the ELF server answered.
    elf_hits: Arc<AtomicUsize>,
}

impl World {
    async fn new(dir: &Path, program: Program, cases: &[Case], clock: Clock) -> Self {
        Self::with_programs(dir, vec![program], cases, clock, vec![1]).await
    }

    /// The program of a job.
    fn program_of(&self, job: &Job) -> &Program {
        match job.program {
            0 => &self.program,
            i => &self.extra[i - 1],
        }
    }

    /// A world whose programs get `copies[i]` jobs of each case, program `i` in order (the last
    /// count repeats for any program past the end).
    async fn with_programs(
        dir: &Path,
        programs: Vec<Program>,
        cases: &[Case],
        clock: Clock,
        copies: Vec<usize>,
    ) -> Self {
        let mut programs = programs.into_iter();
        let program = programs.next().expect("a world has a program");
        let extra: Vec<Program> = programs.collect();
        let mut anvil = start_anvil(dir);
        let provider = ProviderBuilder::new()
            .connect_http(anvil.url.parse().unwrap())
            .erased();
        // The first call waits for the fork to load.
        let started = Instant::now();
        loop {
            match provider.get_chain_id().await {
                Ok(id) => {
                    assert_eq!(id, DEPLOYMENT.chain_id);
                    break;
                }
                Err(e) => {
                    if let Some(status) = anvil.child.try_wait().ok().flatten() {
                        panic!(
                            "anvil exited ({status}) before serving; see {}/anvil.log",
                            dir.display()
                        );
                    }
                    if started.elapsed() > Duration::from_secs(180) {
                        panic!(
                            "anvil did not come up ({e}); see {}/anvil.log",
                            dir.display()
                        );
                    }
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
            }
        }
        assert!(
            !provider
                .get_code_at(DEPLOYMENT.router)
                .await
                .expect("read the router's code")
                .is_empty(),
            "the fork has no router at {}: the fork block predates the deployment pinned in \
             zkminer-chain/src/deployment.rs (move FORK_BLOCK)",
            DEPLOYMENT.router
        );
        // anvil carries on from the fork block's timestamp, hours behind the wall clock for a pinned
        // block. The miner judges deadlines by the wall clock as well as the chain (a lock whose
        // deadline looks past is released), so put the fork's clock on the wall clock (or behind
        // it by the lag asked for).
        let lag = match clock {
            Clock::Wall => 0,
            Clock::Lagging(secs) => secs,
        };
        let _: serde_json::Value = provider
            .raw_request("evm_setTime".into(), (unix_now() - lag,))
            .await
            .expect("evm_setTime");
        let from_block = provider.get_block_number().await.unwrap() + 1;

        let (elf_url, elf_hits) = serve_file(program.elf.clone());
        let extra_urls: Vec<String> = extra.iter().map(|p| serve_file(p.elf.clone()).0).collect();
        let n_programs = 1 + extra.len();
        let last = *copies.last().expect("a job count per program");
        let copies: Vec<usize> = (0..n_programs)
            .map(|i| copies.get(i).copied().unwrap_or(last))
            .collect();

        let submitter = Address::from_word(keccak256(b"zkminer localnet submitter"));
        let prover = PrivateKeySigner::random();
        // tHEMI is minted by its owner, which anvil impersonates.
        let token_owner = owner_of(&provider, DEPLOYMENT.token).await;
        for a in [token_owner, submitter, prover.address()] {
            set_balance(&provider, a, 100 * HEMI).await;
        }

        // The submitter pays the registry's fee (as set on the fork) for each program it registers,
        // and each job's deposit.
        let registrations = n_programs
            + cases
                .iter()
                .filter(|c| matches!(c, Case::DecoyElf | Case::ElfUnreachable))
                .count();
        let registration_fees = IProgramRegistryFee::new(DEPLOYMENT.program_registry, &provider)
            .registrationFee()
            .call()
            .await
            .expect("read the registry's registrationFee()")
            * U256::from(registrations);
        let deposits = U256::from(
            cases.iter().map(|c| c.deposit()).sum::<u128>() * copies.iter().sum::<usize>() as u128,
        );

        let token = ITestnetToken::new(DEPLOYMENT.token, &provider);
        let erc20 = IERC20::new(DEPLOYMENT.token, &provider);
        mined!(
            token
                .mint(submitter, registration_fees + deposits)
                .from(token_owner),
            "mint tHEMI to the submitter"
        );
        mined!(
            token
                .mint(prover.address(), U256::from(prover_stake()))
                .from(token_owner),
            "mint tHEMI to the prover"
        );

        mined!(
            erc20
                .approve(DEPLOYMENT.staking, U256::from(prover_stake()))
                .from(prover.address()),
            "approve the stake"
        );
        mined!(
            IHemiProveStaking::new(DEPLOYMENT.staking, &provider)
                .stake(prover.address(), prover_stake())
                .from(prover.address()),
            "stake"
        );

        // Registration is permissionless, for the fee.
        mined!(
            erc20
                .approve(DEPLOYMENT.program_registry, registration_fees)
                .from(submitter),
            "approve the registration fees"
        );
        let elf_hash = keccak256(&program.elf);
        for (p, url) in std::iter::once((&program, &elf_url)).chain(extra.iter().zip(&extra_urls)) {
            let hash = keccak256(&p.elf);
            register_program(
                &provider,
                submitter,
                p.id,
                p.proof_system,
                p.name,
                url,
                hash,
            )
            .await;
            if is_sp1_id(p.proof_system) {
                // The registry takes an SP1 program's ELF hash in a call of its own, and the miner
                // claims no SP1 job without it.
                set_build_info(&provider, submitter, p.id, hash, p.name).await;
            }
        }
        if cases.contains(&Case::DecoyElf) {
            // Another programId whose URI serves this run's ELF.
            let id = Case::DecoyElf.program_id(&program);
            register_program(
                &provider,
                submitter,
                id,
                program.proof_system,
                "decoy (zkminer localnet)",
                &elf_url,
                elf_hash,
            )
            .await;
        }
        if cases.contains(&Case::ElfUnreachable) {
            let id = Case::ElfUnreachable.program_id(&program);
            let url = format!("http://127.0.0.1:{}/unreachable.bin", free_port());
            register_program(
                &provider,
                submitter,
                id,
                program.proof_system,
                "unreachable (zkminer localnet)",
                &url,
                B256::ZERO,
            )
            .await;
        }

        mined!(
            erc20.approve(DEPLOYMENT.router, deposits).from(submitter),
            "approve the job deposits"
        );
        let mut world = World {
            rpc_url: anvil.url.clone(),
            _anvil: anvil,
            provider,
            prover,
            submitter,
            program,
            extra,
            copies,
            cases: cases.to_vec(),
            jobs: Vec::new(),
            from_block,
            elf_hits,
        };
        // Case::Full first: the miner's backfill starts at its block ([`World::scan_from_block`]), so
        // every other job submitted before the miner starts must land in a later one. Each submit
        // waits for its receipt, so the next is mined in a later block.
        let mut before: Vec<Case> = cases.iter().copied().filter(|c| c.before_start()).collect();
        before.sort_by_key(|&c| c != Case::Full);
        // The first program's first Full job first (see above), then the rest in order.
        for program in 0..n_programs {
            for copy in 0..world.copies[program] {
                for &case in &before {
                    world.submit_job(case, program, copy).await;
                }
            }
        }
        if let Some(full) = world.jobs.iter().find(|j| j.case == Case::Full) {
            for job in world.jobs.iter().filter(|j| j.case != Case::Full) {
                assert!(
                    job.block > full.block,
                    "the {:?} job was mined in block {}, not after the Full job's block {}",
                    job.case,
                    job.block,
                    full.block
                );
            }
        }
        let skew = world.clock_skew().await;
        assert!(
            (skew + lag as i64).abs() < 30,
            "the fork's clock is {skew} s off the wall clock, not -{lag} s, after evm_setTime"
        );
        world
    }

    /// `contract`'s `owner()`, funded for gas (anvil impersonates it). On a fork the lookup and the
    /// funding can each wait on the upstream RPC, so a test whose owner transaction must land at
    /// once resolves the owner before the miner starts.
    async fn funded_owner(&self, contract: Address) -> Address {
        funded_owner(&self.provider, contract).await
    }

    /// Send `data` to `contract` from `from` (anvil impersonates it) and require success. Returns
    /// the block it was mined in.
    async fn send_as(&self, from: Address, contract: Address, data: Vec<u8>, what: &str) -> u64 {
        let receipt = tokio::time::timeout(SETUP_TX_TIMEOUT, async {
            self.provider
                .send_transaction(
                    TransactionRequest::default()
                        .from(from)
                        .to(contract)
                        .input(Bytes::from(data).into()),
                )
                .await
                .unwrap_or_else(|e| panic!("{what}: {e}"))
                .get_receipt()
                .await
                .unwrap_or_else(|e| panic!("{what}: no receipt: {e}"))
        })
        .await
        .unwrap_or_else(|_| panic!("{what}: not mined within {SETUP_TX_TIMEOUT:?}"));
        assert!(receipt.status(), "{what} reverted");
        receipt
            .block_number
            .unwrap_or_else(|| panic!("{what}: a receipt without a block"))
    }

    /// Call `contract` as its `owner()`.
    async fn call_as_owner(&self, contract: Address, data: Vec<u8>, what: &str) {
        let owner = self.funded_owner(contract).await;
        self.send_as(owner, contract, data, what).await;
    }

    /// Pause or unpause the router as `owner`, its owner from [`World::funded_owner`]. Returns the
    /// block the transaction was mined in.
    async fn set_router_paused(&self, owner: Address, paused: bool) -> u64 {
        let selector = if paused { "pause()" } else { "unpause()" };
        self.send_as(
            owner,
            DEPLOYMENT.router,
            keccak256(selector).0[..4].to_vec(),
            &format!("router {selector}"),
        )
        .await
    }

    async fn disable_risc0_adapter(&self) {
        let mut data = keccak256("disableAdapter(bytes32)").0[..4].to_vec();
        data.extend_from_slice(risc_zero_groth16_v1_id().as_slice());
        self.call_as_owner(
            DEPLOYMENT.registry,
            data,
            "disableAdapter(risczero.groth16.v1)",
        )
        .await;
    }

    /// The latest block's timestamp minus the wall clock, in seconds.
    async fn clock_skew(&self) -> i64 {
        let block = self
            .provider
            .get_block_by_number(alloy::eips::BlockNumberOrTag::Latest)
            .await
            .unwrap()
            .expect("the latest block");
        block.header.timestamp as i64 - unix_now() as i64
    }

    /// A job's status and prover on the fork.
    async fn job_state(&self, id: B256) -> (u8, Address) {
        let v = IHemiProveAux::new(DEPLOYMENT.router, &self.provider)
            .getJobStatusView(id)
            .call()
            .await
            .expect("getJobStatusView");
        (v.status, v.prover)
    }

    /// Each job's status and prover on the fork, and the prover's stake, for a failure report.
    async fn describe_state(&self) -> Vec<String> {
        let mut out = Vec::new();
        for job in &self.jobs {
            let (status, prover) = self.job_state(job.id).await;
            out.push(format!(
                "{:?} {}: status {status} prover {prover}",
                job.case,
                short_id(job.id)
            ));
        }
        let st = self.stake().await;
        out.push(format!(
            "prover stake: {} HEMI total, {} HEMI locked",
            hemi(st.totalStaked),
            hemi(st.lockedCollateral)
        ));
        out.push(format!("fork clock skew: {} s", self.clock_skew().await));
        out
    }

    async fn stake(&self) -> zkminer_contracts::bindings::ProverStake {
        IHemiProveStaking::new(DEPLOYMENT.staking, &self.provider)
            .getProverStake(self.prover.address())
            .call()
            .await
            .expect("read the prover's stake")
    }

    async fn submit(&mut self, case: Case) {
        self.submit_job(case, 0, 0).await;
    }

    /// Submit a job of `case` for the world's `program`-th program, the `copy`-th of its kind.
    /// A failure is retried a few times first: the fork reads storage it has not cached from the
    /// upstream RPC, which can refuse (429) or drop a request mid-setup.
    async fn submit_job(&mut self, case: Case, program: usize, copy: usize) {
        let mut tries = 0;
        while let Err(e) = self.try_submit_job(case, program, copy).await {
            tries += 1;
            if tries >= SUBMIT_TRIES {
                panic!("submit the {case:?} job ({tries} tries): {e}");
            }
            eprintln!("localnet: submitting the {case:?} job failed, trying again in 20 s: {e}");
            tokio::time::sleep(Duration::from_secs(20)).await;
        }
    }

    /// As `submit_job`, returning a failure instead of panicking on it, for a caller that can wait
    /// and try again: the fork's upstream RPC rate-limits anvil (HTTP 429) under a burst of submits,
    /// each of which reads storage slots anvil has not fetched yet.
    async fn try_submit_job(
        &mut self,
        case: Case,
        program: usize,
        copy: usize,
    ) -> Result<(), String> {
        let core = IHemiProveCore::new(DEPLOYMENT.router, &self.provider);
        let p = match program {
            0 => &self.program,
            i => &self.extra[i - 1],
        };
        let pending = core
            .submitJob(
                descriptor(case, p, self.prover.address(), copy),
                case.auction(),
                no_cycles(),
                no_bidding(),
            )
            .from(self.submitter)
            .send()
            .await
            .map_err(|e| e.to_string())?;
        let receipt = tokio::time::timeout(SETUP_TX_TIMEOUT, pending.get_receipt())
            .await
            .map_err(|_| format!("not mined within {SETUP_TX_TIMEOUT:?}"))?
            .map_err(|e| format!("no receipt: {e}"))?;
        if !receipt.status() {
            return Err(format!("reverted ({})", receipt.transaction_hash));
        }
        let id = receipt
            .inner
            .logs()
            .iter()
            .find_map(|l| l.log_decode::<IHemiProveCore::JobSubmitted>().ok())
            .map(|l| l.inner.data.jobId)
            .expect("JobSubmitted in the submit receipt");
        let block = receipt
            .block_number
            .expect("the submit receipt has a block");
        self.jobs.push(Job {
            case,
            program,
            id,
            block,
        });
        Ok(())
    }

    /// Mint the submitter `amount` more tHEMI for job deposits, and let the router take any amount.
    async fn fund_deposits(&self, amount: U256) {
        let owner = owner_of(&self.provider, DEPLOYMENT.token).await;
        mined!(
            ITestnetToken::new(DEPLOYMENT.token, &self.provider)
                .mint(self.submitter, amount)
                .from(owner),
            "mint tHEMI for more job deposits"
        );
        mined!(
            IERC20::new(DEPLOYMENT.token, &self.provider)
                .approve(DEPLOYMENT.router, U256::MAX)
                .from(self.submitter),
            "approve the router for any deposit"
        );
    }

    /// Where the miner's backfill starts: the block of the Case::Full job's submit, the first job
    /// submitted (see [`World::new`]). A backfill that started a block late would lose that job.
    fn scan_from_block(&self) -> u64 {
        self.jobs
            .iter()
            .find(|j| j.case == Case::Full)
            .map(|j| j.block)
            .expect("every run submits a Case::Full job before the miner starts")
    }

    /// Submit the jobs held back for the live monitor, once the miner's monitor runs.
    async fn submit_after_start(&mut self, miner: &mut Miner) {
        if !wait_for_line(miner, "Job monitor started", Duration::from_secs(120)).await {
            miner.fail("the miner's job monitor did not start within 120 s");
        }
        self.submit_held_back().await;
    }

    /// Submit the jobs held back from setup (the cases not `before_start`), every copy of each.
    async fn submit_held_back(&mut self) {
        let after: Vec<Case> = self
            .cases
            .iter()
            .copied()
            .filter(|c| !c.before_start())
            .collect();
        for program in 0..=self.extra.len() {
            for copy in 0..self.copies[program] {
                for &case in &after {
                    self.submit_job(case, program, copy).await;
                }
            }
        }
    }

    async fn prover_nonce(&self) -> u64 {
        self.provider
            .get_transaction_count(self.prover.address())
            .await
            .unwrap()
    }

    /// The router's `E` logs since setup began: each with its job (topic 1), block and transaction.
    async fn logs<E: SolEvent>(&self) -> Vec<(B256, Logged<E>)> {
        let filter = Filter::new()
            .address(DEPLOYMENT.router)
            .event_signature(E::SIGNATURE_HASH)
            .from_block(self.from_block);
        self.provider
            .get_logs(&filter)
            .await
            .unwrap()
            .into_iter()
            .filter_map(|l| {
                let job = *l.topics().get(1)?;
                let block = l.block_number?;
                let tx = l.transaction_hash?;
                let event = l.log_decode::<E>().ok()?.inner.data;
                Some((job, Logged { block, tx, event }))
            })
            .collect()
    }

    /// The jobs with an `E` log since setup began.
    async fn jobs_with<E: SolEvent>(&self) -> Vec<B256> {
        self.logs::<E>().await.into_iter().map(|(j, _)| j).collect()
    }

    /// The miner's config: the fork, the 743111 contracts, and fast polling.
    fn write_config(&self, dir: &Path, worker: &Path, discover_worker: bool) -> PathBuf {
        let mut c = ZkMinerConfig::default();
        c.chain.rpc_url = self.rpc_url.clone();
        c.chain.chain_id = DEPLOYMENT.chain_id;
        c.chain.scan_from_block = Some(self.scan_from_block());
        c.chain.monitor_poll_secs = Some(2);
        // A local node has no rate limit to stay under.
        c.chain.max_requests_per_sec = Some(50);
        c.contracts.hemi_prove = DEPLOYMENT.router.to_string();
        c.contracts.hemi_prove_staking = DEPLOYMENT.staking.to_string();
        c.contracts.hemi_prove_registry = DEPLOYMENT.registry.to_string();
        c.contracts.hemi_token = DEPLOYMENT.token.to_string();
        c.contracts.program_registry = DEPLOYMENT.program_registry.to_string();
        // A 5 HEMI job is the whole market here: claim anything that pays.
        c.prover.min_profit_threshold = 0.0;
        c.prover.skip_benchmark_gate = true;
        if discover_worker {
            // One worker per GPU, from a directory holding only the risc0 worker.
            let provers = dir.join("provers");
            std::fs::create_dir_all(&provers).unwrap();
            let link = provers.join(worker.file_name().unwrap());
            let _ = std::fs::remove_file(&link);
            std::os::unix::fs::symlink(worker, &link).unwrap();
            c.prover.worker_search_paths = vec![provers.display().to_string()];
        } else {
            // Named outright, so a host without a GPU still gets the risc0 measure pool, and the
            // dispatcher pins no CUDA_VISIBLE_DEVICES on it: the environment's setting holds.
            c.prover
                .worker_binaries
                .insert("risc0".into(), worker.display().to_string());
        }
        let path = dir.join(".zkminer/config.toml");
        c.save(Some(&path)).expect("write the miner config");
        path
    }

    /// The miner's config with every worker in `workers` discovered (one per card each), and risc0
    /// job sizes for the cards in `risc0_po2` (device id, po2): a card under 14 GiB proves risc0 jobs
    /// only with a size, from calibration or the config.
    fn write_config_for(
        &self,
        dir: &Path,
        workers: &[PathBuf],
        risc0_po2: &[(String, u8)],
    ) -> PathBuf {
        let path = self.write_config(dir, &workers[0], true);
        let mut c = ZkMinerConfig::load(Some(&path)).expect("read the miner config back");
        let provers = dir.join("provers");
        for worker in &workers[1..] {
            let link = provers.join(worker.file_name().unwrap());
            let _ = std::fs::remove_file(&link);
            std::os::unix::fs::symlink(worker, &link).unwrap();
        }
        for (device, po2) in risc0_po2 {
            c.prover.risc0_job_po2.insert(device.clone(), *po2);
        }
        c.save(Some(&path)).expect("write the miner config");
        path
    }
}

async fn set_balance(provider: &DynProvider, a: Address, wei: u128) {
    let _: serde_json::Value = provider
        .raw_request("anvil_setBalance".into(), (a, U256::from(wei)))
        .await
        .expect("anvil_setBalance");
}

/// A contract's `owner()`.
async fn owner_of(provider: &DynProvider, contract: Address) -> Address {
    let word = provider
        .call(
            TransactionRequest::default()
                .to(contract)
                .input(Bytes::from(keccak256("owner()").0[..4].to_vec()).into()),
        )
        .await
        .unwrap_or_else(|e| panic!("owner() of {contract}: {e}"));
    assert_eq!(word.len(), 32, "owner() of {contract} returned {word}");
    Address::from_word(B256::from_slice(&word))
}

/// A contract's `owner()`, funded for gas: anvil impersonates it.
async fn funded_owner(provider: &DynProvider, contract: Address) -> Address {
    let owner = owner_of(provider, contract).await;
    set_balance(provider, owner, HEMI).await;
    owner
}

alloy::sol! {
    /// The ProgramRegistry's governance calls (`onlyOwner`), which zkminer's bindings leave out
    /// (zkmarket c8333aa, `src/core/ProgramRegistry.sol`).
    #[sol(rpc)]
    interface IProgramRegistryGovernance {
        function revokeProgram(bytes32 programId, string calldata reason) external;
        function clearRevokedProgram(bytes32 programId) external;
    }

    /// The ProgramRegistry's fee for a registration, in tHEMI wei, which zkminer's bindings leave
    /// out (same source; at most `MAX_REGISTRATION_FEE`, 100 HEMI).
    #[sol(rpc)]
    interface IProgramRegistryFee {
        function registrationFee() external view returns (uint256);
    }
}

/// `ProgramStatus.Revoked`: a `ProgramVersion`'s `status` once governance revokes it.
const PROGRAM_REVOKED: u8 = 2;

/// Register `id` in the ProgramRegistry (permissionless) with one HTTP storage URI.
///
/// The ids are content-derived (an image id, a fixed hash), so anyone may already have registered
/// one on 743111, with storage URIs this test does not serve. Such a registration is first revoked
/// (unless it already is) and cleared, as the registry's owner: `clearRevokedProgram` deletes the
/// record, its URIs, its build hashes and any pending registrant, so the id registers afresh.
async fn register_program(
    provider: &DynProvider,
    from: Address,
    id: B256,
    proof_system: B256,
    name: &str,
    url: &str,
    content_hash: B256,
) {
    let registry = IProgramRegistry::new(DEPLOYMENT.program_registry, provider);
    if registry
        .isRegistered(id)
        .call()
        .await
        .expect("isRegistered")
    {
        let earlier = registry.getProgram(id).call().await.expect("getProgram");
        eprintln!(
            "localnet: program {id} ({name}) is already registered at the fork block (by {}, \
             status {}): clearing it as the registry's owner",
            earlier.registrant, earlier.status
        );
        let owner = funded_owner(provider, DEPLOYMENT.program_registry).await;
        let governance = IProgramRegistryGovernance::new(DEPLOYMENT.program_registry, provider);
        if earlier.status != PROGRAM_REVOKED {
            mined!(
                governance
                    .revokeProgram(id, "zkminer localnet: re-registered on a local fork".into())
                    .from(owner),
                format!("revoke the earlier registration of {name}")
            );
        }
        mined!(
            governance.clearRevokedProgram(id).from(owner),
            format!("clear the earlier registration of {name}")
        );
    }
    mined!(
        registry
            .registerProgram(
                id,
                proof_system,
                B256::ZERO,
                ResourceEstimate {
                    estimatedCycles: 0,
                    peakMemoryBytes: 0,
                    estimatedWallTimeS: 0,
                },
                name.into(),
                String::new(),
                String::new(),
                vec![StorageURI {
                    storageType: 2, // HTTP
                    uri: url.into(),
                    contentHash: content_hash,
                }],
            )
            .from(from),
        format!("register {name}")
    );
}

alloy::sol! {
    #[sol(rpc)]
    interface IProgramBuildInfo {
        function setBuildInfo(
            bytes32 programId,
            bytes32 sourceCodeHash,
            bytes32 elfHash,
            string sourceUri,
            string buildCommand,
            string toolchainVersion,
            string rustToolchain,
            string containerImage
        ) external;
    }
}

/// Record a program's ELF hash (`ProgramRegistry.setBuildInfo`, as its registrant).
async fn set_build_info(
    provider: &DynProvider,
    from: Address,
    id: B256,
    elf_hash: B256,
    name: &str,
) {
    mined!(
        IProgramBuildInfo::new(DEPLOYMENT.program_registry, provider)
            .setBuildInfo(
                id,
                B256::ZERO,
                elf_hash,
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
            )
            .from(from),
        format!("set the build info of {name}")
    );
}

fn descriptor(case: Case, program: &Program, prover: Address, copy: usize) -> JobDescriptor {
    let psid = program.proof_system;
    let (program_id, journal) = (case.program_id(program), &program.journal);
    let slot0 = |word: u32| {
        let mut f = B256::ZERO;
        f.0[..4].copy_from_slice(&word.to_be_bytes());
        f
    };
    // One FIELDS range: offset 0, length 8.
    let first_8 = slot0(8);
    let (assigned, expected, fields) = match case {
        // HighCollateral differs only in its auction (`Case::auction`).
        Case::Full | Case::HighCollateral => (
            Address::ZERO,
            full_hash(psid, program_id, journal),
            B256::ZERO,
        ),
        Case::Fields => (Address::ZERO, fields_hash(journal, first_8), first_8),
        Case::FullWrongJournal => (
            Address::ZERO,
            full_hash(psid, program_id, &program.wrong_journal()),
            B256::ZERO,
        ),
        Case::FieldsWrongJournal => (
            Address::ZERO,
            fields_hash(&program.wrong_journal(), first_8),
            first_8,
        ),
        Case::NoneForUs => (prover, B256::ZERO, B256::ZERO),
        Case::NoneForAnother => (ANOTHER_PROVER, B256::ZERO, B256::ZERO),
        // The FULL hash covers (domain, psId, programId, journal), not the assignment: bound as
        // Case::Full is, with only the descriptor (and its hash) different. Their auctions differ
        // too (`Case::auction`).
        Case::FullForAnother | Case::FullExclusiveForAnother => (
            ANOTHER_PROVER,
            full_hash(psid, program_id, journal),
            B256::ZERO,
        ),
        Case::PrefixMarker => (
            Address::ZERO,
            full_hash(psid, program_id, journal),
            slot0(0xffff_ffff),
        ),
        // Bound as the program would commit: only the ELF stops them.
        Case::DecoyElf | Case::ElfUnreachable => (
            Address::ZERO,
            full_hash(psid, program_id, journal),
            B256::ZERO,
        ),
    };
    JobDescriptor {
        programId: program_id,
        proofSystemId: psid,
        callbackContract: Address::ZERO,
        assignedProver: assigned,
        tag: keccak256(format!("zkminer localnet {case:?} {} {copy}", program.name)),
        inputData: program.input.clone().into(),
        callbackExtraData: Bytes::new(),
        extraVerifierData: Bytes::new(),
        expectedJournalHash: expected,
        journalFields: fields,
    }
}

/// A fixed-price auction at `price`: no ramp, no premium, no exclusivity window, and the default
/// collateral rate.
fn fixed_price(price: u128) -> AuctionConfig {
    AuctionConfig {
        minPrice: U96::from(price),
        maxPrice: U96::from(price),
        rampUpPeriod: U40::ZERO,
        curveType: 0,
        fulfillmentTimeout: U40::from(3_600u64),
        lockCollateralBps: U96::ZERO,
        speedPremium: U96::ZERO,
        exclusivityDuration: U40::ZERO,
        callbackGasLimit: 0,
        excludeFromEwma: false,
        laxCallbackMode: false,
    }
}

fn no_cycles() -> CycleConfig {
    CycleConfig {
        expectedCycles: 0,
        cycleCommitCollateral: U96::ZERO,
        snapshotMode: 0,
        snapshotToleranceBps: 0,
        snapshotFullBonusOvershootBps: 0,
        snapshotUndershootPenaltyBps: 0,
        snapshotFullPenaltyUndershootBps: 0,
        snapshotResolverRewardBps: 0,
    }
}

fn no_bidding() -> CompetitiveBidConfig {
    CompetitiveBidConfig {
        underbidWindow: U40::ZERO,
        maxBiddingDuration: U40::ZERO,
        maxBidExtension: U40::ZERO,
        minBidDecrement: U96::ZERO,
        bidExtensionCurveType: 0,
    }
}

/// `PATH` without the directories that hold a zkminer worker, so a miner finds only the workers
/// its config names (and none of an installed release's).
fn path_without_workers() -> String {
    const SYSTEM: [&str; 4] = ["/usr/bin", "/bin", "/usr/sbin", "/sbin"];
    let path = std::env::var("PATH").unwrap_or_default();
    std::env::split_paths(&path)
        .filter(|dir| {
            let has_workers = std::fs::read_dir(dir).is_ok_and(|entries| {
                entries.flatten().any(|e| {
                    e.file_name()
                        .to_string_lossy()
                        .starts_with("zkminer-prove-")
                })
            });
            // A system directory stays (the miner needs nvidia-smi, systemd-run, busctl): a worker
            // installed there can still be found, so say so.
            if has_workers && SYSTEM.iter().any(|s| dir == Path::new(s)) {
                eprintln!(
                    "localnet: {} holds zkminer workers; the miner may start them",
                    dir.display()
                );
                return true;
            }
            !has_workers
        })
        .map(|d| d.display().to_string())
        .collect::<Vec<_>>()
        .join(":")
}

/// A running `zkminer`, its log lines collected as they arrive; stopped on drop.
struct Miner {
    child: Child,
    lines: Arc<Mutex<Vec<String>>>,
    /// Its HOME, which holds its log.
    dir: PathBuf,
}

impl Miner {
    /// Start `zkminer` from a link in `dir` (its own directory is searched for workers, so it finds
    /// only the ones the config names), with `dir` as its HOME and a cleaned environment: none of
    /// this shell's `ZKMINER_*`, `MOCK_*`, `BONSAI_*`, `RISC0_DEV_MODE`, `RISC0_PROVER` or
    /// `RISC0_EXECUTOR` settings, only `env` (set after they are removed, so it may set one).
    fn start(
        dir: &Path,
        config: &Path,
        global: &[&str],
        args: &[&str],
        env: &[(&str, String)],
    ) -> Self {
        let mut cmd = Self::command(dir, config, global, "run", args, env);
        die_with_parent(&mut cmd);
        let mut child = cmd.spawn().expect("start zkminer");
        let lines = Arc::new(Mutex::new(Vec::new()));
        let echo = env_flag("ZKMINER_LOCALNET_ECHO");
        let log = Arc::new(Mutex::new(
            std::fs::File::create(dir.join("zkminer.log")).expect("create zkminer.log"),
        ));
        for stream in [
            Box::new(child.stdout.take().unwrap()) as Box<dyn Read + Send>,
            Box::new(child.stderr.take().unwrap()),
        ] {
            let (lines, log) = (lines.clone(), log.clone());
            std::thread::spawn(move || {
                for line in BufReader::new(stream).lines().map_while(Result::ok) {
                    let line = strip_ansi(&line);
                    if echo {
                        eprintln!("zkminer| {line}");
                    }
                    let _ = writeln!(log.lock().unwrap(), "{line}");
                    lines.lock().unwrap().push(line);
                }
            });
        }
        Miner {
            child,
            lines,
            dir: dir.to_path_buf(),
        }
    }

    /// `zkminer [global] --config <config> <sub> [args]` from a link in `dir`, as `start` describes:
    /// `dir` is its HOME, the environment is cleaned and `env` set on top, and its output is piped.
    fn command(
        dir: &Path,
        config: &Path,
        global: &[&str],
        sub: &str,
        args: &[&str],
        env: &[(&str, String)],
    ) -> Command {
        let exe = dir.join("zkminer");
        let _ = std::fs::remove_file(&exe);
        let zkminer = zkminer_exe();
        if std::fs::hard_link(&zkminer, &exe).is_err() {
            std::fs::copy(&zkminer, &exe).expect("copy the zkminer binary");
        }
        let mut cmd = Command::new(&exe);
        cmd.args(global)
            .arg("--config")
            .arg(config)
            .arg(sub)
            .args(args);
        for (k, _) in std::env::vars_os() {
            let name = k.to_string_lossy();
            // risc0's own switches would change what a real worker does (dev mode fakes every
            // proof, Bonsai proves remotely); RISC0_HOME stays, below.
            if name.starts_with("ZKMINER_")
                || name.starts_with("MOCK_")
                || name.starts_with("BONSAI_")
                || matches!(
                    name.as_ref(),
                    "RISC0_DEV_MODE" | "RISC0_PROVER" | "RISC0_EXECUTOR"
                )
            {
                cmd.env_remove(&k);
            }
        }
        // risc0 finds its Groth16 key under ~/.risc0: keep the real one when HOME moves.
        if std::env::var_os("RISC0_HOME").is_none() {
            if let Some(home) = std::env::var_os("HOME") {
                let risc0 = Path::new(&home).join(".risc0");
                if risc0.is_dir() {
                    cmd.env("RISC0_HOME", risc0);
                }
            }
        }
        cmd.env("HOME", dir)
            .env("PATH", path_without_workers())
            // The programs are served from this machine.
            .env("ZKMINER_ELF_ALLOW_PRIVATE_URLS", "1")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for (k, v) in env {
            cmd.env(k, v);
        }
        cmd
    }

    fn lines(&self) -> Vec<String> {
        self.lines.lock().unwrap().clone()
    }

    fn exit_status(&mut self) -> Option<ExitStatus> {
        self.child.try_wait().ok().flatten()
    }

    fn exited(&mut self) -> bool {
        self.exit_status().is_some()
    }

    /// SIGINT (the miner's drain), then wait up to `grace` before killing it. Returns its exit
    /// status if it exited on its own (or already had), None if it had to be killed.
    fn stop(&mut self, grace: Duration) -> Option<ExitStatus> {
        if let Some(status) = self.exit_status() {
            return Some(status);
        }
        signal(&self.child, libc::SIGINT);
        let deadline = Instant::now() + grace;
        while Instant::now() < deadline {
            if let Some(status) = self.exit_status() {
                return Some(status);
            }
            std::thread::sleep(Duration::from_millis(200));
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
        None
    }

    /// Panic with `what` for a miner that never got where a test needed it, after printing its log
    /// tail, whether (and how) it exited, and its directory.
    fn fail(&mut self, what: &str) -> ! {
        let state = match self.child.try_wait() {
            Ok(Some(status)) => {
                // Let the readers take its last lines (often the reason it exited).
                std::thread::sleep(Duration::from_millis(500));
                format!("zkminer exited ({status})")
            }
            Ok(None) => "zkminer is still running".to_string(),
            Err(e) => format!("zkminer's exit status is unreadable ({e})"),
        };
        dump_tail(&self.dir, &self.lines());
        panic!("{what}; {state} (run directory {})", self.dir.display());
    }
}

impl Drop for Miner {
    fn drop(&mut self) {
        let _ = self.stop(Duration::from_secs(20));
    }
}

/// What is wrong with how a miner stopped ([`Miner::stop`] with `grace`), if anything: it must
/// exit 0, on its own.
fn stop_failure(stopped: Option<ExitStatus>, grace: Duration) -> Option<String> {
    match stopped {
        Some(status) if status.success() => None,
        Some(status) => Some(format!("zkminer stopped with {status}, not exit 0")),
        None => Some(format!(
            "zkminer did not exit within {} s of SIGINT",
            grace.as_secs()
        )),
    }
}

fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' && chars.peek() == Some(&'[') {
            chars.next();
            for c in chars.by_ref() {
                if c.is_ascii_alphabetic() {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// The `WATCH <job>: …` verdicts logged for `id`.
fn watch_lines(lines: &[String], id: B256) -> Vec<String> {
    let tag = format!("WATCH {}: ", short_id(id));
    lines
        .iter()
        .filter_map(|l| l.find(&tag).map(|i| l[i + tag.len()..].to_string()))
        .collect()
}

/// The cycle counts a verdict reports: the digits of each match of `(\d+) cycles(,| measured)` (the
/// inspector's `N cycles, …` and the would-claim verdict's `N cycles measured`).
fn reported_cycles(verdict: &str) -> Vec<&str> {
    const UNIT: &str = " cycles";
    let mut counts = Vec::new();
    let mut from = 0;
    while let Some(at) = verdict[from..].find(UNIT).map(|i| from + i) {
        let digits = verdict[..at]
            .bytes()
            .rev()
            .take_while(u8::is_ascii_digit)
            .count();
        let after = &verdict[at + UNIT.len()..];
        if digits > 0 && (after.starts_with(',') || after.starts_with(" measured")) {
            counts.push(&verdict[at - digits..at]);
        }
        from = at + UNIT.len();
    }
    counts
}

/// Whether the brain dispatched a claim of `id` (its `CLAIM <job> (price …` line): the job got past
/// every gate the brain applies.
fn dispatched(lines: &[String], id: B256) -> bool {
    let tag = format!("CLAIM {} (", short_id(id));
    lines.iter().any(|l| l.contains(&tag))
}

/// Print the tail of the miner's log, for a failure.
fn dump_tail(dir: &Path, lines: &[String]) {
    eprintln!(
        "---- last zkminer log lines (full log: {}/zkminer.log) ----",
        dir.display()
    );
    for l in lines.iter().rev().take(80).rev() {
        eprintln!("{l}");
    }
}

/// Wait until the miner has logged `needle` `times` times; false if it exits or `timeout` passes.
async fn wait_for_lines(miner: &mut Miner, needle: &str, times: usize, timeout: Duration) -> bool {
    let started = Instant::now();
    loop {
        if miner.lines().iter().filter(|l| l.contains(needle)).count() >= times {
            return true;
        }
        if miner.exited() || started.elapsed() > timeout {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

async fn wait_for_line(miner: &mut Miner, needle: &str, timeout: Duration) -> bool {
    wait_for_lines(miner, needle, 1, timeout).await
}

/// Wait for a watch-only miner's verdicts on every job, watch for [`SETTLE`] more, then stop it
/// (it must exit 0). As the staked prover, each claimable job must also be reported WOULD CLAIM
/// (unless `ZKMINER_LOCALNET_EXPECT_CLAIMS=0`); nothing else, and nothing at all as an address with
/// no stake, may be. Returns the failures and the log.
async fn watch_and_check(
    world: &World,
    miner: &mut Miner,
    staked: bool,
) -> (Vec<String>, Vec<String>) {
    let expect_claims =
        staked && std::env::var("ZKMINER_LOCALNET_EXPECT_CLAIMS").as_deref() != Ok("0");
    let started = Instant::now();
    let mut failures = loop {
        let lines = miner.lines();
        let mut missing = Vec::new();
        let mut inconclusive = Vec::new();
        for job in &world.jobs {
            let verdicts = watch_lines(&lines, job.id);
            let want = job.case.inspector_verdict(staked);
            if !verdicts.iter().any(|v| v.contains(&want)) {
                missing.push(format!("{:?}: a verdict containing {want:?}", job.case));
            }
            if expect_claims
                && job.case.claimable()
                && !verdicts.iter().any(|v| v.starts_with("WOULD CLAIM"))
            {
                missing.push(format!("{:?}: WOULD CLAIM", job.case));
            }
            if let Some(v) = verdicts.iter().find(|v| v.starts_with("no verdict after")) {
                inconclusive.push(format!("{:?}: {v}", job.case));
            }
        }
        if !inconclusive.is_empty() {
            break inconclusive;
        }
        if missing.is_empty() {
            tokio::time::sleep(SETTLE).await;
            break Vec::new();
        }
        if started.elapsed() > WATCH_TIMEOUT || miner.exited() {
            break missing;
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    };
    if miner.exited() {
        failures.push("zkminer exited before every verdict was in".into());
    }
    failures.extend(stop_failure(miner.stop(STOP_GRACE), STOP_GRACE));
    let lines = miner.lines();
    for job in &world.jobs {
        let would_claim = watch_lines(&lines, job.id)
            .iter()
            .any(|v| v.starts_with("WOULD CLAIM"));
        if would_claim && !(staked && job.case.claimable()) {
            failures.push(format!("{:?}: reported WOULD CLAIM", job.case));
        }
        for v in watch_lines(&lines, job.id) {
            eprintln!(
                "localnet{}: {:?} {}: {v}",
                if staked { "" } else { " (unstaked)" },
                job.case,
                short_id(job.id)
            );
        }
    }
    if lines.iter().any(|l| l.contains("refusing to send")) {
        failures.push("the send guard refused a send".into());
    }
    (failures, lines)
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs anvil, the release risc0 worker and the 743111 RPC; see the module docs"]
async fn watch_only_reports_every_job() {
    let dir = RunDir::new("watch");
    let worker = risc0_worker();
    let program = Program::fibonacci(&worker, &dir.0);
    let mut world = World::new(&dir.0, program, &Case::ALL, Clock::Wall).await;
    let config = world.write_config(&dir.0, &worker, false);
    let nonce_before = world.prover_nonce().await;
    // risc0's default executor hits `unimplemented!` on an executor it does not know; the worker
    // must not use it (its measurements run locally, whatever this says), so every verdict that
    // needs a measurement shows it held.
    let env = [("RISC0_EXECUTOR", "bogus".to_string())];

    // As the staked prover.
    let mut miner = Miner::start(
        &dir.0,
        &config,
        &[],
        &[
            "--watch-only",
            "--address",
            &world.prover.address().to_string(),
        ],
        &env,
    );
    world.submit_after_start(&mut miner).await;
    let (mut failures, mut lines) = watch_and_check(&world, &mut miner, true).await;
    // The program came from its registry URI, and the decoy was refused for its image id, not for
    // some other failure.
    if world.elf_hits.load(Ordering::SeqCst) == 0 {
        failures.push("the guest was never downloaded from its registry URI".into());
    }
    if !lines
        .iter()
        .any(|l| l.contains("does not match job programId"))
    {
        failures.push("the decoy ELF was never refused for its image id".into());
    }

    // As an address with no stake: the quote is refused for want of stake, and nothing would be
    // claimed.
    let unstaked_home = dir.0.join("unstaked");
    std::fs::create_dir_all(unstaked_home.join(".zkminer")).unwrap();
    let mut unstaked = Miner::start(
        &unstaked_home,
        &config,
        &[],
        &[
            "--watch-only",
            "--address",
            &Address::repeat_byte(0x77).to_string(),
        ],
        &env,
    );
    let (unstaked_failures, unstaked_lines) = watch_and_check(&world, &mut unstaked, false).await;
    failures.extend(
        unstaked_failures
            .into_iter()
            .map(|f| format!("unstaked: {f}")),
    );

    // The guests run in one segment, so each total cycle count the verdicts report is a power of
    // two (a count of user cycles would almost never be). Some must be reported, or this proves
    // nothing.
    let mut counts = 0;
    for job in &world.jobs {
        let verdicts = [
            watch_lines(&lines, job.id),
            watch_lines(&unstaked_lines, job.id),
        ]
        .concat();
        for v in &verdicts {
            for n in reported_cycles(v) {
                counts += 1;
                if !n.parse::<u64>().is_ok_and(u64::is_power_of_two) {
                    failures.push(format!(
                        "{:?}: {n} cycles is not a power of two ({v})",
                        job.case
                    ));
                }
            }
        }
    }
    if counts == 0 {
        failures.push("no verdict reported a measured cycle count".into());
    }

    // Watch-only sends nothing. Setup sends with eth_sendTransaction (anvil signs), so any
    // eth_sendRawTransaction the node saw came from a miner (its send guard must stop even its
    // throwaway key's); setup's own sends show that anvil.log records them. The prover's nonce
    // and the claims are checked too, for completeness.
    let anvil_log = std::fs::read_to_string(dir.0.join("anvil.log")).unwrap_or_default();
    if !anvil_log.contains("eth_sendTransaction") {
        failures.push(
            "anvil.log has no eth_sendTransaction, though setup sent with it: it cannot show a \
             raw send either"
                .into(),
        );
    }
    let raw_sends = anvil_log.matches("eth_sendRawTransaction").count();
    if raw_sends > 0 {
        failures.push(format!("the node received {raw_sends} raw transaction(s)"));
    }
    let nonce_after = world.prover_nonce().await;
    if nonce_after != nonce_before {
        failures.push(format!(
            "the prover's nonce moved from {nonce_before} to {nonce_after}"
        ));
    }
    let claimed = world.jobs_with::<IHemiProveCore::JobClaimed>().await;
    if !claimed.is_empty() {
        failures.push(format!("JobClaimed on the fork for {claimed:?}"));
    }
    if !failures.is_empty() {
        lines.extend(unstaked_lines);
        dump_tail(&dir.0, &lines);
        panic!(
            "watch-only localnet run failed (run directory {}):\n  {}",
            dir.0.display(),
            failures.join("\n  ")
        );
    }
    dir.finish();
}

/// The environment for a miner on the replayed receipt fixture.
fn replay_env() -> Vec<(&'static str, String)> {
    vec![
        ("MOCK_BACKEND", "risc0".to_string()),
        ("MOCK_JOURNAL_HEX", alloy::hex::encode(FIXTURE_JOURNAL)),
        // A worker returns the bare proof, and the miner prefixes the selector.
        ("MOCK_SEAL_HEX", FIXTURE_SEAL_HEX[8..].to_string()),
    ]
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs anvil, the mock worker and the 743111 RPC; see the module docs"]
async fn fulfils_with_a_replayed_receipt() {
    let dir = RunDir::new("replay");
    let worker = mock_worker();
    let mut world = World::new(&dir.0, Program::fixture(), &Case::REPLAYABLE, Clock::Wall).await;
    let config = world.write_config(&dir.0, &worker, false);
    mine_and_check(&mut world, &dir, &config, replay_env(), REPLAY_TIMEOUT).await;
    dir.finish();
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs anvil, the mock worker and the 743111 RPC; see the module docs"]
async fn holds_its_lock_through_a_pause() {
    let dir = RunDir::new("pause-locked");
    let worker = mock_worker();
    let world = World::new(&dir.0, Program::fixture(), &[Case::Full], Clock::Wall).await;
    let config = world.write_config(&dir.0, &worker, false);
    let job = world.jobs[0].id;
    // Looked up and funded now, so the pause lands as soon as the job is claimed.
    let router_owner = world.funded_owner(DEPLOYMENT.router).await;
    let nonce_before = world.prover_nonce().await;
    // A proof that takes a while, so the router can pause while the lock is held.
    let mut env = replay_env();
    env.push((
        "MOCK_PROVE_DELAY_SECS",
        PAUSE_PROVE_DELAY.as_secs().to_string(),
    ));
    let mut miner = start_mining(&world, &dir, &config, env, false);

    let mut failures = Vec::new();
    let started = Instant::now();
    while world
        .jobs_with::<IHemiProveCore::JobClaimed>()
        .await
        .is_empty()
    {
        if miner.exited() || started.elapsed() > Duration::from_secs(180) {
            miner.fail("the job was never claimed (waited 180 s)");
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    let pause_block = world.set_router_paused(router_owner, true).await;
    let nonce_paused = world.prover_nonce().await;
    // The proof finishes while paused: its fulfil must be held, nothing sent, and the lock kept.
    let hold = format!(
        "KEEP: {} fulfil held (router or Registry paused — holding the fulfil)",
        short_id(job)
    );
    if !wait_for_line(
        &mut miner,
        &hold,
        PAUSE_PROVE_DELAY + Duration::from_secs(120),
    )
    .await
    {
        failures.push(format!("the miner never logged {hold:?} while paused"));
    }
    // Held past the nonce-gap watchdog's reach.
    tokio::time::sleep(PAUSE_HOLD).await;
    let (status, prover) = world.job_state(job).await;
    if status != zkminer_chain::jobs::JOB_STATUS_LOCKED || prover != world.prover.address() {
        failures.push(format!(
            "during the pause the job reads status {status} prover {prover}, not locked by us"
        ));
    }
    let nonce_held = world.prover_nonce().await;
    if nonce_held != nonce_paused {
        failures.push(format!(
            "the prover's nonce moved from {nonce_paused} to {nonce_held} while its fulfil was held"
        ));
    }
    world.set_router_paused(router_owner, false).await;
    let (fulfilled, exited_early) = wait_fulfilled(&world, &mut miner, REPLAY_TIMEOUT).await;
    tokio::time::sleep(SETTLE).await;
    let stopped = miner.stop(DRAIN_GRACE);
    failures.extend(
        check_settlement(
            &world,
            &miner.lines(),
            nonce_before,
            &fulfilled,
            exited_early,
            stopped,
        )
        .await,
    );
    // A fulfil mined before the pause leaves nothing above to trust: say so first.
    let fulfil_block = world
        .logs::<IHemiProveFulfill::JobFulfilled>()
        .await
        .into_iter()
        .find(|(j, _)| *j == job)
        .map(|(_, l)| l.block);
    if let Some(fulfil_block) = fulfil_block.filter(|&f| pause_block >= f) {
        failures.insert(
            0,
            format!(
                "the pause landed late (block {pause_block} ≥ fulfil block {fulfil_block}) — \
                 harness race, not a miner bug"
            ),
        );
    }
    finish_or_report(world, dir, miner, failures).await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs anvil, the mock worker and the 743111 RPC; see the module docs"]
async fn holds_off_while_the_router_is_paused() {
    let dir = RunDir::new("pause");
    let worker = mock_worker();
    // Submitted before the pause (a paused router refuses submits too).
    let world = World::new(
        &dir.0,
        Program::fixture(),
        &[Case::Full, Case::FullWrongJournal],
        Clock::Wall,
    )
    .await;
    let config = world.write_config(&dir.0, &worker, false);
    let router_owner = world.funded_owner(DEPLOYMENT.router).await;
    world.set_router_paused(router_owner, true).await;
    let nonce_before = world.prover_nonce().await;
    let mut miner = start_mining(&world, &dir, &config, replay_env(), false);

    // The miner's own gate holds the claim: it reports the pause, dispatches no claim, and sends
    // nothing (a claim it tried would be refused anyway, so only that proves the gate).
    let mut failures = Vec::new();
    if !wait_for_line(
        &mut miner,
        "PAUSED: the router or Registry is paused",
        Duration::from_secs(120),
    )
    .await
    {
        failures.push("the miner never reported the pause".to_string());
    }
    tokio::time::sleep(SETTLE).await;
    if world.jobs.iter().any(|j| dispatched(&miner.lines(), j.id)) {
        failures.push("a claim was dispatched while the router was paused".into());
    }
    if world.prover_nonce().await != nonce_before {
        failures.push("the prover sent a transaction while the router was paused".into());
    }
    // Lifted: the claimable job is dispatched, claimed and fulfilled.
    world.set_router_paused(router_owner, false).await;
    let (fulfilled, exited_early) = wait_fulfilled(&world, &mut miner, REPLAY_TIMEOUT).await;
    tokio::time::sleep(SETTLE).await;
    let stopped = miner.stop(DRAIN_GRACE);
    failures.extend(
        check_settlement(
            &world,
            &miner.lines(),
            nonce_before,
            &fulfilled,
            exited_early,
            stopped,
        )
        .await,
    );
    finish_or_report(world, dir, miner, failures).await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs anvil, the mock worker and the 743111 RPC; see the module docs"]
async fn refuses_to_claim_while_its_adapter_is_disabled() {
    let dir = RunDir::new("disabled");
    let worker = mock_worker();
    let world = World::new(&dir.0, Program::fixture(), &[Case::Full], Clock::Wall).await;
    let config = world.write_config(&dir.0, &worker, false);
    world.disable_risc0_adapter().await;
    // The brain's own skip of this job (a debug line), not just the startup check's report: it
    // proves the brain evaluated the job and held it.
    let needle = format!(
        "Skipping {}: risczero.groth16.v1 is not verified claimable right now",
        short_id(world.jobs[0].id)
    );
    no_claims_after(world, dir, &config, &needle, 1, true).await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs anvil, the mock worker and the 743111 RPC; see the module docs"]
async fn refuses_to_claim_on_a_skewed_clock() {
    let dir = RunDir::new("skew");
    let worker = mock_worker();
    // The chain an hour behind this host: every lock would look about to expire, and be released.
    let world = World::new(
        &dir.0,
        Program::fixture(),
        &[Case::Full],
        Clock::Lagging(3_600),
    )
    .await;
    let config = world.write_config(&dir.0, &worker, false);
    // The gate reports at once and then each minute: two reports prove it held for that minute.
    no_claims_after(
        world,
        dir,
        &config,
        "s ahead of the chain's (more than",
        2,
        false,
    )
    .await;
}

/// The replay test with the real risc0 worker on the fibonacci guest: real GPU proofs.
///
/// The miner discovers the worker and starts one per card, each pinned with its own
/// `CUDA_VISIBLE_DEVICES`, which overrides the developer's. So with `CUDA_VISIBLE_DEVICES` set the
/// worker is named outright instead: one worker, which the dispatcher does not pin, so that setting
/// holds. Its indices count in PCI bus order, as nvidia-smi's do (the dispatcher sets
/// `CUDA_DEVICE_ORDER=PCI_BUS_ID`).
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs a GPU, anvil, the release risc0 worker and ZKMINER_LOCALNET_MINE=1"]
async fn mines_the_claimable_jobs() {
    if !env_flag("ZKMINER_LOCALNET_MINE") {
        eprintln!(
            "localnet: SKIPPED the mining test (it did not run); set ZKMINER_LOCALNET_MINE=1 to run it"
        );
        return;
    }
    let timeout = Duration::from_secs(
        std::env::var("ZKMINER_LOCALNET_MINE_TIMEOUT_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(1_800),
    );
    let dir = RunDir::new("mine");
    let worker = risc0_worker();
    let program = Program::fibonacci(&worker, &dir.0);
    let mut world = World::new(&dir.0, program, &Case::ALL, Clock::Wall).await;
    let discover = std::env::var_os("CUDA_VISIBLE_DEVICES").is_none();
    if !discover {
        eprintln!(
            "localnet: CUDA_VISIBLE_DEVICES is set: one risc0 worker, named outright, on the cards \
             it allows"
        );
    }
    let config = world.write_config(&dir.0, &worker, discover);
    mine_and_check(&mut world, &dir, &config, Vec::new(), timeout).await;
    dir.finish();
}

/// Every GPU proves: risc0 and SP1 fibonacci jobs (FULL, FIELDS and NONE-for-us, several copies each)
/// for one miner holding every worker, until each is fulfilled on the fork; then every slot named in
/// `ZKMINER_LOCALNET_EXPECT_SLOTS` must have proved at least one of them.
///
/// Needs `ZKMINER_LOCALNET_MINE_ALL=1`, `ZKMINER_LOCALNET_WORKERS` (the risc0 workers, `:`-separated,
/// the first exporting the risc0 guest) and `ZKMINER_LOCALNET_SP1_WORKER` (with its servers beside it).
/// Optional: `ZKMINER_LOCALNET_COPIES` (default 3) and `ZKMINER_LOCALNET_SP1_COPIES` (default the
/// same): how many jobs of each case the risc0 and the SP1 program get. `ZKMINER_LOCALNET_RISC0_PO2`
/// (`gpu1=19,...`). `SP1_GROTH16_CIRCUIT_PATH`, `XDG_CACHE_HOME`, `ZKMINER_MIN_AVAILABLE_VRAM_MB` and
/// `ZKMINER_GPU_NAME_FILTER`, passed to the miner.
///
/// For a busy run (see `occupancy`): `ZKMINER_LOCALNET_QUEUE_HORIZON_SECS` turns on the miner's
/// look-ahead (`prover.queue_horizon_secs`), which claims each card's next job while its current one
/// proves, and which acts only on a measured benchmark suite: `ZKMINER_LOCALNET_BENCHMARKS` names one
/// to give the miner, made by `zkminer benchmark --calibrate` in this run if the file does not exist.
/// `ZKMINER_LOCALNET_MIN_OCCUPANCY` (a percentage) fails the run if a card proved for less of the
/// time work was waiting.
#[tokio::test]
#[ignore = "needs every GPU worker and SP1 server"]
async fn mines_on_every_gpu() {
    if !env_flag("ZKMINER_LOCALNET_MINE_ALL") {
        eprintln!(
            "localnet: SKIPPED the every-GPU test; set ZKMINER_LOCALNET_MINE_ALL=1 to run it"
        );
        return;
    }
    let timeout = Duration::from_secs(
        std::env::var("ZKMINER_LOCALNET_MINE_TIMEOUT_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(3_600),
    );
    let EveryGpu {
        dir,
        mut world,
        config,
        env,
        ..
    } = every_gpu("mine-all").await;

    let nonce_before = world.prover_nonce().await;
    let mut miner = start_mining(&world, &dir, &config, env, false);
    world.submit_after_start(&mut miner).await;
    let (fulfilled, exited_early) = wait_fulfilled(&world, &mut miner, timeout).await;
    tokio::time::sleep(SETTLE).await;
    let stopped = miner.stop(DRAIN_GRACE);
    let lines = miner.lines();
    let mut failures = check_settlement(
        &world,
        &lines,
        nonce_before,
        &fulfilled,
        exited_early,
        stopped,
    )
    .await;
    // Which slot proved each job: `Job <id> proved on <slot>`.
    let mut by_slot: std::collections::BTreeMap<String, usize> = Default::default();
    for line in &lines {
        if let Some(rest) = strip_ansi(line).split(" proved on ").nth(1) {
            let slot = rest.split_whitespace().next().unwrap_or("").to_string();
            *by_slot.entry(slot).or_default() += 1;
        }
    }
    eprintln!("localnet: proofs by slot: {by_slot:?}");
    match occupancy(&proof_spans(&lines)) {
        Some(o) => {
            eprintln!(
                "localnet: occupancy over the {:.0} s that work was waiting (first proof start to \
                 last proof start): {}; all {} cards proving at once for {:.0}% of it",
                o.window,
                o.cards
                    .iter()
                    .map(|(card, share)| format!("{card} {:.0}%", share * 100.0))
                    .collect::<Vec<_>>()
                    .join(", "),
                o.cards.len(),
                o.all_busy * 100.0,
            );
            if let Some(min) = std::env::var("ZKMINER_LOCALNET_MIN_OCCUPANCY")
                .ok()
                .and_then(|s| s.parse::<f64>().ok())
            {
                for (card, share) in &o.cards {
                    if share * 100.0 < min {
                        failures.push(format!(
                            "{card} proved for {:.0}% of the time work was waiting, under {min}%",
                            share * 100.0
                        ));
                    }
                }
            }
        }
        None => eprintln!("localnet: occupancy: too few proofs to measure"),
    }
    for slot in std::env::var("ZKMINER_LOCALNET_EXPECT_SLOTS")
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        if !by_slot.contains_key(slot) {
            failures.push(format!("slot {slot} proved none of the jobs ({by_slot:?})"));
        }
    }
    report(&world, &dir, &miner, &failures).await;
    dir.finish();
}

/// A localnet for a miner someone runs BY HAND, to watch it work in its TUI: the every-GPU world
/// (`every_gpu`, with all its variables), a launcher for the miner, and a job queue kept topped up
/// until `<run dir>/stop` exists or `ZKMINER_LOCALNET_TUI_SECS` (default 7200) pass. The test does
/// not start a miner; run `<run dir>/run-tui.sh` in a terminal of its own.
///
/// Needs `ZKMINER_LOCALNET_TUI=1`. The queue: a round of `ZKMINER_LOCALNET_TUI_ROUND` copies of each
/// case (`risc0,sp1`, default `4,1`) is submitted whenever fewer than `ZKMINER_LOCALNET_TUI_QUEUE`
/// (default 16) jobs are unfulfilled. At the end it reports what was fulfilled and, from the miner's
/// log (`<run dir>/.zkminer/logs`), each card's occupancy.
#[tokio::test]
#[ignore = "serves a localnet to a miner run by hand"]
async fn serves_a_tui_miner() {
    if !env_flag("ZKMINER_LOCALNET_TUI") {
        eprintln!("localnet: SKIPPED the TUI localnet; set ZKMINER_LOCALNET_TUI=1 to serve one");
        return;
    }
    let EveryGpu {
        dir,
        mut world,
        config,
        mut env,
        copies,
    } = every_gpu("tui").await;
    // No monitor to wait for: the miner's backfill finds these as it does the jobs set up before it.
    world.submit_held_back().await;
    env.push((
        "ZKMINER_PRIVATE_KEY",
        format!("{}", world.prover.to_bytes()),
    ));
    let launcher = write_launcher(&dir.0, &config, &env);
    let stop = dir.0.join("stop");
    let secs = std::env::var("ZKMINER_LOCALNET_TUI_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(7_200);
    let queue: usize = std::env::var("ZKMINER_LOCALNET_TUI_QUEUE")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(16);
    let round: Vec<usize> = std::env::var("ZKMINER_LOCALNET_TUI_ROUND")
        .unwrap_or_else(|_| "4,1".into())
        .split(',')
        .map(|n| {
            n.trim()
                .parse()
                .expect("ZKMINER_LOCALNET_TUI_ROUND is `risc0,sp1` copies")
        })
        .collect();
    assert_eq!(
        round.len(),
        2,
        "ZKMINER_LOCALNET_TUI_ROUND is `risc0,sp1` copies"
    );
    eprintln!(
        "localnet: READY. {} jobs are open on the fork at {}.\n\
         localnet: run the miner in a terminal of its own:  bash {}\n\
         localnet: the queue is kept at {queue}+ open jobs for {secs} s; stop early with:  touch {}",
        world.jobs.len(),
        world.rpc_url,
        launcher.display(),
        stop.display()
    );
    let cases = world.cases.clone();
    let per_round =
        U256::from(cases.iter().map(|c| c.deposit()).sum::<u128>() * (round[0] + round[1]) as u128);
    // Every round's deposits up front: one mint, rather than more fork reads in each round.
    world.fund_deposits(per_round * U256::from(500u64)).await;
    let mut next = copies;
    let started = Instant::now();
    while started.elapsed() < Duration::from_secs(secs) && !stop.exists() {
        let fulfilled: std::collections::HashSet<B256> = world
            .jobs_with::<IHemiProveFulfill::JobFulfilled>()
            .await
            .into_iter()
            .collect();
        let open = world
            .jobs
            .iter()
            .filter(|j| j.case.claimable() && !fulfilled.contains(&j.id))
            .count();
        if open < queue {
            // One job at a time, a second apart, and a refused one tried again after a pause: a
            // burst of submits trips the fork's upstream rate limit (see `try_submit_job`).
            for program in 0..2 {
                for _ in 0..round[program] {
                    for &case in &cases {
                        while let Err(e) = world.try_submit_job(case, program, next[program]).await
                        {
                            eprintln!("localnet: submit failed, trying again in 30 s: {e}");
                            tokio::time::sleep(Duration::from_secs(30)).await;
                        }
                        tokio::time::sleep(Duration::from_secs(1)).await;
                    }
                    next[program] += 1;
                }
            }
            eprintln!(
                "localnet: {open} open, {} fulfilled; submitted another round ({} jobs in all)",
                fulfilled.len(),
                world.jobs.len()
            );
        }
        tokio::time::sleep(Duration::from_secs(10)).await;
    }
    let fulfilled = world
        .jobs_with::<IHemiProveFulfill::JobFulfilled>()
        .await
        .len();
    eprintln!(
        "localnet: done: {fulfilled} of {} jobs fulfilled",
        world.jobs.len()
    );
    let mut lines = Vec::new();
    for log in std::fs::read_dir(dir.0.join(".zkminer").join("logs"))
        .into_iter()
        .flatten()
        .flatten()
    {
        if let Ok(text) = std::fs::read_to_string(log.path()) {
            lines.extend(text.lines().map(strip_ansi));
        }
    }
    if let Some(o) = occupancy(&proof_spans(&lines)) {
        eprintln!(
            "localnet: occupancy over the {:.0} s that work was waiting: {}; all {} cards at once \
             {:.0}% of it",
            o.window,
            o.cards
                .iter()
                .map(|(card, share)| format!("{card} {:.0}%", share * 100.0))
                .collect::<Vec<_>>()
                .join(", "),
            o.cards.len(),
            o.all_busy * 100.0,
        );
    }
    dir.finish();
}

/// `<dir>/run-tui.sh`: the miner `Miner::start` would run, as a script someone runs in a terminal of
/// their own, so it gets the TUI. The same cleaned environment and HOME, the same config.
fn write_launcher(dir: &Path, config: &Path, env: &[(&str, String)]) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let cmd = Miner::command(dir, config, &[], "run", &[], env);
    let quote = |s: &std::ffi::OsStr| format!("'{}'", s.to_string_lossy().replace('\'', r"'\''"));
    let mut script = format!(
        "#!/bin/bash\n\
         # zkminer with its TUI against the localnet run in this directory, written by the localnet\n\
         # test. Its HOME is this directory (config, journal, logs in .zkminer/), and the key below\n\
         # is the run's throwaway prover on the anvil fork. Quit the TUI to stop it.\n\
         set -e\n\
         cd {}\n\
         for v in $(compgen -e | grep -E '^(ZKMINER_|MOCK_|BONSAI_)'); do unset \"$v\"; done\n",
        quote(dir.as_os_str())
    );
    for (k, v) in cmd.get_envs() {
        let k = k.to_string_lossy();
        match v {
            Some(v) => script += &format!("export {k}={}\n", quote(v)),
            None => script += &format!("unset {k}\n"),
        }
    }
    script += &format!("exec {}", quote(cmd.get_program()));
    for arg in cmd.get_args() {
        script += &format!(" {}", quote(arg));
    }
    script.push('\n');
    let path = dir.join("run-tui.sh");
    std::fs::write(&path, script).expect("write the TUI launcher");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
        .expect("make the TUI launcher executable");
    path
}

/// What the every-GPU tests share: the run directory, the world with every program's held-back jobs
/// still to submit, the miner's config naming every worker, the environment passed to the miner,
/// and how many jobs of each case the risc0 and the SP1 program got. See `mines_on_every_gpu` for
/// the variables it reads.
struct EveryGpu {
    dir: RunDir,
    world: World,
    config: PathBuf,
    env: Vec<(&'static str, String)>,
    copies: [usize; 2],
}

async fn every_gpu(name: &str) -> EveryGpu {
    let workers: Vec<PathBuf> = std::env::var("ZKMINER_LOCALNET_WORKERS")
        .expect("ZKMINER_LOCALNET_WORKERS: the risc0 workers, `:`-separated")
        .split(':')
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .collect();
    let sp1_worker = PathBuf::from(
        std::env::var("ZKMINER_LOCALNET_SP1_WORKER").expect("ZKMINER_LOCALNET_SP1_WORKER"),
    );
    for w in workers.iter().chain(std::iter::once(&sp1_worker)) {
        assert!(w.is_file(), "no worker at {}", w.display());
    }
    let copies = std::env::var("ZKMINER_LOCALNET_COPIES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(3);
    let sp1_copies = std::env::var("ZKMINER_LOCALNET_SP1_COPIES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(copies);
    let po2: Vec<(String, u8)> = std::env::var("ZKMINER_LOCALNET_RISC0_PO2")
        .unwrap_or_default()
        .split(',')
        .filter_map(|kv| {
            let (k, v) = kv.split_once('=')?;
            Some((k.trim().to_string(), v.trim().parse().ok()?))
        })
        .collect();
    let dir = RunDir::new(name);
    let risc0 = Program::fibonacci(&workers[0], &dir.0);
    let sp1 = Program::sp1_fibonacci(&sp1_worker, &dir.0);
    let cases = [Case::Full, Case::Fields, Case::NoneForUs];
    let world = World::with_programs(
        &dir.0,
        vec![risc0, sp1],
        &cases,
        Clock::Wall,
        vec![copies, sp1_copies],
    )
    .await;
    let mut all = workers.clone();
    all.push(sp1_worker);
    let config = world.write_config_for(&dir.0, &all, &po2);
    if let Some(horizon) = std::env::var("ZKMINER_LOCALNET_QUEUE_HORIZON_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
    {
        let mut c = ZkMinerConfig::load(Some(&config)).expect("read the miner config back");
        c.prover.queue_horizon_secs = horizon;
        c.save(Some(&config)).expect("write the miner config");
    }
    let env: Vec<(&'static str, String)> = [
        // Named, not merely inherited, so the TUI launcher carries it too: CUDA numbers cards by
        // speed without it, which is not `nvidia-smi`'s order.
        "CUDA_DEVICE_ORDER",
        "SP1_GROTH16_CIRCUIT_PATH",
        "XDG_CACHE_HOME",
        "ZKMINER_MIN_AVAILABLE_VRAM_MB",
        // To steer jobs onto particular NVIDIA cards: one SP1 proof at a time fits this host's
        // `/dev/shm` (each may stage 24 GiB), so it lands on the same card unless others are hidden.
        "ZKMINER_GPU_NAME_FILTER",
    ]
    .into_iter()
    .filter_map(|k| std::env::var(k).ok().map(|v| (k, v)))
    .collect();
    if let Ok(cache) = std::env::var("ZKMINER_LOCALNET_BENCHMARKS") {
        seed_benchmarks(&dir.0, &config, &env, Path::new(&cache));
    }
    EveryGpu {
        dir,
        world,
        config,
        env,
        copies: [copies, sp1_copies],
    }
}

/// Give the miner whose HOME is `dir` a measured benchmark suite: `cache` when that file exists,
/// otherwise one `zkminer benchmark --calibrate` makes here first (a plain benchmark saves nothing),
/// saved to `cache` for later runs. The suite is
/// fingerprinted on this host's CPU, RAM and GPUs, not on paths, so one serves every run on the host
/// until a card or driver changes (and the miner discards it then).
fn seed_benchmarks(dir: &Path, config: &Path, env: &[(&str, String)], cache: &Path) {
    let suite = dir.join(".zkminer").join("benchmarks.json");
    std::fs::create_dir_all(suite.parent().unwrap()).expect("create the miner's ~/.zkminer");
    if cache.is_file() {
        std::fs::copy(cache, &suite).expect("copy the benchmark suite");
        eprintln!("localnet: benchmark suite from {}", cache.display());
        return;
    }
    eprintln!(
        "localnet: no benchmark suite at {}; running zkminer benchmark --calibrate (every worker, \
         every card)",
        cache.display()
    );
    let mut cmd = Miner::command(dir, config, &[], "benchmark", &["--calibrate"], env);
    die_with_parent(&mut cmd);
    let out = cmd.output().expect("run zkminer benchmark");
    let log = dir.join("benchmark.log");
    let _ = std::fs::write(&log, [&out.stdout[..], &out.stderr[..]].concat());
    assert!(
        out.status.success() && suite.is_file(),
        "zkminer benchmark failed or saved no suite; see {}",
        log.display()
    );
    std::fs::copy(&suite, cache).expect("save the benchmark suite for later runs");
}

/// One proof the miner logged as `<time> INFO Proof complete on <slot> [<card>]: <n> cycles in <t>s`:
/// its slot, its card (`cuda:0`), and when it ran, in seconds, timed back from the line by `t`.
struct ProofSpan {
    card: String,
    start: f64,
    end: f64,
}

fn proof_spans(lines: &[String]) -> Vec<ProofSpan> {
    lines
        .iter()
        .filter_map(|line| {
            let (stamp, rest) = line.split_once(' ')?;
            let (slot, rest) = rest.split_once("Proof complete on ")?.1.split_once(' ')?;
            let secs: f64 = rest
                .rsplit_once(" in ")?
                .1
                .trim()
                .strip_suffix('s')?
                .parse()
                .ok()?;
            let end = chrono::DateTime::parse_from_rfc3339(stamp)
                .ok()?
                .timestamp_micros() as f64
                / 1e6;
            Some(ProofSpan {
                card: slot.split_once(':')?.1.to_string(),
                start: end - secs,
                end,
            })
        })
        .collect()
}

/// How busy each card was while work was waiting.
struct Occupancy {
    /// The window measured, in seconds.
    window: f64,
    /// Each card and the share of the window it spent proving (any backend).
    cards: Vec<(String, f64)>,
    /// The share of the window every card spent proving at once.
    all_busy: f64,
}

/// Occupancy over the window from the first proof's start to the LAST proof's start. Until then a
/// job was waiting to start, so a card standing idle was the miner's doing (a claim or fulfil it did
/// not overlap, a worker respawn, a wait); after it the queue is empty and cards go idle by design.
/// Proof time is what the worker reports, so a respawn, a warm-up or a wait for memory counts as idle.
fn occupancy(spans: &[ProofSpan]) -> Option<Occupancy> {
    let from = spans.iter().map(|s| s.start).fold(f64::INFINITY, f64::min);
    let to = spans
        .iter()
        .map(|s| s.start)
        .fold(f64::NEG_INFINITY, f64::max);
    if spans.len() < 2 || to <= from {
        return None;
    }
    let mut names: Vec<&str> = spans.iter().map(|s| s.card.as_str()).collect();
    names.sort_unstable();
    names.dedup();
    // Each card's proving time inside the window, its spans merged so two backends' overlap (which
    // the per-card guard forbids) could not count twice.
    let busy_on = |card: &str| -> Vec<(f64, f64)> {
        let mut runs: Vec<(f64, f64)> = spans
            .iter()
            .filter(|s| s.card == card)
            .map(|s| (s.start.max(from), s.end.min(to)))
            .filter(|(a, b)| b > a)
            .collect();
        runs.sort_by(|x, y| x.0.total_cmp(&y.0));
        let mut merged: Vec<(f64, f64)> = Vec::new();
        for (a, b) in runs {
            match merged.last_mut() {
                Some(last) if a <= last.1 => last.1 = last.1.max(b),
                _ => merged.push((a, b)),
            }
        }
        merged
    };
    let per_card: Vec<(String, Vec<(f64, f64)>)> = names
        .iter()
        .map(|card| (card.to_string(), busy_on(card)))
        .collect();
    let window = to - from;
    let cards = per_card
        .iter()
        .map(|(card, runs)| {
            (
                card.clone(),
                runs.iter().map(|(a, b)| b - a).sum::<f64>() / window,
            )
        })
        .collect();
    // Every card at once: walk the pieces between consecutive span edges.
    let mut edges: Vec<f64> = per_card
        .iter()
        .flat_map(|(_, runs)| runs.iter().flat_map(|&(a, b)| [a, b]))
        .chain([from, to])
        .collect();
    edges.sort_by(f64::total_cmp);
    let all_busy = edges
        .windows(2)
        .filter(|w| {
            let mid = (w[0] + w[1]) / 2.0;
            per_card
                .iter()
                .all(|(_, runs)| runs.iter().any(|&(a, b)| a <= mid && mid < b))
        })
        .map(|w| w[1] - w[0])
        .sum::<f64>()
        / window;
    Some(Occupancy {
        window,
        cards,
        all_busy,
    })
}

/// `zkminer run` with the prover's key.
fn start_mining(
    world: &World,
    dir: &RunDir,
    config: &Path,
    mut env: Vec<(&'static str, String)>,
    verbose: bool,
) -> Miner {
    env.push((
        "ZKMINER_PRIVATE_KEY",
        format!("{}", world.prover.to_bytes()),
    ));
    let global: &[&str] = if verbose { &["-v"] } else { &[] };
    Miner::start(&dir.0, config, global, &["--headless"], &env)
}

/// Wait until every claimable job is fulfilled, the miner exits, or `timeout` passes. Returns the
/// fulfilled jobs and whether the miner exited on its own.
async fn wait_fulfilled(world: &World, miner: &mut Miner, timeout: Duration) -> (Vec<B256>, bool) {
    let want: Vec<B256> = world
        .jobs
        .iter()
        .filter(|j| j.case.claimable())
        .map(|j| j.id)
        .collect();
    let started = Instant::now();
    loop {
        let fulfilled = world.jobs_with::<IHemiProveFulfill::JobFulfilled>().await;
        let exited = miner.exited();
        if want.iter().all(|id| fulfilled.contains(id)) || started.elapsed() > timeout || exited {
            return (fulfilled, exited);
        }
        tokio::time::sleep(Duration::from_secs(3)).await;
    }
}

/// After a mining run: exactly the claimable jobs fulfilled, each by us, with the program's journal
/// and claimed in an earlier transaction (the seal is never broadcast before the lock), and each
/// dispatched by the brain (the positive control for [`dispatched`], which the no-claim checks rely
/// on); none of the others claimed, every one of them still Open, and those the brain must hold
/// ([`Case::held_before_dispatch`]) never even dispatched; the prover's nonce moved from
/// `nonce_before` by exactly a claim and a fulfil per claimable job; no collateral left locked; the
/// stake whole; a clean exit (0, within [`DRAIN_GRACE`] of SIGINT).
async fn check_settlement(
    world: &World,
    lines: &[String],
    nonce_before: u64,
    fulfilled: &[B256],
    exited_early: bool,
    stopped: Option<ExitStatus>,
) -> Vec<String> {
    let mut failures = Vec::new();
    if exited_early {
        failures.push("zkminer exited on its own".to_string());
    }
    failures.extend(stop_failure(stopped, DRAIN_GRACE));
    let claims = world.logs::<IHemiProveCore::JobClaimed>().await;
    let fulfils = world.logs::<IHemiProveFulfill::JobFulfilled>().await;
    for job in &world.jobs {
        let claim = claims.iter().find(|(j, _)| *j == job.id).map(|(_, l)| l);
        let fulfil = fulfils.iter().find(|(j, _)| *j == job.id).map(|(_, l)| l);
        let (status, prover) = world.job_state(job.id).await;
        eprintln!(
            "localnet: {:?} {}: claimed={} fulfilled={} status={status}",
            job.case,
            short_id(job.id),
            claim.is_some(),
            fulfilled.contains(&job.id)
        );
        if job.case.claimable() {
            if !dispatched(lines, job.id) {
                failures.push(format!(
                    "{:?}: the log has no `CLAIM {} (` line, which the no-claim checks look for",
                    job.case,
                    short_id(job.id)
                ));
            }
            match (claim, fulfil) {
                (Some(c), Some(f)) => {
                    if c.tx == f.tx || c.block >= f.block {
                        failures.push(format!(
                            "{:?}: fulfilled in block {} by tx {}, not after a lock mined before it \
                             (claim block {}, tx {})",
                            job.case, f.block, f.tx, c.block, c.tx
                        ));
                    }
                    if c.event.prover != world.prover.address()
                        || f.event.prover != world.prover.address()
                    {
                        failures.push(format!(
                            "{:?}: claimed or fulfilled by another prover",
                            job.case
                        ));
                    }
                    if f.event.publicValues.as_ref() != world.program_of(job).journal.as_slice() {
                        failures.push(format!(
                            "{:?}: fulfilled with journal {}, not the program's",
                            job.case, f.event.publicValues
                        ));
                    }
                }
                (None, _) => failures.push(format!("{:?}: never claimed", job.case)),
                (Some(_), None) => failures.push(format!("{:?}: not fulfilled", job.case)),
            }
            if status != zkminer_chain::jobs::JOB_STATUS_FULFILLED {
                failures.push(format!(
                    "{:?}: ends with status {status}, not Fulfilled",
                    job.case
                ));
            }
        } else {
            if claim.is_some() {
                failures.push(format!("{:?}: claimed, but must never be", job.case));
            }
            if job.case.held_before_dispatch() && dispatched(lines, job.id) {
                failures.push(format!(
                    "{:?}: dispatched (`CLAIM {} (`), but the brain must hold it",
                    job.case,
                    short_id(job.id)
                ));
            }
            if status != zkminer_chain::jobs::JOB_STATUS_OPEN || prover != Address::ZERO {
                failures.push(format!(
                    "{:?}: ends with status {status} prover {prover}, not Open",
                    job.case
                ));
            }
        }
    }
    let stake = world.stake().await;
    if stake.lockedCollateral != 0 {
        failures.push(format!(
            "{} HEMI of collateral still locked",
            hemi(stake.lockedCollateral)
        ));
    }
    if stake.totalStaked != prover_stake() {
        failures.push(format!(
            "the stake is {} HEMI, not the {} HEMI staked",
            hemi(stake.totalStaked),
            hemi(prover_stake())
        ));
    }
    // Nothing else is sent in a clean run: no release, no resend at a new nonce, no nonce-gap fill.
    let claimable = world.jobs.iter().filter(|j| j.case.claimable()).count() as u64;
    let nonce_after = world.prover_nonce().await;
    if nonce_after.checked_sub(nonce_before) != Some(2 * claimable) {
        failures.push(format!(
            "the prover's nonce moved from {nonce_before} to {nonce_after}, not by {} (a claim and \
             a fulfil for each of the {claimable} claimable jobs)",
            2 * claimable
        ));
    }
    failures
}

/// Run `zkminer run` with the prover's key until every claimable job is fulfilled or `timeout`
/// passes, watch for [`SETTLE`] more, then drain it with SIGINT and require [`check_settlement`].
async fn mine_and_check(
    world: &mut World,
    dir: &RunDir,
    config: &Path,
    env: Vec<(&'static str, String)>,
    timeout: Duration,
) {
    let nonce_before = world.prover_nonce().await;
    let mut miner = start_mining(world, dir, config, env, false);
    world.submit_after_start(&mut miner).await;
    let (fulfilled, exited_early) = wait_fulfilled(world, &mut miner, timeout).await;
    tokio::time::sleep(SETTLE).await;
    let stopped = miner.stop(DRAIN_GRACE);
    let failures = check_settlement(
        world,
        &miner.lines(),
        nonce_before,
        &fulfilled,
        exited_early,
        stopped,
    )
    .await;
    report(world, dir, &miner, &failures).await;
}

/// A mining miner must log `needle` `times` times (the gate that holds it, at debug verbosity if
/// `verbose`), dispatch no claim, send nothing, and exit 0 when stopped.
async fn no_claims_after(
    world: World,
    dir: RunDir,
    config: &Path,
    needle: &str,
    times: usize,
    verbose: bool,
) {
    let nonce_before = world.prover_nonce().await;
    let mut miner = start_mining(&world, &dir, config, replay_env(), verbose);
    let mut failures = Vec::new();
    if !wait_for_lines(&mut miner, needle, times, Duration::from_secs(180)).await {
        failures.push(format!("the miner did not log {needle:?} {times} time(s)"));
    }
    tokio::time::sleep(SETTLE).await;
    if world.jobs.iter().any(|j| dispatched(&miner.lines(), j.id)) {
        failures.push("a claim was dispatched".into());
    }
    failures.extend(stop_failure(miner.stop(STOP_GRACE), STOP_GRACE));
    let nonce_after = world.prover_nonce().await;
    if nonce_after != nonce_before {
        failures.push(format!(
            "the prover sent {} transaction(s)",
            nonce_after - nonce_before
        ));
    }
    let claimed = world.jobs_with::<IHemiProveCore::JobClaimed>().await;
    if !claimed.is_empty() {
        failures.push(format!("claimed: {claimed:?}"));
    }
    finish_or_report(world, dir, miner, failures).await;
}

/// Panic with the failures, the miner's log tail and the fork's state, if there are failures.
async fn report(world: &World, dir: &RunDir, miner: &Miner, failures: &[String]) {
    if failures.is_empty() {
        return;
    }
    dump_tail(&dir.0, &miner.lines());
    for l in world.describe_state().await {
        eprintln!("localnet state: {l}");
    }
    panic!(
        "localnet run failed (run directory {}):\n  {}",
        dir.0.display(),
        failures.join("\n  ")
    );
}

async fn finish_or_report(world: World, dir: RunDir, miner: Miner, failures: Vec<String>) {
    report(&world, &dir, &miner, &failures).await;
    drop(miner);
    drop(world);
    dir.finish();
}

/// The occupancy arithmetic on a hand-made log: two cards, the queue empty once the last proof starts.
#[test]
fn occupancy_is_measured_while_work_waits() {
    let line = |at: &str, slot: &str, secs: &str| {
        format!(
            "2026-11-02T17:00:{at}Z  INFO Proof complete on {slot} [Some Card]: 100 cycles in {secs}s"
        )
    };
    // cuda:0 proves over 0-10 s and 12-20 s, rocm:0 over 0-20 s; the last proof starts at 12 s.
    let lines = vec![
        line("10.000000", "risc0:cuda:0", "10.0"),
        line("20.000000", "sp1:rocm:0", "20.0"),
        line("20.000000", "risc0:cuda:0", "8.0"),
        "2026-11-02T17:00:21.000000Z  INFO Job 0x1234 proved on risc0:cuda:0".to_string(),
    ];
    let spans = proof_spans(&lines);
    assert_eq!(spans.len(), 3);
    let o = occupancy(&spans).expect("enough proofs to measure");
    assert!((o.window - 12.0).abs() < 1e-6, "window {}", o.window);
    let share = |card: &str| o.cards.iter().find(|(c, _)| c == card).unwrap().1;
    assert!((share("cuda:0") - 10.0 / 12.0).abs() < 1e-6);
    assert!((share("rocm:0") - 1.0).abs() < 1e-6);
    assert!((o.all_busy - 10.0 / 12.0).abs() < 1e-6);
    // One proof is no window at all.
    assert!(occupancy(&spans[..1]).is_none());
}
