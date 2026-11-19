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
//! - `serves_witness_jobs` (Linux): witness-construction jobs end to end with `[witness] enabled`,
//!   the real broker, builder runner and CPU risc0 worker under the rootless sandbox, a builder
//!   published on the fork as `hemi-code`: one job simulated, pinned, claimed, proven on the CPU,
//!   fulfilled with `fulfillJobHashed` and its bundle deleted; one with a bad binding never claimed;
//!   one from a caller not on `[witness] callers` never simulated. Needs a delegated cgroup: see the
//!   witness section at the end of this file.
//! - `serves_the_proxy_slots_witness_job` and `serves_the_proxy_slots_witness_job_on_a_gpu`
//!   (Linux): plan §12's job end to end, on the CPU worker and on a GPU worker: a second anvil as the
//!   `evm-rpc` chain, the reference builder published with `zkminer artifact publish`, the job made
//!   with the requester tools, its `publicValues` checked against that chain's state. See the
//!   witness section.
//!
//! risc0 3.1 (P31-19, B9-CHAIN): the 743111 deployment of 2026-11-16 verifies risc0 3.1 receipts only
//! (risc0-ethereum v3.1.0 `RiscZeroGroth16Verifier`, SELECTOR 0xe71e6620, the selector this build
//! derives from the linked risc0, see `risc0_groth16_default_selector` in `run.rs`). So:
//! - the replay tests replay a risc0 3.1 Groth16 receipt made by the Metal worker (the fibonacci
//!   benchmark guest, [`FIXTURE_IMAGE_ID`]), under the build's own selector: no override;
//! - `refuses_to_claim_without_a_matching_verifier` is the negative case: a miner configured with
//!   the risc0 3.0 selector (0x73c457ba, acknowledged with `ZKMINER_RISC0_SELECTOR_OVERRIDE_UNSAFE=1`)
//!   must refuse every risc0 claim (zkminer-chain refuses a 3.0 seal prefix before any eth_call);
//! - the tests that prove with the real risc0 worker (`watch_only_reports_every_job`,
//!   `mines_the_claimable_jobs`, `mines_on_every_gpu`) run whenever zkminer-chain pins a verifier for
//!   the build's selector (it does: `pins::RISC0_V3_1_GROTH16_VERIFIER`). On macOS point
//!   `ZKMINER_LOCALNET_RISC0_WORKER` at `target/release/zkminer-prove-risc0-metal`.
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

/// The 743111 block the fork starts from by default, after the deployment's setup: the 2026-11-16
/// stack's router exists from block 7226099 and its three adapters are registered by 7226300. Move it
/// forward whenever `zkminer_chain::deployment::HEMI_TESTNET_743111` changes: the fork would otherwise
/// run the old deployment, and zkminer's startup checks refuse it. A later block is fine even once
/// someone registers this test's programs on 743111 (their ids are content-derived): setup clears
/// such a registration first (see [`register_program`]).
const FORK_BLOCK: u64 = 7_234_420;
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
/// The replayed receipt: a risc0 3.1 Groth16 receipt of the fibonacci benchmark guest (image id
/// below, input 1000), made by the Metal worker (`zkminer-prove-risc0-metal --benchmark` with
/// `ZKMINER_BENCH_RECEIPT_DIR`, B9-CHAIN 2026-11-17) and checked with the stock crates.io risc0-zkvm
/// 3.1.0 verifier and by `eth_call` against the live 743111 `RiscZeroGroth16Verifier` (v3.1.0).
const FIXTURE_IMAGE_ID: B256 =
    alloy::primitives::b256!("245dd297a191e76f29e9263832a6653d19e34f4ebbe0ca5ad8bbd14e8e3158aa");
/// The fixture's journal: the guest's 8-byte commit (`4b60c05cc74d590b`).
const FIXTURE_JOURNAL: &[u8] = &[0x4b, 0x60, 0xc0, 0x5c, 0xc7, 0x4d, 0x59, 0x0b];
/// The fixture's 260-byte seal: the 4-byte selector (0xe71e6620), then the proof.
const FIXTURE_SEAL_HEX: &str = concat!(
    "e71e6620146c454daa44bad2f5d36d5477dc27c2b64fd4d3f4f602457547b084f6b86e0a15d0c20accf4de29f0bc86efd99b5daa",
    "18f1ddd867ef8f05dc8d838f187d01b3109493f74fcee83b89af088c5ac2ebcc1eb8313c0b140f6c11d5e50da2eacedb0ecbe8c7",
    "79b336b5976a31e9305f0a64396f2378766a906951290c04cc4db32902c5dca5357b00358c74f80889414fa610501840d0f9c88c",
    "a534d6ae62bd6d380a33174af80706d2598ac6fc60a56f8a83c6a9018115aa9cf229fb9245bfcd961b5a3b2317d60ac7e563a8f7",
    "ef69b9dd6108f6c67bd2a4df735319fa400ed8890aef08f62664338e766b0fbda032d6f57e3d234b9e1b6c0818e036b463dd0bab",
);

/// This build's default RISC Zero seal selector, derived as `run.rs` derives it from the linked risc0.
fn build_selector() -> [u8; 4] {
    use risc0_zkvm::sha::Digestible;
    let d = risc0_zkvm::Groth16ReceiptVerifierParameters::default().digest();
    d.as_bytes()[..4].try_into().unwrap()
}

/// Whether the real risc0 worker's proofs can verify on the fork: zkminer-chain pins an audited
/// verifier for this build's seal selector (`deployment::risc0_verifier_pin`, B9-ZK), so the gate
/// follows the pin: on risc0 3.1 it opens by itself once `pins::RISC0_V3_1_GROTH16_VERIFIER` is
/// filled. Until then (P31-19: the 743111 verifier is v3.0) the test reports SKIPPED unless
/// `ZKMINER_LOCALNET_FORCE_RISC0=1`.
fn risc0_proofs_verify_on_the_fork(test: &str) -> bool {
    let pin = zkminer_chain::deployment::risc0_verifier_pin(build_selector());
    if pin.is_ok() || env_flag("ZKMINER_LOCALNET_FORCE_RISC0") {
        return true;
    }
    eprintln!(
        "localnet: SKIPPED {test} (it did not run): this build's risc0 seals carry selector 0x{} and \
         no verifier is pinned for it ({}), so every risc0 claim is refused; set \
         ZKMINER_LOCALNET_FORCE_RISC0=1 on a fork with a matching verifier",
        alloy::hex::encode(build_selector()),
        pin.err().unwrap_or_default()
    );
    false
}

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
/// submitter may ask (hemiprove-contracts 3bc441d, `src/libraries/Constants.sol`).
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
    /// submitted (see [`World::new`]). A backfill that started a block late would lose that job. A
    /// world with no inline cases (the witness test) starts at the first block after setup began.
    fn scan_from_block(&self) -> u64 {
        if self.cases.is_empty() {
            return self.from_block;
        }
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
        // The programs are served from this machine (127.0.0.1), which the network guard refuses
        // outside developer mode. The config file is the only switch: there is no environment
        // variable for it, and the miner refuses it on mainnet (the fork is 743111). It names the
        // chain it is meant for, which the RPC confirms at startup.
        c.dev.private_network = true;
        c.dev.chain_id = Some(c.chain.chain_id);
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
    /// (hemiprove-contracts 3bc441d, `src/core/ProgramRegistry.sol`).
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
        // A config that names a selector other than this build's (the 3.0 one, in
        // `refuses_to_claim_without_a_matching_verifier`) is refused unless acknowledged (P31-19);
        // acknowledge it so that the refusal under test is zkminer-chain's verifier pin.
        if std::fs::read_to_string(config)
            .map(|c| c.contains("risc0_groth16_selector"))
            .unwrap_or(false)
        {
            cmd.env("ZKMINER_RISC0_SELECTOR_OVERRIDE_UNSAFE", "1");
        }
        cmd.env("HOME", dir)
            .env("PATH", path_without_workers())
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
    if !risc0_proofs_verify_on_the_fork("watch_only_reports_every_job") {
        return;
    }
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
    // Served from 127.0.0.1 because the config's `[dev] private_network` let it, and said so.
    if !lines
        .iter()
        .any(|l| l.contains(zkminer_config::DEV_MODE_BANNER))
    {
        failures.push("the miner never announced developer mode".into());
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

/// `zkminer simulate` over every job: the RISC Zero program's cases, and with
/// `ZKMINER_LOCALNET_SP1_WORKER` set the SP1 program's too (its vkey derived on the CPU, minutes).
/// Each measurable job must come back `measured` with its program bound (image id / vkey), a risc0
/// count a power of two (one segment), the binding verdict its case implies, no host input and the
/// worker's SDK; the decoy ELF must come back `program_mismatch` (its URI's content hash vouches for
/// those bytes) and the unreachable one `unavailable`; a journal-prefix job, open (no prover to name
/// in its input), `unavailable` under risc0 and `not_served` under SP1 (never reproducible); an
/// unknown job id `unavailable`. Then through `--stdin`, with submit-tx hints and the public values a
/// fulfil would carry, a READY line first, the same outcomes and counts, `proven` matching the honest
/// journal and differing from another, and the decoy and the unreachable ELF answered from the
/// memory of the first run. Every run has a HOME it cannot write, as the indexer's unit gives it:
/// the risc0 journal still comes back, so the bindings are judged. And `--max-cycles` below a count
/// makes it `too_heavy`. Nothing is sent.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs anvil, the release risc0 worker (a CPU one serves) and the 743111 RPC; see the module docs"]
async fn simulate_reports_every_job() {
    let dir = RunDir::new("simulate");
    let risc0 = risc0_worker();
    let sp1 = std::env::var("ZKMINER_LOCALNET_SP1_WORKER")
        .ok()
        .map(PathBuf::from);
    let mut programs = vec![Program::fibonacci(&risc0, &dir.0)];
    if let Some(w) = &sp1 {
        programs.push(Program::sp1_fibonacci(w, &dir.0));
    }
    let n_programs = programs.len();
    let mut world = World::with_programs(&dir.0, programs, &Case::ALL, Clock::Wall, vec![1]).await;
    world.submit_held_back().await;
    let config = world.write_config(&dir.0, &risc0, false);
    let mut args: Vec<String> = vec![
        "--risc0-worker".into(),
        risc0.display().to_string(),
        "--cache-dir".into(),
        dir.0.join("simulate-cache").display().to_string(),
    ];
    if let Some(w) = &sp1 {
        args.extend(["--sp1-worker".into(), w.display().to_string()]);
    }
    // A HOME it cannot write, as the indexer's unit gives it (ProtectSystem=strict): no sys_rand key
    // file can be read or made there, and none is needed.
    let home = dir.0.join("read-only-home");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::set_permissions(&home, std::os::unix::fs::PermissionsExt::from_mode(0o500)).unwrap();
    let home_env = [("HOME", home.display().to_string())];
    let unknown = keccak256(b"zkminer localnet: no such job");
    let mut run_args = args.clone();
    for job in &world.jobs {
        run_args.extend(["--job".into(), job.id.to_string()]);
    }
    run_args.extend(["--job".into(), unknown.to_string()]);
    let argv: Vec<&str> = run_args.iter().map(String::as_str).collect();
    let out = Miner::command(&dir.0, &config, &[], "simulate", &argv, &home_env)
        .stdin(Stdio::null())
        .output()
        .expect("run zkminer simulate");
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    std::fs::write(dir.0.join("simulate.log"), &stderr).ok();
    let mut failures: Vec<String> = Vec::new();
    if !out.status.success() {
        failures.push(format!("zkminer simulate exited {}", out.status));
    }
    let reports: Vec<serde_json::Value> = String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(|l| serde_json::from_str(l).unwrap_or_else(|e| panic!("not a JSON report ({e}): {l}")))
        .collect();
    if reports.len() != world.jobs.len() + 1 {
        failures.push(format!(
            "{} reports for {} requests",
            reports.len(),
            world.jobs.len() + 1
        ));
    }
    let report_of = |id: B256| {
        reports
            .iter()
            .find(|r| r["jobId"].as_str() == Some(&id.to_string()))
            .cloned()
    };
    let mut sp1_derivations = 0;
    for job in &world.jobs {
        let program = world.program_of(job);
        let sp1_job = is_sp1_id(program.proof_system);
        let Some(r) = report_of(job.id) else {
            failures.push(format!("{:?} ({}): no report", job.case, program.name));
            continue;
        };
        let what = format!("{:?} ({})", job.case, program.name);
        let outcome = r["outcome"].as_str().unwrap_or_default();
        match job.case {
            Case::DecoyElf => {
                // The decoy serves the risc0 guest. Its image id is not the job's: a mismatch. Under
                // SP1, setup either derives a vkey that is not the job's (a mismatch) or refuses the
                // bytes, which SP1 reports as a retryable failure (setup can fail for the host too).
                let ok = outcome == "program_mismatch" || (sp1_job && outcome == "failed" && r["retryable"] == true);
                if !ok {
                    failures.push(format!("{what}: {outcome}, not program_mismatch: {r}"));
                }
            }
            Case::ElfUnreachable => {
                if outcome != "unavailable" || r["retryable"] != true {
                    failures.push(format!("{what}: {outcome}, not a retryable unavailable: {r}"));
                }
            }
            Case::PrefixMarker => {
                // Its input begins with abi.encode(jobId, prover), and an open job has no prover (for
                // now: retryable); an SP1 guest reads the prefix as a stdin buffer of its own, which
                // simulate can never pass (final).
                let (want, retryable) = if sp1_job { ("not_served", false) } else { ("unavailable", true) };
                let reason = r["reason"].as_str().unwrap_or_default();
                if outcome != want || r["retryable"] != retryable || !reason.contains("journal-prefix") {
                    failures.push(format!("{what}: {outcome}, not {want} (retryable {retryable}) for its prefix: {r}"));
                }
            }
            case => {
                if outcome != "measured" {
                    failures.push(format!("{what}: {outcome}, not measured: {r}"));
                    continue;
                }
                let cycles: u64 = r["cycles"].as_str().and_then(|c| c.parse().ok()).unwrap_or(0);
                let check = r["programCheck"].as_str().unwrap_or_default();
                if sp1_job {
                    if check != "vkey" || cycles == 0 || !r["po2"].is_null() {
                        failures.push(format!("{what}: an SP1 measurement must be vkey-bound, nonzero and have no po2: {r}"));
                    }
                    if r["programCheckSecs"].as_f64().unwrap_or(0.0) > 0.0 {
                        sp1_derivations += 1;
                    }
                } else if check != "image_id" || !cycles.is_power_of_two() || r["po2"] != 20 {
                    failures.push(format!("{what}: a risc0 measurement must be image-id-bound, a power of two at po2 20: {r}"));
                }
                let binding = r["binding"].as_str().unwrap_or_default();
                let want = match case {
                    Case::Full | Case::Fields | Case::FullForAnother | Case::FullExclusiveForAnother | Case::HighCollateral => Some("satisfied"),
                    Case::FullWrongJournal | Case::FieldsWrongJournal => Some("fails"),
                    Case::NoneForUs | Case::NoneForAnother => Some("none"),
                    _ => None,
                };
                if want.is_some_and(|w| w != binding) {
                    failures.push(format!("{what}: binding {binding}, expected {want:?}: {r}"));
                }
                if r["inputBytes"] != program.input.len() as u64 {
                    failures.push(format!("{what}: inputBytes {} for a {}-byte input", r["inputBytes"], program.input.len()));
                }
                // No public values were sent; the guest reads no host entropy (risc0: none past its
                // runtime's draw, counted; SP1: none to read); the worker names its SDK.
                if r["proven"] != "unknown" || r["hostInput"] != false || r["hostInputReads"] != 0 {
                    failures.push(format!("{what}: proven unknown, hostInput false and 0 reads expected: {r}"));
                }
                if !r["sdkVersion"].as_str().is_some_and(|v| !v.is_empty()) {
                    failures.push(format!("{what}: no sdkVersion: {r}"));
                }
                if r["journalHash"] != serde_json::json!(keccak256(&program.journal).to_string()) {
                    failures.push(format!("{what}: the journal did not come back under a read-only HOME: {r}"));
                }
            }
        }
    }
    if sp1.is_some() && sp1_derivations != 1 {
        failures.push(format!("the SP1 vkey was derived {sp1_derivations} times, not once and then cached"));
    }
    match report_of(unknown) {
        Some(r) if r["outcome"] == "unavailable" => {}
        other => failures.push(format!("an unknown job id: {other:?}")),
    }

    // The same through --stdin, as the indexer asks: the submitting tx as a hint and the public
    // values a fulfil would carry (the honest journal, then another), a garbage line skipped, a bare
    // id; the decoy and the unreachable ELF now answered from the first run's memory; and every SP1
    // vkey from the cache.
    let submitted = world.logs::<IHemiProveCore::JobSubmitted>().await;
    let risc0_job = |case: Case| {
        world
            .jobs
            .iter()
            .find(|j| j.case == case && !is_sp1_id(world.program_of(j).proof_system))
            .unwrap_or_else(|| panic!("no risc0 {case:?} job"))
    };
    let (first, second) = (risc0_job(Case::Full), risc0_job(Case::Fields));
    let (decoy, unreachable) = (risc0_job(Case::DecoyElf), risc0_job(Case::ElfUnreachable));
    let tx = submitted
        .iter()
        .find(|(id, _)| *id == first.id)
        .map(|(_, l)| l.tx)
        .expect("the first job's JobSubmitted");
    let program = world.program_of(first);
    let hex = |b: &[u8]| format!("0x{}", alloy::hex::encode(b));
    let input = format!(
        "{{\"jobId\":\"{}\",\"submitTx\":\"{tx}\",\"publicValues\":\"{}\"}}\nnot a request\n{}\n\
         {{\"jobId\":\"{}\",\"publicValues\":\"{}\"}}\n{}\n{}\n",
        first.id,
        hex(&program.journal),
        second.id,
        first.id,
        hex(&program.wrong_journal()),
        decoy.id,
        unreachable.id,
    );
    let argv: Vec<&str> = args.iter().map(String::as_str).chain(["--stdin"]).collect();
    let mut child = Miner::command(&dir.0, &config, &[], "simulate", &argv, &home_env)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start zkminer simulate --stdin");
    child.stdin.take().unwrap().write_all(input.as_bytes()).unwrap();
    let out = child.wait_with_output().expect("wait for zkminer simulate --stdin");
    if !out.status.success() {
        failures.push(format!("zkminer simulate --stdin exited {}", out.status));
    }
    let lines: Vec<serde_json::Value> = String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(|l| serde_json::from_str(l).unwrap_or_else(|e| panic!("--stdin: not JSON ({e}): {l}")))
        .collect();
    // First, before any request is read: READY, naming the backends with a live measure worker.
    let mut backends = vec!["risc0"];
    if sp1.is_some() {
        backends.push("sp1");
    }
    let ready = serde_json::json!({
        "schema": 1,
        "ready": true,
        "backends": backends,
        "zkminerVersion": env!("CARGO_PKG_VERSION"),
        "protocolVersion": zkminer_prover_protocol::PROTOCOL_VERSION,
        "sysRandRule": zkminer_prover_protocol::sys_rand::SYS_RAND_RULE,
    });
    if lines.first() != Some(&ready) {
        failures.push(format!("--stdin's first line is {:?}, not {ready}", lines.first()));
    }
    let ids: Vec<String> = lines.iter().filter_map(|r| r["jobId"].as_str().map(str::to_string)).collect();
    let want_ids: Vec<String> = [first.id, second.id, first.id, decoy.id, unreachable.id]
        .iter()
        .map(|id| id.to_string())
        .collect();
    if ids != want_ids {
        failures.push(format!("--stdin reported {ids:?}"));
    }
    // One line out per line in: the garbage line is answered, in its place.
    let shape: Vec<&str> = lines
        .iter()
        .map(|r| {
            if r["ready"] == true {
                "ready"
            } else if r["error"] == "invalid_request" {
                "invalid"
            } else {
                "report"
            }
        })
        .collect();
    if shape != ["ready", "report", "invalid", "report", "report", "report", "report"] {
        failures.push(format!("--stdin answered {shape:?}"));
    }
    let reports: Vec<&serde_json::Value> = lines.iter().filter(|r| r["jobId"].is_string()).collect();
    // A measured risc0 run names the seed rule the indexer requires; SP1, with no host seed, names none.
    for r in reports.iter().filter(|r| r["outcome"] == "measured") {
        let want = (r["backend"] == "risc0").then_some(zkminer_prover_protocol::sys_rand::SYS_RAND_RULE);
        if r["sysRandRule"].as_str() != want {
            failures.push(format!("--stdin: a measured report should name rule {want:?}: {r}"));
        }
        let size = (r["backend"] == "risc0").then_some("same");
        if r["sizeCheck"].as_str() != size {
            failures.push(format!("--stdin: a measured report should say sizeCheck {size:?}: {r}"));
        }
    }
    // The indexer's own path gives what `--job` gave for the measurable ones, and says whether the
    // count is of the proven run: the honest journal matches, another differs, none is unknown.
    for (r, proven) in reports.iter().take(3).zip(["matches", "unknown", "differs"]) {
        let id: B256 = r["jobId"].as_str().unwrap().parse().unwrap();
        let Some(via_job) = report_of(id) else {
            failures.push(format!("--stdin: {id} has no --job report"));
            continue;
        };
        for field in ["outcome", "retryable", "cycles", "po2", "binding", "programCheck", "elfHash", "inputHash", "journalHash", "hostInput", "sdkVersion"] {
            if r[field] != via_job[field] {
                failures.push(format!(
                    "--stdin's {field} for {id} is {}, --job's {}",
                    r[field], via_job[field]
                ));
            }
        }
        let cycles: u64 = r["cycles"].as_str().and_then(|c| c.parse().ok()).unwrap_or(0);
        if r["outcome"] != "measured" || cycles == 0 {
            failures.push(format!("--stdin: {id} not measured with a count: {r}"));
        }
        if r["proven"] != proven || r["hostInput"] != false {
            failures.push(format!("--stdin: {id} should be proven {proven} with no host input: {r}"));
        }
    }
    // Remembered: the decoy's verdict (its URI still vouches for the bytes), and the unreachable
    // ELF's fetch failure, neither fetched again.
    for (r, outcome) in reports.iter().skip(3).zip(["program_mismatch", "unavailable"]) {
        let reason = r["reason"].as_str().unwrap_or_default();
        if r["outcome"] != outcome || !reason.contains("remembered from") || !r["elfHash"].is_null() {
            failures.push(format!("--stdin: {outcome} from memory expected: {r}"));
        }
    }
    if !String::from_utf8_lossy(&out.stderr).contains("skipping a request line") {
        failures.push("--stdin did not say it skipped the garbage line".into());
    }
    for r in &lines {
        if r["programCheckSecs"].as_f64().unwrap_or(0.0) > 0.0 && r["programCheck"] == "vkey" {
            failures.push(format!("--stdin derived an SP1 vkey the cache holds: {r}"));
        }
    }

    // `--max-cycles` below the count: `too_heavy`, final, the count only in the reason.
    let mut capped: Vec<String> = args.clone();
    capped.extend(["--max-cycles".into(), "1".into(), "--job".into(), first.id.to_string()]);
    let argv: Vec<&str> = capped.iter().map(String::as_str).collect();
    let out = Miner::command(&dir.0, &config, &[], "simulate", &argv, &home_env)
        .stdin(Stdio::null())
        .output()
        .expect("run zkminer simulate --max-cycles 1");
    let capped: Vec<serde_json::Value> = String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect();
    match capped.as_slice() {
        [r] if r["outcome"] == "too_heavy"
            && r["retryable"] == false
            && r["cycles"].is_null()
            && r["reason"].as_str().is_some_and(|w| w.contains("--max-cycles")) => {}
        other => failures.push(format!("--max-cycles 1: {other:?}")),
    }
    std::fs::set_permissions(&home, std::os::unix::fs::PermissionsExt::from_mode(0o700)).ok();
    if std::fs::read_dir(&home).map_or(true, |mut d| d.next().is_some()) {
        failures.push("simulate wrote under its HOME".into());
    }

    // Simulating sends nothing.
    let anvil_log = std::fs::read_to_string(dir.0.join("anvil.log")).unwrap_or_default();
    if anvil_log.matches("eth_sendRawTransaction").count() > 0 {
        failures.push("the node received a raw transaction".into());
    }
    eprintln!(
        "localnet: simulate covered {} jobs over {n_programs} program(s)",
        world.jobs.len()
    );
    if !failures.is_empty() {
        let tail: Vec<String> = stderr.lines().rev().take(60).map(str::to_string).collect();
        dump_tail(&dir.0, &tail.into_iter().rev().collect::<Vec<_>>());
        panic!(
            "simulate localnet run failed (run directory {}):\n  {}",
            dir.0.display(),
            failures.join("\n  ")
        );
    }
    dir.finish();
}

/// Serves a fork set up as [`simulate_reports_every_job`]'s (the risc0 program's cases, and the SP1
/// program's with `ZKMINER_LOCALNET_SP1_WORKER`) to a `zkminer simulate` consumer run by hand, such
/// as an indexer's runner: writes `simulate-jobs.json` (each job's id, submit tx, case and program)
/// and the miner config into the run directory, says READY, and keeps the fork up until a `stop`
/// file appears there (or `ZKMINER_LOCALNET_SERVE_SECS`, default 3600). CPU only.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "serves a localnet to a simulate consumer run by hand; set ZKMINER_LOCALNET_SERVE=1"]
async fn serves_jobs_to_simulate() {
    if !env_flag("ZKMINER_LOCALNET_SERVE") {
        eprintln!("localnet: SKIPPED; set ZKMINER_LOCALNET_SERVE=1 to serve one");
        return;
    }
    let dir = RunDir::new("serve-simulate");
    let risc0 = risc0_worker();
    let mut programs = vec![Program::fibonacci(&risc0, &dir.0)];
    if let Ok(w) = std::env::var("ZKMINER_LOCALNET_SP1_WORKER") {
        programs.push(Program::sp1_fibonacci(Path::new(&w), &dir.0));
    }
    let mut world = World::with_programs(&dir.0, programs, &Case::ALL, Clock::Wall, vec![1]).await;
    world.submit_held_back().await;
    let config = world.write_config(&dir.0, &risc0, false);
    let submitted = world.logs::<IHemiProveCore::JobSubmitted>().await;
    let jobs: Vec<serde_json::Value> = world
        .jobs
        .iter()
        .map(|j| {
            let tx = submitted
                .iter()
                .find(|(id, _)| *id == j.id)
                .map(|(_, l)| l.tx.to_string());
            serde_json::json!({
                "jobId": j.id.to_string(),
                "submitTx": tx,
                "case": format!("{:?}", j.case),
                "program": world.program_of(j).name,
                "proofSystem": world.program_of(j).proof_system.to_string(),
            })
        })
        .collect();
    let list = dir.0.join("simulate-jobs.json");
    std::fs::write(&list, serde_json::to_string_pretty(&jobs).unwrap()).unwrap();
    let stop = dir.0.join("stop");
    let secs: u64 = std::env::var("ZKMINER_LOCALNET_SERVE_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(3_600);
    eprintln!(
        "localnet: READY. {} jobs on the fork at {}; jobs in {}, miner config {}; stop with: touch {}",
        jobs.len(),
        world.rpc_url,
        list.display(),
        config.display(),
        stop.display()
    );
    let started = Instant::now();
    while started.elapsed() < Duration::from_secs(secs) && !stop.exists() {
        tokio::time::sleep(Duration::from_secs(1)).await;
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

/// P31-19 / B9-CHAIN, the 3.0 negative case: a miner whose seals carry the risc0 3.0 selector
/// (0x73c457ba, configured and acknowledged) against the fork's risc0 3.1 verifier. Its startup check
/// refuses risczero.groth16.v1 (`deployment::risc0_verifier_pin` refuses a 3.0 seal prefix before
/// any verifier call), so the brain holds the job and nothing is sent: a claim would lock collateral
/// for a fulfil that can only revert.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs anvil, the mock worker and the 743111 RPC; see the module docs"]
async fn refuses_to_claim_without_a_matching_verifier() {
    let old = zkminer_chain::deployment::pins::RISC0_V3_0_SELECTOR;
    assert_ne!(build_selector(), old, "this build proves risc0 3.1");
    let dir = RunDir::new("selector");
    let worker = mock_worker();
    let world = World::new(&dir.0, Program::fixture(), &[Case::Full], Clock::Wall).await;
    let config = world.write_config(&dir.0, &worker, false);
    let mut c = ZkMinerConfig::load(Some(&config)).expect("read the miner config back");
    c.prover.risc0_groth16_selector = Some(format!("0x{}", alloy::hex::encode(old)));
    c.save(Some(&config)).expect("write the miner config");
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
    if !risc0_proofs_verify_on_the_fork("mines_the_claimable_jobs") {
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
    if !risc0_proofs_verify_on_the_fork("mines_on_every_gpu") {
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
        // To steer jobs onto particular NVIDIA cards: the host's RAM may hold one SP1 proof at a
        // time (each may stage 24 GiB), so it lands on the same card unless others are hidden.
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
                    // Handoff §4/§13 test 6: payout = settledPrice + speedBonus - 1% protocol fee
                    // (100 bps on 743111), paid to the prover's wallet.
                    let gross = U256::from(f.event.settledPrice) + f.event.speedBonus;
                    let fee = gross * U256::from(100u64) / U256::from(10_000u64);
                    if f.event.protocolFee != fee || f.event.proverPayout != gross - fee {
                        failures.push(format!(
                            "{:?}: JobFulfilled pays {} with fee {}, not settledPrice {} + \
                             speedBonus {} - 1% ({} with fee {fee})",
                            job.case,
                            f.event.proverPayout,
                            f.event.protocolFee,
                            f.event.settledPrice,
                            f.event.speedBonus,
                            gross - fee
                        ));
                    } else {
                        eprintln!(
                            "localnet: {:?}: JobFulfilled payout {} = settledPrice {} + speedBonus \
                             {} - fee {}",
                            job.case,
                            f.event.proverPayout,
                            f.event.settledPrice,
                            f.event.speedBonus,
                            f.event.protocolFee
                        );
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

// ── witness-construction jobs ─────────────────────────────────────────────────────────────────────
//
// `serves_witness_jobs`: the miner with `[witness] enabled` on the fork, end to end, with the real
// broker, builder runner and CPU risc0 worker under the rootless sandbox. The SDK's `params-echo`
// test builder is published on the fork as `hemi-code` (its chunks and manifest deployed with
// `manifest::creation_code`); it writes its `builderParams` as `W`, and the fibonacci guest reads
// `n` from `W` and commits `fib(n)`. Three witness jobs are submitted: one FULL-bound job from an
// allowlisted caller (simulated, pinned, claimed, proven on the CPU, fulfilled with
// `fulfillJobHashed`, its bundle deleted once Fulfilled), one whose binding names a journal the guest
// does not commit (simulated and skipped, never claimed), and one from a caller not on
// `[witness] callers` (never simulated, never claimed).
//
// `serves_the_proxy_slots_witness_job` (and `..._on_a_gpu`): plan §12's job end to end. A second
// anvil (chain 31337, standing for Base) is the `evm-rpc/v1` chain: an EIP-1967 proxy is deployed on
// it and changed by real transactions before and after the block B the job pins (an upgrade and slot
// writes through the proxy; `anvil_set*` would rewrite the head block's state in place, and B's proofs
// with it). The reference builder (`sdk/examples/proxy-slots`) is published on the fork by `zkminer
// artifact publish`; the reference guest (`reference/proxy-slots/guest`, exported by the methods
// crate) is registered in the ProgramRegistry and served as the other tests serve theirs; and the
// job is made by the requester tools (`zkminer witness envelope encode`, `witness binding compute`
// and `check`): FIELDS over the 160-byte header with the journal-prefix marker, assigned to the
// miner's prover with an exclusivity window. The miner's broker reads the second anvil as its
// `evm-rpc` endpoint and the fork as its artifact endpoint. The job must be simulated before its
// claim, claimed, executed, compared and proven, and fulfilled with `fulfillJobHashed`, and
// `JobFulfilled.publicValues` must be byte for byte the journal of the second chain's state at B
// (its implementation, that one's code hash and the slots' values, read from the second anvil at B,
// where they differ from its head). The CPU test proves on the CPU worker (a debug build: the guest's
// one 2^20 segment and the Groth16 wrap took 24 minutes on a busy 32-core host); the GPU test on
// `ZKMINER_LOCALNET_RISC0_WORKER` (default the release CUDA worker; 4 s on an RTX 4090), with the
// CPU worker still the sandboxed execute. With `CUDA_VISIBLE_DEVICES` set, that worker is named
// outright and proves on the cards it allows; unset, the miner discovers one worker per card the
// binary covers (the way to run an AMD or Intel worker, which the dispatcher then pins and tunes per
// card). A real Groth16 seal: the fork's verifier accepts it at fulfil.
//
// Needs a delegated cgroup, anvil, the 743111 RPC and the SDK's pinned toolchain; the §12 tests also
// need the risc0 toolchain (rzup), with which the methods crate builds the guest:
//
// ```text
// systemd-run --user --scope -q -p Delegate=yes -- env ZKMINER_SANDBOX_TESTS_REQUIRED=1 \
//     cargo test -p zkminer-cli --test localnet serves_witness_jobs -- --ignored --nocapture
// systemd-run --user --scope -q -p Delegate=yes -- env ZKMINER_SANDBOX_TESTS_REQUIRED=1 \
//     cargo test -p zkminer-cli --test localnet serves_the_proxy_slots_witness_job -- --ignored \
//     --nocapture --exact
// ```
//
// They build the builder runner, the broker, the sandbox probe and (unless
// `ZKMINER_LOCALNET_RISC0_CPU_WORKER` names one) `zkminer-prove-risc0-cpu` into this test's target
// dir. The miner runs in developer mode (`[dev] private_network`: anvil and the ELF server are on
// 127.0.0.1) with a fixed DA backlog reading (`[dev] da_backlog_bytes`: anvil's receipts carry no
// `l1GasUsed`). The broker's endpoints are local anvils its `chain_rpc_host` is told otherwise: a
// real deployment never shares them with the miner's chain RPC.

#[cfg(target_os = "linux")]
mod witness_support {
    use super::*;
    use alloy::eips::{BlockId, BlockNumberOrTag};
    use hemiprove_proxy_slots::{Rule, RuleKind, Statement, EIP1967_IMPLEMENTATION_SLOT};
    use zkminer_config::witness::{BrokerSection, RetentionConfig, SandboxModeConfig, UnitPrices};
    use zkminer_witness::envelope::{
        encode_envelope, encode_evm_rpc_config, Capability, Limits, WitnessJobV1, CLASS_EVM_RPC_V1,
        METHOD_SET_STATE_READ,
    };
    use zkminer_witness::manifest::{chunk_runtime_code, creation_code, manifest_runtime_code, sha256};

    /// `<target>/debug`, where this test binary's workspace binaries are.
    pub fn target_debug_dir() -> PathBuf {
        std::env::current_exe()
            .unwrap()
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .to_path_buf()
    }

    fn cargo_build(args: &[&str]) {
        let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
        let target = target_debug_dir().parent().unwrap().to_path_buf();
        let out = Command::new(cargo)
            .current_dir(workspace_root())
            .arg("build")
            .args(args)
            .arg("--target-dir")
            .arg(&target)
            .output()
            .expect("run cargo");
        assert!(
            out.status.success(),
            "cargo build {args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    pub struct Bins {
        pub builder: PathBuf,
        pub broker: PathBuf,
        pub probe: PathBuf,
        pub cpu_worker: PathBuf,
    }

    /// The sandboxed binaries and the CPU risc0 worker (built here, one cargo at a time).
    pub fn bins() -> Bins {
        cargo_build(&[
            "-p",
            "zkminer-witness-builder",
            "-p",
            "zkminer-witness-broker",
            "-p",
            "zkminer-witness-sandbox",
            "--bins",
        ]);
        let debug = target_debug_dir();
        let cpu_worker = match std::env::var_os("ZKMINER_LOCALNET_RISC0_CPU_WORKER") {
            Some(p) => PathBuf::from(p),
            None => {
                cargo_build(&[
                    "-p",
                    "zkminer-prove-risc0",
                    "--features",
                    "cpu",
                    "--bin",
                    "zkminer-prove-risc0-cpu",
                ]);
                debug.join("zkminer-prove-risc0-cpu")
            }
        };
        Bins {
            builder: debug.join("zkminer-witness-builder"),
            broker: debug.join("zkminer-witness-broker"),
            probe: debug.join("zkminer-witness-sandbox-probe"),
            cpu_worker,
        }
    }

    fn sdk_dir() -> PathBuf {
        workspace_root().join("sdk").canonicalize().unwrap()
    }

    fn sdk_tool(tool: &str) -> std::ffi::OsString {
        let out = Command::new("rustup")
            .args(["which", tool])
            .current_dir(sdk_dir())
            .env_remove("RUSTUP_TOOLCHAIN")
            .output();
        match out {
            Ok(o) if o.status.success() => String::from_utf8(o.stdout).unwrap().trim().into(),
            _ => tool.into(),
        }
    }

    /// An SDK builder (`package`, its module `file`), built with the SDK's pinned toolchain, one
    /// package per invocation (unified features would change a module's bytes).
    fn sdk_wasm(package: &str, file: &str) -> Vec<u8> {
        let target =
            Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("sdk-target-localnet-{package}"));
        let mut cmd = Command::new(sdk_tool("cargo"));
        cmd.current_dir(sdk_dir())
            .args([
                "build",
                "--locked",
                "--release",
                "--target",
                "wasm32-unknown-unknown",
                "-p",
                package,
                "--target-dir",
            ])
            .arg(&target)
            .env("RUSTC", sdk_tool("rustc"));
        for v in [
            "RUSTUP_TOOLCHAIN",
            "RUSTFLAGS",
            "CARGO_ENCODED_RUSTFLAGS",
            "CARGO_BUILD_RUSTFLAGS",
            "CARGO_TARGET_DIR",
        ] {
            cmd.env_remove(v);
        }
        let out = cmd.output().expect("run the SDK's cargo");
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
        std::fs::read(target.join(format!("wasm32-unknown-unknown/release/{file}"))).unwrap()
    }

    /// The SDK's `params-echo` test builder.
    pub fn params_echo_wasm() -> Vec<u8> {
        sdk_wasm("params-echo", "params_echo.wasm")
    }

    /// Plan §12's reference builder (`sdk/examples/proxy-slots`).
    pub fn proxy_slots_wasm() -> Vec<u8> {
        sdk_wasm("proxy-slots-builder", "proxy_slots_builder.wasm")
    }

    /// Plan §12's reference guest (risc0's program binary) and its image id, exported by the methods
    /// crate, whose build script builds the guest with risc0-build (the risc0 toolchain).
    pub fn proxy_slots_guest(dir: &Path) -> (Vec<u8>, B256) {
        let path = dir.join("proxy-slots.bin");
        let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
        let target = target_debug_dir().parent().unwrap().to_path_buf();
        let out = Command::new(cargo)
            .current_dir(workspace_root())
            .args(["run", "-q", "-p", "hemiprove-proxy-slots-methods", "--example", "export-guest"])
            .arg("--target-dir")
            .arg(&target)
            .args(["--", "proxy-slots"])
            .arg(&path)
            .output()
            .expect("run cargo");
        assert!(
            out.status.success(),
            "export the proxy-slots guest: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let id: B256 = String::from_utf8_lossy(&out.stdout)
            .trim()
            .parse()
            .expect("export-guest prints the image id");
        (std::fs::read(&path).unwrap(), id)
    }

    impl World {
        /// Deploys `runtime` verbatim (`creation_code`) from the submitter; the address and block.
        async fn deploy_code(&self, runtime: &[u8]) -> (Address, u64) {
            let tx = TransactionRequest {
                from: Some(self.submitter),
                to: Some(alloy::primitives::TxKind::Create),
                input: alloy::rpc::types::TransactionInput::new(Bytes::from(creation_code(runtime))),
                ..Default::default()
            };
            let receipt = tokio::time::timeout(SETUP_TX_TIMEOUT, async {
                self.provider
                    .send_transaction(tx)
                    .await
                    .expect("send a hemi-code deployment")
                    .get_receipt()
                    .await
                    .expect("a hemi-code deployment's receipt")
            })
            .await
            .expect("a hemi-code deployment mined in time");
            assert!(receipt.status(), "a hemi-code deployment reverted");
            (
                receipt.contract_address.expect("a contract address"),
                receipt.block_number.expect("a block"),
            )
        }

        /// Publishes `bytes` as `hemi-code` on the fork (chunks, then the manifest) and waits until
        /// the manifest is 40 blocks deep (the broker reads code at the safe head first). Returns the
        /// locator.
        pub async fn publish_hemi_code(&self, bytes: &[u8]) -> String {
            let mut chunks = Vec::new();
            for c in bytes.chunks(20_000) {
                chunks.push(self.deploy_code(&chunk_runtime_code(c)).await.0);
            }
            let (manifest, block) = self
                .deploy_code(&manifest_runtime_code(bytes.len() as u64, &sha256(bytes), &chunks))
                .await;
            let deadline = Instant::now() + Duration::from_secs(180);
            while self.provider.get_block_number().await.unwrap() < block + 40 {
                assert!(Instant::now() < deadline, "the fork stopped mining");
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
            format!("hemi-code://{}/{manifest:#x}", DEPLOYMENT.chain_id)
        }

        /// Gives `who` ETH and `amount` tHEMI, and lets the router take any of it.
        pub async fn fund_caller(&self, who: Address, amount: U256) {
            set_balance(&self.provider, who, 100 * HEMI).await;
            let owner = owner_of(&self.provider, DEPLOYMENT.token).await;
            mined!(
                ITestnetToken::new(DEPLOYMENT.token, &self.provider)
                    .mint(who, amount)
                    .from(owner),
                "mint tHEMI to a witness caller"
            );
            mined!(
                IERC20::new(DEPLOYMENT.token, &self.provider)
                    .approve(DEPLOYMENT.router, U256::MAX)
                    .from(who),
                "approve the router for a witness caller"
            );
        }

        /// Submits `d` from `caller` directly to the router (`submitJob`, a fixed price); the jobId.
        pub async fn submit_witness(&self, caller: Address, d: JobDescriptor, what: &str) -> B256 {
            self.submit_witness_with(caller, d, fixed_price(JOB_PRICE), what).await
        }

        /// [`World::submit_witness`] under `auction`.
        pub async fn submit_witness_with(
            &self,
            caller: Address,
            d: JobDescriptor,
            auction: AuctionConfig,
            what: &str,
        ) -> B256 {
            let core = IHemiProveCore::new(DEPLOYMENT.router, &self.provider);
            let receipt = mined!(
                core.submitJob(d.clone(), auction.clone(), no_cycles(), no_bidding())
                    .from(caller),
                what
            );
            receipt
                .inner
                .logs()
                .iter()
                .find_map(|l| l.log_decode::<IHemiProveCore::JobSubmitted>().ok())
                .map(|l| l.inner.data.jobId)
                .expect("JobSubmitted in the submit receipt")
        }
    }

    /// A witness job for the fibonacci guest: `params-echo` writes `n` (4 little-endian bytes) as
    /// `W`; FULL-bound to `journal`.
    pub fn witness_descriptor(
        program: &Program,
        wasm: &[u8],
        locator: &str,
        n: u32,
        journal: &[u8],
        tag: &str,
    ) -> JobDescriptor {
        let envelope = WitnessJobV1 {
            builderType: 1,
            builderId: B256::from(sha256(wasm)),
            builderURIs: vec![locator.to_string()],
            builderParams: n.to_le_bytes().to_vec().into(),
            sources: vec![Capability {
                class: CLASS_EVM_RPC_V1,
                config: encode_evm_rpc_config(DEPLOYMENT.chain_id, true, METHOD_SET_STATE_READ, 0).into(),
            }],
            limits: Limits {
                maxFetches: 4,
                maxFetchBytes: 1 << 20,
                maxRequestBytes: 65_536,
                maxResponseBytes: 1 << 20,
                maxBuilderFuel: 1_000_000_000,
                maxBuilderMemoryBytes: 64 << 20,
                maxBuilderSeconds: 30,
                maxWitnessBytes: 1 << 16,
                // Within the CPU slot's derived maximum: what one attempt can prove inside the
                // configured 1,800 s watchdog beside the CPU Groth16 allowance, both with the 1.5
                // safety margin (about 3M sized cycles at the CPU floor rate); the guest uses 32,768.
                maxGuestCycles: 1 << 21,
            },
        };
        JobDescriptor {
            programId: program.id,
            proofSystemId: program.proof_system,
            callbackContract: Address::ZERO,
            assignedProver: Address::ZERO,
            tag: keccak256(format!("zkminer localnet witness {tag}")),
            inputData: encode_envelope(&envelope).into(),
            callbackExtraData: Bytes::new(),
            extraVerifierData: Bytes::new(),
            expectedJournalHash: full_hash(program.proof_system, program.id, journal),
            journalFields: B256::ZERO,
        }
    }

    /// The broker's own config file: each `(alias, url, chain id)` as an `evm-rpc/v1` endpoint, and
    /// `artifacts_url` (the fork) as its `[artifacts]` endpoint for 743111.
    pub fn write_broker_config(dir: &Path, evm_rpc: &[(&str, &str, u64)], artifacts_url: &str) -> PathBuf {
        let spool = dir.join("broker-spool");
        std::fs::create_dir_all(&spool).unwrap();
        let path = dir.join("broker.toml");
        let mut text = format!("chain_rpc_host = \"chain-rpc.invalid\"\nspool_dir = \"{}\"\n", spool.display());
        for (alias, url, chain) in evm_rpc {
            text.push_str(&format!(
                "[[evm_rpc]]\nalias = \"{alias}\"\nurl = \"{url}\"\nchain_id = {chain}\narchive = true\n\
                 max_proof_age = 1000000\nmethod_sets = [\"state-read\"]\ncidrs = [\"127.0.0.1/32\"]\n"
            ));
        }
        text.push_str(&format!(
            "[artifacts]\nalias = \"fork-artifacts\"\nurl = \"{artifacts_url}\"\nchain_id = {chain}\n\
             max_requests_per_sec = 1000\nmax_builder_bytes = 4194304\ncidrs = [\"127.0.0.1/32\"]\n",
            chain = DEPLOYMENT.chain_id,
        ));
        std::fs::write(&path, text).unwrap();
        path
    }

    /// The miner's config for witness serving on the fork: `[witness] enabled` for the world's
    /// submitter, the rootless sandbox, the broker with `broker_config`, a retention store
    /// initialised by `zkminer witness init-store`, all checked by `zkminer witness self-test`. The
    /// CPU worker is the sandboxed execute; `worker` proves, named outright or (`discover`) found
    /// per card. Returns the config and the store's directory.
    pub fn witness_miner_config(
        world: &World,
        dir: &RunDir,
        bins: &Bins,
        broker_config: PathBuf,
        worker: &Path,
        discover: bool,
        proving_timeout_secs: u64,
    ) -> (PathBuf, PathBuf) {
        let config = world.write_config(&dir.0, worker, discover);
        let store_dir = dir.0.join("witness-store");
        let segment_dir = dir.0.join("witness-segments");
        std::fs::create_dir_all(&store_dir).unwrap();
        let mut c = ZkMinerConfig::load(Some(&config)).unwrap();
        c.witness.enabled = true;
        c.witness.sandbox_mode = SandboxModeConfig::Rootless;
        c.witness.callers = vec![world.submitter];
        c.witness.prover_address = Some(world.prover.address());
        c.witness.hemi_per_eth = Some(1.0);
        c.witness.hemi_per_eth_expires =
            Some((chrono::Utc::now() + chrono::Duration::days(7)).to_rfc3339());
        c.witness.unit_prices = Some(UnitPrices {
            cpu_second_hemi: 0.0,
            gib_hour_retained_hemi: 0.0,
            provider_overage_unit_hemi: 0.0,
        });
        c.witness.builder_binary = Some(bins.builder.clone());
        c.witness.execute_binary = Some(bins.cpu_worker.clone());
        c.witness.execute_memory_bytes = 4 << 30;
        c.retention = Some(RetentionConfig {
            dir: store_dir.clone(),
            store_uuid: String::new(),
            quota_bytes: 4 << 30,
            quota_inodes: 100_000,
            per_caller_bytes: 1 << 30,
            free_floor_pct: 1.0,
            segment_dir: segment_dir.clone(),
            require_dedicated_mount: false,
            allow_any_filesystem: false,
        });
        c.broker = Some(BrokerSection {
            config: broker_config,
            binary: Some(bins.broker.clone()),
            memory_bytes: 512 << 20,
        });
        c.dev.da_backlog_bytes = Some(0);
        // A CPU slot with no benchmark row budgets its Groth16 path (minutes on a CPU) at the CPU
        // allowance, and the claim gate refuses an estimate at or over the per-attempt watchdog, as
        // the inline gate refuses one. The default 10-minute watchdog (meant for a wedged GPU) cannot
        // hold that estimate, so a CPU host runs with a watchdog sized for CPU proofs, and the gate
        // checks that the estimate fits it.
        c.prover.proving_timeout_secs = proving_timeout_secs;
        c.save(Some(&config)).unwrap();
        // The probe the self-test runs is found next to zkminer (a link in the run directory).
        let probe = dir.0.join("zkminer-witness-sandbox-probe");
        let _ = std::fs::remove_file(&probe);
        if std::fs::hard_link(&bins.probe, &probe).is_err() {
            std::fs::copy(&bins.probe, &probe).unwrap();
        }

        // `zkminer witness init-store`, then its UUID into the config.
        let out = Miner::command(&dir.0, &config, &[], "witness", &["init-store"], &[])
            .output()
            .expect("run zkminer witness init-store");
        let stdout = String::from_utf8_lossy(&out.stdout).to_string();
        assert!(
            out.status.success(),
            "init-store: {stdout}{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let uuid = stdout
            .lines()
            .find_map(|l| l.strip_prefix("store_uuid = \""))
            .and_then(|l| l.strip_suffix('"'))
            .unwrap_or_else(|| panic!("init-store printed no store_uuid: {stdout}"))
            .to_string();
        let mut c = ZkMinerConfig::load(Some(&config)).unwrap();
        c.retention.as_mut().unwrap().store_uuid = uuid;
        c.save(Some(&config)).unwrap();

        // `zkminer witness self-test`: the sandbox and the broker, as the miner runs them.
        let out = Miner::command(&dir.0, &config, &[], "witness", &["self-test"], &[])
            .output()
            .expect("run zkminer witness self-test");
        assert!(
            out.status.success(),
            "self-test: {}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        (config, store_dir)
    }

    /// What is wrong with a fulfilled witness lock's log: it must be simulated, its bundle pinned,
    /// claimed, proved, fulfilled with `fulfillJobHashed` and its bundle deleted, in that order.
    pub fn lock_step_failures(lines: &[String], id: B256) -> Vec<String> {
        let s = short_id(id);
        let steps = [
            format!("witness job {s}: simulated"),
            format!("WITNESS-LOCK {s}: bundle v"),
            format!("WITNESS-LOCK {s}: claimed"),
            format!("WITNESS-LOCK {s}: proved"),
            format!("WITNESS-LOCK {s}: fulfilled with fulfillJobHashed"),
            format!("WITNESS-LOCK {s}: bundle deleted"),
        ];
        let mut failures = Vec::new();
        let mut last = None;
        for step in &steps {
            match lines.iter().position(|l| l.contains(step)) {
                None => failures.push(format!("no `{step}` line")),
                Some(i) => {
                    if last.is_some_and(|l| i < l) {
                        failures.push(format!("`{step}` came out of order"));
                    }
                    last = Some(i);
                }
            }
        }
        failures
    }

    /// The claim gate's estimate and the proof's time for `id`, in seconds, from the log.
    pub fn estimate_and_proof_secs(lines: &[String], id: B256) -> (Option<f64>, Option<f64>) {
        let s = short_id(id);
        let secs_after = |needle: &str, marker: &str| -> Option<f64> {
            let line = lines.iter().find(|l| l.contains(needle))?;
            let rest = &line[line.find(marker)? + marker.len()..];
            rest.split(|c: char| !(c.is_ascii_digit() || c == '.'))
                .find(|t| !t.is_empty())?
                .parse()
                .ok()
        };
        (
            secs_after(&format!("witness job {s}: claim gate passed"), "~"),
            secs_after(&format!("WITNESS-LOCK {s}: proved ("), " cycles, "),
        )
    }

    /// What is wrong with `id`'s claim and fulfil on the fork: claimed by the world's prover in an
    /// earlier block than its fulfil, fulfilled by `fulfillJobHashed` with `publicValues` = `journal`.
    pub async fn fulfil_failures(world: &World, id: B256, journal: &[u8]) -> Vec<String> {
        let mut failures = Vec::new();
        let claims = world.logs::<IHemiProveCore::JobClaimed>().await;
        let fulfils = world.logs::<IHemiProveFulfill::JobFulfilled>().await;
        match (
            claims.iter().find(|(j, _)| *j == id).map(|(_, l)| l),
            fulfils.iter().find(|(j, _)| *j == id).map(|(_, l)| l),
        ) {
            (Some(c), Some(f)) => {
                if c.block >= f.block || c.event.prover != world.prover.address() {
                    failures.push(format!(
                        "claimed in block {} by {} and fulfilled in block {}",
                        c.block, c.event.prover, f.block
                    ));
                }
                if f.event.publicValues.as_ref() != journal {
                    failures.push(format!(
                        "fulfilled with journal {}, not 0x{}",
                        f.event.publicValues,
                        alloy::hex::encode(journal)
                    ));
                }
                let tx = world
                    .provider
                    .get_transaction_by_hash(f.tx)
                    .await
                    .unwrap()
                    .expect("the fulfil transaction");
                use alloy::consensus::Transaction as _;
                use alloy::sol_types::SolCall;
                if tx.input()[..4] != IHemiProveFulfill::fulfillJobHashedCall::SELECTOR {
                    failures.push(format!(
                        "fulfilled by selector 0x{}, not fulfillJobHashed",
                        alloy::hex::encode(&tx.input()[..4])
                    ));
                }
            }
            (c, f) => failures.push(format!("claimed {}, fulfilled {}", c.is_some(), f.is_some())),
        }
        failures
    }

    /// What is wrong with the store after `id`'s lock ended: its bundles and pin must be gone.
    pub fn store_failures(store_dir: &Path, id: B256) -> Vec<String> {
        let mut failures = Vec::new();
        let hex_id = alloy::hex::encode(id);
        if store_dir.join("bundles").join(&hex_id).exists() {
            failures.push(format!("{}'s bundles are still in the store", short_id(id)));
        }
        let pins: Vec<String> = std::fs::read_dir(store_dir.join("pins"))
            .unwrap()
            .filter_map(|e| e.ok().map(|e| e.file_name().to_string_lossy().into_owned()))
            .collect();
        if pins.iter().any(|p| p.starts_with(&hex_id)) {
            failures.push(format!("{} is still pinned", short_id(id)));
        }
        failures
    }

    // ── Plan §12 ──────────────────────────────────────────────────────────────────────────────────

    /// The second chain's id: a plain anvil's.
    pub const EVM_CHAIN_ID: u64 = 31337;

    /// A plain anvil (chain [`EVM_CHAIN_ID`]): the `evm-rpc/v1` chain a witness job's builder reads,
    /// as Base is plan §12's. It mines a block per transaction. Stopped on drop.
    pub struct EvmChain {
        child: Child,
        pub url: String,
        pub provider: DynProvider,
        /// anvil's first dev account, which it signs for.
        dev: Address,
    }

    impl Drop for EvmChain {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    impl EvmChain {
        pub async fn start(dir: &Path) -> Self {
            let port = free_port();
            let log = std::fs::File::create(dir.join("anvil-evm-rpc.log")).expect("create its log");
            let mut cmd = Command::new(std::env::var("ANVIL").unwrap_or_else(|_| "anvil".into()));
            cmd.args(["--host", "127.0.0.1", "--port", &port.to_string()])
                .args(["--chain-id", &EVM_CHAIN_ID.to_string()])
                .stdin(Stdio::null())
                .stdout(log.try_clone().unwrap())
                .stderr(log);
            die_with_parent(&mut cmd);
            let child = cmd.spawn().expect("start the second anvil");
            let url = format!("http://127.0.0.1:{port}");
            let provider = ProviderBuilder::new()
                .connect_http(url.parse().unwrap())
                .erased();
            let deadline = Instant::now() + Duration::from_secs(60);
            while provider.get_chain_id().await.ok() != Some(EVM_CHAIN_ID) {
                assert!(Instant::now() < deadline, "the second anvil did not come up");
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            let dev = provider.get_accounts().await.unwrap()[0];
            EvmChain { child, url, provider, dev }
        }

        /// Sends `input` from the dev account, to `to` or as a creation; the receipt.
        async fn send(
            &self,
            to: Option<Address>,
            input: Vec<u8>,
            what: &str,
        ) -> alloy::rpc::types::TransactionReceipt {
            let tx = TransactionRequest {
                from: Some(self.dev),
                to: Some(to.map_or(alloy::primitives::TxKind::Create, alloy::primitives::TxKind::Call)),
                input: alloy::rpc::types::TransactionInput::new(Bytes::from(input)),
                ..Default::default()
            };
            let receipt = self
                .provider
                .send_transaction(tx)
                .await
                .unwrap_or_else(|e| panic!("{what}: {e}"))
                .get_receipt()
                .await
                .unwrap_or_else(|e| panic!("{what}: no receipt: {e}"));
            assert!(receipt.status(), "{what} reverted");
            receipt
        }

        async fn deploy(&self, creation: Vec<u8>, what: &str) -> Address {
            self.send(None, creation, what)
                .await
                .contract_address
                .expect("a contract address")
        }

        /// `slot` of `at` in block `block`.
        pub async fn storage(&self, at: Address, slot: [u8; 32], block: BlockId) -> [u8; 32] {
            self.provider
                .get_storage_at(at, U256::from_be_bytes(slot))
                .block_id(block)
                .await
                .expect("eth_getStorageAt")
                .to_be_bytes()
        }
    }

    /// Creation code: `SSTORE(slot, value)` for each pair, then return `runtime` (no compiler needed;
    /// as reference/proxy-slots/methods/tests/anvil_e2e.rs assembles it).
    fn creation(stores: &[([u8; 32], [u8; 32])], runtime: &[u8]) -> Vec<u8> {
        let mut c = Vec::new();
        for (slot, value) in stores {
            c.push(0x7f); // PUSH32 value
            c.extend_from_slice(value);
            c.push(0x7f); // PUSH32 slot
            c.extend_from_slice(slot);
            c.push(0x55); // SSTORE
        }
        let len = u16::try_from(runtime.len()).unwrap().to_be_bytes();
        let offset = u16::try_from(c.len() + 15).unwrap().to_be_bytes();
        // PUSH2 len PUSH2 offset PUSH1 0 CODECOPY PUSH2 len PUSH1 0 RETURN
        c.extend_from_slice(&[
            0x61, len[0], len[1], 0x61, offset[0], offset[1], 0x60, 0x00, 0x39, 0x61, len[0], len[1],
            0x60, 0x00, 0xf3,
        ]);
        c.extend_from_slice(runtime);
        c
    }

    /// An implementation: stores calldata word 1 at the slot calldata word 0 names (in the proxy's
    /// storage, when called through it), then returns 42. So a call through the proxy can write any
    /// of the proxy's slots, the EIP-1967 one included: an upgrade.
    const IMPLEMENTATION_RUNTIME: [u8; 14] = [
        0x60, 0x20, 0x35, 0x5f, 0x35, 0x55, 0x60, 0x2a, 0x5f, 0x52, 0x60, 0x20, 0x5f, 0xf3,
    ];

    /// An EIP-1967 proxy: delegate the calldata to the address in the implementation slot, return or
    /// revert with what it returned.
    fn proxy_runtime() -> Vec<u8> {
        let mut r = vec![0x36, 0x5f, 0x5f, 0x37, 0x5f, 0x5f, 0x36, 0x5f, 0x7f];
        r.extend_from_slice(&EIP1967_IMPLEMENTATION_SLOT);
        // SLOAD GAS DELEGATECALL; RETURNDATACOPY(0, 0, size); JUMPI ok; REVERT; ok: RETURN
        r.extend_from_slice(&[
            0x54, 0x5a, 0xf4, 0x3d, 0x5f, 0x5f, 0x3e, 0x60, 0x36, 0x57, 0x3d, 0x5f, 0xfd, 0x5b, 0x3d,
            0x5f, 0xf3,
        ]);
        assert_eq!(r[0x36], 0x5b, "the jump target is the JUMPDEST");
        r
    }

    fn word(n: u64) -> [u8; 32] {
        B256::from(U256::from(n)).0
    }

    fn address_word(a: Address) -> [u8; 32] {
        B256::left_padding_from(a.as_slice()).0
    }

    /// The §12 statement on the second chain, and what its state at B says.
    pub struct ProxyAtB {
        pub statement: Statement,
        pub implementation: Address,
        /// `EXTCODEHASH(implementation)` at B.
        pub code_hash: B256,
        /// The k slots' values at B, in rule order.
        pub values: Vec<[u8; 32]>,
    }

    impl ProxyAtB {
        /// The journal a proof of this statement for `job` by `prover` commits: the prefix, the
        /// header, then the implementation, its code hash and each `(slot, value)`.
        pub fn journal(&self, job: B256, prover: Address) -> Vec<u8> {
            let mut j = zkminer_witness::binding::journal_prefix(job, prover).to_vec();
            j.extend_from_slice(&self.statement.header());
            j.extend_from_slice(&address_word(self.implementation));
            j.extend_from_slice(self.code_hash.as_slice());
            let slots = self.statement.rule.slots(&self.implementation.0 .0, self.statement.k);
            for (slot, value) in slots.iter().zip(&self.values) {
                j.extend_from_slice(slot);
                j.extend_from_slice(value);
            }
            assert_eq!(j.len(), hemiprove_proxy_slots::journal_len(self.statement.k));
            j
        }
    }

    /// The proxy of plan §12 on `chain`, deployed and then changed by real transactions: deployed
    /// pointing at implementation A with slots 10–12 = 100, 101, 102; then, through the proxy, slot
    /// 11 set to 201 and an upgrade to implementation B (other code). That block is B. After it, slot
    /// 10 is set to 999 and the proxy downgraded to A, so B's state is not the head's. The statement:
    /// rule 1 at slot 10, k = 3. What B's state says is read back from the chain at B.
    pub async fn proxy_at_b(chain: &EvmChain) -> ProxyAtB {
        let a = chain
            .deploy(creation(&[], &IMPLEMENTATION_RUNTIME), "deploy implementation A")
            .await;
        // B: the same, with an unreachable trailing STOP (another code hash).
        let mut b_runtime = IMPLEMENTATION_RUNTIME.to_vec();
        b_runtime.push(0x00);
        let b_impl = chain
            .deploy(creation(&[], &b_runtime), "deploy implementation B")
            .await;
        let stores = [
            (EIP1967_IMPLEMENTATION_SLOT, address_word(a)),
            (word(10), word(100)),
            (word(11), word(101)),
            (word(12), word(102)),
        ];
        let proxy = chain
            .deploy(creation(&stores, &proxy_runtime()), "deploy the proxy")
            .await;
        let write = |slot: [u8; 32], value: [u8; 32]| [slot, value].concat();
        chain
            .send(Some(proxy), write(word(11), word(201)), "set slot 11 through the proxy")
            .await;
        let upgrade = chain
            .send(
                Some(proxy),
                write(EIP1967_IMPLEMENTATION_SLOT, address_word(b_impl)),
                "upgrade the proxy to implementation B",
            )
            .await;
        let b_hash = upgrade.block_hash.expect("the upgrade's block");
        // A working proxy: a call reaches implementation B through DELEGATECALL.
        let answer = chain
            .provider
            .call(TransactionRequest::default().to(proxy).input(Bytes::from(vec![0x12, 0x34]).into()))
            .await
            .expect("eth_call through the proxy");
        assert_eq!(answer.as_ref(), word(42), "the proxy delegates");
        // After B.
        chain
            .send(Some(proxy), write(word(10), word(999)), "set slot 10 through the proxy, after B")
            .await;
        chain
            .send(
                Some(proxy),
                write(EIP1967_IMPLEMENTATION_SLOT, address_word(a)),
                "downgrade the proxy to implementation A, after B",
            )
            .await;
        let head = BlockId::Number(BlockNumberOrTag::Latest);
        assert_eq!(chain.storage(proxy, word(10), head).await, word(999));
        assert_eq!(chain.storage(proxy, EIP1967_IMPLEMENTATION_SLOT, head).await, address_word(a));

        let statement = Statement {
            block_hash: b_hash.0,
            proxy: proxy.0 .0,
            rule: Rule::new(RuleKind::Consecutive, &word(10)).unwrap(),
            k: 3,
        };
        // What B's state says, read from the chain at B.
        let at_b = BlockId::hash(b_hash);
        let implementation = Address::from_word(B256::from(
            chain.storage(proxy, EIP1967_IMPLEMENTATION_SLOT, at_b).await,
        ));
        let code = chain
            .provider
            .get_code_at(implementation)
            .block_id(at_b)
            .await
            .expect("eth_getCode");
        let mut values = Vec::new();
        for slot in statement.rule.slots(&implementation.0 .0, statement.k) {
            values.push(chain.storage(proxy, slot, at_b).await);
        }
        assert_eq!(implementation, b_impl, "B's implementation is B");
        assert_eq!(values, vec![word(100), word(201), word(102)], "B's values");
        ProxyAtB {
            statement,
            implementation,
            code_hash: keccak256(&code),
            values,
        }
    }

    /// `zkminer artifact publish FILE --kind builder` to the fork, from a fresh funded key in a
    /// keystore, its password on fd 3, one send a second (developer mode allows the floor below
    /// Hemi's 12 s). The JSON it prints.
    pub async fn publish_with_the_cli(
        world: &World,
        dir: &Path,
        config: &Path,
        file: &Path,
    ) -> serde_json::Value {
        let key = PrivateKeySigner::random();
        set_balance(&world.provider, key.address(), 10 * HEMI).await;
        PrivateKeySigner::encrypt_keystore(
            dir,
            &mut rand::thread_rng(),
            key.to_bytes(),
            "pw",
            Some("publisher"),
        )
        .unwrap();
        let mut fds = [0i32; 2];
        // SAFETY: a valid array of two fds.
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        // SAFETY: the write end is ours.
        let mut w = unsafe { <std::fs::File as std::os::fd::FromRawFd>::from_raw_fd(fds[1]) };
        w.write_all(b"pw\n").unwrap();
        drop(w);
        let read_end = fds[0];
        let chain = DEPLOYMENT.chain_id.to_string();
        let file = file.display().to_string();
        let keystore = dir.join("publisher").display().to_string();
        let args = [
            "publish",
            &file,
            "--kind",
            "builder",
            "--rpc-url",
            &world.rpc_url,
            "--chain-id",
            &chain,
            "--keystore",
            &keystore,
            "--password-fd",
            "3",
            "--block-time-ms",
            "1000",
            "--yes",
            "--json",
        ];
        let mut cmd = Miner::command(dir, config, &[], "artifact", &args, &[]);
        use std::os::unix::process::CommandExt;
        // SAFETY: only async-signal-safe calls between fork and exec.
        unsafe {
            cmd.pre_exec(move || {
                // `dup2` onto itself, when the read end already is 3, would leave it close-on-exec.
                if read_end != 3 && libc::dup2(read_end, 3) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::fcntl(3, libc::F_SETFD, 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let started = Instant::now();
        let out = tokio::task::spawn_blocking(move || cmd.output())
            .await
            .unwrap()
            .expect("run zkminer artifact publish");
        // SAFETY: the parent's copy of the read end.
        unsafe { libc::close(read_end) };
        let stderr = String::from_utf8_lossy(&out.stderr).to_string();
        std::fs::write(dir.join("artifact-publish.log"), &stderr).unwrap();
        assert!(out.status.success(), "artifact publish: {stderr}");
        eprintln!(
            "localnet: artifact publish took {:.0} s",
            started.elapsed().as_secs_f64()
        );
        serde_json::from_slice(&out.stdout).expect("artifact publish --json prints JSON")
    }

    /// `zkminer` (from the run directory, as the miner runs) with `args`; its output, required to
    /// succeed.
    fn zkminer_ok(dir: &Path, config: &Path, sub: &str, args: &[&str]) -> String {
        let out = Miner::command(dir, config, &[], sub, args, &[])
            .output()
            .unwrap_or_else(|e| panic!("run zkminer {sub} {args:?}: {e}"));
        assert!(
            out.status.success(),
            "zkminer {sub} {args:?}: {}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).into_owned()
    }

    /// The §12 job, made as a requester makes it: the job spec encoded by `zkminer witness envelope
    /// encode` (the builder's sha256 as its builderId, the descriptor file), its binding computed
    /// from the requester's own parameters by `zkminer witness binding compute` and checked by
    /// `binding check`: FIELDS over the 160-byte header after the journal-prefix marker, assigned to
    /// `prover`.
    pub fn proxy_slots_descriptor(
        dir: &Path,
        config: &Path,
        program: &Program,
        prover: Address,
        locator: &str,
        wasm: &Path,
        p: &ProxyAtB,
    ) -> JobDescriptor {
        let words: Vec<String> = p
            .statement
            .header_words()
            .iter()
            .map(|w| format!("word:0x{}", alloy::hex::encode(w)))
            .collect();
        let spec = dir.join("proxy-slots-job.toml");
        std::fs::write(
            &spec,
            format!(
                "program_id = \"{id}\"\nassigned_prover = \"{prover}\"\n\
                 [binding]\nprefix = true\nheader = {words:?}\n\
                 [envelope]\nbuilder_uris = [\"{locator}\"]\nbuilder_params = \"0x{params}\"\n\
                 [[envelope.sources]]\nclass = \"evm-rpc/v1\"\nchain_id = {EVM_CHAIN_ID}\narchive = true\n\
                 method_set = \"state-read\"\nmax_proof_age = 1000\n\
                 [envelope.limits]\nmax_fetches = 8\nmax_fetch_bytes = 4194304\nmax_request_bytes = 65536\n\
                 max_response_bytes = 1048576\nmax_builder_fuel = 5000000000\n\
                 max_builder_memory_bytes = 67108864\nmax_builder_seconds = 60\nmax_witness_bytes = 1048576\n\
                 max_guest_cycles = {max_cycles}\n",
                id = program.id,
                params = alloy::hex::encode(p.statement.builder_params(EVM_CHAIN_ID)),
                // The guest runs in one 2^20 segment here; within the CPU slot's derived maximum at a
                // 1,800 s watchdog (about 3M sized cycles at the CPU floor rate).
                max_cycles = 1u64 << 21,
            ),
        )
        .unwrap();
        let d_path = dir.join("proxy-slots-job.json");
        let (spec_s, wasm_s, d_s) = (
            spec.display().to_string(),
            wasm.display().to_string(),
            d_path.display().to_string(),
        );
        zkminer_ok(
            dir,
            config,
            "witness",
            &["envelope", "encode", &spec_s, "--builder", &wasm_s, "--descriptor-out", &d_s],
        );
        let d: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&d_path).unwrap()).expect("the descriptor file");
        let b256 = |k: &str| -> B256 { d[k].as_str().unwrap().parse().unwrap() };
        let bytes = |k: &str| -> Bytes { d[k].as_str().unwrap().parse().unwrap() };

        // The binding from the requester's own parameters, by the separate calculator.
        let mut args = vec!["binding", "compute", "--json"];
        for w in &words {
            args.extend(["--word", w.as_str()]);
        }
        let out: serde_json::Value =
            serde_json::from_str(&zkminer_ok(dir, config, "witness", &args)).unwrap();
        let computed = &out["binding"];
        assert_eq!(computed["mode"], "fields", "{out}");
        assert_eq!(computed["prefix"], true, "{out}");
        assert_eq!(computed["headerBytes"], 160, "{out}");
        assert_eq!(out["check"]["ok"], true, "the mutation check over the header: {out}");
        let fields: B256 = computed["journalFields"].as_str().unwrap().parse().unwrap();
        let expected: B256 = computed["expectedJournalHash"].as_str().unwrap().parse().unwrap();
        assert_eq!(fields, B256::from(hemiprove_proxy_slots::journal_fields()), "FIELDS: the marker, then [0, 160)");
        assert_eq!(expected, B256::from(p.statement.expected_journal_hash()));
        assert_eq!((b256("journalFields"), b256("expectedJournalHash")), (fields, expected), "envelope encode agrees");
        // And the mutation check over the whole header.
        let header = format!("0x{}", alloy::hex::encode(p.statement.header()));
        zkminer_ok(
            dir,
            config,
            "witness",
            &["binding", "check", "--descriptor", &d_s, "--statement", &header, "--header-bytes", "160"],
        );

        let descriptor = JobDescriptor {
            programId: b256("programId"),
            proofSystemId: b256("proofSystemId"),
            callbackContract: d["callbackContract"].as_str().unwrap().parse().unwrap(),
            assignedProver: d["assignedProver"].as_str().unwrap().parse().unwrap(),
            tag: b256("tag"),
            inputData: bytes("inputData"),
            callbackExtraData: bytes("callbackExtraData"),
            extraVerifierData: bytes("extraVerifierData"),
            expectedJournalHash: b256("expectedJournalHash"),
            journalFields: b256("journalFields"),
        };
        assert_eq!(descriptor.programId, program.id);
        assert_eq!(descriptor.proofSystemId, program.proof_system);
        assert_eq!(descriptor.assignedProver, prover);
        descriptor
    }
}

#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs a delegated cgroup, anvil, the SDK toolchain and the 743111 RPC; see the witness section"]
async fn serves_witness_jobs() {
    use witness_support::*;

    let dir = RunDir::new("witness");
    let bins = bins();
    let wasm = params_echo_wasm();
    let program = Program::fibonacci(&bins.cpu_worker, &dir.0);
    let journal = program.journal.clone();
    let mut wrong = journal.clone();
    wrong[0] ^= 1;
    let world = World::new(&dir.0, program, &[], Clock::Wall).await;
    let locator = world.publish_hemi_code(&wasm).await;
    eprintln!("localnet: params-echo published at {locator}");

    // Three witness jobs: an allowlisted caller's good one and bad one, and an outsider's.
    let outsider = Address::from_word(keccak256(b"zkminer localnet witness outsider"));
    world.fund_deposits(U256::from(10 * JOB_PRICE)).await;
    world.fund_caller(outsider, U256::from(10 * JOB_PRICE)).await;
    let n = fib_n();
    let good = world
        .submit_witness(
            world.submitter,
            witness_descriptor(&world.program, &wasm, &locator, n, &journal, "good"),
            "submit the good witness job",
        )
        .await;
    let bad = world
        .submit_witness(
            world.submitter,
            witness_descriptor(&world.program, &wasm, &locator, n, &wrong, "bad binding"),
            "submit the bad-binding witness job",
        )
        .await;
    let foreign = world
        .submit_witness(
            outsider,
            witness_descriptor(&world.program, &wasm, &locator, n, &journal, "outsider"),
            "submit the outsider's witness job",
        )
        .await;
    eprintln!(
        "localnet: witness jobs good {} bad {} outsider {}",
        short_id(good),
        short_id(bad),
        short_id(foreign)
    );

    // The miner's config: the fork, witness serving with the allowlist, the store, the broker (the
    // fork as its evm-rpc endpoint for 743111 and its artifact endpoint). The host proves on a CPU
    // slot, with a watchdog sized for a CPU proof.
    let broker_config =
        write_broker_config(&dir.0, &[("fork", &world.rpc_url, DEPLOYMENT.chain_id)], &world.rpc_url);
    let (config, store_dir) =
        witness_miner_config(&world, &dir, &bins, broker_config, &bins.cpu_worker, false, 1_800);

    let nonce_before = world.prover_nonce().await;
    let mut miner = start_mining(&world, &dir, &config, Vec::new(), false);
    let started = Instant::now();
    let timeout = Duration::from_secs(1_200);
    loop {
        let fulfilled = world.jobs_with::<IHemiProveFulfill::JobFulfilled>().await;
        if fulfilled.contains(&good) {
            break;
        }
        if miner.exited() {
            miner.fail("zkminer exited before the witness job was fulfilled");
        }
        if started.elapsed() > timeout {
            miner.fail("the witness job was not fulfilled in time");
        }
        tokio::time::sleep(Duration::from_secs(3)).await;
    }
    let (sg, sb, sf) = (short_id(good), short_id(bad), short_id(foreign));
    if !wait_for_line(&mut miner, &format!("WITNESS-LOCK {sg}: bundle deleted"), Duration::from_secs(120)).await {
        miner.fail("the fulfilled witness job's bundle was not deleted");
    }
    if !wait_for_line(&mut miner, &format!("witness job {sb}: skipped — BindingMismatch"), Duration::from_secs(300)).await {
        miner.fail("the bad-binding witness job was not skipped for its binding");
    }
    tokio::time::sleep(SETTLE).await;
    let stopped = miner.stop(DRAIN_GRACE);
    let lines = miner.lines();

    let mut failures: Vec<String> = stop_failure(stopped, DRAIN_GRACE).into_iter().collect();
    let pos = |needle: &str| lines.iter().position(|l| l.contains(needle));
    // The good job: simulated, pinned before the claim, claimed, proved, fulfilled, deleted.
    failures.extend(lock_step_failures(&lines, good));
    // The claim gate's estimate was realistic: at least what the CPU proof took, and inside the
    // watchdog it was checked against.
    let (estimated, proved) = estimate_and_proof_secs(&lines, good);
    eprintln!("localnet: the claim gate estimated {estimated:?} s; the CPU proof took {proved:?} s");
    match (estimated, proved) {
        (Some(e), Some(p)) => {
            if e < p {
                failures.push(format!("the claim gate estimated {e} s, the proof took {p} s"));
            }
            if e >= 1_800.0 {
                failures.push(format!("the claim gate admitted a {e} s estimate at a 1,800 s watchdog"));
            }
        }
        _ => failures.push("no claim-gate estimate or proof time in the log".into()),
    }
    failures.extend(fulfil_failures(&world, good, &journal).await.into_iter().map(|f| format!("the good job: {f}")));
    // Its bundle and pin are gone from the store.
    failures.extend(store_failures(&store_dir, good));
    // The bad binding: simulated, never claimed. The outsider's: never simulated, never claimed.
    let claims = world.logs::<IHemiProveCore::JobClaimed>().await;
    for (id, what) in [(bad, "the bad-binding job"), (foreign, "the outsider's job")] {
        if claims.iter().any(|(j, _)| *j == id) {
            failures.push(format!("{what} was claimed"));
        }
        let (status, prover) = world.job_state(id).await;
        if status != zkminer_chain::jobs::JOB_STATUS_OPEN || prover != Address::ZERO {
            failures.push(format!("{what} ends with status {status} prover {prover}"));
        }
    }
    if pos(&format!("witness job {sf}: simulating")).is_some() {
        failures.push("the outsider's job was simulated".into());
    }
    if pos(&format!("witness job {sb}: simulating")).is_none() {
        failures.push("the bad-binding job was never simulated".into());
    }
    eprintln!(
        "localnet: outsider recognised: {}",
        pos(&format!("witness job {sf}: caller")).is_some()
            || pos(&format!("job {sf} is a witness-construction job")).is_some()
    );
    // Exactly a claim and a fulfil were sent, and nothing is left locked.
    let nonce_after = world.prover_nonce().await;
    if nonce_after.checked_sub(nonce_before) != Some(2) {
        failures.push(format!(
            "the prover's nonce moved from {nonce_before} to {nonce_after}, not by a claim and a fulfil"
        ));
    }
    let stake = world.stake().await;
    if stake.lockedCollateral != 0 {
        failures.push(format!("{} HEMI of collateral still locked", hemi(stake.lockedCollateral)));
    }
    report(&world, &dir, &miner, &failures).await;
    drop(world);
    dir.finish();
}

/// Plan §12's job on the miner, proven on the CPU worker: see the witness section.
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs a delegated cgroup, anvil, the risc0 and SDK toolchains and the 743111 RPC; see the witness section"]
async fn serves_the_proxy_slots_witness_job() {
    proxy_slots_witness_job(false).await;
}

/// Plan §12's job on the miner, proven on a GPU by `ZKMINER_LOCALNET_RISC0_WORKER`: see the witness
/// section.
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs a GPU, its release risc0 worker, a delegated cgroup, anvil, the risc0 and SDK toolchains and the 743111 RPC"]
async fn serves_the_proxy_slots_witness_job_on_a_gpu() {
    proxy_slots_witness_job(true).await;
}

#[cfg(target_os = "linux")]
async fn proxy_slots_witness_job(gpu: bool) {
    use witness_support::*;

    let dir = RunDir::new(if gpu { "proxy-slots-gpu" } else { "proxy-slots" });
    let bins = bins();
    let worker = if gpu { risc0_worker() } else { bins.cpu_worker.clone() };
    let wasm = proxy_slots_wasm();
    let wasm_path = dir.0.join("proxy_slots_builder.wasm");
    std::fs::write(&wasm_path, &wasm).unwrap();
    let (elf, id) = proxy_slots_guest(&dir.0);
    eprintln!("localnet: the proxy-slots guest's image id is {id}");

    // The second chain and the statement: the proxy at B.
    let chain = EvmChain::start(&dir.0).await;
    let proxy = proxy_at_b(&chain).await;
    eprintln!(
        "localnet: on chain {EVM_CHAIN_ID} at {}: proxy {} -> implementation {} (code hash {}), values {}",
        chain.url,
        Address::from(proxy.statement.proxy),
        proxy.implementation,
        proxy.code_hash,
        proxy.values.iter().map(alloy::hex::encode).collect::<Vec<_>>().join(", ")
    );

    // The fork, with the guest registered and served.
    let program = Program {
        name: "proxy-slots, plan §12 (zkminer localnet)",
        id,
        proof_system: risc_zero_groth16_v1_id(),
        elf,
        input: Vec::new(),
        journal: Vec::new(),
    };
    let world = World::new(&dir.0, program, &[], Clock::Wall).await;

    // The miner's config (the publisher reads developer mode from it): the broker's evm-rpc endpoint
    // is the second chain, its artifact endpoint the fork.
    let broker_config =
        write_broker_config(&dir.0, &[("evm", &chain.url, EVM_CHAIN_ID)], &world.rpc_url);
    let discover = gpu && std::env::var_os("CUDA_VISIBLE_DEVICES").is_none();
    let proving_timeout_secs = if gpu { 600 } else { 3_600 };
    let (config, store_dir) = witness_miner_config(
        &world,
        &dir,
        &bins,
        broker_config,
        &worker,
        discover,
        proving_timeout_secs,
    );

    // The builder, published by the requester's tool.
    let published = publish_with_the_cli(&world, &dir.0, &config, &wasm_path).await;
    let locator = published["locator"].as_str().unwrap().to_string();
    assert!(locator.starts_with("hemi-code://743111/0x"), "{published}");
    let builder_id: B256 = published["builderId"].as_str().unwrap().parse().unwrap();
    assert_eq!(builder_id, B256::from(zkminer_witness::manifest::sha256(&wasm)));
    eprintln!("localnet: the proxy-slots builder published at {locator}");

    // The job, made by the requester tools and submitted with an exclusivity window for the prover.
    let descriptor = proxy_slots_descriptor(
        &dir.0,
        &config,
        &world.program,
        world.prover.address(),
        &locator,
        &wasm_path,
        &proxy,
    );
    world.fund_deposits(U256::from(10 * JOB_PRICE)).await;
    let mut auction = fixed_price(JOB_PRICE);
    auction.exclusivityDuration = U40::from(EXCLUSIVITY.as_secs());
    let job = world
        .submit_witness_with(world.submitter, descriptor, auction, "submit the proxy-slots witness job")
        .await;
    let journal = proxy.journal(job, world.prover.address());
    eprintln!("localnet: proxy-slots witness job {job}");

    let nonce_before = world.prover_nonce().await;
    let mut miner = start_mining(&world, &dir, &config, Vec::new(), false);
    let started = Instant::now();
    let timeout = Duration::from_secs(if gpu { 1_800 } else { 5_400 });
    loop {
        if world.jobs_with::<IHemiProveFulfill::JobFulfilled>().await.contains(&job) {
            break;
        }
        if miner.exited() {
            miner.fail("zkminer exited before the proxy-slots job was fulfilled");
        }
        if started.elapsed() > timeout {
            miner.fail("the proxy-slots job was not fulfilled in time");
        }
        tokio::time::sleep(Duration::from_secs(3)).await;
    }
    let fulfilled_after = started.elapsed();
    let s = short_id(job);
    if !wait_for_line(&mut miner, &format!("WITNESS-LOCK {s}: bundle deleted"), Duration::from_secs(120)).await {
        miner.fail("the fulfilled proxy-slots job's bundle was not deleted");
    }
    tokio::time::sleep(SETTLE).await;
    let stopped = miner.stop(DRAIN_GRACE);
    let lines = miner.lines();

    let mut failures: Vec<String> = stop_failure(stopped, DRAIN_GRACE).into_iter().collect();
    // Simulated before the claim, pinned, claimed, proved (execute, compare, prove), fulfilled with
    // fulfillJobHashed, deleted.
    failures.extend(lock_step_failures(&lines, job));
    // `JobFulfilled.publicValues`: exactly the journal of the second chain's state at B.
    failures.extend(fulfil_failures(&world, job, &journal).await);
    let fulfils = world.logs::<IHemiProveFulfill::JobFulfilled>().await;
    if let Some((_, f)) = fulfils.iter().find(|(j, _)| *j == job) {
        match hemiprove_proxy_slots::decode_journal(&f.event.publicValues) {
            Ok(j) => {
                if j.statement != proxy.statement
                    || j.prefix.job_id() != job.0
                    || Address::from(j.prefix.prover()) != world.prover.address()
                    || Address::from(j.outputs.implementation) != proxy.implementation
                    || j.outputs.code_hash != proxy.code_hash.0
                    || j.outputs.slots.iter().map(|(_, v)| *v).collect::<Vec<_>>() != proxy.values
                {
                    failures.push(format!("the fulfilled journal says {j:?}"));
                }
            }
            Err(e) => failures.push(format!("the fulfilled journal does not decode: {e:?}")),
        }
    }
    failures.extend(store_failures(&store_dir, job));
    let (estimated, proved) = estimate_and_proof_secs(&lines, job);
    let proofs: Vec<&String> = lines.iter().filter(|l| l.contains("Proof complete on ")).collect();
    eprintln!(
        "localnet: fulfilled {:.0} s after the miner started; the claim gate estimated {estimated:?} s, \
         the proof took {proved:?} s; {proofs:?}",
        fulfilled_after.as_secs_f64()
    );
    match (estimated, proved) {
        (Some(e), Some(_)) if e >= proving_timeout_secs as f64 => failures.push(format!(
            "the claim gate admitted a {e} s estimate at a {proving_timeout_secs} s watchdog"
        )),
        (Some(_), Some(_)) => {}
        _ => failures.push("no claim-gate estimate or proof time in the log".into()),
    }
    // The proving slot, by its key: a worker named outright (CUDA_VISIBLE_DEVICES set) has no
    // discovered card name, so the line's `[…]` reads `cpu` for it whatever it runs on.
    let slots: Vec<&str> = proofs
        .iter()
        .filter_map(|l| l.split_once("Proof complete on ")?.1.split_once(' ').map(|(k, _)| k))
        .collect();
    if gpu && (slots.len() != 1 || slots[0].ends_with(":cpu") || slots[0].contains(":measure")) {
        failures.push(format!("not one proof on a GPU slot: {proofs:?}"));
    }
    let nonce_after = world.prover_nonce().await;
    if nonce_after.checked_sub(nonce_before) != Some(2) {
        failures.push(format!(
            "the prover's nonce moved from {nonce_before} to {nonce_after}, not by a claim and a fulfil"
        ));
    }
    let stake = world.stake().await;
    if stake.lockedCollateral != 0 {
        failures.push(format!("{} HEMI of collateral still locked", hemi(stake.lockedCollateral)));
    }
    report(&world, &dir, &miner, &failures).await;
    drop(world);
    drop(chain);
    dir.finish();
}
