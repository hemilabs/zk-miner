//! The fulfil-side DA work against an anvil fork of Hemi testnet 743111, started as
//! `zkminer-cli/tests/localnet.rs` starts it (same fork block, `--auto-impersonate`, the public
//! testnet RPC unless `ZKMINER_LOCALNET_FORK_URL` names another; no key or secret is needed).
//!
//! - `gas_price_oracle_estimates_on_the_fork`: Hemi's GasPriceOracle predeploy is Fjord, and
//!   `da::estimated_da_bytes` / `da::estimate_fulfil_da_bytes` work through it;
//! - `fulfill_job_hashed_and_the_da_nonce_rule_on_the_fork`: claimability, the `fulfillJobHashed`
//!   routing (revert decodes), then a LARGE hashed fulfil held out of blocks while the head advances
//!   is replaced at its nonce by a self-transfer, held, and re-sent once the throttle clears;
//! - `backlog_reading_on_the_live_endpoint`: the §13.5 reading against the real op-geth endpoint
//!   (read-only), since anvil's receipts carry no `l1GasUsed`.
//!
//! ```text
//! cargo test -p zkminer-chain --test da_fork -- --ignored --nocapture --test-threads=1
//! ```
//!
//! Environment: `ZKMINER_LOCALNET_FORK_URL`, `ZKMINER_LOCALNET_FORK_BLOCK` (`latest` for the head),
//! `ANVIL` — as the localnet tests.
#![cfg(unix)]

use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use alloy::primitives::aliases::{U40, U96};
use alloy::primitives::{keccak256, Address, Bytes, B256, U256};
use alloy::providers::{DynProvider, Provider, ProviderBuilder};
use alloy::rpc::types::TransactionRequest;
use alloy::signers::local::PrivateKeySigner;
use alloy::sol_types::SolCall;
use zkminer_chain::auction::risc_zero_groth16_v1_id;
use zkminer_chain::binding::full_hash;
use zkminer_chain::client::ChainClient;
use zkminer_chain::da::{
    self, Backlog, BacklogReader, BacklogReading, BacklogSource, NonceRuleConfig, SealSpec,
};
use zkminer_chain::deployment::HEMI_TESTNET_743111 as DEPLOYMENT;
use zkminer_chain::jobs::{fulfill_job_hashed_calldata, FulfilDa, HashedFulfil};
use zkminer_chain::revert::{decode, Decoded, FulfilClass, FulfilFailure};
use zkminer_contracts::bindings::IHemiProveErrors::IHemiProveErrorsErrors as E;
use zkminer_contracts::bindings::{
    AuctionConfig, CompetitiveBidConfig, CycleConfig, IGasPriceOracle, IHemiProveAux,
    IHemiProveCore, IHemiProveFulfill, IHemiProveRegistry, IHemiProveStaking, ITestnetToken,
    IVerifierAdapter, JobDescriptor, GAS_PRICE_ORACLE, IERC20,
};

/// localnet.rs's fork block (after the 2026-11-16 deployment's setup: its router exists from block
/// 7226099 and its adapters are registered by 7226300). Keep it equal to localnet.rs's.
const FORK_BLOCK: u64 = 7_226_550;
const DEFAULT_FORK_URL: &str = "https://testnet.rpc.hemi.network/rpc";
const HEMI: u128 = 1_000_000_000_000_000_000;
/// localnet.rs's receipt fixture (risc0-ethereum v3.1.0 `TestReceiptV3_1.sol`).
const FIXTURE_IMAGE_ID: B256 =
    alloy::primitives::b256!("c92414d80cdeb43ba0f4ff4882447c21f18b547d41ffa506a84da164e8e31f7d");
const FIXTURE_JOURNAL: &[u8] = b"just a simple receipt";
const FIXTURE_SEAL_HEX: &str = concat!(
    "e71e662021a0c81a5cc1c5cddabc3eefe6a3841315ad1a1cd74da3f34db1db91d01240a70b220d069e774da52f06c0d0ca166b21",
    "9f0e1b0548a08270fa88f5e71a55bb2911fba8d9c52968295894f9b6e1804afcda16b66956ad973a290cb8d6736813502b336b4e",
    "c0382ab1a7508781f3e1a8d7ea73d4491382cae39ec9f14aff07f53623bc5d3d6a718a686588bd6027b1713110031c85fa34117a",
    "4fed94d98a41fe8e0bcf572d3389eedcc34ec00bd1aa571b0bcaa80af13b30bf3cb26741e56deabb23d1abf7efdfba3f55523687",
    "ce10ef220c8d6d879f2e9161684f044e6e3597a2087d050b687d2242476dde08f789d726635f51ccd6fc216091297f0b7b416a6a",
);

/// anvil forking 743111; killed (by its own pid) on drop.
struct Anvil {
    child: Child,
    url: String,
    log: PathBuf,
}

impl Drop for Anvil {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn fork_url() -> String {
    std::env::var("ZKMINER_LOCALNET_FORK_URL").unwrap_or_else(|_| DEFAULT_FORK_URL.into())
}

fn start_anvil(name: &str) -> Anvil {
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"));
    std::fs::create_dir_all(&dir).unwrap();
    let log = dir.join(format!("da-fork-{name}-{}.anvil.log", std::process::id()));
    let out = std::fs::File::create(&log).unwrap();
    let mut cmd = Command::new(std::env::var("ANVIL").unwrap_or_else(|_| "anvil".into()));
    cmd.args(["--fork-url", &fork_url()])
        .args(["--chain-id", &DEPLOYMENT.chain_id.to_string()])
        .args(["--fork-chain-id", &DEPLOYMENT.chain_id.to_string()])
        .args(["--host", "127.0.0.1", "--port", &port.to_string()])
        .args(["--block-time", "1"])
        .arg("--auto-impersonate")
        .args([
            "--retries",
            "60",
            "--fork-retry-backoff",
            "2000",
            "--timeout",
            "60000",
        ])
        .stdin(Stdio::null())
        .stdout(out.try_clone().unwrap())
        .stderr(out);
    match std::env::var("ZKMINER_LOCALNET_FORK_BLOCK").as_deref() {
        Ok("latest") => {}
        Ok(b) => {
            cmd.args(["--fork-block-number", b]);
        }
        Err(_) => {
            cmd.args(["--fork-block-number", &FORK_BLOCK.to_string()]);
        }
    }
    let child = cmd
        .spawn()
        .expect("start anvil: install Foundry, or set ANVIL to its path");
    Anvil {
        child,
        url: format!("http://127.0.0.1:{port}"),
        log,
    }
}

async fn connect(anvil: &mut Anvil) -> DynProvider {
    let provider = ProviderBuilder::new()
        .connect_http(anvil.url.parse().unwrap())
        .erased();
    let started = Instant::now();
    loop {
        match provider.get_chain_id().await {
            Ok(id) => {
                assert_eq!(id, DEPLOYMENT.chain_id);
                break;
            }
            Err(e) => {
                if let Some(st) = anvil.child.try_wait().ok().flatten() {
                    panic!("anvil exited ({st}); see {}", anvil.log.display());
                }
                assert!(
                    started.elapsed() < Duration::from_secs(180),
                    "anvil did not come up ({e}); see {}",
                    anvil.log.display()
                );
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        }
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let _: serde_json::Value = provider
        .raw_request("evm_setTime".into(), (now,))
        .await
        .expect("evm_setTime");
    provider
}

fn config(rpc_url: &str) -> zkminer_config::ZkMinerConfig {
    let mut c = zkminer_config::ZkMinerConfig::default();
    c.chain.rpc_url = rpc_url.to_string();
    c.chain.chain_id = DEPLOYMENT.chain_id;
    c.chain.max_requests_per_sec = Some(50);
    c.contracts.hemi_prove = DEPLOYMENT.router.to_string();
    c.contracts.hemi_prove_staking = DEPLOYMENT.staking.to_string();
    c.contracts.hemi_prove_registry = DEPLOYMENT.registry.to_string();
    c.contracts.hemi_token = DEPLOYMENT.token.to_string();
    c.contracts.program_registry = DEPLOYMENT.program_registry.to_string();
    c
}

async fn rpc<T: alloy_json_rpc::RpcRecv>(
    p: &DynProvider,
    method: &'static str,
    params: serde_json::Value,
) -> T {
    p.raw_request(method.into(), params)
        .await
        .unwrap_or_else(|e| panic!("{method}: {e}"))
}

async fn set_balance(p: &DynProvider, a: Address, wei: u128) {
    let _: serde_json::Value = rpc(
        p,
        "anvil_setBalance",
        serde_json::json!([a, U256::from(wei)]),
    )
    .await;
}

async fn owner_of(p: &DynProvider, contract: Address) -> Address {
    let word = p
        .call(
            TransactionRequest::default()
                .to(contract)
                .input(Bytes::from(keccak256("owner()").0[..4].to_vec()).into()),
        )
        .await
        .expect("owner()");
    Address::from_word(B256::from_slice(&word))
}

/// Send from an impersonated address and require a successful receipt (retried while the fork's
/// upstream refuses a read, as localnet.rs does).
async fn mined(
    p: &DynProvider,
    tx: TransactionRequest,
    what: &str,
) -> alloy::rpc::types::TransactionReceipt {
    for tries in 1..=6 {
        match p.send_transaction(tx.clone()).await {
            Ok(pending) => {
                let r = tokio::time::timeout(Duration::from_secs(120), pending.get_receipt())
                    .await
                    .unwrap_or_else(|_| panic!("{what}: not mined"))
                    .unwrap_or_else(|e| panic!("{what}: {e}"));
                assert!(r.status(), "{what} reverted");
                return r;
            }
            Err(e) if tries < 6 => {
                eprintln!("da_fork: {what} refused ({e}); retrying in 10 s");
                tokio::time::sleep(Duration::from_secs(10)).await;
            }
            Err(e) => panic!("{what}: {e}"),
        }
    }
    unreachable!()
}

fn call_tx<C: SolCall>(from: Address, to: Address, call: C) -> TransactionRequest {
    TransactionRequest::default()
        .from(from)
        .to(to)
        .input(Bytes::from(call.abi_encode()).into())
}

fn fixture_seal() -> Bytes {
    alloy::hex::decode(FIXTURE_SEAL_HEX).unwrap().into()
}

/// The revert of an `eth_call` of `data` to the router from `from`, decoded.
async fn router_revert(p: &DynProvider, from: Address, data: Bytes) -> Decoded {
    let err = p
        .call(
            TransactionRequest::default()
                .from(from)
                .to(DEPLOYMENT.router)
                .gas_limit(12_000_000)
                .input(data.into()),
        )
        .await
        .expect_err("the call should revert");
    let data = err
        .as_error_resp()
        .and_then(|r| r.as_revert_data())
        .unwrap_or_else(|| panic!("no revert data in {err}"));
    decode(&data)
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs anvil and the 743111 RPC; see the module docs"]
async fn gas_price_oracle_estimates_on_the_fork() {
    let mut anvil = start_anvil("gpo");
    let p = connect(&mut anvil).await;
    // The predeploy is there, Fjord, with Hemi's fee parameters.
    assert!(
        !p.get_code_at(GAS_PRICE_ORACLE).await.unwrap().is_empty(),
        "no GasPriceOracle predeploy"
    );
    let gpo = IGasPriceOracle::new(GAS_PRICE_ORACLE, &p);
    assert!(
        gpo.isFjord().call().await.unwrap(),
        "GasPriceOracle is not Fjord"
    );
    let version = gpo.version().call().await.unwrap();
    let (l1_base_fee, scalar, blob_scalar) = (
        gpo.l1BaseFee().call().await.unwrap(),
        gpo.baseFeeScalar().call().await.unwrap(),
        gpo.blobBaseFeeScalar().call().await.unwrap(),
    );
    eprintln!(
        "GasPriceOracle {GAS_PRICE_ORACLE}: version {version}, Fjord, l1BaseFee {l1_base_fee}, \
         baseFeeScalar {scalar}, blobBaseFeeScalar {blob_scalar}"
    );

    let client = ChainClient::new(&config(&anvil.url), PrivateKeySigner::random())
        .await
        .expect("client on the fork");
    // The floor, an incompressible payload, and a compressible one.
    let to = Address::repeat_byte(0x11);
    let tx = |input: Vec<u8>| {
        da::unsigned_eip1559_tx(
            DEPLOYMENT.chain_id,
            7,
            21_000,
            2_000,
            1_000,
            to,
            input.into(),
        )
    };
    let empty = da::estimated_da_bytes(&client, &tx(vec![])).await.unwrap();
    assert_eq!(empty, da::MIN_ESTIMATED_DA_BYTES, "the Fjord floor");
    for len in [200usize, 2_000, 20_000] {
        let random = da::incompressible(len, b"da_fork").to_vec();
        let t = tx(random);
        let est = da::estimated_da_bytes(&client, &t).await.unwrap();
        let bound = da::da_bytes_upper_bound(t.len());
        eprintln!(
            "random {len} B: unsigned tx {} B, estimated {est} B, offline bound {bound} B",
            t.len()
        );
        assert!(est <= bound, "the offline bound must cover the oracle");
        assert!(
            est >= len as u64 * 8 / 10,
            "incompressible data estimates near its length"
        );
        let zeros = da::estimated_da_bytes(&client, &tx(vec![0u8; len]))
            .await
            .unwrap();
        assert!(zeros < est, "zeros compress ({zeros} vs {est})");
        if len >= 2_000 {
            assert!(zeros * 4 < est, "zeros compress ({zeros} vs {est})");
        }
    }

    // The exact hashed fulfil: the fixture journal and seal, and a 1 KB callbackExtraData.
    let d = descriptor(B256::repeat_byte(5), 1_024);
    let f = HashedFulfil::from_descriptor(&d);
    let job = B256::repeat_byte(9);
    let exact = da::estimate_fulfil_da_bytes(
        &client,
        job,
        &f,
        FIXTURE_JOURNAL,
        &SealSpec::Exact(fixture_seal()),
    )
    .await
    .unwrap();
    let placeholder = da::estimate_fulfil_da_bytes(
        &client,
        job,
        &f,
        FIXTURE_JOURNAL,
        &SealSpec::risc0_groth16(),
    )
    .await
    .unwrap();
    eprintln!(
        "hashed fulfil (1 KB callbackExtraData): exact {exact:?}, placeholder {placeholder:?}"
    );
    assert_eq!(
        exact.calldata_len,
        fulfill_job_hashed_calldata(job, &f, FIXTURE_JOURNAL, &fixture_seal()).len()
    );
    assert!(exact.is_large(), "a 1 KB extra makes the fulfil large");
    assert!(exact.estimated_bytes.abs_diff(placeholder.estimated_bytes) <= 4);
    // Without the extra, the fixture's fulfil is a standard one.
    let small = HashedFulfil::from_descriptor(&descriptor(B256::repeat_byte(5), 0));
    let std_est = da::estimate_fulfil_da_bytes(
        &client,
        job,
        &small,
        FIXTURE_JOURNAL,
        &SealSpec::Exact(fixture_seal()),
    )
    .await
    .unwrap();
    eprintln!("hashed fulfil (no extras): {std_est:?}");
    assert!(
        !std_est.is_large(),
        "the fixture's own fulfil is standard size"
    );
    // The conservative fields never under-estimate the transaction actually sent.
    let real = da::unsigned_eip1559_tx(
        DEPLOYMENT.chain_id,
        3,
        10_000_000,
        1_000_000_000,
        10_000_000,
        DEPLOYMENT.router,
        fulfill_job_hashed_calldata(job, &small, FIXTURE_JOURNAL, &fixture_seal()),
    );
    assert!(da::estimated_da_bytes(&client, &real).await.unwrap() <= std_est.estimated_bytes);
}

/// A FULL-bound job for the receipt fixture, with `extra` bytes of incompressible
/// `callbackExtraData` (no callback contract: the router only hashes it) and a large `inputData` that
/// `fulfillJobHashed` must leave out.
fn descriptor(tag: B256, extra: usize) -> JobDescriptor {
    let psid = risc_zero_groth16_v1_id();
    JobDescriptor {
        programId: FIXTURE_IMAGE_ID,
        proofSystemId: psid,
        callbackContract: Address::ZERO,
        assignedProver: Address::ZERO,
        tag,
        inputData: da::incompressible(8_192, b"witness envelope"),
        callbackExtraData: da::incompressible(extra, b"callback extra"),
        extraVerifierData: Bytes::new(),
        expectedJournalHash: full_hash(psid, FIXTURE_IMAGE_ID, FIXTURE_JOURNAL),
        journalFields: B256::ZERO,
    }
}

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

/// Mine one block every `every` until `stop`.
fn mine_every(
    p: DynProvider,
    every: Duration,
    stop: Arc<AtomicBool>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        while !stop.load(Ordering::SeqCst) {
            let _: Result<serde_json::Value, _> = p.raw_request("evm_mine".into(), ()).await;
            tokio::time::sleep(every).await;
        }
    })
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs anvil and the 743111 RPC; see the module docs"]
async fn fulfill_job_hashed_and_the_da_nonce_rule_on_the_fork() {
    let mut anvil = start_anvil("hashed");
    let p = connect(&mut anvil).await;
    // anvil's `safe` is head - 32: mine past the clock jump `connect` made, so the safe-head lag is
    // anvil's ~32 s and the head-advance trigger (not the lag) is what step 5 exercises.
    let _: serde_json::Value = rpc(&p, "anvil_mine", serde_json::json!(["0x28"])).await;
    let prover = PrivateKeySigner::random();
    let submitter = Address::from_word(keccak256(b"zkminer da_fork submitter"));
    let token_owner = owner_of(&p, DEPLOYMENT.token).await;
    for a in [token_owner, submitter, prover.address()] {
        set_balance(&p, a, 100 * HEMI).await;
    }
    let stake = 1_000 * HEMI;
    let price = 5 * HEMI;
    mined(
        &p,
        call_tx(
            token_owner,
            DEPLOYMENT.token,
            ITestnetToken::mintCall {
                to: submitter,
                amount: U256::from(10 * price),
            },
        ),
        "mint to the submitter",
    )
    .await;
    mined(
        &p,
        call_tx(
            token_owner,
            DEPLOYMENT.token,
            ITestnetToken::mintCall {
                to: prover.address(),
                amount: U256::from(stake),
            },
        ),
        "mint to the prover",
    )
    .await;
    mined(
        &p,
        call_tx(
            prover.address(),
            DEPLOYMENT.token,
            IERC20::approveCall {
                spender: DEPLOYMENT.staking,
                amount: U256::from(stake),
            },
        ),
        "approve the stake",
    )
    .await;
    mined(
        &p,
        call_tx(
            prover.address(),
            DEPLOYMENT.staking,
            IHemiProveStaking::stakeCall {
                prover: prover.address(),
                amount: stake,
            },
        ),
        "stake",
    )
    .await;
    mined(
        &p,
        call_tx(
            submitter,
            DEPLOYMENT.token,
            IERC20::approveCall {
                spender: DEPLOYMENT.router,
                amount: U256::MAX,
            },
        ),
        "approve the deposits",
    )
    .await;

    // A job whose hashed fulfil is LARGE (1 KB of incompressible callbackExtraData) and whose
    // 8 KB inputData the hashed fulfil leaves out.
    let d = descriptor(keccak256(b"da_fork large"), 1_024);
    let r = mined(
        &p,
        call_tx(
            submitter,
            DEPLOYMENT.router,
            IHemiProveCore::submitJobCall {
                descriptor: d.clone(),
                config: fixed_price(price),
                cycleConfig: no_cycles(),
                bidConfig: no_bidding(),
            },
        ),
        "submit the job",
    )
    .await;
    let job = r
        .inner
        .logs()
        .iter()
        .find_map(|l| l.log_decode::<IHemiProveCore::JobSubmitted>().ok())
        .map(|l| l.inner.data.jobId)
        .expect("JobSubmitted");
    // A block past the stake's deposit block (claims need `block.number > depositBlock`).
    let _: serde_json::Value = rpc(&p, "evm_mine", serde_json::json!([])).await;

    let client = ChainClient::new(&config(&anvil.url), prover.clone())
        .await
        .expect("client");
    let f = HashedFulfil::from_descriptor(&d);
    let seal = fixture_seal();
    let journal = Bytes::from_static(FIXTURE_JOURNAL);
    let calldata = fulfill_job_hashed_calldata(job, &f, &journal, &seal);
    assert_eq!(
        calldata[..4],
        IHemiProveFulfill::fulfillJobHashedCall::SELECTOR
    );

    // 1. Claimability: the static gate's read, as the prover and as an unstaked address.
    let quote = client
        .claimability(job, prover.address())
        .await
        .expect("claimable");
    assert_eq!(quote.price_floor, price);
    let unstaked = client
        .claimability(job, Address::repeat_byte(0x77))
        .await
        .expect_err("unstaked");
    eprintln!(
        "claimability: prover {quote:?}; unstaked address: {unstaked} ({:?})",
        unstaked.class()
    );
    assert!(
        matches!(
            unstaked,
            zkminer_chain::claimability::NotClaimable::Stake { .. }
        ),
        "{unstaked:?}"
    );

    // 2. The selector routes to the fulfil facet: on an Open job it reverts JobNotLocked(jobId).
    match router_revert(&p, prover.address(), calldata.clone()).await {
        Decoded::Hemi(E::JobNotLocked(e)) => assert_eq!(e.jobId, job),
        other => panic!("fulfillJobHashed on an Open job: {}", other.name()),
    }

    // 3. Claim.
    let claimed = client.claim_job_idempotent(job, 0).await.expect("claim");
    let lock_block = match claimed {
        zkminer_chain::jobs::ClaimOutcome::Claimed(r) => r.block,
        other => panic!("claim: {other:?}"),
    };
    let rec = client
        .read_job_record(job, Some(lock_block))
        .await
        .unwrap()
        .0;
    assert_eq!((rec.status, rec.prover), (1, prover.address()));
    assert_eq!(
        f.descriptor_hash(),
        rec.descriptor_hash,
        "the hashed descriptor rebuilds the stored hash"
    );

    // 4. Locked: the descriptor hash rebuilt from the hashed fields and the FULL binding both pass —
    //    the call reaches the verifier, which refuses the fixture (this fork's verifier is not
    //    risc0-ethereum v3.1's). A wrong inputData hash stops at the descriptor check instead.
    match router_revert(&p, prover.address(), calldata.clone()).await {
        Decoded::Hemi(E::VerifierCallFailed(_)) => {}
        other => panic!("fulfillJobHashed on our lock: {}", other.name()),
    }
    let mut wrong = f.clone();
    wrong.hashed.inputDataHash = keccak256(b"not the input");
    match router_revert(
        &p,
        prover.address(),
        fulfill_job_hashed_calldata(job, &wrong, &journal, &seal),
    )
    .await
    {
        Decoded::Hemi(E::InvalidDescriptorHash(e)) => assert_eq!(e.expected, rec.descriptor_hash),
        other => panic!("a wrong inputDataHash: {}", other.name()),
    }
    let adapter = IHemiProveRegistry::new(DEPLOYMENT.registry, &p)
        .getAdapter(risc_zero_groth16_v1_id())
        .call()
        .await
        .unwrap()
        .adapter;
    let native = IVerifierAdapter::new(adapter, &p)
        .nativeVerifier()
        .call()
        .await
        .unwrap();
    // From here on, a stub verifier (code: STOP — every call returns) stands in for the real one, so
    // the fixture settles. The router's own checks are untouched.
    let _: serde_json::Value = rpc(&p, "anvil_setCode", serde_json::json!([native, "0x00"])).await;

    // 5. The DA nonce rule. Mining is stopped; the large fulfil is sent and pooled; then the block gas
    //    limit drops below the fulfil's 10M gas, so blocks keep coming without it — the shape of the
    //    sequencer's DA filter (the 21,000-gas self-transfer still fits).
    let _: serde_json::Value = rpc(&p, "evm_setIntervalMining", serde_json::json!([0])).await;
    let _: serde_json::Value = rpc(&p, "evm_setAutomine", serde_json::json!([false])).await;
    let throttled = FulfilDa {
        rule: NonceRuleConfig {
            unmined_blocks: 3,
            resend_backoff_blocks: 1_000,
            ..NonceRuleConfig::default()
        },
        // anvil's receipts carry no l1GasUsed, so a real reading is Unknown here: the same.
        backlog: BacklogSource::Fixed(BacklogReading::fixed(Backlog::Unknown, None)),
    };
    let mined_before = p.get_transaction_count(prover.address()).await.unwrap();
    let send = {
        let (client, f, journal, seal, da) = (
            client.clone(),
            f.clone(),
            journal.clone(),
            seal.clone(),
            throttled.clone(),
        );
        tokio::spawn(async move {
            client
                .fulfill_job_hashed(
                    job,
                    f,
                    journal,
                    seal,
                    Some(Duration::from_secs(240)),
                    Some(lock_block),
                    Some(&da),
                )
                .await
        })
    };
    // Wait for the fulfil in the pool.
    let started = Instant::now();
    let fulfil_hash = loop {
        let pool: serde_json::Value = rpc(&p, "txpool_content", serde_json::json!([])).await;
        let mine = pool["pending"]
            .as_object()
            .and_then(|m| {
                m.iter()
                    .find(|(a, _)| a.eq_ignore_ascii_case(&format!("{:#x}", prover.address())))
            })
            .and_then(|(_, txs)| txs.get(mined_before.to_string()).cloned());
        if let Some(tx) = mine {
            assert_eq!(
                tx["input"].as_str().unwrap().get(..10),
                Some("0x80f765f2"),
                "fulfillJobHashed"
            );
            break tx["hash"].as_str().unwrap().parse::<B256>().unwrap();
        }
        assert!(
            started.elapsed() < Duration::from_secs(60),
            "the fulfil never reached the pool"
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    };
    let tracked = loop {
        let t = client.da_book().get(mined_before);
        if let Some(t) = t {
            break t;
        }
        assert!(
            started.elapsed() < Duration::from_secs(60),
            "the DA book never tracked the fulfil"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    };
    eprintln!(
        "large fulfil pooled at nonce {mined_before}: {fulfil_hash} ({} estimated DA bytes)",
        tracked.estimated_bytes
    );
    assert!(tracked.is_large());
    let _: serde_json::Value = rpc(
        &p,
        "anvil_setBlockGasLimit",
        serde_json::json!(["0x4c4b40"]),
    )
    .await;
    let stop = Arc::new(AtomicBool::new(false));
    let miner = mine_every(p.clone(), Duration::from_millis(1_500), stop.clone());
    let out = tokio::time::timeout(Duration::from_secs(300), send)
        .await
        .expect("the fulfil returned")
        .unwrap();
    let failure = out.expect_err("a held fulfil is not settled");
    let failure = failure
        .downcast_ref::<FulfilFailure>()
        .expect("a typed failure");
    eprintln!("fulfil returned: {failure}");
    assert_eq!(failure.class, FulfilClass::Keep);
    assert_eq!(failure.error_name, da::DA_THROTTLE_HOLD_NAME);
    assert!(failure.published);
    assert!(
        failure.reason.contains("head advanced"),
        "the head-advance trigger: {}",
        failure.reason
    );
    // The nonce was spent by a self-transfer; the fulfil is gone; the lock is intact.
    let deadline = Instant::now() + Duration::from_secs(60);
    while p.get_transaction_count(prover.address()).await.unwrap() <= mined_before {
        assert!(Instant::now() < deadline, "the replacement never mined");
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    assert!(
        p.get_transaction_by_hash(fulfil_hash)
            .await
            .unwrap()
            .is_none_or(|t| t.block_number.is_none()),
        "the replaced fulfil must not be mined"
    );
    let replacement = find_tx_at(&p, prover.address(), mined_before).await;
    assert_eq!(replacement.to, Some(prover.address()), "a self-transfer");
    assert_eq!(replacement.gas_limit, 21_000);
    assert!(replacement.input.is_empty());
    let rec = client.read_job_record(job, None).await.unwrap().0;
    assert_eq!(
        (rec.status, rec.prover),
        (1, prover.address()),
        "the lock is kept"
    );
    let replaced = client
        .da_book()
        .replaced(job)
        .expect("recorded for a re-send");
    eprintln!(
        "replaced at nonce {} (head {}), by {}",
        replaced.nonce, replaced.head, replacement.hash
    );

    // 6. Still throttled (unknown, inside the back-off): held, and no nonce touched.
    let before = p
        .get_transaction_count(prover.address())
        .block_id(alloy::eips::BlockId::pending())
        .await
        .unwrap();
    let held = client
        .fulfill_job_hashed(
            job,
            f.clone(),
            journal.clone(),
            seal.clone(),
            Some(Duration::from_secs(30)),
            Some(lock_block),
            Some(&throttled),
        )
        .await
        .expect_err("held");
    let held = held.downcast_ref::<FulfilFailure>().unwrap();
    assert_eq!(
        (held.class, held.error_name.as_str()),
        (FulfilClass::Keep, da::DA_THROTTLE_HOLD_NAME)
    );
    assert_eq!(
        p.get_transaction_count(prover.address())
            .block_id(alloy::eips::BlockId::pending())
            .await
            .unwrap(),
        before
    );

    // 7. The throttle clears (a reading that fits, a short safe-head lag): re-sent at a fresh nonce
    //    and settled.
    stop.store(true, Ordering::SeqCst);
    miner.await.unwrap();
    let _: serde_json::Value = rpc(
        &p,
        "anvil_setBlockGasLimit",
        serde_json::json!(["0x1c9c380"]),
    )
    .await;
    let _: serde_json::Value = rpc(&p, "evm_setIntervalMining", serde_json::json!([1])).await;
    let clear = FulfilDa {
        backlog: BacklogSource::Fixed(BacklogReading::fixed(Backlog::Known(0), Some(30))),
        ..throttled.clone()
    };
    client
        .fulfill_job_hashed(
            job,
            f.clone(),
            journal.clone(),
            seal.clone(),
            Some(Duration::from_secs(180)),
            Some(lock_block),
            Some(&clear),
        )
        .await
        .expect("re-sent and fulfilled");
    let view = IHemiProveAux::new(DEPLOYMENT.router, &p)
        .getJobStatusView(job)
        .call()
        .await
        .unwrap();
    assert_eq!(view.status, 2, "Fulfilled");
    let settled = find_tx_at(&p, prover.address(), mined_before + 1).await;
    assert_eq!(
        settled.input.get(..4),
        Some(&IHemiProveFulfill::fulfillJobHashedCall::SELECTOR[..])
    );
    assert!(
        !settled
            .input
            .windows(32)
            .any(|w| w == &d.inputData[100..132]),
        "inputData stays out of the calldata"
    );
    assert!(client.da_book().replaced(job).is_none() && client.da_book().unmined_bytes() == 0);

    // 8. The reader on anvil: no l1GasUsed in its receipts, so the backlog is Unknown (above
    //    threshold for the claim gate), with anvil's safe-head lag (head - 32 blocks).
    let reading = BacklogReader::default().read(&client).await;
    eprintln!("backlog reading on anvil: {reading:?}");
    assert!(reading.safe_lag_secs.is_some());
    eprintln!("da_fork: pass (anvil log {})", anvil.log.display());
}

/// The mined transaction `from` sent at `nonce` (scans back from the head).
async fn find_tx_at(p: &DynProvider, from: Address, nonce: u64) -> SimpleTx {
    let head = p.get_block_number().await.unwrap();
    for n in (head.saturating_sub(400)..=head).rev() {
        let b = p
            .get_block_by_number(alloy::eips::BlockNumberOrTag::Number(n))
            .full()
            .await
            .unwrap()
            .unwrap();
        for tx in b.transactions.txns() {
            use alloy::consensus::Transaction as _;
            if tx.inner.signer() == from && tx.nonce() == nonce {
                return SimpleTx {
                    hash: *tx.inner.tx_hash(),
                    to: tx.to(),
                    gas_limit: tx.gas_limit(),
                    input: tx.input().clone(),
                };
            }
        }
    }
    panic!("no mined transaction from {from} at nonce {nonce}");
}

#[derive(Debug)]
struct SimpleTx {
    hash: B256,
    to: Option<Address>,
    gas_limit: u64,
    input: Bytes,
}

/// The §13.5 reading against the real op-geth endpoint (read-only; the public testnet RPC unless
/// `ZKMINER_LOCALNET_FORK_URL` names another): its receipts carry `l1GasUsed`, so the backlog is
/// Known, and a second reading fetches only new blocks.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "reads the 743111 RPC; see the module docs"]
async fn backlog_reading_on_the_live_endpoint() {
    let mut c = config(&fork_url());
    c.chain.max_requests_per_sec = Some(2);
    let client = ChainClient::new_watch_only(&c, Address::repeat_byte(0x42))
        .await
        .expect("watch-only client on the live endpoint");
    let lag = client.safe_head_lag().await.expect("safe-head lag");
    eprintln!(
        "live: head {} safe {} lag {} s",
        lag.head,
        lag.safe,
        lag.lag_secs()
    );
    let reader = BacklogReader::default();
    let first = reader.read(&client).await;
    eprintln!("live reading 1: {first:?}");
    if lag.head - lag.safe > reader.config().max_blocks {
        assert_eq!(
            first.backlog,
            Backlog::Unknown,
            "a lag past the scan cap is unknown"
        );
        return;
    }
    assert!(matches!(first.backlog, Backlog::Known(_)), "{first:?}");
    tokio::time::sleep(Duration::from_secs(13)).await;
    let second = reader.read(&client).await;
    eprintln!("live reading 2: {second:?}");
    assert!(matches!(second.backlog, Backlog::Known(_)), "{second:?}");
    let window = second.head.unwrap() - second.safe.unwrap();
    assert!(
        second.blocks_fetched < window.max(1) || window <= 2,
        "the cache spares blocks already read ({} fetched of {window})",
        second.blocks_fetched
    );
    // The claim gate's view of it.
    let policy = da::DaCapPolicy::default();
    eprintln!(
        "claim gate at this backlog: 455 B {:?}, 2,048 B {:?}",
        policy.fulfil_fits(455, second.backlog),
        policy.fulfil_fits(2_048, second.backlog)
    );
}
