//! One-shot helper: register a simple SP1 program (fibonacci) on ProgramRegistry,
//! host the ELF over local HTTP, and submit a fulfillable job to HemiProve.
//!
//! Usage: `zkminer sp1-demo --input 42`
//!
//! Flow:
//!   1. Read fibonacci-sp1-guest ELF from the packaged guest
//!   2. Derive vkey via sp1_sdk setup → that's the programId for SP1
//!   3. Spawn a local HTTP server bound to 127.0.0.1:PORT serving the ELF
//!   4. Register the program on ProgramRegistry with the HTTP URI
//!   5. Approve HemiProve for the deposit, submit a job via submitJobDefault
//!   6. Print the jobId — the miner will pick it up from the monitor

use alloy::primitives::{Address, B256, Bytes, U256, keccak256};
use anyhow::{Context, Result};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use zkminer_chain::client::ChainClient;
use zkminer_config::ZkMinerConfig;
use zkminer_config::wallet::load_signer;
use zkminer_contracts::bindings::{
    AuctionConfig, CompetitiveBidConfig, CycleConfig, IERC20, IHemiProveCore,
    IProgramRegistry, JobDescriptor, ResourceEstimate, StorageURI,
};

const FIBONACCI_ELF: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../zkminer-prover/guests/sp1/fibonacci/target/elf-compilation/riscv64im-succinct-zkvm-elf/release/fibonacci-sp1-guest",
));

pub async fn run(config_path: Option<&Path>, n: u32) -> Result<()> {
    // 0. sanity-check ELF is baked in
    if FIBONACCI_ELF.is_empty() {
        anyhow::bail!(
            "fibonacci-sp1-guest ELF is empty — rebuild the guest first. Expected at target/elf-compilation/..."
        );
    }
    println!("Loaded fibonacci-sp1-guest ELF: {} bytes", FIBONACCI_ELF.len());

    // 1. Derive SP1 vkey — that's the on-chain programId.
    //    Setup is expensive but we only do it once.
    println!("Deriving SP1 vkey (this may take a few seconds)...");
    let (vkey_bytes, content_hash) = tokio::task::spawn_blocking(|| compute_sp1_vkey(FIBONACCI_ELF))
        .await??;
    let program_id = B256::from(vkey_bytes);
    let content_hash = B256::from(content_hash);
    println!("  programId (vkey):  {program_id}");
    println!("  content_hash:      {content_hash}");

    // 2. Spawn local HTTP server on an ephemeral port, serving the ELF.
    let port = pick_free_port().context("could not bind local port")?;
    let elf_url = format!("http://127.0.0.1:{port}/fibonacci-sp1-guest.bin");
    tokio::spawn(serve_elf_forever(port));
    println!("Serving ELF at {elf_url}");
    // Brief warm-up so the listener is ready before registration.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // 3. Chain client
    let config = ZkMinerConfig::load(config_path)?;
    config.validate_for_chain()?;
    let signer = load_signer(&config.wallet)?;
    let client = ChainClient::new(&config, signer).await?;
    println!("Using wallet {}", client.address);

    // 4. Register the program (idempotent — skip if already registered)
    let sp1_v1 = zkminer_chain::auction::sp1_v1_id();
    let program_registry_addr = client
        .program_registry
        .context("program_registry address not configured")?;
    let registry = IProgramRegistry::new(program_registry_addr, &*client.provider);
    let already = registry.isRegistered(program_id).call().await?;
    if already {
        println!("Program already registered — skipping registerProgram");
    } else {
        println!("Registering program on ProgramRegistry...");
        let resources = ResourceEstimate {
            estimatedCycles: 200_000,
            peakMemoryBytes: 64 * 1024 * 1024,
            estimatedWallTimeS: 60,
        };
        let uri = StorageURI {
            storageType: 2, // HTTP
            uri: elf_url.clone(),
            contentHash: content_hash,
        };
        let family_id = keccak256(b"zkminer-sp1-demo");
        let tx = registry.registerProgram(
            program_id,
            sp1_v1,
            family_id,
            resources,
            "sp1-fibonacci-demo".to_string(),
            "Simple SP1 fibonacci(n) guest for zkminer end-to-end demo".to_string(),
            String::new(),
            vec![uri],
        );
        let pending = tx.send().await.context("registerProgram send failed")?;
        let receipt = pending.get_receipt().await.context("registerProgram receipt failed")?;
        if !receipt.status() {
            anyhow::bail!("registerProgram reverted");
        }
        println!("  registered in tx {}", receipt.transaction_hash);
    }

    // 5. Approve HemiProve to pull our deposit, then submitJobDefault
    // Standard preset deposit = maxPrice + speedPremium. Cover conservatively with
    // 10 HEMI (1e19 wei) — the standard preset on testnet is well under that.
    let deposit_approval = U256::from(10_000_000_000_000_000_000u128); // 10 HEMI
    let token = IERC20::new(client.hemi_token, &*client.provider);
    let allowance = token
        .allowance(client.address, client.hemi_prove)
        .call()
        .await?;
    if allowance < deposit_approval {
        println!("Approving HemiProve for {} wei of tHEMI...", deposit_approval);
        let tx = token.approve(client.hemi_prove, deposit_approval);
        let pending = tx.send().await?;
        let r = pending.get_receipt().await?;
        if !r.status() {
            anyhow::bail!("approve reverted");
        }
    }

    println!("Minting tHEMI in case balance is short...");
    use zkminer_contracts::bindings::ITestnetToken;
    let minter = ITestnetToken::new(client.hemi_token, &*client.provider);
    let mint_tx = minter.mint(client.address, deposit_approval);
    let _ = mint_tx.send().await?.get_receipt().await?; // best-effort

    // Input data for fibonacci(n) — SP1 `read::<u32>()` reads 4 LE bytes.
    let input_data = Bytes::from(n.to_le_bytes().to_vec());
    println!("Submitting job for fibonacci({n})...");
    let core = IHemiProveCore::new(client.hemi_prove, &*client.provider);
    let descriptor = JobDescriptor {
        programId: program_id,
        proofSystemId: sp1_v1,
        callbackContract: Address::ZERO,
        assignedProver: Address::ZERO,
        tag: B256::ZERO,
        inputData: input_data,
        callbackExtraData: Bytes::new(),
        extraVerifierData: Bytes::new(),
        expectedJournalHash: B256::ZERO, // no predicate for the demo
    };
    use alloy::primitives::aliases::{U40, U96};
    let auction = AuctionConfig {
        minPrice: U96::from(1_000_000_000_000_000_000u128), // 1 HEMI
        maxPrice: U96::from(5_000_000_000_000_000_000u128), // 5 HEMI
        rampUpPeriod: U40::from(60u64),
        curveType: 0, // Linear
        fulfillmentTimeout: U40::from(14_400u64), // 4h
        lockCollateralBps: U96::from(15_000u64), // 150%
        speedPremium: U96::from(0u64),
        exclusivityDuration: U40::from(0u64),
        callbackGasLimit: 0,
        excludeFromEwma: false,
        strictCallbackMode: false,
    };
    let cycle = CycleConfig {
        expectedCycles: 0,
        cycleCommitCollateral: U96::from(0u64),
        snapshotMode: 0,
        snapshotToleranceBps: 0,
        snapshotFullBonusOvershootBps: 0,
        snapshotUndershootPenaltyBps: 0,
        snapshotFullPenaltyUndershootBps: 0,
        snapshotResolverRewardBps: 0,
    };
    let bid = CompetitiveBidConfig {
        underbidWindow: U40::from(0u64),
        maxBiddingDuration: U40::from(0u64),
        maxBidExtension: U40::from(0u64),
        minBidDecrement: U96::from(0u64),
        bidExtensionCurveType: 0,
    };
    let submit_tx = core.submitJob(descriptor, auction, cycle, bid);
    let pending = submit_tx.send().await.context("submitJobDefault send failed")?;
    let receipt = pending.get_receipt().await?;
    if !receipt.status() {
        anyhow::bail!("submitJobDefault reverted");
    }
    // Extract jobId from the JobSubmitted event (topic1).
    let topic0 = keccak256(
        "JobSubmitted(bytes32,bytes32,address,bytes32,bytes32,uint96,uint96,uint96,uint40,uint8)",
    );
    let job_id = receipt
        .logs()
        .iter()
        .find(|l| l.topics().first() == Some(&topic0))
        .and_then(|l| l.topics().get(1).cloned())
        .context("JobSubmitted event not found in receipt")?;
    println!("Job submitted");
    println!("  tx:      {}", receipt.transaction_hash);
    println!("  jobId:   {job_id}");
    println!("  fibonacci({n})  →  input 0x{}", alloy::hex::encode(n.to_le_bytes()));
    println!();
    println!(
        "The zkminer should now pick this up via the monitor and produce a proof. \
         Keep this process running — the local HTTP server must stay up until the \
         miner downloads the ELF into its cache."
    );
    // Park until Ctrl-C so the HTTP server keeps serving
    tokio::signal::ctrl_c().await?;
    Ok(())
}

fn compute_sp1_vkey(elf: &[u8]) -> Result<([u8; 32], [u8; 32])> {
    // Compute the VKey using SP1's CPU prover setup. We don't run an actual
    // prove, just derive the verifying key. This is deterministic per ELF.
    use sp1_sdk::blocking::{Elf, Prover, ProverClient};
    use sp1_sdk::{HashableKey, ProvingKey};
    let client = ProverClient::builder().cpu().build();
    let pk = client.setup(Elf::from(elf.to_vec())).map_err(|e| anyhow::anyhow!("{e}"))?;
    let vk = pk.verifying_key();
    let vk_hash = vk.bytes32();
    // bytes32() returns a 0x-prefixed hex string of 32 bytes
    let vkey_bytes = hex_to_32(&vk_hash)?;
    let content_hash: [u8; 32] = keccak256(elf).into();
    Ok((vkey_bytes, content_hash))
}

fn hex_to_32(s: &str) -> Result<[u8; 32]> {
    let stripped = s.strip_prefix("0x").unwrap_or(s);
    let bytes = alloy::hex::decode(stripped).context("invalid hex for vkey")?;
    if bytes.len() != 32 {
        anyhow::bail!("expected 32-byte vkey, got {} bytes", bytes.len());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn pick_free_port() -> Result<u16> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    drop(listener);
    Ok(port)
}

async fn serve_elf_forever(port: u16) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    let addr: SocketAddr = ([127, 0, 0, 1], port).into();
    let listener = match TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("ELF server bind failed: {e}");
            return;
        }
    };
    loop {
        let (mut stream, _) = match listener.accept().await {
            Ok(v) => v,
            Err(_) => continue,
        };
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            let _ = stream.read(&mut buf).await; // discard request line
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: application/octet-stream\r\nConnection: close\r\n\r\n",
                FIBONACCI_ELF.len()
            );
            let _ = stream.write_all(response.as_bytes()).await;
            let _ = stream.write_all(FIBONACCI_ELF).await;
            let _ = stream.shutdown().await;
        });
    }
}
