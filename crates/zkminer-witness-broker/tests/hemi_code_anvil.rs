//! `hemi-code` reads (plan §13.4) through the broker's control channel against anvil 1.7.1: chunk
//! and manifest contracts deployed with `manifest::creation_code` (signed by anvil for its dev
//! account), read back into sealed memfds, and every failure class.
//!
//! anvil's tags: `safe` = latest − 32 and `finalized` = latest − 64 (saturating at 0) by default
//! (`--slots-in-an-epoch`, default 32), so a read fixed at the latest block is never at or below
//! `safe` however many blocks are mined; `--slots-in-an-epoch 0` makes `safe` equal latest, so every
//! read is at the safe head.

mod common;

use std::os::unix::fs::FileExt;
use std::sync::{Arc, Mutex};

use alloy_primitives::{Address, B256};
use common::*;
use zkminer_witness::ipc::{ArtifactFailure, ArtifactSource};
use zkminer_witness::manifest::{manifest_runtime_code, sha256, ARTIFACT_MANIFEST_TAG_V1};
use zkminer_witness_broker::client::{ArtifactCharge, ArtifactRequest, BrokerClient, FetchedArtifact};
use zkminer_witness_broker::testkit::{config_text, test_hooks};

const ANVIL_CHAIN: u64 = 31337;

fn artifacts(anvil: &Anvil) -> String {
    format!(
        "[artifacts]\nalias = \"anvil\"\nurl = \"{}\"\nchain_id = {ANVIL_CHAIN}\nmax_requests_per_sec = 1000\nmax_builder_bytes = 33554432\ncidrs = [\"127.0.0.1/32\"]\n",
        anvil.url
    )
}

struct Reader {
    client: BrokerClient,
    _task: tokio::task::JoinHandle<anyhow::Result<()>>,
    _dir: tempfile::TempDir,
    charges: Arc<Mutex<Vec<ArtifactCharge>>>,
}

impl Reader {
    async fn new(anvil: &Anvil) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let (client, task) = start(dir.path(), &config_text(dir.path(), &artifacts(anvil)), test_hooks()).await;
        Self { client, _task: task, _dir: dir, charges: Arc::default() }
    }

    async fn fetch_with(
        &self,
        manifest: Address,
        builder_type: u8,
        expected: Option<B256>,
        max_bytes: u64,
        proceed: bool,
        chain_id: u64,
    ) -> Result<FetchedArtifact, ArtifactFailure> {
        let req = ArtifactRequest {
            job_key: B256::repeat_byte(1),
            caller: Address::repeat_byte(2),
            source: ArtifactSource::HemiCode { chain_id, manifest },
            builder_type,
            expected_sha256: expected,
            max_bytes,
            held_lock: false,
        };
        let charges = self.charges.clone();
        self.client
            .fetch_artifact(req, move |c| {
                charges.lock().unwrap().push(c);
                async move { proceed }
            })
            .await
            .expect("control channel")
    }

    async fn fetch(&self, manifest: Address, expected: Option<B256>) -> Result<FetchedArtifact, ArtifactFailure> {
        let ty = if expected.is_some() { 1 } else { 2 };
        self.fetch_with(manifest, ty, expected, 1 << 25, true, ANVIL_CHAIN).await
    }

    fn charges(&self) -> Vec<(u64, u32)> {
        self.charges.lock().unwrap().iter().map(|c| (c.length, c.chunks)).collect()
    }
}

fn contents(a: &FetchedArtifact) -> Vec<u8> {
    let mut v = vec![0u8; a.len as usize];
    a.memfd.read_exact_at(&mut v, 0).unwrap();
    v
}

#[tokio::test]
async fn reads_verifies_and_caches_artifacts() {
    let anvil = Anvil::start(&[]).await;
    let r = Reader::new(&anvil).await;
    // 300 chunks: two JSON-RPC batches (256 + 44).
    let small = publish(&anvil, &pattern(30_000, 1), 100).await;
    let a = r.fetch(small.manifest, Some(small.sha256)).await.unwrap();
    assert_eq!((a.len, a.sha256, a.cached), (30_000, small.sha256, false));
    assert_eq!(contents(&a), small.bytes);
    assert_eq!(r.charges(), vec![(30_000, 300)], "charged before any chunk read");
    // Cached by (type, sha256): no reads, no charge.
    let b = r.fetch(small.manifest, Some(small.sha256)).await.unwrap();
    assert!(b.cached);
    assert_eq!(contents(&b), small.bytes);
    assert_eq!(r.charges().len(), 1);
    // A type whose id is not the sha256 (2): keyed on the broker's own hash of the manifest's bytes,
    // found after the manifest read on the second fetch.
    let c = r.fetch(small.manifest, None).await.unwrap();
    assert!(!c.cached);
    assert_eq!(r.charges().len(), 2);
    let d = r.fetch(small.manifest, None).await.unwrap();
    assert!(d.cached);
    assert_eq!((d.sha256, r.charges().len()), (small.sha256, 2));

    // Full-size chunks (24,575-byte bodies, 24,576 bytes of code).
    let big = publish(&anvil, &pattern(2 * 24_575 + 10, 2), 24_575).await;
    let e = r.fetch(big.manifest, Some(big.sha256)).await.unwrap();
    assert_eq!(contents(&e), big.bytes);
    assert_eq!(r.charges().last(), Some(&(49_160, 3)));
}

#[tokio::test]
async fn failures_are_classified_and_unsafe_ones_are_not_remembered() {
    let anvil = Anvil::start(&[]).await;
    let r = Reader::new(&anvil).await;
    let good = publish(&anvil, &pattern(1_000, 3), 400).await;
    let other = publish(&anvil, &pattern(1_500, 4), 400).await;
    let good_code = anvil.code(good.manifest).await;

    // Empty manifest: transient, never remembered.
    let nowhere = Address::repeat_byte(0x42);
    assert_eq!(r.fetch(nowhere, None).await.unwrap_err(), ArtifactFailure::EmptyManifest);
    assert_eq!(r.fetch(nowhere, None).await.unwrap_err(), ArtifactFailure::EmptyManifest);

    // Structurally bad (wrong tag), read above the safe head: per job, not remembered...
    let mut bad = manifest_runtime_code(1_000, &good.sha256.0, &good.chunks);
    bad[1] ^= 0xff;
    assert_ne!(bad[1..33], ARTIFACT_MANIFEST_TAG_V1[..]);
    let bad_addr = anvil.deploy(&bad).await;
    let unsafe_invalid = ArtifactFailure::ManifestInvalid { at_or_below_safe: false };
    assert_eq!(r.fetch(bad_addr, None).await.unwrap_err(), unsafe_invalid);
    // ...however many blocks are mined: anvil's safe head trails the latest block by 32.
    anvil.mine(100).await;
    assert_eq!(anvil.block_number().await - anvil.tag_number("safe").await, 32);
    assert_eq!(r.fetch(bad_addr, None).await.unwrap_err(), unsafe_invalid);
    // So when the code at that address changes (as a reorg could make it), the next read sees it.
    anvil.set_code(bad_addr, &good_code).await;
    assert_eq!(contents(&r.fetch(bad_addr, Some(good.sha256)).await.unwrap()), good.bytes);

    // A chunk whose code starts 0xef (an EIP-7702 designator; EIP-3541 forbids deploying it, so
    // anvil_setCode puts it there).
    let ef = publish(&anvil, &pattern(800, 5), 400).await;
    let mut designator = vec![0xef, 0x01, 0x00];
    designator.extend_from_slice(Address::repeat_byte(7).as_slice());
    anvil.set_code(ef.chunks[1], &designator).await;
    assert_eq!(
        r.fetch(ef.manifest, Some(ef.sha256)).await.unwrap_err(),
        ArtifactFailure::ChunkInvalid { at_or_below_safe: false }
    );

    // Chunks that assemble to bytes with another hash.
    let lie = sha256(&pattern(1_000, 9));
    let liar = anvil.deploy(&manifest_runtime_code(1_000, &lie, &good.chunks)).await;
    let mismatch = ArtifactFailure::HashMismatch { at_or_below_safe: false };
    assert_eq!(r.fetch(liar, None).await.unwrap_err(), mismatch);
    assert_eq!(r.fetch(liar, Some(B256::from(lie))).await.unwrap_err(), mismatch);
    // Chunks shorter than the manifest's length.
    let short = anvil.deploy(&manifest_runtime_code(1_001, &good.sha256.0, &good.chunks)).await;
    assert_eq!(r.fetch(short, None).await.unwrap_err(), ArtifactFailure::ChunkInvalid { at_or_below_safe: false });

    // Valid, but for another artifact: bad for that (manifest, builderId) pair only.
    assert_eq!(r.fetch(good.manifest, Some(other.sha256)).await.unwrap_err(), ArtifactFailure::IdMismatch);
    anvil.set_code(good.manifest, &anvil.code(other.manifest).await).await;
    assert_eq!(
        r.fetch(good.manifest, Some(other.sha256)).await.unwrap_err(),
        ArtifactFailure::IdMismatch,
        "remembered for the pair, without reading"
    );
    assert_eq!(contents(&r.fetch(good.manifest, None).await.unwrap()), other.bytes, "not for the manifest");

    // Larger than the caller's max_bytes; a refused charge; another chain.
    let fresh = publish(&anvil, &pattern(2_000, 6), 500).await;
    assert_eq!(
        r.fetch_with(fresh.manifest, 1, Some(fresh.sha256), 1_999, true, ANVIL_CHAIN).await.unwrap_err(),
        ArtifactFailure::TooLarge
    );
    assert_eq!(
        r.fetch_with(fresh.manifest, 1, Some(fresh.sha256), 1 << 20, false, ANVIL_CHAIN).await.unwrap_err(),
        ArtifactFailure::Budget
    );
    assert_eq!(r.charges().last(), Some(&(2_000, 4)));
    assert_eq!(
        r.fetch_with(fresh.manifest, 1, Some(fresh.sha256), 1 << 20, true, 1).await.unwrap_err(),
        ArtifactFailure::NotConfigured
    );
    assert_eq!(contents(&r.fetch(fresh.manifest, Some(fresh.sha256)).await.unwrap()), fresh.bytes);
}

#[tokio::test]
async fn failures_at_the_safe_head_are_remembered_per_manifest() {
    // safe == latest: every fixed read block is at the safe head.
    let anvil = Anvil::start(&["--slots-in-an-epoch", "0"]).await;
    anvil.mine(3).await;
    assert_eq!(anvil.tag_number("safe").await, anvil.block_number().await);
    let r = Reader::new(&anvil).await;
    let good = publish(&anvil, &pattern(900, 7), 300).await;
    let good_code = anvil.code(good.manifest).await;

    let bad_addr = anvil.deploy(&{
        let mut c = manifest_runtime_code(900, &good.sha256.0, &good.chunks);
        c[5] ^= 1; // the tag
        c
    })
    .await;
    let safe_invalid = ArtifactFailure::ManifestInvalid { at_or_below_safe: true };
    assert_eq!(r.fetch(bad_addr, None).await.unwrap_err(), safe_invalid);
    // Remembered by address across jobs: a good manifest at that address is no longer read.
    anvil.set_code(bad_addr, &good_code).await;
    assert_eq!(r.fetch(bad_addr, Some(good.sha256)).await.unwrap_err(), safe_invalid);

    // A bad chunk at the safe head: remembered for the manifest, even once the chunk is fixed.
    let c = publish(&anvil, &pattern(600, 8), 300).await;
    let chunk_code = anvil.code(c.chunks[0]).await;
    anvil.set_code(c.chunks[0], &[0x00]).await; // an empty body
    let safe_chunk = ArtifactFailure::ChunkInvalid { at_or_below_safe: true };
    assert_eq!(r.fetch(c.manifest, Some(c.sha256)).await.unwrap_err(), safe_chunk);
    anvil.set_code(c.chunks[0], &chunk_code).await;
    assert_eq!(r.fetch(c.manifest, Some(c.sha256)).await.unwrap_err(), safe_chunk);
    // An empty manifest stays transient even at the safe head.
    let nowhere = Address::repeat_byte(0x43);
    assert_eq!(r.fetch(nowhere, None).await.unwrap_err(), ArtifactFailure::EmptyManifest);
    let late = publish(&anvil, &pattern(100, 9), 100).await;
    anvil.set_code(nowhere, &anvil.code(late.manifest).await).await;
    assert_eq!(contents(&r.fetch(nowhere, Some(late.sha256)).await.unwrap()), late.bytes);
}

#[tokio::test]
async fn an_unreachable_artifact_endpoint_is_operator_side() {
    let dir = tempfile::tempdir().unwrap();
    let text = config_text(
        dir.path(),
        "[artifacts]\nalias = \"down\"\nurl = \"http://127.0.0.1:1\"\nchain_id = 31337\nmax_requests_per_sec = 1000\ncidrs = [\"127.0.0.1/32\"]\n",
    );
    let (client, _t) = start(dir.path(), &text, test_hooks()).await;
    let req = ArtifactRequest {
        job_key: B256::ZERO,
        caller: Address::ZERO,
        source: ArtifactSource::HemiCode { chain_id: 31337, manifest: Address::repeat_byte(1) },
        builder_type: 1,
        expected_sha256: Some(B256::repeat_byte(3)),
        max_bytes: 1 << 20,
        held_lock: true,
    };
    let r = client.fetch_artifact(req, |_| async { true }).await.unwrap();
    assert_eq!(r.unwrap_err(), ArtifactFailure::Endpoint);
}
