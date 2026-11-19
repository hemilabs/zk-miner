//! `hemi-code` reads (plan §13.4) through the broker's control channel against anvil 1.7.1: chunk
//! and manifest contracts deployed with `manifest::creation_code` (signed by anvil for its dev
//! account), read back into sealed memfds, and every failure class.
//!
//! anvil's tags: `safe` = latest − 32 and `finalized` = latest − 64 (saturating at 0) by default
//! (`--slots-in-an-epoch`, default 32): a manifest deployed within the last 32 blocks is absent at
//! the safe head and read at the latest block (failures per job, pending), one deployed earlier is
//! read at the safe head (failures remembered); `--slots-in-an-epoch 0` makes `safe` equal latest,
//! so every read is at the safe head.

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

    // Structurally bad (wrong tag), read above the safe head (anvil's trails latest by 32): per
    // job, not remembered...
    let mut bad = manifest_runtime_code(1_000, &good.sha256.0, &good.chunks);
    bad[1] ^= 0xff;
    assert_ne!(bad[1..33], ARTIFACT_MANIFEST_TAG_V1[..]);
    let bad_addr = anvil.deploy(&bad).await;
    let unsafe_invalid = ArtifactFailure::ManifestInvalid { at_or_below_safe: false };
    assert_eq!(r.fetch(bad_addr, None).await.unwrap_err(), unsafe_invalid);
    assert_eq!(r.fetch(bad_addr, None).await.unwrap_err(), unsafe_invalid);
    // ...so when the code at that address changes (as a reorg could make it), the next read sees it.
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

    // Valid, but for another artifact, read above the safe head: per job, like every other failure
    // there (review F8: this once was remembered for the pair whatever the block)...
    assert_eq!(r.fetch(good.manifest, Some(other.sha256)).await.unwrap_err(), ArtifactFailure::IdMismatch);
    anvil.set_code(good.manifest, &anvil.code(other.manifest).await).await;
    // ...so the next read sees the new code.
    assert_eq!(contents(&r.fetch(good.manifest, Some(other.sha256)).await.unwrap()), other.bytes);
    assert_eq!(contents(&r.fetch(good.manifest, None).await.unwrap()), other.bytes, "nor for the manifest");

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

/// Review F8 and the safe-head design: a manifest deployed more than 32 blocks ago is read at the
/// safe head, so an invalid one is remembered on the first fetch; an id mismatch there is
/// remembered for the pair only.
#[tokio::test]
async fn an_invalid_manifest_below_the_safe_head_is_remembered_on_the_first_fetch() {
    let anvil = Anvil::start(&[]).await;
    let r = Reader::new(&anvil).await;
    let good = publish(&anvil, &pattern(700, 11), 300).await;
    let other = publish(&anvil, &pattern(800, 12), 300).await;
    let good_code = anvil.code(good.manifest).await;
    let mut bad = good_code.clone();
    bad[3] ^= 0x40; // the tag
    let bad_addr = anvil.deploy(&bad).await;
    anvil.mine(40).await;
    let safe_invalid = ArtifactFailure::ManifestInvalid { at_or_below_safe: true };
    assert_eq!(r.fetch(bad_addr, None).await.unwrap_err(), safe_invalid);
    // Remembered: a good manifest at that address is no longer read.
    anvil.set_code(bad_addr, &good_code).await;
    anvil.mine(40).await;
    assert_eq!(r.fetch(bad_addr, Some(good.sha256)).await.unwrap_err(), safe_invalid);

    // An id mismatch at the safe head: remembered for (manifest, builderId)...
    assert_eq!(r.fetch(good.manifest, Some(other.sha256)).await.unwrap_err(), ArtifactFailure::IdMismatch);
    anvil.set_code(good.manifest, &anvil.code(other.manifest).await).await;
    anvil.mine(40).await;
    assert_eq!(r.fetch(good.manifest, Some(other.sha256)).await.unwrap_err(), ArtifactFailure::IdMismatch, "without reading");
    // ...never for the manifest, which serves other ids.
    assert_eq!(contents(&r.fetch(good.manifest, None).await.unwrap()), other.bytes);
}

/// Within the last 32 blocks a failure is per job (pending), then promoted to remembered once the
/// safe head passes the block it was read at, if that block is still canonical.
#[tokio::test]
async fn a_failure_above_the_safe_head_is_promoted_once_the_safe_head_passes_it() {
    let anvil = Anvil::start(&[]).await;
    let r = Reader::new(&anvil).await;
    let good = publish(&anvil, &pattern(500, 13), 250).await;
    let other = publish(&anvil, &pattern(600, 14), 250).await;
    let good_code = anvil.code(good.manifest).await;
    let mut bad = good_code.clone();
    bad[20] ^= 1; // the tag
    let bad_addr = anvil.deploy(&bad).await;
    let pending = ArtifactFailure::ManifestInvalid { at_or_below_safe: false };
    assert_eq!(r.fetch(bad_addr, None).await.unwrap_err(), pending);
    assert_eq!(r.fetch(bad_addr, None).await.unwrap_err(), pending, "still above the safe head");
    // A pending id mismatch, too.
    let pair = anvil.deploy(&good_code).await;
    assert_eq!(r.fetch(pair, Some(other.sha256)).await.unwrap_err(), ArtifactFailure::IdMismatch);
    anvil.mine(40).await;
    let safe_invalid = ArtifactFailure::ManifestInvalid { at_or_below_safe: true };
    assert_eq!(r.fetch(bad_addr, None).await.unwrap_err(), safe_invalid, "promoted");
    assert_eq!(r.fetch(pair, Some(other.sha256)).await.unwrap_err(), ArtifactFailure::IdMismatch);
    // Remembered: new code at both addresses, safe by now, is not read.
    anvil.set_code(bad_addr, &good_code).await;
    anvil.set_code(pair, &anvil.code(other.manifest).await).await;
    anvil.mine(40).await;
    assert_eq!(r.fetch(bad_addr, Some(good.sha256)).await.unwrap_err(), safe_invalid, "and remembered");
    assert_eq!(r.fetch(pair, Some(other.sha256)).await.unwrap_err(), ArtifactFailure::IdMismatch, "the pair is remembered");
}

/// A reorg drops a pending failure instead of promoting it.
#[tokio::test]
async fn a_reorged_pending_failure_is_dropped() {
    let anvil = Anvil::start(&[]).await;
    let r = Reader::new(&anvil).await;
    let good = publish(&anvil, &pattern(400, 15), 200).await;
    let good_code = anvil.code(good.manifest).await;
    let snapshot = anvil.rpc("evm_snapshot", serde_json::json!([])).await;
    let mut bad = good_code.clone();
    bad[10] ^= 2;
    let bad_addr = anvil.deploy(&bad).await;
    assert_eq!(r.fetch(bad_addr, None).await.unwrap_err(), ArtifactFailure::ManifestInvalid { at_or_below_safe: false });
    // The block that held the deployment is replaced by other blocks at the same heights.
    assert_eq!(anvil.rpc("evm_revert", serde_json::json!([snapshot])).await, serde_json::json!(true));
    anvil.mine(50).await;
    assert!(anvil.code(bad_addr).await.is_empty());
    // Not promoted: the manifest is simply gone.
    assert_eq!(r.fetch(bad_addr, None).await.unwrap_err(), ArtifactFailure::EmptyManifest);
    // And nothing was remembered: a good manifest at that address serves.
    anvil.set_code(bad_addr, &good_code).await;
    assert_eq!(contents(&r.fetch(bad_addr, Some(good.sha256)).await.unwrap()), good.bytes);
}

/// Review F6 (the reviewer's PoC, inverted): a manifest that declares 256 bytes over 256 full-size
/// chunks no longer makes the broker take a ~12.6 MB batch: the batch's raw cap follows the
/// declared length, the read fails as an invalid chunk, and the endpoint's answer is cut off.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_under_declared_length_cannot_amplify_a_batch() {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use zkminer_witness::manifest::{chunk_runtime_code, MAX_CHUNK_BODY};
    let anvil = Anvil::start(&[]).await;
    let n = 256usize;
    let body = vec![0x5au8; MAX_CHUNK_BODY];
    let mut chunks = Vec::new();
    for i in 0..n {
        let mut a = [0u8; 20];
        a[0] = 0x77;
        a[16..].copy_from_slice(&(i as u32 + 1).to_be_bytes());
        let a = Address::from(a);
        anvil.set_code(a, &chunk_runtime_code(&body)).await;
        chunks.push(a);
    }
    let manifest = Address::repeat_byte(0x66);
    anvil.set_code(manifest, &manifest_runtime_code(n as u64, &[9u8; 32], &chunks)).await;
    anvil.mine(40).await;

    // A forwarding proxy that streams anvil's answer and records whether the broker took all of it.
    let largest = Arc::new(AtomicUsize::new(0));
    let cut_off = Arc::new(AtomicBool::new(false));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy = format!("http://{}", listener.local_addr().unwrap());
    let (anvil_url, l2, c2) = (anvil.url.clone(), largest.clone(), cut_off.clone());
    tokio::spawn(async move {
        let http = reqwest::Client::builder().no_proxy().build().unwrap();
        loop {
            let Ok((mut conn, _)) = listener.accept().await else { return };
            let (http, anvil_url, largest, cut_off) = (http.clone(), anvil_url.clone(), l2.clone(), c2.clone());
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut tmp = [0u8; 65536];
                let body_start = loop {
                    let k = conn.read(&mut tmp).await.unwrap_or(0);
                    if k == 0 {
                        return;
                    }
                    buf.extend_from_slice(&tmp[..k]);
                    if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        break i + 4;
                    }
                };
                let head = String::from_utf8_lossy(&buf[..body_start]).to_ascii_lowercase();
                let len: usize = head.lines().find_map(|l| l.strip_prefix("content-length:")).unwrap().trim().parse().unwrap();
                while buf.len() < body_start + len {
                    let k = conn.read(&mut tmp).await.unwrap_or(0);
                    if k == 0 {
                        return;
                    }
                    buf.extend_from_slice(&tmp[..k]);
                }
                let answer = http
                    .post(&anvil_url)
                    .header("content-type", "application/json")
                    .body(buf[body_start..].to_vec())
                    .send()
                    .await
                    .unwrap()
                    .bytes()
                    .await
                    .unwrap();
                largest.fetch_max(answer.len(), Ordering::SeqCst);
                // No Content-Length: the broker's cap is enforced while it streams.
                let _ = conn.write_all(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n").await;
                for piece in answer.chunks(16 << 10) {
                    if conn.write_all(piece).await.is_err() {
                        cut_off.store(true, Ordering::SeqCst);
                        return;
                    }
                }
                let _ = conn.shutdown().await;
            });
        }
    });
    let dir = tempfile::tempdir().unwrap();
    let text = config_text(
        dir.path(),
        &format!("[artifacts]\nalias = \"p\"\nurl = \"{proxy}\"\nchain_id = {ANVIL_CHAIN}\nmax_requests_per_sec = 1000\nmax_builder_bytes = 33554432\ncidrs = [\"127.0.0.1/32\"]\n"),
    );
    let (client, _t) = start(dir.path(), &text, test_hooks()).await;
    let charges = Arc::new(Mutex::new(Vec::new()));
    let c2 = charges.clone();
    let req = ArtifactRequest {
        job_key: B256::ZERO,
        caller: Address::ZERO,
        source: ArtifactSource::HemiCode { chain_id: ANVIL_CHAIN, manifest },
        builder_type: 2,
        expected_sha256: None,
        max_bytes: 1 << 25,
        held_lock: false,
    };
    let r = client
        .fetch_artifact(req, move |c| {
            c2.lock().unwrap().push((c.length, c.chunks));
            async { true }
        })
        .await
        .unwrap();
    assert_eq!(r.unwrap_err(), ArtifactFailure::ChunkInvalid { at_or_below_safe: true }, "remembered: read at the safe head");
    assert_eq!(*charges.lock().unwrap(), vec![(n as u64, n as u32)]);
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    assert!(largest.load(Ordering::SeqCst) > 12_000_000, "anvil did answer the whole batch");
    assert!(cut_off.load(Ordering::SeqCst), "the broker stopped reading it at its cap");
}
