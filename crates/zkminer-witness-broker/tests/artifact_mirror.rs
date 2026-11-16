//! The operator artifact mirror (`[artifacts.mirror]`, `…/{type}/{id}`) and the artifact cache it
//! shares with `hemi-code` reads.

mod common;

use std::os::unix::fs::FileExt;

use alloy_primitives::{Address, B256};
use common::*;
use zkminer_witness::ipc::{ArtifactFailure, ArtifactSource};
use zkminer_witness::manifest::sha256;
use zkminer_witness_broker::client::{ArtifactRequest, BrokerClient, FetchedArtifact};
use zkminer_witness_broker::testkit::{config_text, test_hooks, TestResponse, TestServer};

fn req(source: ArtifactSource, expected: Option<B256>, max_bytes: u64) -> ArtifactRequest {
    let builder_type = match source {
        ArtifactSource::Mirror { builder_type, .. } => builder_type,
        ArtifactSource::HemiCode { .. } => 1,
    };
    ArtifactRequest {
        job_key: B256::repeat_byte(1),
        caller: Address::ZERO,
        source,
        builder_type,
        expected_sha256: expected,
        max_bytes,
        held_lock: false,
    }
}

async fn fetch(c: &BrokerClient, r: ArtifactRequest) -> Result<FetchedArtifact, ArtifactFailure> {
    c.fetch_artifact(r, |_| async { panic!("mirror reads are not charged per chunk") }).await.unwrap()
}

fn read_all(a: &FetchedArtifact) -> Vec<u8> {
    let mut v = vec![0u8; a.len as usize];
    a.memfd.read_exact_at(&mut v, 0).unwrap();
    v
}

#[tokio::test]
async fn mirror_reads_are_verified_and_cached() {
    let dir = tempfile::tempdir().unwrap();
    let good = pattern(70_000, 1);
    let good_id = B256::from(sha256(&good));
    let lying_id = B256::repeat_byte(0x11);
    let image_id = B256::repeat_byte(0x22);
    let (g, gid) = (good.clone(), hex::encode(good_id));
    let (lid, iid) = (hex::encode(lying_id), hex::encode(image_id));
    let mirror = TestServer::start(move |r| {
        if r.path == format!("/a/1/{gid}") || r.path == format!("/a/2/{iid}") {
            TestResponse::ok(g.clone())
        } else if r.path == format!("/a/1/{lid}") {
            TestResponse::ok(b"something else".to_vec())
        } else {
            TestResponse::status(404)
        }
    })
    .await;
    let text = config_text(
        dir.path(),
        &format!(
            "[artifacts]\nalias = \"hemi\"\nurl = \"http://127.0.0.1:1\"\nchain_id = 31337\ncidrs = [\"127.0.0.1/32\"]\n\
             [artifacts.mirror]\nalias = \"am\"\nurl_template = \"{}/a/{{type}}/{{id}}\"\ncidrs = [\"127.0.0.1/32\"]\n",
            mirror.url()
        ),
    );
    let (c, _t) = start(dir.path(), &text, test_hooks()).await;

    let a = fetch(&c, req(ArtifactSource::Mirror { builder_type: 1, builder_id: good_id }, Some(good_id), 1 << 20)).await.unwrap();
    assert_eq!((a.len, a.sha256, a.cached), (70_000, good_id, false));
    assert_eq!(read_all(&a), good);
    let b = fetch(&c, req(ArtifactSource::Mirror { builder_type: 1, builder_id: good_id }, Some(good_id), 1 << 20)).await.unwrap();
    assert!(b.cached);
    assert_eq!(mirror.hits(), 1);
    // Fetch order: what the mirror delivered serves a hemi-code locator for the same builder id
    // from the cache (the artifact endpoint here is down).
    let h = fetch(&c, req(ArtifactSource::HemiCode { chain_id: 31337, manifest: Address::repeat_byte(5) }, Some(good_id), 1 << 20))
        .await
        .unwrap();
    assert!(h.cached);
    assert_eq!(read_all(&h), good);

    assert_eq!(
        fetch(&c, req(ArtifactSource::Mirror { builder_type: 1, builder_id: lying_id }, Some(lying_id), 1 << 20)).await.unwrap_err(),
        ArtifactFailure::MirrorMismatch
    );
    let missing = B256::repeat_byte(0x33);
    assert_eq!(
        fetch(&c, req(ArtifactSource::Mirror { builder_type: 1, builder_id: missing }, Some(missing), 1 << 20)).await.unwrap_err(),
        ArtifactFailure::MirrorMissing
    );
    // Type 2: the id is not a sha256; the broker returns its own hash of the bytes.
    let t2 = fetch(&c, req(ArtifactSource::Mirror { builder_type: 2, builder_id: image_id }, None, 1 << 20)).await.unwrap();
    assert_eq!(t2.sha256, good_id);
    assert_eq!(
        fetch(&c, req(ArtifactSource::Mirror { builder_type: 2, builder_id: image_id }, None, 69_999)).await.unwrap_err(),
        ArtifactFailure::TooLarge
    );

    // No mirror configured.
    let text = config_text(dir.path(), "[artifacts]\nalias = \"hemi\"\nurl = \"http://127.0.0.1:1\"\nchain_id = 31337\n");
    let (c, _t) = start(dir.path(), &text, test_hooks()).await;
    assert_eq!(
        fetch(&c, req(ArtifactSource::Mirror { builder_type: 1, builder_id: good_id }, Some(good_id), 1 << 20)).await.unwrap_err(),
        ArtifactFailure::NotConfigured
    );
    // No artifact endpoint at all.
    let (c, _t) = start(dir.path(), &config_text(dir.path(), ""), test_hooks()).await;
    assert_eq!(
        fetch(&c, req(ArtifactSource::HemiCode { chain_id: 31337, manifest: Address::ZERO }, None, 1 << 20)).await.unwrap_err(),
        ArtifactFailure::NotConfigured
    );
}
