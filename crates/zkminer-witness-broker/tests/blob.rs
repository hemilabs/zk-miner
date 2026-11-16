//! `blob/v1` end to end: RegisterJob over the control socket, `KIND_FETCH` frames from a fake
//! builder over the job socket, mirrors on a local HTTP server (127.0.0.1, admitted by role
//! entries), then EndJob and its JobStats.

mod common;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use alloy_primitives::B256;
use common::*;
use tokio::io::AsyncWriteExt;
use zkminer_witness::envelope::{encode_blob_config, CLASS_BLOB_V1};
use zkminer_witness::ipc::{FetchStatus, KIND_FETCH};
use zkminer_witness::manifest::sha256;
use zkminer_witness_broker::testkit::{config_text, test_hooks, TestRequest, TestResponse, TestServer};

fn blob(max: u64) -> (B256, Vec<u8>) {
    (CLASS_BLOB_V1, encode_blob_config(max))
}

fn mirrors(servers: &[&TestServer], extra: &str) -> String {
    let mut s = String::from(extra);
    for (i, m) in servers.iter().enumerate() {
        s.push_str(&format!(
            "\n[[blob_mirror]]\nalias = \"m{i}\"\nurl_template = \"{}/blobs/{{sha256}}\"\ncidrs = [\"127.0.0.1/32\"]\n",
            m.url()
        ));
    }
    s
}

/// A mirror serving `content` for its own hash (404 otherwise).
fn serving(content: Vec<u8>) -> impl Fn(TestRequest) -> TestResponse + Send + Sync + 'static {
    let path = format!("/blobs/{}", hex::encode(sha256(&content)));
    move |req| if req.path == path { TestResponse::ok(content.clone()) } else { TestResponse::status(404) }
}

#[tokio::test]
async fn fetches_verified_blobs_and_reports_job_stats() {
    let dir = tempfile::tempdir().unwrap();
    let content = pattern(200_000, 1);
    let mirror = TestServer::start(serving(content.clone())).await;
    let (client, _t) = start(dir.path(), &config_text(dir.path(), &mirrors(&[&mirror], "")), test_hooks()).await;
    let mut b = register(&client, 1, vec![blob(1 << 20)], budget(10, 1 << 20, 1 << 20), false).await;
    let id = sha256(&content);
    let (s, body) = b.fetch(0, &id).await;
    assert_eq!(s, FetchStatus::Ok);
    assert_eq!(body, content);
    assert_eq!(mirror.requests.lock().unwrap()[0].path, format!("/blobs/{}", hex::encode(id)));
    // Not 32 bytes, or a cap index out of range: refused.
    assert_eq!(b.fetch(0, &id[..31]).await.0, FetchStatus::Denied);
    assert_eq!(b.fetch(1, &id).await.0, FetchStatus::Denied);
    // A blob no mirror has: status 2.
    assert_eq!(b.fetch(0, &[7u8; 32]).await.0, FetchStatus::Failed);
    let stats = client.end_job(B256::repeat_byte(1)).await.unwrap();
    assert_eq!(stats.fetches, 4, "every request is a unit, refused ones included");
    assert_eq!(stats.fetch_bytes, content.len() as u64);
    assert_eq!(stats.denied, 2);
    assert!(stats.transient);
    assert!(!stats.fetch_in_flight_at_end);
    // The broker closed its end of the job socket.
    assert!(b.recv().await.is_none());
}

#[tokio::test]
async fn hash_mismatch_and_errors_fail_over_to_the_next_mirror() {
    let dir = tempfile::tempdir().unwrap();
    let content = pattern(5_000, 2);
    let wrong = TestServer::start(|_| TestResponse::ok(b"not the content".to_vec())).await;
    let broken = TestServer::start(|_| TestResponse::status(500)).await;
    let good = TestServer::start(serving(content.clone())).await;
    let text = config_text(dir.path(), &mirrors(&[&wrong, &broken, &good], ""));
    let (client, _t) = start(dir.path(), &text, test_hooks()).await;
    let mut b = register(&client, 2, vec![blob(1 << 20)], budget(10, 1 << 20, 1 << 20), false).await;
    let (s, body) = b.fetch(0, &sha256(&content)).await;
    assert_eq!((s, body), (FetchStatus::Ok, content.clone()));
    assert_eq!((wrong.hits(), broken.hits(), good.hits()), (1, 1, 1));
    let stats = client.end_job(B256::repeat_byte(2)).await.unwrap();
    assert!(!stats.transient, "a fetch that succeeded after failover is not transient");

    // Every mirror wrong: status 2, never the bytes.
    let text = config_text(dir.path(), &mirrors(&[&wrong, &broken], ""));
    let (client, _t) = start(dir.path(), &text, test_hooks()).await;
    let mut b = register(&client, 3, vec![blob(1 << 20)], budget(10, 1 << 20, 1 << 20), false).await;
    assert_eq!(b.fetch(0, &sha256(&content)).await, (FetchStatus::Failed, vec![]));
    assert!(client.end_job(B256::repeat_byte(3)).await.unwrap().transient);
}

#[tokio::test]
async fn oversize_bodies_are_the_jobs_limit() {
    let dir = tempfile::tempdir().unwrap();
    let content = pattern(10_000, 3);
    let id = sha256(&content);
    // Without Content-Length too: the cap is enforced while streaming.
    let streamed = {
        let c = content.clone();
        TestServer::start(move |_| TestResponse::ok(c.clone()).without_length()).await
    };
    let text = config_text(dir.path(), &mirrors(&[&streamed], ""));
    let (client, _t) = start(dir.path(), &text, test_hooks()).await;
    // The config's maxBytes caps it...
    let mut b = register(&client, 4, vec![blob(9_999), blob(10_000)], budget(10, 1 << 20, 1 << 20), false).await;
    assert_eq!(b.fetch(0, &id).await.0, FetchStatus::Exhausted);
    assert_eq!(b.fetch(1, &id).await, (FetchStatus::Ok, content.clone()));
    client.end_job(B256::repeat_byte(4)).await.unwrap();
    // ...and so does maxResponseBytes, and the job's remaining maxFetchBytes.
    let mut b = register(&client, 5, vec![blob(1 << 20)], budget(10, 1 << 20, 9_000), false).await;
    assert_eq!(b.fetch(0, &id).await.0, FetchStatus::Exhausted);
    client.end_job(B256::repeat_byte(5)).await.unwrap();
    let mut b = register(&client, 6, vec![blob(1 << 20)], budget(10, 15_000, 1 << 20), false).await;
    assert_eq!(b.fetch(0, &id).await.0, FetchStatus::Ok);
    assert_eq!(b.fetch(0, &id).await.0, FetchStatus::Exhausted, "5,000 bytes left");
    let stats = client.end_job(B256::repeat_byte(6)).await.unwrap();
    assert_eq!((stats.fetch_bytes, stats.transient), (10_000, false));
}

#[tokio::test]
async fn fetch_and_unit_budgets() {
    let dir = tempfile::tempdir().unwrap();
    let content = pattern(100, 4);
    let mirror = TestServer::start(serving(content.clone())).await;
    let (client, _t) = start(dir.path(), &config_text(dir.path(), &mirrors(&[&mirror], "")), test_hooks()).await;
    let mut b = register(&client, 7, vec![blob(1 << 20)], budget(2, 1 << 20, 1 << 20), false).await;
    assert_eq!(b.fetch(0, &sha256(&content)).await.0, FetchStatus::Ok);
    assert_eq!(b.fetch(0, &sha256(&content)).await.0, FetchStatus::Ok);
    assert_eq!(b.fetch(0, &sha256(&content)).await.0, FetchStatus::Exhausted);
    assert_eq!(mirror.hits(), 2, "an exhausted job makes no request");
    let s = client.end_job(B256::repeat_byte(7)).await.unwrap();
    assert_eq!(s.fetches, 2);
}

#[tokio::test]
async fn spool_quota_is_operator_side() {
    let dir = tempfile::tempdir().unwrap();
    let content = pattern(5_000, 5);
    let mirror = TestServer::start(serving(content.clone())).await;
    let text = config_text(dir.path(), &mirrors(&[&mirror], "spool_quota_bytes = 4096\n"));
    let (client, _t) = start(dir.path(), &text, test_hooks()).await;
    let mut b = register(&client, 8, vec![blob(1 << 20)], budget(10, 1 << 20, 1 << 20), false).await;
    assert_eq!(b.fetch(0, &sha256(&content)).await.0, FetchStatus::Failed);
}

#[tokio::test]
async fn a_fetch_in_flight_when_the_job_ends_is_recorded() {
    let dir = tempfile::tempdir().unwrap();
    let content = pattern(64, 6);
    let slow = {
        let c = content.clone();
        TestServer::start(move |_| TestResponse::ok(c.clone()).delayed(Duration::from_secs(3))).await
    };
    let (client, _t) = start(dir.path(), &config_text(dir.path(), &mirrors(&[&slow], "")), test_hooks()).await;

    // EndJob while the fetch is being served.
    let mut b = register(&client, 9, vec![blob(1 << 20)], budget(10, 1 << 20, 1 << 20), false).await;
    b.send(0, &sha256(&content)).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let stats = client.end_job(B256::repeat_byte(9)).await.unwrap();
    assert!(stats.fetch_in_flight_at_end);
    assert!(!stats.transient);
    assert!(b.recv().await.is_none(), "no result after EndJob");

    // The builder's socket closes (the runner was killed) while a fetch is served.
    let mut b = register(&client, 10, vec![blob(1 << 20)], budget(10, 1 << 20, 1 << 20), false).await;
    b.send(0, &sha256(&content)).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    drop(b);
    tokio::time::sleep(Duration::from_millis(300)).await;
    let stats = client.end_job(B256::repeat_byte(10)).await.unwrap();
    assert!(stats.fetch_in_flight_at_end);

    // An idle job whose socket closed: nothing in flight.
    let b = register(&client, 11, vec![blob(1 << 20)], budget(10, 1 << 20, 1 << 20), false).await;
    drop(b);
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(!client.end_job(B256::repeat_byte(11)).await.unwrap().fetch_in_flight_at_end);
}

#[tokio::test]
async fn frames_are_capped_and_partial_frames_time_out() {
    let dir = tempfile::tempdir().unwrap();
    let mirror = TestServer::start(|_| TestResponse::status(404)).await;
    let text = config_text(dir.path(), &mirrors(&[&mirror], "[timeouts]\npartial_frame_secs = 1\n"));
    let (client, _t) = start(dir.path(), &text, test_hooks()).await;

    // A header announcing more than fetch_frame_max(maxRequestBytes): refused before allocating.
    let mut b = register(&client, 12, vec![blob(1 << 20)], budget(10, 1 << 20, 1 << 20), false).await;
    let mut h = vec![KIND_FETCH];
    h.extend_from_slice(&(65_536u32 + 5).to_be_bytes());
    b.sock.write_all(&h).await.unwrap();
    assert_eq!(b.recv().await.map(|r| r.0), Some(FetchStatus::Denied));
    assert!(b.recv().await.is_none(), "and the socket is closed");
    let stats = client.end_job(B256::repeat_byte(12)).await.unwrap();
    assert_eq!(stats.denied, 1);

    // Half a header, then silence: the broker gives up on the job's socket.
    let mut b = register(&client, 13, vec![blob(1 << 20)], budget(10, 1 << 20, 1 << 20), false).await;
    b.sock.write_all(&[KIND_FETCH, 0]).await.unwrap();
    let start = std::time::Instant::now();
    assert!(b.recv().await.is_none());
    assert!(start.elapsed() >= Duration::from_millis(900));
    client.end_job(B256::repeat_byte(13)).await.unwrap();
}

#[tokio::test]
async fn held_lock_fetches_pass_a_flood_of_simulations() {
    let dir = tempfile::tempdir().unwrap();
    let content = pattern(1_000, 7);
    let id = sha256(&content);
    let gate = Arc::new(AtomicUsize::new(0));
    let slow = {
        let (c, g) = (content.clone(), gate.clone());
        TestServer::start(move |_| {
            g.fetch_add(1, Ordering::SeqCst);
            TestResponse::ok(c.clone()).delayed(Duration::from_secs(2))
        })
        .await
    };
    // 2 MiB in flight, 1 MiB of it reserved: one simulation fetch (1 MiB cap) fills the shared lane.
    let text = config_text(dir.path(), &mirrors(&[&slow], "[budget]\ninflight_bytes = 2097152\nheld_lock_share = 0.5\n"));
    let (client, _t) = start(dir.path(), &text, test_hooks()).await;
    let mut sims = Vec::new();
    for k in 0..3u8 {
        let mut b = register(&client, 20 + k, vec![blob(1 << 20)], budget(10, 1 << 20, 1 << 20), false).await;
        b.send(0, &id).await;
        sims.push(b);
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(gate.load(Ordering::SeqCst), 1, "the shared lane admits one simulation fetch at a time");
    let mut held = register(&client, 30, vec![blob(1 << 20)], budget(10, 1 << 20, 1 << 20), true).await;
    let start = std::time::Instant::now();
    assert_eq!(held.fetch(0, &id).await.0, FetchStatus::Ok);
    assert!(start.elapsed() < Duration::from_millis(3_500), "the held lock did not wait behind the flood");
    for mut s in sims {
        assert_eq!(s.recv().await.unwrap().0, FetchStatus::Ok);
    }
}
