//! Builder artifacts (plan §13.3–§13.4): `hemi-code` reads from the artifact endpoint and the
//! operator artifact mirror, into sealed memfds, with a cache keyed by `(builder type, the broker's
//! own sha256)`.
//!
//! **`hemi-code`**, one fetch:
//! 1. Fix one block number (`eth_blockNumber`); every read of the fetch uses it.
//! 2. Read the manifest with `eth_getCode` (capped at 24,576 code bytes) and check it with
//!    [`parse_manifest`] (the job's expected sha256, `min(max_bytes, max_builder_bytes)`).
//! 3. A cached artifact with the manifest's sha256 is served from the cache. Otherwise the cost is
//!    reported before any chunk is read (`length` bytes, `n` chunk reads): the caller's charge hook
//!    (the control channel's `ArtifactCharge` → `ChargeDecision`) may refuse it (`Budget`).
//! 4. Read the chunks in JSON-RPC batches of at most 256, each capped at 24,576 code bytes, check
//!    each with [`chunk_body`] and stream it into an [`Assembler`] over a memfd, which aborts as soon
//!    as the total exceeds `length`; finish (count, length and sha256), seal, cache, return.
//!
//! **Failures** map to [`ArtifactFailure`]: an empty manifest is transient (never remembered; the
//! miner retries at most three times per job); a structural, chunk or hash failure is remembered per
//! manifest address only when the fixed block is at or below the `safe` head (else it is per job and
//! transient); an id mismatch is remembered per `(manifest, builderId)`; endpoint errors are retried
//! once at a new fixed block, then `Endpoint`. The artifact endpoint is paced by its own limiter,
//! held-lock reads first.

use std::fs::File;
use std::future::Future;
use std::io::{Seek, Write};
use std::pin::Pin;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};

use alloy_primitives::{Address, B256};
use sha2::{Digest, Sha256};
use zkminer_witness::ipc::{ArtifactFailure, ArtifactSource};
use zkminer_witness::manifest::{chunk_body, parse_manifest, AssembleError, Assembler, ManifestError};

use crate::cache::{ArtifactKey, Lru, ManifestKey, ManifestPairKey};
use crate::config::{BrokerConfig, TimeoutConfig};
use crate::fdpass::{copy_sealed, memfd, seal};
use crate::jsonrpc::{RpcClient, RpcError, MAX_CODE_BATCH};
use crate::lanes::{ByteLanes, WaitFlag};
use crate::net::{Endpoint, EndpointError};

const MEMFD_NAME: &std::ffi::CStr = c"zkminer-artifact";

/// The caller's charge hook: `(length, chunk reads)` → proceed?
pub type ChargeFn = Box<dyn FnMut(u64, u32) -> Pin<Box<dyn Future<Output = bool> + Send>> + Send>;

/// One `FetchArtifact`.
#[derive(Debug, Clone)]
pub struct ArtifactRequest {
    pub source: ArtifactSource,
    pub builder_type: u8,
    /// `Some(builderId)` for builder types whose id is the sha256 (1 and 3).
    pub expected_sha256: Option<B256>,
    pub max_bytes: u64,
    pub held_lock: bool,
}

/// A sealed memfd (offset 0) with exactly `len` bytes hashing to `sha256`.
#[derive(Debug)]
pub struct FetchedArtifact {
    pub file: File,
    pub len: u64,
    pub sha256: B256,
    pub cached: bool,
}

struct CachedArtifact {
    file: Arc<File>,
    len: u64,
}

enum Step {
    /// Operator-side: retried at a new fixed block.
    Retry(String),
    Fail(ArtifactFailure),
}

impl From<RpcError> for Step {
    fn from(e: RpcError) -> Self {
        Step::Retry(e.to_string())
    }
}

pub(crate) struct ArtifactReader {
    endpoint: Option<Arc<Endpoint>>,
    mirror: Option<Arc<Endpoint>>,
    chain_id: u64,
    max_builder_bytes: u64,
    cache: Mutex<Lru<ArtifactKey, CachedArtifact>>,
    bad: Mutex<Lru<ManifestKey, ArtifactFailure>>,
    bad_pairs: Mutex<Lru<ManifestPairKey, ()>>,
    ids: AtomicU64,
    bytes: Arc<ByteLanes>,
    timeouts: TimeoutConfig,
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

impl ArtifactReader {
    pub fn new(
        endpoint: Option<Arc<Endpoint>>,
        mirror: Option<Arc<Endpoint>>,
        chain_id: u64,
        max_builder_bytes: u64,
        cfg: &BrokerConfig,
        bytes: Arc<ByteLanes>,
    ) -> Self {
        let c = &cfg.cache;
        Self {
            endpoint,
            mirror,
            chain_id,
            max_builder_bytes,
            cache: Mutex::new(Lru::new(c.artifact_max_bytes, c.artifact_max_entries)),
            bad: Mutex::new(Lru::new(u64::MAX, c.bad_manifest_max_entries)),
            bad_pairs: Mutex::new(Lru::new(u64::MAX, c.bad_manifest_max_entries)),
            ids: AtomicU64::new(1),
            bytes,
            timeouts: cfg.timeouts,
        }
    }

    pub fn endpoint(&self) -> Option<&Arc<Endpoint>> {
        self.endpoint.as_ref()
    }

    /// The artifact endpoint and mirror, where configured.
    pub fn endpoints(&self) -> impl Iterator<Item = &Arc<Endpoint>> {
        self.endpoint.iter().chain(self.mirror.iter())
    }

    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }

    /// Serves one `FetchArtifact` within `artifact_fetch_secs` (then `Endpoint`).
    pub async fn fetch(&self, req: &ArtifactRequest, charge: ChargeFn) -> Result<FetchedArtifact, ArtifactFailure> {
        let fut = async {
            match req.source {
                ArtifactSource::HemiCode { chain_id, manifest } => self.hemi_code(req, chain_id, manifest, charge).await,
                ArtifactSource::Mirror { builder_type, builder_id } => self.mirror_read(req, builder_type, builder_id).await,
            }
        };
        tokio::time::timeout(self.timeouts.artifact_fetch(), fut).await.unwrap_or(Err(ArtifactFailure::Endpoint))
    }

    /// A fresh sealed copy of a cached artifact.
    async fn cached(&self, builder_type: u8, sha256: B256) -> Option<FetchedArtifact> {
        let hit = {
            let mut c = lock(&self.cache);
            c.get(&ArtifactKey { builder_type, sha256 }).map(|a| (a.file.clone(), a.len))
        }?;
        let (file, len) = hit;
        let copy = tokio::task::spawn_blocking(move || copy_sealed(&file, len, MEMFD_NAME)).await.ok()?.ok()?;
        Some(FetchedArtifact { file: copy, len, sha256, cached: true })
    }

    fn insert(&self, builder_type: u8, sha256: B256, file: &File, len: u64) {
        let Ok(dup) = file.try_clone() else { return };
        lock(&self.cache).insert(ArtifactKey { builder_type, sha256 }, CachedArtifact { file: Arc::new(dup), len }, len);
    }

    async fn hemi_code(
        &self,
        req: &ArtifactRequest,
        chain_id: u64,
        manifest: Address,
        mut charge: ChargeFn,
    ) -> Result<FetchedArtifact, ArtifactFailure> {
        let Some(ep) = &self.endpoint else { return Err(ArtifactFailure::NotConfigured) };
        if chain_id != self.chain_id {
            return Err(ArtifactFailure::NotConfigured);
        }
        if let Some(exp) = req.expected_sha256 {
            if let Some(hit) = self.cached(req.builder_type, exp).await {
                return Ok(hit);
            }
        }
        let mkey = ManifestKey { chain_id, manifest };
        if let Some(f) = lock(&self.bad).get(&mkey) {
            return Err(*f);
        }
        if let Some(exp) = req.expected_sha256 {
            if lock(&self.bad_pairs).contains(&ManifestPairKey { chain_id, manifest, builder_id: exp }) {
                return Err(ArtifactFailure::IdMismatch);
            }
        }
        let max = req.max_bytes.min(self.max_builder_bytes);
        let wait = WaitFlag::default();
        let rpc = RpcClient { ep, held: req.held_lock, ids: &self.ids, wait: &wait };
        let mut charged: Option<(u64, u32)> = None;
        let mut last = String::new();
        for _attempt in 0..2 {
            match self.read_once(&rpc, req, mkey, max, &mut charge, &mut charged).await {
                Ok(a) => return Ok(a),
                Err(Step::Fail(f)) => return Err(f),
                Err(Step::Retry(e)) => {
                    tracing::warn!(endpoint = %ep.alias(), error = %ep.redact(&e), "hemi-code read failed; retrying at a new block");
                    last = e;
                }
            }
        }
        tracing::warn!(endpoint = %ep.alias(), error = %ep.redact(&last), "hemi-code read failed");
        Err(ArtifactFailure::Endpoint)
    }

    /// Whether `block` is at or below the endpoint's `safe` head (false when unknown).
    async fn at_or_below_safe(&self, rpc: &RpcClient<'_>, block: u64) -> bool {
        matches!(rpc.tag_number("safe").await, Ok(Some(s)) if block <= s)
    }

    /// A present-but-invalid manifest: remembered per address when final.
    async fn invalid(
        &self,
        rpc: &RpcClient<'_>,
        mkey: ManifestKey,
        block: u64,
        kind: fn(bool) -> ArtifactFailure,
    ) -> Step {
        let safe = self.at_or_below_safe(rpc, block).await;
        let failure = kind(safe);
        if safe {
            lock(&self.bad).insert(mkey, failure, 0);
        }
        Step::Fail(failure)
    }

    async fn read_once(
        &self,
        rpc: &RpcClient<'_>,
        req: &ArtifactRequest,
        mkey: ManifestKey,
        max: u64,
        charge: &mut ChargeFn,
        charged: &mut Option<(u64, u32)>,
    ) -> Result<FetchedArtifact, Step> {
        let block = rpc.block_number().await?;
        let code = rpc.get_code(mkey.manifest, block).await?;
        let expected = req.expected_sha256.map(|b| b.0);
        let m = match parse_manifest(&code, mkey.manifest, max, expected.as_ref()) {
            Ok(m) => m,
            Err(ManifestError::Empty) => return Err(Step::Fail(ArtifactFailure::EmptyManifest)),
            Err(ManifestError::Structural(_)) => {
                return Err(self
                    .invalid(rpc, mkey, block, |s| ArtifactFailure::ManifestInvalid { at_or_below_safe: s })
                    .await)
            }
            Err(ManifestError::TooLarge) => return Err(Step::Fail(ArtifactFailure::TooLarge)),
            Err(ManifestError::IdMismatch) => {
                if let Some(exp) = req.expected_sha256 {
                    lock(&self.bad_pairs).insert(
                        ManifestPairKey { chain_id: mkey.chain_id, manifest: mkey.manifest, builder_id: exp },
                        (),
                        0,
                    );
                }
                return Err(Step::Fail(ArtifactFailure::IdMismatch));
            }
        };
        let sha256 = B256::from(m.sha256);
        if let Some(hit) = self.cached(req.builder_type, sha256).await {
            return Ok(hit);
        }
        let n = m.chunks.len() as u32;
        if *charged != Some((m.length, n)) {
            if !charge(m.length, n).await {
                return Err(Step::Fail(ArtifactFailure::Budget));
            }
            *charged = Some((m.length, n));
        }
        let _bytes = self.bytes.acquire(req.held_lock, m.length).await;
        let file = memfd(MEMFD_NAME).map_err(|e| Step::Retry(format!("memfd: {e}")))?;
        let mut asm = Assembler::new(&m, file);
        let chunk_invalid = |s| ArtifactFailure::ChunkInvalid { at_or_below_safe: s };
        for batch in m.chunks.chunks(MAX_CODE_BATCH) {
            let codes = rpc.get_codes(batch, block).await?;
            for code in &codes {
                let Ok(body) = chunk_body(code) else {
                    return Err(self.invalid(rpc, mkey, block, chunk_invalid).await);
                };
                match asm.push(body) {
                    Ok(()) => {}
                    Err(AssembleError::Io(k)) => return Err(Step::Retry(format!("memfd write: {k:?}"))),
                    Err(_) => return Err(self.invalid(rpc, mkey, block, chunk_invalid).await),
                }
            }
        }
        let mut file = match asm.finish() {
            Ok(f) => f,
            Err(AssembleError::HashMismatch) => {
                return Err(self
                    .invalid(rpc, mkey, block, |s| ArtifactFailure::HashMismatch { at_or_below_safe: s })
                    .await)
            }
            Err(AssembleError::Io(k)) => return Err(Step::Retry(format!("memfd write: {k:?}"))),
            Err(_) => return Err(self.invalid(rpc, mkey, block, chunk_invalid).await),
        };
        seal(&file).and_then(|_| file.rewind()).map_err(|e| Step::Retry(format!("memfd seal: {e}")))?;
        self.insert(req.builder_type, sha256, &file, m.length);
        tracing::info!(endpoint = %rpc.ep.alias(), length = m.length, chunks = n, block, "hemi-code artifact read");
        Ok(FetchedArtifact { file, len: m.length, sha256, cached: false })
    }

    /// The operator artifact mirror: `GET …/{type}/{id}`, checked against the expected sha256.
    async fn mirror_read(&self, req: &ArtifactRequest, builder_type: u8, builder_id: B256) -> Result<FetchedArtifact, ArtifactFailure> {
        let Some(mirror) = &self.mirror else { return Err(ArtifactFailure::NotConfigured) };
        if let Some(exp) = req.expected_sha256 {
            if let Some(hit) = self.cached(builder_type, exp).await {
                return Ok(hit);
            }
        }
        let max = req.max_bytes.min(self.max_builder_bytes);
        let url = mirror.spec.url_with(&[("type", &builder_type.to_string()), ("id", &hex::encode(builder_id))]);
        let _bytes = self.bytes.acquire(req.held_lock, max).await;
        let file = memfd(MEMFD_NAME).map_err(|_| ArtifactFailure::Endpoint)?;
        let mut hasher = Sha256::new();
        let wait = WaitFlag::default();
        let failed = |e: EndpointError| match e {
            EndpointError::Status(404 | 410) => ArtifactFailure::MirrorMissing,
            EndpointError::TooLarge => ArtifactFailure::TooLarge,
            e => {
                mirror.log_failure("artifact mirror request failed", &e);
                ArtifactFailure::Endpoint
            }
        };
        let mut body = mirror.get(&url, req.held_lock, max, &wait).await.map_err(failed)?;
        let mut buf = Vec::new();
        while body.next_into(&mut buf).await.map_err(failed)? {
            hasher.update(&buf);
            (&file).write_all(&buf).map_err(|_| ArtifactFailure::Endpoint)?;
            buf.clear();
        }
        let len = body.total();
        if len == 0 {
            return Err(ArtifactFailure::MirrorMissing);
        }
        let sha256 = B256::from(<[u8; 32]>::from(hasher.finalize()));
        if req.expected_sha256.is_some_and(|exp| exp != sha256) {
            tracing::warn!(endpoint = %mirror.alias(), "artifact mirror body does not hash to the builder id");
            return Err(ArtifactFailure::MirrorMismatch);
        }
        let mut file = file;
        seal(&file).and_then(|_| file.rewind()).map_err(|_| ArtifactFailure::Endpoint)?;
        self.insert(builder_type, sha256, &file, len);
        Ok(FetchedArtifact { file, len, sha256, cached: false })
    }
}
