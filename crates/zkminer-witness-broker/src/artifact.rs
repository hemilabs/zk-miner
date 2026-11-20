//! Builder artifacts (plan §13.3–§13.4): `hemi-code` reads from the artifact endpoint and the
//! operator artifact mirror, into sealed memfds, with a cache keyed by `(builder type, the broker's
//! own sha256)`.
//!
//! **`hemi-code`**, one attempt (every read of it pinned to one block **hash**, `eth_getCode(addr,
//! {"blockHash": H})`, so a reorg between reads cannot mix two chains):
//!
//! 1. Fix the safe head `S` (`eth_getBlockByNumber("safe")`; `finalized` on a node without `safe`;
//!    none on a node with neither). A failure recorded earlier above the safe head (below) is
//!    settled first: once `S.number ≥` its block's number, if the block at that height still has
//!    the recorded hash the failure is promoted to remembered and returned; if not (reorged away)
//!    it is dropped.
//! 2. Read at `S`. Every structural, chunk, hash or id-mismatch failure at `S` is final and
//!    remembered across jobs and callers (`at_or_below_safe: true`): by manifest address, or for an
//!    id mismatch by `(manifest, builderId)`, so a decoy job naming someone else's good manifest
//!    cannot make it fail for others.
//! 3. If the manifest is empty at `S` (not yet safe, or never published), or `S`'s state is
//!    unavailable (pruned: operator-side), read at the latest block `L` instead, pinned by its hash.
//!    Success at `L` is served (correctness rests on the sha256). A failure at `L` is per job
//!    (`at_or_below_safe: false`) and recorded as pending `{failure, L.number, L.hash}` in a bounded
//!    LRU, for step 1 to settle.
//!
//! Within a read: the manifest is checked with [`parse_manifest`] (the job's expected sha256,
//! `min(max_bytes, max_builder_bytes)`); a cached artifact with the manifest's sha256 is served from
//! the cache; otherwise the cost is reported before any chunk is read (`length` bytes, `n` chunk
//! reads) and the caller's charge hook (the control channel's `ArtifactCharge` → `ChargeDecision`)
//! may refuse it (`Budget`). Chunks are read in JSON-RPC batches of at most 256, each batch's raw
//! body capped at `k·128 + 2·min(remaining, k·24,575)` bytes (the hex doubles them; `remaining` is
//! what the manifest's `length` leaves for this batch), so a manifest that under-declares its
//! length makes the node send at most about twice that length before the read fails: an oversize
//! batch is `ChunkInvalid`. The in-flight byte permit covers `length` plus the largest batch's raw
//! cap (the batch size shrinks to fit the lane). Each chunk is checked with [`chunk_body`] and
//! streamed into an [`Assembler`] over a memfd, which aborts as soon as the total exceeds `length`;
//! finish (count, length and sha256), seal, cache, return.
//!
//! An empty manifest is transient (never remembered; the miner retries at most three times per
//! job). Endpoint errors are retried once (a new attempt, new blocks), then `Endpoint`. The
//! artifact endpoint is paced by its own limiter, held-lock reads first.
//!
//! Cache hits are served as a duplicate of the cached sealed memfd (no copy). The duplicate shares
//! the file offset with the cache and with every other receiver: read it with `pread`/`mmap`, never
//! by the offset.

use std::fs::File;
use std::future::Future;
use std::io::{Seek, Write};
use std::pin::Pin;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};

use alloy_primitives::{Address, B256};
use sha2::{Digest, Sha256};
use zkminer_witness::ipc::{ArtifactFailure, ArtifactSource};
use zkminer_witness::manifest::{chunk_body, parse_manifest, AssembleError, Assembler, ManifestError, MAX_CHUNK_BODY};

use crate::cache::{ArtifactKey, Lru, ManifestKey, ManifestPairKey, PendingKey};
use crate::config::{BrokerConfig, TimeoutConfig};
use crate::fdpass::{memfd, seal};
use crate::jsonrpc::{BlockRef, RpcClient, RpcError, CODE_ANSWER_OVERHEAD, MAX_CODE_BATCH};
use crate::lanes::{permit_bytes, ByteLanes, WaitFlag};
use crate::net::{Endpoint, EndpointError};

const MEMFD_NAME: &std::ffi::CStr = c"zkminer-artifact";
/// Slack on a batch's raw cap (array brackets and separators beyond the per-element allowance).
const BATCH_SLACK: u64 = 64;

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

/// A sealed memfd with exactly `len` bytes hashing to `sha256`. Read it with `pread`: its file
/// offset may be shared (a cache hit is a duplicate of the cached descriptor).
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
    /// Operator-side: retried with a new attempt.
    Retry(String),
    Fail(ArtifactFailure),
}

impl From<RpcError> for Step {
    fn from(e: RpcError) -> Self {
        Step::Retry(e.to_string())
    }
}

/// What makes a present manifest bad.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Invalid {
    Manifest,
    Chunk,
    Hash,
    /// Valid, but for another artifact.
    IdMismatch,
}

impl Invalid {
    fn failure(self, at_or_below_safe: bool) -> ArtifactFailure {
        match self {
            Invalid::Manifest => ArtifactFailure::ManifestInvalid { at_or_below_safe },
            Invalid::Chunk => ArtifactFailure::ChunkInvalid { at_or_below_safe },
            Invalid::Hash => ArtifactFailure::HashMismatch { at_or_below_safe },
            Invalid::IdMismatch => ArtifactFailure::IdMismatch,
        }
    }
}

/// The result of reading at one block.
enum Read {
    Done(FetchedArtifact),
    Invalid(Invalid),
    /// No manifest code at that block.
    Empty,
    /// The node cannot serve that block's state (a JSON-RPC error: pruned, unknown block).
    Unavailable(String),
    /// Operator-side: a new attempt.
    Retry(String),
    /// Final for this request, not about the manifest (too large for the caller, budget).
    Fail(ArtifactFailure),
}

#[derive(Debug, Clone, Copy)]
struct Pending {
    invalid: Invalid,
    block: BlockRef,
}

pub(crate) struct ArtifactReader {
    endpoint: Option<Arc<Endpoint>>,
    mirror: Option<Arc<Endpoint>>,
    chain_id: u64,
    max_builder_bytes: u64,
    cache: Mutex<Lru<ArtifactKey, CachedArtifact>>,
    bad: Mutex<Lru<ManifestKey, ArtifactFailure>>,
    bad_pairs: Mutex<Lru<ManifestPairKey, ()>>,
    pending: Mutex<Lru<PendingKey, Pending>>,
    ids: AtomicU64,
    bytes: Arc<ByteLanes>,
    timeouts: TimeoutConfig,
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

/// The raw cap of a batch of `k` chunk reads whose bodies may total at most `remaining` bytes.
fn batch_cap(k: u64, remaining: u64) -> u64 {
    k * CODE_ANSWER_OVERHEAD + 2 * remaining.min(k * MAX_CHUNK_BODY as u64) + BATCH_SLACK
}

fn key_of(mkey: ManifestKey, expected: Option<B256>, invalid: Invalid) -> Option<PendingKey> {
    match invalid {
        Invalid::IdMismatch => expected.map(|builder_id| {
            PendingKey::Pair(ManifestPairKey { chain_id: mkey.chain_id, manifest: mkey.manifest, builder_id })
        }),
        _ => Some(PendingKey::Manifest(mkey)),
    }
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
            pending: Mutex::new(Lru::new(u64::MAX, c.bad_manifest_max_entries)),
            ids: AtomicU64::new(1),
            bytes,
            timeouts: cfg.timeouts,
        }
    }

    pub fn endpoint(&self) -> Option<&Arc<Endpoint>> {
        self.endpoint.as_ref()
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

    /// A cached artifact: a duplicate of the cached sealed memfd (shared offset; see the module doc).
    fn cached(&self, builder_type: u8, sha256: B256) -> Option<FetchedArtifact> {
        let (file, len) = {
            let mut c = lock(&self.cache);
            c.get(&ArtifactKey { builder_type, sha256 }).map(|a| (a.file.clone(), a.len))
        }?;
        let dup = file.try_clone().ok()?;
        Some(FetchedArtifact { file: dup, len, sha256, cached: true })
    }

    fn insert(&self, builder_type: u8, sha256: B256, file: &File, len: u64) {
        let Ok(dup) = file.try_clone() else { return };
        lock(&self.cache).insert(ArtifactKey { builder_type, sha256 }, CachedArtifact { file: Arc::new(dup), len }, len);
    }

    /// Remembers a failure read at or below the safe head (final for every job and caller).
    fn remember(&self, mkey: ManifestKey, expected: Option<B256>, invalid: Invalid) {
        match key_of(mkey, expected, invalid) {
            Some(PendingKey::Manifest(k)) => {
                lock(&self.bad).insert(k, invalid.failure(true), 0);
            }
            Some(PendingKey::Pair(k)) => {
                lock(&self.bad_pairs).insert(k, (), 0);
            }
            None => {}
        }
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
            if let Some(hit) = self.cached(req.builder_type, exp) {
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
                    tracing::warn!(endpoint = %ep.alias(), error = %ep.redact(&e), "hemi-code read failed; retrying");
                    last = e;
                }
            }
        }
        tracing::warn!(endpoint = %ep.alias(), error = %ep.redact(&last), "hemi-code read failed");
        Err(ArtifactFailure::Endpoint)
    }

    /// The safe head: `safe`, else `finalized`; `None` on a node with neither (a null answer or a
    /// JSON-RPC error). A transport failure is operator-side.
    async fn safe_head(&self, rpc: &RpcClient<'_>) -> Result<Option<BlockRef>, Step> {
        for tag in ["safe", "finalized"] {
            match rpc.tag_block(tag).await {
                Ok(Some(b)) => return Ok(Some(b)),
                Ok(None) | Err(RpcError::Rpc(_)) => continue,
                Err(e) => return Err(e.into()),
            }
        }
        Ok(None)
    }

    /// A manifest that now reads valid has nothing pending (a pending failure can only have been
    /// read on a branch that no longer matters, or before the code changed).
    fn forget_pending(&self, mkey: ManifestKey, expected: Option<B256>) {
        let mut p = lock(&self.pending);
        p.remove(&PendingKey::Manifest(mkey));
        if let Some(builder_id) = expected {
            p.remove(&PendingKey::Pair(ManifestPairKey { chain_id: mkey.chain_id, manifest: mkey.manifest, builder_id }));
        }
    }

    /// Step 1: a pending failure whose block the safe head has passed is promoted (still on the
    /// canonical chain) or dropped (reorged away). Returns a promoted failure.
    async fn settle_pending(
        &self,
        rpc: &RpcClient<'_>,
        mkey: ManifestKey,
        expected: Option<B256>,
        safe: Option<BlockRef>,
    ) -> Option<ArtifactFailure> {
        let safe = safe?;
        let mut keys = vec![PendingKey::Manifest(mkey)];
        if let Some(builder_id) = expected {
            keys.push(PendingKey::Pair(ManifestPairKey { chain_id: mkey.chain_id, manifest: mkey.manifest, builder_id }));
        }
        for key in keys {
            let Some(p) = lock(&self.pending).get(&key).copied() else { continue };
            if safe.number < p.block.number {
                continue;
            }
            match rpc.block_by_number(p.block.number).await {
                Ok(Some(b)) if b.hash == p.block.hash => {
                    lock(&self.pending).remove(&key);
                    self.remember(mkey, expected, p.invalid);
                    tracing::info!(manifest = %mkey.manifest, block = p.block.number, "hemi-code failure is now at or below the safe head: remembered");
                    return Some(p.invalid.failure(true));
                }
                Ok(_) => {
                    lock(&self.pending).remove(&key);
                    tracing::info!(manifest = %mkey.manifest, block = p.block.number, "hemi-code failure was reorged away: dropped");
                }
                // Unknown for now: keep it, and read as usual.
                Err(_) => {}
            }
        }
        None
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
        let safe = self.safe_head(rpc).await?;
        if let Some(f) = self.settle_pending(rpc, mkey, req.expected_sha256, safe).await {
            return Err(Step::Fail(f));
        }
        if let Some(s) = safe {
            match self.read_at(rpc, req, mkey, max, s, charge, charged).await {
                Read::Done(a) => {
                    self.forget_pending(mkey, req.expected_sha256);
                    return Ok(a);
                }
                Read::Invalid(i) => {
                    self.remember(mkey, req.expected_sha256, i);
                    return Err(Step::Fail(i.failure(true)));
                }
                Read::Empty => {}
                Read::Unavailable(e) => {
                    tracing::info!(endpoint = %rpc.ep.alias(), error = %rpc.ep.redact(&e), "the safe head's state is unavailable; reading at the latest block");
                }
                Read::Retry(e) => return Err(Step::Retry(e)),
                Read::Fail(f) => return Err(Step::Fail(f)),
            }
        }
        let latest = rpc.tag_block("latest").await?.ok_or_else(|| Step::Retry("no latest block".into()))?;
        match self.read_at(rpc, req, mkey, max, latest, charge, charged).await {
            Read::Done(a) => {
                self.forget_pending(mkey, req.expected_sha256);
                Ok(a)
            }
            Read::Invalid(i) => {
                if let Some(k) = key_of(mkey, req.expected_sha256, i) {
                    lock(&self.pending).insert(k, Pending { invalid: i, block: latest }, 0);
                }
                Err(Step::Fail(i.failure(false)))
            }
            Read::Empty => Err(Step::Fail(ArtifactFailure::EmptyManifest)),
            Read::Unavailable(e) | Read::Retry(e) => Err(Step::Retry(e)),
            Read::Fail(f) => Err(Step::Fail(f)),
        }
    }

    /// Reads the artifact with every read pinned to `at`'s hash.
    #[allow(clippy::too_many_arguments)]
    async fn read_at(
        &self,
        rpc: &RpcClient<'_>,
        req: &ArtifactRequest,
        mkey: ManifestKey,
        max: u64,
        at: BlockRef,
        charge: &mut ChargeFn,
        charged: &mut Option<(u64, u32)>,
    ) -> Read {
        let code = match rpc.get_code(mkey.manifest, at.hash).await {
            Ok(c) => c,
            // Longer than any manifest can be.
            Err(RpcError::CodeTooLarge | RpcError::Endpoint(EndpointError::TooLarge)) => return Read::Invalid(Invalid::Manifest),
            Err(e @ RpcError::Rpc(_)) => return Read::Unavailable(e.to_string()),
            Err(e) => return Read::Retry(e.to_string()),
        };
        let expected = req.expected_sha256.map(|b| b.0);
        let m = match parse_manifest(&code, mkey.manifest, max, expected.as_ref()) {
            Ok(m) => m,
            Err(ManifestError::Empty) => return Read::Empty,
            Err(ManifestError::Structural(_)) => return Read::Invalid(Invalid::Manifest),
            Err(ManifestError::TooLarge) => return Read::Fail(ArtifactFailure::TooLarge),
            Err(ManifestError::IdMismatch) => return Read::Invalid(Invalid::IdMismatch),
        };
        let sha256 = B256::from(m.sha256);
        if let Some(hit) = self.cached(req.builder_type, sha256) {
            return Read::Done(hit);
        }
        let n = m.chunks.len() as u32;
        if *charged != Some((m.length, n)) {
            if !charge(m.length, n).await {
                return Read::Fail(ArtifactFailure::Budget);
            }
            *charged = Some((m.length, n));
        }
        // The memfd's `length` plus one batch's raw body in flight; batches shrink to fit the lane.
        let per_chunk = batch_cap(1, MAX_CHUNK_BODY as u64) - BATCH_SLACK;
        let room = self.bytes.largest(req.held_lock).saturating_sub(m.length + BATCH_SLACK);
        let k = ((room / per_chunk) as usize).clamp(1, MAX_CODE_BATCH);
        let largest_batch = batch_cap(k as u64, m.length);
        let _bytes = rpc.wait.during(self.bytes.acquire(req.held_lock, m.length + largest_batch)).await;
        let file = match memfd(MEMFD_NAME) {
            Ok(f) => f,
            Err(e) => return Read::Retry(format!("memfd: {e}")),
        };
        let mut asm = Assembler::new(&m, file);
        let mut assembled = 0u64;
        let mut left = m.chunks.len() as u64;
        for batch in m.chunks.chunks(k) {
            left -= batch.len() as u64;
            // Every later chunk needs at least one byte of its own.
            let remaining = m.length.saturating_sub(assembled).saturating_sub(left);
            let cap = batch_cap(batch.len() as u64, remaining);
            let codes = match rpc.get_codes(batch, at.hash, cap).await {
                Ok(c) => c,
                // More bytes than the manifest's length leaves for this batch.
                Err(RpcError::CodeTooLarge | RpcError::Endpoint(EndpointError::TooLarge)) => return Read::Invalid(Invalid::Chunk),
                Err(e @ RpcError::Rpc(_)) => return Read::Unavailable(e.to_string()),
                Err(e) => return Read::Retry(e.to_string()),
            };
            for code in &codes {
                let Ok(body) = chunk_body(code) else { return Read::Invalid(Invalid::Chunk) };
                match asm.push(body) {
                    Ok(()) => assembled += body.len() as u64,
                    Err(AssembleError::Io(k)) => return Read::Retry(format!("memfd write: {k:?}")),
                    Err(_) => return Read::Invalid(Invalid::Chunk),
                }
            }
        }
        let mut file = match asm.finish() {
            Ok(f) => f,
            Err(AssembleError::HashMismatch) => return Read::Invalid(Invalid::Hash),
            Err(AssembleError::Io(k)) => return Read::Retry(format!("memfd write: {k:?}")),
            Err(_) => return Read::Invalid(Invalid::Chunk),
        };
        if let Err(e) = seal(&file).and_then(|_| file.rewind()) {
            return Read::Retry(format!("memfd seal: {e}"));
        }
        self.insert(req.builder_type, sha256, &file, m.length);
        tracing::info!(endpoint = %rpc.ep.alias(), length = m.length, chunks = n, block = at.number, "hemi-code artifact read");
        Read::Done(FetchedArtifact { file, len: m.length, sha256, cached: false })
    }

    /// The operator artifact mirror: `GET …/{type}/{id}`, checked against the expected sha256.
    async fn mirror_read(&self, req: &ArtifactRequest, builder_type: u8, builder_id: B256) -> Result<FetchedArtifact, ArtifactFailure> {
        let Some(mirror) = &self.mirror else { return Err(ArtifactFailure::NotConfigured) };
        if let Some(exp) = req.expected_sha256 {
            if let Some(hit) = self.cached(builder_type, exp) {
                return Ok(hit);
            }
        }
        let max = req.max_bytes.min(self.max_builder_bytes);
        let url = mirror.spec.url_with(&[("type", &builder_type.to_string()), ("id", &hex::encode(builder_id))]);
        let wait = WaitFlag::default();
        let permit = wait.during(self.bytes.acquire(req.held_lock, max)).await;
        let cap = max.min(permit_bytes(&permit));
        let file = memfd(MEMFD_NAME).map_err(|_| ArtifactFailure::Endpoint)?;
        let mut hasher = Sha256::new();
        let failed = |e: EndpointError| match e {
            EndpointError::Status(404 | 410) => ArtifactFailure::MirrorMissing,
            // Larger than the caller allows; a lane narrower than that is the operator's.
            EndpointError::TooLarge if cap == max => ArtifactFailure::TooLarge,
            e => {
                mirror.log_failure("artifact mirror request failed", &e);
                ArtifactFailure::Endpoint
            }
        };
        let mut body = mirror.get(&url, req.held_lock, cap, &wait).await.map_err(failed)?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn batch_caps_follow_the_declared_length() {
        // 256 chunks of a manifest declaring 256 bytes: about twice that plus envelopes, not 12.6 MB.
        assert_eq!(batch_cap(256, 256), 256 * 128 + 512 + BATCH_SLACK);
        // A full batch of full chunks.
        assert_eq!(batch_cap(256, u64::MAX), 256 * 128 + 2 * 256 * MAX_CHUNK_BODY as u64 + BATCH_SLACK);
        assert!(batch_cap(256, u64::MAX) > 12_000_000);
    }
}
