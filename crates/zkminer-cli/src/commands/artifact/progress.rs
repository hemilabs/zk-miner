//! `--progress FILE`: what a run deployed, so a later run of the same artifact to the same chain
//! reuses it instead of sending (and paying for) it again. Each mined deployment is recorded, and so
//! is each transaction sent and not yet known to have mined (its nonce, the address its creation
//! makes and every hash sent at that nonce), before it is sent; each record is atomic and durable
//! (written beside the file and synced, renamed over it, the directory synced). A later run takes
//! the recorded chunks from the start of the file, in order, for as long as each one's receipt shows
//! a successful creation at its address and the code there (at that receipt's block) is exactly the
//! chunk this file's bytes give for its range; then the transaction left pending, when it is the
//! next deployment and one of its hashes created it as recorded. The first that is not (reorged
//! away, another file, an edited record, a nonce used otherwise) and everything after it is sent
//! again; a pending one still in the pool stops the run until it settles. The manifest is reused
//! only when every chunk was and its code is the manifest of those addresses. Whatever is reused is
//! read back at the safe head with the rest, so a record can save sends but never change what is
//! published.

use std::ops::Range;
use std::path::{Path, PathBuf};

use alloy::primitives::{Address, B256};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::json;
use zkminer_witness::manifest::{chunk_runtime_code, manifest_runtime_code, MAX_CHUNK_BODY};

use super::{qty, Chain, Deployed};

/// The largest progress file read.
const MAX_PROGRESS_BYTES: u64 = 1 << 20;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RecordedChunk {
    start: usize,
    end: usize,
    address: Address,
    tx_hash: B256,
    nonce: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RecordedManifest {
    address: Address,
    tx_hash: B256,
    nonce: u64,
}

/// A deployment sent and not yet known to have mined: a chunk (`start..end`) or, without a range,
/// the manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RecordedPending {
    start: Option<usize>,
    end: Option<usize>,
    nonce: u64,
    /// The address the creation at `nonce` makes.
    address: Address,
    /// Every transaction sent at `nonce` for it (replacements included), in order.
    tx_hashes: Vec<B256>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Record {
    version: u32,
    chain_id: u64,
    sha256: B256,
    length: usize,
    chunks: Vec<RecordedChunk>,
    manifest: Option<RecordedManifest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pending: Option<RecordedPending>,
}

/// An open progress file.
#[derive(Debug)]
pub(super) struct Progress {
    path: PathBuf,
    record: Record,
}

impl Progress {
    /// `path`'s record of this artifact on this chain: an earlier run's, or a new one when the file
    /// does not exist. A record of another artifact or chain is refused (name another file).
    pub fn open(path: &Path, chain_id: u64, sha256: B256, length: usize) -> Result<Self> {
        let fresh = Record { version: 1, chain_id, sha256, length, chunks: Vec::new(), manifest: None, pending: None };
        let record = match std::fs::File::open(path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => fresh,
            Err(e) => return Err(e).with_context(|| format!("reading the progress file {}", path.display())),
            Ok(f) => {
                let mut text = Vec::new();
                std::io::Read::read_to_end(&mut std::io::Read::take(f, MAX_PROGRESS_BYTES + 1), &mut text)
                    .with_context(|| format!("reading the progress file {}", path.display()))?;
                if text.len() as u64 > MAX_PROGRESS_BYTES {
                    bail!("{} is larger than {MAX_PROGRESS_BYTES} bytes: not a progress file", path.display());
                }
                let r: Record = serde_json::from_slice(&text)
                    .with_context(|| format!("{} is not a progress file of `zkminer artifact publish`", path.display()))?;
                if r.version != 1 {
                    bail!("{}: progress file version {} (this zkminer writes 1)", path.display(), r.version);
                }
                if (r.chain_id, r.sha256, r.length) != (chain_id, sha256, length) {
                    bail!(
                        "{} records another publication (chain {}, sha256 {}, {} bytes): name a progress file of its own",
                        path.display(),
                        r.chain_id,
                        r.sha256,
                        r.length
                    );
                }
                r
            }
        };
        Ok(Progress { path: path.to_path_buf(), record })
    }

    /// The recorded chunks that are on chain as recorded, from the start of the file, with their
    /// ranges; then the deployment left pending, when it is the next one and one of its transactions
    /// created it as recorded; and the manifest, when every chunk is and so is it.
    pub async fn reusable(&self, chain: &Chain, bytes: &[u8]) -> Result<(Vec<(Range<usize>, Deployed)>, Option<Deployed>)> {
        let mut out = Vec::new();
        let mut at = 0;
        for r in &self.record.chunks {
            if r.start != at || r.end <= r.start || r.end > bytes.len() || r.end - r.start > MAX_CHUNK_BODY {
                break;
            }
            let runtime = chunk_runtime_code(&bytes[r.start..r.end]);
            let Some(d) = on_chain(chain, r.address, r.tx_hash, r.nonce, &runtime).await? else { break };
            out.push((r.start..r.end, d));
            at = r.end;
        }
        let every_chunk = out.len() == self.record.chunks.len();
        let pending = self.record.pending.as_ref().filter(|_| every_chunk);
        // A chunk sent before the stop: the next one.
        if let Some(p @ RecordedPending { start: Some(start), end: Some(end), .. }) = pending {
            let (start, end) = (*start, *end);
            if start == at && end > start && end <= bytes.len() && end - start <= MAX_CHUNK_BODY {
                if let Some(d) = pending_on_chain(chain, p, &chunk_runtime_code(&bytes[start..end])).await? {
                    out.push((start..end, d));
                    at = end;
                }
            }
        }
        let addresses = || out.iter().map(|(_, d)| d.address).collect::<Vec<Address>>();
        let manifest = match (&self.record.manifest, pending) {
            (Some(m), _) if at == bytes.len() && every_chunk => {
                let runtime = manifest_runtime_code(bytes.len() as u64, &self.record.sha256.0, &addresses());
                on_chain(chain, m.address, m.tx_hash, m.nonce, &runtime).await?
            }
            // The manifest sent before the stop.
            (None, Some(p @ RecordedPending { start: None, .. })) if at == bytes.len() => {
                let runtime = manifest_runtime_code(bytes.len() as u64, &self.record.sha256.0, &addresses());
                pending_on_chain(chain, p, &runtime).await?
            }
            _ => None,
        };
        Ok((out, manifest))
    }

    /// The nonce and hashes of the deployment left pending, if any.
    pub fn pending_send(&self) -> Option<(u64, &[B256])> {
        self.record.pending.as_ref().map(|p| (p.nonce, p.tx_hashes.as_slice()))
    }

    /// Keeps what was found on chain (`chunks`, `manifest`) as the record; nothing is pending.
    pub fn keep(&mut self, chunks: &[(Range<usize>, Deployed)], manifest: Option<&Deployed>) {
        self.record.chunks.clear();
        self.record.manifest = None;
        self.record.pending = None;
        for (range, d) in chunks {
            self.push_chunk(range.clone(), d);
        }
        if let Some(m) = manifest {
            self.set_manifest(m);
        }
    }

    pub fn push_chunk(&mut self, range: Range<usize>, d: &Deployed) {
        self.record.chunks.push(RecordedChunk {
            start: range.start,
            end: range.end,
            address: d.address,
            tx_hash: d.tx_hash,
            nonce: d.nonce,
        });
        self.record.pending = None;
    }

    pub fn set_manifest(&mut self, d: &Deployed) {
        self.record.manifest = Some(RecordedManifest { address: d.address, tx_hash: d.tx_hash, nonce: d.nonce });
        self.record.pending = None;
    }

    /// Records a transaction about to be sent at `nonce` for the chunk `range` (the manifest when
    /// `None`), whose creation makes `address`: a new pending deployment, or another hash of the one
    /// pending at that nonce (a replacement).
    pub fn note_send(&mut self, range: Option<Range<usize>>, nonce: u64, address: Address, tx_hash: B256) {
        let (start, end) = (range.as_ref().map(|r| r.start), range.as_ref().map(|r| r.end));
        match &mut self.record.pending {
            Some(p) if p.nonce == nonce && (p.start, p.end) == (start, end) && p.address == address => {
                if !p.tx_hashes.contains(&tx_hash) {
                    p.tx_hashes.push(tx_hash);
                }
            }
            slot => *slot = Some(RecordedPending { start, end, nonce, address, tx_hashes: vec![tx_hash] }),
        }
    }

    /// Writes the record beside the file and syncs it, renames it over the file, then syncs the
    /// directory: a crash leaves the old record or the new one, never half of one, and a record once
    /// saved survives a power loss.
    pub fn save(&self) -> Result<()> {
        use std::io::Write;
        let mut tmp = self.path.clone().into_os_string();
        tmp.push(".tmp");
        let tmp = PathBuf::from(tmp);
        let write = || -> std::io::Result<()> {
            let mut f = std::fs::File::create(&tmp)?;
            f.write_all(&serde_json::to_vec_pretty(&self.record)?)?;
            f.sync_all()
        };
        write().with_context(|| format!("writing {}", tmp.display()))?;
        std::fs::rename(&tmp, &self.path).with_context(|| format!("writing the progress file {}", self.path.display()))?;
        let dir = match self.path.parent() {
            Some(d) if !d.as_os_str().is_empty() => d,
            _ => Path::new("."),
        };
        std::fs::File::open(dir).and_then(|d| d.sync_all()).with_context(|| format!("syncing {}", dir.display()))
    }
}

/// The pending deployment `p` as the chain holds it now: one of its transactions created `runtime`
/// at its address ([`on_chain`]); `None` when none did (not mined, or its nonce used otherwise).
async fn pending_on_chain(chain: &Chain, p: &RecordedPending, runtime: &[u8]) -> Result<Option<Deployed>> {
    for h in &p.tx_hashes {
        if let Some(d) = on_chain(chain, p.address, *h, p.nonce, runtime).await? {
            return Ok(Some(d));
        }
    }
    Ok(None)
}

/// A recorded deployment as the chain holds it now: its receipt successful with this address, and
/// `runtime` the code there at the receipt's block; `None` otherwise.
async fn on_chain(chain: &Chain, address: Address, tx_hash: B256, nonce: u64, runtime: &[u8]) -> Result<Option<Deployed>> {
    let Some(r) = chain.receipt(tx_hash).await? else { return Ok(None) };
    let created: Option<Address> = r["contractAddress"].as_str().and_then(|a| a.parse().ok());
    if qty(&r["status"]).unwrap_or(0) != 1 || created != Some(address) {
        return Ok(None);
    }
    let block_hash: B256 = r["blockHash"].as_str().context("a receipt without a block hash")?.parse()?;
    if chain.code(address, json!({"blockHash": format!("{block_hash:#x}")})).await? != runtime {
        return Ok(None);
    }
    let gas_used = qty(&r["gasUsed"])?;
    let price = r.get("effectiveGasPrice").map(qty).transpose()?.unwrap_or(0);
    let l1 = r.get("l1Fee").filter(|v| !v.is_null()).map(qty).transpose()?.unwrap_or(0);
    Ok(Some(Deployed {
        address,
        tx_hash,
        nonce,
        block_number: qty(&r["blockNumber"])? as u64,
        block_hash,
        body_bytes: runtime.len().saturating_sub(1),
        cost_wei: gas_used.saturating_mul(price).saturating_add(l1).to_string(),
        replacements: 0,
        redeploys: 0,
        reused: true,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_record_is_of_one_publication_and_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("p.json");
        let sha = B256::repeat_byte(3);
        let mut p = Progress::open(&path, 31337, sha, 100).unwrap();
        assert!(!path.exists(), "nothing is written until a save");
        let d = Deployed {
            address: Address::repeat_byte(1),
            tx_hash: B256::repeat_byte(2),
            nonce: 7,
            block_number: 1,
            block_hash: B256::ZERO,
            body_bytes: 50,
            cost_wei: "1".into(),
            replacements: 0,
            redeploys: 0,
            reused: false,
        };
        p.push_chunk(0..50, &d);
        // A send recorded before it goes, and its replacement: one pending deployment.
        p.note_send(Some(50..100), 8, Address::repeat_byte(5), B256::repeat_byte(6));
        p.note_send(Some(50..100), 8, Address::repeat_byte(5), B256::repeat_byte(7));
        p.save().unwrap();
        let again = Progress::open(&path, 31337, sha, 100).unwrap();
        assert_eq!(again.record, p.record);
        assert_eq!(again.pending_send(), Some((8, &[B256::repeat_byte(6), B256::repeat_byte(7)][..])));
        // A send at another nonce (a creation redeployed) is a new pending deployment.
        p.note_send(Some(50..100), 9, Address::repeat_byte(8), B256::repeat_byte(9));
        assert_eq!(p.pending_send(), Some((9, &[B256::repeat_byte(9)][..])));
        // Mined: recorded, nothing pending.
        p.push_chunk(50..100, &d);
        assert_eq!(p.pending_send(), None);
        p.note_send(None, 10, Address::repeat_byte(1), B256::repeat_byte(2));
        p.set_manifest(&d);
        assert_eq!(p.pending_send(), None);
        p.save().unwrap();
        let again = Progress::open(&path, 31337, sha, 100).unwrap();
        assert_eq!(again.record, p.record);
        let mut kept = again;
        kept.note_send(None, 11, Address::repeat_byte(1), B256::repeat_byte(3));
        kept.keep(&[(0..50, d.clone())], None);
        assert_eq!(kept.record.chunks.len(), 1);
        assert!(kept.record.manifest.is_none() && kept.pending_send().is_none());
        // A file of a version without pending sends still reads.
        let old = serde_json::json!({
            "version": 1, "chainId": 31337, "sha256": sha, "length": 100, "chunks": [], "manifest": null
        });
        std::fs::write(&path, serde_json::to_vec(&old).unwrap()).unwrap();
        assert!(Progress::open(&path, 31337, sha, 100).unwrap().pending_send().is_none());
        // Another artifact, length or chain: refused.
        for (chain, sha, len) in [(1, sha, 100), (31337, B256::repeat_byte(4), 100), (31337, sha, 101)] {
            let e = Progress::open(&path, chain, sha, len).unwrap_err().to_string();
            assert!(e.contains("another publication"), "{e}");
        }
        std::fs::write(&path, "{}").unwrap();
        assert!(Progress::open(&path, 31337, sha, 100).is_err());
    }
}
