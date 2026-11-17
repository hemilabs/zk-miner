//! `--progress FILE`: what a run deployed, so a later run of the same artifact to the same chain
//! reuses it instead of sending (and paying for) it again. Each mined deployment is recorded
//! (atomically: written beside the file, then renamed over it); a later run takes the recorded
//! chunks from the start of the file, in order, for as long as each one's receipt shows a successful
//! creation at its address and the code there (at that receipt's block) is exactly the chunk this
//! file's bytes give for its range. The first that is not (reorged away, another file, an edited
//! record) and everything after it is sent again. The manifest is reused only when every chunk was
//! and its code is the manifest of those addresses. Whatever is reused is read back at the safe head
//! with the rest, so a record can save sends but never change what is published.

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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Record {
    version: u32,
    chain_id: u64,
    sha256: B256,
    length: usize,
    chunks: Vec<RecordedChunk>,
    manifest: Option<RecordedManifest>,
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
        let fresh = Record { version: 1, chain_id, sha256, length, chunks: Vec::new(), manifest: None };
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
    /// ranges; and the manifest, when every chunk is and so is it.
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
        let manifest = match &self.record.manifest {
            Some(m) if at == bytes.len() && out.len() == self.record.chunks.len() => {
                let addresses: Vec<Address> = out.iter().map(|(_, d)| d.address).collect();
                let runtime = manifest_runtime_code(bytes.len() as u64, &self.record.sha256.0, &addresses);
                on_chain(chain, m.address, m.tx_hash, m.nonce, &runtime).await?
            }
            _ => None,
        };
        Ok((out, manifest))
    }

    /// Keeps the first `chunks` recorded chunks (those found on chain), and the manifest only if
    /// `manifest`.
    pub fn keep(&mut self, chunks: usize, manifest: bool) {
        self.record.chunks.truncate(chunks);
        if !manifest {
            self.record.manifest = None;
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
    }

    pub fn set_manifest(&mut self, d: &Deployed) {
        self.record.manifest = Some(RecordedManifest { address: d.address, tx_hash: d.tx_hash, nonce: d.nonce });
    }

    /// Writes the record beside the file, then renames it over the file: a crash leaves the old
    /// record or the new one, never half of one.
    pub fn save(&self) -> Result<()> {
        let mut tmp = self.path.clone().into_os_string();
        tmp.push(".tmp");
        let tmp = PathBuf::from(tmp);
        std::fs::write(&tmp, serde_json::to_vec_pretty(&self.record)?).with_context(|| format!("writing {}", tmp.display()))?;
        std::fs::rename(&tmp, &self.path).with_context(|| format!("writing the progress file {}", self.path.display()))
    }
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
        p.push_chunk(50..100, &d);
        p.set_manifest(&d);
        p.save().unwrap();
        let again = Progress::open(&path, 31337, sha, 100).unwrap();
        assert_eq!(again.record, p.record);
        let mut kept = again;
        kept.keep(1, false);
        assert_eq!(kept.record.chunks.len(), 1);
        assert!(kept.record.manifest.is_none());
        // Another artifact, length or chain: refused.
        for (chain, sha, len) in [(1, sha, 100), (31337, B256::repeat_byte(4), 100), (31337, sha, 101)] {
            let e = Progress::open(&path, chain, sha, len).unwrap_err().to_string();
            assert!(e.contains("another publication"), "{e}");
        }
        std::fs::write(&path, "{}").unwrap();
        assert!(Progress::open(&path, 31337, sha, 100).is_err());
    }
}
