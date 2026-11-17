//! A per-card cap on SP1's shard size (`SP1_GPU_ELEMENT_THRESHOLD`), recorded when SP1 on that card
//! had to run smaller after running out of GPU memory, and kept on disk so every later run sizes
//! that card's SP1 worker no larger.
//!
//! The tiers come from a measured suite (`zkminer_prover_protocol::types`), with a margin that is
//! thin on a 12 GB card at its larger tier: a program whose shards need more than the suite's did
//! can run out there. When one does, the dispatcher (`WorkerPool::prove_on_slot`) lowers the card
//! to the next measured tier below the one the worker ran at, for the rest of the run, and retries
//! the job there. Only when that program then proves at the smaller size is the cap written here:
//! the smaller size was what it needed, not a cure for a failure the size had nothing to do with.
//!
//! The cap only ever goes down. It is lifted by removing the card's entry, or the file, with the
//! miner stopped (a running miner keeps the caps its workers were started with).
//!
//! A card is known by its PCI bus id, name and total VRAM together, so a different card in the same
//! slot does not inherit another's cap. A card whose bus id is unknown is capped for the run only.

use std::path::{Path, PathBuf};

/// The file, in the miner's directory.
pub const FILE_NAME: &str = "sp1_shard_caps.json";

/// The default path: `~/.zkminer/sp1_shard_caps.json`.
pub fn default_path() -> PathBuf {
    zkminer_config::ZkMinerConfig::default_dir().join(FILE_NAME)
}

/// One card's cap.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CardCap {
    pub pci_bus_id: String,
    pub gpu_name: String,
    pub total_bytes: u64,
    /// The largest `SP1_GPU_ELEMENT_THRESHOLD` its SP1 worker may run at.
    pub max_element_threshold: u64,
    /// When it was last lowered, in seconds since the Unix epoch.
    pub recorded_unix_secs: u64,
}

#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
struct CapsFile {
    cards: Vec<CardCap>,
}

/// The caps in a file, read at start and written through on every change.
#[derive(Debug)]
pub struct Store {
    path: PathBuf,
    cards: Vec<CardCap>,
}

/// The cards of `path`'s file: `Ok(None)` when there is none, `Err` when it cannot be read or is
/// not a record. Entries below the smallest measured tier (which nothing here writes) are dropped:
/// the server would be handed a shard size nothing has measured, or one too small to prove
/// anything.
fn read(path: &Path) -> Result<Option<Vec<CardCap>>, String> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("{}: {e}", path.display())),
    };
    let file = serde_json::from_str::<CapsFile>(&text)
        .map_err(|e| format!("{}: not a shard-size record ({e})", path.display()))?;
    let smallest = zkminer_prover_protocol::types::sp1_smallest_measured_threshold();
    let (kept, dropped): (Vec<_>, Vec<_>) = file
        .cards
        .into_iter()
        .partition(|c| c.max_element_threshold >= smallest);
    for c in &dropped {
        tracing::warn!(
            "{}: ignoring the cap {} for {} ({}): below the smallest measured shard size {smallest}",
            path.display(),
            c.max_element_threshold,
            c.gpu_name,
            c.pci_bus_id
        );
    }
    Ok(Some(kept))
}

fn same_card(c: &CardCap, pci_bus_id: &str, gpu_name: &str, total_bytes: u64) -> bool {
    c.pci_bus_id == pci_bus_id && c.gpu_name == gpu_name && c.total_bytes == total_bytes
}

impl Store {
    /// The caps in `path`, or `Err` saying why the file there cannot be used.
    pub fn load_checked(path: PathBuf) -> Result<Self, String> {
        let cards = read(&path)?.unwrap_or_default();
        Ok(Self { path, cards })
    }

    /// The caps in `path`: none when there is no file, and none (said in the log) when it cannot be
    /// read; such a file is then left as it is (`lower` refuses to write over it).
    pub fn load(path: PathBuf) -> Self {
        Self::load_checked(path.clone()).unwrap_or_else(|e| {
            tracing::warn!("{e}; no SP1 shard-size caps are applied");
            Self {
                path,
                cards: Vec::new(),
            }
        })
    }

    /// Every card's cap.
    pub fn cards(&self) -> &[CardCap] {
        &self.cards
    }

    /// The cap recorded for this card, if any.
    pub fn cap_for(&self, pci_bus_id: &str, gpu_name: &str, total_bytes: u64) -> Option<&CardCap> {
        self.cards
            .iter()
            .find(|c| same_card(c, pci_bus_id, gpu_name, total_bytes))
    }

    /// Lowers this card's cap to `threshold` (never raises it) and writes the file, merged into
    /// what the file holds now: an entry the operator removed is not written back, and one written
    /// by another run is kept. Returns the cap now in force, or `Err` (the cap then holds for this
    /// run only) when the file cannot be read back or written: a file that cannot be read is never
    /// written over.
    pub fn lower(
        &mut self,
        pci_bus_id: &str,
        gpu_name: &str,
        total_bytes: u64,
        threshold: u64,
        now_unix_secs: u64,
    ) -> Result<u64, String> {
        self.cards = read(&self.path)?.unwrap_or_default();
        let cap = match self
            .cards
            .iter_mut()
            .find(|c| same_card(c, pci_bus_id, gpu_name, total_bytes))
        {
            Some(c) if c.max_element_threshold <= threshold => return Ok(c.max_element_threshold),
            Some(c) => {
                c.max_element_threshold = threshold;
                c.recorded_unix_secs = now_unix_secs;
                threshold
            }
            None => {
                self.cards.push(CardCap {
                    pci_bus_id: pci_bus_id.to_string(),
                    gpu_name: gpu_name.to_string(),
                    total_bytes,
                    max_element_threshold: threshold,
                    recorded_unix_secs: now_unix_secs,
                });
                threshold
            }
        };
        self.save()
            .map_err(|e| format!("{}: {e:#}", self.path.display()))?;
        Ok(cap)
    }

    /// Temp file and rename, so a reader sees the old file or the new one, never half of one.
    fn save(&self) -> anyhow::Result<()> {
        if let Some(dir) = self.path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let text = serde_json::to_string_pretty(&CapsFile {
            cards: self.cards.clone(),
        })?;
        let tmp = tmp_path(&self.path);
        std::fs::write(&tmp, text)?;
        std::fs::rename(&tmp, &self.path)?;
        Ok(())
    }
}

fn tmp_path(path: &Path) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(format!(".{}.tmp", std::process::id()));
    path.with_file_name(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    const GIB: u64 = 1 << 30;
    const BUS: &str = "0000:03:00.0";
    const NAME: &str = "RTX 4070";

    fn temp_file(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("zkminer-sp1-caps-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir.join(FILE_NAME)
    }

    fn cap(store: &Store) -> Option<u64> {
        store
            .cap_for(BUS, NAME, 12 * GIB)
            .map(|c| c.max_element_threshold)
    }

    #[test]
    fn a_cap_is_kept_across_loads_and_only_ever_lowered() {
        let path = temp_file("kept");
        let mut store = Store::load(path.clone());
        assert_eq!(cap(&store), None);
        assert_eq!(
            store.lower(BUS, NAME, 12 * GIB, 134_217_728, 1),
            Ok(134_217_728)
        );
        // A later run reads it back.
        let mut store = Store::load(path.clone());
        assert_eq!(cap(&store), Some(134_217_728));
        // Another card in the same slot, or the same model elsewhere, has no cap.
        assert!(store.cap_for(BUS, "RTX 4080", 16 * GIB).is_none());
        assert!(store.cap_for("0000:04:00.0", NAME, 12 * GIB).is_none());
        // Never raised.
        assert_eq!(
            store.lower(BUS, NAME, 12 * GIB, 268_435_456, 2),
            Ok(134_217_728)
        );
        assert_eq!(cap(&Store::load(path.clone())), Some(134_217_728));
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn an_entry_removed_while_running_is_not_written_back() {
        let path = temp_file("removed");
        let mut store = Store::load(path.clone());
        store.lower(BUS, NAME, 12 * GIB, 134_217_728, 1).unwrap();
        // The operator removes the file; this run's store still holds the entry, but the next
        // change, for another card, does not bring it back.
        std::fs::remove_file(&path).unwrap();
        store
            .lower("0000:04:00.0", NAME, 12 * GIB, 134_217_728, 2)
            .unwrap();
        let reread = Store::load(path.clone());
        assert_eq!(cap(&reread), None);
        assert_eq!(reread.cards().len(), 1);
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn an_unreadable_record_is_no_cap_and_is_never_written_over() {
        let path = temp_file("bad");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, "not json").unwrap();
        assert!(Store::load_checked(path.clone()).is_err());
        let mut store = Store::load(path.clone());
        assert!(store.cards().is_empty());
        assert!(store.lower(BUS, NAME, 12 * GIB, 134_217_728, 1).is_err());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "not json");
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn a_cap_below_every_measured_size_is_ignored() {
        let path = temp_file("tiny");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let file = format!(
            r#"{{"cards":[{{"pci_bus_id":"{BUS}","gpu_name":"{NAME}","total_bytes":{},"max_element_threshold":0,"recorded_unix_secs":0}}]}}"#,
            12 * GIB
        );
        std::fs::write(&path, file).unwrap();
        assert_eq!(cap(&Store::load(path.clone())), None);
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }
}
