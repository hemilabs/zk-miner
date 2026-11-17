//! A per-card cap on SP1's shard size (`SP1_GPU_ELEMENT_THRESHOLD`), recorded when a proof on that
//! card ran out of GPU memory and kept on disk, so every later run sizes that card's SP1 worker no
//! larger.
//!
//! The tiers come from a measured suite (`zkminer_prover_protocol::types`), with a margin that is thin
//! on a 12 GB card at its larger tier: a program whose shards need more than the suite's did can run
//! out there. When one does, the dispatcher (`WorkerPool::prove_on_slot`) lowers the card to the next
//! measured tier below the one the worker ran at, for the retry and for good: a program that did it
//! once is likely to be submitted again. The cap only ever goes down; deleting the file
//! (`~/.zkminer/sp1_shard_caps.json`) lifts it.
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

/// The caps in a file, read once and written through on every change.
#[derive(Debug)]
pub struct Store {
    path: PathBuf,
    cards: Vec<CardCap>,
}

impl Store {
    /// The caps in `path`: none when it is missing, or unreadable (said in the log; a cap that cannot be
    /// read is one more out-of-memory away from being recorded again).
    pub fn load(path: PathBuf) -> Self {
        let cards = match std::fs::read_to_string(&path) {
            Ok(text) => match serde_json::from_str::<CapsFile>(&text) {
                Ok(file) => file.cards,
                Err(e) => {
                    tracing::warn!(
                        "{}: not a shard-size record ({e}); starting with none",
                        path.display()
                    );
                    Vec::new()
                }
            },
            Err(_) => Vec::new(),
        };
        Self { path, cards }
    }

    /// Every card's cap.
    pub fn cards(&self) -> &[CardCap] {
        &self.cards
    }

    /// The cap recorded for this card, if any.
    pub fn cap_for(&self, pci_bus_id: &str, gpu_name: &str, total_bytes: u64) -> Option<u64> {
        self.cards
            .iter()
            .find(|c| {
                c.pci_bus_id == pci_bus_id && c.gpu_name == gpu_name && c.total_bytes == total_bytes
            })
            .map(|c| c.max_element_threshold)
    }

    /// Lowers this card's cap to `threshold` (never raises it) and writes the file. Returns the cap
    /// now in force.
    pub fn lower(
        &mut self,
        pci_bus_id: &str,
        gpu_name: &str,
        total_bytes: u64,
        threshold: u64,
        now_unix_secs: u64,
    ) -> u64 {
        let cap = match self.cards.iter_mut().find(|c| {
            c.pci_bus_id == pci_bus_id && c.gpu_name == gpu_name && c.total_bytes == total_bytes
        }) {
            Some(c) if c.max_element_threshold <= threshold => return c.max_element_threshold,
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
        if let Err(e) = self.save() {
            tracing::error!(
                "could not write {} ({e:#}); the shard-size cap holds for this run only",
                self.path.display()
            );
        }
        cap
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
    name.push(".tmp");
    path.with_file_name(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_file(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("zkminer-sp1-caps-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir.join(FILE_NAME)
    }

    #[test]
    fn a_cap_is_kept_across_loads_and_only_ever_lowered() {
        let path = temp_file("kept");
        const GIB: u64 = 1 << 30;
        let mut store = Store::load(path.clone());
        assert_eq!(store.cap_for("0000:03:00.0", "RTX 4070", 12 * GIB), None);
        assert_eq!(
            store.lower("0000:03:00.0", "RTX 4070", 12 * GIB, 134_217_728, 1),
            134_217_728
        );
        // A later run reads it back.
        let store = Store::load(path.clone());
        assert_eq!(
            store.cap_for("0000:03:00.0", "RTX 4070", 12 * GIB),
            Some(134_217_728)
        );
        // Another card in the same slot, or the same model elsewhere, has no cap.
        assert_eq!(store.cap_for("0000:03:00.0", "RTX 4080", 16 * GIB), None);
        assert_eq!(store.cap_for("0000:04:00.0", "RTX 4070", 12 * GIB), None);
        // Never raised.
        let mut store = store;
        assert_eq!(
            store.lower("0000:03:00.0", "RTX 4070", 12 * GIB, 268_435_456, 2),
            134_217_728
        );
        assert_eq!(
            Store::load(path.clone()).cap_for("0000:03:00.0", "RTX 4070", 12 * GIB),
            Some(134_217_728)
        );
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn an_unreadable_record_is_no_cap() {
        let path = temp_file("bad");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, "not json").unwrap();
        assert!(Store::load(path.clone()).cards().is_empty());
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }
}
