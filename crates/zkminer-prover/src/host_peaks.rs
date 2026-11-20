//! What each card's real proofs took in host memory (RAM and, on Windows, commit), learned per
//! proof (`WorkerPool::learn_host_peak`) and kept on disk, so a restart charges a card what its
//! proofs take rather than going back to the defaults measured on another machine.
//!
//! A card is known by its zkVM and PCI bus id (`"risc0@0000:01:00.0"`); one whose bus id is unknown
//! by its slot key, which is kept for the run only.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};

/// The file, in the miner's directory.
pub const FILE_NAME: &str = "host_peaks.json";

/// The default path: `~/.zkminer/host_peaks.json`.
pub fn default_path() -> PathBuf {
    zkminer_config::ZkMinerConfig::default_dir().join(FILE_NAME)
}

/// One card's learned figures, by the po2 its proofs ran at, in bytes (raw peaks: the margin is
/// added when charged).
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Card {
    /// `"<zkVM>@<PCI bus id>"`.
    pub card: String,
    #[serde(default)]
    pub ram: BTreeMap<u8, u64>,
    #[serde(default)]
    pub commit: BTreeMap<u8, u64>,
}

#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
struct File {
    cards: Vec<Card>,
}

/// The figures in `path`, by card; none when there is no file, and none (with a warning) when it
/// cannot be read: a lost record costs only the defaults until the next proof.
pub fn load(path: &Path) -> HashMap<String, Card> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return HashMap::new(),
        Err(e) => {
            tracing::warn!(
                "{}: {e}; starting from the default host-memory figures",
                path.display()
            );
            return HashMap::new();
        }
    };
    match serde_json::from_str::<File>(&text) {
        Ok(file) => file
            .cards
            .into_iter()
            .filter(|c| c.card.contains('@'))
            .map(|c| (c.card.clone(), c))
            .collect(),
        Err(e) => {
            tracing::warn!(
                "{}: not a host-memory record ({e}); starting from the default figures",
                path.display()
            );
            HashMap::new()
        }
    }
}

/// Write `cards` (those known by bus id) to `path`, through a temporary file renamed into place.
pub fn save(path: &Path, cards: &HashMap<String, Card>) -> std::io::Result<()> {
    let mut list: Vec<Card> = cards
        .values()
        .filter(|c| c.card.contains('@'))
        .cloned()
        .collect();
    list.sort_by(|a, b| a.card.cmp(&b.card));
    let text =
        serde_json::to_string_pretty(&File { cards: list }).map_err(std::io::Error::other)?;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, text)?;
    std::fs::rename(&tmp, path)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What is saved is read back; a card known only by its slot key is not saved; a missing or
    /// damaged file reads as nothing.
    #[test]
    fn figures_survive_a_restart() {
        let dir = std::env::temp_dir().join(format!("zkminer-host-peaks-{}", std::process::id()));
        let path = dir.join(FILE_NAME);
        let _ = std::fs::remove_file(&path);
        assert!(load(&path).is_empty());
        let mut cards = HashMap::new();
        cards.insert(
            "sp1@0000:01:00.0".to_string(),
            Card {
                card: "sp1@0000:01:00.0".into(),
                ram: BTreeMap::from([(20, 37 << 30)]),
                commit: BTreeMap::from([(20, 63 << 30)]),
            },
        );
        cards.insert(
            "risc0:cuda:9".to_string(),
            Card {
                card: "risc0:cuda:9".into(),
                ram: BTreeMap::from([(19, 5 << 30)]),
                ..Default::default()
            },
        );
        save(&path, &cards).unwrap();
        let back = load(&path);
        assert_eq!(back.len(), 1);
        assert_eq!(back["sp1@0000:01:00.0"], cards["sp1@0000:01:00.0"]);
        std::fs::write(&path, "not json").unwrap();
        assert!(load(&path).is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
