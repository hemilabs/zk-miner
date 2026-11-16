//! The broker's caches (plan §11.4): LRU with byte and entry caps, in type-tagged namespaces. Each
//! namespace has its own key type, so an RPC answer can never be looked up as an artifact:
//!
//! - [`RpcKey`]: answers to calls pinned to a block hash, keyed by chain and the broker's canonical
//!   outgoing call (never errors);
//! - [`ArtifactKey`]: builder artifacts by `(builder type, the broker's own sha256 of the bytes)`;
//! - [`ManifestKey`] / [`ManifestPairKey`]: remembered bad `hemi-code` manifests (§13.4), and
//!   [`PendingKey`]: failures read above the safe head, promoted once it passes their block.
//!
//! Lookups never change what a job is charged: every builder-visible budget is charged as if each
//! request missed (the callers' rule), so cache state cannot be probed through budgets.

use std::collections::{BTreeMap, HashMap};
use std::hash::Hash;

use alloy_primitives::{Address, B256};

/// An RPC answer: the chain it is from and the canonical call (no id).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RpcKey {
    pub chain_id: u64,
    pub call: Vec<u8>,
}

/// A builder artifact, by the sha256 the broker computed over its bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ArtifactKey {
    pub builder_type: u8,
    pub sha256: B256,
}

/// A manifest address on a chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ManifestKey {
    pub chain_id: u64,
    pub manifest: Address,
}

/// A manifest read for one builder id.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ManifestPairKey {
    pub chain_id: u64,
    pub manifest: Address,
    pub builder_id: B256,
}

/// What a pending (above-safe) `hemi-code` failure is about: a manifest address, or a manifest
/// read for one builder id (an id mismatch).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PendingKey {
    Manifest(ManifestKey),
    Pair(ManifestPairKey),
}

/// Fixed per-entry overhead charged against the byte cap.
pub const ENTRY_OVERHEAD: u64 = 64;

/// A least-recently-used map with a byte cap (over the sizes callers declare) and an entry cap.
#[derive(Debug)]
pub struct Lru<K: Hash + Eq + Clone, V> {
    map: HashMap<K, Entry<V>>,
    order: BTreeMap<u64, K>,
    tick: u64,
    bytes: u64,
    max_bytes: u64,
    max_entries: usize,
}

#[derive(Debug)]
struct Entry<V> {
    value: V,
    size: u64,
    tick: u64,
}

impl<K: Hash + Eq + Clone, V> Lru<K, V> {
    pub fn new(max_bytes: u64, max_entries: usize) -> Self {
        Self { map: HashMap::new(), order: BTreeMap::new(), tick: 0, bytes: 0, max_bytes, max_entries }
    }

    /// The value, marked most recently used.
    pub fn get(&mut self, k: &K) -> Option<&V> {
        let tick = self.next_tick();
        let e = self.map.get_mut(k)?;
        self.order.remove(&e.tick);
        e.tick = tick;
        self.order.insert(tick, k.clone());
        Some(&e.value)
    }

    pub fn contains(&self, k: &K) -> bool {
        self.map.contains_key(k)
    }

    /// Inserts (or replaces) `k`, evicting least-recently-used entries until both caps hold. An
    /// entry larger than the byte cap is not stored (`false`).
    pub fn insert(&mut self, k: K, value: V, size: u64) -> bool {
        let size = size.saturating_add(ENTRY_OVERHEAD);
        self.remove(&k);
        if size > self.max_bytes || self.max_entries == 0 {
            return false;
        }
        while self.bytes + size > self.max_bytes || self.map.len() >= self.max_entries {
            let Some((_, oldest)) = self.order.pop_first() else { break };
            if let Some(e) = self.map.remove(&oldest) {
                self.bytes -= e.size;
            }
        }
        let tick = self.next_tick();
        self.order.insert(tick, k.clone());
        self.map.insert(k, Entry { value, size, tick });
        self.bytes += size;
        true
    }

    pub fn remove(&mut self, k: &K) -> Option<V> {
        let e = self.map.remove(k)?;
        self.order.remove(&e.tick);
        self.bytes -= e.size;
        Some(e.value)
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Bytes charged, overhead included.
    pub fn bytes(&self) -> u64 {
        self.bytes
    }

    fn next_tick(&mut self) -> u64 {
        self.tick += 1;
        self.tick
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evicts_least_recently_used_by_entries() {
        let mut c = Lru::new(u64::MAX, 2);
        c.insert(1, "a", 1);
        c.insert(2, "b", 1);
        assert_eq!(c.get(&1), Some(&"a")); // 2 is now the oldest
        c.insert(3, "c", 1);
        assert!(c.contains(&1) && c.contains(&3) && !c.contains(&2));
        assert_eq!(c.len(), 2);
    }

    #[test]
    fn evicts_by_bytes_and_refuses_oversize() {
        let mut c = Lru::new(3 * (100 + ENTRY_OVERHEAD), 100);
        for k in 0..3 {
            assert!(c.insert(k, k, 100));
        }
        assert_eq!(c.bytes(), 3 * (100 + ENTRY_OVERHEAD));
        assert!(c.insert(9, 9, 150), "evicts two to fit");
        assert!(!c.contains(&0) && !c.contains(&1) && c.contains(&2) && c.contains(&9));
        assert!(!c.insert(10, 10, 4 * 100 + 4 * ENTRY_OVERHEAD), "larger than the cap: not stored");
        assert!(!c.contains(&10));
        // Replacing an entry re-charges it.
        assert!(c.insert(2, 22, 1));
        assert_eq!(c.get(&2), Some(&22));
        assert_eq!(c.bytes(), (150 + ENTRY_OVERHEAD) + (1 + ENTRY_OVERHEAD));
        assert_eq!(c.remove(&2), Some(22));
        assert_eq!(c.bytes(), 150 + ENTRY_OVERHEAD);
    }

    #[test]
    fn namespaces_are_distinct_types() {
        let mut rpc: Lru<RpcKey, Vec<u8>> = Lru::new(1 << 20, 10);
        let k = RpcKey { chain_id: 1, call: b"x".to_vec() };
        rpc.insert(k.clone(), b"1".to_vec(), 1);
        assert!(!rpc.contains(&RpcKey { chain_id: 2, call: b"x".to_vec() }), "keyed by chain");
        assert_eq!(rpc.get(&k), Some(&b"1".to_vec()));
    }
}
