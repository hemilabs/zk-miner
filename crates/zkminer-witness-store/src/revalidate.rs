//! Revalidation (plan §15.2): before a lock on a retained bundle, compare it with the host as it is
//! now. Pure functions over [`BundleV1`] and [`HostProfile`].

use alloy_primitives::B256;
use zkminer_witness::bundle::{BundleV1, GuestExit};

/// The host as it is now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostProfile {
    /// The po2 set of the enabled cards.
    pub po2s: Vec<u32>,
    /// Fingerprint of the `sys_rand` host key.
    pub sys_rand_key_fingerprint: B256,
    /// `RISC0_KECCAK_PO2`.
    pub keccak_po2: u32,
    /// Build ids of every worker binary that may prove the job now.
    pub worker_builds: Vec<String>,
}

/// How a bundle compares with the host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Revalidation {
    /// Requested po2s with no recorded result: execute them from the retained `W` (never by
    /// rebuilding) before proving there.
    pub missing_po2s: Vec<u32>,
    /// Requested po2s whose recorded result is not `Halted(0)`: not provable.
    pub unprovable_po2s: Vec<u32>,
    pub key_fingerprint_matches: bool,
    pub keccak_po2_matches: bool,
    /// Host worker builds the bundle was not executed under.
    pub unrecorded_worker_builds: Vec<String>,
}

impl Revalidation {
    pub fn worker_builds_match(&self) -> bool {
        self.unrecorded_worker_builds.is_empty()
    }

    /// The bundle can be proven on this host as it is, at every requested po2.
    pub fn is_current(&self) -> bool {
        self.missing_po2s.is_empty()
            && self.unprovable_po2s.is_empty()
            && self.key_fingerprint_matches
            && self.keccak_po2_matches
            && self.worker_builds_match()
    }
}

fn sorted_unique(v: impl IntoIterator<Item = u32>) -> Vec<u32> {
    let mut v: Vec<u32> = v.into_iter().collect();
    v.sort_unstable();
    v.dedup();
    v
}

/// Requested po2s the bundle has no result for (sorted, unique).
pub fn missing_po2s(bundle: &BundleV1, requested: &[u32]) -> Vec<u32> {
    sorted_unique(requested.iter().copied().filter(|p| bundle.at(*p).is_none()))
}

/// Requested po2s whose recorded result is not `Halted(0)` (sorted, unique).
pub fn unprovable_po2s(bundle: &BundleV1, requested: &[u32]) -> Vec<u32> {
    sorted_unique(requested.iter().copied().filter(|p| bundle.at(*p).is_some_and(|r| r.exit != GuestExit::Halted(0))))
}

/// Compares a bundle with the host: missing and unprovable po2s from the host's set, the `sys_rand`
/// key fingerprint, the keccak po2, and whether every host worker build is one the bundle records.
pub fn revalidate(bundle: &BundleV1, host: &HostProfile) -> Revalidation {
    let mut unrecorded: Vec<String> =
        host.worker_builds.iter().filter(|b| !bundle.worker_builds.contains(b)).cloned().collect();
    unrecorded.sort();
    unrecorded.dedup();
    Revalidation {
        missing_po2s: missing_po2s(bundle, &host.po2s),
        unprovable_po2s: unprovable_po2s(bundle, &host.po2s),
        key_fingerprint_matches: bundle.sys_rand_key_fingerprint == host.sys_rand_key_fingerprint,
        keccak_po2_matches: bundle.keccak_po2 == host.keccak_po2,
        unrecorded_worker_builds: unrecorded,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::Address;
    use zkminer_witness::bundle::{Po2Result, BUNDLE_FORMAT_VERSION};

    fn bundle() -> BundleV1 {
        let r = |po2, exit| Po2Result {
            po2,
            journal_hex: String::new(),
            journal_sha256: B256::ZERO,
            cycles: 1,
            exit,
            segment_bytes: 0,
        };
        BundleV1 {
            format_version: BUNDLE_FORMAT_VERSION,
            job_id: B256::ZERO,
            descriptor_hash: B256::ZERO,
            prover: Address::ZERO,
            descriptor_hex: String::new(),
            submit_tx_hash: B256::ZERO,
            prefix: true,
            image_id: B256::ZERO,
            po2_results: vec![r(19, GuestExit::Halted(0)), r(20, GuestExit::Halted(0)), r(21, GuestExit::Halted(1))],
            input_sha256: B256::ZERO,
            w_sha256: B256::ZERO,
            w_len: 0,
            sys_rand_key_fingerprint: B256::repeat_byte(7),
            keccak_po2: 17,
            worker_builds: vec!["cuda-abc".into(), "cpu-def".into()],
            created_at_block: 1,
            builder_id: B256::ZERO,
            caller: Address::ZERO,
        }
    }

    #[test]
    fn reports_each_dimension() {
        let b = bundle();
        let host = HostProfile {
            po2s: vec![22, 20, 19, 20],
            sys_rand_key_fingerprint: B256::repeat_byte(7),
            keccak_po2: 17,
            worker_builds: vec!["cuda-abc".into()],
        };
        let r = revalidate(&b, &host);
        assert_eq!(r.missing_po2s, vec![22]);
        assert!(r.unprovable_po2s.is_empty());
        assert!(r.key_fingerprint_matches && r.keccak_po2_matches && r.worker_builds_match());
        assert!(!r.is_current());
        assert!(revalidate(&b, &HostProfile { po2s: vec![19, 20], ..host.clone() }).is_current());

        let other = HostProfile {
            po2s: vec![21],
            sys_rand_key_fingerprint: B256::repeat_byte(8),
            keccak_po2: 18,
            worker_builds: vec!["cuda-abc".into(), "rocm-new".into(), "rocm-new".into()],
        };
        let r = revalidate(&b, &other);
        assert!(r.missing_po2s.is_empty());
        assert_eq!(r.unprovable_po2s, vec![21]);
        assert!(!r.key_fingerprint_matches && !r.keccak_po2_matches);
        assert_eq!(r.unrecorded_worker_builds, vec!["rocm-new".to_string()]);
        assert_eq!(missing_po2s(&b, &[]), Vec::<u32>::new());
    }
}
