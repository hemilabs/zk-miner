//! Random sequences of store operations against a model. After every step: every pinned bundle
//! verifies and serves its exact `W`; what is on disk is exactly the model's set of versions; version
//! numbers only grow; pins, ELF refcounts and verdicts match; in-memory usage equals a re-count.

mod common;

use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;

use alloy_primitives::{keccak256, Address, B256};
use common::*;
use proptest::prelude::*;
use zkminer_witness::bundle::PinRecord;
use zkminer_witness::verdict::{SkipReason, VerdictRecord};
use zkminer_witness_store::*;

#[derive(Debug, Clone)]
enum Op {
    Write { job: u8, desc: u8, prov: u8, len: u16, chunk: u16, prefix: bool },
    Abort { job: u8, desc: u8, prov: u8, len: u16 },
    Pin { job: u8, desc: u8, prov: u8 },
    Unpin { job: u8, desc: u8, prov: u8 },
    Evict { extra_kib: u8, salt: u32 },
    Delete { job: u8 },
    Reopen,
    Verdict { job: u8, expires: u8 },
    Expire { now: u8 },
}

fn op() -> impl Strategy<Value = Op> {
    let key = || (0..3u8, 0..2u8, 0..2u8);
    prop_oneof![
        5 => (key(), 0..3000u16, 1..2500u16, any::<bool>())
            .prop_map(|((job, desc, prov), len, chunk, prefix)| Op::Write { job, desc, prov, len, chunk, prefix }),
        1 => (key(), 0..3000u16).prop_map(|((job, desc, prov), len)| Op::Abort { job, desc, prov, len }),
        3 => key().prop_map(|(job, desc, prov)| Op::Pin { job, desc, prov }),
        1 => key().prop_map(|(job, desc, prov)| Op::Unpin { job, desc, prov }),
        2 => (0..16u8, any::<u32>()).prop_map(|(extra_kib, salt)| Op::Evict { extra_kib, salt }),
        1 => (0..3u8).prop_map(|job| Op::Delete { job }),
        1 => Just(Op::Reopen),
        1 => (0..3u8, 0..8u8).prop_map(|(job, expires)| Op::Verdict { job, expires }),
        1 => (0..8u8).prop_map(|now| Op::Expire { now }),
    ]
}

fn job_id(j: u8) -> B256 {
    job(j + 1)
}

fn prover_of(p: u8) -> Address {
    Address::repeat_byte(0x30 + p)
}

fn key_of(j: u8, d: u8, p: u8) -> BundleKey {
    BundleKey::new(job_id(j), keccak256(descriptor(job_id(j), d)), prover_of(p))
}

#[derive(Default)]
struct Model {
    /// The `W` of every version that should be on disk.
    w: BTreeMap<BundleRef, Vec<u8>>,
    /// The highest version ever published per key, and store-wide.
    max_version: BTreeMap<BundleKey, u32>,
    global_max: u32,
    pins: BTreeMap<BundleKey, u32>,
    verdicts: BTreeMap<B256, u64>,
    scan_complete: bool,
}

impl Model {
    fn latest(&self, k: &BundleKey) -> Option<u32> {
        self.w.range(k.at(0)..=k.at(u32::MAX)).next_back().map(|(r, _)| r.version)
    }

    fn protected(&self, r: &BundleRef) -> bool {
        self.pins.get(&r.key()).is_some_and(|&v| v == r.version || self.latest(&r.key()) == Some(r.version))
    }
}

fn opts_for(quota: u64) -> StoreOptions {
    StoreOptions { quota_bytes: quota, ..opts() }
}

fn check(s: &Store, m: &Model) {
    // Every pinned bundle is readable and serves its W.
    for (k, &v) in &m.pins {
        let r = k.at(v);
        s.verify(&r, &desc_hash).unwrap_or_else(|e| panic!("pinned {r:?}: {e}"));
        let mut back = Vec::new();
        s.open_w(&r).unwrap().read_to_end(&mut back).unwrap();
        assert_eq!(&back, &m.w[&r], "pinned W");
    }
    // Exactly the model's versions are on disk, and every one reads.
    let keys: BTreeSet<BundleKey> =
        (0..3).flat_map(|j| (0..2).flat_map(move |d| (0..2).map(move |p| key_of(j, d, p)))).collect();
    for k in &keys {
        let want: Vec<u32> = m.w.range(k.at(0)..=k.at(u32::MAX)).map(|(r, _)| r.version).collect();
        assert_eq!(s.versions(k.job_id, k.descriptor_hash, k.prover).unwrap(), want, "{k:?}");
        match s.latest(k.job_id, k.descriptor_hash, k.prover) {
            Ok(r) => assert_eq!(Some(r.version), m.latest(k)),
            Err(e) => assert!(e.is_missing() && m.latest(k).is_none(), "{e}"),
        }
    }
    for (r, w) in &m.w {
        assert_eq!(s.read(r, &desc_hash).unwrap().w_len, w.len() as u64);
    }
    let pins: BTreeMap<BundleKey, u32> =
        s.pins().iter().map(|p| (BundleKey::of_pin(p), p.bundle_version)).collect();
    assert_eq!(pins, m.pins);
    assert_eq!(s.elf_refs(sha256(&elf(1))) as usize, m.w.len());
    for j in 0..3 {
        assert_eq!(s.verdict(job_id(j)).unwrap().map(|v| v.expires_at), m.verdicts.get(&job_id(j)).copied());
    }
    assert_accounting(s);
}

fn run(ops: Vec<Op>, quota: u64) {
    let d = tmpdir();
    let mut s = Store::open(d.path(), &expected(), opts_for(quota)).unwrap();
    // The ELF every bundle references; held for the whole run so an empty store never collects it.
    let mut hold = Some(s.put_elf(sha256(&elf(1)), &elf(1), &image_id).unwrap());
    let mut m = Model::default();
    for (i, op) in ops.into_iter().enumerate() {
        match op {
            Op::Write { job, desc, prov, len, chunk, prefix } => {
                let k = key_of(job, desc, prov);
                let w = witness(i as u8, len as usize);
                let spec = Spec { desc, prover: prover_of(prov), prefix, block: i as u64, ..Spec::new(job_id(job)) };
                let b = spec.bundle(&w);
                assert_eq!(BundleKey::of_bundle(&b), k);
                match publish(&s, &b, &w, chunk as usize) {
                    Ok(r) => {
                        assert_eq!(r.key(), k);
                        assert!(r.version > m.global_max, "versions only grow: {} after {}", r.version, m.global_max);
                        assert!(m.max_version.get(&k).is_none_or(|&v| r.version > v));
                        m.global_max = r.version;
                        m.max_version.insert(k, r.version);
                        m.w.insert(r, w);
                    }
                    Err(e) => assert!(e.is_full(), "{e}"),
                }
            }
            Op::Abort { job, desc, prov, len } => {
                let k = key_of(job, desc, prov);
                match s.begin_bundle(k.job_id, k.descriptor_hash, k.prover, 1 << 20) {
                    Ok(mut wr) => {
                        let _ = wr.write_w(&witness(1, len as usize));
                        drop(wr);
                    }
                    Err(e) => assert!(e.is_full(), "{e}"),
                }
            }
            Op::Pin { job, desc, prov } => {
                let k = key_of(job, desc, prov);
                match m.latest(&k) {
                    Some(v) => {
                        let rec = PinRecord {
                            job_id: k.job_id,
                            descriptor_hash: k.descriptor_hash,
                            prover: k.prover,
                            bundle_version: v,
                            pinned_at_block: i as u64,
                        };
                        s.pin(&rec).unwrap();
                        m.pins.insert(k, v);
                    }
                    None => {
                        let rec = PinRecord {
                            job_id: k.job_id,
                            descriptor_hash: k.descriptor_hash,
                            prover: k.prover,
                            bundle_version: m.global_max + 1,
                            pinned_at_block: 0,
                        };
                        assert!(s.pin(&rec).unwrap_err().is_missing());
                    }
                }
            }
            Op::Unpin { job, desc, prov } => {
                let k = key_of(job, desc, prov);
                assert_eq!(s.unpin(k.job_id, k.descriptor_hash, k.prover).unwrap(), m.pins.remove(&k).is_some());
            }
            Op::Evict { extra_kib, salt } => {
                let value = move |meta: &BundleMeta| {
                    (meta.bundle.version as u64).wrapping_mul(2_654_435_761) ^ salt as u64
                };
                if !m.scan_complete {
                    assert!(matches!(s.evict_to(u64::MAX, &value).unwrap_err(), StoreError::EvictionDisabled));
                    let scan = s.scan().unwrap();
                    assert_eq!(scan.bundles.len(), m.w.len());
                    assert!(scan.bundles.iter().all(|b| b.record.is_ok()));
                    assert!(scan.anomalies.is_empty() && scan.unreadable_pins.is_empty());
                    s.mark_recovery_scan_complete();
                    m.scan_complete = true;
                    continue;
                }
                let target = s.headroom().unwrap() + extra_kib as u64 * 1024;
                let rep = s.evict_to(target, &value).unwrap();
                for r in &rep.evicted {
                    assert!(!m.protected(r), "evicted a protected version {r:?}");
                    m.w.remove(r).expect("evicted a version the model has");
                }
                if !rep.reached {
                    // Nothing evictable is left.
                    let refs: Vec<BundleRef> = m.w.keys().copied().collect();
                    assert!(refs.iter().all(|r| m.protected(r)), "stopped short with evictable versions");
                }
            }
            Op::Delete { job } => {
                let j = job_id(job);
                let t = TerminalProof { job_id: j, state: TerminalState::Cancelled, read_at_block: i as u64 };
                let pinned = m.pins.keys().any(|k| k.job_id == j);
                match s.delete_job(j, &t) {
                    Ok(rep) => {
                        assert!(!pinned, "deleted a pinned job");
                        let before = m.w.len();
                        m.w.retain(|r, _| r.job_id != j);
                        assert_eq!(rep.versions_removed, before - m.w.len());
                        assert_eq!(rep.verdict_removed, m.verdicts.remove(&j).is_some());
                    }
                    Err(StoreError::Pinned(_)) => assert!(pinned),
                    Err(e) => panic!("{e}"),
                }
            }
            Op::Reopen => {
                drop(hold.take());
                drop(s);
                s = Store::open(d.path(), &expected(), opts_for(quota)).unwrap();
                hold = Some(s.hold_elf(sha256(&elf(1))).unwrap());
                assert_eq!(s.open_report().tmp_entries_removed, 0);
                m.scan_complete = false;
            }
            Op::Verdict { job, expires } => {
                let v = VerdictRecord {
                    job_id: job_id(job),
                    reason: SkipReason::ALL[(i + job as usize) % SkipReason::ALL.len()],
                    attempts: 1,
                    recorded_at: 0,
                    expires_at: expires as u64,
                    wasmtime_version: None,
                };
                match s.put_verdict(&v) {
                    Ok(()) => {
                        m.verdicts.insert(v.job_id, v.expires_at);
                    }
                    Err(e) => assert!(e.is_full(), "{e}"),
                }
            }
            Op::Expire { now } => {
                let now = now as u64;
                let want = m.verdicts.values().filter(|&&e| e <= now).count();
                assert_eq!(s.expire_verdicts(now).unwrap(), want);
                m.verdicts.retain(|_, e| *e > now);
            }
        }
        check(&s, &m);
    }
    drop(hold);
}

fn cases() -> u32 {
    std::env::var("PROPTEST_CASES").ok().and_then(|s| s.parse().ok()).unwrap_or(24)
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: cases(),
        failure_persistence: None,
        ..ProptestConfig::default()
    })]

    /// A roomy quota: mostly publishes, pins and evictions under a self-imposed target.
    #[test]
    fn invariants_hold_with_room(ops in prop::collection::vec(op(), 1..40)) {
        run(ops, 1 << 30);
    }

    /// A tight quota (a handful of bundles): writes hit RetentionFull and eviction makes room.
    #[test]
    fn invariants_hold_under_a_tight_quota(ops in prop::collection::vec(op(), 1..40)) {
        run(ops, 24_000);
    }
}
