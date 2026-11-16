//! Crash-at-step-k sweeps: the seam stops the "process" just before its k-th mutating call (that
//! call and every later one fail without touching the disk; the `Store` is then dropped, releasing
//! its lock, as a dead process would). For every k, the reopened store must be consistent: `tmp/`
//! emptied, no partial or unreadable version, every pin naming a version that verifies, the
//! counter ahead of every version, usage matching a re-count — and every completed operation's
//! promise kept.

use std::path::Path;

use alloy_primitives::B256;
use zkminer_witness::verdict::{SkipReason, VerdictRecord};

use super::common::*;
use crate::faults;
use crate::*;

/// What the child finished (`Done`) or began (`Begun`) before the crash.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Step {
    Published(BundleRef),
    Pinned(BundleRef),
    Begun(Removal),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Removal {
    /// Eviction, an unpin or a delete of a job may remove what an earlier step promised.
    Of(B256),
}

fn terminal(job_id: B256) -> TerminalProof {
    TerminalProof { job_id, state: TerminalState::Fulfilled, read_at_block: 1 }
}

/// Every kind of change the store makes, in an order a miner could.
fn child_ops(dir: &Path, log: &mut Vec<Step>) -> Result<(), StoreError> {
    let s = Store::open(dir, &expected(dir), opts())?;
    drop(s.put_elf(sha256(&elf(1)), &elf(1), &image_id)?);
    let spec = Spec::new(job(20));

    let w1 = witness(1, 3000);
    let va = publish(&s, &spec.bundle(&w1), &w1, 1000)?;
    log.push(Step::Published(va));
    s.pin(&s.pin_record(&va, 1)?)?;
    log.push(Step::Pinned(va));

    // Sealed for execution before publication.
    let w2 = witness(2, 3500);
    let b2 = spec.bundle(&w2);
    let mut wr = s.begin_bundle(b2.job_id, b2.descriptor_hash, b2.prover, 1 << 20)?;
    wr.write_w(&w2)?;
    drop(wr.seal_w()?);
    let v = wr.version();
    let vb = wr.finish(&at(&b2, v), &desc_hash)?;
    log.push(Step::Published(vb));
    s.pin(&s.pin_record(&vb, 2)?)?;
    log.push(Step::Pinned(vb));

    // Re-versioned from the retained W.
    let wr = s.begin_version_from(&vb)?;
    let v = wr.version();
    let vc = wr.finish(&at(&b2, v), &desc_hash)?;
    log.push(Step::Published(vc));

    let w3 = witness(3, 2000);
    let o = publish(&s, &Spec::new(job(21)).bundle(&w3), &w3, 700)?;
    log.push(Step::Published(o));
    let verdict = VerdictRecord {
        job_id: job(21),
        reason: SkipReason::GuestFailed,
        attempts: 1,
        recorded_at: 1,
        expires_at: 99,
        wasmtime_version: None,
    };
    s.put_verdict(&verdict)?;

    s.mark_recovery_scan_complete();
    log.push(Step::Begun(Removal::Of(job(20))));
    log.push(Step::Begun(Removal::Of(job(21))));
    let rep = s.evict_to(u64::MAX, &|_| 0)?;
    assert!(rep.evicted.contains(&va) && rep.evicted.contains(&o), "{rep:?}");
    s.unpin(vb.job_id, vb.descriptor_hash, vb.prover)?;
    s.delete_job(job(20), &terminal(job(20)))?;
    s.delete_job(job(21), &terminal(job(21)))?;
    s.expire_verdicts(1_000)?;
    Ok(())
}

fn check_after_crash(dir: &Path, k: u64, log: &[Step]) {
    let s = Store::open(dir, &expected(dir), opts()).unwrap_or_else(|e| panic!("k={k}: open {e:?}"));
    assert_eq!(tmp_entries(dir), 0, "k={k}");
    let scan = s.scan().unwrap_or_else(|e| panic!("k={k}: scan {e:?}"));
    assert!(scan.anomalies.is_empty() && scan.unreadable_pins.is_empty(), "k={k}: {:?}", scan.anomalies);
    let mut max = 0;
    for m in &scan.bundles {
        assert!(m.record.is_ok(), "k={k}: partial version {:?}", m.bundle);
        s.verify(&m.bundle, &desc_hash, &image_id).unwrap_or_else(|e| panic!("k={k}: {e:?}"));
        max = max.max(m.bundle.version);
    }
    for p in &scan.pins {
        let r = BundleKey::of_pin(p).at(p.bundle_version);
        s.verify(&r, &desc_hash, &image_id).unwrap_or_else(|e| panic!("k={k}: pin names a bad version: {e:?}"));
    }
    let nv: u32 = std::fs::read_to_string(dir.join("next_version")).unwrap().trim().parse().unwrap();
    assert!(nv > max, "k={k}");
    assert_accounting(&s);

    // Promises: what completed is there, unless a later step began to remove it.
    let removing = |j: B256, after: usize| log[after..].contains(&Step::Begun(Removal::Of(j)));
    for (i, step) in log.iter().enumerate() {
        match *step {
            Step::Published(r) if !removing(r.job_id, i) => {
                s.verify(&r, &desc_hash, &image_id).unwrap_or_else(|e| panic!("k={k}: published {r:?} lost: {e:?}"));
            }
            Step::Pinned(r) if !removing(r.job_id, i) => {
                assert!(scan.pins.iter().any(|p| BundleKey::of_pin(p) == r.key()), "k={k}: pin of {r:?} lost")
            }
            _ => {}
        }
    }
}

#[test]
fn crash_at_every_step_leaves_a_consistent_store() {
    let mut k = 1u64;
    loop {
        let d = tmpdir();
        Store::init(d.path(), &init_id()).unwrap();
        let mut log = Vec::new();
        let f = faults::install();
        f.crash_at(k);
        let res = child_ops(d.path(), &mut log);
        let crashed = f.crashed();
        drop(f);
        if !crashed {
            res.unwrap_or_else(|e| panic!("uncrashed run failed: {e:?}"));
            check_after_crash(d.path(), k, &log);
            assert!(k > 50, "the sweep covered only {k} steps");
            eprintln!("crash sweep: {} crash points checked", k - 1);
            break;
        }
        assert!(res.is_err(), "k={k}: a crashed run cannot succeed");
        check_after_crash(d.path(), k, &log);
        k += 1;
        assert!(k < 5_000);
    }
}

#[test]
fn crash_during_init_is_finished_by_running_it_again() {
    let mut k = 1u64;
    loop {
        let d = tmpdir();
        let f = faults::install();
        f.crash_at(k);
        let res = Store::init(d.path(), &init_id());
        let crashed = f.crashed();
        drop(f);
        if !crashed {
            res.unwrap();
            break;
        }
        assert!(res.is_err(), "k={k}");
        // Either the identity never landed (init again), or it did (it is initialised).
        match Store::init(d.path(), &init_id()) {
            Ok(_) | Err(StoreError::Rejected(Reject::AlreadyInitialised)) => {}
            Err(e) => panic!("k={k}: re-init {e:?}"),
        }
        let s = Store::open(d.path(), &expected(d.path()), opts()).unwrap_or_else(|e| panic!("k={k}: {e:?}"));
        assert_eq!(tmp_entries(d.path()), 0, "k={k}");
        assert_accounting(&s);
        k += 1;
        assert!(k < 100);
    }
    assert!(k > 5, "{k}");
}
