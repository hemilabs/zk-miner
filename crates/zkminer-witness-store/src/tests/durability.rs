//! F1, F5, F8: what an fsync or rename failure leaves, and the order of removal.

use super::common::*;
use super::{poisoned, unavailable};
use crate::faults::{self, Op};
use crate::*;

fn key_sub(r: &BundleRef) -> String {
    format!("{}/{}", hex::encode(r.descriptor_hash), hex::encode(r.prover))
}

fn terminal(job_id: alloy_primitives::B256) -> TerminalProof {
    TerminalProof { job_id, state: TerminalState::Fulfilled, read_at_block: 1 }
}

/// Every public call on a poisoned store is refused, and none of them touches the disk.
fn assert_all_refused(s: &Store, f: &faults::Faults, r: &BundleRef, rec: &zkminer_witness::bundle::PinRecord) {
    f.trace(true);
    poisoned(s.latest(r.job_id, r.descriptor_hash, r.prover));
    poisoned(s.versions(r.job_id, r.descriptor_hash, r.prover));
    poisoned(s.read(r, &desc_hash));
    poisoned(s.open_w(r));
    poisoned(s.verify(r, &desc_hash, &image_id));
    poisoned(s.pin_record(r, 1));
    poisoned(s.pin(rec));
    poisoned(s.unpin(r.job_id, r.descriptor_hash, r.prover));
    poisoned(s.scan());
    poisoned(s.headroom());
    poisoned(s.recount_usage());
    poisoned(s.begin_bundle(r.job_id, r.descriptor_hash, r.prover, 10));
    poisoned(s.begin_version_from(r));
    poisoned(s.evict_to(u64::MAX, &|_| 0));
    poisoned(s.delete_job(r.job_id, &terminal(r.job_id)));
    poisoned(s.put_elf(sha256(&elf(1)), &elf(1), &image_id));
    poisoned(s.hold_elf(sha256(&elf(1))));
    poisoned(s.open_elf(sha256(&elf(1)), &image_id));
    poisoned(s.verdict(r.job_id));
    poisoned(s.expire_verdicts(0));
    assert!(s.is_poisoned());
    assert_eq!(f.take_mutations(), Vec::<String>::new(), "a poisoned store changes nothing");
    f.trace(false);
}

/// F1: the key directory's fsync fails after the publishing rename. The version is taken back
/// out of view and never indexed, the store is poisoned, and a reopen finds no trace of it.
#[test]
fn a_publish_whose_final_fsync_fails_is_rolled_back_and_poisons() {
    let d = tmpdir();
    let s = open(d.path());
    let spec = Spec::new(job(1));
    let w = witness(1, 10_000);
    let b = spec.bundle(&w);
    let old = put_and_publish(&s, &spec, &w);
    let rec = pin_rec(&s, &old);
    s.pin(&rec).unwrap();

    let f = faults::install();
    f.fail(Op::Fsync, &key_sub(&old), libc::EIO, 0, 1);
    let mut wr = s.begin_bundle(b.job_id, b.descriptor_hash, b.prover, 1 << 20).unwrap();
    wr.write_w(&w).unwrap();
    let v = wr.version();
    let e = wr.finish(&at(&b, v), &desc_hash).unwrap_err();
    assert_eq!(unavailable(e), UnavailableKind::Eio);
    let new = old.key().at(v);
    assert!(!vdir(d.path(), &new).exists(), "renamed back out of view");
    assert!(!s.inner.state().versions.contains_key(&new), "never indexed");
    assert_eq!(tmp_entries(d.path()), 0, "the writer removed it");
    assert_all_refused(&s, &f, &old, &rec);
    drop(f);
    drop(s);

    let s = open(d.path());
    assert_eq!(s.versions(old.job_id, old.descriptor_hash, old.prover).unwrap(), vec![old.version]);
    s.verify(&old, &desc_hash, &image_id).unwrap();
    assert_eq!(s.pins(), vec![rec]);
    let again = publish(&s, &b, &w, 1000).unwrap();
    assert!(again.version > v, "the number is never reused");
    assert_accounting(&s);
}

/// F1 (b, c, d): `pins/`'s fsync fails after the rename. The store is poisoned, the key's pin is
/// unknown (every version protected), and neither a retried pin nor a scan can make it look
/// durable; after a reopen the pin read back from disk protects the version.
#[test]
fn a_pin_whose_directory_fsync_fails_poisons_and_protects() {
    let d = tmpdir();
    let s = open(d.path());
    let r = put_and_publish(&s, &Spec::new(job(2)), &witness(2, 5000));
    let rec = pin_rec(&s, &r);
    s.mark_recovery_scan_complete();

    let f = faults::install();
    f.fail(Op::Fsync, "/pins", libc::EIO, 0, 1);
    assert_eq!(unavailable(s.pin(&rec).unwrap_err()), UnavailableKind::Eio);
    assert!(pin_file(d.path(), &r).exists(), "the rename happened");
    assert_eq!(s.pin_status(&r.key()), PinStatus::Unreadable);
    assert_eq!(s.unreadable_pins(), vec![r.key()]);
    // F1c/F1d: the retry, the scan that would reload the pin, and the retry after it.
    f.trace(true);
    poisoned(s.pin(&rec));
    poisoned(s.scan());
    poisoned(s.pin(&rec));
    assert_eq!(f.take_mutations(), Vec::<String>::new());
    assert_all_refused(&s, &f, &r, &rec);
    drop(f);
    drop(s);

    let s = open(d.path());
    assert_eq!(s.pins(), vec![rec.clone()]);
    s.scan().unwrap();
    s.mark_recovery_scan_complete();
    assert!(s.evict_to(u64::MAX, &|_| 0).unwrap().evicted.is_empty());
    s.verify(&r, &desc_hash, &image_id).unwrap();
}

/// A pin whose write fails before anything is visible does not poison, but its key is protected
/// until the pin succeeds or a scan reads the old state back.
#[test]
fn a_pin_that_fails_before_its_rename_protects_without_poisoning() {
    let d = tmpdir();
    let s = open(d.path());
    let spec = Spec::new(job(3));
    let r1 = put_and_publish(&s, &spec, &witness(3, 3000));
    let rec1 = pin_rec(&s, &r1);
    s.pin(&rec1).unwrap();
    let r2 = put_and_publish(&s, &spec, &witness(4, 3000));
    let r3 = put_and_publish(&s, &spec, &witness(5, 3000));
    let rec2 = pin_rec(&s, &r2);
    s.mark_recovery_scan_complete();

    let f = faults::install();
    f.fail(Op::Write, ".part", libc::ENOSPC, 0, 1);
    assert!(matches!(s.pin(&rec2).unwrap_err(), StoreError::RetentionFull(FullReason::Filesystem)));
    assert!(!s.is_poisoned());
    assert_eq!(s.pin_status(&r1.key()), PinStatus::Unreadable);
    // Unknown protects every version of the key, r1 included (the old pin is still on disk).
    let rep = s.evict_to(u64::MAX, &|_| 0).unwrap();
    assert!(rep.evicted.is_empty());
    // A scan reads the old, still-valid pin back.
    s.scan().unwrap();
    assert_eq!(s.pin_status(&r1.key()), PinStatus::Pinned { version: r1.version });
    // The retry writes it (the earlier temp file and its fd were abandoned, never re-fsynced).
    f.trace(true);
    s.pin(&rec2).unwrap();
    assert!(f.take_mutations().iter().any(|m| m.starts_with("Fsync") && m.ends_with("/pins")));
    assert_eq!(s.pins(), vec![rec2]);
    let rep = s.evict_to(u64::MAX, &|_| 0).unwrap();
    assert_eq!(rep.evicted, vec![r1], "r2 pinned, r3 its latest");
    let _ = r3;
}

/// An identical pin is skipped only when this `Store` wrote and fsynced it; one read back from
/// disk is rewritten.
#[test]
fn an_identical_pin_is_skipped_only_when_written_here() {
    let d = tmpdir();
    let s = open(d.path());
    let r = put_and_publish(&s, &Spec::new(job(4)), &witness(4, 1000));
    let rec = pin_rec(&s, &r);
    let f = faults::install();
    f.trace(true);
    s.pin(&rec).unwrap();
    assert!(f.take_mutations().iter().any(|m| m.starts_with("Fsync") && m.ends_with("/pins")));
    s.pin(&rec).unwrap();
    assert_eq!(f.take_mutations(), Vec::<String>::new(), "written and fsynced here: nothing to do");
    // A scan reloads the pin from disk: no longer known durable by this store.
    s.scan().unwrap();
    s.pin(&rec).unwrap();
    assert!(f.take_mutations().iter().any(|m| m.starts_with("Fsync") && m.ends_with("/pins")));
    drop(s);
    let s = open(d.path());
    s.pin(&rec).unwrap();
    assert!(f.take_mutations().iter().any(|m| m.starts_with("Fsync") && m.ends_with("/pins")), "after a reopen");
}

/// An unpin whose directory fsync fails leaves the key unknown and poisons.
#[test]
fn an_unpin_whose_fsync_fails_poisons_and_protects() {
    let d = tmpdir();
    let s = open(d.path());
    let r = put_and_publish(&s, &Spec::new(job(5)), &witness(5, 1000));
    s.pin(&pin_rec(&s, &r)).unwrap();
    let f = faults::install();
    f.fail(Op::Fsync, "/pins", libc::EIO, 0, 1);
    assert_eq!(unavailable(s.unpin(r.job_id, r.descriptor_hash, r.prover).unwrap_err()), UnavailableKind::Eio);
    assert!(s.is_poisoned());
    assert_eq!(s.pin_status(&r.key()), PinStatus::Unreadable);
}

/// F5: eviction renames the version into `tmp/`, fsyncs the old parent, and only then deletes the
/// contents.
#[test]
fn removal_fsyncs_the_old_parent_before_deleting() {
    let d = tmpdir();
    let s = open(d.path());
    let spec = Spec::new(job(6));
    let r1 = put_and_publish(&s, &spec, &witness(6, 5000));
    let _r2 = put_and_publish(&s, &spec, &witness(7, 5000));
    s.mark_recovery_scan_complete();
    let f = faults::install();
    f.trace(true);
    let target = s.headroom().unwrap() + 1;
    assert_eq!(s.evict_to(target, &|m| m.bundle.version as u64).unwrap().evicted, vec![r1]);
    let m = f.take_mutations();
    let key_dir = vdir(d.path(), &r1).parent().unwrap().to_string_lossy().into_owned();
    let pos = |pred: &dyn Fn(&String) -> bool| m.iter().position(pred).unwrap_or_else(|| panic!("{m:#?}"));
    let rename = pos(&|l| l.starts_with("Rename") && l.ends_with(&format!("/v{}", r1.version)));
    let fsync = pos(&|l| *l == format!("Fsync {key_dir}"));
    let unlink = pos(&|l| l.starts_with("Unlink") && l.contains(".del/"));
    assert!(rename < fsync && fsync < unlink, "{m:#?}");
}

/// F8: the parent's fsync fails after an eviction's rename: the index entry is already gone (it
/// went with the rename), the store is poisoned, and a reopen agrees.
#[test]
fn an_eviction_whose_fsync_fails_has_already_left_the_index() {
    let d = tmpdir();
    let s = open(d.path());
    let r1 = put_and_publish(&s, &Spec::new(job(30)), &witness(30, 3000));
    let r2 = put_and_publish(&s, &Spec::new(job(31)), &witness(31, 3000));
    s.mark_recovery_scan_complete();
    let f = faults::install();
    f.fail(Op::Fsync, &key_sub(&r1), libc::EIO, 0, 1);
    let e = s.evict_to(u64::MAX, &|m| m.bundle.version as u64).unwrap_err();
    assert_eq!(unavailable(e), UnavailableKind::Eio);
    assert!(s.is_poisoned());
    let st = s.inner.state();
    assert!(!st.versions.contains_key(&r1) && st.versions.contains_key(&r2));
    drop(st);
    drop(f);
    drop(s);
    let s = open(d.path());
    assert_eq!(s.open_report().tmp_entries_removed, 1, "the renamed version, never deleted");
    assert!(s.read(&r1, &desc_hash).unwrap_err().is_missing());
    s.verify(&r2, &desc_hash, &image_id).unwrap();
    assert_accounting(&s);
}

/// A failed mkdir of a missing parent before anything is visible is a plain error; once a parent
/// was created, its parent's fsync failing poisons.
#[test]
fn publish_failures_before_and_after_a_visible_change() {
    let d = tmpdir();
    let s = open(d.path());
    let spec = Spec::new(job(7));
    let w = witness(7, 2000);
    let b = spec.bundle(&w);
    drop(s.put_elf(sha256(&elf(1)), &elf(1), &image_id).unwrap());
    let f = faults::install();
    f.fail(Op::Mkdir, &hex::encode(job(7)), libc::ENOSPC, 0, 1);
    let mut wr = s.begin_bundle(b.job_id, b.descriptor_hash, b.prover, 1 << 20).unwrap();
    wr.write_w(&w).unwrap();
    let v = wr.version();
    assert!(wr.finish(&at(&b, v), &desc_hash).unwrap_err().is_full());
    assert!(!s.is_poisoned());
    assert_eq!(tmp_entries(d.path()), 0);
    assert_accounting(&s);

    f.fail(Op::Fsync, "/bundles", libc::EIO, 0, 1);
    let mut wr = s.begin_bundle(b.job_id, b.descriptor_hash, b.prover, 1 << 20).unwrap();
    wr.write_w(&w).unwrap();
    let v = wr.version();
    assert_eq!(unavailable(wr.finish(&at(&b, v), &desc_hash).unwrap_err()), UnavailableKind::Eio);
    assert!(s.is_poisoned());
    drop(f);
    drop(s);
    let s = open(d.path());
    assert!(s.latest(b.job_id, b.descriptor_hash, b.prover).unwrap_err().is_missing());
    assert_accounting(&s);
}

/// A writer whose seal fails is dead: its fsync is never retried.
#[test]
fn a_failed_seal_is_never_retried() {
    let d = tmpdir();
    let s = open(d.path());
    let b = Spec::new(job(8)).bundle(&[1, 2, 3]);
    let mut wr = s.begin_bundle(b.job_id, b.descriptor_hash, b.prover, 10).unwrap();
    wr.write_w(&[1, 2, 3]).unwrap();
    let f = faults::install();
    f.fail(Op::Fsync, "w.bin", libc::EIO, 0, 1);
    assert_eq!(unavailable(wr.seal_w().unwrap_err()), UnavailableKind::Eio);
    f.trace(true);
    assert!(matches!(wr.seal_w().unwrap_err(), StoreError::Rejected(Reject::WriterFailed)));
    let v = wr.version();
    assert!(matches!(wr.finish(&at(&b, v), &desc_hash).unwrap_err(), StoreError::Rejected(Reject::WriterFailed)));
    assert!(!f.take_mutations().iter().any(|m| m.starts_with("Fsync")));
}
