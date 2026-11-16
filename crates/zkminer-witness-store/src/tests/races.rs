//! Deterministic interleavings: a seam hook runs another store call at the exact moment a reader
//! or writer is between two syscalls (outside the store lock).

use std::sync::Arc;

use super::common::*;
use crate::faults::{self, Op};
use crate::*;

/// F7: a read racing the eviction of the very version it reads is Missing, never Corrupt, at
/// whichever file the eviction strikes.
#[test]
fn reads_racing_eviction_are_missing_not_corrupt() {
    let d = tmpdir();
    let s = Arc::new(open(d.path()));
    s.mark_recovery_scan_complete();
    type Read = fn(&Store, &BundleRef) -> Result<(), StoreError>;
    let reads: [(&str, &str, Read); 5] = [
        ("open_w", "w.bin", |s, r| s.open_w(r).map(drop)),
        ("open_w", "bundle.json", |s, r| s.open_w(r).map(drop)),
        ("read", "bundle.json", |s, r| s.read(r, &desc_hash).map(drop)),
        ("verify", "w.bin", |s, r| s.verify(r, &desc_hash, &image_id).map(drop)),
        ("begin_version_from", "w.bin", |s, r| s.begin_version_from(r).map(drop)),
    ];
    for (i, (name, file, read)) in reads.into_iter().enumerate() {
        let r = put_and_publish(&s, &Spec::new(job(10 + i as u8)), &witness(10, 5000));
        let f = faults::install();
        let s2 = Arc::clone(&s);
        let op = if name == "begin_version_from" { Op::Link } else { Op::Open };
        f.hook(op, &format!("/v{}/{file}", r.version), move || {
            let rep = s2.evict_to(u64::MAX, &|_| 0).unwrap();
            assert!(rep.evicted.contains(&r), "{rep:?}");
        });
        let e = read(&s, &r).unwrap_err();
        assert!(e.is_missing(), "{name} at {file}: {e:?}");
        drop(f);
        assert_eq!(tmp_entries(d.path()), 0, "{name}");
    }
    assert_accounting(&s);
}

/// A read that opened the version directory before an eviction removed it, but whose file is
/// still there, reads the bundle (it was intact when asked for); one whose file is gone while the
/// same directory remains is Corrupt.
#[test]
fn a_file_missing_from_a_present_version_is_corrupt() {
    let d = tmpdir();
    let s = Arc::new(open(d.path()));
    let r = put_and_publish(&s, &Spec::new(job(20)), &witness(20, 3000));
    let w_path = vdir(d.path(), &r).join("w.bin");
    let f = faults::install();
    let p = w_path.clone();
    f.hook(Op::Open, &format!("/v{}/w.bin", r.version), move || std::fs::remove_file(&p).unwrap());
    assert_eq!(super::defect(s.open_w(&r).unwrap_err()), Defect::FileMissing);
}

/// put_elf takes its hold before verifying, so an eviction that runs in between cannot collect
/// the copy it accepts.
#[test]
fn put_elf_racing_eviction_keeps_the_elf() {
    let d = tmpdir();
    let s = Arc::new(open(d.path()));
    let id = sha256(&elf(3));
    drop(s.put_elf(id, &elf(3), &image_id).unwrap());
    s.mark_recovery_scan_complete();
    let f = faults::install();
    let s2 = Arc::clone(&s);
    f.hook(Op::Open, &format!("/elfs/{}", hex::encode(id)), move || {
        assert!(s2.evict_to(u64::MAX, &|_| 0).unwrap().elfs_removed.is_empty());
    });
    let hold = s.put_elf(id, &elf(3), &image_id).unwrap();
    drop(f);
    assert_eq!(s.open_elf(id, &image_id).unwrap(), elf(3));
    // Unheld and unreferenced, it goes.
    drop(hold);
    assert_eq!(s.evict_to(u64::MAX, &|_| 0).unwrap().elfs_removed, vec![id]);
}

/// The free-space floor counts bytes admitted to a writer that has not written them yet: a second
/// writer admitted at that moment would otherwise pass a floor the two together cross.
#[test]
fn the_floor_counts_bytes_admitted_but_not_yet_written() {
    let d = tmpdir();
    drop(open(d.path()));
    const N: u64 = 16 << 20;
    let avail = open_with(d.path(), StoreOptions { quota_bytes: u64::MAX, ..opts() }).headroom().unwrap();
    assert!(avail > 8 * N, "the test needs some free disk");
    // Room above the floor for one piece and a half.
    let o = StoreOptions { free_space_floor_bytes: avail - N * 3 / 2, quota_bytes: u64::MAX, ..opts() };
    let s = Arc::new(open_with(d.path(), o));
    let b = Spec::new(job(30)).bundle(&[]);
    let mut a = s.begin_bundle(b.job_id, b.descriptor_hash, b.prover, 1 << 30).unwrap();
    let mut other = s.begin_bundle(b.job_id, b.descriptor_hash, b.prover, 1 << 30).unwrap();
    let f = faults::install();
    let s2 = Arc::clone(&s);
    let (tx, rx) = std::sync::mpsc::channel();
    // While `a`'s piece is admitted but not yet written, `other` asks for the same amount.
    f.hook(Op::Write, "/w.bin", move || {
        let head = s2.headroom().unwrap();
        let res = other.write_w(&vec![1u8; N as usize]);
        tx.send((head, res)).unwrap();
    });
    a.write_w(&vec![7u8; N as usize]).unwrap();
    drop(f);
    let (head, res) = rx.recv().unwrap();
    assert!(head < N, "headroom during the pending write: {head}");
    assert!(matches!(res, Err(StoreError::RetentionFull(FullReason::FreeSpaceFloor))), "{res:?}");
    drop(a);
    assert_accounting(&s);
}
