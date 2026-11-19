//! The review fixes that need no fault injection: open never creates (F2), open classifies every
//! failure as unavailable (F3), symlinks are never followed (F4), swapped versions and forged pins
//! are caught (F6), eviction races (F8), verify checks the ELF (F9), sealing and re-versioning W,
//! and eviction on admission.

mod common;

use std::fs;
use std::io::Read;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use alloy_primitives::B256;
use common::*;
use zkminer_witness::bundle::{BundleV1, GuestExit, Po2Result};
use zkminer_witness_store::*;

fn unavailable(e: StoreError) -> UnavailableKind {
    match e {
        StoreError::Unavailable { kind, .. } => kind,
        other => panic!("expected Unavailable, got {other:?}"),
    }
}

fn defect(e: StoreError) -> Defect {
    match e {
        StoreError::Corrupt { defect, .. } => defect,
        other => panic!("expected Corrupt, got {other:?}"),
    }
}

fn terminal(job_id: B256) -> TerminalProof {
    TerminalProof { job_id, state: TerminalState::Fulfilled, read_at_block: 99 }
}

fn read_all(mut f: fs::File) -> Vec<u8> {
    let mut v = Vec::new();
    f.read_to_end(&mut v).unwrap();
    v
}

/// F2: a store whose disk is not mounted leaves an empty mount point at the configured path. Open
/// must call that unavailable (so every lock is kept), never an empty store whose locks look
/// missing, and must write nothing into it.
#[test]
fn an_unmounted_mount_point_is_unavailable_and_untouched() {
    let base = tmpdir();
    let disk = base.path().join("disk");
    fs::create_dir(&disk).unwrap();
    let s = open(&disk);
    let r = put_and_publish(&s, &Spec::new(job(5)), &witness(5, 1000));
    s.pin(&pin_rec(&s, &r)).unwrap();
    let want = expected(&disk);
    drop(s);

    // Boot with the disk not mounted: the configured path is a bare directory.
    let mnt = base.path().join("mnt");
    fs::create_dir(&mnt).unwrap();
    assert_eq!(unavailable(Store::open(&mnt, &want, opts()).unwrap_err()), UnavailableKind::IdentityMissing);
    let dedicated = StoreOptions { require_dedicated_mount: true, ..opts() };
    assert_eq!(unavailable(Store::open(&mnt, &want, dedicated).unwrap_err()), UnavailableKind::NotMounted);
    let init_dedicated = StoreIdentityInit { require_dedicated_mount: true, ..init_id() };
    assert_eq!(unavailable(Store::init(&mnt, &init_dedicated).unwrap_err()), UnavailableKind::NotMounted);
    assert_eq!(fs::read_dir(&mnt).unwrap().count(), 0, "nothing written into the mount point");

    // A store that is a plain directory (not its own filesystem) is refused when a dedicated mount
    // is required, and accepted otherwise.
    assert_eq!(unavailable(Store::open(&disk, &want, dedicated).unwrap_err()), UnavailableKind::NotMounted);
    let s = Store::open(&disk, &want, opts()).unwrap();
    s.verify(&r, &desc_hash, &image_id).unwrap();
    assert_eq!(s.pins().len(), 1);
}

/// F3: every way the top level can be wrong is `Unavailable` (BadLayout or an I/O kind) from
/// `open`, never Corrupt, Missing or RetentionFull; a repaired store opens again.
#[test]
fn open_classifies_every_bad_top_level_entry_as_unavailable() {
    let d = tmpdir();
    let root = d.path();
    let s = open(root);
    let r = put_and_publish(&s, &Spec::new(job(1)), &witness(1, 500));
    drop(s);
    let open_err = || Store::open(root, &expected(root), opts()).unwrap_err();
    let p = |n: &str| root.join(n);

    // next_version: a directory or a symlink is a bad layout; garbage is rewritten.
    let nv = p("next_version");
    let saved = fs::read(&nv).unwrap();
    fs::remove_file(&nv).unwrap();
    fs::create_dir(&nv).unwrap();
    assert_eq!(unavailable(open_err()), UnavailableKind::BadLayout);
    fs::remove_dir(&nv).unwrap();
    std::os::unix::fs::symlink(root.join("identity.json"), &nv).unwrap();
    assert_eq!(unavailable(open_err()), UnavailableKind::BadLayout);
    fs::remove_file(&nv).unwrap();
    fs::write(&nv, vec![b'9'; 5000]).unwrap();
    let s = Store::open(root, &expected(root), opts()).unwrap();
    assert!(s.open_report().version_counter_recovered);
    drop(s);
    fs::write(&nv, &saved).unwrap();

    // .lock: a symlink, a directory, a FIFO, or absent beside an identity.
    let lock = p(".lock");
    fs::remove_file(&lock).unwrap();
    std::os::unix::fs::symlink("/nonexistent-target", &lock).unwrap();
    assert_eq!(unavailable(open_err()), UnavailableKind::BadLayout);
    assert!(!Path::new("/nonexistent-target").exists());
    fs::remove_file(&lock).unwrap();
    fs::create_dir(&lock).unwrap();
    assert_eq!(unavailable(open_err()), UnavailableKind::BadLayout);
    fs::remove_dir(&lock).unwrap();
    let c = std::ffi::CString::new(lock.to_str().unwrap()).unwrap();
    // SAFETY: a valid path.
    assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
    assert_eq!(unavailable(open_err()), UnavailableKind::BadLayout);
    fs::remove_file(&lock).unwrap();
    assert_eq!(unavailable(open_err()), UnavailableKind::BadLayout);
    fs::write(&lock, b"").unwrap();

    // identity.json a directory.
    let id = p("identity.json");
    let id_saved = fs::read(&id).unwrap();
    make_writable(&id);
    fs::remove_file(&id).unwrap();
    fs::create_dir(&id).unwrap();
    assert_eq!(unavailable(Store::open(root, &expected_from(&id_saved), opts()).unwrap_err()), UnavailableKind::IdentityInvalid);
    fs::remove_dir(&id).unwrap();
    fs::write(&id, &id_saved).unwrap();

    // Areas: absent, a file, a symlink.
    for area in ["tmp", "bundles", "pins", "elfs", "verdicts"] {
        let a = p(area);
        let aside = root.join(format!("{area}.aside"));
        fs::rename(&a, &aside).unwrap();
        assert_eq!(unavailable(open_err()), UnavailableKind::BadLayout, "{area} absent");
        fs::write(&a, b"x").unwrap();
        assert_eq!(unavailable(open_err()), UnavailableKind::BadLayout, "{area} a file");
        fs::remove_file(&a).unwrap();
        std::os::unix::fs::symlink(&aside, &a).unwrap();
        assert_eq!(unavailable(open_err()), UnavailableKind::BadLayout, "{area} a symlink");
        fs::remove_file(&a).unwrap();
        fs::rename(&aside, &a).unwrap();
    }

    // Read errors in the scan: an unreadable record or directory is an I/O kind, not Corrupt.
    let bj = vdir(root, &r).join("bundle.json");
    fs::set_permissions(&bj, fs::Permissions::from_mode(0o000)).unwrap();
    if fs::read(&bj).is_err() {
        assert_eq!(unavailable(open_err()), UnavailableKind::Io { errno: Some(libc::EACCES) });
    }
    fs::set_permissions(&bj, fs::Permissions::from_mode(0o444)).unwrap();
    let jd = root.join("bundles").join(hex::encode(r.job_id));
    fs::set_permissions(&jd, fs::Permissions::from_mode(0o000)).unwrap();
    if fs::read_dir(&jd).is_err() {
        assert_eq!(unavailable(open_err()), UnavailableKind::Io { errno: Some(libc::EACCES) });
    }
    fs::set_permissions(&jd, fs::Permissions::from_mode(0o700)).unwrap();

    let s = Store::open(root, &expected(root), opts()).unwrap();
    s.verify(&r, &desc_hash, &image_id).unwrap();
    assert_accounting(&s);
}

fn expected_from(identity_json: &[u8]) -> ExpectedIdentity {
    let v: serde_json::Value = serde_json::from_slice(identity_json).unwrap();
    ExpectedIdentity {
        chain_id: CHAIN,
        router: router(),
        prover: prover(),
        store_uuid: v["store_uuid"].as_str().unwrap().into(),
    }
}

#[derive(Debug, Clone, Copy)]
enum Level {
    Job,
    Desc,
    Prover,
    Version,
}

/// F4: a symlink at any level of a bundle path is never followed — not by reads, the scan,
/// eviction, deletion, publishing or pruning — and nothing outside the root is ever touched.
#[test]
fn symlinks_at_every_level_are_never_followed() {
    for level in [Level::Job, Level::Desc, Level::Prover, Level::Version] {
        let base = tmpdir();
        let root = base.path().join("store");
        fs::create_dir(&root).unwrap();
        let s = open(&root);
        let spec = Spec::new(job(6));
        let v1 = put_and_publish(&s, &Spec { block: 1, ..Spec::new(job(6)) }, &witness(6, 2000));
        let v2 = put_and_publish(&s, &Spec { block: 2, ..Spec::new(job(6)) }, &witness(7, 2000));
        // A sibling key in the same job (another descriptor), and another job: both evictable.
        let sib = put_and_publish(&s, &Spec { desc: 1, block: 3, ..Spec::new(job(6)) }, &witness(8, 2000));
        let other = put_and_publish(&s, &Spec { block: 4, ..Spec::new(job(9)) }, &witness(9, 2000));
        let recs = (pin_rec(&s, &v1), pin_rec(&s, &v2));
        let w1 = witness(6, 2000);
        let b = spec.bundle(&w1);

        // Move the real directory at `level` outside the root and leave a symlink in its place.
        let vd = vdir(&root, &v1);
        let at_level: PathBuf = match level {
            Level::Job => vd.ancestors().nth(3).unwrap().to_path_buf(),
            Level::Desc => vd.ancestors().nth(2).unwrap().to_path_buf(),
            Level::Prover => vd.ancestors().nth(1).unwrap().to_path_buf(),
            Level::Version => vd.clone(),
        };
        let outside = base.path().join("outside");
        fs::rename(&at_level, &outside).unwrap();
        std::os::unix::fs::symlink(&outside, &at_level).unwrap();
        let before = snapshot(&outside);
        let bad = |e: StoreError| assert_eq!(unavailable(e), UnavailableKind::BadLayout, "{level:?}");

        // Reads through it.
        bad(s.read(&v1, &desc_hash).unwrap_err());
        bad(s.open_w(&v1).unwrap_err());
        bad(s.verify(&v1, &desc_hash, &image_id).unwrap_err());
        bad(s.pin_record(&v1, 1).unwrap_err());
        bad(s.pin(&recs.0).unwrap_err());
        bad(s.begin_version_from(&v1).unwrap_err());
        match level {
            Level::Version => {
                // The other version of the key is still served; listing the key names the link.
                s.verify(&v2, &desc_hash, &image_id).unwrap();
                s.pin(&recs.1).unwrap();
                bad(s.latest(v1.job_id, v1.descriptor_hash, v1.prover).unwrap_err());
            }
            _ => {
                bad(s.read(&v2, &desc_hash).unwrap_err());
                bad(s.latest(v1.job_id, v1.descriptor_hash, v1.prover).unwrap_err());
            }
        }
        // Publishing into it (a symlinked version leaves its key directory real: a new version
        // publishes beside it).
        let mut wr = s.begin_bundle(b.job_id, b.descriptor_hash, b.prover, 1 << 20).unwrap();
        wr.write_w(&w1).unwrap();
        let v = wr.version();
        let res = wr.finish(&at(&b, v), &desc_hash);
        match level {
            Level::Version => assert_eq!(res.unwrap().version, v),
            _ => bad(res.unwrap_err()),
        }
        assert_eq!(tmp_entries(&root), 0);
        assert_eq!(snapshot(&outside), before, "{level:?}: publishing touched the outside");

        // Eviction with an index from before the link: the versions behind it are refused, not
        // followed.
        s.mark_recovery_scan_complete();
        let first = |m: &BundleMeta| if m.bundle == v1 { 0 } else { 1 + m.bundle.version as u64 };
        bad(s.evict_to(u64::MAX, &first).unwrap_err());
        assert_eq!(snapshot(&outside), before, "{level:?}: eviction touched the outside");

        // The scan reports the link and indexes nothing behind it.
        let scan = s.scan().unwrap();
        assert!(scan.anomalies.iter().any(|a| a.path == at_level && a.kind == AnomalyKind::UnexpectedEntry), "{level:?}");
        assert!(scan.bundles.iter().all(|m| m.bundle != v1), "{level:?}");
        // Eviction (and pruning of emptied parents) now runs around it.
        let rep = s.evict_to(u64::MAX, &|m| m.bundle.version as u64).unwrap();
        assert!(rep.evicted.contains(&other), "{level:?}");
        match level {
            Level::Job => assert!(!rep.evicted.contains(&sib)),
            _ => assert!(rep.evicted.contains(&sib), "{level:?}"),
        }
        assert_eq!(snapshot(&outside), before, "{level:?}: eviction touched the outside");

        // Deleting the job: a symlinked job directory is refused; below it, the link itself goes
        // with the job, never its target.
        s.unpin(v2.job_id, v2.descriptor_hash, v2.prover).unwrap();
        match level {
            Level::Job => bad(s.delete_job(job(6), &terminal(job(6))).unwrap_err()),
            _ => {
                s.delete_job(job(6), &terminal(job(6))).unwrap();
            }
        }
        assert_eq!(snapshot(&outside), before, "{level:?}: deletion touched the outside");
        assert_eq!(tmp_entries(&root), 0);
        s.scan().unwrap();
        assert_accounting(&s);
    }
}

/// F6: versions swapped on disk, or a pinned version's record rewritten, are corrupt.
#[test]
fn swapped_versions_and_forged_pinned_records_are_corrupt() {
    let d = tmpdir();
    let s = open(d.path());
    let spec = Spec::new(job(8));
    let (wa, wb) = (witness(8, 3000), witness(9, 4000));
    let ra = put_and_publish(&s, &spec, &wa);
    let rb = put_and_publish(&s, &spec, &wb);
    s.pin(&pin_rec(&s, &rb)).unwrap();
    let (pa, pb) = (vdir(d.path(), &ra), vdir(d.path(), &rb));

    // Whole directories swapped.
    let tmpx = pa.with_file_name("swap");
    fs::rename(&pa, &tmpx).unwrap();
    fs::rename(&pb, &pa).unwrap();
    fs::rename(&tmpx, &pb).unwrap();
    for r in [ra, rb] {
        assert_eq!(defect(s.read(&r, &desc_hash).unwrap_err()), Defect::VersionMismatch);
        assert_eq!(defect(s.open_w(&r).unwrap_err()), Defect::VersionMismatch);
        assert_eq!(defect(s.verify(&r, &desc_hash, &image_id).unwrap_err()), Defect::VersionMismatch);
    }
    let scan = s.scan().unwrap();
    assert!(scan.bundles.iter().all(|m| m.record == Err(Defect::VersionMismatch)));
    fs::rename(&pa, &tmpx).unwrap();
    fs::rename(&pb, &pa).unwrap();
    fs::rename(&tmpx, &pb).unwrap();
    s.scan().unwrap();
    assert_eq!(read_all(s.open_w(&rb).unwrap()), wb);

    // Only bundle.json swapped: its version names the other directory.
    let jb = pb.join("bundle.json");
    let saved = fs::read(&jb).unwrap();
    make_writable(&jb);
    fs::write(&jb, fs::read(pa.join("bundle.json")).unwrap()).unwrap();
    assert_eq!(defect(s.read(&rb, &desc_hash).unwrap_err()), Defect::VersionMismatch);

    // A record rewritten in place, consistent with its directory but not with its pin.
    let mut forged: BundleV1 = serde_json::from_slice(&saved).unwrap();
    forged.created_at_block += 1;
    fs::write(&jb, serde_json::to_vec_pretty(&forged).unwrap()).unwrap();
    assert_eq!(defect(s.read(&rb, &desc_hash).unwrap_err()), Defect::PinMismatch);
    assert_eq!(defect(s.open_w(&rb).unwrap_err()), Defect::PinMismatch);
    assert!(s.scan().unwrap().bundles.iter().any(|m| m.bundle == rb && m.record == Err(Defect::PinMismatch)));
    // The same rewrite of an unpinned version reads (no pin to compare with).
    let ja = pa.join("bundle.json");
    make_writable(&ja);
    let mut fa: BundleV1 = serde_json::from_slice(&fs::read(&ja).unwrap()).unwrap();
    fa.created_at_block += 1;
    fs::write(&ja, serde_json::to_vec_pretty(&fa).unwrap()).unwrap();
    assert_eq!(s.read(&ra, &desc_hash).unwrap(), fa);
    // Restored, the pinned version reads again.
    fs::write(&jb, &saved).unwrap();
    s.scan().unwrap();
    s.verify(&rb, &desc_hash, &image_id).unwrap();
}

/// F9: verify reads and checks the ELF as well.
#[test]
fn verify_checks_the_elf() {
    let d = tmpdir();
    let s = open(d.path());
    let r = put_and_publish(&s, &Spec::new(job(11)), &witness(11, 700));
    let ep = d.path().join("elfs").join(hex::encode(sha256(&elf(1))));
    let saved = fs::read(&ep).unwrap();
    fs::remove_file(&ep).unwrap();
    assert_eq!(defect(s.verify(&r, &desc_hash, &image_id).unwrap_err()), Defect::ElfMissing);
    s.read(&r, &desc_hash).unwrap();
    s.open_w(&r).unwrap();
    fs::write(&ep, b"another elf").unwrap();
    assert_eq!(defect(s.verify(&r, &desc_hash, &image_id).unwrap_err()), Defect::ImageId);
    fs::write(&ep, &saved).unwrap();
    s.verify(&r, &desc_hash, &image_id).unwrap();
    // The ELF area itself gone: unavailable, not a bad bundle.
    fs::rename(d.path().join("elfs"), d.path().join("elfs.aside")).unwrap();
    assert_eq!(unavailable(s.verify(&r, &desc_hash, &image_id).unwrap_err()), UnavailableKind::NotFound);
}

/// F8 and the eviction races that can be driven through `value_fn` (it runs between ranking and
/// removal, without the store lock): a pin taken then is honoured, a delete then is absorbed, and
/// a version gone from disk is dropped from the index as already removed.
#[test]
fn eviction_races_with_pin_delete_and_external_removal() {
    let d = tmpdir();
    let s = std::sync::Arc::new(open(d.path()));
    let w = witness(1, 1500);
    let a = put_and_publish(&s, &Spec { block: 1, ..Spec::new(job(40)) }, &w);
    let b = put_and_publish(&s, &Spec { block: 2, ..Spec::new(job(41)) }, &w);
    let c = put_and_publish(&s, &Spec { block: 3, ..Spec::new(job(42)) }, &w);
    s.mark_recovery_scan_complete();

    // Pin `a` while eviction ranks it lowest.
    let rec = pin_rec(&s, &a);
    let s2 = std::sync::Arc::clone(&s);
    let pinned = std::cell::Cell::new(false);
    let value = |m: &BundleMeta| {
        if !pinned.replace(true) {
            s2.pin(&rec).unwrap();
        }
        m.bundle.version as u64
    };
    let rep = s.evict_to(s.headroom().unwrap() + 1, &value).unwrap();
    assert!(!rep.evicted.contains(&a), "a pin taken during ranking is honoured");
    assert_eq!(rep.evicted, vec![b]);
    s.verify(&a, &desc_hash, &image_id).unwrap();

    // Delete `c`'s job while eviction ranks it.
    let b2 = put_and_publish(&s, &Spec { block: 5, ..Spec::new(job(43)) }, &w);
    let deleted = std::cell::Cell::new(false);
    let value = |m: &BundleMeta| {
        if !deleted.replace(true) {
            s2.delete_job(job(42), &terminal(job(42))).unwrap();
        }
        m.bundle.version as u64
    };
    let rep = s.evict_to(u64::MAX, &value).unwrap();
    assert_eq!(rep.evicted, vec![b2], "the deleted version is not evicted twice");
    assert!(s.read(&c, &desc_hash).unwrap_err().is_missing());

    // A version removed behind the store's back is dropped from the index as already removed.
    let e = put_and_publish(&s, &Spec { block: 6, ..Spec::new(job(44)) }, &w);
    let f = put_and_publish(&s, &Spec { block: 7, ..Spec::new(job(45)) }, &w);
    fs::rename(vdir(d.path(), &e), d.path().join("gone")).unwrap();
    let rep = s.evict_to(u64::MAX, &|m| m.bundle.version as u64).unwrap();
    assert_eq!(rep.evicted, vec![f]);
    assert!(s.scan().unwrap().bundles.iter().all(|m| m.bundle == a));
    fs::remove_dir_all(d.path().join("gone")).unwrap();
    assert_accounting(&s);
}

/// Execute before publish (§5.1 step 2): W is sealed and handed out read-only, then published
/// unchanged.
#[test]
fn seal_w_hands_out_the_persisted_witness_before_publication() {
    let d = tmpdir();
    let s = open(d.path());
    drop(s.put_elf(sha256(&elf(1)), &elf(1), &image_id).unwrap());
    let w = witness(12, 300_000);
    let b = Spec::new(job(12)).bundle(&w);
    let mut wr = s.begin_bundle(b.job_id, b.descriptor_hash, b.prover, 1 << 20).unwrap();
    wr.write_w(&w[..100_000]).unwrap();
    wr.write_w(&w[100_000..]).unwrap();
    let fd = wr.seal_w().unwrap();
    // SAFETY: F_GETFL on a valid fd.
    let flags = unsafe { libc::fcntl(std::os::fd::AsRawFd::as_raw_fd(&fd), libc::F_GETFL) };
    assert_eq!(flags & libc::O_ACCMODE, libc::O_RDONLY);
    assert_eq!(flags & libc::O_NONBLOCK, 0);
    assert_eq!(fd.metadata().unwrap().permissions().mode() & 0o777, 0o444);
    assert_eq!(read_all(fd), w);
    assert_eq!(read_all(wr.seal_w().unwrap()), w, "a second seal hands out a fresh fd");
    match wr.write_w(b"more").unwrap_err() {
        StoreError::Rejected(Reject::Sealed) => {}
        e => panic!("{e:?}"),
    }
    let keep = wr.seal_w().unwrap();
    let v = wr.version();
    let r = wr.finish(&at(&b, v), &desc_hash).unwrap();
    assert_eq!(r.version, v);
    assert_eq!(s.verify(&r, &desc_hash, &image_id).unwrap(), at(&b, v));
    assert_eq!(read_all(keep), w, "the execute fd stays valid across publication");
    assert_eq!(tmp_entries(d.path()), 0);
    assert_accounting(&s);
}

/// A new version from the retained W (§15.2 missing po2, §15.3 JournalDiverged): shared by a hard
/// link, verified before use, independent of its source afterwards.
#[test]
fn begin_version_from_reuses_the_retained_witness() {
    let d = tmpdir();
    let s = open(d.path());
    let w = witness(13, 50_000);
    let r1 = put_and_publish(&s, &Spec::new(job(13)), &w);
    let b1 = s.read(&r1, &desc_hash).unwrap();

    let mut wr = s.begin_version_from(&r1).unwrap();
    assert!(wr.version() > r1.version);
    assert_eq!(wr.written(), w.len() as u64);
    match wr.write_w(b"x").unwrap_err() {
        StoreError::Rejected(Reject::Sealed) => {}
        e => panic!("{e:?}"),
    }
    assert_eq!(read_all(wr.seal_w().unwrap()), w);
    // Executed at a po2 the bundle lacked: the new record adds it.
    let mut b2 = at(&b1, wr.version());
    let j = b"po2 21 journal".to_vec();
    b2.po2_results.push(Po2Result {
        po2: 21,
        journal_hex: hex::encode(&j),
        journal_sha256: sha256(&j),
        cycles: 1,
        exit: GuestExit::Halted(0),
        segment_bytes: 1,
    });
    let r2 = wr.finish(&b2, &desc_hash).unwrap();
    assert_eq!(s.verify(&r2, &desc_hash, &image_id).unwrap(), b2);
    let ino = |r: &BundleRef| fs::metadata(vdir(d.path(), r).join("w.bin")).unwrap().ino();
    assert_eq!(ino(&r1), ino(&r2), "W is shared, not copied");
    assert_accounting(&s);

    // A record that does not match the shared W is refused.
    let wr = s.begin_version_from(&r2).unwrap();
    let mut bad = at(&b1, wr.version());
    bad.w_len += 1;
    match wr.finish(&bad, &desc_hash).unwrap_err() {
        StoreError::Rejected(Reject::Record(Defect::WLength)) => {}
        e => panic!("{e:?}"),
    }

    // The source can be evicted; the new version keeps W.
    s.mark_recovery_scan_complete();
    s.pin(&pin_rec(&s, &r2)).unwrap();
    let rep = s.evict_to(u64::MAX, &|_| 0).unwrap();
    assert_eq!(rep.evicted, vec![r1]);
    assert_eq!(read_all(s.open_w(&r2).unwrap()), w);

    // From an absent version: Missing. From a corrupt W: Corrupt, nothing published.
    assert!(s.begin_version_from(&r1).unwrap_err().is_missing());
    let p = vdir(d.path(), &r2).join("w.bin");
    make_writable(&p);
    let mut bytes = fs::read(&p).unwrap();
    bytes[10] ^= 1;
    fs::write(&p, &bytes).unwrap();
    assert_eq!(defect(s.begin_version_from(&r2).unwrap_err()), Defect::WHash);
    assert_eq!(tmp_entries(d.path()), 0);
    assert_accounting(&s);
}

/// Admission: unpinned versions count against the quota until evicted; `begin_bundle_evicting`
/// evicts them (lowest value first) once eviction is enabled.
#[test]
fn begin_bundle_evicting_makes_room_from_the_cache() {
    let d = tmpdir();
    drop(open(d.path()));
    let s = open_with(d.path(), StoreOptions { quota_bytes: 40_000, ..opts() });
    let w = witness(1, 9_000);
    let olds: Vec<BundleRef> =
        (0..3u8).map(|i| put_and_publish(&s, &Spec { block: i as u64, ..Spec::new(job(50 + i)) }, &w)).collect();
    s.pin(&pin_rec(&s, &olds[2])).unwrap();
    let spec = Spec::new(job(60));
    let b = spec.bundle(&w);
    let value = |m: &BundleMeta| m.record.as_ref().map_or(0, |r| r.created_at_block);

    // Without eviction the cache fills the quota.
    let mut wr = s.begin_bundle(b.job_id, b.descriptor_hash, b.prover, 9_000).unwrap();
    assert!(matches!(wr.write_w(&w).unwrap_err(), StoreError::RetentionFull(FullReason::QuotaBytes)));
    drop(wr);
    // Before the recovery scan, nothing is evicted.
    let mut wr = s.begin_bundle_evicting(b.job_id, b.descriptor_hash, b.prover, 9_000, &value).unwrap();
    assert!(wr.write_w(&w).unwrap_err().is_full());
    drop(wr);
    assert_eq!(s.scan().unwrap().bundles.len(), 3);
    s.mark_recovery_scan_complete();
    let mut wr = s.begin_bundle_evicting(b.job_id, b.descriptor_hash, b.prover, 9_000, &value).unwrap();
    wr.write_w(&w).unwrap();
    let v = wr.version();
    let r = wr.finish(&at(&b, v), &desc_hash).unwrap();
    let left: Vec<BundleRef> = s.scan().unwrap().bundles.iter().map(|m| m.bundle).collect();
    assert_eq!(left, vec![olds[2], r], "the unpinned cache went, the pinned version stayed");
    assert_accounting(&s);
}
