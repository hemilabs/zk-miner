mod common;

use std::fs;
use std::io::Read;
use std::os::unix::fs::PermissionsExt;

use alloy_primitives::{Address, B256};
use common::*;
use zkminer_witness::bundle::PinRecord;
use zkminer_witness::verdict::{SkipReason, VerdictRecord};
use zkminer_witness_store::*;

fn terminal(job_id: B256) -> TerminalProof {
    TerminalProof { job_id, state: TerminalState::Fulfilled, read_at_block: 99 }
}

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

fn rejected(e: StoreError) -> Reject {
    match e {
        StoreError::Rejected(r) => r,
        other => panic!("expected Rejected, got {other:?}"),
    }
}

#[test]
fn types_are_send_and_sync() {
    fn send_sync<T: Send + Sync>() {}
    fn send<T: Send>() {}
    send_sync::<Store>();
    send_sync::<ElfHold>();
    send::<BundleWriter>();
    send_sync::<StoreError>();
}

#[test]
fn init_creates_the_identity_and_open_requires_it() {
    let d = tmpdir();
    let id = Store::init(d.path(), &init_id()).unwrap();
    assert_eq!((id.chain_id, id.router, id.prover), (CHAIN, router(), prover()));
    assert_eq!(id.store_uuid.len(), 36);
    assert_eq!(&id.store_uuid[14..15], "4", "version-4 UUID");
    for area in ["tmp", "bundles", "pins", "elfs", "verdicts"] {
        assert!(d.path().join(area).is_dir(), "{area}");
    }
    assert_eq!(fs::read_to_string(d.path().join("next_version")).unwrap(), "1");
    let want = ExpectedIdentity { chain_id: CHAIN, router: router(), prover: prover(), store_uuid: id.store_uuid.clone() };
    let s = Store::open(d.path(), &want, opts()).unwrap();
    assert_eq!(s.identity(), &id);
    assert_eq!(s.open_report(), OpenReport::default());
    assert_accounting(&s);
    // init never touches a store, open or not.
    assert_eq!(rejected(Store::init(d.path(), &init_id()).unwrap_err()), Reject::AlreadyInitialised);
    drop(s);
    assert_eq!(rejected(Store::init(d.path(), &init_id()).unwrap_err()), Reject::AlreadyInitialised);
    assert_eq!(uuid_of(d.path()), id.store_uuid);

    // A directory with anything else in it is refused.
    let e = tmpdir();
    fs::write(e.path().join("stray"), b"x").unwrap();
    assert_eq!(rejected(Store::init(e.path(), &init_id()).unwrap_err()), Reject::NotEmpty);
    assert_eq!(fs::read_dir(e.path()).unwrap().count(), 1, "nothing written, not even .lock");
    let f = tmpdir();
    fs::create_dir_all(f.path().join("bundles/x")).unwrap();
    assert_eq!(rejected(Store::init(f.path(), &init_id()).unwrap_err()), Reject::NotEmpty);
    // What an interrupted init leaves (no identity yet) is finished by running it again.
    let g = tmpdir();
    for a in ["tmp", "bundles", "pins"] {
        fs::create_dir(g.path().join(a)).unwrap();
    }
    fs::write(g.path().join(".lock"), b"").unwrap();
    fs::write(g.path().join("next_version"), b"1").unwrap();
    fs::write(g.path().join("tmp/0123.part"), b"{").unwrap();
    fs::create_dir(g.path().join("lost+found")).unwrap();
    let gid = Store::init(g.path(), &init_id()).unwrap();
    assert_eq!(tmp_entries(g.path()), 0);
    let s = Store::open(g.path(), &expected(g.path()), opts()).unwrap();
    assert_eq!(s.identity(), &gid);
}

#[test]
fn identity_mismatch_and_missing_are_unavailable_and_open_never_creates() {
    let d = tmpdir();
    drop(open(d.path()));
    let base = expected(d.path());
    let wrong = [
        ExpectedIdentity { chain_id: 1, ..base.clone() },
        ExpectedIdentity { router: Address::repeat_byte(0x99), ..base.clone() },
        ExpectedIdentity { prover: Address::repeat_byte(0x99), ..base.clone() },
        ExpectedIdentity { store_uuid: "00000000-0000-4000-8000-000000000000".into(), ..base.clone() },
    ];
    for w in wrong {
        let e = Store::open(d.path(), &w, opts()).unwrap_err();
        assert_eq!(unavailable(e), UnavailableKind::IdentityMismatch, "{w:?}");
    }

    // An unreadable identity record.
    let id = d.path().join("identity.json");
    make_writable(&id);
    fs::write(&id, b"{ not json").unwrap();
    assert_eq!(unavailable(Store::open(d.path(), &base, opts()).unwrap_err()), UnavailableKind::IdentityInvalid);

    // An empty directory (an unmounted disk's mount point) is never initialised by open, and
    // nothing is written into it — not even `.lock`.
    let e = tmpdir();
    let want = ExpectedIdentity { store_uuid: base.store_uuid.clone(), ..base.clone() };
    assert_eq!(unavailable(Store::open(e.path(), &want, opts()).unwrap_err()), UnavailableKind::IdentityMissing);
    assert_eq!(fs::read_dir(e.path()).unwrap().count(), 0);
    fs::create_dir(e.path().join("lost+found")).unwrap();
    assert_eq!(unavailable(Store::open(e.path(), &want, opts()).unwrap_err()), UnavailableKind::IdentityMissing);
    assert_eq!(fs::read_dir(e.path()).unwrap().count(), 1);

    // An absent root is never created.
    let gone = e.path().join("absent");
    assert_eq!(unavailable(Store::open(&gone, &want, opts()).unwrap_err()), UnavailableKind::RootAbsent);
    assert_eq!(unavailable(Store::init(&gone, &init_id()).unwrap_err()), UnavailableKind::RootAbsent);
    assert!(!gone.exists());
}

#[test]
fn second_open_is_refused_while_the_lock_is_held() {
    let d = tmpdir();
    let a = open(d.path());
    let e = Store::open(d.path(), &expected(d.path()), opts()).unwrap_err();
    assert_eq!(unavailable(e), UnavailableKind::LockHeld);

    // A live writer keeps the lock after its store is dropped.
    let w = a.begin_bundle(job(1), B256::ZERO, prover(), 100).unwrap();
    drop(a);
    assert_eq!(unavailable(Store::open(d.path(), &expected(d.path()), opts()).unwrap_err()), UnavailableKind::LockHeld);
    drop(w);
    let b = open(d.path());
    assert_eq!(b.open_report().tmp_entries_removed, 0, "the dropped writer cleaned up after itself");
}

#[test]
fn refuses_unsupported_filesystems_symlinks_and_files_as_root() {
    let shm = tempfile::Builder::new().prefix("wstore-").tempdir_in("/dev/shm").unwrap();
    let tmpfs = UnavailableKind::UnsupportedFilesystem { f_type: 0x0102_1994 };
    assert_eq!(unavailable(Store::init(shm.path(), &init_id()).unwrap_err()), tmpfs);
    assert_eq!(fs::read_dir(shm.path()).unwrap().count(), 0, "nothing written on tmpfs");
    // The explicit override accepts it (for tests and exotic hosts), and only with the override.
    let any = StoreIdentityInit { allow_any_filesystem: true, ..init_id() };
    Store::init(shm.path(), &any).unwrap();
    let want = expected(shm.path());
    assert_eq!(unavailable(Store::open(shm.path(), &want, opts()).unwrap_err()), tmpfs);
    drop(Store::open(shm.path(), &want, StoreOptions { allow_any_filesystem: true, ..opts() }).unwrap());

    let d = tmpdir();
    let real = d.path().join("real");
    fs::create_dir(&real).unwrap();
    let link = d.path().join("link");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    assert_eq!(unavailable(Store::init(&link, &init_id()).unwrap_err()), UnavailableKind::SymlinkRoot);
    assert_eq!(fs::read_dir(&real).unwrap().count(), 0, "nothing written through the symlink");
    Store::init(&real, &init_id()).unwrap();
    assert_eq!(unavailable(Store::open(&link, &expected(&real), opts()).unwrap_err()), UnavailableKind::SymlinkRoot);

    let file = d.path().join("file");
    fs::write(&file, b"x").unwrap();
    assert_eq!(unavailable(Store::open(&file, &expected(&real), opts()).unwrap_err()), UnavailableKind::NotADirectory);

    // An area replaced by a symlink makes the store unavailable rather than being followed.
    let root = d.path().join("store");
    fs::create_dir(&root).unwrap();
    drop(open(&root));
    fs::remove_dir(root.join("pins")).unwrap();
    std::os::unix::fs::symlink(&real, root.join("pins")).unwrap();
    assert_eq!(unavailable(Store::open(&root, &expected(&root), opts()).unwrap_err()), UnavailableKind::BadLayout);
}

#[test]
fn publish_read_and_open_w_round_trip() {
    let d = tmpdir();
    let s = open(d.path());
    let w = witness(1, 3 * 1024 * 1024 + 17);
    for prefix in [true, false] {
        let spec = Spec { prefix, ..Spec::new(job(if prefix { 1 } else { 2 })) };
        let b = spec.bundle(&w);
        let r = put_and_publish(&s, &spec, &w);
        assert_eq!(r.key(), BundleKey::of_bundle(&b));
        let b = at(&b, r.version);
        assert_eq!(s.read(&r, &desc_hash).unwrap(), b);
        assert_eq!(s.verify(&r, &desc_hash, &image_id).unwrap(), b);
        let mut f = s.open_w(&r).unwrap();
        // SAFETY: F_GETFL on a valid fd.
        let flags = unsafe { libc::fcntl(std::os::fd::AsRawFd::as_raw_fd(&f), libc::F_GETFL) };
        assert_eq!(flags & libc::O_ACCMODE, libc::O_RDONLY, "read-only");
        assert_eq!(flags & libc::O_NONBLOCK, 0, "no O_NONBLOCK carried to the worker");
        let mut back = Vec::new();
        f.read_to_end(&mut back).unwrap();
        assert_eq!(back, w, "the fd is rewound and serves W");
        assert!(fs::OpenOptions::new().write(true).open(vdir(d.path(), &r).join("w.bin")).is_err());
        assert_eq!(s.latest(r.job_id, r.descriptor_hash, r.prover).unwrap(), r);
    }
    // Published files are read-only; a new result is a new version.
    let spec = Spec::new(job(1));
    let r1 = s.latest(job(1), spec.bundle(&w).descriptor_hash, prover()).unwrap();
    let w2 = witness(2, 10);
    let r2 = publish(&s, &spec.bundle(&w2), &w2, 3).unwrap();
    assert!(r2.version > r1.version);
    assert_eq!(s.versions(r1.job_id, r1.descriptor_hash, r1.prover).unwrap(), vec![r1.version, r2.version]);
    assert_eq!(s.latest(r1.job_id, r1.descriptor_hash, r1.prover).unwrap(), r2);
    assert_eq!(s.read(&r1, &desc_hash).unwrap().w_len, w.len() as u64, "the old version is untouched");
    assert_eq!(tmp_entries(d.path()), 0);
    assert_accounting(&s);

    // Everything survives a reopen.
    drop(s);
    let s = open(d.path());
    assert_eq!(s.verify(&r2, &desc_hash, &image_id).unwrap(), at(&spec.bundle(&w2), r2.version));
    assert_accounting(&s);
}

#[test]
fn finish_refuses_records_that_do_not_match_what_was_written() {
    let d = tmpdir();
    let s = open(d.path());
    let spec = Spec::new(job(3));
    drop(s.put_elf(sha256(&elf(1)), &elf(1), &image_id).unwrap());
    let base = data_usage(&s, d.path());
    let w = witness(3, 5000);
    let good = spec.bundle(&w);

    type Mutation = Box<dyn Fn(&mut zkminer_witness::bundle::BundleV1)>;
    let cases: Vec<(&str, Mutation, Reject)> = vec![
        ("w_len", Box::new(|b| b.w_len += 1), Reject::Record(Defect::WLength)),
        ("w_sha256", Box::new(|b| b.w_sha256.0[0] ^= 1), Reject::Record(Defect::WHash)),
        ("input_sha256", Box::new(|b| b.input_sha256.0[0] ^= 1), Reject::Record(Defect::InputHash)),
        // The prefix flag decides the input hash.
        ("prefix flag", Box::new(|b| b.prefix = false), Reject::Record(Defect::InputHash)),
        ("descriptor", Box::new(|b| b.descriptor_hex.push_str("00")), Reject::Record(Defect::DescriptorHash)),
        ("descriptor hex", Box::new(|b| b.descriptor_hex.push('z')), Reject::Record(Defect::DescriptorHex)),
        ("key", Box::new(|_| {}), Reject::Record(Defect::KeyMismatch)),
        ("journal", Box::new(|b| b.po2_results[0].journal_sha256.0[0] ^= 1), Reject::Record(Defect::JournalHash)),
        ("journal size", Box::new(|b| {
            let j = vec![0u8; 32_769];
            b.po2_results[0].journal_hex = hex::encode(&j);
            b.po2_results[0].journal_sha256 = sha256(&j);
        }), Reject::Record(Defect::JournalTooLarge)),
        ("po2 twice", Box::new(|b| b.po2_results[1].po2 = 19), Reject::Record(Defect::Po2Duplicate)),
        ("format", Box::new(|b| b.format_version = 2), Reject::Record(Defect::FormatVersion)),
        ("version", Box::new(|b| b.version += 1), Reject::Record(Defect::VersionMismatch)),
        ("elf", Box::new(|b| b.image_id = B256::repeat_byte(0xee)), Reject::ElfMissing),
    ];
    for (name, mutate, want) in cases {
        // The key case: change the key the writer was opened with instead.
        let prov = if name == "key" { Address::repeat_byte(0x77) } else { good.prover };
        let mut wr = s.begin_bundle(good.job_id, good.descriptor_hash, prov, 1 << 20).unwrap();
        let mut b = at(&good, wr.version());
        mutate(&mut b);
        wr.write_w(&w).unwrap();
        assert_eq!(rejected(wr.finish(&b, &desc_hash).unwrap_err()), want, "{name}");
        assert_eq!(tmp_entries(d.path()), 0, "{name}: the failed writer is gone");
        assert_eq!(data_usage(&s, d.path()), base, "{name}");
        assert!(s.latest(good.job_id, good.descriptor_hash, good.prover).unwrap_err().is_missing(), "{name}");
    }
    // A descriptor hash function that cannot decode the descriptor refuses too.
    let mut wr = s.begin_bundle(good.job_id, good.descriptor_hash, good.prover, 1 << 20).unwrap();
    wr.write_w(&w).unwrap();
    let v = wr.version();
    assert_eq!(rejected(wr.finish(&at(&good, v), &|_| None).unwrap_err()), Reject::Record(Defect::DescriptorHash));

    // `max_w_bytes` is enforced mid-stream, and the writer is dead afterwards.
    let mut wr = s.begin_bundle(good.job_id, good.descriptor_hash, good.prover, 4096).unwrap();
    wr.write_w(&w[..4000]).unwrap();
    assert_eq!(rejected(wr.write_w(&w[4000..4100]).unwrap_err()), Reject::WitnessTooLarge { max: 4096 });
    assert_eq!(rejected(wr.write_w(&[1]).unwrap_err()), Reject::WriterFailed);
    assert_eq!(rejected(wr.finish(&good, &desc_hash).unwrap_err()), Reject::WriterFailed);
    assert_eq!(data_usage(&s, d.path()), base);
    assert_accounting(&s);
    // And the good record publishes.
    publish(&s, &good, &w, 999).unwrap();
}

#[test]
fn an_interrupted_write_is_never_a_version_and_is_cleaned() {
    let d = tmpdir();
    let s = open(d.path());
    let spec = Spec::new(job(4));
    drop(s.put_elf(sha256(&elf(1)), &elf(1), &image_id).unwrap());
    let w = witness(4, 70_000);
    let b = spec.bundle(&w);

    // Dropped mid-stream: gone at once.
    let mut wr = s.begin_bundle(b.job_id, b.descriptor_hash, b.prover, 1 << 20).unwrap();
    wr.write_w(&w[..30_000]).unwrap();
    assert_eq!(tmp_entries(d.path()), 1);
    drop(wr);
    assert_eq!(tmp_entries(d.path()), 0);
    assert!(s.latest(b.job_id, b.descriptor_hash, b.prover).unwrap_err().is_missing());
    assert_accounting(&s);

    // A crash leaves debris in tmp/: a half-written W, a fully written but unrenamed bundle, and a
    // half-written atomic file. None of it is a version, and the next open removes it.
    let mut wr = s.begin_bundle(b.job_id, b.descriptor_hash, b.prover, 1 << 20).unwrap();
    wr.write_w(&w[..30_000]).unwrap();
    let live = fs::read_dir(d.path().join("tmp")).unwrap().next().unwrap().unwrap().path();
    let half = d.path().join("tmp/0123456789abcdef0123456789abcdef");
    fs::create_dir(&half).unwrap();
    fs::copy(live.join("w.bin"), half.join("w.bin")).unwrap();
    drop(wr);
    let full = d.path().join("tmp/fedcba9876543210fedcba9876543210");
    fs::create_dir(&full).unwrap();
    fs::write(full.join("w.bin"), &w).unwrap();
    fs::write(full.join("bundle.json"), serde_json::to_vec(&b).unwrap()).unwrap();
    fs::write(d.path().join("tmp/aaaa.part"), b"{\"job_id\":").unwrap();
    drop(s);

    let s = open(d.path());
    assert_eq!(s.open_report().tmp_entries_removed, 3);
    assert_eq!(tmp_entries(d.path()), 0);
    assert!(s.latest(b.job_id, b.descriptor_hash, b.prover).unwrap_err().is_missing());
    assert!(s.scan().unwrap().bundles.is_empty());
    assert_accounting(&s);
}

#[test]
fn corruption_is_corrupt_and_absence_is_missing() {
    let d = tmpdir();
    let s = open(d.path());
    let w = witness(5, 9000);
    let refs: Vec<BundleRef> = (10..17).map(|j| put_and_publish(&s, &Spec::new(job(j)), &w)).collect();
    let vdir = |r: &BundleRef| vdir(d.path(), r);

    // A flipped byte in W: the record reads, W never verifies.
    let p = vdir(&refs[0]).join("w.bin");
    make_writable(&p);
    let mut bytes = fs::read(&p).unwrap();
    bytes[4321] ^= 0x40;
    fs::write(&p, &bytes).unwrap();
    assert!(s.read(&refs[0], &desc_hash).is_ok());
    assert_eq!(defect(s.open_w(&refs[0]).unwrap_err()), Defect::WHash);
    assert_eq!(defect(s.verify(&refs[0], &desc_hash, &image_id).unwrap_err()), Defect::WHash);

    // A truncated W.
    let p = vdir(&refs[1]).join("w.bin");
    make_writable(&p);
    fs::write(&p, &w[..100]).unwrap();
    assert_eq!(defect(s.read(&refs[1], &desc_hash).unwrap_err()), Defect::WLength);
    assert_eq!(defect(s.open_w(&refs[1]).unwrap_err()), Defect::WLength);

    // Garbage bundle.json.
    let p = vdir(&refs[2]).join("bundle.json");
    make_writable(&p);
    fs::write(&p, b"{\"format_version\": 1").unwrap();
    assert_eq!(defect(s.read(&refs[2], &desc_hash).unwrap_err()), Defect::Unparseable);
    assert_eq!(defect(s.open_w(&refs[2]).unwrap_err()), Defect::Unparseable);
    assert_eq!(s.latest(refs[2].job_id, refs[2].descriptor_hash, refs[2].prover).unwrap(), refs[2], "still complete");

    // A well-formed record whose descriptor no longer hashes to descriptor_hash.
    let p = vdir(&refs[3]).join("bundle.json");
    make_writable(&p);
    let mut b: zkminer_witness::bundle::BundleV1 = serde_json::from_slice(&fs::read(&p).unwrap()).unwrap();
    b.descriptor_hex.replace_range(0..2, "ff");
    fs::write(&p, serde_json::to_vec(&b).unwrap()).unwrap();
    assert_eq!(defect(s.read(&refs[3], &desc_hash).unwrap_err()), Defect::DescriptorHash);

    // A record moved under another job's key.
    let p = vdir(&refs[4]).join("bundle.json");
    make_writable(&p);
    fs::copy(vdir(&refs[5]).join("bundle.json"), &p).unwrap();
    assert_eq!(defect(s.read(&refs[4], &desc_hash).unwrap_err()), Defect::KeyMismatch);

    // w.bin missing, then replaced by a symlink to a good copy.
    let p = vdir(&refs[6]).join("w.bin");
    let good = d.path().join("good.bin");
    fs::copy(&p, &good).unwrap();
    fs::remove_file(&p).unwrap();
    assert_eq!(defect(s.read(&refs[6], &desc_hash).unwrap_err()), Defect::FileMissing);
    assert_eq!(defect(s.open_w(&refs[6]).unwrap_err()), Defect::FileMissing);
    std::os::unix::fs::symlink(&good, &p).unwrap();
    assert_eq!(defect(s.open_w(&refs[6]).unwrap_err()), Defect::NotRegularFile);

    // Missing: no such version, no such key.
    let mut absent = refs[5];
    absent.version += 1000;
    assert!(s.read(&absent, &desc_hash).unwrap_err().is_missing());
    assert!(s.open_w(&absent).unwrap_err().is_missing());
    assert!(s.latest(job(99), B256::ZERO, prover()).unwrap_err().is_missing());
    // The untouched one still verifies.
    s.verify(&refs[5], &desc_hash, &image_id).unwrap();

    // The scan reports every corrupt version rather than skipping it.
    let scan = s.scan().unwrap();
    assert_eq!(scan.bundles.len(), 7);
    let bad: Vec<_> = scan.bundles.iter().filter(|m| m.record.is_err()).map(|m| m.bundle).collect();
    assert_eq!(bad, vec![refs[1], refs[2], refs[4], refs[6]]);

    // A corrupt ELF and a missing one.
    let ep = d.path().join("elfs").join(hex::encode(sha256(&elf(1))));
    make_writable(&ep);
    fs::write(&ep, b"not the elf").unwrap();
    assert_eq!(defect(s.open_elf(sha256(&elf(1)), &image_id).unwrap_err()), Defect::ImageId);
    assert!(s.open_elf(B256::repeat_byte(3), &image_id).unwrap_err().is_missing());
    // put_elf replaces a corrupt copy.
    drop(s.put_elf(sha256(&elf(1)), &elf(1), &image_id).unwrap());
    assert_eq!(s.open_elf(sha256(&elf(1)), &image_id).unwrap(), elf(1));
    // Files were changed behind the store's back: the scan re-counts them.
    s.scan().unwrap();
    assert_accounting(&s);
}

#[test]
fn a_vanished_or_replaced_root_is_unavailable() {
    let parent = tmpdir();
    let root = parent.path().join("store");
    fs::create_dir(&root).unwrap();
    let s = open(&root);
    let r = put_and_publish(&s, &Spec::new(job(1)), &witness(1, 100));
    let rec = pin_rec(&s, &r);
    let moved = parent.path().join("moved");
    fs::rename(&root, &moved).unwrap();
    assert_eq!(unavailable(s.read(&r, &desc_hash).unwrap_err()), UnavailableKind::RootAbsent);
    fs::create_dir(&root).unwrap();
    assert_eq!(unavailable(s.read(&r, &desc_hash).unwrap_err()), UnavailableKind::RootChanged);
    assert_eq!(unavailable(s.pin(&rec).unwrap_err()), UnavailableKind::RootChanged);
    fs::remove_dir(&root).unwrap();
    fs::rename(&moved, &root).unwrap();
    s.verify(&r, &desc_hash, &image_id).unwrap();

    // The bundles area vanishing is an unavailable store, not a missing bundle.
    let other = parent.path().join("bundles-elsewhere");
    fs::rename(root.join("bundles"), &other).unwrap();
    assert_eq!(unavailable(s.read(&r, &desc_hash).unwrap_err()), UnavailableKind::NotFound);
    assert_eq!(unavailable(s.latest(r.job_id, r.descriptor_hash, r.prover).unwrap_err()), UnavailableKind::NotFound);
}

#[test]
fn quota_and_floor_refuse_mid_stream() {
    let d = tmpdir();
    let s = open(d.path());
    let spec = Spec::new(job(6));
    drop(s.put_elf(sha256(&elf(1)), &elf(1), &image_id).unwrap());
    let b = spec.bundle(&[]);
    let base = s.usage();
    drop(s);
    let avail = Store::open(d.path(), &expected(d.path()), StoreOptions { quota_bytes: u64::MAX, ..opts() })
        .unwrap()
        .headroom()
        .unwrap();

    // Byte quota: room for two 4 KiB pieces.
    let o = StoreOptions { quota_bytes: base.bytes + 10_000, ..opts() };
    let s = Store::open(d.path(), &expected(d.path()), o).unwrap();
    let mut wr = s.begin_bundle(b.job_id, b.descriptor_hash, b.prover, 1 << 20).unwrap();
    wr.write_w(&[1; 4096]).unwrap();
    wr.write_w(&[2; 4096]).unwrap();
    assert!(matches!(wr.write_w(&[3; 4096]).unwrap_err(), StoreError::RetentionFull(FullReason::QuotaBytes)));
    assert_eq!(wr.written(), 8192);
    assert_eq!(rejected(wr.write_w(&[4; 1]).unwrap_err()), Reject::WriterFailed);
    drop(wr);
    assert_eq!(s.usage(), base, "the counter went from 1 to 2: same size");
    assert_eq!(tmp_entries(d.path()), 0);
    // A verdict is refused at the quota; a pin never is (it protects a lock).
    let small = witness(6, 1500);
    let bb = spec.bundle(&small);
    let r = publish(&s, &bb, &small, 500).unwrap();
    let mut wr = s.begin_bundle(b.job_id, b.descriptor_hash, b.prover, 1 << 20).unwrap();
    wr.write_w(&vec![0; (o.quota_bytes - s.usage().bytes) as usize]).unwrap();
    assert_eq!(s.headroom().unwrap(), 0);
    let v = VerdictRecord {
        job_id: job(6),
        reason: SkipReason::BindingMismatch,
        attempts: 1,
        recorded_at: 1,
        expires_at: 2,
        wasmtime_version: None,
    };
    assert!(s.put_verdict(&v).unwrap_err().is_full());
    s.pin(&pin_rec(&s, &r)).unwrap();
    drop(wr);
    assert_accounting(&s);
    drop(s);

    // Inode quota: a bundle needs up to six entries.
    let used = open(d.path()).usage().inodes;
    let o = StoreOptions { quota_inodes: used + 3, ..opts() };
    let s = Store::open(d.path(), &expected(d.path()), o).unwrap();
    assert!(matches!(
        s.begin_bundle(b.job_id, b.descriptor_hash, b.prover, 1 << 20).unwrap_err(),
        StoreError::RetentionFull(FullReason::QuotaInodes)
    ));
    drop(s);

    // Free-space floor: refused from the start when already crossed, and mid-stream when W grows
    // into it (3 MiB of room, 1 MiB pieces).
    let o = StoreOptions { free_space_floor_bytes: u64::MAX, ..opts() };
    let s = Store::open(d.path(), &expected(d.path()), o).unwrap();
    assert!(matches!(
        s.begin_bundle(b.job_id, b.descriptor_hash, b.prover, 1 << 30).unwrap_err(),
        StoreError::RetentionFull(FullReason::FreeSpaceFloor)
    ));
    drop(s);
    assert!(avail > 1 << 30, "the test needs some free disk");
    // 16 MiB of room above the floor, 4 MiB pieces (other writers on the disk move it a little).
    let o = StoreOptions { free_space_floor_bytes: avail - (16 << 20), quota_bytes: u64::MAX, ..opts() };
    let s = Store::open(d.path(), &expected(d.path()), o).unwrap();
    let mut wr = s.begin_bundle(b.job_id, b.descriptor_hash, b.prover, 1 << 30).unwrap();
    let piece = vec![7u8; 4 << 20];
    let mut n = 0;
    let err = loop {
        match wr.write_w(&piece) {
            Ok(()) => n += 1,
            Err(e) => break e,
        }
        assert!(n < 32, "the floor never refused");
    };
    assert!(matches!(err, StoreError::RetentionFull(FullReason::FreeSpaceFloor)), "{err:?}");
    assert!((1..=6).contains(&n), "{n} pieces of 4 MiB against a 16 MiB margin");
    drop(wr);
    assert_eq!(tmp_entries(d.path()), 0);
    assert_accounting(&s);
}

#[test]
fn pins_are_durable_and_checked() {
    let d = tmpdir();
    let s = open(d.path());
    let r = put_and_publish(&s, &Spec::new(job(7)), &witness(7, 2000));
    let rec = pin_rec(&s, &r);
    assert_eq!(rec.input_sha256, s.read(&r, &desc_hash).unwrap().input_sha256);
    assert_eq!(rec.bundle_json_sha256, sha256(&fs::read(vdir(d.path(), &r).join("bundle.json")).unwrap()));
    s.pin(&rec).unwrap();
    s.pin(&rec).unwrap(); // idempotent
    assert_eq!(s.pins(), vec![rec.clone()]);
    assert_eq!(s.pin_status(&r.key()), PinStatus::Pinned { version: r.version });
    let pin_file = pin_file(d.path(), &r);
    assert_eq!(serde_json::from_slice::<PinRecord>(&fs::read(&pin_file).unwrap()).unwrap(), rec);
    assert_eq!(fs::metadata(&pin_file).unwrap().permissions().mode() & 0o777, 0o444);
    assert_accounting(&s);
    drop(s);

    let s = open(d.path());
    assert_eq!(s.pins(), vec![rec.clone()], "the pin survives a reopen");
    // A pin must name an existing, readable version, with the hashes it has.
    let mut missing = rec.clone();
    missing.bundle_version += 50;
    assert!(s.pin(&missing).unwrap_err().is_missing());
    for mismatch in [
        PinRecord { input_sha256: B256::repeat_byte(1), ..rec.clone() },
        PinRecord { bundle_json_sha256: B256::repeat_byte(1), ..rec.clone() },
    ] {
        assert_eq!(rejected(s.pin(&mismatch).unwrap_err()), Reject::Record(Defect::PinMismatch));
    }
    assert_eq!(s.pins(), vec![rec.clone()], "a refused pin changes nothing");
    let r2 = put_and_publish(&s, &Spec::new(job(8)), &witness(8, 2000));
    let rec2 = pin_rec(&s, &r2);
    let jp = vdir(d.path(), &r2).join("bundle.json");
    make_writable(&jp);
    fs::write(&jp, b"[]").unwrap();
    assert!(s.pin(&rec2).unwrap_err().is_corrupt());
    // Re-pinning at a newer version replaces the pin.
    let spec = Spec::new(job(7));
    let w3 = witness(9, 10);
    let r3 = publish(&s, &spec.bundle(&w3), &w3, 4).unwrap();
    let rec3 = pin_rec(&s, &r3);
    s.pin(&rec3).unwrap();
    assert_eq!(s.pins(), vec![rec3]);
    assert!(s.unpin(r.job_id, r.descriptor_hash, r.prover).unwrap());
    assert!(!s.unpin(r.job_id, r.descriptor_hash, r.prover).unwrap());
    assert!(s.pins().is_empty());
    s.scan().unwrap();
    assert_accounting(&s);
    drop(s);
    assert!(open(d.path()).pins().is_empty(), "the unpin is durable");
}

#[test]
fn eviction_waits_for_the_scan_and_never_touches_pins() {
    let d = tmpdir();
    let s = open(d.path());
    let value = |m: &BundleMeta| m.record.as_ref().map_or(0, |r| r.created_at_block);
    assert!(matches!(s.evict_to(u64::MAX, &value).unwrap_err(), StoreError::EvictionDisabled));

    // Job 20 pinned at v_a, with a newer v_b after the pin and an older v_0 before it.
    let spec = |j: u8, block: u64| Spec { block, ..Spec::new(job(j)) };
    let w = witness(1, 4000);
    let v0 = put_and_publish(&s, &spec(20, 1), &w);
    let va = put_and_publish(&s, &spec(20, 2), &w);
    s.pin(&pin_rec(&s, &va)).unwrap();
    let vb = put_and_publish(&s, &spec(20, 3), &w);
    // Unpinned jobs with values 10, 11, 12 (by block).
    let others: Vec<BundleRef> = [(21, 10), (22, 11), (23, 12)].iter().map(|&(j, b)| put_and_publish(&s, &spec(j, b), &w)).collect();
    // A key whose pin file is unreadable: all its versions are protected.
    let u1 = put_and_publish(&s, &spec(24, 0), &w);
    fs::write(pin_file(d.path(), &u1), b"garbage").unwrap();
    drop(s);

    let s = open(d.path());
    assert!(matches!(s.evict_to(u64::MAX, &value).unwrap_err(), StoreError::EvictionDisabled), "disabled again after a restart");
    let scan = s.scan().unwrap();
    assert_eq!(scan.unreadable_pins, vec![u1.key()]);
    assert!(scan.anomalies.iter().any(|a| a.kind == AnomalyKind::UnreadablePin));
    s.mark_recovery_scan_complete();

    // Free one byte past the current headroom (the quota term, 1 GiB, is the binding one): only the
    // lowest-value unprotected version goes (v0, block 1).
    let target = s.headroom().unwrap() + 1;
    let rep = s.evict_to(target, &value).unwrap();
    assert_eq!(rep.evicted, vec![v0]);
    assert!(rep.reached);

    // Evict everything evictable.
    let rep = s.evict_to(u64::MAX, &value).unwrap();
    assert!(!rep.reached);
    assert_eq!(rep.evicted, others, "ascending value");
    let left: Vec<BundleRef> = s.scan().unwrap().bundles.iter().map(|m| m.bundle).collect();
    assert_eq!(left, vec![va, vb, u1], "pinned, latest of pinned, unreadable-pinned");
    for r in [va, vb, u1] {
        s.verify(&r, &desc_hash, &image_id).unwrap();
    }
    for r in &others {
        assert!(s.read(r, &desc_hash).unwrap_err().is_missing());
        assert!(!d.path().join("bundles").join(hex::encode(r.job_id)).exists(), "empty parents pruned");
    }
    assert_accounting(&s);
}

#[test]
fn deletion_needs_no_pins_and_drops_elf_refs_and_verdicts() {
    let d = tmpdir();
    let s = open(d.path());
    let w = witness(1, 3000);
    // Jobs 30 and 31 share ELF 1; job 32 uses ELF 2.
    let a = put_and_publish(&s, &Spec::new(job(30)), &w);
    let a2 = put_and_publish(&s, &Spec { desc: 1, ..Spec::new(job(30)) }, &w);
    let b = put_and_publish(&s, &Spec::new(job(31)), &w);
    let c = put_and_publish(&s, &Spec { elf: 2, ..Spec::new(job(32)) }, &w);
    let e1 = sha256(&elf(1));
    let e2 = sha256(&elf(2));
    assert_eq!((s.elf_refs(e1), s.elf_refs(e2)), (3, 1));
    let v = VerdictRecord {
        job_id: job(30),
        reason: SkipReason::GuestFailed,
        attempts: 1,
        recorded_at: 10,
        expires_at: 1_000,
        wasmtime_version: Some((48, 0, 8)),
    };
    s.put_verdict(&v).unwrap();

    s.pin(&pin_rec(&s, &a2)).unwrap();
    match s.delete_job(job(30), &terminal(job(30))).unwrap_err() {
        StoreError::Pinned(keys) => assert_eq!(keys, vec![a2.key()]),
        e => panic!("{e:?}"),
    }
    assert_eq!(rejected(s.delete_job(job(30), &terminal(job(31))).unwrap_err()), Reject::TerminalJobMismatch);
    s.verify(&a, &desc_hash, &image_id).unwrap();

    s.unpin(a2.job_id, a2.descriptor_hash, a2.prover).unwrap();
    let rep = s.delete_job(job(30), &terminal(job(30))).unwrap();
    assert_eq!(rep.versions_removed, 2);
    assert!(rep.elfs_removed.is_empty(), "job 31 still references ELF 1");
    assert!(rep.verdict_removed);
    assert_eq!(s.verdict(job(30)).unwrap(), None);
    assert!(s.read(&a, &desc_hash).unwrap_err().is_missing());
    assert_eq!(s.elf_refs(e1), 1);
    assert!(!d.path().join("bundles").join(hex::encode(job(30))).exists());

    let rep = s.delete_job(job(31), &terminal(job(31))).unwrap();
    assert_eq!(rep.elfs_removed, vec![e1]);
    assert!(s.read(&b, &desc_hash).unwrap_err().is_missing());
    assert!(s.open_elf(e1, &image_id).unwrap_err().is_missing());

    // A held ELF outlives its last reference.
    let hold = s.hold_elf(e2).unwrap();
    let rep = s.delete_job(job(32), &terminal(job(32))).unwrap();
    assert!(rep.elfs_removed.is_empty());
    assert!(s.read(&c, &desc_hash).unwrap_err().is_missing());
    assert_eq!(s.open_elf(e2, &image_id).unwrap(), elf(2));
    drop(hold);
    // ... and an unreferenced, unheld one is collected under pressure.
    s.mark_recovery_scan_complete();
    let rep = s.evict_to(u64::MAX, &|_| 0).unwrap();
    assert_eq!(rep.elfs_removed, vec![e2]);
    // Deleting a job with nothing stored is fine.
    assert_eq!(s.delete_job(job(33), &terminal(job(33))).unwrap(), DeleteReport::default());
    assert_accounting(&s);
}

#[test]
fn elf_area_verifies_and_shares() {
    let d = tmpdir();
    let s = open(d.path());
    let id = sha256(&elf(1));
    assert_eq!(rejected(s.put_elf(B256::repeat_byte(1), &elf(1), &image_id).unwrap_err()), Reject::Record(Defect::ImageId));
    assert!(s.hold_elf(id).unwrap_err().is_missing());
    let h1 = s.put_elf(id, &elf(1), &image_id).unwrap();
    let usage = s.usage();
    // A second copy with the same image id (stripped vs unstripped) keeps the first.
    let alt = [elf(1), b"debug".to_vec()].concat();
    let same_id = |b: &[u8]| if b.starts_with(&elf(1)) { Some(id) } else { None };
    let h2 = s.put_elf(id, &alt, &same_id).unwrap();
    assert_eq!(s.usage(), usage);
    assert_eq!(s.open_elf(id, &image_id).unwrap(), elf(1));
    assert_eq!(h1.image_id(), h2.image_id());
    // Two bundles share one file.
    let w = witness(1, 100);
    put_and_publish(&s, &Spec::new(job(40)), &w);
    put_and_publish(&s, &Spec::new(job(41)), &w);
    assert_eq!(s.elf_refs(id), 2);
    assert_eq!(fs::read_dir(d.path().join("elfs")).unwrap().count(), 1);
    // Holds keep the store (and its lock) alive.
    drop(s);
    assert_eq!(unavailable(Store::open(d.path(), &expected(d.path()), opts()).unwrap_err()), UnavailableKind::LockHeld);
    drop((h1, h2));
    let s = open(d.path());
    assert_eq!(s.elf_refs(id), 2, "refcounts are rebuilt from bundle records");
}

#[test]
fn verdicts_persist_expire_and_stay_fixed() {
    let d = tmpdir();
    let s = open(d.path());
    let mk = |j: u8, expires_at: u64| VerdictRecord {
        job_id: job(j),
        reason: SkipReason::BuilderTrap,
        attempts: 2,
        recorded_at: 100,
        expires_at,
        wasmtime_version: Some((48, 0, 8)),
    };
    for (j, e) in [(1, 150), (2, 250), (3, 350)] {
        s.put_verdict(&mk(j, e)).unwrap();
    }
    s.put_verdict(&VerdictRecord { attempts: 3, ..mk(1, 150) }).unwrap();
    assert_eq!(s.verdict(job(1)).unwrap().unwrap().attempts, 3);
    assert_eq!(s.verdict(job(9)).unwrap(), None);
    drop(s);
    let s = open(d.path());
    assert_eq!(s.verdict(job(2)).unwrap(), Some(mk(2, 250)));
    // Every reason encodes to a small record.
    for r in SkipReason::ALL {
        let len = serde_json::to_vec(&VerdictRecord { reason: r, ..mk(1, 1) }).unwrap().len();
        assert!(len < 400, "{r:?}: {len}");
    }
    // A corrupt verdict is Corrupt to read and dropped by expiry.
    let p = d.path().join("verdicts").join(format!("{}.json", hex::encode(job(3))));
    fs::write(&p, b"nope").unwrap();
    assert!(s.verdict(job(3)).unwrap_err().is_corrupt());
    assert_eq!(s.expire_verdicts(200).unwrap(), 2, "job 1 expired, job 3 corrupt");
    assert_eq!(s.verdict(job(1)).unwrap(), None);
    assert_eq!(s.verdict(job(2)).unwrap(), Some(mk(2, 250)));
    assert_eq!(s.expire_verdicts(250).unwrap(), 1);
    s.scan().unwrap();
    assert_accounting(&s);
}

#[test]
fn scan_reports_layout_anomalies_pins_and_callers() {
    let d = tmpdir();
    let s = open(d.path());
    let w = witness(1, 1000);
    let alice = Address::repeat_byte(0xa1);
    let bob = Address::repeat_byte(0xb0);
    let r1 = put_and_publish(&s, &Spec { caller: alice, ..Spec::new(job(50)) }, &w);
    let r2 = put_and_publish(&s, &Spec { caller: alice, ..Spec::new(job(50)) }, &w);
    let r3 = put_and_publish(&s, &Spec { caller: bob, ..Spec::new(job(51)) }, &w);
    let rec1 = pin_rec(&s, &r1);
    s.pin(&rec1).unwrap();
    fs::create_dir(d.path().join("bundles/not-a-job")).unwrap();
    fs::write(d.path().join("bundles").join(hex::encode(job(51))).join("stray"), b"x").unwrap();
    let scan = s.scan().unwrap();
    let m = |r: BundleRef| scan.bundles.iter().find(|m| m.bundle == r).unwrap().clone();
    assert_eq!((m(r1).pin, m(r1).latest, m(r1).protected()), (PinStatus::Pinned { version: r1.version }, false, true));
    assert_eq!((m(r2).latest, m(r2).protected()), (true, true));
    assert_eq!((m(r3).pin, m(r3).protected()), (PinStatus::Unpinned, false));
    assert_eq!(m(r3).caller(), Some(bob));
    assert_eq!(scan.anomalies.len(), 2);
    assert!(scan.anomalies.iter().all(|a| a.kind == AnomalyKind::UnexpectedEntry));
    let by = s.bytes_by_caller();
    assert_eq!(by[&alice], m(r1).usage.bytes + m(r2).usage.bytes);
    assert_eq!(by[&bob], m(r3).usage.bytes);
    assert_eq!(scan.pins, vec![rec1]);
    assert_accounting(&s);
}

#[test]
fn version_numbers_are_never_reused() {
    let d = tmpdir();
    let s = open(d.path());
    let spec = Spec::new(job(60));
    let w = witness(1, 100);
    let r1 = put_and_publish(&s, &spec, &w);
    let r2 = put_and_publish(&s, &spec, &w);
    s.delete_job(job(60), &terminal(job(60))).unwrap();
    let r3 = put_and_publish(&s, &spec, &w);
    assert!(r1.version < r2.version && r2.version < r3.version);
    drop(s);

    // A lost counter is rebuilt from the highest version on disk.
    fs::remove_file(d.path().join("next_version")).unwrap();
    let s = open(d.path());
    assert!(s.open_report().version_counter_recovered);
    let r4 = put_and_publish(&s, &spec, &w);
    assert!(r4.version > r3.version);
    drop(s);
    fs::write(d.path().join("next_version"), b"1").unwrap();
    let s = open(d.path());
    assert!(s.open_report().version_counter_recovered, "a counter behind the disk is corrected");
    assert!(put_and_publish(&s, &spec, &w).version > r4.version);
    assert_accounting(&s);
}

#[test]
fn concurrent_writers_get_distinct_versions() {
    let d = tmpdir();
    let s = std::sync::Arc::new(open(d.path()));
    drop(s.put_elf(sha256(&elf(1)), &elf(1), &image_id).unwrap());
    let spec = Spec::new(job(70));
    let handles: Vec<_> = (0..8u8)
        .map(|i| {
            let s = std::sync::Arc::clone(&s);
            let w = witness(i, 50_000 + i as usize);
            let b = spec.bundle(&w);
            std::thread::spawn(move || publish(&s, &b, &w, 4096).unwrap())
        })
        .collect();
    let mut versions: Vec<u32> = handles.into_iter().map(|h| h.join().unwrap().version).collect();
    versions.sort_unstable();
    versions.dedup();
    assert_eq!(versions.len(), 8);
    assert_eq!(s.versions(job(70), spec.bundle(&[]).descriptor_hash, prover()).unwrap(), versions);
    for v in versions {
        s.verify(&BundleKey::new(job(70), spec.bundle(&[]).descriptor_hash, prover()).at(v), &desc_hash, &image_id).unwrap();
    }
    assert_accounting(&s);
}
