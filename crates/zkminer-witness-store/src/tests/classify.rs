//! F3 under injected faults: `open` and `init` return nothing but `Unavailable` (BadLayout or an
//! I/O kind) — never Corrupt, Missing or RetentionFull — and a later attempt succeeds.

use std::fs;
use std::path::Path;

use super::common::*;
use super::unavailable;
use crate::faults::{self, Op};
use crate::*;

const ENOSPC: UnavailableKind = UnavailableKind::Io { errno: Some(libc::ENOSPC) };

fn open_err(dir: &Path) -> StoreError {
    Store::open(dir, &expected(dir), opts()).unwrap_err()
}

#[test]
fn open_under_faults_is_only_unavailable() {
    let d = tmpdir();
    let root = d.path();
    let s = open(root);
    let r = put_and_publish(&s, &Spec::new(job(1)), &witness(1, 800));
    drop(s);
    let root_s = root.to_string_lossy().into_owned();

    // Repairing a lost counter is open's one write.
    let cases: [(Op, &str, i32, u32, UnavailableKind); 6] = [
        (Op::Create, ".part", libc::ENOSPC, 0, ENOSPC),
        (Op::Write, ".part", libc::ENOSPC, 0, ENOSPC),
        (Op::Write, ".part", libc::EDQUOT, 0, ENOSPC),
        (Op::Fsync, ".part", libc::EIO, 0, UnavailableKind::Eio),
        (Op::Rename, ".part", libc::EIO, 0, UnavailableKind::Eio),
        // The root's fsync after the rename (the part file's fsync is skipped).
        (Op::Fsync, &root_s, libc::EIO, 1, UnavailableKind::Eio),
    ];
    for (op, sub, errno, skip, want) in cases {
        fs::remove_file(root.join("next_version")).unwrap();
        let f = faults::install();
        f.fail(op, sub, errno, skip, 1);
        assert_eq!(unavailable(open_err(root)), want, "{op:?} {sub} {errno}");
        drop(f);
        // The next open succeeds (and repairs the counter, unless the failed one had renamed it
        // into place already).
        let s = Store::open(root, &expected(root), opts()).unwrap();
        assert_eq!(s.open_report().version_counter_recovered, !(op == Op::Fsync && skip == 1), "{op:?}");
    }

    // Removing `tmp/` debris.
    fs::write(root.join("tmp/junk"), b"x").unwrap();
    let f = faults::install();
    f.fail(Op::Unlink, "junk", libc::EIO, 0, 1);
    assert_eq!(unavailable(open_err(root)), UnavailableKind::Eio);
    f.fail(Op::Unlink, "junk", libc::EROFS, 0, 1);
    assert_eq!(unavailable(open_err(root)), UnavailableKind::ReadOnly);
    drop(f);

    // Reads during the scan.
    let reads: [(&str, i32, UnavailableKind); 4] = [
        ("bundle.json", libc::EIO, UnavailableKind::Eio),
        ("bundle.json", libc::ENOMEM, UnavailableKind::Io { errno: Some(libc::ENOMEM) }),
        (&format!("/bundles/{}", hex::encode(r.job_id)), libc::EIO, UnavailableKind::Eio),
        ("/pins", libc::EIO, UnavailableKind::Eio),
    ];
    for (sub, errno, want) in reads {
        let f = faults::install();
        f.fail(Op::Open, sub, errno, 0, 1);
        assert_eq!(unavailable(open_err(root)), want, "{sub} {errno}");
    }
    // An ENOENT while reading is not a missing bundle at open either.
    let f = faults::install();
    f.fail(Op::Open, "/bundles", libc::ENOENT, 0, 1);
    assert!(open_err(root).is_unavailable());
    drop(f);

    let s = Store::open(root, &expected(root), opts()).unwrap();
    s.verify(&r, &desc_hash, &image_id).unwrap();
    assert_accounting(&s);
}

#[test]
fn init_under_faults_is_only_unavailable_and_can_be_rerun() {
    let cases: [(Op, &str, i32, UnavailableKind); 7] = [
        (Op::Create, ".lock", libc::ENOSPC, ENOSPC),
        (Op::Mkdir, "bundles", libc::ENOSPC, ENOSPC),
        (Op::Mkdir, "verdicts", libc::EIO, UnavailableKind::Eio),
        (Op::Write, ".part", libc::ENOSPC, ENOSPC),
        (Op::Fsync, ".part", libc::EIO, UnavailableKind::Eio),
        (Op::Rename, ".part", libc::EROFS, UnavailableKind::ReadOnly),
        (Op::Chmod, ".part", libc::EPERM, UnavailableKind::Io { errno: Some(libc::EPERM) }),
    ];
    for (op, sub, errno, want) in cases {
        let d = tmpdir();
        let f = faults::install();
        f.fail(op, sub, errno, 0, 1);
        assert_eq!(unavailable(Store::init(d.path(), &init_id()).unwrap_err()), want, "{op:?} {sub}");
        drop(f);
        // What the failed init left is finished by running it again.
        let id = Store::init(d.path(), &init_id()).unwrap();
        let s = Store::open(d.path(), &expected(d.path()), opts()).unwrap();
        assert_eq!(s.identity(), &id);
    }
}

/// The dedicated-mount check: `/dev/shm` is always its own mount; a directory on the test disk is
/// not (tests cannot mount, so the store-level refusal is tested on plain directories elsewhere).
#[test]
fn the_mount_check_tells_a_mount_point_from_a_directory() {
    use crate::fsutil::Dir;
    use crate::store::is_mount_root;
    assert!(is_mount_root(&Dir::open_path(Path::new("/dev/shm")).unwrap()).unwrap());
    assert!(is_mount_root(&Dir::open_path(Path::new("/")).unwrap()).is_ok());
    let d = tmpdir();
    assert!(!is_mount_root(&Dir::open_path(d.path()).unwrap()).unwrap());
}
