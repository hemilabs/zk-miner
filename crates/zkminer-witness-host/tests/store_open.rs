//! Opening and initialising the store from config, on the real disk (the store refuses tmpfs).

use alloy_primitives::Address;
use zkminer_config::witness::RetentionConfig;
use zkminer_witness_host::store_open::{free_floor_bytes, init_store, open_store};
use zkminer_witness_store::StoreError;

fn cfg(dir: &std::path::Path, uuid: &str) -> RetentionConfig {
    RetentionConfig {
        dir: dir.to_path_buf(),
        store_uuid: uuid.into(),
        quota_bytes: 1 << 30,
        quota_inodes: 100_000,
        per_caller_bytes: 1 << 28,
        free_floor_pct: 1.0,
        segment_dir: dir.with_extension("segments"),
        require_dedicated_mount: false,
        allow_any_filesystem: false,
    }
}

#[test]
fn init_then_open_and_refuse_wrong_uuid_or_empty_dir() {
    // On the real disk (the store refuses tmpfs).
    let base = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
    let dir = base.path().join("store");
    std::fs::create_dir(&dir).unwrap();
    let (router, prover) = (Address::repeat_byte(1), Address::repeat_byte(2));
    let id = init_store(&dir, 743111, router, prover, false, false).unwrap();
    let store = open_store(&cfg(&dir, &id.store_uuid), 743111, router, prover).unwrap();
    drop(store);
    assert!(open_store(&cfg(&dir, "not-the-uuid"), 743111, router, prover).is_err());
    // An empty directory (an unmounted mount point) is never a store.
    let empty = base.path().join("empty");
    std::fs::create_dir(&empty).unwrap();
    assert!(matches!(
        open_store(&cfg(&empty, &id.store_uuid), 743111, router, prover),
        Err(StoreError::Unavailable { .. })
    ));
    assert!(free_floor_bytes(&dir, 5.0).unwrap() > 0);
}
