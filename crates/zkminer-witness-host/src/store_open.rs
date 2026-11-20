//! Opening and initialising the retention store from the miner's config (§15.1, §15.2).

use alloy_primitives::Address;
use zkminer_config::witness::RetentionConfig;
use zkminer_witness::bundle::StoreIdentity;
use zkminer_witness_store::{ExpectedIdentity, Store, StoreError, StoreIdentityInit, StoreOptions};

/// The free-space floor in bytes: `pct` percent of the filesystem holding `dir`.
pub fn free_floor_bytes(dir: &std::path::Path, pct: f64) -> std::io::Result<u64> {
    let c = std::ffi::CString::new(dir.as_os_str().as_encoded_bytes())
        .map_err(|_| std::io::Error::other("path contains NUL"))?;
    // SAFETY: statvfs fills a plain struct.
    let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statvfs(c.as_ptr(), &mut st) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let size = (st.f_blocks as u128) * (st.f_frsize as u128);
    Ok(((size as f64) * pct / 100.0) as u64)
}

/// Opens the store the config names, for this chain, router and prover. Never creates it: a store
/// that does not exist (or a mount point that did not mount) is `Unavailable`.
pub fn open_store(r: &RetentionConfig, chain_id: u64, router: Address, prover: Address) -> Result<Store, StoreError> {
    let floor = free_floor_bytes(&r.dir, r.free_floor_pct).unwrap_or(u64::MAX);
    Store::open(
        &r.dir,
        &ExpectedIdentity { chain_id, router, prover, store_uuid: r.store_uuid.clone() },
        StoreOptions {
            quota_bytes: r.quota_bytes,
            quota_inodes: r.quota_inodes,
            free_space_floor_bytes: floor,
            require_dedicated_mount: r.require_dedicated_mount,
            allow_any_filesystem: r.allow_any_filesystem,
        },
    )
}

/// `zkminer witness init-store`: initialises an empty directory and returns the identity whose UUID
/// goes into `[retention] store_uuid`.
pub fn init_store(
    dir: &std::path::Path,
    chain_id: u64,
    router: Address,
    prover: Address,
    require_dedicated_mount: bool,
    allow_any_filesystem: bool,
) -> Result<StoreIdentity, StoreError> {
    Store::init(dir, &StoreIdentityInit { chain_id, router, prover, require_dedicated_mount, allow_any_filesystem })
}
