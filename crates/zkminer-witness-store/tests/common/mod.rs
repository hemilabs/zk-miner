#![allow(dead_code)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use alloy_primitives::{keccak256, Address, B256};
use sha2::{Digest, Sha256};
use zkminer_witness::binding::{input_sha256, journal_prefix};
use zkminer_witness::bundle::{BundleV1, GuestExit, Po2Result, BUNDLE_FORMAT_VERSION};
use zkminer_witness_store::{BundleRef, ExpectedIdentity, Store, StoreError, StoreOptions};

pub const CHAIN: u64 = 743_111;

pub fn router() -> Address {
    Address::repeat_byte(0x11)
}

pub fn prover() -> Address {
    Address::repeat_byte(0x22)
}

/// A directory on the real disk (`target/tmp`, under the worktree), never tmpfs.
pub fn tmpdir() -> tempfile::TempDir {
    tempfile::Builder::new().prefix("wstore-").tempdir_in(env!("CARGO_TARGET_TMPDIR")).expect("tempdir")
}

pub fn expected() -> ExpectedIdentity {
    ExpectedIdentity { chain_id: CHAIN, router: router(), prover: prover(), store_uuid: None }
}

pub fn opts() -> StoreOptions {
    StoreOptions { quota_bytes: 1 << 30, quota_inodes: 1_000_000, free_space_floor_bytes: 0, create: true }
}

pub fn open(dir: &Path) -> Store {
    Store::open(dir, &expected(), opts()).expect("open")
}

pub fn sha256(b: &[u8]) -> B256 {
    B256::from(<[u8; 32]>::from(Sha256::digest(b)))
}

/// The caller-supplied descriptor hash (the real one decodes and hashes with zkminer-chain).
pub fn desc_hash(b: &[u8]) -> Option<B256> {
    Some(keccak256(b))
}

/// The caller-supplied image id (the real one is risc0's).
pub fn image_id(b: &[u8]) -> Option<B256> {
    Some(sha256(b))
}

pub fn elf(n: u8) -> Vec<u8> {
    let mut v = b"\x7fELF fake guest ".to_vec();
    v.extend(std::iter::repeat_n(n, 300));
    v
}

pub fn descriptor(job: B256, d: u8) -> Vec<u8> {
    let mut v = job.to_vec();
    v.push(d);
    v.extend_from_slice(b"descriptor");
    v
}

pub fn job(n: u8) -> B256 {
    B256::repeat_byte(n)
}

pub fn witness(seed: u8, len: usize) -> Vec<u8> {
    (0..len).map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed)).collect()
}

fn po2(po2: u32, journal: &[u8]) -> Po2Result {
    Po2Result {
        po2,
        journal_hex: hex::encode(journal),
        journal_sha256: sha256(journal),
        cycles: 1 << 18,
        exit: GuestExit::Halted(0),
        segment_bytes: 4096,
    }
}

/// A record consistent with `w`, built with the shared binding helpers.
pub struct Spec {
    pub job: B256,
    pub desc: u8,
    pub prover: Address,
    pub prefix: bool,
    pub elf: u8,
    pub caller: Address,
    pub block: u64,
}

impl Spec {
    pub fn new(job: B256) -> Self {
        Spec { job, desc: 0, prover: prover(), prefix: true, elf: 1, caller: Address::repeat_byte(0xca), block: 100 }
    }

    pub fn bundle(&self, w: &[u8]) -> BundleV1 {
        let d = descriptor(self.job, self.desc);
        let prefix = self.prefix.then(|| journal_prefix(self.job, self.prover));
        let (input, len) = input_sha256(prefix.as_ref(), w).unwrap();
        let journal = [self.job.as_slice(), b"journal"].concat();
        BundleV1 {
            format_version: BUNDLE_FORMAT_VERSION,
            job_id: self.job,
            descriptor_hash: keccak256(&d),
            prover: self.prover,
            descriptor_hex: hex::encode(&d),
            submit_tx_hash: B256::repeat_byte(5),
            prefix: self.prefix,
            image_id: sha256(&elf(self.elf)),
            po2_results: vec![po2(19, &journal), po2(20, &journal)],
            input_sha256: input,
            w_sha256: sha256(w),
            w_len: len,
            sys_rand_key_fingerprint: B256::repeat_byte(6),
            keccak_po2: 17,
            worker_builds: vec!["cpu-test".into()],
            created_at_block: self.block,
            builder_id: B256::repeat_byte(9),
            caller: self.caller,
        }
    }
}

/// Streams `w` in `chunk`-byte pieces and publishes `b`.
pub fn publish(store: &Store, b: &BundleV1, w: &[u8], chunk: usize) -> Result<BundleRef, StoreError> {
    let mut wr = store.begin_bundle(b.job_id, b.descriptor_hash, b.prover, 1 << 30)?;
    for c in w.chunks(chunk.max(1)) {
        wr.write_w(c)?;
    }
    wr.finish(b, &desc_hash)
}

/// Puts the spec's ELF (dropping the hold) and publishes.
pub fn put_and_publish(store: &Store, spec: &Spec, w: &[u8]) -> BundleRef {
    drop(store.put_elf(sha256(&elf(spec.elf)), &elf(spec.elf), &image_id).unwrap());
    publish(store, &spec.bundle(w), w, 1000).unwrap()
}

pub fn make_writable(p: &Path) {
    fs::set_permissions(p, fs::Permissions::from_mode(0o644)).unwrap();
}

pub fn tmp_entries(root: &Path) -> usize {
    fs::read_dir(root.join("tmp")).unwrap().count()
}

pub fn assert_accounting(store: &Store) {
    assert_eq!(store.usage(), store.recount_usage().unwrap(), "in-memory usage matches a re-count");
}
