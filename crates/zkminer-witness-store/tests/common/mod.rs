#![allow(dead_code)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use alloy_primitives::{keccak256, Address, B256};
use sha2::{Digest, Sha256};
use zkminer_witness::binding::{input_sha256, journal_prefix};
use zkminer_witness::bundle::{BundleV1, GuestExit, PinRecord, Po2Result, BUNDLE_FORMAT_VERSION};
use zkminer_witness_store::{
    BundleRef, ExpectedIdentity, Store, StoreError, StoreIdentityInit, StoreOptions,
};

pub const CHAIN: u64 = 743_111;

pub fn router() -> Address {
    Address::repeat_byte(0x11)
}

pub fn prover() -> Address {
    Address::repeat_byte(0x22)
}

/// `target/tmp`: on the real disk (ext4 here), never tmpfs. Integration tests get it from Cargo;
/// the crate's unit tests (which include this module) derive it from the test binary's path,
/// `target/<profile>/deps/<binary>`.
pub fn target_tmp() -> PathBuf {
    let p = match option_env!("CARGO_TARGET_TMPDIR") {
        Some(p) => PathBuf::from(p),
        None => {
            let exe = std::env::current_exe().expect("test binary path");
            exe.ancestors().nth(3).expect("target dir").join("tmp")
        }
    };
    fs::create_dir_all(&p).expect("target/tmp");
    p
}

pub fn tmpdir() -> tempfile::TempDir {
    tempfile::Builder::new().prefix("wstore-").tempdir_in(target_tmp()).expect("tempdir")
}

pub fn init_id() -> StoreIdentityInit {
    StoreIdentityInit {
        chain_id: CHAIN,
        router: router(),
        prover: prover(),
        require_dedicated_mount: false,
        allow_any_filesystem: false,
    }
}

/// The identity this miner expects for the store at `dir` (its UUID read from `identity.json`, as
/// the miner's configuration would hold it).
pub fn expected(dir: &Path) -> ExpectedIdentity {
    ExpectedIdentity { chain_id: CHAIN, router: router(), prover: prover(), store_uuid: uuid_of(dir) }
}

pub fn uuid_of(dir: &Path) -> String {
    let v: serde_json::Value = serde_json::from_slice(&fs::read(dir.join("identity.json")).expect("identity.json"))
        .expect("identity parses");
    v["store_uuid"].as_str().expect("store_uuid").to_string()
}

pub fn opts() -> StoreOptions {
    StoreOptions {
        quota_bytes: 1 << 30,
        quota_inodes: 1_000_000,
        free_space_floor_bytes: 0,
        require_dedicated_mount: false,
        allow_any_filesystem: false,
    }
}

/// Initialises `dir` if it holds no store yet, then opens it.
pub fn open(dir: &Path) -> Store {
    open_with(dir, opts())
}

pub fn open_with(dir: &Path, o: StoreOptions) -> Store {
    if !dir.join("identity.json").exists() {
        Store::init(dir, &init_id()).expect("init");
    }
    Store::open(dir, &expected(dir), o).expect("open")
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

    /// The record for `w`, with `version` 0 (a writer's [`zkminer_witness_store::BundleWriter::version`]
    /// goes in before `finish`; see [`at`]).
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
            version: 0,
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

/// `b` as published at `version`.
pub fn at(b: &BundleV1, version: u32) -> BundleV1 {
    BundleV1 { version, ..b.clone() }
}

/// Streams `w` in `chunk`-byte pieces and publishes `b` at the writer's version.
pub fn publish(store: &Store, b: &BundleV1, w: &[u8], chunk: usize) -> Result<BundleRef, StoreError> {
    let mut wr = store.begin_bundle(b.job_id, b.descriptor_hash, b.prover, 1 << 30)?;
    for c in w.chunks(chunk.max(1)) {
        wr.write_w(c)?;
    }
    let b = at(b, wr.version());
    wr.finish(&b, &desc_hash)
}

/// Puts the spec's ELF (dropping the hold) and publishes.
pub fn put_and_publish(store: &Store, spec: &Spec, w: &[u8]) -> BundleRef {
    drop(store.put_elf(sha256(&elf(spec.elf)), &elf(spec.elf), &image_id).unwrap());
    publish(store, &spec.bundle(w), w, 1000).unwrap()
}

/// The pin record for `r` as the store has it.
pub fn pin_rec(store: &Store, r: &BundleRef) -> PinRecord {
    store.pin_record(r, 1234).expect("pin_record")
}

pub fn vdir(root: &Path, r: &BundleRef) -> PathBuf {
    root.join(format!(
        "bundles/{}/{}/{}/v{}",
        hex::encode(r.job_id),
        hex::encode(r.descriptor_hash),
        hex::encode(r.prover),
        r.version
    ))
}

pub fn pin_file(root: &Path, r: &BundleRef) -> PathBuf {
    root.join("pins").join(format!(
        "{}.{}.{}.json",
        hex::encode(r.job_id),
        hex::encode(r.descriptor_hash),
        hex::encode(r.prover)
    ))
}

pub fn make_writable(p: &Path) {
    fs::set_permissions(p, fs::Permissions::from_mode(0o644)).unwrap();
}

pub fn tmp_entries(root: &Path) -> usize {
    fs::read_dir(root.join("tmp")).unwrap().count()
}

/// Usage without the version counter, whose length grows as writers reserve numbers.
pub fn data_usage(store: &Store, root: &Path) -> zkminer_witness_store::Usage {
    let mut u = store.usage();
    u.bytes -= fs::metadata(root.join("next_version")).unwrap().len();
    u
}

pub fn assert_accounting(store: &Store) {
    assert_eq!(store.usage(), store.recount_usage().unwrap(), "in-memory usage matches a re-count");
}

/// Every path and file under `p` with its contents (symlinks as their targets), for proving a
/// tree outside the store was never touched.
pub fn snapshot(p: &Path) -> Vec<(PathBuf, String)> {
    let mut out = Vec::new();
    fn walk(base: &Path, p: &Path, out: &mut Vec<(PathBuf, String)>) {
        let m = fs::symlink_metadata(p).unwrap();
        let rel = p.strip_prefix(base).unwrap().to_path_buf();
        if m.file_type().is_symlink() {
            out.push((rel, format!("-> {}", fs::read_link(p).unwrap().display())));
        } else if m.is_dir() {
            out.push((rel, "dir".into()));
            let mut es: Vec<_> = fs::read_dir(p).unwrap().map(|e| e.unwrap().path()).collect();
            es.sort();
            for e in es {
                walk(base, &e, out);
            }
        } else {
            out.push((rel, hex::encode(sha256(&fs::read(p).unwrap()))));
        }
    }
    walk(p, p, &mut out);
    out
}
