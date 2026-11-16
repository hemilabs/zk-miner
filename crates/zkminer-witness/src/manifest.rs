//! `hemi-code` artifact manifests and chunks (plan §13.2, §13.4).
//!
//! A chunk is a data contract whose runtime code is `0x00 ‖ chunk` (at most 24,575 bytes of body).
//! The artifact manifest is a data contract whose runtime code is exactly `77 + 20n` bytes:
//! `0x00 ‖ ARTIFACT_MANIFEST_TAG_V1 (32) ‖ length (u64 BE) ‖ sha256 (32) ‖ n (u32 BE) ‖ n × address`.

use std::io::Write;

use alloy_primitives::{b256, Address, B256};
use sha2::{Digest, Sha256};

/// `keccak256("hemiprove.artifact-manifest.v1")`.
pub const ARTIFACT_MANIFEST_TAG_V1: B256 =
    b256!("2c32d42729ca2ebf1a99d2e3ef5185dcbe8268aa20f771babcb6ea05baf41b0a");

/// EIP-170 code-size limit.
pub const MAX_CODE_BYTES: usize = 24_576;
/// The largest chunk body (one byte goes to the `0x00` prefix).
pub const MAX_CHUNK_BODY: usize = MAX_CODE_BYTES - 1;
/// Manifest code length without addresses: prefix + tag + length + sha256 + n.
pub const MANIFEST_FIXED_BYTES: usize = 1 + 32 + 8 + 32 + 4;
/// The most addresses that fit in one manifest contract.
pub const MAX_MANIFEST_CHUNKS: u32 = ((MAX_CODE_BYTES - MANIFEST_FIXED_BYTES) / 20) as u32;

/// A validated manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactManifest {
    pub length: u64,
    pub sha256: [u8; 32],
    pub chunks: Vec<Address>,
}

/// Structural failures are permanent for a manifest address (when read at or below the safe head);
/// an id mismatch is bad only for the (manifest, builderId) pair (plan §13.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ManifestError {
    #[error("no code at the manifest address")]
    Empty,
    #[error("manifest code is malformed")]
    Structural(ManifestDefect),
    #[error("manifest length is above the operator's maximum artifact size")]
    TooLarge,
    #[error("manifest sha256 does not equal the job's builderId")]
    IdMismatch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManifestDefect {
    TooShort,
    Prefix,
    Tag,
    ChunkCount,
    CodeLength,
    ZeroLength,
    LengthVsChunks,
    DuplicateAddress,
    SelfReference,
}

/// Validates manifest code in the order of plan §13.4 step 2. `expected_sha256` is `Some(builderId)`
/// for builder types whose id is the sha256 (types 1 and 3), `None` otherwise.
pub fn parse_manifest(
    code: &[u8],
    own_address: Address,
    max_artifact_bytes: u64,
    expected_sha256: Option<&[u8; 32]>,
) -> Result<ArtifactManifest, ManifestError> {
    use ManifestDefect as D;
    let s = |d| Err(ManifestError::Structural(d));
    if code.is_empty() {
        return Err(ManifestError::Empty);
    }
    if code.len() < MANIFEST_FIXED_BYTES {
        return s(D::TooShort);
    }
    if code[0] != 0x00 {
        return s(D::Prefix);
    }
    if code[1..33] != ARTIFACT_MANIFEST_TAG_V1[..] {
        return s(D::Tag);
    }
    let length = u64::from_be_bytes(code[33..41].try_into().unwrap());
    let mut sha256 = [0u8; 32];
    sha256.copy_from_slice(&code[41..73]);
    let n = u32::from_be_bytes(code[73..77].try_into().unwrap());
    if n == 0 || n > MAX_MANIFEST_CHUNKS {
        return s(D::ChunkCount);
    }
    let expected_len = (MANIFEST_FIXED_BYTES as u64) + 20 * u64::from(n);
    if code.len() as u64 != expected_len {
        return s(D::CodeLength);
    }
    if length == 0 {
        return s(D::ZeroLength);
    }
    let min_chunks = length.div_ceil(MAX_CHUNK_BODY as u64);
    if u64::from(n) < min_chunks || u64::from(n) > length {
        return s(D::LengthVsChunks);
    }
    if length > max_artifact_bytes {
        return Err(ManifestError::TooLarge);
    }
    if let Some(expected) = expected_sha256 {
        if &sha256 != expected {
            return Err(ManifestError::IdMismatch);
        }
    }
    let mut chunks = Vec::with_capacity(n as usize);
    let mut seen = std::collections::HashSet::with_capacity(n as usize);
    for i in 0..n as usize {
        let a = Address::from_slice(&code[77 + 20 * i..77 + 20 * (i + 1)]);
        if a == own_address {
            return s(D::SelfReference);
        }
        if !seen.insert(a) {
            return s(D::DuplicateAddress);
        }
        chunks.push(a);
    }
    Ok(ArtifactManifest { length, sha256, chunks })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ChunkError {
    #[error("no code at the chunk address")]
    Empty,
    #[error("chunk code does not start with 0x00")]
    Prefix,
    #[error("chunk body is empty or longer than {MAX_CHUNK_BODY} bytes")]
    BodySize,
}

/// Returns the body of a chunk's runtime code (plan §13.4 step 4).
pub fn chunk_body(code: &[u8]) -> Result<&[u8], ChunkError> {
    if code.is_empty() {
        return Err(ChunkError::Empty);
    }
    if code[0] != 0x00 {
        return Err(ChunkError::Prefix);
    }
    let body = &code[1..];
    if body.is_empty() || body.len() > MAX_CHUNK_BODY {
        return Err(ChunkError::BodySize);
    }
    Ok(body)
}

/// Incrementally assembles an artifact from chunk bodies into `sink` and verifies it (plan §13.4
/// steps 4–5): exactly the manifest's `n` chunks, at most `length` bytes at any point, exactly
/// `length` at the end, hashing to the manifest's sha256. The broker passes a memfd so a 30 MB
/// artifact is never held in a `Vec`.
pub struct Assembler<W: Write> {
    expected_len: u64,
    expected_chunks: usize,
    expected_sha256: [u8; 32],
    hasher: Sha256,
    written: u64,
    chunks: usize,
    sink: W,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AssembleError {
    #[error("more chunks than the manifest lists")]
    TooManyChunks,
    #[error("fewer chunks than the manifest lists")]
    TooFewChunks,
    #[error("chunks exceed the manifest length")]
    TooLong,
    #[error("chunks total less than the manifest length")]
    TooShort,
    #[error("assembled bytes do not hash to the manifest sha256")]
    HashMismatch,
    #[error("writing the assembled bytes failed: {0:?}")]
    Io(std::io::ErrorKind),
}

impl<W: Write> Assembler<W> {
    pub fn new(manifest: &ArtifactManifest, sink: W) -> Self {
        Self {
            expected_len: manifest.length,
            expected_chunks: manifest.chunks.len(),
            expected_sha256: manifest.sha256,
            hasher: Sha256::new(),
            written: 0,
            chunks: 0,
            sink,
        }
    }

    /// Appends one chunk body (already checked with [`chunk_body`]).
    pub fn push(&mut self, body: &[u8]) -> Result<(), AssembleError> {
        if self.chunks >= self.expected_chunks {
            return Err(AssembleError::TooManyChunks);
        }
        if self.written + body.len() as u64 > self.expected_len {
            return Err(AssembleError::TooLong);
        }
        self.sink.write_all(body).map_err(|e| AssembleError::Io(e.kind()))?;
        self.hasher.update(body);
        self.written += body.len() as u64;
        self.chunks += 1;
        Ok(())
    }

    /// Verifies the totals and the hash and returns the sink.
    pub fn finish(mut self) -> Result<W, AssembleError> {
        if self.chunks < self.expected_chunks {
            return Err(AssembleError::TooFewChunks);
        }
        if self.written < self.expected_len {
            return Err(AssembleError::TooShort);
        }
        let got: [u8; 32] = self.hasher.finalize().into();
        if got != self.expected_sha256 {
            return Err(AssembleError::HashMismatch);
        }
        self.sink.flush().map_err(|e| AssembleError::Io(e.kind()))?;
        Ok(self.sink)
    }
}

/// Publisher side: the runtime code of a chunk.
pub fn chunk_runtime_code(body: &[u8]) -> Vec<u8> {
    assert!(!body.is_empty() && body.len() <= MAX_CHUNK_BODY);
    let mut code = Vec::with_capacity(body.len() + 1);
    code.push(0x00);
    code.extend_from_slice(body);
    code
}

/// Publisher side: the runtime code of a manifest.
pub fn manifest_runtime_code(length: u64, sha256: &[u8; 32], chunks: &[Address]) -> Vec<u8> {
    assert!(!chunks.is_empty() && chunks.len() as u32 <= MAX_MANIFEST_CHUNKS);
    let mut code = Vec::with_capacity(MANIFEST_FIXED_BYTES + 20 * chunks.len());
    code.push(0x00);
    code.extend_from_slice(ARTIFACT_MANIFEST_TAG_V1.as_slice());
    code.extend_from_slice(&length.to_be_bytes());
    code.extend_from_slice(sha256);
    code.extend_from_slice(&(chunks.len() as u32).to_be_bytes());
    for a in chunks {
        code.extend_from_slice(a.as_slice());
    }
    code
}

/// Publisher side: CREATE init code that deploys `runtime` verbatim
/// (`PUSH4 len; DUP1; PUSH1 0x0e; PUSH1 0; CODECOPY; PUSH1 0; RETURN` ‖ runtime).
pub fn creation_code(runtime: &[u8]) -> Vec<u8> {
    let len = u32::try_from(runtime.len()).expect("runtime fits in u32");
    let mut code = Vec::with_capacity(14 + runtime.len());
    code.push(0x63);
    code.extend_from_slice(&len.to_be_bytes());
    code.extend_from_slice(&[0x80, 0x60, 0x0e, 0x60, 0x00, 0x39, 0x60, 0x00, 0xf3]);
    code.extend_from_slice(runtime);
    code
}

/// `sha256(bytes)`.
pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::keccak256;

    fn addr(i: u8) -> Address {
        Address::repeat_byte(i)
    }

    #[test]
    fn constants() {
        assert_eq!(ARTIFACT_MANIFEST_TAG_V1, keccak256("hemiprove.artifact-manifest.v1"));
        assert_eq!(MANIFEST_FIXED_BYTES, 77);
        assert_eq!(MAX_MANIFEST_CHUNKS, 1_224);
        const _: () = assert!(MANIFEST_FIXED_BYTES + 20 * 1_224 <= MAX_CODE_BYTES);
        const _: () = assert!(MANIFEST_FIXED_BYTES + 20 * 1_225 > MAX_CODE_BYTES);
        assert_eq!(u64::from(MAX_MANIFEST_CHUNKS) * MAX_CHUNK_BODY as u64, 30_079_800);
    }

    #[test]
    fn round_trip_and_assemble() {
        let artifact: Vec<u8> = (0..60_000u32).map(|i| (i % 251) as u8).collect();
        let bodies: Vec<&[u8]> = artifact.chunks(23_000).collect();
        let chunks: Vec<Address> = (1..=bodies.len() as u8).map(addr).collect();
        let sha = sha256(&artifact);
        let code = manifest_runtime_code(artifact.len() as u64, &sha, &chunks);
        let m = parse_manifest(&code, addr(0xff), 1 << 30, Some(&sha)).unwrap();
        assert_eq!(m.chunks, chunks);
        let mut a = Assembler::new(&m, Vec::new());
        for b in &bodies {
            let code = chunk_runtime_code(b);
            a.push(chunk_body(&code).unwrap()).unwrap();
        }
        assert_eq!(a.finish().unwrap(), artifact);
    }

    #[test]
    fn manifest_checks_in_order() {
        let sha = [7u8; 32];
        let good = manifest_runtime_code(100, &sha, &[addr(1)]);
        assert_eq!(parse_manifest(&[], addr(9), 1 << 20, None), Err(ManifestError::Empty));
        assert_eq!(
            parse_manifest(&good[..50], addr(9), 1 << 20, None),
            Err(ManifestError::Structural(ManifestDefect::TooShort))
        );
        let mut c = good.clone();
        c[0] = 0xef;
        assert_eq!(parse_manifest(&c, addr(9), 1 << 20, None), Err(ManifestError::Structural(ManifestDefect::Prefix)));
        let mut c = good.clone();
        c[5] ^= 1;
        assert_eq!(parse_manifest(&c, addr(9), 1 << 20, None), Err(ManifestError::Structural(ManifestDefect::Tag)));
        // n = huge: rejected before the length arithmetic.
        let mut c = good.clone();
        c[73..77].copy_from_slice(&u32::MAX.to_be_bytes());
        assert_eq!(parse_manifest(&c, addr(9), 1 << 20, None), Err(ManifestError::Structural(ManifestDefect::ChunkCount)));
        let mut c = good.clone();
        c.extend_from_slice(&[0u8; 20]);
        assert_eq!(parse_manifest(&c, addr(9), 1 << 20, None), Err(ManifestError::Structural(ManifestDefect::CodeLength)));
        let z = manifest_runtime_code(0, &sha, &[addr(1)]);
        assert_eq!(parse_manifest(&z, addr(9), 1 << 20, None), Err(ManifestError::Structural(ManifestDefect::ZeroLength)));
        // 30,000 bytes need at least two chunks.
        let short = manifest_runtime_code(30_000, &sha, &[addr(1)]);
        assert_eq!(parse_manifest(&short, addr(9), 1 << 20, None), Err(ManifestError::Structural(ManifestDefect::LengthVsChunks)));
        // n > length: 1,224 one-byte chunks for a 3-byte artifact.
        let many: Vec<Address> = (0..4u8).map(addr).collect();
        let m = manifest_runtime_code(3, &sha, &many);
        assert_eq!(parse_manifest(&m, addr(99), 1 << 20, None), Err(ManifestError::Structural(ManifestDefect::LengthVsChunks)));
        assert_eq!(parse_manifest(&good, addr(9), 99, None), Err(ManifestError::TooLarge));
        assert_eq!(parse_manifest(&good, addr(9), 1 << 20, Some(&[8u8; 32])), Err(ManifestError::IdMismatch));
        let dup = manifest_runtime_code(100, &sha, &[addr(1), addr(1)]);
        assert_eq!(parse_manifest(&dup, addr(9), 1 << 20, None), Err(ManifestError::Structural(ManifestDefect::DuplicateAddress)));
        assert_eq!(parse_manifest(&good, addr(1), 1 << 20, None), Err(ManifestError::Structural(ManifestDefect::SelfReference)));
    }

    #[test]
    fn chunk_checks_and_assembler_bounds() {
        assert_eq!(chunk_body(&[]), Err(ChunkError::Empty));
        assert_eq!(chunk_body(&[0xef, 0x01, 0x00]), Err(ChunkError::Prefix), "a 7702 designator is refused");
        assert_eq!(chunk_body(&[0x00]), Err(ChunkError::BodySize));
        let m = ArtifactManifest { length: 4, sha256: sha256(b"abcd"), chunks: vec![addr(1), addr(2)] };
        let mut a = Assembler::new(&m, Vec::new());
        a.push(b"abc").unwrap();
        assert_eq!(a.push(b"de"), Err(AssembleError::TooLong));
        let mut a = Assembler::new(&m, Vec::new());
        a.push(b"ab").unwrap();
        assert_eq!(a.finish(), Err(AssembleError::TooFewChunks));
        let mut a = Assembler::new(&m, Vec::new());
        a.push(b"ab").unwrap();
        a.push(b"c").unwrap();
        assert_eq!(a.finish(), Err(AssembleError::TooShort));
        let mut a = Assembler::new(&m, Vec::new());
        a.push(b"ab").unwrap();
        a.push(b"ce").unwrap();
        assert_eq!(a.finish(), Err(AssembleError::HashMismatch));
        // Three chunks listed: two bodies that already total `length` do not finish the artifact.
        let m3 = ArtifactManifest { length: 4, sha256: sha256(b"abcd"), chunks: vec![addr(1), addr(2), addr(3)] };
        let mut a = Assembler::new(&m3, Vec::new());
        a.push(b"ab").unwrap();
        a.push(b"cd").unwrap();
        assert_eq!(a.finish(), Err(AssembleError::TooFewChunks));
        let mut a = Assembler::new(&m, Vec::new());
        a.push(b"a").unwrap();
        a.push(b"b").unwrap();
        assert_eq!(a.push(b"c"), Err(AssembleError::TooManyChunks));
    }

    #[test]
    fn adjacent_checks_fail_in_order() {
        use ManifestDefect as D;
        let sha = [7u8; 32];
        let p = |c: &[u8], own: Address, max: u64, id: Option<&[u8; 32]>| parse_manifest(c, own, max, id);
        // Prefix before Tag.
        let mut c = manifest_runtime_code(100, &sha, &[addr(1)]);
        c[0] = 1;
        c[5] ^= 1;
        assert_eq!(p(&c, addr(9), 1 << 20, None), Err(ManifestError::Structural(D::Prefix)));
        // Tag before ChunkCount.
        let mut c = manifest_runtime_code(100, &sha, &[addr(1)]);
        c[5] ^= 1;
        c[73..77].copy_from_slice(&0u32.to_be_bytes());
        assert_eq!(p(&c, addr(9), 1 << 20, None), Err(ManifestError::Structural(D::Tag)));
        // CodeLength before ZeroLength.
        let mut c = manifest_runtime_code(0, &sha, &[addr(1)]);
        c.push(0);
        assert_eq!(p(&c, addr(9), 1 << 20, None), Err(ManifestError::Structural(D::CodeLength)));
        // ZeroLength before TooLarge.
        let c = manifest_runtime_code(0, &sha, &[addr(1)]);
        assert_eq!(p(&c, addr(9), 0, None), Err(ManifestError::Structural(D::ZeroLength)));
        // LengthVsChunks before TooLarge.
        let c = manifest_runtime_code(30_000, &sha, &[addr(1)]);
        assert_eq!(p(&c, addr(9), 10, None), Err(ManifestError::Structural(D::LengthVsChunks)));
        // TooLarge before IdMismatch.
        let c = manifest_runtime_code(100, &sha, &[addr(1)]);
        assert_eq!(p(&c, addr(9), 99, Some(&[8u8; 32])), Err(ManifestError::TooLarge));
        // IdMismatch before DuplicateAddress and SelfReference.
        let c = manifest_runtime_code(100, &sha, &[addr(9), addr(9)]);
        assert_eq!(p(&c, addr(9), 1 << 20, Some(&[8u8; 32])), Err(ManifestError::IdMismatch));
        // SelfReference and DuplicateAddress: whichever address comes first.
        assert_eq!(p(&c, addr(9), 1 << 20, None), Err(ManifestError::Structural(D::SelfReference)));
    }

    #[test]
    fn manifest_bounds() {
        let sha = [7u8; 32];
        let many = |n: u32| -> Vec<Address> {
            (0..n).map(|i| { let mut a = [0u8; 20]; a[16..].copy_from_slice(&(i + 1).to_be_bytes()); Address::from(a) }).collect()
        };
        let max_len = u64::from(MAX_MANIFEST_CHUNKS) * MAX_CHUNK_BODY as u64;
        let c = manifest_runtime_code(max_len, &sha, &many(MAX_MANIFEST_CHUNKS));
        assert_eq!(c.len(), 24_557);
        assert!(parse_manifest(&c, Address::ZERO, u64::MAX, None).is_ok());
        assert_eq!(
            parse_manifest(&manifest_runtime_code(max_len + 1, &sha, &many(MAX_MANIFEST_CHUNKS)), Address::ZERO, u64::MAX, None),
            Err(ManifestError::Structural(ManifestDefect::LengthVsChunks))
        );
        // n = 1,225 cannot be written by the publisher; craft it.
        let mut c = manifest_runtime_code(1_225, &sha, &many(MAX_MANIFEST_CHUNKS));
        c[73..77].copy_from_slice(&1_225u32.to_be_bytes());
        c.extend_from_slice(&[0xee; 20]);
        assert_eq!(parse_manifest(&c, Address::ZERO, u64::MAX, None), Err(ManifestError::Structural(ManifestDefect::ChunkCount)));
        // length = n: every chunk one byte.
        assert!(parse_manifest(&manifest_runtime_code(5, &sha, &many(5)), Address::ZERO, u64::MAX, None).is_ok());
        // Code lengths of 77 + 20n ± 1.
        let good = manifest_runtime_code(100, &sha, &many(2));
        assert_eq!(parse_manifest(&good[..good.len() - 1], Address::ZERO, u64::MAX, None), Err(ManifestError::Structural(ManifestDefect::CodeLength)));
        let mut long = good.clone();
        long.push(0);
        assert_eq!(parse_manifest(&long, Address::ZERO, u64::MAX, None), Err(ManifestError::Structural(ManifestDefect::CodeLength)));
        // An EIP-7702 designator (23 bytes) is too short to be a manifest.
        let mut d = vec![0xef, 0x01, 0x00];
        d.extend_from_slice(&[0x42; 20]);
        assert_eq!(parse_manifest(&d, Address::ZERO, u64::MAX, None), Err(ManifestError::Structural(ManifestDefect::TooShort)));
    }

    #[test]
    fn creation_code_layout() {
        let rt = chunk_runtime_code(b"hello");
        let cc = creation_code(&rt);
        assert_eq!(cc[0], 0x63);
        assert_eq!(&cc[1..5], &(rt.len() as u32).to_be_bytes());
        assert_eq!(cc.len(), 14 + rt.len());
        assert_eq!(&cc[14..], &rt[..]);
    }

    proptest::proptest! {
        #[test]
        fn parse_never_panics(code in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..400)) {
            let _ = parse_manifest(&code, Address::ZERO, u64::MAX, None);
        }
    }
}
