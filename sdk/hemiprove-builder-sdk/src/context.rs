//! `BuilderContextV1`, decoded from `abi.encode(ctx)` (zkminer docs/witness-construction-jobs.md
//! §9.2). Decoding is bounds-checked everywhere and allocates only what the input holds.

use core::fmt;

/// The envelope's declared limits (never the host's clamps).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Limits {
    pub max_fetches: u32,
    pub max_fetch_bytes: u64,
    pub max_request_bytes: u32,
    pub max_response_bytes: u32,
    pub max_builder_fuel: u64,
    pub max_builder_memory_bytes: u64,
    pub max_builder_seconds: u32,
    pub max_witness_bytes: u64,
    pub max_guest_cycles: u64,
}

/// A declared data source. `fetch(cap, …)` addresses `Context::sources[cap]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capability {
    pub class: [u8; 32],
    pub config: Vec<u8>,
}

/// The builder's input. It carries no job id and no prover address, by design.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Context {
    pub hemi_chain_id: u64,
    pub router: [u8; 20],
    pub program_id: [u8; 32],
    pub proof_system_id: [u8; 32],
    pub expected_journal_hash: [u8; 32],
    pub journal_fields: [u8; 32],
    pub sources: Vec<Capability>,
    pub limits: Limits,
    pub builder_params: Vec<u8>,
}

/// `evm-rpc/v1`'s capability config: `abi.encode(uint64 chainId, bool archive, bytes32 methodSet,
/// uint64 maxProofAge)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EvmRpcConfig {
    pub chain_id: u64,
    pub archive: bool,
    pub method_set: [u8; 32],
    pub max_proof_age: u64,
}

/// Malformed ABI input; `at` is the byte offset where decoding failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecodeError {
    pub at: usize,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "malformed ABI encoding at byte {}", self.at)
    }
}

struct Abi<'a>(&'a [u8]);

impl<'a> Abi<'a> {
    fn word(&self, at: usize) -> Result<&'a [u8; 32], DecodeError> {
        let end = at.checked_add(32).ok_or(DecodeError { at })?;
        self.0.get(at..end).map(|w| w.try_into().unwrap()).ok_or(DecodeError { at })
    }

    /// An unsigned integer of `bytes` bytes, right-aligned in its word with zero high bytes.
    fn uint(&self, at: usize, bytes: usize) -> Result<u64, DecodeError> {
        let w = self.word(at)?;
        if w[..32 - bytes].iter().any(|&b| b != 0) {
            return Err(DecodeError { at });
        }
        Ok(w[32 - bytes..].iter().fold(0u64, |acc, &b| (acc << 8) | u64::from(b)))
    }

    /// A dynamic member's offset word, relative to `base`, as an absolute position in the input.
    fn offset(&self, at: usize, base: usize) -> Result<usize, DecodeError> {
        let off = self.uint(at, 8)?;
        let pos = usize::try_from(off).ok().and_then(|o| o.checked_add(base)).ok_or(DecodeError { at })?;
        if pos > self.0.len() {
            return Err(DecodeError { at });
        }
        Ok(pos)
    }

    /// `bytes` at `at`: a length word, then the data.
    fn bytes(&self, at: usize) -> Result<Vec<u8>, DecodeError> {
        let len = self.uint(at, 8)?;
        let start = at + 32;
        let end = usize::try_from(len).ok().and_then(|l| start.checked_add(l)).ok_or(DecodeError { at })?;
        self.0.get(start..end).map(<[u8]>::to_vec).ok_or(DecodeError { at })
    }

    fn bytes32(&self, at: usize) -> Result<[u8; 32], DecodeError> {
        self.word(at).copied()
    }
}

impl Context {
    /// Decodes `abi.encode(BuilderContextV1)` (its `0x20` head word first).
    pub fn decode(input: &[u8]) -> Result<Self, DecodeError> {
        let abi = Abi(input);
        if abi.uint(0, 8)? != 0x20 {
            return Err(DecodeError { at: 0 });
        }
        let base = 32;
        let head = |i: usize| base + 32 * i;
        let router_word = abi.word(head(1))?;
        if router_word[..12].iter().any(|&b| b != 0) {
            return Err(DecodeError { at: head(1) });
        }
        let limits = Limits {
            max_fetches: abi.uint(head(7), 4)? as u32,
            max_fetch_bytes: abi.uint(head(8), 8)?,
            max_request_bytes: abi.uint(head(9), 4)? as u32,
            max_response_bytes: abi.uint(head(10), 4)? as u32,
            max_builder_fuel: abi.uint(head(11), 8)?,
            max_builder_memory_bytes: abi.uint(head(12), 8)?,
            max_builder_seconds: abi.uint(head(13), 4)? as u32,
            max_witness_bytes: abi.uint(head(14), 8)?,
            max_guest_cycles: abi.uint(head(15), 8)?,
        };

        let sources_at = abi.offset(head(6), base)?;
        let count = abi.uint(sources_at, 8)?;
        let elems = sources_at + 32;
        // Each element needs at least its offset word: bounds the allocation by the input.
        if count > (input.len().saturating_sub(elems) / 32) as u64 {
            return Err(DecodeError { at: sources_at });
        }
        let mut sources = Vec::with_capacity(count as usize);
        for i in 0..count as usize {
            let el = abi.offset(elems + 32 * i, elems)?;
            let config_at = abi.offset(el + 32, el)?;
            sources.push(Capability { class: abi.bytes32(el)?, config: abi.bytes(config_at)? });
        }
        let params_at = abi.offset(head(16), base)?;

        Ok(Self {
            hemi_chain_id: abi.uint(head(0), 8)?,
            router: router_word[12..].try_into().unwrap(),
            program_id: abi.bytes32(head(2))?,
            proof_system_id: abi.bytes32(head(3))?,
            expected_journal_hash: abi.bytes32(head(4))?,
            journal_fields: abi.bytes32(head(5))?,
            sources,
            limits,
            builder_params: abi.bytes(params_at)?,
        })
    }
}

impl EvmRpcConfig {
    /// Decodes an `evm-rpc/v1` capability config.
    pub fn decode(config: &[u8]) -> Result<Self, DecodeError> {
        let abi = Abi(config);
        if config.len() != 128 {
            return Err(DecodeError { at: config.len().min(128) });
        }
        let archive = match abi.uint(32, 1)? {
            0 => false,
            1 => true,
            _ => return Err(DecodeError { at: 32 }),
        };
        Ok(Self { chain_id: abi.uint(0, 8)?, archive, method_set: abi.bytes32(64)?, max_proof_age: abi.uint(96, 8)? })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn word(v: u64) -> [u8; 32] {
        let mut w = [0u8; 32];
        w[24..].copy_from_slice(&v.to_be_bytes());
        w
    }

    fn padded(data: &[u8]) -> Vec<u8> {
        let mut out = word(data.len() as u64).to_vec();
        out.extend_from_slice(data);
        out.resize(32 + data.len().div_ceil(32) * 32, 0);
        out
    }

    /// Encodes a context the way Solidity's `abi.encode` does.
    pub(crate) fn encode(c: &Context) -> Vec<u8> {
        let mut head = Vec::new();
        head.extend_from_slice(&word(c.hemi_chain_id));
        let mut router = [0u8; 32];
        router[12..].copy_from_slice(&c.router);
        head.extend_from_slice(&router);
        for w in [c.program_id, c.proof_system_id, c.expected_journal_hash, c.journal_fields] {
            head.extend_from_slice(&w);
        }
        let l = &c.limits;
        let limit_words = [
            l.max_fetches as u64,
            l.max_fetch_bytes,
            l.max_request_bytes as u64,
            l.max_response_bytes as u64,
            l.max_builder_fuel,
            l.max_builder_memory_bytes,
            l.max_builder_seconds as u64,
            l.max_witness_bytes,
            l.max_guest_cycles,
        ];
        // sources
        let mut sources = word(c.sources.len() as u64).to_vec();
        let mut elems: Vec<Vec<u8>> = Vec::new();
        for s in &c.sources {
            let mut e = s.class.to_vec();
            e.extend_from_slice(&word(64));
            e.extend_from_slice(&padded(&s.config));
            elems.push(e);
        }
        let mut off = 32 * elems.len() as u64;
        for e in &elems {
            sources.extend_from_slice(&word(off));
            off += e.len() as u64;
        }
        for e in &elems {
            sources.extend_from_slice(e);
        }
        let head_len = 17 * 32;
        head.extend_from_slice(&word(head_len as u64));
        for v in limit_words {
            head.extend_from_slice(&word(v));
        }
        head.extend_from_slice(&word((head_len + sources.len()) as u64));
        let mut out = word(0x20).to_vec();
        out.extend_from_slice(&head);
        out.extend_from_slice(&sources);
        out.extend_from_slice(&padded(&c.builder_params));
        out
    }

    pub(crate) fn sample() -> Context {
        Context {
            hemi_chain_id: 743_111,
            router: [5; 20],
            program_id: [1; 32],
            proof_system_id: [2; 32],
            expected_journal_hash: [3; 32],
            journal_fields: [4; 32],
            sources: vec![
                Capability { class: crate::CLASS_EVM_RPC_V1, config: (0..128).collect() },
                Capability { class: crate::CLASS_BLOB_V1, config: vec![9; 33] },
            ],
            limits: Limits {
                max_fetches: 100,
                max_fetch_bytes: 1 << 24,
                max_request_bytes: 65_536,
                max_response_bytes: 1 << 20,
                max_builder_fuel: 1 << 32,
                max_builder_memory_bytes: 1 << 28,
                max_builder_seconds: 60,
                max_witness_bytes: 1 << 25,
                max_guest_cycles: 1 << 30,
            },
            builder_params: vec![1, 2, 3],
        }
    }

    #[test]
    fn round_trips() {
        let c = sample();
        assert_eq!(Context::decode(&encode(&c)).unwrap(), c);
        let empty = Context { sources: vec![], builder_params: vec![], ..sample() };
        assert_eq!(Context::decode(&encode(&empty)).unwrap(), empty);
    }

    #[test]
    fn every_truncation_fails_cleanly() {
        let bytes = encode(&sample());
        for n in 0..bytes.len() - 1 {
            // Trailing padding of the last member is not needed to decode it; the rest is.
            if n >= bytes.len() - 29 {
                continue;
            }
            assert!(Context::decode(&bytes[..n]).is_err(), "prefix {n}");
        }
    }

    #[test]
    fn rejects_dirty_words_and_huge_counts() {
        let mut b = encode(&sample());
        b[31] = 0x40;
        assert!(Context::decode(&b).is_err(), "head word");
        let mut b = encode(&sample());
        b[32 + 32] = 1; // router's high bytes
        assert!(Context::decode(&b).is_err());
        let mut b = encode(&sample());
        b[32 + 7 * 32 + 27] = 1; // maxFetches is a uint32
        assert!(Context::decode(&b).is_err());
        let mut b = encode(&sample());
        let sources_at = 32 + 17 * 32;
        b[sources_at + 24..sources_at + 32].copy_from_slice(&u64::MAX.to_be_bytes());
        assert!(Context::decode(&b).is_err(), "a count larger than the input");
    }

    #[test]
    fn evm_rpc_config() {
        let mut cfg = word(8453).to_vec();
        cfg.extend_from_slice(&word(1));
        cfg.extend_from_slice(&crate::METHOD_SET_STATE_READ);
        cfg.extend_from_slice(&word(300));
        let d = EvmRpcConfig::decode(&cfg).unwrap();
        assert_eq!(
            d,
            EvmRpcConfig {
                chain_id: 8453,
                archive: true,
                method_set: crate::METHOD_SET_STATE_READ,
                max_proof_age: 300
            }
        );
        cfg[63] = 2;
        assert!(EvmRpcConfig::decode(&cfg).is_err());
        assert!(EvmRpcConfig::decode(&cfg[..96]).is_err());
    }
}
