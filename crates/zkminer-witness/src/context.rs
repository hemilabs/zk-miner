//! The builder's input, `BuilderContextV1` (plan §9.2). It deliberately carries no `jobId` and no
//! prover address: the miner adds the journal prefix itself, and their absence denies a requester any
//! link between a staked prover and a simulating host.

use alloy_primitives::{Address, B256};
use alloy_sol_types::SolValue;

pub use crate::envelope::BuilderContextV1;
use crate::envelope::WitnessJobV1;

/// The descriptor fields the context copies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DescriptorFields {
    pub program_id: B256,
    pub proof_system_id: B256,
    pub expected_journal_hash: B256,
    pub journal_fields: B256,
}

/// Builds the context for a job: the envelope's sources, declared limits and params, plus the
/// chain, router and descriptor fields.
pub fn build_context(hemi_chain_id: u64, router: Address, d: &DescriptorFields, job: &WitnessJobV1) -> BuilderContextV1 {
    BuilderContextV1 {
        hemiChainId: hemi_chain_id,
        router,
        programId: d.program_id,
        proofSystemId: d.proof_system_id,
        expectedJournalHash: d.expected_journal_hash,
        journalFields: d.journal_fields,
        sources: job.sources.clone(),
        limits: job.limits.clone(),
        builderParams: job.builderParams.clone(),
    }
}

/// `abi.encode(ctx)` — the bytes `input_len`/`input_read` expose.
pub fn encode_context(ctx: &BuilderContextV1) -> Vec<u8> {
    ctx.abi_encode()
}

/// Decodes a context (used by the SDK's host-side tests and by tooling).
pub fn decode_context(bytes: &[u8]) -> Option<BuilderContextV1> {
    let ctx = BuilderContextV1::abi_decode(bytes).ok()?;
    (ctx.abi_encode() == bytes).then_some(ctx)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::tests::sample_job;

    #[test]
    fn round_trips_and_copies_declared_limits() {
        let job = sample_job();
        let d = DescriptorFields {
            program_id: B256::repeat_byte(1),
            proof_system_id: B256::repeat_byte(2),
            expected_journal_hash: B256::repeat_byte(3),
            journal_fields: B256::repeat_byte(4),
        };
        let ctx = build_context(743111, Address::repeat_byte(5), &d, &job);
        let bytes = encode_context(&ctx);
        assert_eq!(&bytes[..32], &B256::left_padding_from(&[0x20])[..]);
        assert_eq!(decode_context(&bytes).unwrap(), ctx);
        assert_eq!(ctx.limits, job.limits);
    }
}
