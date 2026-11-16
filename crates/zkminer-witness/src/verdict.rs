//! Local verdicts (plan §16): a fixed set of reasons, each with a retry class. No attacker-controlled
//! strings are ever stored in a verdict.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum VerdictClass {
    /// Never retried for this job.
    PermanentForJob,
    /// One jittered retry on other endpoints, then permanent for the job.
    RetryOnceThenPermanent,
    /// Retried with backoff, bounded per job.
    Transient,
    /// The operator's own resources failed: retried, never counted against the caller.
    OperatorSide,
    /// Not a failure of the job: deferred and re-evaluated later (e.g. a probation clamp).
    Deferred,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SkipReason {
    // Static gates.
    EnvelopeMalformed,
    EnvelopeOutOfRange,
    UnsupportedBuilderType,
    UnsupportedProofSystem,
    UnsupportedBinding,
    UnsupportedSubmission,
    DeploymentNotVerified,
    CapabilityNotProvisioned,
    LimitsAboveHostMaxima,
    NotClaimable,
    NotAdmitted,
    WitnessDisabled,
    // Guest ELF.
    ElfUnavailable,
    ElfImageIdMismatch,
    // Builder artifact.
    ArtifactAllSourcesBad,
    ArtifactUnavailable,
    // Builder run.
    BuilderInvalidModule,
    BuilderUnknownImport,
    BuilderTrap,
    BuilderFuelExhausted,
    BuilderMemoryExhausted,
    BuilderNonZeroReturn,
    BuilderWitnessTooLarge,
    BuilderTransient,
    BuilderWallClock,
    BuilderClampedByProbation,
    // Guest execution.
    GuestFailed,
    GuestCyclesAboveLimit,
    BindingMismatch,
    JournalsDifferAcrossPo2,
    // Claim gate.
    JournalTooLarge,
    FulfilDaTooLarge,
    BelowReservation,
    DeadlineMargin,
    ProveResources,
    VerifierSelectorMismatch,
    // Operator side.
    OperatorEndpoint,
    OperatorBudget,
    RetentionFull,
}

impl SkipReason {
    pub fn class(self) -> VerdictClass {
        use SkipReason::*;
        use VerdictClass::*;
        match self {
            EnvelopeMalformed | EnvelopeOutOfRange | UnsupportedBuilderType | UnsupportedProofSystem
            | UnsupportedBinding | UnsupportedSubmission | BuilderInvalidModule | BuilderUnknownImport
            | BuilderTrap | BuilderFuelExhausted | BuilderMemoryExhausted | BuilderNonZeroReturn
            | BuilderWitnessTooLarge | ElfImageIdMismatch | ArtifactAllSourcesBad
            | JournalsDifferAcrossPo2 | GuestCyclesAboveLimit | JournalTooLarge => PermanentForJob,
            BuilderTransient | BuilderWallClock | GuestFailed | BindingMismatch => RetryOnceThenPermanent,
            ElfUnavailable | ArtifactUnavailable | NotClaimable | FulfilDaTooLarge | BelowReservation
            | DeadlineMargin | ProveResources | VerifierSelectorMismatch | DeploymentNotVerified => Transient,
            OperatorEndpoint | OperatorBudget | RetentionFull | CapabilityNotProvisioned
            | LimitsAboveHostMaxima | WitnessDisabled => OperatorSide,
            NotAdmitted | BuilderClampedByProbation => Deferred,
        }
    }

    /// Whether this reason counts against the caller's credit (plan §17.4).
    pub fn counts_against_caller(self) -> bool {
        matches!(self.class(), VerdictClass::PermanentForJob | VerdictClass::RetryOnceThenPermanent)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operator_side_never_counts_against_the_caller() {
        for r in [SkipReason::OperatorEndpoint, SkipReason::OperatorBudget, SkipReason::RetentionFull] {
            assert!(!r.counts_against_caller());
        }
        assert!(SkipReason::BindingMismatch.counts_against_caller());
        assert!(!SkipReason::BuilderClampedByProbation.counts_against_caller());
    }
}
