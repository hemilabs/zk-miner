//! Local verdicts (plan §16): a fixed set of reasons, each with a retry policy and whether it may
//! count against the caller's credit (§17.4). No attacker-controlled strings are ever stored.

use alloy_primitives::{Address, B256};
use serde::{Deserialize, Serialize};

use crate::ipc::exit;

/// When a skipped job may be evaluated again.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Retry {
    /// Never for this job.
    Never,
    /// One jittered retry on other endpoints, then never.
    OnceJittered,
    /// Retried with backoff, at most `max_attempts` times for the job.
    Backoff { max_attempts: u8 },
    /// Only after this host's configuration or build changes (the outcome cannot change before).
    OnHostChange,
    /// Not a judgement of the job: re-evaluated later (e.g. after a probation clamp or admission).
    Deferred,
}

/// The policy for one reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Verdict {
    pub retry: Retry,
    /// Whether the final (retries exhausted) outcome counts against the caller's credit. Failures of
    /// this host's own resources, configuration or support never do.
    pub blames_caller: bool,
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
    /// A fetch returned status 2, or the wall clock expired while a fetch was in flight.
    BuilderTransient,
    /// The wall clock expired with no fetch in flight.
    BuilderWallClock,
    BuilderClampedByProbation,
    /// The runner itself failed (not the module).
    RunnerInternal,
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
    pub const ALL: [SkipReason; 40] = {
        use SkipReason::*;
        [
            EnvelopeMalformed, EnvelopeOutOfRange, UnsupportedBuilderType, UnsupportedProofSystem,
            UnsupportedBinding, UnsupportedSubmission, DeploymentNotVerified, CapabilityNotProvisioned,
            LimitsAboveHostMaxima, NotClaimable, NotAdmitted, WitnessDisabled, ElfUnavailable,
            ElfImageIdMismatch, ArtifactAllSourcesBad, ArtifactUnavailable, BuilderInvalidModule,
            BuilderUnknownImport, BuilderTrap, BuilderFuelExhausted, BuilderMemoryExhausted,
            BuilderNonZeroReturn, BuilderWitnessTooLarge, BuilderTransient, BuilderWallClock,
            BuilderClampedByProbation, RunnerInternal, GuestFailed, GuestCyclesAboveLimit,
            BindingMismatch, JournalsDifferAcrossPo2, JournalTooLarge, FulfilDaTooLarge,
            BelowReservation, DeadlineMargin, ProveResources, VerifierSelectorMismatch,
            OperatorEndpoint, OperatorBudget, RetentionFull,
        ]
    };

    pub fn verdict(self) -> Verdict {
        use Retry::*;
        use SkipReason::*;
        let (retry, blames_caller) = match self {
            // The job itself is malformed or exceeds what it declared: permanent, the caller's.
            EnvelopeMalformed | EnvelopeOutOfRange | ElfImageIdMismatch | ArtifactAllSourcesBad
            | BuilderInvalidModule | BuilderUnknownImport | BuilderTrap | BuilderFuelExhausted
            | BuilderMemoryExhausted | BuilderNonZeroReturn | BuilderWitnessTooLarge | BuilderWallClock
            | GuestCyclesAboveLimit | JournalsDifferAcrossPo2 | JournalTooLarge => (Never, true),
            // A stale node can cause these: one rebuild on other endpoints, then the caller's.
            GuestFailed | BindingMismatch => (OnceJittered, true),
            // Status 2 includes operator-budget exhaustion (§11.2), so never the caller's.
            BuilderTransient => (OnceJittered, false),
            // What this host supports or is configured for: re-evaluated only when that changes.
            UnsupportedBuilderType | UnsupportedProofSystem | UnsupportedBinding | UnsupportedSubmission
            | DeploymentNotVerified | CapabilityNotProvisioned | LimitsAboveHostMaxima
            | WitnessDisabled => (OnHostChange, false),
            // State that moves on its own: chain, prices, DA backlog, resources, endpoints.
            NotClaimable | FulfilDaTooLarge | BelowReservation | ProveResources
            | VerifierSelectorMismatch | OperatorEndpoint | OperatorBudget | RetentionFull
            | RunnerInternal | ElfUnavailable => (Backoff { max_attempts: 8 }, false),
            // An empty manifest: at most three retries per job (§13.4), then permanent.
            ArtifactUnavailable => (Backoff { max_attempts: 3 }, false),
            // The deadline only gets closer.
            DeadlineMargin => (Never, false),
            NotAdmitted | BuilderClampedByProbation => (Deferred, false),
        };
        Verdict { retry, blames_caller }
    }
}

/// Everything known about how a builder run ended. `any_status2` and `fetch_in_flight_at_end` come
/// from the broker's `JobStats`, never from the sandboxed runner's own summary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct BuilderOutcome {
    /// The runner's exit code; `None` when it was killed by a signal.
    pub exit: Option<i32>,
    /// The cgroup recorded an OOM kill.
    pub oom_killed: bool,
    /// The miner's wall clock (the outer deadline) expired and it killed the runner.
    pub wall_clock_hit: bool,
    pub any_status2: bool,
    pub fetch_in_flight_at_end: bool,
}

/// Classifies a builder run (plan §9.2, §16). `None` means success.
pub fn builder_verdict(o: &BuilderOutcome) -> Option<SkipReason> {
    use SkipReason::*;
    if o.exit == Some(exit::OK) && !o.wall_clock_hit && !o.oom_killed {
        return None;
    }
    if o.exit == Some(exit::INTERNAL) {
        return Some(RunnerInternal);
    }
    if o.any_status2 || ((o.wall_clock_hit || o.exit == Some(exit::WALL_CLOCK)) && o.fetch_in_flight_at_end) {
        return Some(BuilderTransient);
    }
    if o.oom_killed {
        return Some(BuilderMemoryExhausted);
    }
    if o.wall_clock_hit {
        return Some(BuilderWallClock);
    }
    Some(match o.exit {
        Some(exit::INVALID_MODULE) => BuilderInvalidModule,
        Some(exit::UNKNOWN_IMPORT) => BuilderUnknownImport,
        Some(exit::FUEL) => BuilderFuelExhausted,
        Some(exit::MEMORY) => BuilderMemoryExhausted,
        Some(exit::NONZERO_RETURN) => BuilderNonZeroReturn,
        Some(exit::WITNESS_TOO_LARGE) => BuilderWitnessTooLarge,
        Some(exit::WALL_CLOCK) | None => BuilderWallClock,
        _ => BuilderTrap,
    })
}

/// Keys scores and verdicts are recorded under (§16): never `builderId` or `programId` alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ScoreKey {
    Caller(Address),
    BuilderCaller { builder_id: B256, caller: Address },
    ProgramCaller { program_id: B256, caller: Address },
}

/// Artifact verdict scope (§13.4): a structurally invalid manifest is bad for its address; a valid
/// manifest of another artifact is bad only for the `(manifest, builderId)` pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ArtifactVerdictKey {
    Manifest { chain_id: u64, manifest: Address },
    ManifestForBuilder { chain_id: u64, manifest: Address, builder_id: B256 },
}

/// Post-lock failure accounting (§16): per caller and per (device, failure class).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PostLockFailureClass {
    Gpu,
    ProverCrash,
    ResourceLimit,
    ProveTimeEstimate,
    GasOrRpc,
    BundleLoss,
    JournalDiverged,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DeviceFailureKey {
    /// The device's stable UUID bytes (ours, never attacker-supplied).
    pub device_uuid: [u8; 16],
    pub class: PostLockFailureClass,
}

/// A persisted verdict: fixed-size, no attacker strings, dropped when the job is terminal or after
/// `expires_at` (§15.2). Records the wasmtime version that judged a builder run (§10.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerdictRecord {
    pub job_id: B256,
    pub reason: SkipReason,
    pub attempts: u8,
    /// Unix seconds.
    pub recorded_at: u64,
    pub expires_at: u64,
    /// `(major, minor, patch)` of the wasmtime that ran the builder, if one ran.
    pub wasmtime_version: Option<(u16, u16, u16)>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use SkipReason::*;

    #[test]
    fn table_matches_section_16() {
        let v = |r: SkipReason| r.verdict();
        // Permanent for the job, the caller's.
        for r in [EnvelopeMalformed, EnvelopeOutOfRange, BuilderUnknownImport, BuilderTrap, BuilderFuelExhausted,
            BuilderMemoryExhausted, BuilderNonZeroReturn, BuilderWallClock, JournalsDifferAcrossPo2]
        {
            assert_eq!(v(r), Verdict { retry: Retry::Never, blames_caller: true }, "{r:?}");
        }
        // One jittered retry.
        assert_eq!(v(GuestFailed).retry, Retry::OnceJittered);
        assert_eq!(v(BindingMismatch).retry, Retry::OnceJittered);
        assert_eq!(v(BuilderTransient), Verdict { retry: Retry::OnceJittered, blames_caller: false });
        // Operator side and host support never blame the caller.
        for r in [OperatorEndpoint, OperatorBudget, RetentionFull, RunnerInternal, UnsupportedSubmission,
            UnsupportedBuilderType, CapabilityNotProvisioned, LimitsAboveHostMaxima, WitnessDisabled]
        {
            assert!(!v(r).blames_caller, "{r:?}");
        }
        assert_eq!(v(CapabilityNotProvisioned).retry, Retry::OnHostChange);
        assert_eq!(v(ArtifactUnavailable).retry, Retry::Backoff { max_attempts: 3 });
        assert_eq!(v(BuilderClampedByProbation).retry, Retry::Deferred);
        // ALL lists each reason once (`verdict`'s match is exhaustive, so every reason has a policy).
        let set: std::collections::HashSet<_> = SkipReason::ALL.iter().collect();
        assert_eq!(set.len(), SkipReason::ALL.len());
    }

    #[test]
    fn builder_classifier() {
        let o = |exit, any_status2, fetch_in_flight_at_end, wall_clock_hit, oom_killed| BuilderOutcome {
            exit, any_status2, fetch_in_flight_at_end, wall_clock_hit, oom_killed,
        };
        assert_eq!(builder_verdict(&o(Some(exit::OK), false, false, false, false)), None);
        assert_eq!(builder_verdict(&o(Some(exit::INTERNAL), true, false, false, false)), Some(RunnerInternal));
        // A deterministic failure after a status-2 fetch is transient.
        assert_eq!(builder_verdict(&o(Some(exit::NONZERO_RETURN), true, false, false, false)), Some(BuilderTransient));
        assert_eq!(builder_verdict(&o(Some(exit::NONZERO_RETURN), false, false, false, false)), Some(BuilderNonZeroReturn));
        // The wall clock: transient only with a fetch in flight.
        assert_eq!(builder_verdict(&o(None, false, true, true, false)), Some(BuilderTransient));
        assert_eq!(builder_verdict(&o(None, false, false, true, false)), Some(BuilderWallClock));
        assert_eq!(builder_verdict(&o(Some(exit::WALL_CLOCK), false, false, false, false)), Some(BuilderWallClock));
        assert_eq!(builder_verdict(&o(None, false, false, false, true)), Some(BuilderMemoryExhausted));
        assert_eq!(builder_verdict(&o(Some(exit::TRAP), false, false, false, false)), Some(BuilderTrap));
        assert_eq!(builder_verdict(&o(Some(-5), false, false, false, false)), Some(BuilderTrap));
        assert_eq!(builder_verdict(&o(Some(exit::OK), false, false, true, false)), Some(BuilderWallClock));
    }
}
