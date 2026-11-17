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

impl Retry {
    /// A stable name for reports (`zkminer simulate`): `never`, `once_jittered`, `backoff`,
    /// `on_host_change`, `deferred`.
    pub fn as_str(self) -> &'static str {
        match self {
            Retry::Never => "never",
            Retry::OnceJittered => "once_jittered",
            Retry::Backoff { .. } => "backoff",
            Retry::OnHostChange => "on_host_change",
            Retry::Deferred => "deferred",
        }
    }

    /// `Backoff`'s attempts; `None` for the others.
    pub fn max_attempts(self) -> Option<u8> {
        match self {
            Retry::Backoff { max_attempts } => Some(max_attempts),
            _ => None,
        }
    }
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
    /// A fetch failed for an operator-side reason (`JobStats.operator_failure`), or the wall clock
    /// expired while a fetch waited on operator-side capacity. Not: a fetch the builder made
    /// unanswerable (unknown hashes, missing state), nor one in flight on its own cost.
    BuilderTransient,
    /// The wall clock expired with no fetch in flight.
    BuilderWallClock,
    BuilderClampedByProbation,
    /// The runner itself failed (not the module).
    RunnerInternal,
    /// The runner died on a signal (not an OOM kill or the miner's timeout) after the module
    /// started: the module's doing, possibly an escape attempt (a seccomp SIGSYS included).
    BuilderCrashed,
    /// The runner died on a signal before the module started (compiling hostile input).
    RunnerCrashed,
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
    /// This host's own machinery failed, not the job: the retention store unavailable or failing,
    /// a sandbox, cgroup or spawn failure, the broker's control channel lost, the execute worker's
    /// own error or malformed answer. Never the caller's.
    HostInternal,
    /// This host's capacity was busy just now, not the job: no risc0 measure worker came free in time
    /// to derive the guest ELF's image id. Deferred (looked at again soon), never final, never the
    /// caller's.
    HostBusy,
    // After a lock.
    /// A witness lock of this job failed after the lock and was released (§16 "post-lock witness
    /// failure"). Final for the job: its bundle is never locked again. Counted per caller and per
    /// (device, failure class) apart from the simulation verdicts, never against the caller's
    /// simulation record.
    PostLockFailure,
}

impl SkipReason {
    pub const ALL: [SkipReason; 45] = {
        use SkipReason::*;
        [
            EnvelopeMalformed, EnvelopeOutOfRange, UnsupportedBuilderType, UnsupportedProofSystem,
            UnsupportedBinding, UnsupportedSubmission, DeploymentNotVerified, CapabilityNotProvisioned,
            LimitsAboveHostMaxima, NotClaimable, NotAdmitted, WitnessDisabled, ElfUnavailable,
            ElfImageIdMismatch, ArtifactAllSourcesBad, ArtifactUnavailable, BuilderInvalidModule,
            BuilderUnknownImport, BuilderTrap, BuilderFuelExhausted, BuilderMemoryExhausted,
            BuilderNonZeroReturn, BuilderWitnessTooLarge, BuilderTransient, BuilderWallClock,
            BuilderClampedByProbation, RunnerInternal, BuilderCrashed, RunnerCrashed, GuestFailed, GuestCyclesAboveLimit,
            BindingMismatch, JournalsDifferAcrossPo2, JournalTooLarge, FulfilDaTooLarge,
            BelowReservation, DeadlineMargin, ProveResources, VerifierSelectorMismatch,
            OperatorEndpoint, OperatorBudget, RetentionFull, HostInternal, HostBusy, PostLockFailure,
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
            | BuilderCrashed
            | GuestCyclesAboveLimit | JournalsDifferAcrossPo2 | JournalTooLarge => (Never, true),
            // A stale node can cause these: one rebuild on other endpoints, then the caller's.
            GuestFailed | BindingMismatch => (OnceJittered, true),
            // Only operator-side failures (§11.2), so never the caller's.
            BuilderTransient => (OnceJittered, false),
            // What this host supports or is configured for: re-evaluated only when that changes.
            UnsupportedBuilderType | UnsupportedProofSystem | UnsupportedBinding | UnsupportedSubmission
            | DeploymentNotVerified | CapabilityNotProvisioned | LimitsAboveHostMaxima
            | WitnessDisabled => (OnHostChange, false),
            // State that moves on its own: chain, prices, DA backlog, resources, endpoints.
            NotClaimable | FulfilDaTooLarge | BelowReservation | ProveResources
            | VerifierSelectorMismatch | OperatorEndpoint | OperatorBudget | RetentionFull | HostInternal
            | RunnerInternal | ElfUnavailable => (Backoff { max_attempts: 8 }, false),
            // A crash while compiling: hostile input may cause it, but the module never ran, so a
            // few retries and never the caller's blame.
            RunnerCrashed => (Backoff { max_attempts: 2 }, false),
            // An empty manifest: at most three retries per job (§13.4), then permanent.
            ArtifactUnavailable => (Backoff { max_attempts: 3 }, false),
            // The deadline only gets closer.
            DeadlineMargin => (Never, false),
            // A lock of the job already failed here: never locked again (the post-lock counts are
            // kept separately).
            PostLockFailure => (Never, false),
            NotAdmitted | BuilderClampedByProbation | HostBusy => (Deferred, false),
        };
        Verdict { retry, blames_caller }
    }
}

/// Everything known about how a builder run ended. `operator_failure`, `fetch_in_flight_at_end`
/// and `in_flight_operator_wait` come from the broker's `JobStats`, never from the sandboxed
/// runner's own summary. (`JobStats.unanswerable` is deliberately absent: a fetch the builder made
/// unanswerable never excuses its failure.)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct BuilderOutcome {
    /// The runner's exit code; `None` when it was killed by a signal.
    pub exit: Option<i32>,
    /// The cgroup recorded an OOM kill.
    pub oom_killed: bool,
    /// The miner's wall clock (the outer deadline) expired and it killed the runner.
    pub wall_clock_hit: bool,
    /// Some fetch failed (status 2) for an operator-side reason.
    pub operator_failure: bool,
    /// A fetch was being served when the run ended.
    pub fetch_in_flight_at_end: bool,
    /// ...and it was waiting on operator-side capacity, or had met an operator-side failure.
    pub in_flight_operator_wait: bool,
    /// The runner wrote its "module started" marker (before instantiation) on its summary pipe:
    /// past it, the runner's own `INTERNAL` exit is the module's doing.
    pub module_started: bool,
    /// The signal that killed the runner, when `exit` is `None`.
    pub signal: Option<i32>,
    /// The miner itself saw this job's W pipe or broker channel fail (its own side, not the
    /// module's): an `INTERNAL` exit is then the operator's, even after the marker.
    pub miner_side_failure: bool,
}

/// Classifies a builder run (plan §9.2, §16). `None` means success.
pub fn builder_verdict(o: &BuilderOutcome) -> Option<SkipReason> {
    use SkipReason::*;
    if o.exit == Some(exit::OK) && !o.wall_clock_hit && !o.oom_killed {
        return None;
    }
    if o.miner_side_failure {
        return Some(RunnerInternal);
    }
    if o.exit == Some(exit::INTERNAL) && !o.module_started {
        return Some(RunnerInternal);
    }
    let deadline = o.wall_clock_hit || o.exit == Some(exit::WALL_CLOCK);
    if o.operator_failure || (deadline && o.fetch_in_flight_at_end && o.in_flight_operator_wait) {
        return Some(BuilderTransient);
    }
    if o.oom_killed {
        return Some(BuilderMemoryExhausted);
    }
    if o.wall_clock_hit {
        return Some(BuilderWallClock);
    }
    if o.exit.is_none() {
        // Killed by a signal that was neither the OOM killer nor the miner's own timeout.
        return Some(if o.module_started { BuilderCrashed } else { RunnerCrashed });
    }
    Some(match o.exit {
        Some(exit::INVALID_MODULE) => BuilderInvalidModule,
        Some(exit::UNKNOWN_IMPORT) => BuilderUnknownImport,
        Some(exit::FUEL) => BuilderFuelExhausted,
        Some(exit::MEMORY) => BuilderMemoryExhausted,
        Some(exit::NONZERO_RETURN) => BuilderNonZeroReturn,
        Some(exit::WITNESS_TOO_LARGE) => BuilderWitnessTooLarge,
        Some(exit::WALL_CLOCK) => BuilderWallClock,
        // Includes INTERNAL once the module started.
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
        for r in [OperatorEndpoint, OperatorBudget, RetentionFull, HostInternal, RunnerInternal, UnsupportedSubmission,
            UnsupportedBuilderType, CapabilityNotProvisioned, LimitsAboveHostMaxima, WitnessDisabled]
        {
            assert!(!v(r).blames_caller, "{r:?}");
        }
        assert_eq!(v(CapabilityNotProvisioned).retry, Retry::OnHostChange);
        assert_eq!(v(ArtifactUnavailable).retry, Retry::Backoff { max_attempts: 3 });
        assert_eq!(v(BuilderClampedByProbation).retry, Retry::Deferred);
        assert_eq!(v(HostBusy), Verdict { retry: Retry::Deferred, blames_caller: false });
        assert_eq!(v(PostLockFailure), Verdict { retry: Retry::Never, blames_caller: false });
        // ALL lists each reason once (`verdict`'s match is exhaustive, so every reason has a policy).
        let set: std::collections::HashSet<_> = SkipReason::ALL.iter().collect();
        assert_eq!(set.len(), SkipReason::ALL.len());
    }

    #[test]
    fn builder_classifier() {
        let o = |exit, operator_failure, fetch_in_flight_at_end, wall_clock_hit, oom_killed| BuilderOutcome {
            exit,
            operator_failure,
            fetch_in_flight_at_end,
            in_flight_operator_wait: fetch_in_flight_at_end,
            wall_clock_hit,
            oom_killed,
            module_started: true,
            signal: None,
            miner_side_failure: false,
        };
        assert_eq!(builder_verdict(&o(Some(exit::OK), false, false, false, false)), None);
        assert_eq!(
            builder_verdict(&BuilderOutcome { module_started: false, ..o(Some(exit::INTERNAL), true, false, false, false) }),
            Some(RunnerInternal)
        );
        // A deterministic failure after an operator-side fetch failure is transient.
        assert_eq!(builder_verdict(&o(Some(exit::NONZERO_RETURN), true, false, false, false)), Some(BuilderTransient));
        assert_eq!(builder_verdict(&o(Some(exit::NONZERO_RETURN), false, false, false, false)), Some(BuilderNonZeroReturn));
        // The wall clock: transient only with a fetch in flight in an operator-side wait.
        assert_eq!(builder_verdict(&o(None, false, true, true, false)), Some(BuilderTransient));
        assert_eq!(builder_verdict(&o(None, false, false, true, false)), Some(BuilderWallClock));
        assert_eq!(builder_verdict(&o(Some(exit::WALL_CLOCK), false, false, false, false)), Some(BuilderWallClock));
        assert_eq!(builder_verdict(&o(None, false, false, false, true)), Some(BuilderMemoryExhausted));
        assert_eq!(builder_verdict(&o(Some(exit::TRAP), false, false, false, false)), Some(BuilderTrap));
        assert_eq!(builder_verdict(&o(Some(-5), false, false, false, false)), Some(BuilderTrap));
        assert_eq!(builder_verdict(&o(Some(exit::OK), false, false, true, false)), Some(BuilderWallClock));
        // A signal death that is neither the OOM killer nor the miner's timeout: the module's after
        // the marker, the runner's before it.
        let crash = BuilderOutcome { signal: Some(31), ..o(None, false, false, false, false) };
        assert_eq!(builder_verdict(&crash), Some(BuilderCrashed));
        assert_eq!(builder_verdict(&BuilderOutcome { module_started: false, ..crash }), Some(RunnerCrashed));
        assert!(BuilderCrashed.verdict().blames_caller && !RunnerCrashed.verdict().blames_caller);
        // INTERNAL after the marker is the module's, unless the miner saw its own side fail.
        assert_eq!(builder_verdict(&o(Some(exit::INTERNAL), false, false, false, false)), Some(BuilderTrap));
        assert_eq!(
            builder_verdict(&BuilderOutcome { miner_side_failure: true, ..o(Some(exit::INTERNAL), false, false, false, false) }),
            Some(RunnerInternal)
        );
    }

    /// Review F2: a builder that made its own fetches fail (unknown hashes, missing state: the
    /// broker's `unanswerable`) or straddled its deadline with a fetch the endpoint was working on
    /// is judged on its own exit; only operator-side failures and waits excuse it.
    #[test]
    fn only_operator_side_failures_are_transient() {
        let base = BuilderOutcome { exit: Some(exit::TRAP), module_started: true, ..Default::default() };
        // `unanswerable` is not an input at all: a trap after unanswerable fetches is a trap.
        assert_eq!(builder_verdict(&base), Some(BuilderTrap));
        // The deadline with a fetch in flight on its own cost: the wall clock is the builder's.
        let straddle = BuilderOutcome { exit: None, wall_clock_hit: true, fetch_in_flight_at_end: true, ..base };
        assert_eq!(builder_verdict(&straddle), Some(BuilderWallClock));
        assert_eq!(builder_verdict(&BuilderOutcome { exit: Some(exit::WALL_CLOCK), wall_clock_hit: false, ..straddle }), Some(BuilderWallClock));
        // ...in an operator-side wait: transient, not the caller's.
        let waiting = BuilderOutcome { in_flight_operator_wait: true, ..straddle };
        assert_eq!(builder_verdict(&waiting), Some(BuilderTransient));
        assert!(!BuilderTransient.verdict().blames_caller);
        // The operator wait without the deadline changes nothing.
        assert_eq!(builder_verdict(&BuilderOutcome { fetch_in_flight_at_end: true, in_flight_operator_wait: true, ..base }), Some(BuilderTrap));
        // An operator-side failure excuses any exit.
        assert_eq!(builder_verdict(&BuilderOutcome { operator_failure: true, ..base }), Some(BuilderTransient));
    }

    /// The runner's "module started" marker: its own INTERNAL exit before the marker is the
    /// runner's; after it, the module's (a trap).
    #[test]
    fn internal_exits_after_the_module_started_are_traps() {
        let o = BuilderOutcome { exit: Some(exit::INTERNAL), ..Default::default() };
        assert_eq!(builder_verdict(&o), Some(RunnerInternal));
        assert_eq!(builder_verdict(&BuilderOutcome { module_started: true, ..o }), Some(BuilderTrap));
        assert_eq!(
            builder_verdict(&BuilderOutcome { module_started: true, operator_failure: true, ..o }),
            Some(BuilderTransient)
        );
    }
}
