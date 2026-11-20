//! Governance watchers for witness-construction jobs (design §5.2, §5.5, §17.6, §18).
//!
//! A witness job is simulated before it is locked, and a witness lock is proved from its published
//! bundle, so governance actions are the residual risk the miner can still see coming:
//!
//! - a **verifier swap** for a proof system becomes executable at the `readyAt` of the Registry's
//!   `VerifierSwitchProposed`; a proof for the old verifier can then only be released, so no witness
//!   lock is taken whose deadline reaches a pending swap's `readyAt`;
//! - a pending **router (or Registry) upgrade** likewise: no witness lock whose deadline falls at or
//!   after its `readyAt`;
//! - while the **router or Registry is paused**, or the job's **adapter is disabled**, simulation and
//!   locking hold;
//! - a running simulation is **aborted** on `JobCancelled`, on `JobClaimed` by another prover, and on
//!   `BidSubmitted`.
//!
//! [`GovernanceWatcher`] keeps that state from the chain: it starts from view calls at one block
//! (`paused()`, `pendingUpgrade()`, `getAdapter`, `pendingReactivation`) plus a bounded log look-back,
//! then polls the router's and Registry's logs incrementally in bounded block ranges (one
//! `eth_getLogs` per range, both contracts and every watched event in one filter), and re-reads the
//! views every [`GovernanceConfig::resync_interval`]. Queries go through a cheap, cloneable
//! [`GovernanceView`]; aborts are also broadcast ([`GovernanceView::subscribe_aborts`]).
//!
//! The log decoding ([`decode_governance_log`]) and the state machine ([`GovernanceState`]) are pure.
//!
//! The section at the end holds the per-block cache of deployment constants (§17.6).

use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::hash::Hash;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use alloy::eips::BlockId;
use alloy::primitives::{Address, B256};
use alloy::providers::Provider;
use alloy::rpc::types::{Filter, Log};
use alloy::sol_types::SolEvent;
use anyhow::{bail, Context, Result};
use tokio::sync::broadcast;
use tokio::time::Instant;

use zkminer_contracts::bindings::{
    IHemiProveAux, IHemiProveCore, IHemiProveFulfill, IHemiProveRegistry, IHemiProveRouterGov,
    IRiscZeroSelectable, IVerifierAdapter,
};

use crate::client::ChainClient;

/// Default log look-back at start: about a day of Hemi's 12-s blocks. Governance state itself comes
/// from view calls; the look-back only recovers per-job marks (`BidSubmitted`, `JobCancelled`).
pub const DEFAULT_LOOKBACK_BLOCKS: u64 = 7_200;
/// Default block range of one `eth_getLogs` (well under common provider caps).
pub const DEFAULT_CHUNK_BLOCKS: u64 = 2_000;
/// Default bound on the ranges one poll scans, so catching up after an outage is spread out.
pub const DEFAULT_MAX_CHUNKS_PER_POLL: u32 = 8;
/// Per-job marks kept (FIFO-evicted beyond it), so a flood of bids or cancels cannot grow the heap.
pub const PER_JOB_MARKS_CAP: usize = 16_384;
/// A cached head that has not moved for this long is re-read live (the monitor may not be running).
const HEAD_STALL: Duration = Duration::from_secs(60);
/// Abort broadcast capacity; a lagging subscriber sees `RecvError::Lagged` and should re-query.
const ABORT_CHANNEL_CAP: usize = 1024;
/// AdapterStatus.Disabled (Types.sol: Unregistered, Active, Deprecated, Disabled).
const ADAPTER_STATUS_DISABLED: u8 = 3;

/// Watcher settings.
#[derive(Debug, Clone)]
pub struct GovernanceConfig {
    /// The staked prover this miner claims for: a `JobClaimed` by anyone else aborts a simulation.
    pub prover: Address,
    /// Proof systems whose adapter state is read at start and on every resync (logs cover every
    /// proof system regardless).
    pub proof_systems: Vec<B256>,
    pub lookback_blocks: u64,
    pub chunk_blocks: u64,
    pub max_chunks_per_poll: u32,
    pub poll_interval: Duration,
    /// How often the view calls are re-read, correcting anything the logs missed.
    pub resync_interval: Duration,
    /// The view is stale (every gate refuses) when the watcher has not caught up with the head for
    /// this long.
    pub stale_after: Duration,
}

impl GovernanceConfig {
    pub fn new(prover: Address, proof_systems: Vec<B256>) -> Self {
        Self {
            prover,
            proof_systems,
            lookback_blocks: DEFAULT_LOOKBACK_BLOCKS,
            chunk_blocks: DEFAULT_CHUNK_BLOCKS,
            max_chunks_per_poll: DEFAULT_MAX_CHUNKS_PER_POLL,
            poll_interval: Duration::from_secs(12),
            resync_interval: Duration::from_secs(600),
            stale_after: Duration::from_secs(180),
        }
    }
}

// ─── Events ─────────────────────────────────────────────────────────────────────────────────────

/// Which watched contract a log came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GovContract {
    Router,
    Registry,
}

/// A watched event, decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GovEvent {
    Paused {
        contract: GovContract,
        paused: bool,
    },
    UpgradeProposed {
        contract: GovContract,
        op_hash: B256,
        ready_at: u64,
    },
    /// `UpgradeCancelled` or `UpgradeExecuted`: either way the operation is no longer pending.
    UpgradeCleared {
        contract: GovContract,
        op_hash: B256,
    },
    VerifierSwitchProposed {
        proof_system_id: B256,
        new_adapter: Address,
        ready_at: u64,
    },
    VerifierSwitchCancelled {
        proof_system_id: B256,
    },
    AdapterDisabled {
        proof_system_id: B256,
    },
    /// `AdapterRegistered` or `AdapterReactivated` (an instant re-enable, or a verifier swap landing):
    /// the adapter is enabled at `adapter`, and no swap is pending for it.
    AdapterEnabled {
        proof_system_id: B256,
        adapter: Address,
    },
    BidSubmitted {
        job_id: B256,
        bidder: Address,
    },
    JobClaimed {
        job_id: B256,
        prover: Address,
    },
    JobCancelled {
        job_id: B256,
        caller: Address,
    },
}

/// Every topic0 the watcher queries (router and Registry together; `Paused`/`Unpaused` and
/// `UpgradeProposed`/`UpgradeCancelled` share their topic0 across the two).
pub fn governance_topics() -> Vec<B256> {
    vec![
        IHemiProveAux::Paused::SIGNATURE_HASH,
        IHemiProveAux::Unpaused::SIGNATURE_HASH,
        IHemiProveRouterGov::UpgradeProposed::SIGNATURE_HASH,
        IHemiProveRouterGov::UpgradeCancelled::SIGNATURE_HASH,
        IHemiProveRouterGov::UpgradeExecuted::SIGNATURE_HASH,
        IHemiProveRegistry::UpgradeExecuted::SIGNATURE_HASH,
        IHemiProveAux::BidSubmitted::SIGNATURE_HASH,
        IHemiProveCore::JobClaimed::SIGNATURE_HASH,
        IHemiProveFulfill::JobCancelled::SIGNATURE_HASH,
        IHemiProveRegistry::VerifierSwitchProposed::SIGNATURE_HASH,
        IHemiProveRegistry::VerifierSwitchCancelled::SIGNATURE_HASH,
        IHemiProveRegistry::AdapterDisabledEvent::SIGNATURE_HASH,
        IHemiProveRegistry::AdapterReactivated::SIGNATURE_HASH,
        IHemiProveRegistry::AdapterRegistered::SIGNATURE_HASH,
    ]
}

fn decode<E: SolEvent>(log: &Log) -> Option<E> {
    E::decode_log_data(log.data()).ok()
}

/// Decode a log from the router or the Registry into a [`GovEvent`], keyed strictly on (emitting
/// address, topic0): a log from any other address, a removed (reorged) log, an unwatched event or a
/// malformed one is `None`.
pub fn decode_governance_log(log: &Log, router: Address, registry: Address) -> Option<GovEvent> {
    if log.removed {
        return None;
    }
    let t0 = *log.topics().first()?;
    let address = log.address();
    if address == router {
        decode_router_log(log, t0)
    } else if address == registry {
        decode_registry_log(log, t0)
    } else {
        None
    }
}

fn decode_router_log(log: &Log, t0: B256) -> Option<GovEvent> {
    use GovContract::Router;
    Some(if t0 == IHemiProveAux::Paused::SIGNATURE_HASH {
        decode::<IHemiProveAux::Paused>(log)?;
        GovEvent::Paused {
            contract: Router,
            paused: true,
        }
    } else if t0 == IHemiProveAux::Unpaused::SIGNATURE_HASH {
        decode::<IHemiProveAux::Unpaused>(log)?;
        GovEvent::Paused {
            contract: Router,
            paused: false,
        }
    } else if t0 == IHemiProveRouterGov::UpgradeProposed::SIGNATURE_HASH {
        let e = decode::<IHemiProveRouterGov::UpgradeProposed>(log)?;
        GovEvent::UpgradeProposed {
            contract: Router,
            op_hash: e.operationHash,
            ready_at: e.readyAt.to::<u64>(),
        }
    } else if t0 == IHemiProveRouterGov::UpgradeCancelled::SIGNATURE_HASH {
        let e = decode::<IHemiProveRouterGov::UpgradeCancelled>(log)?;
        GovEvent::UpgradeCleared {
            contract: Router,
            op_hash: e.operationHash,
        }
    } else if t0 == IHemiProveRouterGov::UpgradeExecuted::SIGNATURE_HASH {
        let e = decode::<IHemiProveRouterGov::UpgradeExecuted>(log)?;
        GovEvent::UpgradeCleared {
            contract: Router,
            op_hash: e.operationHash,
        }
    } else if t0 == IHemiProveAux::BidSubmitted::SIGNATURE_HASH {
        let e = decode::<IHemiProveAux::BidSubmitted>(log)?;
        GovEvent::BidSubmitted {
            job_id: e.jobId,
            bidder: e.bidder,
        }
    } else if t0 == IHemiProveCore::JobClaimed::SIGNATURE_HASH {
        let e = decode::<IHemiProveCore::JobClaimed>(log)?;
        GovEvent::JobClaimed {
            job_id: e.jobId,
            prover: e.prover,
        }
    } else if t0 == IHemiProveFulfill::JobCancelled::SIGNATURE_HASH {
        let e = decode::<IHemiProveFulfill::JobCancelled>(log)?;
        GovEvent::JobCancelled {
            job_id: e.jobId,
            caller: e.caller,
        }
    } else {
        return None;
    })
}

fn decode_registry_log(log: &Log, t0: B256) -> Option<GovEvent> {
    use GovContract::Registry;
    Some(if t0 == IHemiProveRegistry::Paused::SIGNATURE_HASH {
        decode::<IHemiProveRegistry::Paused>(log)?;
        GovEvent::Paused {
            contract: Registry,
            paused: true,
        }
    } else if t0 == IHemiProveRegistry::Unpaused::SIGNATURE_HASH {
        decode::<IHemiProveRegistry::Unpaused>(log)?;
        GovEvent::Paused {
            contract: Registry,
            paused: false,
        }
    } else if t0 == IHemiProveRegistry::UpgradeProposed::SIGNATURE_HASH {
        let e = decode::<IHemiProveRegistry::UpgradeProposed>(log)?;
        GovEvent::UpgradeProposed {
            contract: Registry,
            op_hash: e.opHash,
            ready_at: e.readyAt.to::<u64>(),
        }
    } else if t0 == IHemiProveRegistry::UpgradeCancelled::SIGNATURE_HASH {
        let e = decode::<IHemiProveRegistry::UpgradeCancelled>(log)?;
        GovEvent::UpgradeCleared {
            contract: Registry,
            op_hash: e.opHash,
        }
    } else if t0 == IHemiProveRegistry::UpgradeExecuted::SIGNATURE_HASH {
        let e = decode::<IHemiProveRegistry::UpgradeExecuted>(log)?;
        GovEvent::UpgradeCleared {
            contract: Registry,
            op_hash: e.opHash,
        }
    } else if t0 == IHemiProveRegistry::VerifierSwitchProposed::SIGNATURE_HASH {
        let e = decode::<IHemiProveRegistry::VerifierSwitchProposed>(log)?;
        GovEvent::VerifierSwitchProposed {
            proof_system_id: e.proofSystemId,
            new_adapter: e.newAdapter,
            ready_at: e.readyAt.to::<u64>(),
        }
    } else if t0 == IHemiProveRegistry::VerifierSwitchCancelled::SIGNATURE_HASH {
        let e = decode::<IHemiProveRegistry::VerifierSwitchCancelled>(log)?;
        GovEvent::VerifierSwitchCancelled {
            proof_system_id: e.proofSystemId,
        }
    } else if t0 == IHemiProveRegistry::AdapterDisabledEvent::SIGNATURE_HASH {
        let e = decode::<IHemiProveRegistry::AdapterDisabledEvent>(log)?;
        GovEvent::AdapterDisabled {
            proof_system_id: e.proofSystemId,
        }
    } else if t0 == IHemiProveRegistry::AdapterReactivated::SIGNATURE_HASH {
        let e = decode::<IHemiProveRegistry::AdapterReactivated>(log)?;
        GovEvent::AdapterEnabled {
            proof_system_id: e.proofSystemId,
            adapter: e.adapter,
        }
    } else if t0 == IHemiProveRegistry::AdapterRegistered::SIGNATURE_HASH {
        let e = decode::<IHemiProveRegistry::AdapterRegistered>(log)?;
        GovEvent::AdapterEnabled {
            proof_system_id: e.proofSystemId,
            adapter: e.adapter,
        }
    } else {
        return None;
    })
}

// ─── State ──────────────────────────────────────────────────────────────────────────────────────

/// Why a running simulation of a job must stop (design §5.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AbortReason {
    /// The caller cancelled the job (terminal).
    Cancelled { caller: Address },
    /// Another prover locked it. Not sticky: a release reopens the job, and the claimability
    /// `eth_call` is what decides whether it is lockable again.
    ClaimedByOther { prover: Address },
    /// A competitive bid (zkminer does not bid in Phase 1). Sticky.
    BidSubmitted { bidder: Address },
}

/// "Abort the simulation of `job_id`", broadcast as the event is seen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AbortSimulation {
    pub job_id: B256,
    pub reason: AbortReason,
    /// The block the event was mined in, when the log carried it.
    pub block: Option<u64>,
}

/// A pending verifier swap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PendingSwitch {
    pub new_adapter: Address,
    pub ready_at: u64,
}

/// A pending upgrade operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PendingUpgrade {
    pub contract: GovContract,
    pub op_hash: B256,
    pub ready_at: u64,
}

/// What the watcher knows of one proof system's adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AdapterState {
    /// The registered adapter (zero until a view or a log names it).
    pub adapter: Address,
    pub disabled: bool,
}

/// A FIFO-bounded map of per-job marks.
#[derive(Debug, Clone)]
struct JobMarks<V> {
    map: HashMap<B256, V>,
    order: VecDeque<B256>,
    cap: usize,
}

impl<V> JobMarks<V> {
    fn new(cap: usize) -> Self {
        Self {
            map: HashMap::new(),
            order: VecDeque::new(),
            cap,
        }
    }

    /// Mark `job` with `v` unless it is already marked (the first mark is kept).
    fn mark(&mut self, job: B256, v: V) {
        if let std::collections::hash_map::Entry::Vacant(e) = self.map.entry(job) {
            e.insert(v);
            self.order.push_back(job);
            while self.order.len() > self.cap {
                if let Some(old) = self.order.pop_front() {
                    self.map.remove(&old);
                }
            }
        }
    }

    fn get(&self, job: &B256) -> Option<&V> {
        self.map.get(job)
    }
}

/// View-call state at one block, overlaid on the log-derived state by [`GovernanceState::apply_views`].
/// Each `None` is a read that failed (the log-derived value is kept).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ViewSnapshot {
    pub block: u64,
    pub router_paused: Option<bool>,
    pub registry_paused: Option<bool>,
    /// `pendingUpgrade()`: `(operationHash, readyAt)`, `(0, 0)` when nothing is pending.
    pub router_upgrade: Option<(B256, u64)>,
    pub registry_upgrade: Option<(B256, u64)>,
    pub adapters: Vec<AdapterView>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AdapterView {
    pub proof_system_id: B256,
    /// `getAdapter`: `(adapter, status)`.
    pub entry: Option<(Address, u8)>,
    /// `pendingReactivation`: `(newAdapter, readyAt)`, `(0, 0)` when none.
    pub pending_switch: Option<(Address, u64)>,
}

impl ViewSnapshot {
    /// Whether every read succeeded.
    pub fn complete(&self) -> bool {
        self.router_paused.is_some()
            && self.registry_paused.is_some()
            && self.router_upgrade.is_some()
            && self.registry_upgrade.is_some()
            && self
                .adapters
                .iter()
                .all(|a| a.entry.is_some() && a.pending_switch.is_some())
    }
}

/// The governance state machine: pure, fed decoded events in chain order and view snapshots.
#[derive(Debug, Clone)]
pub struct GovernanceState {
    prover: Address,
    router_paused: bool,
    registry_paused: bool,
    upgrades: HashMap<(GovContract, B256), u64>,
    switches: HashMap<B256, PendingSwitch>,
    adapters: HashMap<B256, AdapterState>,
    bids: JobMarks<Address>,
    aborted: JobMarks<AbortReason>,
}

impl GovernanceState {
    /// An empty state for a miner claiming as `prover`.
    pub fn new(prover: Address) -> Self {
        Self::with_job_cap(prover, PER_JOB_MARKS_CAP)
    }

    fn with_job_cap(prover: Address, cap: usize) -> Self {
        Self {
            prover,
            router_paused: false,
            registry_paused: false,
            upgrades: HashMap::new(),
            switches: HashMap::new(),
            adapters: HashMap::new(),
            bids: JobMarks::new(cap),
            aborted: JobMarks::new(cap),
        }
    }

    /// Apply one event. `live` is false for the start-up look-back: history then updates the state
    /// but aborts nothing (no simulation is running), and a historical `JobClaimed` is ignored (the
    /// job may have been released since). Returns the abort a live event calls for.
    pub fn apply(
        &mut self,
        ev: &GovEvent,
        live: bool,
        block: Option<u64>,
    ) -> Option<AbortSimulation> {
        let abort = |job_id, reason| {
            live.then_some(AbortSimulation {
                job_id,
                reason,
                block,
            })
        };
        match *ev {
            GovEvent::Paused { contract, paused } => match contract {
                GovContract::Router => self.router_paused = paused,
                GovContract::Registry => self.registry_paused = paused,
            },
            GovEvent::UpgradeProposed {
                contract,
                op_hash,
                ready_at,
            } => {
                // One pending operation per contract: a new proposal names the only one.
                self.upgrades.retain(|(c, _), _| *c != contract);
                self.upgrades.insert((contract, op_hash), ready_at);
            }
            GovEvent::UpgradeCleared { contract, op_hash } => {
                self.upgrades.remove(&(contract, op_hash));
            }
            GovEvent::VerifierSwitchProposed {
                proof_system_id,
                new_adapter,
                ready_at,
            } => {
                self.switches.insert(
                    proof_system_id,
                    PendingSwitch {
                        new_adapter,
                        ready_at,
                    },
                );
            }
            GovEvent::VerifierSwitchCancelled { proof_system_id } => {
                self.switches.remove(&proof_system_id);
            }
            GovEvent::AdapterDisabled { proof_system_id } => {
                self.adapters.entry(proof_system_id).or_default().disabled = true;
            }
            GovEvent::AdapterEnabled {
                proof_system_id,
                adapter,
            } => {
                self.adapters.insert(
                    proof_system_id,
                    AdapterState {
                        adapter,
                        disabled: false,
                    },
                );
                self.switches.remove(&proof_system_id);
            }
            GovEvent::BidSubmitted { job_id, bidder } => {
                self.bids.mark(job_id, bidder);
                let reason = AbortReason::BidSubmitted { bidder };
                self.aborted.mark(job_id, reason);
                return abort(job_id, reason);
            }
            GovEvent::JobClaimed { job_id, prover } => {
                if prover != self.prover {
                    return abort(job_id, AbortReason::ClaimedByOther { prover });
                }
            }
            GovEvent::JobCancelled { job_id, caller } => {
                let reason = AbortReason::Cancelled { caller };
                self.aborted.mark(job_id, reason);
                return abort(job_id, reason);
            }
        }
        None
    }

    /// Overlay view-call state read at `snap.block`. Views are authoritative for that block: apply
    /// them after every log up to and including it.
    pub fn apply_views(&mut self, snap: &ViewSnapshot) {
        if let Some(p) = snap.router_paused {
            self.router_paused = p;
        }
        if let Some(p) = snap.registry_paused {
            self.registry_paused = p;
        }
        for (contract, slot) in [
            (GovContract::Router, snap.router_upgrade),
            (GovContract::Registry, snap.registry_upgrade),
        ] {
            if let Some((op_hash, ready_at)) = slot {
                self.upgrades.retain(|(c, _), _| *c != contract);
                if ready_at != 0 {
                    self.upgrades.insert((contract, op_hash), ready_at);
                }
            }
        }
        for a in &snap.adapters {
            if let Some((adapter, status)) = a.entry {
                self.adapters.insert(
                    a.proof_system_id,
                    AdapterState {
                        adapter,
                        disabled: status == ADAPTER_STATUS_DISABLED,
                    },
                );
            }
            if let Some((new_adapter, ready_at)) = a.pending_switch {
                if ready_at == 0 {
                    self.switches.remove(&a.proof_system_id);
                } else {
                    self.switches.insert(
                        a.proof_system_id,
                        PendingSwitch {
                            new_adapter,
                            ready_at,
                        },
                    );
                }
            }
        }
    }

    /// The router or the Registry is paused.
    pub fn paused(&self) -> bool {
        self.router_paused || self.registry_paused
    }

    pub fn router_paused(&self) -> bool {
        self.router_paused
    }

    pub fn registry_paused(&self) -> bool {
        self.registry_paused
    }

    /// A verifier swap for `proof_system_id` is pending and executable at or before `t` (unix s).
    pub fn verifier_switch_ready_before(&self, proof_system_id: B256, t: u64) -> bool {
        self.switches
            .get(&proof_system_id)
            .is_some_and(|s| s.ready_at <= t)
    }

    pub fn pending_switch(&self, proof_system_id: B256) -> Option<PendingSwitch> {
        self.switches.get(&proof_system_id).copied()
    }

    /// A router or Registry upgrade is pending and executable at or before `t` (unix s).
    pub fn upgrade_ready_before(&self, t: u64) -> bool {
        self.upgrades.values().any(|&r| r <= t)
    }

    /// Every pending upgrade, earliest first.
    pub fn pending_upgrades(&self) -> Vec<PendingUpgrade> {
        let mut v: Vec<_> = self
            .upgrades
            .iter()
            .map(|(&(contract, op_hash), &ready_at)| PendingUpgrade {
                contract,
                op_hash,
                ready_at,
            })
            .collect();
        v.sort_by_key(|u| u.ready_at);
        v
    }

    /// The adapter for `proof_system_id` is Disabled.
    pub fn adapter_disabled(&self, proof_system_id: B256) -> bool {
        self.adapters
            .get(&proof_system_id)
            .is_some_and(|a| a.disabled)
    }

    /// Some proof system whose registered adapter is `adapter` is Disabled.
    pub fn adapter_address_disabled(&self, adapter: Address) -> bool {
        self.adapters
            .values()
            .any(|a| a.adapter == adapter && a.disabled)
    }

    pub fn adapter(&self, proof_system_id: B256) -> Option<AdapterState> {
        self.adapters.get(&proof_system_id).copied()
    }

    /// A `BidSubmitted` was seen for `job_id`.
    pub fn bid_submitted(&self, job_id: B256) -> bool {
        self.bids.get(&job_id).is_some()
    }

    /// The sticky abort recorded for `job_id` (`Cancelled` or `BidSubmitted`), if any.
    pub fn abort_reason(&self, job_id: B256) -> Option<AbortReason> {
        self.aborted.get(&job_id).copied()
    }
}

/// Why [`GovernanceView::witness_lock_gate`] refuses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateRefusal {
    /// The watcher has not finished its start-up read.
    NotSynced,
    /// The watcher has not caught up with the head recently: its state cannot be trusted.
    Stale,
    RouterPaused,
    RegistryPaused,
    AdapterDisabled,
    /// A verifier swap for the job's proof system is executable at or before the lock's deadline.
    VerifierSwitch {
        ready_at: u64,
    },
    /// An upgrade is executable at or before the lock's deadline.
    Upgrade {
        contract: GovContract,
        ready_at: u64,
    },
    /// The job was cancelled or bid on.
    Aborted(AbortReason),
}

impl std::fmt::Display for GateRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotSynced => write!(f, "governance watcher not synced yet"),
            Self::Stale => write!(f, "governance watcher is behind the head"),
            Self::RouterPaused => write!(f, "router paused"),
            Self::RegistryPaused => write!(f, "Registry paused"),
            Self::AdapterDisabled => write!(f, "adapter disabled"),
            Self::VerifierSwitch { ready_at } => {
                write!(
                    f,
                    "verifier swap executable at {ready_at}, before the lock deadline"
                )
            }
            Self::Upgrade { contract, ready_at } => {
                write!(
                    f,
                    "{contract:?} upgrade executable at {ready_at}, before the lock deadline"
                )
            }
            Self::Aborted(r) => write!(f, "job aborted: {r:?}"),
        }
    }
}

// ─── Watcher ────────────────────────────────────────────────────────────────────────────────────

struct Inner {
    state: GovernanceState,
    /// The last block whose logs are applied (`None` until the start-up read completes).
    scanned_through: Option<u64>,
    /// When the watcher last caught up with the head it knew.
    synced_at: Option<Instant>,
}

struct Shared {
    inner: Mutex<Inner>,
    aborts: broadcast::Sender<AbortSimulation>,
    stale_after: Duration,
}

impl Shared {
    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// A cheap, cloneable handle to the watcher's state.
#[derive(Clone)]
pub struct GovernanceView {
    shared: Arc<Shared>,
}

impl GovernanceView {
    fn read<R>(&self, f: impl FnOnce(&GovernanceState) -> R) -> R {
        f(&self.shared.lock().state)
    }

    /// See [`GovernanceState::verifier_switch_ready_before`].
    pub fn verifier_switch_ready_before(&self, proof_system_id: B256, t: u64) -> bool {
        self.read(|s| s.verifier_switch_ready_before(proof_system_id, t))
    }

    /// See [`GovernanceState::upgrade_ready_before`].
    pub fn upgrade_ready_before(&self, t: u64) -> bool {
        self.read(|s| s.upgrade_ready_before(t))
    }

    /// The router or the Registry is paused.
    pub fn paused(&self) -> bool {
        self.read(|s| s.paused())
    }

    /// The adapter registered for `proof_system_id` is Disabled.
    pub fn adapter_disabled(&self, proof_system_id: B256) -> bool {
        self.read(|s| s.adapter_disabled(proof_system_id))
    }

    /// Some proof system whose registered adapter is `adapter` is Disabled.
    pub fn adapter_address_disabled(&self, adapter: Address) -> bool {
        self.read(|s| s.adapter_address_disabled(adapter))
    }

    /// A `BidSubmitted` was seen for `job_id`.
    pub fn bid_submitted(&self, job_id: B256) -> bool {
        self.read(|s| s.bid_submitted(job_id))
    }

    /// The sticky abort recorded for `job_id`, for a simulation that starts after the event.
    pub fn abort_reason(&self, job_id: B256) -> Option<AbortReason> {
        self.read(|s| s.abort_reason(job_id))
    }

    /// A copy of the whole state (for a status page).
    pub fn state(&self) -> GovernanceState {
        self.read(|s| s.clone())
    }

    /// Live aborts, as the watcher sees them. A subscriber that lags past the channel's capacity
    /// gets `Lagged` and should fall back to [`Self::abort_reason`] for the jobs it runs.
    pub fn subscribe_aborts(&self) -> broadcast::Receiver<AbortSimulation> {
        self.shared.aborts.subscribe()
    }

    /// The last block whose logs are applied (`None` before the start-up read).
    pub fn scanned_through(&self) -> Option<u64> {
        self.shared.lock().scanned_through
    }

    /// `Some` while the state cannot be trusted: before the start-up read, or when the watcher has
    /// not caught up with the head for [`GovernanceConfig::stale_after`].
    pub fn sync_refusal(&self) -> Option<GateRefusal> {
        let inner = self.shared.lock();
        match inner.synced_at {
            None => Some(GateRefusal::NotSynced),
            Some(t) if t.elapsed() > self.shared.stale_after => Some(GateRefusal::Stale),
            Some(_) => None,
        }
    }

    /// Hold simulation of a `proof_system_id` job now: unsynced or stale, paused, or adapter disabled.
    pub fn hold(&self, proof_system_id: B256) -> Option<GateRefusal> {
        if let Some(r) = self.sync_refusal() {
            return Some(r);
        }
        self.read(|s| {
            if s.router_paused() {
                Some(GateRefusal::RouterPaused)
            } else if s.registry_paused() {
                Some(GateRefusal::RegistryPaused)
            } else if s.adapter_disabled(proof_system_id) {
                Some(GateRefusal::AdapterDisabled)
            } else {
                None
            }
        })
    }

    /// The governance part of the witness static gates and claim gate: refuse a witness lock on
    /// `job_id` (proof system `proof_system_id`) whose deadline is `deadline` (unix s) while the
    /// watcher is unsynced or stale, the router or Registry is paused, the adapter is disabled, a
    /// verifier swap or an upgrade is executable at or before `deadline`, or the job was cancelled or
    /// bid on.
    pub fn witness_lock_gate(
        &self,
        job_id: B256,
        proof_system_id: B256,
        deadline: u64,
    ) -> Result<(), GateRefusal> {
        if let Some(r) = self.hold(proof_system_id) {
            return Err(r);
        }
        self.read(|s| {
            if let Some(sw) = s.pending_switch(proof_system_id) {
                if sw.ready_at <= deadline {
                    return Err(GateRefusal::VerifierSwitch {
                        ready_at: sw.ready_at,
                    });
                }
            }
            if let Some(u) = s
                .pending_upgrades()
                .into_iter()
                .find(|u| u.ready_at <= deadline)
            {
                return Err(GateRefusal::Upgrade {
                    contract: u.contract,
                    ready_at: u.ready_at,
                });
            }
            if let Some(r) = s.abort_reason(job_id) {
                return Err(GateRefusal::Aborted(r));
            }
            Ok(())
        })
    }
}

/// The watcher: owns the polling, feeds [`GovernanceState`], serves [`GovernanceView`]s.
pub struct GovernanceWatcher {
    client: ChainClient,
    cfg: GovernanceConfig,
    shared: Arc<Shared>,
    /// `(head, when it was last seen to move or read live)` for the stalled-cache fallback.
    head_seen: Mutex<(u64, Instant)>,
    last_resync: Mutex<Instant>,
}

/// What one [`GovernanceWatcher::poll_once`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PollOutcome {
    pub head: u64,
    pub scanned_through: u64,
    pub logs_applied: usize,
    pub aborts: usize,
}

impl GovernanceWatcher {
    pub fn new(client: ChainClient, cfg: GovernanceConfig) -> Self {
        let (aborts, _) = broadcast::channel(ABORT_CHANNEL_CAP);
        let now = Instant::now();
        Self {
            shared: Arc::new(Shared {
                inner: Mutex::new(Inner {
                    state: GovernanceState::new(cfg.prover),
                    scanned_through: None,
                    synced_at: None,
                }),
                aborts,
                stale_after: cfg.stale_after,
            }),
            client,
            cfg,
            head_seen: Mutex::new((0, now)),
            last_resync: Mutex::new(now),
        }
    }

    pub fn view(&self) -> GovernanceView {
        GovernanceView {
            shared: self.shared.clone(),
        }
    }

    fn filter(&self, from: u64, to: u64) -> Filter {
        Filter::new()
            .address(vec![
                self.client.hemi_prove,
                self.client.hemi_prove_registry,
            ])
            .event_signature(governance_topics())
            .from_block(from)
            .to_block(to)
    }

    /// One bounded `eth_getLogs`, decoded, in chain order.
    async fn fetch_range(&self, from: u64, to: u64) -> Result<Vec<(GovEvent, Option<u64>)>> {
        let mut logs = self
            .client
            .provider
            .get_logs(&self.filter(from, to))
            .await
            .with_context(|| format!("governance logs {from}..={to}"))?;
        logs.sort_by_key(|l| (l.block_number, l.log_index));
        let (router, registry) = (self.client.hemi_prove, self.client.hemi_prove_registry);
        Ok(logs
            .iter()
            .filter_map(|l| decode_governance_log(l, router, registry).map(|e| (e, l.block_number)))
            .collect())
    }

    /// Read every view at `block` (each `None` a failed read).
    pub async fn read_views(&self, block: u64) -> ViewSnapshot {
        let at = BlockId::number(block);
        let p = &*self.client.provider;
        let router = IHemiProveAux::new(self.client.hemi_prove, p);
        let router_gov = IHemiProveRouterGov::new(self.client.hemi_prove, p);
        let registry = IHemiProveRegistry::new(self.client.hemi_prove_registry, p);
        let router_paused = router.paused().block(at).call().await.ok();
        let registry_paused = registry.paused().block(at).call().await.ok();
        let router_upgrade = router_gov
            .pendingUpgrade()
            .block(at)
            .call()
            .await
            .ok()
            .map(|r| (r.operationHash, r.readyAt.to::<u64>()));
        let registry_upgrade = registry
            .pendingUpgrade()
            .block(at)
            .call()
            .await
            .ok()
            .map(|r| (r.opHash, r.readyAt.to::<u64>()));
        let mut adapters = Vec::with_capacity(self.cfg.proof_systems.len());
        for &ps in &self.cfg.proof_systems {
            let entry = registry
                .getAdapter(ps)
                .block(at)
                .call()
                .await
                .ok()
                .map(|e| (e.adapter, e.status));
            let pending_switch = registry
                .pendingReactivation(ps)
                .block(at)
                .call()
                .await
                .ok()
                .map(|r| (r.newAdapter, r.readyAt.to::<u64>()));
            adapters.push(AdapterView {
                proof_system_id: ps,
                entry,
                pending_switch,
            });
        }
        ViewSnapshot {
            block,
            router_paused,
            registry_paused,
            router_upgrade,
            registry_upgrade,
            adapters,
        }
    }

    /// The start-up read: a bounded log look-back up to the head, then the views at the head on top.
    /// Every view must read (a partial picture could hide a pause); the look-back must complete.
    /// Returns the head it synced to.
    pub async fn init(&self) -> Result<u64> {
        let head = self.client.get_block_number().await?;
        let floor = self.client.scan_from_block.min(head);
        let from = head.saturating_sub(self.cfg.lookback_blocks).max(floor);
        let chunk = self.cfg.chunk_blocks.max(1);
        let mut events = Vec::new();
        let mut start = from;
        while start <= head {
            let end = start.saturating_add(chunk - 1).min(head);
            events.extend(self.fetch_range(start, end).await?);
            start = end + 1;
        }
        let snap = self.read_views(head).await;
        if !snap.complete() {
            bail!("governance views at block {head} did not all read: {snap:?}");
        }
        let mut inner = self.shared.lock();
        let mut state = GovernanceState::new(self.cfg.prover);
        for (ev, block) in &events {
            state.apply(ev, false, *block);
        }
        state.apply_views(&snap);
        inner.state = state;
        inner.scanned_through = Some(head);
        inner.synced_at = Some(Instant::now());
        drop(inner);
        *self.head_seen.lock().unwrap_or_else(|e| e.into_inner()) = (head, Instant::now());
        *self.last_resync.lock().unwrap_or_else(|e| e.into_inner()) = Instant::now();
        tracing::info!(
            "governance watcher synced at block {head} ({} look-back events from block {from})",
            events.len()
        );
        Ok(head)
    }

    /// The head to scan to: the monitor's cached head, read live when it has not moved for
    /// [`HEAD_STALL`] (the monitor may not be running).
    async fn head(&self) -> Result<u64> {
        let cached = self.client.head_block_cached().await?;
        let (seen, at) = *self.head_seen.lock().unwrap_or_else(|e| e.into_inner());
        let head = if cached > seen {
            cached
        } else if at.elapsed() >= HEAD_STALL {
            self.client.get_block_number().await?.max(cached)
        } else {
            return Ok(seen.max(cached));
        };
        *self.head_seen.lock().unwrap_or_else(|e| e.into_inner()) = (head, Instant::now());
        Ok(head)
    }

    /// One incremental poll: scan up to [`GovernanceConfig::max_chunks_per_poll`] ranges past the
    /// last scanned block, applying events live (and broadcasting their aborts), advancing per range;
    /// then, once caught up and [`GovernanceConfig::resync_interval`] has passed, re-read the views
    /// at the scanned block. Errors leave the progress made so far.
    pub async fn poll_once(&self) -> Result<PollOutcome> {
        let Some(mut through) = self.shared.lock().scanned_through else {
            bail!("governance watcher polled before init");
        };
        let head = self.head().await?;
        let chunk = self.cfg.chunk_blocks.max(1);
        let mut applied = 0;
        let mut aborts = 0;
        for _ in 0..self.cfg.max_chunks_per_poll.max(1) {
            if through >= head {
                break;
            }
            let start = through + 1;
            let end = start.saturating_add(chunk - 1).min(head);
            let events = self.fetch_range(start, end).await?;
            let mut inner = self.shared.lock();
            for (ev, block) in &events {
                if let Some(a) = inner.state.apply(ev, true, *block) {
                    aborts += 1;
                    // No subscriber is fine: the sticky marks still answer `abort_reason`.
                    let _ = self.shared.aborts.send(a);
                }
            }
            applied += events.len();
            inner.scanned_through = Some(end);
            through = end;
        }
        if through >= head {
            self.shared.lock().synced_at = Some(Instant::now());
            let due = self
                .last_resync
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .elapsed()
                >= self.cfg.resync_interval;
            if due {
                self.resync(through).await;
            }
        }
        Ok(PollOutcome {
            head,
            scanned_through: through,
            logs_applied: applied,
            aborts,
        })
    }

    /// Re-read the views at `block` (the block the logs are applied through) and overlay them,
    /// keeping the log-derived value of any read that fails.
    async fn resync(&self, block: u64) {
        let snap = self.read_views(block).await;
        let mut inner = self.shared.lock();
        // Only if no newer logs were applied meanwhile (views are authoritative for `block` alone).
        if inner.scanned_through == Some(block) {
            inner.state.apply_views(&snap);
        }
        drop(inner);
        *self.last_resync.lock().unwrap_or_else(|e| e.into_inner()) = Instant::now();
        if !snap.complete() {
            tracing::debug!("governance resync at block {block}: some views did not read");
        }
    }

    /// Run forever: start-up read (retried every poll interval until it succeeds), then a poll every
    /// [`GovernanceConfig::poll_interval`]. Like the job monitor, a poll is skipped while the endpoint
    /// is rate-limiting and the last poll was recent. To charge its requests to a lane, run it inside
    /// [`crate::rpc_meter::with_lane`].
    pub async fn run(self) -> Result<()> {
        const RATE_LIMITED_POLL: Duration = Duration::from_secs(30);
        let mut timer = tokio::time::interval(self.cfg.poll_interval);
        timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut last_poll = Instant::now();
        loop {
            timer.tick().await;
            if self.shared.lock().scanned_through.is_none() {
                if let Err(e) = self.init().await {
                    tracing::warn!("governance watcher start-up read failed: {e:#}; retrying");
                }
                continue;
            }
            if self
                .client
                .rpc_meter()
                .rate_limited_within(RATE_LIMITED_POLL)
                && last_poll.elapsed() < RATE_LIMITED_POLL
            {
                continue;
            }
            last_poll = Instant::now();
            match self.poll_once().await {
                Ok(o) if o.aborts > 0 => {
                    tracing::debug!("governance poll: {o:?}");
                }
                Ok(_) => {}
                Err(e) => tracing::warn!("governance poll failed: {e:#}"),
            }
        }
    }
}

// ─── Deployment constants, cached per block (§17.6) ─────────────────────────────────────────────

/// Values that cannot change within a block (deployment constants, oracle parameters), cached per
/// `(key, block)`: a read at a block the cache already holds costs no request. Only the newest block
/// per key is kept. Generic, so the DA path can cache its oracle parameters here too.
pub struct PerBlockCache<K, V> {
    entries: Mutex<HashMap<K, (u64, V)>>,
}

impl<K: Eq + Hash + Clone, V: Clone> Default for PerBlockCache<K, V> {
    fn default() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
        }
    }
}

impl<K: Eq + Hash + Clone, V: Clone> PerBlockCache<K, V> {
    pub fn new() -> Self {
        Self::default()
    }

    /// The value cached for `key` at exactly `block`.
    pub fn get(&self, key: &K, block: u64) -> Option<V> {
        let entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        entries
            .get(key)
            .filter(|(b, _)| *b == block)
            .map(|(_, v)| v.clone())
    }

    /// Cache `value` for `key` at `block`, unless a newer block is already cached.
    pub fn insert(&self, key: K, block: u64, value: V) {
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        match entries.get(&key) {
            Some((b, _)) if *b > block => {}
            _ => {
                entries.insert(key, (block, value));
            }
        }
    }

    /// The value for `key` at `block`: cached, else `fetch`ed (a failed fetch is not cached).
    pub async fn get_or_try_fetch<F, Fut>(&self, key: K, block: u64, fetch: F) -> Result<V>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<V>>,
    {
        if let Some(v) = self.get(&key, block) {
            return Ok(v);
        }
        let v = fetch().await?;
        self.insert(key, block, v.clone());
        Ok(v)
    }
}

/// A risc0 adapter's constants at one block: what the claim gate's "the adapter's `SELECTOR()`
/// matches this toolchain" reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdapterConstants {
    pub block: u64,
    pub adapter: Address,
    /// AdapterStatus (0 Unregistered, 1 Active, 2 Deprecated, 3 Disabled).
    pub status: u8,
    pub native_verifier: Address,
    /// The native verifier's `SELECTOR()`: the 4 bytes every seal must start with.
    pub selector: [u8; 4],
}

/// Per-block cache of deployment constants (design §17.6).
#[derive(Default)]
pub struct DeploymentConstants {
    risc0: PerBlockCache<B256, AdapterConstants>,
}

impl DeploymentConstants {
    pub fn new() -> Self {
        Self::default()
    }

    /// The risc0 adapter registered for `proof_system_id`, its native verifier and that verifier's
    /// `SELECTOR()`, read at the client's cached head and cached for that block (three reads on a
    /// miss, none on a hit).
    pub async fn risc0_adapter(
        &self,
        client: &ChainClient,
        proof_system_id: B256,
    ) -> Result<AdapterConstants> {
        let block = client.head_block_cached().await?;
        self.risc0
            .get_or_try_fetch(proof_system_id, block, || {
                read_risc0_adapter(client, proof_system_id, block)
            })
            .await
    }
}

async fn read_risc0_adapter(
    client: &ChainClient,
    proof_system_id: B256,
    block: u64,
) -> Result<AdapterConstants> {
    let at = BlockId::number(block);
    let p = &*client.provider;
    let entry = IHemiProveRegistry::new(client.hemi_prove_registry, p)
        .getAdapter(proof_system_id)
        .block(at)
        .call()
        .await
        .context("Registry.getAdapter")?;
    if entry.adapter == Address::ZERO {
        bail!("proof system {proof_system_id} has no adapter registered");
    }
    let native_verifier = IVerifierAdapter::new(entry.adapter, p)
        .nativeVerifier()
        .block(at)
        .call()
        .await
        .context("adapter.nativeVerifier()")?;
    let selector = IRiscZeroSelectable::new(native_verifier, p)
        .SELECTOR()
        .block(at)
        .call()
        .await
        .context("verifier SELECTOR()")?;
    Ok(AdapterConstants {
        block,
        adapter: entry.adapter,
        status: entry.status,
        native_verifier,
        selector: selector.0,
    })
}

/// Compile-time: the handles are shareable, and `run` can be spawned.
#[allow(dead_code)]
fn _assert_send_sync(w: GovernanceWatcher) {
    fn is<T: Send + Sync>() {}
    fn spawnable<T: Send + 'static>(_: T) {}
    is::<GovernanceView>();
    is::<GovernanceWatcher>();
    is::<DeploymentConstants>();
    spawnable(w.run());
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::{aliases::U40, aliases::U48, aliases::U96, Log as PrimLog, U256};

    const ROUTER: Address = Address::repeat_byte(0xa1);
    const REGISTRY: Address = Address::repeat_byte(0xa2);
    const ME: Address = Address::repeat_byte(0x11);
    const OTHER: Address = Address::repeat_byte(0x22);

    fn ps() -> B256 {
        alloy::primitives::keccak256("risczero.groth16.v1")
    }

    /// An RPC log carrying `ev` (encoded by the bindings), emitted by `address` in `block`.
    fn rpc_log<E: SolEvent>(address: Address, ev: &E, block: u64) -> Log {
        Log {
            inner: PrimLog {
                address,
                data: ev.encode_log_data(),
            },
            block_number: Some(block),
            ..Default::default()
        }
    }

    fn dec(log: &Log) -> Option<GovEvent> {
        decode_governance_log(log, ROUTER, REGISTRY)
    }

    #[test]
    fn decodes_every_watched_event_from_the_right_contract() {
        let op = B256::repeat_byte(0x0b);
        let job = B256::repeat_byte(0x0c);
        let new_adapter = Address::repeat_byte(0x33);
        let cases: Vec<(Log, GovEvent)> = vec![
            (
                rpc_log(ROUTER, &IHemiProveAux::Paused { account: OTHER }, 1),
                GovEvent::Paused {
                    contract: GovContract::Router,
                    paused: true,
                },
            ),
            (
                rpc_log(REGISTRY, &IHemiProveRegistry::Paused { account: OTHER }, 1),
                GovEvent::Paused {
                    contract: GovContract::Registry,
                    paused: true,
                },
            ),
            (
                rpc_log(
                    REGISTRY,
                    &IHemiProveRegistry::Unpaused { account: OTHER },
                    1,
                ),
                GovEvent::Paused {
                    contract: GovContract::Registry,
                    paused: false,
                },
            ),
            (
                rpc_log(
                    ROUTER,
                    &IHemiProveRouterGov::UpgradeProposed {
                        operationHash: op,
                        readyAt: U48::from(1_900_000_000u64),
                    },
                    1,
                ),
                GovEvent::UpgradeProposed {
                    contract: GovContract::Router,
                    op_hash: op,
                    ready_at: 1_900_000_000,
                },
            ),
            (
                rpc_log(
                    ROUTER,
                    &IHemiProveRouterGov::UpgradeExecuted { operationHash: op },
                    1,
                ),
                GovEvent::UpgradeCleared {
                    contract: GovContract::Router,
                    op_hash: op,
                },
            ),
            (
                rpc_log(
                    REGISTRY,
                    &IHemiProveRegistry::UpgradeExecuted {
                        opHash: op,
                        newImpl: new_adapter,
                    },
                    1,
                ),
                GovEvent::UpgradeCleared {
                    contract: GovContract::Registry,
                    op_hash: op,
                },
            ),
            (
                rpc_log(
                    REGISTRY,
                    &IHemiProveRegistry::VerifierSwitchProposed {
                        proofSystemId: ps(),
                        newAdapter: new_adapter,
                        readyAt: U40::from(1_800_000_000u64),
                    },
                    1,
                ),
                GovEvent::VerifierSwitchProposed {
                    proof_system_id: ps(),
                    new_adapter,
                    ready_at: 1_800_000_000,
                },
            ),
            (
                rpc_log(
                    REGISTRY,
                    &IHemiProveRegistry::VerifierSwitchCancelled {
                        proofSystemId: ps(),
                        rejectedAdapter: new_adapter,
                    },
                    1,
                ),
                GovEvent::VerifierSwitchCancelled {
                    proof_system_id: ps(),
                },
            ),
            (
                rpc_log(
                    REGISTRY,
                    &IHemiProveRegistry::AdapterDisabledEvent {
                        proofSystemId: ps(),
                    },
                    1,
                ),
                GovEvent::AdapterDisabled {
                    proof_system_id: ps(),
                },
            ),
            (
                rpc_log(
                    REGISTRY,
                    &IHemiProveRegistry::AdapterReactivated {
                        proofSystemId: ps(),
                        adapter: new_adapter,
                    },
                    1,
                ),
                GovEvent::AdapterEnabled {
                    proof_system_id: ps(),
                    adapter: new_adapter,
                },
            ),
            (
                rpc_log(
                    ROUTER,
                    &IHemiProveAux::BidSubmitted {
                        jobId: job,
                        bidder: OTHER,
                        bidAmount: U96::from(5u64),
                        newBidDeadline: U40::from(9u64),
                        operator: Address::ZERO,
                        previousBidder: Address::ZERO,
                    },
                    1,
                ),
                GovEvent::BidSubmitted {
                    job_id: job,
                    bidder: OTHER,
                },
            ),
            (
                rpc_log(
                    ROUTER,
                    &IHemiProveCore::JobClaimed {
                        jobId: job,
                        prover: OTHER,
                        operator: ME,
                        settledPrice: U96::from(7u64),
                        bonusAmount: U96::ZERO,
                        lockDeadline: U40::from(10u64),
                    },
                    1,
                ),
                GovEvent::JobClaimed {
                    job_id: job,
                    prover: OTHER,
                },
            ),
            (
                rpc_log(
                    ROUTER,
                    &IHemiProveFulfill::JobCancelled {
                        jobId: job,
                        caller: OTHER,
                        refundAmount: U256::from(1u64),
                        bonusBurned: U256::ZERO,
                    },
                    1,
                ),
                GovEvent::JobCancelled {
                    job_id: job,
                    caller: OTHER,
                },
            ),
        ];
        let topics = governance_topics();
        for (log, want) in &cases {
            assert_eq!(dec(log).as_ref(), Some(want), "{want:?}");
            assert!(
                topics.contains(&log.topics()[0]),
                "{want:?} not in the filter"
            );
        }
    }

    #[test]
    fn logs_are_attributed_by_address_and_foreign_or_removed_ones_ignored() {
        // The router's Paused is not the Registry's, though topic0 is shared.
        let paused = IHemiProveAux::Paused { account: OTHER };
        assert_eq!(
            dec(&rpc_log(ROUTER, &paused, 1)),
            Some(GovEvent::Paused {
                contract: GovContract::Router,
                paused: true
            })
        );
        // Any other contract's Paused (Staking, a token) says nothing.
        assert_eq!(dec(&rpc_log(Address::repeat_byte(0x99), &paused, 1)), None);
        // A registry-only event emitted by the router address is not decoded as one.
        let disabled = IHemiProveRegistry::AdapterDisabledEvent {
            proofSystemId: ps(),
        };
        assert_eq!(dec(&rpc_log(ROUTER, &disabled, 1)), None);
        // A job event from the Registry address is ignored.
        let cancelled = IHemiProveFulfill::JobCancelled {
            jobId: B256::ZERO,
            caller: OTHER,
            refundAmount: U256::ZERO,
            bonusBurned: U256::ZERO,
        };
        assert_eq!(dec(&rpc_log(REGISTRY, &cancelled, 1)), None);
        // A reorged-out log.
        let mut removed = rpc_log(ROUTER, &paused, 1);
        removed.removed = true;
        assert_eq!(dec(&removed), None);
        // Malformed: right topic0, truncated topics.
        let mut short = rpc_log(ROUTER, &cancelled, 1);
        short.inner.data = alloy::primitives::LogData::new_unchecked(
            vec![IHemiProveFulfill::JobCancelled::SIGNATURE_HASH],
            Default::default(),
        );
        assert_eq!(dec(&short), None);
        // An unwatched router event.
        let reopened_topic = alloy::primitives::keccak256("Something(bytes32)");
        let mut other = rpc_log(ROUTER, &paused, 1);
        other.inner.data =
            alloy::primitives::LogData::new_unchecked(vec![reopened_topic], Default::default());
        assert_eq!(dec(&other), None);
    }

    #[test]
    fn pauses_track_router_and_registry_separately() {
        let mut s = GovernanceState::new(ME);
        assert!(!s.paused());
        s.apply(
            &GovEvent::Paused {
                contract: GovContract::Registry,
                paused: true,
            },
            true,
            None,
        );
        assert!(s.paused() && s.registry_paused() && !s.router_paused());
        s.apply(
            &GovEvent::Paused {
                contract: GovContract::Router,
                paused: true,
            },
            true,
            None,
        );
        s.apply(
            &GovEvent::Paused {
                contract: GovContract::Registry,
                paused: false,
            },
            true,
            None,
        );
        assert!(s.paused() && s.router_paused());
        s.apply(
            &GovEvent::Paused {
                contract: GovContract::Router,
                paused: false,
            },
            true,
            None,
        );
        assert!(!s.paused());
    }

    #[test]
    fn upgrades_are_pending_from_proposal_until_cancelled_or_executed() {
        let mut s = GovernanceState::new(ME);
        let (a, b) = (B256::repeat_byte(1), B256::repeat_byte(2));
        s.apply(
            &GovEvent::UpgradeProposed {
                contract: GovContract::Router,
                op_hash: a,
                ready_at: 1_000,
            },
            true,
            None,
        );
        assert!(s.upgrade_ready_before(1_000), "ready AT t counts");
        assert!(s.upgrade_ready_before(5_000));
        assert!(!s.upgrade_ready_before(999));
        // A cancel of another operation hash changes nothing; of this one, clears it.
        s.apply(
            &GovEvent::UpgradeCleared {
                contract: GovContract::Router,
                op_hash: b,
            },
            true,
            None,
        );
        assert!(s.upgrade_ready_before(1_000));
        s.apply(
            &GovEvent::UpgradeCleared {
                contract: GovContract::Registry,
                op_hash: a,
            },
            true,
            None,
        );
        assert!(
            s.upgrade_ready_before(1_000),
            "the Registry's clear is not the router's"
        );
        s.apply(
            &GovEvent::UpgradeCleared {
                contract: GovContract::Router,
                op_hash: a,
            },
            true,
            None,
        );
        assert!(!s.upgrade_ready_before(u64::MAX));
        // Registry upgrades count too; one pending operation per contract.
        s.apply(
            &GovEvent::UpgradeProposed {
                contract: GovContract::Registry,
                op_hash: a,
                ready_at: 7,
            },
            true,
            None,
        );
        s.apply(
            &GovEvent::UpgradeProposed {
                contract: GovContract::Registry,
                op_hash: b,
                ready_at: 9,
            },
            true,
            None,
        );
        assert_eq!(
            s.pending_upgrades(),
            vec![PendingUpgrade {
                contract: GovContract::Registry,
                op_hash: b,
                ready_at: 9
            }]
        );
    }

    #[test]
    fn a_verifier_switch_is_pending_until_cancelled_or_landed() {
        let mut s = GovernanceState::new(ME);
        let new = Address::repeat_byte(0x44);
        s.apply(
            &GovEvent::AdapterDisabled {
                proof_system_id: ps(),
            },
            true,
            None,
        );
        assert!(s.adapter_disabled(ps()));
        s.apply(
            &GovEvent::VerifierSwitchProposed {
                proof_system_id: ps(),
                new_adapter: new,
                ready_at: 500,
            },
            true,
            None,
        );
        assert!(s.verifier_switch_ready_before(ps(), 500));
        assert!(!s.verifier_switch_ready_before(ps(), 499));
        assert!(
            !s.verifier_switch_ready_before(B256::repeat_byte(9), u64::MAX),
            "per proof system"
        );
        // A replacing proposal (the contract emits Cancelled for the old one first).
        s.apply(
            &GovEvent::VerifierSwitchCancelled {
                proof_system_id: ps(),
            },
            true,
            None,
        );
        assert!(!s.verifier_switch_ready_before(ps(), u64::MAX));
        s.apply(
            &GovEvent::VerifierSwitchProposed {
                proof_system_id: ps(),
                new_adapter: new,
                ready_at: 900,
            },
            true,
            None,
        );
        assert_eq!(
            s.pending_switch(ps()),
            Some(PendingSwitch {
                new_adapter: new,
                ready_at: 900
            })
        );
        // The swap lands: enabled at the new adapter, nothing pending.
        s.apply(
            &GovEvent::AdapterEnabled {
                proof_system_id: ps(),
                adapter: new,
            },
            true,
            None,
        );
        assert!(!s.verifier_switch_ready_before(ps(), u64::MAX));
        assert!(!s.adapter_disabled(ps()));
        assert_eq!(s.adapter(ps()).map(|a| a.adapter), Some(new));
    }

    #[test]
    fn adapter_disable_is_queryable_by_proof_system_and_by_address() {
        let mut s = GovernanceState::new(ME);
        let adapter = Address::repeat_byte(0x55);
        s.apply(
            &GovEvent::AdapterEnabled {
                proof_system_id: ps(),
                adapter,
            },
            true,
            None,
        );
        assert!(!s.adapter_address_disabled(adapter));
        s.apply(
            &GovEvent::AdapterDisabled {
                proof_system_id: ps(),
            },
            true,
            None,
        );
        assert!(s.adapter_disabled(ps()));
        assert!(s.adapter_address_disabled(adapter));
        assert!(!s.adapter_address_disabled(Address::repeat_byte(0x56)));
        s.apply(
            &GovEvent::AdapterEnabled {
                proof_system_id: ps(),
                adapter,
            },
            true,
            None,
        );
        assert!(!s.adapter_disabled(ps()));
    }

    #[test]
    fn live_job_events_abort_and_history_does_not() {
        let mut s = GovernanceState::new(ME);
        let job = B256::repeat_byte(0x77);
        // Our own claim never aborts.
        assert_eq!(
            s.apply(
                &GovEvent::JobClaimed {
                    job_id: job,
                    prover: ME
                },
                true,
                Some(5)
            ),
            None
        );
        // Another prover's live claim aborts, but leaves no sticky mark (a release reopens it).
        assert_eq!(
            s.apply(
                &GovEvent::JobClaimed {
                    job_id: job,
                    prover: OTHER
                },
                true,
                Some(6)
            ),
            Some(AbortSimulation {
                job_id: job,
                reason: AbortReason::ClaimedByOther { prover: OTHER },
                block: Some(6)
            })
        );
        assert_eq!(s.abort_reason(job), None);
        // From the look-back: no abort, no claim mark — but bids and cancels are remembered.
        let old = B256::repeat_byte(0x78);
        assert_eq!(
            s.apply(
                &GovEvent::JobClaimed {
                    job_id: old,
                    prover: OTHER
                },
                false,
                Some(1)
            ),
            None
        );
        assert_eq!(
            s.apply(
                &GovEvent::BidSubmitted {
                    job_id: old,
                    bidder: OTHER
                },
                false,
                Some(1)
            ),
            None
        );
        assert!(s.bid_submitted(old));
        assert_eq!(
            s.abort_reason(old),
            Some(AbortReason::BidSubmitted { bidder: OTHER })
        );
        let cancelled = B256::repeat_byte(0x79);
        assert_eq!(
            s.apply(
                &GovEvent::JobCancelled {
                    job_id: cancelled,
                    caller: OTHER
                },
                false,
                None
            ),
            None
        );
        assert_eq!(
            s.abort_reason(cancelled),
            Some(AbortReason::Cancelled { caller: OTHER })
        );
        // Live bid and cancel abort and stick.
        let live = B256::repeat_byte(0x7a);
        assert!(s
            .apply(
                &GovEvent::BidSubmitted {
                    job_id: live,
                    bidder: OTHER
                },
                true,
                None
            )
            .is_some());
        assert!(s.bid_submitted(live));
        assert!(!s.bid_submitted(cancelled));
    }

    #[test]
    fn per_job_marks_are_bounded() {
        let mut s = GovernanceState::with_job_cap(ME, 4);
        for i in 0..10u8 {
            s.apply(
                &GovEvent::BidSubmitted {
                    job_id: B256::repeat_byte(i),
                    bidder: OTHER,
                },
                true,
                None,
            );
        }
        assert!(!s.bid_submitted(B256::repeat_byte(0)), "oldest evicted");
        assert!(s.bid_submitted(B256::repeat_byte(9)));
        assert_eq!(s.bids.map.len(), 4);
        assert_eq!(s.aborted.map.len(), 4);
    }

    #[test]
    fn views_override_the_log_state_for_their_block() {
        let mut s = GovernanceState::new(ME);
        // Logs from the look-back say paused and an upgrade pending; the views at the head say the
        // router was unpaused and the upgrade cancelled before the look-back's view of it ended.
        s.apply(
            &GovEvent::Paused {
                contract: GovContract::Router,
                paused: true,
            },
            false,
            None,
        );
        s.apply(
            &GovEvent::UpgradeProposed {
                contract: GovContract::Router,
                op_hash: B256::repeat_byte(1),
                ready_at: 50,
            },
            false,
            None,
        );
        let switch_to = Address::repeat_byte(0x66);
        let snap = ViewSnapshot {
            block: 100,
            router_paused: Some(false),
            registry_paused: Some(true),
            router_upgrade: Some((B256::ZERO, 0)),
            registry_upgrade: Some((B256::repeat_byte(3), 77)),
            adapters: vec![AdapterView {
                proof_system_id: ps(),
                entry: Some((Address::repeat_byte(0x55), ADAPTER_STATUS_DISABLED)),
                pending_switch: Some((switch_to, 300)),
            }],
        };
        assert!(snap.complete());
        s.apply_views(&snap);
        assert!(!s.router_paused());
        assert!(s.registry_paused());
        assert_eq!(
            s.pending_upgrades(),
            vec![PendingUpgrade {
                contract: GovContract::Registry,
                op_hash: B256::repeat_byte(3),
                ready_at: 77
            }]
        );
        assert!(s.adapter_disabled(ps()));
        assert!(s.verifier_switch_ready_before(ps(), 300));
        // A failed read keeps the log-derived value.
        let partial = ViewSnapshot {
            block: 101,
            router_paused: None,
            adapters: vec![AdapterView {
                proof_system_id: ps(),
                entry: Some((Address::repeat_byte(0x55), 1)),
                pending_switch: None,
            }],
            ..Default::default()
        };
        assert!(!partial.complete());
        s.apply(
            &GovEvent::Paused {
                contract: GovContract::Router,
                paused: true,
            },
            true,
            None,
        );
        s.apply_views(&partial);
        assert!(s.router_paused(), "kept: the read failed");
        assert!(!s.adapter_disabled(ps()), "Active per the view");
        assert!(
            s.verifier_switch_ready_before(ps(), 300),
            "kept: the read failed"
        );
    }

    fn view_with(state: GovernanceState, synced: Option<Instant>) -> GovernanceView {
        let (aborts, _) = broadcast::channel(4);
        GovernanceView {
            shared: Arc::new(Shared {
                inner: Mutex::new(Inner {
                    state,
                    scanned_through: synced.map(|_| 100),
                    synced_at: synced,
                }),
                aborts,
                stale_after: Duration::from_secs(180),
            }),
        }
    }

    #[tokio::test(start_paused = true)]
    async fn the_lock_gate_refuses_on_every_governance_cause() {
        let job = B256::repeat_byte(0x21);
        let unsynced = view_with(GovernanceState::new(ME), None);
        assert_eq!(
            unsynced.witness_lock_gate(job, ps(), 1_000),
            Err(GateRefusal::NotSynced)
        );

        let ok = view_with(GovernanceState::new(ME), Some(Instant::now()));
        assert_eq!(ok.witness_lock_gate(job, ps(), 1_000), Ok(()));
        tokio::time::advance(Duration::from_secs(181)).await;
        assert_eq!(
            ok.witness_lock_gate(job, ps(), 1_000),
            Err(GateRefusal::Stale)
        );

        let gate = |evs: &[GovEvent], deadline: u64| {
            let mut s = GovernanceState::new(ME);
            for e in evs {
                s.apply(e, true, None);
            }
            view_with(s, Some(Instant::now())).witness_lock_gate(job, ps(), deadline)
        };
        assert_eq!(
            gate(
                &[GovEvent::Paused {
                    contract: GovContract::Router,
                    paused: true
                }],
                1_000
            ),
            Err(GateRefusal::RouterPaused)
        );
        assert_eq!(
            gate(
                &[GovEvent::Paused {
                    contract: GovContract::Registry,
                    paused: true
                }],
                1_000
            ),
            Err(GateRefusal::RegistryPaused)
        );
        assert_eq!(
            gate(
                &[GovEvent::AdapterDisabled {
                    proof_system_id: ps()
                }],
                1_000
            ),
            Err(GateRefusal::AdapterDisabled)
        );
        // Another proof system's disable does not hold this one.
        assert_eq!(
            gate(
                &[GovEvent::AdapterDisabled {
                    proof_system_id: B256::ZERO
                }],
                1_000
            ),
            Ok(())
        );
        let switch = GovEvent::VerifierSwitchProposed {
            proof_system_id: ps(),
            new_adapter: OTHER,
            ready_at: 900,
        };
        assert_eq!(
            gate(std::slice::from_ref(&switch), 1_000),
            Err(GateRefusal::VerifierSwitch { ready_at: 900 })
        );
        assert_eq!(gate(&[switch], 899), Ok(()), "ready after the deadline");
        let upgrade = GovEvent::UpgradeProposed {
            contract: GovContract::Router,
            op_hash: B256::repeat_byte(1),
            ready_at: 1_000,
        };
        assert_eq!(
            gate(std::slice::from_ref(&upgrade), 1_000),
            Err(GateRefusal::Upgrade {
                contract: GovContract::Router,
                ready_at: 1_000
            })
        );
        assert_eq!(gate(&[upgrade], 999), Ok(()));
        assert_eq!(
            gate(
                &[GovEvent::BidSubmitted {
                    job_id: job,
                    bidder: OTHER
                }],
                1_000
            ),
            Err(GateRefusal::Aborted(AbortReason::BidSubmitted {
                bidder: OTHER
            }))
        );
        assert_eq!(
            gate(
                &[GovEvent::JobCancelled {
                    job_id: job,
                    caller: OTHER
                }],
                1_000
            ),
            Err(GateRefusal::Aborted(AbortReason::Cancelled {
                caller: OTHER
            }))
        );
        // A claim by another prover is not a lock-gate refusal (the claimability eth_call decides).
        assert_eq!(
            gate(
                &[GovEvent::JobClaimed {
                    job_id: job,
                    prover: OTHER
                }],
                1_000
            ),
            Ok(())
        );
    }

    #[test]
    fn per_block_cache_hits_only_at_its_block() {
        let c: PerBlockCache<u8, u32> = PerBlockCache::new();
        assert_eq!(c.get(&1, 10), None);
        c.insert(1, 10, 7);
        assert_eq!(c.get(&1, 10), Some(7));
        assert_eq!(c.get(&1, 11), None, "a new block re-reads");
        // An older block's value never replaces a newer one.
        c.insert(1, 9, 8);
        assert_eq!(c.get(&1, 10), Some(7));
        c.insert(1, 11, 9);
        assert_eq!(c.get(&1, 11), Some(9));
        assert_eq!(c.get(&1, 10), None);
    }

    #[tokio::test]
    async fn per_block_cache_fetches_once_per_block_and_never_caches_errors() {
        let c: PerBlockCache<u8, u32> = PerBlockCache::new();
        let calls = std::sync::atomic::AtomicU32::new(0);
        let fetch = |v: u32| {
            calls.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            async move { Ok(v) }
        };
        assert_eq!(c.get_or_try_fetch(1, 10, || fetch(5)).await.unwrap(), 5);
        assert_eq!(c.get_or_try_fetch(1, 10, || fetch(6)).await.unwrap(), 5);
        assert_eq!(calls.load(std::sync::atomic::Ordering::Relaxed), 1);
        assert!(c
            .get_or_try_fetch(2, 10, || async { Err(anyhow::anyhow!("rpc down")) })
            .await
            .is_err());
        assert_eq!(c.get_or_try_fetch(2, 10, || fetch(3)).await.unwrap(), 3);
        assert_eq!(c.get_or_try_fetch(1, 11, || fetch(8)).await.unwrap(), 8);
    }
}
