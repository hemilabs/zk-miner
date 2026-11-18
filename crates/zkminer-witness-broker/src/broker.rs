//! The broker's shared state and capability provisioning (plan §11.1).

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use alloy_primitives::B256;
use zkminer_witness::envelope::{decode_capability, Capability, CapabilityKind};

use crate::artifact::ArtifactReader;
use crate::cache::{Lru, RpcKey};
use crate::config::{BrokerConfig, EndpointSpec, EvmRpcEndpoint, HostFacts};
use crate::hooks::Hooks;
use crate::connector::ConnectorClient;
use crate::job::{Job, JobSource};
use crate::lanes::ByteLanes;
use crate::net::{build_policy, Endpoint, EndpointEnv, PolicyHandle};
use crate::spool::Spool;

/// An `evm-rpc/v1` endpoint and what it is provisioned for.
pub(crate) struct EvmEndpoint {
    pub info: EvmRpcEndpoint,
    pub ep: Arc<Endpoint>,
}

/// The fewest blocks of recent state a full node keeps (geth's in-memory window): a non-archive
/// endpoint's pruning horizon is at least this deep, whatever its `max_proof_age`.
pub(crate) const RECENT_STATE_BLOCKS: u64 = 128;

/// The deepest `head − block` at which a source's endpoints, `(archive, max_proof_age)` each, still
/// serve state: unbounded with an archive endpoint, else the largest `max_proof_age`, at least
/// [`RECENT_STATE_BLOCKS`]. A request for state deeper than this is one no provisioned endpoint was
/// promised to answer; within it, an endpoint that lacks the state lags (or is broken).
pub(crate) fn pruning_horizon(endpoints: impl IntoIterator<Item = (bool, u64)>) -> u64 {
    endpoints
        .into_iter()
        .fold(RECENT_STATE_BLOCKS, |h, (archive, age)| {
            if archive {
                u64::MAX
            } else {
                h.max(age)
            }
        })
}

pub(crate) struct Broker {
    pub cfg: BrokerConfig,
    pub hooks: Hooks,
    /// The broker's own (second-layer) floor, with the host's connected prefixes and own
    /// addresses.
    pub policy: PolicyHandle,
    /// The host's facts as the broker read them at startup: every refresh is unioned with them.
    pub startup: HostFacts,
    /// Every connection comes from the miner's connector.
    pub connector: Arc<ConnectorClient>,
    pub evm: Vec<EvmEndpoint>,
    pub blob_mirrors: Vec<Arc<Endpoint>>,
    pub artifacts: ArtifactReader,
    /// The global in-flight byte budget, with its held-lock lane.
    pub bytes: Arc<ByteLanes>,
    pub rpc_cache: Mutex<Lru<RpcKey, Vec<u8>>>,
    pub spool: Arc<Spool>,
    pub jobs: Mutex<HashMap<B256, Arc<Job>>>,
    /// The broker's own JSON-RPC ids.
    pub ids: AtomicU64,
}

impl Broker {
    /// Builds every endpoint client and the broker's own floor. Needs a tokio runtime.
    pub fn new(cfg: BrokerConfig, host: HostFacts, hooks: Hooks, connector: Arc<ConnectorClient>) -> anyhow::Result<Arc<Self>> {
        let policy: PolicyHandle = Arc::new(RwLock::new(build_policy(
            cfg.net_mode,
            cfg.endpoints(),
            cfg.effective_deny_for(&host),
            host.connected.clone(),
            &host.own_addresses,
        )));
        let env = EndpointEnv {
            policy: policy.clone(),
            egress: hooks.egress.clone(),
            connector: connector.clone(),
            held_lock_share: cfg.budget.held_lock_share,
        };
        // Each endpoint's index in `cfg.endpoints()`: what the connector knows it by.
        let index_of = |spec: &EndpointSpec| -> anyhow::Result<u32> {
            let i = cfg
                .endpoints()
                .position(|e| e.role == spec.role && e.alias == spec.alias)
                .ok_or_else(|| anyhow::anyhow!("endpoint {} is not in the configuration", spec.alias))?;
            Ok(u32::try_from(i)?)
        };
        let mk = |spec: &EndpointSpec| -> anyhow::Result<Arc<Endpoint>> {
            Ok(Endpoint::new(spec.clone(), index_of(spec)?, &env, &cfg.timeouts))
        };
        let evm = cfg
            .evm_rpc
            .iter()
            .map(|e| Ok(EvmEndpoint { info: e.clone(), ep: mk(&e.spec)? }))
            .collect::<anyhow::Result<Vec<_>>>()?;
        let blob_mirrors = cfg.blob_mirrors.iter().map(&mk).collect::<anyhow::Result<Vec<_>>>()?;
        let bytes = Arc::new(ByteLanes::new(cfg.budget.inflight_bytes, cfg.held_lock_reserved_bytes()));
        let artifacts = match &cfg.artifacts {
            None => ArtifactReader::new(None, None, 0, 0, &cfg, bytes.clone()),
            Some(a) => ArtifactReader::new(
                Some(mk(&a.spec)?),
                a.mirror.as_ref().map(&mk).transpose()?,
                a.chain_id,
                a.max_builder_bytes,
                &cfg,
                bytes.clone(),
            ),
        };
        let spool = Spool::new(&cfg.spool_dir, cfg.spool_quota_bytes, cfg.budget.held_lock_share)?;
        Ok(Arc::new(Self {
            rpc_cache: Mutex::new(Lru::new(cfg.cache.rpc_max_bytes, cfg.cache.rpc_max_entries)),
            hooks,
            policy,
            startup: host,
            connector,
            evm,
            blob_mirrors,
            artifacts,
            bytes,
            spool,
            jobs: Mutex::new(HashMap::new()),
            ids: AtomicU64::new(1),
            cfg,
        }))
    }

    /// `n` consecutive JSON-RPC ids of the broker's own.
    pub fn next_ids(&self, n: u64) -> u64 {
        self.ids.fetch_add(n.max(1), Ordering::Relaxed)
    }

    /// The source a `(class, config)` pair is served from, if this broker provisions it: for
    /// `evm-rpc/v1`, the endpoints with the chain id, `archive` if required, a served proof age at
    /// least the config's and the method set listed (in configuration order, the failover order);
    /// `blob/v1`, if any mirror is configured. Unknown classes and undecodable configs are not
    /// provisioned.
    pub fn provision(&self, class: B256, config: &[u8]) -> Option<JobSource> {
        let cap = Capability { class, config: config.to_vec().into() };
        match decode_capability(&cap).ok()? {
            CapabilityKind::EvmRpcV1 { chain_id, archive, method_set, max_proof_age } => {
                let serving: Vec<_> = self
                    .evm
                    .iter()
                    .filter(|e| {
                        e.info.chain_id == chain_id
                            && (e.info.archive || !archive)
                            && e.info.max_proof_age >= max_proof_age
                            && e.info.method_sets.contains(&method_set)
                    })
                    .collect();
                let horizon = pruning_horizon(
                    serving
                        .iter()
                        .map(|e| (e.info.archive, e.info.max_proof_age)),
                );
                let endpoints: Vec<_> = serving.iter().map(|e| e.ep.clone()).collect();
                (!endpoints.is_empty()).then_some(JobSource::EvmRpc {
                    chain_id,
                    method_set,
                    endpoints,
                    horizon,
                })
            }
            CapabilityKind::BlobV1 { max_bytes } => (!self.blob_mirrors.is_empty()).then_some(JobSource::Blob { max_bytes }),
        }
    }
}
