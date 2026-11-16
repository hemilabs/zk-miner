//! The broker's shared state and capability provisioning (plan §11.1).

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use alloy_primitives::B256;
use zkminer_witness::envelope::{decode_capability, Capability, CapabilityKind};

use crate::artifact::ArtifactReader;
use crate::cache::{Lru, RpcKey};
use crate::config::{BrokerConfig, EndpointSpec, EvmRpcEndpoint, HostFacts};
use crate::hooks::Hooks;
use crate::job::{Job, JobSource};
use crate::lanes::ByteLanes;
use crate::net::{build_policy, Endpoint, PolicyHandle};
use crate::spool::Spool;

/// An `evm-rpc/v1` endpoint and what it is provisioned for.
pub(crate) struct EvmEndpoint {
    pub info: EvmRpcEndpoint,
    pub ep: Arc<Endpoint>,
}

pub(crate) struct Broker {
    pub cfg: BrokerConfig,
    pub hooks: Hooks,
    pub policy: PolicyHandle,
    pub own_addresses: RwLock<Vec<IpAddr>>,
    pub evm: Vec<EvmEndpoint>,
    pub blob_mirrors: Vec<Arc<Endpoint>>,
    pub artifacts: ArtifactReader,
    /// The global in-flight byte budget, with its held-lock lane.
    pub bytes: Arc<ByteLanes>,
    pub rpc_cache: Mutex<Lru<RpcKey, Vec<u8>>>,
    pub spool: Arc<Spool>,
    pub jobs: Mutex<HashMap<B256, Arc<Job>>>,
    ids: AtomicU64,
}

impl Broker {
    /// Builds every endpoint client and the network floor. Needs a tokio runtime.
    pub fn new(cfg: BrokerConfig, host: HostFacts, hooks: Hooks) -> anyhow::Result<Arc<Self>> {
        let policy: PolicyHandle = Arc::new(RwLock::new(build_policy(
            cfg.endpoints(),
            &host.resolved,
            cfg.deny.clone(),
            host.connected.clone(),
        )));
        let mk = |spec: &EndpointSpec| {
            Endpoint::new(
                spec.clone(),
                host.resolved.get(&spec.alias).cloned().unwrap_or_default(),
                policy.clone(),
                hooks.egress.clone(),
                &cfg.timeouts,
            )
        };
        let evm = cfg
            .evm_rpc
            .iter()
            .map(|e| Ok(EvmEndpoint { info: e.clone(), ep: mk(&e.spec)? }))
            .collect::<Result<Vec<_>, reqwest::Error>>()?;
        let blob_mirrors = cfg.blob_mirrors.iter().map(&mk).collect::<Result<Vec<_>, _>>()?;
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
        let spool = Spool::new(&cfg.spool_dir, cfg.spool_quota_bytes)?;
        Ok(Arc::new(Self {
            rpc_cache: Mutex::new(Lru::new(cfg.cache.rpc_max_bytes, cfg.cache.rpc_max_entries)),
            own_addresses: RwLock::new(host.own_addresses),
            hooks,
            policy,
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
                let endpoints: Vec<_> = self
                    .evm
                    .iter()
                    .filter(|e| {
                        e.info.chain_id == chain_id
                            && (e.info.archive || !archive)
                            && e.info.max_proof_age >= max_proof_age
                            && e.info.method_sets.contains(&method_set)
                    })
                    .map(|e| e.ep.clone())
                    .collect();
                (!endpoints.is_empty()).then_some(JobSource::EvmRpc { chain_id, method_set, endpoints })
            }
            CapabilityKind::BlobV1 { max_bytes } => (!self.blob_mirrors.is_empty()).then_some(JobSource::Blob { max_bytes }),
        }
    }
}
