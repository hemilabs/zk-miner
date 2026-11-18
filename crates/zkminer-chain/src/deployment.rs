//! The deployed HemiProve stack zkminer talks to, and its startup verification (handoff §2, §13
//! test 1-2).
//!
//! Before the first transaction zkminer proves it is talking to the pinned code: every proxy is the
//! ERC-1967 proxy, every implementation and router facet it routes through is the pinned release
//! code, and the RISC Zero adapter wraps the risc0-ethereum v3.1.0 verifier whose `SELECTOR()`
//! (0xe71e6620) is the seal prefix this risc0 3.1 build emits. risc0 3.0 seals (0x73c457ba) are
//! refused: the 2026-11-16 deployment verifies 3.1 only. An implementation's pin is its runtime
//! keccak with its immutables zeroed, so the same code verifies at any address; only the addresses
//! and the scan floor are per-network.
//!
//! Provenance of the pins (B9-CHAIN, 2026-11-17; `docs/metal-port-notes/B9-CHAIN.md`): the
//! authority is `script/lib/ReleaseCorePins.sol` and `script/lib/VerifierPins.sol` at commit
//! `8e1808b` of the contracts repo, which was not readable from the build host (private repository,
//! no credentials). The values below were therefore computed with this module's own method
//! ([`keccak_self_zeroed`], [`keccak_offsets_zeroed`]) from the live 743111 deployment at block
//! 7234324, after checking that the method reproduces every 2026-10-29 pin (zkmarket c8333aa
//! `AuditedCorePins.sol`) from the abandoned stack's live code byte for byte. Unchanged since the
//! 2026-10-29 release: the proxy, both adapters' code and the SP1 v6.1.0 Groth16 verifier. New: the
//! four implementations, the five facets and the risc0 3.1 verifier, whose source on the explorer is
//! risc0-ethereum v3.1.0 (`ff30da77`) with constructor arguments equal to its `ControlID.sol`.
//! `the_pins_match_the_contracts_repo` (run with `ZKMINER_CONTRACTS_REPO=<checkout at 8e1808b>`)
//! checks every pin here against the repo's pin files.

use alloy::primitives::{address, b256, keccak256, Address, B256};
use alloy::providers::Provider;
use anyhow::{bail, Context, Result};

use crate::auction::ProofSystem;
use crate::client::ChainClient;
use zkminer_contracts::bindings::{
    IHemiProveAux, IHemiProveRegistry, IHemiProveStaking, IRiscZeroSelectable, ISP1NativeVerifier,
    IVerifierAdapter,
};

/// Runtime pins of the 2026-11-16 release (contracts repo `8e1808b`; see the module doc for how
/// they were obtained and how to check them against `ReleaseCorePins.sol` / `VerifierPins.sol`).
pub mod pins {
    use super::*;
    /// OpenZeppelin ERC1967Proxy (no immutable): every core proxy. Unchanged since 2026-10-29.
    pub const ERC1967_PROXY: B256 =
        b256!("46a010df31eb642b47284650e80051e8f6239a0c995003d230b437810bc4b9b4");
    /// HemiProve router implementation (its one immutable, UUPS `__self`, zeroed).
    pub const ROUTER_IMPL: B256 =
        b256!("072ef9e8a858aea90b1643fb26d8636dfa49930d7c799750459531081a15b65b");
    /// HemiProveStaking implementation (`__self` zeroed).
    pub const STAKING_IMPL: B256 =
        b256!("d4f7e362dd8e983aaa92839496f5323d25b226bda1c99576c58999c5ceae6046");
    /// HemiProveRegistry implementation (`__self` zeroed).
    pub const REGISTRY_IMPL: B256 =
        b256!("66179b0a73aa40836725499dccca37576c75667d0f0ac6bf3b569354fc03b13f");
    /// ProgramRegistry implementation (`__self` zeroed).
    pub const PROGRAM_REGISTRY_IMPL: B256 =
        b256!("47e0b59907c774b24a7d9f8ff2b9a5dbb5d2dfe826e7e1062ce6a5379f715574");
    /// The five router facets (no immutable): HemiProveCore, Fulfill, Aux, FulfillCycle, AuxGov.
    pub const FACETS: [(&str, B256); 5] = [
        ("HemiProveCore", b256!("2f5c34ff5e6f9a5dca915a187969a81065437be9dad0350e881625dae18c5fbd")),
        ("HemiProveFulfill", b256!("50b6fe0ea4bb38f480809014f6d7d33b24e13b455c5fb42a191d45ddbd634e0b")),
        ("HemiProveAux", b256!("c9ea43491c3db833ba7cc6eae89e210f4a792f48810e4cb68933ce049599a682")),
        ("HemiProveFulfillCycle", b256!("6e11d32015642d76cf294fdf82dff9195d8b0c411a628d9609d31b68334342cd")),
        ("HemiProveAuxGov", b256!("3a7aeee0d0547b79d4dc8295531120caa0335bf4d0d110bf329bcddb6e28242f")),
    ];
    /// RiscZeroGroth16VerifierAdapter runtime with its `nativeVerifier` immutable zeroed at
    /// [`RISC0_GROTH16_ADAPTER_IMMUTABLES`]. Unchanged since 2026-10-29.
    pub const RISC0_GROTH16_ADAPTER: B256 =
        b256!("dc362a202817f67a52ef910bf022660f3723a4b7fc5e451f9799be71fb7b0a89");
    pub const RISC0_GROTH16_ADAPTER_IMMUTABLES: [usize; 3] = [101, 526, 1245];
    /// The `SELECTOR()` of the risc0-ethereum v3.0 verifier: the prefix of every risc0 3.0 Groth16
    /// seal. Kept only to name it in refusals: no deployment zkminer knows accepts it any more.
    pub const RISC0_V3_0_SELECTOR: [u8; 4] = [0x73, 0xc4, 0x57, 0xba];
    /// The `SELECTOR()` of a risc0-ethereum `RiscZeroGroth16Verifier` for risc0 3.1 (the 2026-10-20
    /// Groth16 setup, v0.2.0 key): the first 4 bytes of 3.1's default
    /// `Groth16ReceiptVerifierParameters` digest (`e71e6620a834f4d8...`), the prefix of every seal a
    /// 3.1 worker's receipt is sent with. Derived from the parameters, not from a deployment (the
    /// CLI's tests tie it to the linked risc0).
    pub const RISC0_V3_1_SELECTOR: [u8; 4] = [0xe7, 0x1e, 0x66, 0x20];
    /// risc0-ethereum v3.1.0 `RiscZeroGroth16Verifier` runtime (immutables filled: control root
    /// `e6feef13...551d`, BN254 control id `0ac2eaf9...81de`; raw keccak, 4,611 B), deployed at
    /// `0x9b85437340ce3D722F3a752bb517016B5DfFF852` on 743111. `None` would refuse every risc0 claim
    /// with [`risc0_v3_1_verifier_missing`].
    pub const RISC0_V3_1_GROTH16_VERIFIER: Option<B256> = Some(b256!(
        "26e455ef699495f789d6b9956244b62c4ed95dc3c2d81663c4b13ce14fd81c0c"
    ));
    /// SP1Groth16VerifierAdapter runtime with its `nativeVerifier` immutable zeroed at
    /// [`SP1_GROTH16_ADAPTER_IMMUTABLES`] (1,851 B). Unchanged since 2026-10-29.
    pub const SP1_GROTH16_ADAPTER: B256 =
        b256!("99d18017af86518b2b86cd982aeadc69ed9c5c9611a52ccae7b637eb1b0c636d");
    pub const SP1_GROTH16_ADAPTER_IMMUTABLES: [usize; 3] = [101, 527, 1165];
    /// SP1 circuit v6.1.0 Groth16 verifier (sp1-contracts v6.1.1 `SP1VerifierGroth16.sol`), runtime
    /// keccak (5,463 B, no immutables). Unchanged since 2026-10-29.
    pub const SP1_V6_1_0_GROTH16_VERIFIER: B256 =
        b256!("6e1a354cfd1694f27c6258729ce14a5b29fe57624d1d10c759a33aa2d7aa002b");
    /// Its `VERIFIER_HASH()`: sha256 of the circuit's `groth16_vk.bin` (SP1 SDK 6.1.0 to 6.10.0). The
    /// first 4 bytes prefix every v6.1.0 Groth16 seal.
    pub const SP1_V6_1_0_GROTH16_VERIFIER_HASH: B256 =
        b256!("4388a21c687fdd5f218d7e3d13190cac4c5355818d3605fd5fb811df468ee696");
}

/// What an operator must do before a risc0 3.1 miner can claim risc0 jobs if
/// [`pins::RISC0_V3_1_GROTH16_VERIFIER`] is empty: the exact missing pieces, for the startup log and
/// for every refusal of `risczero.groth16.v1`.
pub fn risc0_v3_1_verifier_missing() -> String {
    format!(
        "this zkminer proves risc0 3.1, whose Groth16 seals carry SELECTOR 0x{sel}, and it has no \
         risc0 3.1 verifier pin to check the chain against: \
         zkminer_chain::deployment::pins::RISC0_V3_1_GROTH16_VERIFIER is empty \
         (crates/zkminer-chain/src/deployment.rs). Missing: (1) a risc0-ethereum 3.1 \
         RiscZeroGroth16Verifier (SELECTOR() = 0x{sel}) deployed on this chain and routed by the \
         risczero.groth16.v1 adapter (Registry status Active or Deprecated); (2) that verifier's \
         runtime keccak, from the deployment's VerifierPins.sol, in \
         RISC0_V3_1_GROTH16_VERIFIER, and a rebuilt zkminer. Until both exist no risc0 job is \
         claimed (held locks are still driven); ZKMINER_SKIP_CODE_PINS=1 skips the code pins, \
         only for a verifier you have checked yourself",
        sel = alloy::hex::encode(pins::RISC0_V3_1_SELECTOR),
    )
}

/// Why a risc0 3.0 seal prefix is refused: the deployment verifies risc0 3.1 receipts only.
pub fn risc0_v3_0_refused() -> String {
    format!(
        "risc0 3.0 Groth16 seals (SELECTOR 0x{old}) are refused: the HemiProve deployment of \
         2026-11-16 verifies risc0-zkvm 3.1.0 receipts only (risc0-ethereum v3.1.0 verifier, \
         SELECTOR 0x{new}), and every fulfil with a 3.0 seal would revert VerifierCallFailed. \
         Remove prover.risc0_groth16_selector from the config so the build's own 3.1 selector is \
         used",
        old = alloy::hex::encode(pins::RISC0_V3_0_SELECTOR),
        new = alloy::hex::encode(pins::RISC0_V3_1_SELECTOR),
    )
}

/// The native-verifier pin (raw runtime keccak) for risc0 Groth16 seals prefixed with
/// `seal_prefix`, or why there is none: 3.1's ([`risc0_v3_1_verifier_missing`] if it were empty);
/// 3.0's is refused ([`risc0_v3_0_refused`]), and so is any other selector.
pub fn risc0_verifier_pin(seal_prefix: [u8; 4]) -> std::result::Result<B256, String> {
    if seal_prefix == pins::RISC0_V3_1_SELECTOR {
        return pins::RISC0_V3_1_GROTH16_VERIFIER.ok_or_else(risc0_v3_1_verifier_missing);
    }
    if seal_prefix == pins::RISC0_V3_0_SELECTOR {
        return Err(risc0_v3_0_refused());
    }
    Err(format!(
        "no risc0 Groth16 verifier is pinned for seal SELECTOR 0x{} (pinned: 3.1 0x{})",
        alloy::hex::encode(seal_prefix),
        alloy::hex::encode(pins::RISC0_V3_1_SELECTOR),
    ))
}

/// The startup notice for a build whose risc0 seals cannot be checked against a pinned verifier
/// (see [`risc0_verifier_pin`]), or `None` when one is pinned or the operator skipped the code pins.
/// Pure, so the caller logs it before any RPC: an operator learns what is missing even when the
/// chain cannot be reached.
pub fn risc0_verifier_pin_notice(seal_prefix: [u8; 4], pins_skipped: bool) -> Option<String> {
    if pins_skipped {
        return None;
    }
    risc0_verifier_pin(seal_prefix).err()
}

/// A known-good risc0 3.1 Groth16 receipt made by zkminer's Metal worker (the fibonacci benchmark
/// guest; B9-CHAIN, 2026-11-17), as zkminer sends it: image id, journal and the 260-byte on-chain seal
/// (`SELECTOR` 0xe71e6620 then the proof). [`ChainClient::verify_proof_system`] `eth_call`s
/// `Registry.verifyProof` with it (handoff §5: "check `Registry.verifyProof` ... on one of your own
/// receipts before the first RISC Zero claim"): a risc0 3.1 seal the chain's adapter rejects would
/// make every fulfil revert after the collateral-locking claim. It is a benchmark receipt bound to no
/// job, so showing it to the RPC operator publishes nothing of value.
pub mod risc0_preflight {
    use super::*;
    pub const IMAGE_ID: B256 =
        b256!("245dd297a191e76f29e9263832a6653d19e34f4ebbe0ca5ad8bbd14e8e3158aa");
    pub const JOURNAL: [u8; 8] = [0x4b, 0x60, 0xc0, 0x5c, 0xc7, 0x4d, 0x59, 0x0b];
    pub const SEAL_HEX: &str = concat!(
    "e71e6620146c454daa44bad2f5d36d5477dc27c2b64fd4d3f4f602457547b084f6b86e0a15d0c20accf4de29f0bc86efd99b",
    "5daa18f1ddd867ef8f05dc8d838f187d01b3109493f74fcee83b89af088c5ac2ebcc1eb8313c0b140f6c11d5e50da2eacedb",
    "0ecbe8c779b336b5976a31e9305f0a64396f2378766a906951290c04cc4db32902c5dca5357b00358c74f80889414fa61050",
    "1840d0f9c88ca534d6ae62bd6d380a33174af80706d2598ac6fc60a56f8a83c6a9018115aa9cf229fb9245bfcd961b5a3b23",
    "17d60ac7e563a8f7ef69b9dd6108f6c67bd2a4df735319fa400ed8890aef08f62664338e766b0fbda032d6f57e3d234b9e1b",
    "6c0818e036b463dd0bab",
    );
    /// Revert knob: `ZKMINER_SKIP_RISC0_RECEIPT_PREFLIGHT=1` skips the `eth_call`.
    pub const SKIP_ENV: &str = "ZKMINER_SKIP_RISC0_RECEIPT_PREFLIGHT";

    pub fn seal() -> Vec<u8> {
        alloy::hex::decode(SEAL_HEX).expect("hex seal")
    }

    pub fn skipped() -> bool {
        std::env::var(SKIP_ENV).ok().as_deref() == Some("1")
    }

    alloy::sol! {
        #[sol(rpc)]
        interface IRegistryVerify {
            function verifyProof(bytes32 proofSystemId, bytes32 programId, bytes publicValues, bytes proofBytes, bytes extraVerifierData) external view returns (uint64);
        }
    }
}

/// ERC-1967 implementation slot: `bytes32(uint256(keccak256("eip1967.proxy.implementation")) - 1)`.
const ERC1967_IMPL_SLOT: B256 =
    b256!("360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc");

/// A known deployment: the addresses an operator's config must name on that chain.
#[derive(Debug, Clone, Copy)]
pub struct KnownDeployment {
    pub name: &'static str,
    pub chain_id: u64,
    pub router: Address,
    pub staking: Address,
    pub registry: Address,
    pub token: Address,
    pub program_registry: Address,
    /// The deployment record's `fromBlock`: no HemiProve log exists below it, so every log scan
    /// (job discovery, lock recovery, descriptor reconstruction) is floored here.
    pub scan_from_block: u64,
    /// Raw runtime keccak of the stake token (no repo pin exists for the testnet token).
    pub token_codehash: B256,
}

/// Hemi testnet, deployed 2026-11-16 from contracts repo `8e1808b` (handoff §1-§2; RISC Zero verifier
/// risc0-ethereum v3.1.0). Every older 743111 stack ([`ABANDONED_743111`]) and the old free-mint
/// tHEMI `0x60525eEB…E698` are abandoned.
pub const HEMI_TESTNET_743111: KnownDeployment = KnownDeployment {
    name: "Hemi testnet (743111, 2026-11-16)",
    chain_id: 743111,
    router: address!("D931725db336B57dBB9A3123F2238A4FE3c6Ed58"),
    staking: address!("F3498fCF729Eb7d4E0323880e4E6aD1EB6da2e2D"),
    registry: address!("A80D9172931521f9bce0491C6374A5f28e79f10F"),
    token: address!("46955EdCF61b23a8c0b0d71428A9F1C07Bbf36cc"),
    program_registry: address!("eBB9Fb9B82f80518f74725eFc2f3FD24ded7695D"),
    scan_from_block: 7_226_094,
    token_codehash: b256!("536084d8a9d1773c86d8dd25aef9e619741e48e072dbbfdc30cad81bc2521aba"),
};

/// Contracts of abandoned 743111 stacks: `(what, address)`. A config naming any of them is refused
/// with [`abandoned_stack_refusal`], even under `ZKMINER_ALLOW_UNKNOWN_DEPLOYMENT=1` (they are dead,
/// not merely unknown; the 2026-10-29 RISC Zero adapter verifies only risc0 3.0 seals).
pub const ABANDONED_743111: [(&str, Address); 6] = [
    ("the 2026-10-29 router", address!("E1a492Dc6D57fCC2B6deb5B64087E69666cA470e")),
    ("the 2026-10-29 Staking", address!("44b2DDCfBe37900917E3750A4996BA007F4aA66E")),
    ("the 2026-10-29 Registry", address!("77fDb1DCE2224B75BA295f2Cdd87Ba5247d4BBc6")),
    ("the 2026-10-29 ProgramRegistry", address!("CC761A929747A81e34517e1f4F98247da925cAb4")),
    ("the old free-mint tHEMI", address!("60525eEBB1BD630Fb093d433675E28221DE1E698")),
    // An older stack's router (examples/testnet_submitter_cast.sh before B9-CHAIN).
    ("an older router", address!("9ce16C8e61BFe6f1a86965f3B22C48562E82Cf76")),
];

/// Why a config naming an abandoned 743111 contract is refused, or `None`. `configured` is
/// `(config key, address)`.
pub fn abandoned_stack_refusal(chain_id: u64, configured: &[(&str, Address)]) -> Option<String> {
    if chain_id != HEMI_TESTNET_743111.chain_id {
        return None;
    }
    let hits: Vec<String> = configured
        .iter()
        .filter_map(|(key, got)| {
            ABANDONED_743111
                .iter()
                .find(|(_, a)| a == got)
                .map(|(what, _)| format!("{key} {got} is {what}"))
        })
        .collect();
    (!hits.is_empty()).then(|| {
        format!(
            "the config names an ABANDONED HemiProve stack on 743111 ({}). It was replaced on \
             2026-11-16 by {} (router {}, verifies risc0 3.1 seals only); nothing there will ever be \
             paid. Rewrite [contracts] with `zkminer init --network testnet --force` (or copy the \
             addresses from the README)",
            hits.join("; "),
            HEMI_TESTNET_743111.name,
            HEMI_TESTNET_743111.router
        )
    })
}

/// The known deployment on `chain_id`, if any. (Hemi mainnet, 43111, has none yet.)
pub fn known_deployment(chain_id: u64) -> Option<&'static KnownDeployment> {
    [&HEMI_TESTNET_743111]
        .into_iter()
        .find(|d| d.chain_id == chain_id)
}

/// keccak256 of `code` with every occurrence of the 20-byte `self_addr` zeroed — a UUPS
/// implementation's `__self` immutable is its own address, so this is its audited-pin hash.
pub fn keccak_self_zeroed(code: &[u8], self_addr: Address) -> B256 {
    let needle = self_addr.as_slice();
    let mut buf = code.to_vec();
    let mut i = 0;
    while i + needle.len() <= buf.len() {
        if &buf[i..i + needle.len()] == needle {
            buf[i..i + needle.len()].fill(0);
            i += needle.len();
        } else {
            i += 1;
        }
    }
    keccak256(&buf)
}

/// keccak256 of `code` with a 32-byte immutable slot zeroed at each offset (the repo's
/// `*_IMMUTABLES` byte offsets). `None` if an offset runs past the code.
pub fn keccak_offsets_zeroed(code: &[u8], offsets: &[usize]) -> Option<B256> {
    let mut buf = code.to_vec();
    for &off in offsets {
        buf.get_mut(off..off + 32)?.fill(0);
    }
    Some(keccak256(&buf))
}

/// Whether every 32-byte word of `code` at `offsets` is `word`: the immutables
/// [`keccak_offsets_zeroed`] blanks must hold the value the caller then pins, or the pinned value and
/// the one the code actually uses can differ.
pub fn immutables_are(code: &[u8], offsets: &[usize], word: B256) -> bool {
    offsets
        .iter()
        .all(|&off| code.get(off..off + 32) == Some(word.as_slice()))
}

/// Whether the operator opted out of the audited-code checks (e.g. a governance upgrade landed
/// before this zkminer shipped its pins). Never skips the chain-id, address or wiring checks.
pub fn code_pins_skipped() -> bool {
    std::env::var("ZKMINER_SKIP_CODE_PINS").ok().as_deref() == Some("1")
}

/// A proof system that was READ and is definitely not serveable right now (disabled, swapped to
/// unaudited code, a SELECTOR mismatch) — as opposed to an RPC failure, which says nothing. Only this
/// clears a previous "verified" verdict.
#[derive(Debug, Clone)]
pub struct ProofSystemRefused(pub String);

impl std::fmt::Display for ProofSystemRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for ProofSystemRefused {}

/// The deployment was READ and is definitely not the audited, configured stack (other addresses,
/// other wiring, other code) — as opposed to an RPC failure, which says nothing. Only this clears a
/// previous "verified" verdict.
#[derive(Debug, Clone)]
pub struct DeploymentRefused(pub String);

impl std::fmt::Display for DeploymentRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for DeploymentRefused {}

macro_rules! refuse {
    ($($arg:tt)*) => {
        return Err(DeploymentRefused(format!($($arg)*)).into())
    };
}

impl ChainClient {
    /// Verify the configured stack before the first transaction (handoff §13 test 1): the chain is a
    /// known deployment's (or the operator explicitly allowed another), the router's own wiring names
    /// the configured Staking/Registry/token, and every proxy, implementation and router facet zkminer
    /// calls through is the audited code. Returns a human summary on success.
    pub async fn verify_deployment(&self) -> Result<Vec<String>> {
        let mut report = Vec::new();
        // 0. An abandoned stack is refused outright (no opt-out: it is dead, not unknown).
        if let Some(why) = abandoned_stack_refusal(
            self.chain_id,
            &[
                ("hemi_prove (router)", self.hemi_prove),
                ("hemi_prove_staking", self.hemi_prove_staking),
                ("hemi_prove_registry", self.hemi_prove_registry),
                ("hemi_token", self.hemi_token),
                ("program_registry", self.program_registry.unwrap_or(Address::ZERO)),
            ],
        ) {
            refuse!("{why}");
        }
        // 1. Known deployment: refuse a dead stack on a known chain.
        match known_deployment(self.chain_id) {
            Some(k) => {
                let mismatches: Vec<String> = [
                    ("hemi_prove (router)", self.hemi_prove, k.router),
                    ("hemi_prove_staking", self.hemi_prove_staking, k.staking),
                    ("hemi_prove_registry", self.hemi_prove_registry, k.registry),
                    ("hemi_token", self.hemi_token, k.token),
                    // Program metadata (ELF URIs) comes only from here: a missing or stale address
                    // would pass every other check and then refuse every program's ELF.
                    (
                        "program_registry",
                        self.program_registry.unwrap_or(Address::ZERO),
                        k.program_registry,
                    ),
                ]
                .into_iter()
                .filter(|(_, got, want)| got != want)
                .map(|(n, got, want)| format!("{n} is {got}, the live deployment's is {want}"))
                .collect();
                if !mismatches.is_empty() {
                    if std::env::var("ZKMINER_ALLOW_UNKNOWN_DEPLOYMENT").ok().as_deref() == Some("1") {
                        tracing::warn!(
                            "configured contracts differ from {} ({}) — continuing because \
                             ZKMINER_ALLOW_UNKNOWN_DEPLOYMENT=1",
                            k.name,
                            mismatches.join("; ")
                        );
                    } else {
                        refuse!(
                            "the configured contracts are not {} — {}. Older stacks on this chain are \
                             abandoned; fix [contracts] in the config (`zkminer init --network testnet \
                             --force` rewrites the whole file), or set ZKMINER_ALLOW_UNKNOWN_DEPLOYMENT=1 \
                             to target another deployment on purpose",
                            k.name,
                            mismatches.join("; ")
                        );
                    }
                } else {
                    report.push(format!("addresses: {}", k.name));
                }
            }
            None => report.push(format!(
                "addresses: no known deployment on chain {} — trusting the config",
                self.chain_id
            )),
        }

        // 2. Wiring: the router's own getters must name the configured contracts.
        let aux = IHemiProveAux::new(self.hemi_prove, &*self.provider);
        let staking = aux.staking().call().await.context("router.staking()")?;
        let registry = aux.registry().call().await.context("router.registry()")?;
        let token = aux.hemiToken().call().await.context("router.hemiToken()")?;
        let staking_token = IHemiProveStaking::new(self.hemi_prove_staking, &*self.provider)
            .hemiToken()
            .call()
            .await
            .context("Staking.hemiToken()")?;
        for (what, got, want) in [
            ("router.staking()", staking, self.hemi_prove_staking),
            ("router.registry()", registry, self.hemi_prove_registry),
            ("router.hemiToken()", token, self.hemi_token),
            ("Staking.hemiToken()", staking_token, self.hemi_token),
        ] {
            if got != want {
                refuse!("{what} is {got} but the config names {want}");
            }
        }
        report.push("wiring: router.staking/registry/hemiToken and Staking.hemiToken match".into());

        // 3. Audited code.
        if code_pins_skipped() {
            tracing::warn!(
                "ZKMINER_SKIP_CODE_PINS=1: NOT verifying that the router, Staking, Registry, their \
                 facets, and the proof systems' adapters and verifiers run the audited code"
            );
            report.push("code: SKIPPED (ZKMINER_SKIP_CODE_PINS=1)".into());
            return Ok(report);
        }
        let mut proxies = vec![
            ("router", self.hemi_prove, pins::ROUTER_IMPL),
            ("Staking", self.hemi_prove_staking, pins::STAKING_IMPL),
            ("Registry", self.hemi_prove_registry, pins::REGISTRY_IMPL),
        ];
        if let Some(pr) = self.program_registry {
            proxies.push(("ProgramRegistry", pr, pins::PROGRAM_REGISTRY_IMPL));
        }
        for (name, proxy, impl_pin) in proxies {
            let code = self.provider.get_code_at(proxy).await.with_context(|| format!("{name} code"))?;
            if keccak256(&code) != pins::ERC1967_PROXY {
                refuse!(
                    "{name} {proxy} is not the audited ERC1967Proxy (runtime keccak {})",
                    keccak256(&code)
                );
            }
            let slot = self
                .provider
                .get_storage_at(proxy, ERC1967_IMPL_SLOT.into())
                .await
                .with_context(|| format!("{name} implementation slot"))?;
            let implementation = Address::from_word(B256::from(slot));
            let icode = self
                .provider
                .get_code_at(implementation)
                .await
                .with_context(|| format!("{name} implementation code"))?;
            if keccak_self_zeroed(&icode, implementation) != impl_pin {
                refuse!(
                    "{name} implementation {implementation} is not the audited code (pin {impl_pin}) \
                     (set ZKMINER_SKIP_CODE_PINS=1 only after verifying an upgrade)"
                );
            }
        }
        // Every selector zkminer sends to the router must route to an audited facet (or be served by
        // the pinned router implementation itself: getFacet == 0).
        use alloy::sol_types::SolCall;
        use zkminer_contracts::bindings::{IHemiProveCore as C, IHemiProveFulfill as F};
        let selectors: [[u8; 4]; 16] = [
            C::claimJobCall::SELECTOR,
            F::fulfillJobCall::SELECTOR,
            F::releaseJobCall::SELECTOR,
            F::graceReleaseCall::SELECTOR,
            IHemiProveAux::getJobStatusViewCall::SELECTOR,
            IHemiProveAux::jobsCall::SELECTOR,
            IHemiProveAux::getJobExtrasCall::SELECTOR,
            IHemiProveAux::getJobSnapshotsCall::SELECTOR,
            IHemiProveAux::getPremiumCapCall::SELECTOR,
            IHemiProveAux::bidConfigsCall::SELECTOR,
            IHemiProveAux::MIN_COLLATERAL_AMOUNTCall::SELECTOR,
            IHemiProveAux::pausedCall::SELECTOR,
            IHemiProveAux::getUnionClockCall::SELECTOR,
            IHemiProveAux::getKeyClockCall::SELECTOR,
            IHemiProveAux::jobProofSystemsCall::SELECTOR,
            C::withdrawCall::SELECTOR,
        ];
        let facet_sig = alloy::primitives::keccak256("getFacet(bytes4)");
        // Several selectors route to one facet: read and hash each facet's code once.
        let mut audited_facets: std::collections::HashSet<Address> =
            std::collections::HashSet::new();
        for sel in selectors {
            let mut data = facet_sig[..4].to_vec();
            let mut word = [0u8; 32];
            word[..4].copy_from_slice(&sel);
            data.extend_from_slice(&word);
            let tx = alloy::rpc::types::TransactionRequest::default()
                .to(self.hemi_prove)
                .input(data.into());
            let out = self.provider.call(tx).await.context("router.getFacet")?;
            if out.len() < 32 {
                refuse!(
                    "router.getFacet(0x{}) returned {} bytes",
                    alloy::hex::encode(sel),
                    out.len()
                );
            }
            let facet = Address::from_slice(&out[12..32]);
            if facet == Address::ZERO || audited_facets.contains(&facet) {
                continue; // served by the pinned router implementation itself, or already checked
            }
            let fcode = self.provider.get_code_at(facet).await.context("facet code")?;
            let h = keccak256(&fcode);
            if pins::FACETS.iter().any(|(_, p)| *p == h) {
                audited_facets.insert(facet);
            } else {
                refuse!(
                    "router selector 0x{} routes to {facet}, which is not an audited facet (keccak {h})",
                    alloy::hex::encode(sel)
                );
            }
        }
        if let Some(k) = known_deployment(self.chain_id) {
            if self.hemi_token == k.token {
                let tcode = self.provider.get_code_at(self.hemi_token).await.context("token code")?;
                if keccak256(&tcode) != k.token_codehash {
                    refuse!(
                        "stake token {} has unexpected code (keccak {})",
                        self.hemi_token,
                        keccak256(&tcode)
                    );
                }
            }
        }
        report.push(
            "code: router/Staking/Registry proxies, implementations and routed facets match the 2026-11-16 release pins"
                .into(),
        );
        Ok(report)
    }

    /// The Registry's adapter for `ps` right now: `(adapter address, status)`. Cheap (one call); used
    /// to notice an adapter swap or disable between full [`Self::verify_proof_system`] runs.
    pub async fn adapter_entry(&self, ps: ProofSystem) -> Result<(Address, u8)> {
        let reg = IHemiProveRegistry::new(self.hemi_prove_registry, &*self.provider);
        let entry = reg
            .getAdapter(ps.id())
            .call()
            .await
            .with_context(|| format!("Registry.getAdapter({})", ps.label()))?;
        Ok((entry.adapter, entry.status))
    }

    /// Verify a proof system zkminer will serve (handoff §13 test 2): its adapter is registered and
    /// claimable (Active or Deprecated), it is the audited adapter code, and it wraps the audited native
    /// verifier whose seal prefix equals `seal_prefix` (the 4 bytes zkminer prepends). Returns the
    /// adapter it verified, so a later swap (`executePendingReactivation`) can be noticed.
    pub async fn verify_proof_system(&self, ps: ProofSystem, seal_prefix: [u8; 4]) -> Result<Address> {
        let reg = IHemiProveRegistry::new(self.hemi_prove_registry, &*self.provider);
        let entry = reg
            .getAdapter(ps.id())
            .call()
            .await
            .with_context(|| format!("Registry.getAdapter({})", ps.label()))?;
        // AdapterStatus: 0 Unregistered, 1 Active, 2 Deprecated (still claimable), 3 Disabled.
        if !matches!(entry.status, 1 | 2) {
            return Err(ProofSystemRefused(format!(
                "{} adapter status is {} (not Active/Deprecated)",
                ps.label(),
                entry.status
            ))
            .into());
        }
        if ps == ProofSystem::Sp1Groth16 {
            return self
                .verify_sp1_groth16(ps, entry.adapter, seal_prefix)
                .await;
        }
        if ps != ProofSystem::Risc0Groth16 {
            bail!("{}: no pinned verifier — zkminer does not serve it yet", ps.label());
        }
        let native = IVerifierAdapter::new(entry.adapter, &*self.provider)
            .nativeVerifier()
            .call()
            .await
            .context("adapter.nativeVerifier()")?;
        if !code_pins_skipped() {
            let acode = self.provider.get_code_at(entry.adapter).await.context("adapter code")?;
            // Its immutables are its verifier: each must be the `nativeVerifier()` pinned below, or
            // `verifyProof` could call another one (VerifierPins._adapterProblem checks the same).
            if !immutables_are(
                &acode,
                &pins::RISC0_GROTH16_ADAPTER_IMMUTABLES,
                B256::left_padding_from(native.as_slice()),
            ) || keccak_offsets_zeroed(&acode, &pins::RISC0_GROTH16_ADAPTER_IMMUTABLES)
                != Some(pins::RISC0_GROTH16_ADAPTER)
            {
                return Err(ProofSystemRefused(format!(
                    "{} adapter {} is not the audited RiscZeroGroth16VerifierAdapter",
                    ps.label(),
                    entry.adapter
                ))
                .into());
            }
            // The pin follows the seal's selector: 3.0's verifier for 0x73c457ba, 3.1's for
            // 0xe71e6620 (refused with what is missing while that pin is empty).
            let pin = risc0_verifier_pin(seal_prefix)
                .map_err(|why| ProofSystemRefused(format!("{}: {why}", ps.label())))?;
            let vcode = self.provider.get_code_at(native).await.context("verifier code")?;
            if keccak256(&vcode) != pin {
                return Err(ProofSystemRefused(format!(
                    "{} native verifier {native} is not the pinned risc0-ethereum verifier for \
                     seal SELECTOR 0x{}",
                    ps.label(),
                    alloy::hex::encode(seal_prefix)
                ))
                .into());
            }
        }
        let selector = IRiscZeroSelectable::new(native, &*self.provider)
            .SELECTOR()
            .call()
            .await
            .context("verifier SELECTOR()")?;
        if selector.0 != seal_prefix {
            return Err(ProofSystemRefused(format!(
                "{} verifier SELECTOR() is 0x{} but zkminer's seals are prefixed 0x{} — every proof \
                 would revert VerifierCallFailed",
                ps.label(),
                alloy::hex::encode(selector),
                alloy::hex::encode(seal_prefix)
            ))
            .into());
        }
        if seal_prefix == pins::RISC0_V3_1_SELECTOR && !risc0_preflight::skipped() {
            self.risc0_receipt_preflight(ps).await?;
        }
        Ok(entry.adapter)
    }

    /// `eth_call` `Registry.verifyProof(risczero.groth16.v1, ...)` with
    /// [`risc0_preflight`]'s known-good risc0 3.1 Metal receipt. A revert (the chain's verifier
    /// rejects what this build makes) refuses the proof system; an RPC failure says nothing.
    async fn risc0_receipt_preflight(&self, ps: ProofSystem) -> Result<()> {
        use risc0_preflight::IRegistryVerify;
        let reg = IRegistryVerify::new(self.hemi_prove_registry, &*self.provider);
        let call = reg.verifyProof(
            ps.id(),
            risc0_preflight::IMAGE_ID,
            risc0_preflight::JOURNAL.to_vec().into(),
            risc0_preflight::seal().into(),
            alloy::primitives::Bytes::new(),
        );
        match call.call().await {
            Ok(_) => Ok(()),
            Err(e) => match crate::revert::revert_data_of(&e) {
                Some(data) => Err(ProofSystemRefused(format!(
                    "{}: Registry.verifyProof rejects a known-good risc0 3.1 receipt from this \
                     build's Metal worker (revert {}), so every fulfil would revert \
                     VerifierCallFailed ({}=1 skips this check)",
                    ps.label(),
                    crate::revert::decode(&data).name(),
                    risc0_preflight::SKIP_ENV
                ))
                .into()),
                None => Err(anyhow::Error::new(e).context("Registry.verifyProof preflight")),
            },
        }
    }

    /// `verify_proof_system` for `sp1.groth16.v1`: the adapter is the audited SP1Groth16VerifierAdapter
    /// wrapping the audited circuit v6.1.0 Groth16 verifier, whose `VERIFIER_HASH()` is the v6.1.0
    /// one and starts with `seal_prefix` (the first 4 bytes of every seal the SP1 worker returns).
    async fn verify_sp1_groth16(
        &self,
        ps: ProofSystem,
        adapter: Address,
        seal_prefix: [u8; 4],
    ) -> Result<Address> {
        let native = IVerifierAdapter::new(adapter, &*self.provider)
            .nativeVerifier()
            .call()
            .await
            .context("adapter.nativeVerifier()")?;
        if !code_pins_skipped() {
            let acode = self
                .provider
                .get_code_at(adapter)
                .await
                .context("adapter code")?;
            if !immutables_are(
                &acode,
                &pins::SP1_GROTH16_ADAPTER_IMMUTABLES,
                B256::left_padding_from(native.as_slice()),
            ) || keccak_offsets_zeroed(&acode, &pins::SP1_GROTH16_ADAPTER_IMMUTABLES)
                != Some(pins::SP1_GROTH16_ADAPTER)
            {
                return Err(ProofSystemRefused(format!(
                    "{} adapter {adapter} is not the audited SP1Groth16VerifierAdapter",
                    ps.label()
                ))
                .into());
            }
            let vcode = self
                .provider
                .get_code_at(native)
                .await
                .context("verifier code")?;
            if keccak256(&vcode) != pins::SP1_V6_1_0_GROTH16_VERIFIER {
                return Err(ProofSystemRefused(format!(
                    "{} native verifier {native} is not the audited SP1 circuit v6.1.0 Groth16 verifier",
                    ps.label()
                ))
                .into());
            }
        }
        let hash = ISP1NativeVerifier::new(native, &*self.provider)
            .VERIFIER_HASH()
            .call()
            .await
            .context("verifier VERIFIER_HASH()")?;
        if hash != pins::SP1_V6_1_0_GROTH16_VERIFIER_HASH || hash[..4] != seal_prefix {
            return Err(ProofSystemRefused(format!(
                "{} verifier VERIFIER_HASH() is {hash} but zkminer's SP1 seals are prefixed 0x{} \
                 (circuit v6.1.0) — every proof would revert VerifierCallFailed",
                ps.label(),
                alloy::hex::encode(seal_prefix)
            ))
            .into());
        }
        Ok(adapter)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_adapters_immutables_must_all_be_its_verifier() {
        let verifier = B256::left_padding_from(&[0xAB; 20]);
        let mut code = vec![0u8; 200];
        for off in [10, 100] {
            code[off..off + 32].copy_from_slice(verifier.as_slice());
        }
        assert!(immutables_are(&code, &[10, 100], verifier));
        assert!(!immutables_are(
            &code,
            &[10, 100],
            B256::left_padding_from(&[0xCD; 20])
        ));
        code[100] ^= 1;
        assert!(
            !immutables_are(&code, &[10, 100], verifier),
            "one reference differs"
        );
        assert!(
            !immutables_are(&code, &[10, 190], verifier),
            "out of the code"
        );
    }

    #[test]
    fn self_zeroing_matches_the_repos_method() {
        // The UUPS __self immutable appears as the implementation's own 20-byte address inside
        // PUSH32 words; zeroing every occurrence must leave the rest of the code untouched.
        let me = Address::repeat_byte(0xAB);
        let mut code = vec![0x60, 0x80];
        code.extend_from_slice(&[0u8; 12]);
        code.extend_from_slice(me.as_slice());
        code.extend_from_slice(&[0x5b, 0x00]);
        code.extend_from_slice(me.as_slice());
        let mut expect = code.clone();
        for w in expect.windows(20).enumerate().filter(|(_, w)| *w == me.as_slice()).map(|(i, _)| i).collect::<Vec<_>>() {
            expect[w..w + 20].fill(0);
        }
        assert_eq!(keccak_self_zeroed(&code, me), keccak256(&expect));
        assert_ne!(keccak_self_zeroed(&code, me), keccak256(&code));
    }

    #[test]
    fn offset_zeroing_rejects_out_of_range() {
        let code = vec![1u8; 64];
        assert!(keccak_offsets_zeroed(&code, &[32]).is_some());
        assert!(keccak_offsets_zeroed(&code, &[33]).is_none());
    }

    /// The risc0 verifier pin follows the seal selector: 3.1 is pinned (the 2026-11-16 deployment's
    /// risc0-ethereum v3.1.0 verifier), 3.0 and anything else is refused with a reason.
    #[test]
    fn the_risc0_verifier_pin_follows_the_selector() {
        assert_eq!(pins::RISC0_V3_1_SELECTOR, [0xe7, 0x1e, 0x66, 0x20]);
        let pin = pins::RISC0_V3_1_GROTH16_VERIFIER.expect("3.1 verifier pinned (B9-CHAIN)");
        assert_eq!(risc0_verifier_pin(pins::RISC0_V3_1_SELECTOR), Ok(pin));
        assert_eq!(risc0_verifier_pin_notice(pins::RISC0_V3_1_SELECTOR, false), None);
        // 3.0 seals: refused, saying why and what to do.
        let old = risc0_verifier_pin(pins::RISC0_V3_0_SELECTOR).unwrap_err();
        assert_eq!(old, risc0_v3_0_refused());
        for needed in ["0x73c457ba", "0xe71e6620", "3.1", "refused", "risc0_groth16_selector"] {
            assert!(old.contains(needed), "{needed:?} missing from: {old}");
        }
        assert_eq!(
            risc0_verifier_pin_notice(pins::RISC0_V3_0_SELECTOR, false),
            Some(old)
        );
        // Skipped code pins: no notice (the operator opted out of every code check).
        assert_eq!(risc0_verifier_pin_notice(pins::RISC0_V3_0_SELECTOR, true), None);
        // Any other selector: no pin.
        let other = risc0_verifier_pin([0xde, 0xad, 0xbe, 0xef]).unwrap_err();
        assert!(other.contains("0xdeadbeef"), "{other}");
        assert!(risc0_verifier_pin_notice([0xde, 0xad, 0xbe, 0xef], false).is_some());
        // The missing-pin message still names what an operator would need.
        let why = risc0_v3_1_verifier_missing();
        for needed in ["0xe71e6620", "RISC0_V3_1_GROTH16_VERIFIER", "VerifierPins.sol"] {
            assert!(why.contains(needed), "{needed:?} missing from: {why}");
        }
    }

    /// The handoff's section 2 addresses and scan floor (2026-11-16 deployment).
    #[test]
    fn the_743111_deployment_is_the_2026_11_16_one() {
        let k = known_deployment(743111).expect("743111 known");
        assert_eq!(k.scan_from_block, 7_226_094);
        assert_eq!(k.router, address!("D931725db336B57dBB9A3123F2238A4FE3c6Ed58"));
        assert_eq!(k.staking, address!("F3498fCF729Eb7d4E0323880e4E6aD1EB6da2e2D"));
        assert_eq!(k.registry, address!("A80D9172931521f9bce0491C6374A5f28e79f10F"));
        assert_eq!(k.program_registry, address!("eBB9Fb9B82f80518f74725eFc2f3FD24ded7695D"));
        assert_eq!(k.token, address!("46955EdCF61b23a8c0b0d71428A9F1C07Bbf36cc"));
        assert!(known_deployment(43111).is_none(), "mainnet has no deployment yet");
        for (what, a) in ABANDONED_743111 {
            assert!(
                ![k.router, k.staking, k.registry, k.program_registry, k.token].contains(&a),
                "{what} {a} is both live and abandoned"
            );
        }
    }

    /// The 2026-10-29 stack is refused as abandoned, with what to do; the live one and other chains
    /// are not.
    #[test]
    fn the_abandoned_stack_is_refused() {
        let old_router = address!("E1a492Dc6D57fCC2B6deb5B64087E69666cA470e");
        let why = abandoned_stack_refusal(743111, &[("hemi_prove (router)", old_router)])
            .expect("refused");
        for needed in [
            "ABANDONED",
            "2026-10-29 router",
            "0xE1a492Dc6D57fCC2B6deb5B64087E69666cA470e",
            "0xD931725db336B57dBB9A3123F2238A4FE3c6Ed58",
            "zkminer init --network testnet --force",
        ] {
            assert!(why.contains(needed), "{needed:?} missing from: {why}");
        }
        let old_token = address!("60525eEBB1BD630Fb093d433675E28221DE1E698");
        assert!(abandoned_stack_refusal(743111, &[("hemi_token", old_token)]).is_some());
        let k = &HEMI_TESTNET_743111;
        assert_eq!(
            abandoned_stack_refusal(
                743111,
                &[("r", k.router), ("s", k.staking), ("g", k.registry), ("t", k.token)]
            ),
            None
        );
        assert_eq!(abandoned_stack_refusal(31337, &[("r", old_router)]), None);
    }

    /// Cross-check every pin against the contracts repo's own pin files (`script/lib/
    /// ReleaseCorePins.sol`, `script/lib/VerifierPins.sol`) when a checkout of it is named by
    /// `ZKMINER_CONTRACTS_REPO` (at commit 8e1808b). Each pin value must appear in one of the two
    /// files. Without the variable the test only reports that it did not run.
    #[test]
    fn the_pins_match_the_contracts_repo() {
        let Ok(repo) = std::env::var("ZKMINER_CONTRACTS_REPO") else {
            eprintln!("SKIPPED: set ZKMINER_CONTRACTS_REPO to a contracts checkout at 8e1808b");
            return;
        };
        let mut text = String::new();
        for f in ["script/lib/ReleaseCorePins.sol", "script/lib/VerifierPins.sol"] {
            let path = std::path::Path::new(&repo).join(f);
            text += &std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
                .to_ascii_lowercase();
        }
        let mut want: Vec<(String, B256)> = vec![
            ("ERC1967_PROXY".into(), pins::ERC1967_PROXY),
            ("ROUTER_IMPL".into(), pins::ROUTER_IMPL),
            ("STAKING_IMPL".into(), pins::STAKING_IMPL),
            ("REGISTRY_IMPL".into(), pins::REGISTRY_IMPL),
            ("PROGRAM_REGISTRY_IMPL".into(), pins::PROGRAM_REGISTRY_IMPL),
            ("RISC0_GROTH16_ADAPTER".into(), pins::RISC0_GROTH16_ADAPTER),
            ("RISC0_V3_1_GROTH16_VERIFIER".into(), pins::RISC0_V3_1_GROTH16_VERIFIER.unwrap()),
            ("SP1_GROTH16_ADAPTER".into(), pins::SP1_GROTH16_ADAPTER),
            ("SP1_V6_1_0_GROTH16_VERIFIER".into(), pins::SP1_V6_1_0_GROTH16_VERIFIER),
            ("SP1_V6_1_0_GROTH16_VERIFIER_HASH".into(), pins::SP1_V6_1_0_GROTH16_VERIFIER_HASH),
        ];
        want.extend(pins::FACETS.iter().map(|(n, h)| (n.to_string(), *h)));
        let missing: Vec<String> = want
            .iter()
            .filter(|(_, h)| !text.contains(&format!("{h:x}")))
            .map(|(n, h)| format!("{n} {h}"))
            .collect();
        assert!(missing.is_empty(), "pins absent from the repo's pin files: {missing:#?}");
    }

    /// The preflight receipt is a 260-byte risc0 3.1 seal and its call is `Registry.verifyProof`
    /// (selector 0xd1140f23, handoff Appendix A).
    #[test]
    fn the_risc0_preflight_receipt_is_a_3_1_seal() {
        use alloy::sol_types::SolCall;
        let seal = risc0_preflight::seal();
        assert_eq!(seal.len(), 260);
        assert_eq!(seal[..4], pins::RISC0_V3_1_SELECTOR);
        assert_eq!(
            risc0_preflight::IRegistryVerify::verifyProofCall::SELECTOR,
            [0xd1, 0x14, 0x0f, 0x23]
        );
    }
}
