//! The deployed HemiProve stack zkminer talks to, and its startup verification (handoff §2, §13
//! test 1-2).
//!
//! Before the first transaction zkminer proves it is talking to the AUDITED code: every proxy is the
//! audited ERC-1967 proxy, every implementation and router facet it routes through is audited code,
//! and each proof system it serves wraps the audited native verifier whose `SELECTOR()` /
//! `VERIFIER_HASH()` is the seal prefix zkminer emits. The pins below are copied verbatim from the
//! deployed contracts repo (hemiprove-contracts 3bc441d, the deployed 8e1808b apart from its LICENSE:
//! `script/lib/ReleaseCorePins.sol` and `script/lib/VerifierPins.sol`) and are hashed the way that
//! repo hashes the chain (`script/lib/CoreRuntimePins.sol`, `VerifierPins._adapterProblem`), so they
//! are DEPLOYMENT-INDEPENDENT: an implementation's pin is its runtime keccak with its immutables
//! zeroed, and the same audited code verifies at any address. Only the addresses and the scan floor
//! are per-network.
//!
//! The same values were derived independently for the macOS beta (B9-CHAIN, 2026-11-17;
//! `docs/metal-port-notes/B9-CHAIN.md`) from the live 743111 code at block 7234324, and then checked
//! against the pin files at 8e1808b: `the_pins_match_the_contracts_repo` (run with
//! `ZKMINER_CONTRACTS_REPO=<checkout>`) requires every pin here to appear in them. On top of the pins,
//! risc0 3.0 seals (0x73c457ba) are refused by selector ([`risc0_verifier_pin`]), a config naming an
//! abandoned 743111 stack is refused ([`abandoned_stack_refusal`]), and before the first RISC Zero claim
//! `Registry.verifyProof` must accept a known-good risc0 3.1 receipt ([`risc0_preflight`]).

use alloy::primitives::{address, b256, keccak256, Address, B256};
use alloy::providers::Provider;
use anyhow::{bail, Context, Result};

use crate::auction::ProofSystem;
use crate::client::ChainClient;
use zkminer_contracts::bindings::{
    IHemiProveAux, IHemiProveRegistry, IHemiProveStaking, IRiscZeroSelectable, ISP1NativeVerifier,
    IVerifierAdapter,
};

/// Release runtime pins: hemiprove-contracts 3bc441d `script/lib/ReleaseCorePins.sol`
/// (`RELEASE_CORE_RUNTIME_KECCAK`) for the core, and `script/lib/VerifierPins.sol` for the adapters
/// and native verifiers.
///
/// The core pins are `runtime-keccak` of the deploy-profile runtime with every immutable zeroed. The
/// only immutable of the pinned implementations is UUPS `__self` (their own address), which the repo
/// zeroes on chain as every 32-byte window equal to the left-padded address
/// (`CoreRuntimePins.maskedKeccak`): [`masked_keccak`] does exactly that. The facets and the proxy have
/// no immutable and are hashed as they are. The adapter pins zero their one immutable
/// (`nativeVerifier`) at fixed 32-byte offsets (`*_IMMUTABLES`), each of which must first hold the
/// verifier itself ([`immutables_are`]); the native verifiers' pins are raw runtime keccaks.
pub mod pins {
    use super::*;
    /// OpenZeppelin ERC1967Proxy (no immutable) — every core proxy.
    pub const ERC1967_PROXY: B256 =
        b256!("46a010df31eb642b47284650e80051e8f6239a0c995003d230b437810bc4b9b4");
    /// HemiProve router implementation (`ROUTER`; its one immutable, UUPS `__self`, zeroed).
    pub const ROUTER_IMPL: B256 =
        b256!("072ef9e8a858aea90b1643fb26d8636dfa49930d7c799750459531081a15b65b");
    /// HemiProveStaking implementation (`STAKING`; `__self` zeroed).
    pub const STAKING_IMPL: B256 =
        b256!("d4f7e362dd8e983aaa92839496f5323d25b226bda1c99576c58999c5ceae6046");
    /// HemiProveRegistry implementation (`REGISTRY`; `__self` zeroed).
    pub const REGISTRY_IMPL: B256 =
        b256!("66179b0a73aa40836725499dccca37576c75667d0f0ac6bf3b569354fc03b13f");
    /// ProgramRegistry implementation (`PROGRAM_REGISTRY`; `__self` zeroed).
    pub const PROGRAM_REGISTRY_IMPL: B256 =
        b256!("47e0b59907c774b24a7d9f8ff2b9a5dbb5d2dfe826e7e1062ce6a5379f715574");
    /// The five router facets (no immutable): `CORE`, `FULFILL`, `AUX`, `FULFILL_CYCLE`, `AUX_GOV`.
    pub const FACETS: [(&str, B256); 5] = [
        ("HemiProveCore", b256!("2f5c34ff5e6f9a5dca915a187969a81065437be9dad0350e881625dae18c5fbd")),
        ("HemiProveFulfill", b256!("50b6fe0ea4bb38f480809014f6d7d33b24e13b455c5fb42a191d45ddbd634e0b")),
        ("HemiProveAux", b256!("c9ea43491c3db833ba7cc6eae89e210f4a792f48810e4cb68933ce049599a682")),
        ("HemiProveFulfillCycle", b256!("6e11d32015642d76cf294fdf82dff9195d8b0c411a628d9609d31b68334342cd")),
        ("HemiProveAuxGov", b256!("3a7aeee0d0547b79d4dc8295531120caa0335bf4d0d110bf329bcddb6e28242f")),
    ];
    /// RiscZeroGroth16VerifierAdapter runtime (1,939 B) with its `nativeVerifier` immutable zeroed at
    /// [`RISC0_GROTH16_ADAPTER_IMMUTABLES`] (`RISC_ZERO_GROTH16_VERIFIER_ADAPTER_RUNTIME`).
    pub const RISC0_GROTH16_ADAPTER: B256 =
        b256!("dc362a202817f67a52ef910bf022660f3723a4b7fc5e451f9799be71fb7b0a89");
    pub const RISC0_GROTH16_ADAPTER_SIZE: usize = 1939;
    pub const RISC0_GROTH16_ADAPTER_IMMUTABLES: [usize; 3] = [101, 526, 1245];
    /// risc0-ethereum v3.1.0 RiscZeroGroth16Verifier runtime (immutables filled, raw keccak, 4,611 B):
    /// `RISC_ZERO_V3_1_GROTH16_RUNTIME`. v3.1.0 fixes GHSA-mm6c-35cm-g4x2, under which the v3.0
    /// verifier (0x0d2be77d…, SELECTOR 0x73c457ba) accepts a forged receipt for any claim.
    pub const RISC0_V3_1_GROTH16_VERIFIER: B256 =
        b256!("26e455ef699495f789d6b9956244b62c4ed95dc3c2d81663c4b13ce14fd81c0c");
    /// Its `SELECTOR()`: the first 4 bytes of the risc0 3.1 Groth16ReceiptVerifierParameters digest
    /// (`RISC_ZERO_V3_1_PARAMS_DIGEST`, e71e6620a834…), the prefix of every risc0-zkvm 3.1 seal.
    pub const RISC0_V3_1_SELECTOR: [u8; 4] = [0xe7, 0x1e, 0x66, 0x20];
    /// The `SELECTOR()` of the risc0-ethereum v3.0 verifier: the prefix of every risc0 3.0 Groth16
    /// seal. Kept only to name it in refusals ([`super::risc0_v3_0_refused`]): no deployment zkminer
    /// knows accepts it any more.
    pub const RISC0_V3_0_SELECTOR: [u8; 4] = [0x73, 0xc4, 0x57, 0xba];
    /// SP1Groth16VerifierAdapter runtime with its `nativeVerifier` immutable zeroed at
    /// [`SP1_GROTH16_ADAPTER_IMMUTABLES`] (1,851 B; `SP1_GROTH16_VERIFIER_ADAPTER_RUNTIME`).
    pub const SP1_GROTH16_ADAPTER: B256 =
        b256!("99d18017af86518b2b86cd982aeadc69ed9c5c9611a52ccae7b637eb1b0c636d");
    pub const SP1_GROTH16_ADAPTER_SIZE: usize = 1851;
    pub const SP1_GROTH16_ADAPTER_IMMUTABLES: [usize; 3] = [101, 527, 1165];
    /// SP1 circuit v6.1.0 Groth16 verifier (sp1-contracts v6.1.1 `SP1VerifierGroth16.sol`), runtime
    /// keccak (5,463 B, no immutables; `SP1_V6_1_0_GROTH16_RUNTIME`).
    pub const SP1_V6_1_0_GROTH16_VERIFIER: B256 =
        b256!("6e1a354cfd1694f27c6258729ce14a5b29fe57624d1d10c759a33aa2d7aa002b");
    /// Its `VERIFIER_HASH()`: sha256 of the circuit's `groth16_vk.bin` (SP1 SDK 6.1.0 to 6.10.0). The
    /// first 4 bytes prefix every v6.1.0 Groth16 seal.
    pub const SP1_V6_1_0_GROTH16_VERIFIER_HASH: B256 =
        b256!("4388a21c687fdd5f218d7e3d13190cac4c5355818d3605fd5fb811df468ee696");
    /// SP1PlonkVerifierAdapter runtime with its `nativeVerifier` immutable zeroed at
    /// [`SP1_PLONK_ADAPTER_IMMUTABLES`] (1,849 B; `SP1_PLONK_VERIFIER_ADAPTER_RUNTIME`). The two SP1
    /// adapters share their code and differ only in `name()`, so each pin admits only its own.
    pub const SP1_PLONK_ADAPTER: B256 =
        b256!("a8306b163225c75ecbf056f4b1de173fd7a1130ee61c5ba23c72b5f7f05c2ce0");
    pub const SP1_PLONK_ADAPTER_SIZE: usize = 1849;
    pub const SP1_PLONK_ADAPTER_IMMUTABLES: [usize; 3] = [101, 527, 1165];
    /// SP1 circuit v6.1.0 PLONK verifier (sp1-contracts v6.1.1 `SP1VerifierPlonk.sol`), runtime keccak
    /// (8,625 B, no immutables; `SP1_V6_1_0_PLONK_RUNTIME`).
    pub const SP1_V6_1_0_PLONK_VERIFIER: B256 =
        b256!("d41d21f0ede6aad839e0aaac997eea8e168333bc5d15fb5f520e385dcb227f47");
    /// Its `VERIFIER_HASH()`: sha256 of the circuit's `plonk_vk.bin`. The first 4 bytes prefix every
    /// v6.1.0 PLONK seal (964 B).
    pub const SP1_V6_1_0_PLONK_VERIFIER_HASH: B256 =
        b256!("5a093a2fcb46394f5cadfe55c44d4d572fad9cec7aeb38026b0278322ef07fac");
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
/// `seal_prefix`, or why there is none: 3.1's is [`pins::RISC0_V3_1_GROTH16_VERIFIER`]; 3.0's is
/// refused ([`risc0_v3_0_refused`]), and so is any other selector.
pub fn risc0_verifier_pin(seal_prefix: [u8; 4]) -> std::result::Result<B256, String> {
    if seal_prefix == pins::RISC0_V3_1_SELECTOR {
        return Ok(pins::RISC0_V3_1_GROTH16_VERIFIER);
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

/// Hemi testnet, deployed 2026-11-16 from hemiprove-contracts 3bc441d (8e1808b) with the risc0 3.1
/// verifier (handoff §1-§2). Every older 743111 stack (the 2026-10-29 one had router
/// `0xE1a492Dc…470e`) — and the old free-mint tHEMI `0x60525eEB…E698` — is abandoned. The tHEMI token
/// did not change.
pub const HEMI_TESTNET_743111: KnownDeployment = KnownDeployment {
    name: "Hemi testnet (743111, 2026-11-16)",
    chain_id: 743111,
    router: address!("D931725db336B57dBB9A3123F2238A4FE3c6Ed58"),
    staking: address!("F3498fCF729Eb7d4E0323880e4E6aD1EB6da2e2D"),
    registry: address!("A80D9172931521f9bce0491C6374A5f28e79f10F"),
    token: address!("46955EdCF61b23a8c0b0d71428A9F1C07Bbf36cc"),
    program_registry: address!("eBB9Fb9B82f80518f74725eFc2f3FD24ded7695D"),
    // The deployment record's `fromBlock`; the router was created in block 7226099.
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

/// keccak256 of `code` with every 32-byte window equal to `value` left-padded zeroed, scanning
/// forward and skipping past each match: hemiprove-contracts `CoreRuntimePins.maskedKeccak`, the hash
/// `ReleaseCorePins` pins. A UUPS implementation's `__self` immutable is its own address, so
/// `masked_keccak(code, implementation)` is its pin hash (`runtimeKeccak`). A stray match can only
/// make the hash differ from the pin (fail closed).
pub fn masked_keccak(code: &[u8], value: Address) -> B256 {
    let word = B256::left_padding_from(value.as_slice());
    let mut buf = code.to_vec();
    let mut i = 0;
    while i + 32 <= buf.len() {
        if buf[i..i + 32] == word[..] {
            buf[i..i + 32].fill(0);
            i += 32;
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
            if masked_keccak(&icode, implementation) != impl_pin {
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
        let selectors: [[u8; 4]; 17] = [
            C::claimJobCall::SELECTOR,
            F::fulfillJobCall::SELECTOR,
            // Witness jobs fulfil without resending `inputData` (`jobs::fulfill_job_hashed`).
            F::fulfillJobHashedCall::SELECTOR,
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
            "code: router/Staking/Registry proxies, implementations and routed facets are the audited code"
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
        match ps {
            ProofSystem::Risc0Groth16 => {}
            ProofSystem::Sp1Groth16 | ProofSystem::Sp1Plonk => {
                return self.verify_sp1(ps, entry.adapter, seal_prefix).await;
            }
            ProofSystem::OpenVmHalo2 => {
                bail!("{}: no pinned verifier — zkminer does not serve it yet", ps.label())
            }
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
            if !adapter_matches(
                &acode,
                pins::RISC0_GROTH16_ADAPTER_SIZE,
                &pins::RISC0_GROTH16_ADAPTER_IMMUTABLES,
                pins::RISC0_GROTH16_ADAPTER,
                native,
            ) {
                return Err(ProofSystemRefused(format!(
                    "{} adapter {} is not the audited RiscZeroGroth16VerifierAdapter",
                    ps.label(),
                    entry.adapter
                ))
                .into());
            }
            // The pin follows the seal's selector: 3.1's verifier for 0xe71e6620; a 3.0 seal prefix
            // (0x73c457ba) or any other is refused with the reason.
            let pin = risc0_verifier_pin(seal_prefix)
                .map_err(|why| ProofSystemRefused(format!("{}: {why}", ps.label())))?;
            let vcode = self.provider.get_code_at(native).await.context("verifier code")?;
            if keccak256(&vcode) != pin {
                return Err(ProofSystemRefused(format!(
                    "{} native verifier {native} is not the audited risc0-ethereum v3.1 verifier \
                     (the pin for seal SELECTOR 0x{})",
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

    /// `verify_proof_system` for `sp1.groth16.v1` and `sp1.plonk.v1`: the adapter is that wrapper's
    /// audited SP1 adapter wrapping the audited circuit v6.1.0 verifier of the same wrapper, whose
    /// `VERIFIER_HASH()` is the pinned one and starts with `seal_prefix` (the first 4 bytes of every
    /// seal zkminer would send for it). The two SP1 adapters differ only in `name()`, so each id
    /// accepts only its own adapter over its own verifier.
    async fn verify_sp1(
        &self,
        ps: ProofSystem,
        adapter: Address,
        seal_prefix: [u8; 4],
    ) -> Result<Address> {
        let p = sp1_pins(ps).with_context(|| format!("{}: not an SP1 proof system", ps.label()))?;
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
            if !adapter_matches(&acode, p.adapter_size, &p.adapter_immutables, p.adapter, native) {
                return Err(ProofSystemRefused(format!(
                    "{} adapter {adapter} is not the audited {}",
                    ps.label(),
                    p.adapter_name
                ))
                .into());
            }
            let vcode = self
                .provider
                .get_code_at(native)
                .await
                .context("verifier code")?;
            if keccak256(&vcode) != p.verifier {
                return Err(ProofSystemRefused(format!(
                    "{} native verifier {native} is not the audited SP1 circuit v6.1.0 {} verifier",
                    ps.label(),
                    p.wrapper
                ))
                .into());
            }
        }
        let hash = ISP1NativeVerifier::new(native, &*self.provider)
            .VERIFIER_HASH()
            .call()
            .await
            .context("verifier VERIFIER_HASH()")?;
        if hash != p.verifier_hash || hash[..4] != seal_prefix {
            return Err(ProofSystemRefused(format!(
                "{} verifier VERIFIER_HASH() is {hash} but zkminer's SP1 {} seals are prefixed 0x{} \
                 (circuit v6.1.0) — every proof would revert VerifierCallFailed",
                ps.label(),
                p.wrapper,
                alloy::hex::encode(seal_prefix)
            ))
            .into());
        }
        Ok(adapter)
    }
}

/// One SP1 wrapper's pins: its adapter and the native verifier that adapter must wrap.
struct Sp1Pins {
    wrapper: &'static str,
    adapter_name: &'static str,
    adapter: B256,
    adapter_size: usize,
    adapter_immutables: [usize; 3],
    verifier: B256,
    verifier_hash: B256,
}

/// The pins of an SP1 proof system, `None` for any other.
fn sp1_pins(ps: ProofSystem) -> Option<Sp1Pins> {
    match ps {
        ProofSystem::Sp1Groth16 => Some(Sp1Pins {
            wrapper: "Groth16",
            adapter_name: "SP1Groth16VerifierAdapter",
            adapter: pins::SP1_GROTH16_ADAPTER,
            adapter_size: pins::SP1_GROTH16_ADAPTER_SIZE,
            adapter_immutables: pins::SP1_GROTH16_ADAPTER_IMMUTABLES,
            verifier: pins::SP1_V6_1_0_GROTH16_VERIFIER,
            verifier_hash: pins::SP1_V6_1_0_GROTH16_VERIFIER_HASH,
        }),
        ProofSystem::Sp1Plonk => Some(Sp1Pins {
            wrapper: "PLONK",
            adapter_name: "SP1PlonkVerifierAdapter",
            adapter: pins::SP1_PLONK_ADAPTER,
            adapter_size: pins::SP1_PLONK_ADAPTER_SIZE,
            adapter_immutables: pins::SP1_PLONK_ADAPTER_IMMUTABLES,
            verifier: pins::SP1_V6_1_0_PLONK_VERIFIER,
            verifier_hash: pins::SP1_V6_1_0_PLONK_VERIFIER_HASH,
        }),
        ProofSystem::Risc0Groth16 | ProofSystem::OpenVmHalo2 => None,
    }
}

/// Whether `code` is the pinned adapter wrapping `native` (`VerifierPins._adapterProblem`): exactly
/// `size` bytes, every immutable reference at `offsets` the left-padded `native`, and with them
/// zeroed the runtime keccak `pin`.
fn adapter_matches(code: &[u8], size: usize, offsets: &[usize], pin: B256, native: Address) -> bool {
    code.len() == size
        && immutables_are(code, offsets, B256::left_padding_from(native.as_slice()))
        && keccak_offsets_zeroed(code, offsets) == Some(pin)
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
    fn masking_matches_core_runtime_pins() {
        // CoreRuntimePins.maskedKeccak zeroes every 32-byte window equal to the left-padded address
        // (a PUSH32 of the `__self` immutable), and nothing else: a bare 20-byte occurrence (not
        // preceded by 12 zero bytes) stays, so it makes the hash differ from the pin (fail closed).
        let me = Address::repeat_byte(0xAB);
        let word = B256::left_padding_from(me.as_slice());
        let mut code = vec![0x60, 0x80, 0x7f];
        code.extend_from_slice(word.as_slice()); // PUSH32 __self
        code.extend_from_slice(&[0x5b, 0x01]);
        let bare = code.len();
        code.extend_from_slice(me.as_slice()); // a bare 20-byte occurrence
        code.extend_from_slice(&[0x7f]);
        let second = code.len();
        code.extend_from_slice(word.as_slice()); // PUSH32 __self again
        let mut expect = code.clone();
        expect[3..35].fill(0);
        expect[second..second + 32].fill(0);
        assert_eq!(masked_keccak(&code, me), keccak256(&expect));
        assert_eq!(&expect[bare..bare + 20], me.as_slice(), "the bare occurrence is kept");
        assert_ne!(masked_keccak(&code, me), keccak256(&code));
        // Another address masks nothing.
        assert_eq!(masked_keccak(&code, Address::repeat_byte(0xCD)), keccak256(&code));
    }

    #[test]
    fn an_adapter_must_be_exactly_its_pinned_size() {
        let verifier = Address::repeat_byte(0xAB);
        let word = B256::left_padding_from(verifier.as_slice());
        let mut code = vec![0x5bu8; 100];
        code[10..42].copy_from_slice(word.as_slice());
        let pin = keccak_offsets_zeroed(&code, &[10]).unwrap();
        assert!(adapter_matches(&code, 100, &[10], pin, verifier));
        assert!(!adapter_matches(&code, 101, &[10], pin, verifier), "size");
        assert!(!adapter_matches(&code, 100, &[10], pin, Address::repeat_byte(0xCD)), "verifier");
        let mut longer = code.clone();
        longer.push(0);
        assert!(!adapter_matches(&longer, 100, &[10], pin, verifier));
    }

    #[test]
    fn each_sp1_wrapper_has_its_own_pins() {
        let g = sp1_pins(ProofSystem::Sp1Groth16).unwrap();
        let p = sp1_pins(ProofSystem::Sp1Plonk).unwrap();
        // The seal prefixes of handoff §3: Groth16 0x4388a21c (356 B), PLONK 0x5a093a2f (964 B).
        assert_eq!(g.verifier_hash[..4], [0x43, 0x88, 0xa2, 0x1c]);
        assert_eq!(p.verifier_hash[..4], [0x5a, 0x09, 0x3a, 0x2f]);
        assert_ne!(g.adapter, p.adapter);
        assert_ne!(g.verifier, p.verifier);
        assert!(sp1_pins(ProofSystem::Risc0Groth16).is_none());
        assert!(sp1_pins(ProofSystem::OpenVmHalo2).is_none());
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
        let pin = pins::RISC0_V3_1_GROTH16_VERIFIER;
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
    }

    #[test]
    fn the_743111_deployment_is_known() {
        let k = known_deployment(743111).expect("743111 known");
        assert_eq!(k.scan_from_block, 7_226_094);
        assert_eq!(k.router, address!("D931725db336B57dBB9A3123F2238A4FE3c6Ed58"));
        assert_ne!(
            k.router,
            address!("E1a492Dc6D57fCC2B6deb5B64087E69666cA470e"),
            "the 2026-10-29 stack is abandoned"
        );
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
    /// `ZKMINER_CONTRACTS_REPO` (at commit 8e1808b, or 3bc441d). Each pin value must appear in one of
    /// the two files, and each adapter's runtime size next to its name. Without the variable the test only reports that it did not run.
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
            ("RISC0_V3_1_GROTH16_VERIFIER".into(), pins::RISC0_V3_1_GROTH16_VERIFIER),
            ("SP1_GROTH16_ADAPTER".into(), pins::SP1_GROTH16_ADAPTER),
            ("SP1_V6_1_0_GROTH16_VERIFIER".into(), pins::SP1_V6_1_0_GROTH16_VERIFIER),
            ("SP1_V6_1_0_GROTH16_VERIFIER_HASH".into(), pins::SP1_V6_1_0_GROTH16_VERIFIER_HASH),
            ("SP1_PLONK_ADAPTER".into(), pins::SP1_PLONK_ADAPTER),
            ("SP1_V6_1_0_PLONK_VERIFIER".into(), pins::SP1_V6_1_0_PLONK_VERIFIER),
            ("SP1_V6_1_0_PLONK_VERIFIER_HASH".into(), pins::SP1_V6_1_0_PLONK_VERIFIER_HASH),
        ];
        want.extend(pins::FACETS.iter().map(|(n, h)| (n.to_string(), *h)));
        let missing: Vec<String> = want
            .iter()
            .filter(|(_, h)| !text.contains(&format!("{h:x}")))
            .map(|(n, h)| format!("{n} {h}"))
            .collect();
        assert!(missing.is_empty(), "pins absent from the repo's pin files: {missing:#?}");
        for (name, size) in [
            ("risc_zero_groth16_verifier_adapter_size", pins::RISC0_GROTH16_ADAPTER_SIZE),
            ("sp1_groth16_verifier_adapter_size", pins::SP1_GROTH16_ADAPTER_SIZE),
            ("sp1_plonk_verifier_adapter_size", pins::SP1_PLONK_ADAPTER_SIZE),
        ] {
            assert!(
                text.contains(&format!("{name} = {size};")),
                "{name} = {size} absent from VerifierPins.sol"
            );
        }
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

    /// The startup verification against the LIVE 743111 deployment, read-only, through a watch-only
    /// client (no key; its transport refuses every send). It runs what `zkminer run` checks before
    /// claiming — the chain id, the addresses, the wiring and the core code pins — then every proof
    /// system's adapter and verifier, SP1 PLONK included (which `run` does not serve), with the seal
    /// prefixes of handoff §3.
    ///
    /// `cargo test -p zkminer-chain --lib -- --ignored --nocapture live_743111`; set
    /// `ZKMINER_LIVE_RPC` for another endpoint than the public testnet RPC.
    #[tokio::test]
    #[ignore = "reads the live Hemi testnet"]
    async fn live_743111_deployment_verifies() {
        let k = &HEMI_TESTNET_743111;
        let mut config = zkminer_config::ZkMinerConfig::default();
        config.chain.rpc_url = std::env::var("ZKMINER_LIVE_RPC")
            .unwrap_or_else(|_| "https://testnet.rpc.hemi.network/rpc".into());
        config.chain.chain_id = k.chain_id;
        config.contracts.hemi_prove = k.router.to_string();
        config.contracts.hemi_prove_staking = k.staking.to_string();
        config.contracts.hemi_prove_registry = k.registry.to_string();
        config.contracts.hemi_token = k.token.to_string();
        config.contracts.program_registry = k.program_registry.to_string();
        let client = ChainClient::new_watch_only(&config, Address::ZERO)
            .await
            .expect("connect (the chain id is checked here)");
        assert_eq!(client.chain_id, 743111);
        assert!(!code_pins_skipped(), "unset ZKMINER_SKIP_CODE_PINS");
        for line in client.verify_deployment().await.expect("verify_deployment") {
            println!("deployment: {line}");
        }
        for (ps, prefix) in [
            (ProofSystem::Risc0Groth16, pins::RISC0_V3_1_SELECTOR),
            (ProofSystem::Sp1Groth16, [0x43, 0x88, 0xa2, 0x1c]),
            (ProofSystem::Sp1Plonk, [0x5a, 0x09, 0x3a, 0x2f]),
        ] {
            let adapter = client
                .verify_proof_system(ps, prefix)
                .await
                .unwrap_or_else(|e| panic!("{}: {e:#}", ps.label()));
            println!(
                "{}: adapter {adapter} is the pinned adapter over the pinned verifier, seal prefix 0x{}",
                ps.label(),
                alloy::hex::encode(prefix)
            );
        }
        // OpenVM Halo2 is not registered at launch.
        let (adapter, status) = client.adapter_entry(ProofSystem::OpenVmHalo2).await.unwrap();
        println!("{}: adapter {adapter}, status {status}", ProofSystem::OpenVmHalo2.label());
    }
}
