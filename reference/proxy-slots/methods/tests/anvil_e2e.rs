//! Plan §12 end to end on a local chain, CPU only: an EIP-1967 proxy deployed on anvil; the
//! reference builder (`sdk/examples/proxy-slots`) run by the real runner binary behind the real
//! broker binary, both sandboxed, in developer mode (anvil is on 127.0.0.1); the reference guest on
//! the risc0 executor over the `W` it wrote; the journal checked against the chain and against a
//! FIELDS binding over the 160-byte header; then every structural mutation of that real `W`.
//!
//! Needs a delegated cgroup, anvil and the SDK's pinned toolchain:
//!
//! ```text
//! systemd-run --user --scope -q -p Delegate=yes -- \
//!     env ZKMINER_SANDBOX_TESTS_REQUIRED=1 CARGO_TARGET_DIR=... \
//!     cargo test -p hemiprove-proxy-slots-methods --test anvil_e2e
//! ```

mod common;

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use alloy_primitives::{keccak256, Address, B256};
use common::{execute, input, prefix};
use hemiprove_eth_prelude::scheme1::{judge, ByteSelection, Mutation, ProofRef, Verdict, Witness};
use hemiprove_proxy_slots::{
    decode_journal, journal_fields, run, Rule, RuleKind, Statement, EIP1967_IMPLEMENTATION_SLOT, HEADER_BYTES, PREFIX_BYTES,
};
use serde_json::Value;
use zkminer_witness::binding::{
    clear_marker, expected_journal_hash, fields_hash, header_from_words, journal_fields_for_header, mutation_check,
};
use zkminer_witness::context::{build_context, encode_context, DescriptorFields};
use zkminer_witness::envelope::{
    effective_limits, encode_evm_rpc_config, Capability, HostMaxima, Limits, CLASS_EVM_RPC_V1, METHOD_SET_STATE_READ,
};
use zkminer_witness::ipc::JobBudget;
use zkminer_witness::WitnessJobV1;
use zkminer_witness_broker::client::JobRegistration;
use zkminer_witness_host::broker_proc::BrokerProcess;
use zkminer_witness_host::builder_run::{run_builder, BuilderRun, VecSink};
use zkminer_witness_host::spawner::Spawner;
use zkminer_witness_sandbox::{delegated_root, landlock_abi, SandboxError, MIN_LANDLOCK_ABI};

const ANVIL_CHAIN: u64 = 31337;
/// anvil's first dev account (unlocked: `eth_sendTransaction` signs for it).
const DEV: &str = "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266";

fn skip(test: &str, reason: &str) {
    if std::env::var_os("ZKMINER_SANDBOX_TESTS_REQUIRED").is_some() {
        panic!("{test}: sandbox unavailable: {reason}");
    }
    let _ = writeln!(std::io::stderr(), "SKIPPED {test}: {reason}");
}

fn delegated(test: &str) -> Option<PathBuf> {
    if landlock_abi() < MIN_LANDLOCK_ABI {
        skip(test, "Landlock too old");
        return None;
    }
    match delegated_root() {
        Ok(r) => Some(r),
        Err(e @ SandboxError::NotDelegated { .. }) => {
            skip(test, &e.to_string());
            None
        }
        Err(e) => panic!("{test}: {e}"),
    }
}

// ---------------------------------------------------------------------------------------------
// Binaries and the builder.

/// The workspace target dir this test binary lives in (`<target>/debug/deps/<test>`).
fn target_dir() -> PathBuf {
    std::env::current_exe().unwrap().parent().unwrap().parent().unwrap().parent().unwrap().to_path_buf()
}

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..").canonicalize().unwrap()
}

/// The runner and broker binaries, built into this test's target dir.
fn binaries() -> (PathBuf, PathBuf) {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
    let out = Command::new(cargo)
        .current_dir(repo())
        .args(["build", "-p", "zkminer-witness-builder", "-p", "zkminer-witness-broker", "--bins", "--target-dir"])
        .arg(target_dir())
        .output()
        .expect("cargo runs");
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let debug = target_dir().join("debug");
    (debug.join("zkminer-witness-builder"), debug.join("zkminer-witness-broker"))
}

fn sdk_tool(tool: &str) -> std::ffi::OsString {
    let out = Command::new("rustup").args(["which", tool]).current_dir(repo().join("sdk")).env_remove("RUSTUP_TOOLCHAIN").output();
    match out {
        Ok(o) if o.status.success() => String::from_utf8(o.stdout).unwrap().trim().into(),
        _ => tool.into(),
    }
}

/// The reference builder, built with the SDK's pinned toolchain and target features.
fn builder_wasm() -> Vec<u8> {
    let target = Path::new(env!("CARGO_TARGET_TMPDIR")).join("sdk-target-proxy-slots");
    let mut cmd = Command::new(sdk_tool("cargo"));
    cmd.current_dir(repo().join("sdk"))
        .args(["build", "--locked", "--release", "--target", "wasm32-unknown-unknown", "-p", "proxy-slots-builder", "--target-dir"])
        .arg(&target)
        .env("RUSTC", sdk_tool("rustc"));
    for v in ["RUSTUP_TOOLCHAIN", "RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "CARGO_BUILD_RUSTFLAGS", "CARGO_TARGET_DIR"] {
        cmd.env_remove(v);
    }
    let out = cmd.output().expect("cargo runs");
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    std::fs::read(target.join("wasm32-unknown-unknown/release/proxy_slots_builder.wasm")).unwrap()
}

// ---------------------------------------------------------------------------------------------
// anvil.

struct Anvil {
    child: Child,
    url: String,
}

impl Drop for Anvil {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

impl Anvil {
    fn start() -> Self {
        let port = free_port();
        let child = Command::new("anvil")
            .args(["--port", &port.to_string(), "--silent"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("anvil on PATH");
        let a = Anvil { child, url: format!("http://127.0.0.1:{port}") };
        for _ in 0..100 {
            if a.try_rpc("eth_chainId", "[]").is_some() {
                return a;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        panic!("anvil did not start");
    }

    fn try_rpc(&self, method: &str, params: &str) -> Option<Value> {
        let body = format!(r#"{{"jsonrpc":"2.0","id":1,"method":"{method}","params":{params}}}"#);
        let out = Command::new("curl").args(["-s", "-H", "content-type: application/json", "-d", &body, &self.url]).output().ok()?;
        let v: Value = serde_json::from_slice(&out.stdout).ok()?;
        v.get("result").cloned()
    }

    fn rpc(&self, method: &str, params: &str) -> Value {
        self.try_rpc(method, params).unwrap_or_else(|| panic!("{method} {params}"))
    }

    /// Sends a transaction from the dev account and returns its receipt.
    fn send(&self, tx: &str) -> Value {
        let hash = self.rpc("eth_sendTransaction", &format!("[{tx}]"));
        for _ in 0..100 {
            if let Some(r) = self.try_rpc("eth_getTransactionReceipt", &format!("[{hash}]")).filter(|r| !r.is_null()) {
                assert_eq!(r["status"], "0x1", "{tx}: {r}");
                return r;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        panic!("no receipt for {tx}");
    }

    fn deploy(&self, creation: &[u8]) -> Address {
        let r = self.send(&format!(r#"{{"from":"{DEV}","data":"0x{}"}}"#, hex::encode(creation)));
        r["contractAddress"].as_str().unwrap().parse().unwrap()
    }
}

fn h(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap().strip_prefix("0x").unwrap()).unwrap()
}

// ---------------------------------------------------------------------------------------------
// The contracts, assembled by hand (no compiler needed).

/// Creation code: `SSTORE(slot, value)` for each pair, then return `runtime`.
fn creation(stores: &[([u8; 32], [u8; 32])], runtime: &[u8]) -> Vec<u8> {
    let mut c = Vec::new();
    for (slot, value) in stores {
        c.push(0x7f); // PUSH32 value
        c.extend_from_slice(value);
        c.push(0x7f); // PUSH32 slot
        c.extend_from_slice(slot);
        c.push(0x55); // SSTORE
    }
    let len = u16::try_from(runtime.len()).unwrap().to_be_bytes();
    let offset = u16::try_from(c.len() + 15).unwrap().to_be_bytes();
    // PUSH2 len PUSH2 offset PUSH1 0 CODECOPY PUSH2 len PUSH1 0 RETURN
    c.extend_from_slice(&[0x61, len[0], len[1], 0x61, offset[0], offset[1], 0x60, 0x00, 0x39, 0x61, len[0], len[1], 0x60, 0x00, 0xf3]);
    c.extend_from_slice(runtime);
    c
}

/// The implementation: stores calldata word 1 at the slot calldata word 0 names (in the proxy's
/// storage, when called through it), then returns 42.
const IMPLEMENTATION_RUNTIME: [u8; 14] = [0x60, 0x20, 0x35, 0x5f, 0x35, 0x55, 0x60, 0x2a, 0x5f, 0x52, 0x60, 0x20, 0x5f, 0xf3];

/// An EIP-1967 proxy: delegate the calldata to the address in the implementation slot, return or
/// revert with what it returned.
fn proxy_runtime() -> Vec<u8> {
    let mut r = vec![0x36, 0x5f, 0x5f, 0x37, 0x5f, 0x5f, 0x36, 0x5f, 0x7f];
    r.extend_from_slice(&EIP1967_IMPLEMENTATION_SLOT);
    // SLOAD GAS DELEGATECALL; RETURNDATACOPY(0, 0, size); JUMPI ok; REVERT; ok: RETURN
    r.extend_from_slice(&[0x54, 0x5a, 0xf4, 0x3d, 0x5f, 0x5f, 0x3e, 0x60, 0x36, 0x57, 0x3d, 0x5f, 0xfd, 0x5b, 0x3d, 0x5f, 0xf3]);
    assert_eq!(r[0x36], 0x5b, "the jump target is the JUMPDEST");
    r
}

fn word(n: u64) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[24..].copy_from_slice(&n.to_be_bytes());
    w
}

fn add(base: [u8; 32], j: u64) -> [u8; 32] {
    (alloy_primitives::U256::from_be_bytes(base).wrapping_add(alloy_primitives::U256::from(j))).to_be_bytes()
}

// ---------------------------------------------------------------------------------------------
// The miner side.

fn dev_miner() -> zkminer_config::ZkMinerConfig {
    let mut c = zkminer_config::ZkMinerConfig::default();
    c.chain.chain_id = ANVIL_CHAIN;
    c.dev.private_network = true;
    c.dev.chain_id = Some(ANVIL_CHAIN);
    assert_eq!(c.net_mode(), zkminer_netguard::NetMode::DevPrivate);
    c
}

fn broker_config(dir: &Path, url: &str) -> String {
    format!(
        "chain_rpc_host = \"chain-rpc.invalid\"\nspool_dir = \"{}\"\n[[evm_rpc]]\nalias = \"anvil\"\nurl = \"{url}\"\n\
         chain_id = {ANVIL_CHAIN}\narchive = true\nmax_proof_age = 1000000\nmethod_sets = [\"state-read\"]\n\
         cidrs = [\"127.0.0.1/32\"]\n",
        dir.join("spool").display()
    )
}

/// One builder run for `statement`, as the miner's pre-claim pipeline runs it.
async fn build_witness(
    spawner: &Spawner,
    broker: &BrokerProcess,
    runner: &Path,
    root: &Path,
    wasm: &[u8],
    statement: &Statement,
    job: u8,
) -> Vec<u8> {
    let source = Capability {
        class: CLASS_EVM_RPC_V1,
        config: encode_evm_rpc_config(ANVIL_CHAIN, true, METHOD_SET_STATE_READ, 1_000).into(),
    };
    let declared = Limits {
        maxFetches: 8,
        maxFetchBytes: 1 << 22,
        maxRequestBytes: 65_536,
        maxResponseBytes: 1 << 20,
        maxBuilderFuel: 5_000_000_000,
        maxBuilderMemoryBytes: 64 << 20,
        maxBuilderSeconds: 60,
        maxWitnessBytes: 1 << 20,
        maxGuestCycles: 1 << 26,
    };
    let host = HostMaxima {
        max_witness_bytes: 32 << 20,
        max_guest_cycles: 1 << 30,
        max_fetches: 1_024,
        max_fetch_bytes: 1 << 28,
        max_request_bytes: 65_536,
        max_response_bytes: 32 << 20,
        max_builder_fuel: 20_000_000_000,
        max_builder_memory_bytes: 512 << 20,
        max_builder_seconds: 120,
    };
    let limits = effective_limits(&declared, &host).unwrap();
    let job_v1 = WitnessJobV1 {
        builderType: 1,
        builderId: keccak256(wasm), // not checked on this path; the pipeline checks sha256
        builderURIs: vec![],
        builderParams: statement.builder_params(ANVIL_CHAIN).to_vec().into(),
        sources: vec![source.clone()],
        limits: declared.clone(),
    };
    let d = DescriptorFields {
        program_id: B256::repeat_byte(1),
        proof_system_id: B256::repeat_byte(2),
        expected_journal_hash: B256::from(statement.expected_journal_hash()),
        journal_fields: B256::from(journal_fields()),
    };
    let context = encode_context(&build_context(743_111, Address::repeat_byte(5), &d, &job_v1));
    let job_key = B256::repeat_byte(job);
    let (result, sink) = run_builder(
        spawner,
        &broker.client,
        &BuilderRun { binary: runner, cgroup_root: root, job_key, module: wasm, context: &context, limits: &limits },
        JobRegistration {
            job_key,
            caller: Address::repeat_byte(6),
            sources: vec![(source.class, source.config.to_vec())],
            budget: JobBudget {
                max_fetches: limits.maxFetches,
                max_fetch_bytes: limits.maxFetchBytes,
                max_request_bytes: limits.maxRequestBytes,
                max_response_bytes: limits.maxResponseBytes,
            },
            held_lock: false,
        },
        VecSink::default(),
    )
    .await
    .unwrap();
    assert_eq!(result.verdict, None, "outcome {:?}\nlog:\n{}", result.outcome, result.log);
    assert!(result.outcome.module_started);
    let stats = result.stats.unwrap();
    eprintln!("builder: {} fetches, W {} bytes; log: {}", stats.fetches, result.w_bytes, result.log.trim());
    assert_eq!(stats.fetches, 4, "header, implementation slot, two proofs");
    sink.0
}

/// Every standard mutation of `w`, plus the parent and a later header swapped in, on the native
/// statement; a sample of them on the risc0 executor. None may give a different answer under the
/// same header.
fn attack(w_bytes: &[u8], honest: &[u8], prefix: &[u8; 64], parent: Vec<u8>, later: Vec<u8>) {
    let w = Witness::decode(w_bytes).unwrap();
    let pinned = PREFIX_BYTES + HEADER_BYTES;
    let mut mutations = w.standard_mutations(ByteSelection::Sample(24));
    mutations.push(Mutation::ReplaceHeader { header: 0, rlp: parent.clone() });
    mutations.push(Mutation::ReplaceHeader { header: 0, rlp: later });
    let mut counts = std::collections::BTreeMap::<String, usize>::new();
    for m in &mutations {
        let mutated = w.mutate(m).unwrap();
        let verdict = judge(honest, run(&input(prefix, &mutated)).ok().as_deref(), pinned);
        assert_ne!(verdict, Verdict::Unsound, "{m:?}");
        *counts.entry(format!("{verdict:?}")).or_default() += 1;
    }
    eprintln!("native: {} mutations of the real W: {counts:?}", mutations.len());
    assert_eq!(counts.get("Rejected"), Some(&mutations.len()), "{counts:?}");
    let on_executor = [
        Mutation::ReplaceHeader { header: 0, rlp: parent },
        Mutation::FlipKind { proof: ProofRef::Account(1) },
        Mutation::FlipKind { proof: ProofRef::Storage { account: 0, slot: 1 } },
        Mutation::SwapProofs { a: ProofRef::Storage { account: 0, slot: 1 }, b: ProofRef::Storage { account: 0, slot: 2 } },
        Mutation::DropNode { proof: ProofRef::Account(0), node: 0 },
        Mutation::NodeByte { proof: ProofRef::Storage { account: 0, slot: 0 }, node: 0, byte: 7, mask: 1 },
        Mutation::DuplicateProof { proof: ProofRef::Storage { account: 0, slot: 1 } },
        Mutation::AppendBytes { bytes: vec![0; 32] },
    ];
    for m in &on_executor {
        let mutated = w.mutate(m).unwrap();
        let out = execute(&input(prefix, &mutated), [7; 32], 20);
        assert!(out.is_err(), "{m:?} executed: the guest must refuse it");
    }
    eprintln!("executor: {} mutations refused", on_executor.len());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_real_builder_run_proves_a_proxy_on_anvil() {
    let Some(root) = delegated("a_real_builder_run_proves_a_proxy_on_anvil") else { return };
    let (runner, broker_bin) = binaries();
    let wasm = builder_wasm();
    let anvil = Anvil::start();

    // The implementation, then a proxy pointing at it with storage under both rules: slots 10–12
    // (rule 1) and the mapping(address => T) at slot 5, keyed by the implementation (rule 2).
    let implementation = anvil.deploy(&creation(&[], &IMPLEMENTATION_RUNTIME));
    let mut imp_word = [0u8; 32];
    imp_word[12..].copy_from_slice(implementation.as_slice());
    let base = keccak256([imp_word, word(5)].concat()).0;
    let stores = [
        (EIP1967_IMPLEMENTATION_SLOT, imp_word),
        (word(10), word(100)),
        (word(11), word(101)),
        (word(12), word(102)),
        (base, word(0xaaaa)),
        (add(base, 1), word(0xbbbb)),
    ];
    let proxy = anvil.deploy(&creation(&stores, &proxy_runtime()));
    // It is a working proxy: a call reaches the implementation through DELEGATECALL.
    let answer = anvil.rpc("eth_call", &format!(r#"[{{"to":"{proxy}","data":"0x12345678"}},"latest"]"#));
    assert_eq!(h(&answer), word(42), "the proxy delegates to the implementation");
    anvil.rpc("anvil_mine", "[\"0x3\"]");

    // B: the block the requester pins. Then the chain moves on: a transaction through the proxy
    // sets slot 10 to 999 after B. (A real transaction: anvil_setStorageAt would rewrite the head
    // block's state in place, and B's proofs with it.)
    let b = anvil.rpc("eth_getBlockByNumber", "[\"latest\",false]");
    let block_hash: [u8; 32] = h(&b["hash"]).try_into().unwrap();
    let parent = anvil.rpc("eth_getBlockByHash", &format!("[\"{}\",false]", b["parentHash"].as_str().unwrap()));
    anvil.send(&format!(r#"{{"from":"{DEV}","to":"{proxy}","data":"0x{}{}"}}"#, hex::encode(word(10)), hex::encode(word(999))));
    let at_head = anvil.rpc("eth_getStorageAt", &format!("[\"{proxy}\",\"0x{}\",\"latest\"]", hex::encode(word(10))));
    assert_eq!(h(&at_head), word(999));
    anvil.rpc("anvil_mine", "[\"0x2\"]");
    let later = anvil.rpc("eth_getBlockByNumber", "[\"latest\",false]");

    let dir = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
    let config = dir.path().join("broker.toml");
    std::fs::write(&config, broker_config(dir.path(), &anvil.url)).unwrap();
    let spawner = Spawner::new().unwrap();
    let broker = BrokerProcess::start(&spawner, &broker_bin, &config, &root, 512 << 20, &dev_miner()).unwrap();

    let mut proxy20 = [0u8; 20];
    proxy20.copy_from_slice(proxy.as_slice());
    let cases = [
        (Statement { block_hash, proxy: proxy20, rule: Rule::new(RuleKind::Consecutive, &word(10)).unwrap(), k: 4 }, vec![word(100), word(101), word(102), [0; 32]]),
        (
            Statement { block_hash, proxy: proxy20, rule: Rule::new(RuleKind::MappingByImplementation, &word(5)).unwrap(), k: 2 },
            vec![word(0xaaaa), word(0xbbbb)],
        ),
    ];
    for (n, (statement, want)) in cases.iter().enumerate() {
        let w = build_witness(&spawner, &broker, &runner, &root, &wasm, statement, 0x50 + n as u8).await;

        // The guest on the risc0 executor, over exactly the W the builder wrote.
        let p = prefix(0xa0 + n as u8, 0xb0);
        let executed = execute(&input(&p, &w), [n as u8; 32], 20).unwrap();
        assert_eq!(executed.journal, run(&input(&p, &w)).unwrap(), "the guest computes what the statement does");
        let j = decode_journal(&executed.journal).unwrap();
        assert_eq!(j.prefix.0, p);
        assert_eq!(&j.outputs.implementation, implementation.as_slice());
        assert_eq!(j.outputs.code_hash, keccak256(IMPLEMENTATION_RUNTIME).0);
        let values: Vec<[u8; 32]> = j.outputs.slots.iter().map(|(_, v)| *v).collect();
        assert_eq!(&values, want, "the values at B, not at the head (slot 10 is 999 there)");
        let slots: Vec<[u8; 32]> = j.outputs.slots.iter().map(|(s, _)| *s).collect();
        assert_eq!(slots, statement.rule.slots(&j.outputs.implementation, statement.k));
        eprintln!("rule {:?}: {} cycles, journal {} bytes", statement.rule.kind(), executed.cycles, executed.journal.len());

        // The binding: FIELDS over the 160-byte header after the prefix, from the requester's own
        // parameters, through zkminer's binding helpers.
        let fields = journal_fields_for_header(HEADER_BYTES, true).unwrap();
        assert_eq!(fields.0, journal_fields());
        assert_eq!(expected_journal_hash(&statement.header()).0, statement.expected_journal_hash());
        assert_eq!(fields_hash(&executed.journal[PREFIX_BYTES..], clear_marker(fields)).0, statement.expected_journal_hash());
        assert_eq!(&executed.journal[..PREFIX_BYTES], &p, "the journal-prefix marker's prefix");
        let params: Vec<B256> = statement.header_words()[1..].iter().map(|w| B256::from(*w)).collect();
        let statement_of = |p: &[B256]| {
            let mut words = vec![B256::from(hemiprove_eth_prelude::scheme1::scheme_word())];
            words.extend_from_slice(p);
            let mut bytes = header_from_words(&words);
            bytes.extend_from_slice(&executed.journal[PREFIX_BYTES + HEADER_BYTES..]);
            bytes
        };
        assert_eq!(mutation_check(&params, fields, statement_of), Ok(()), "every parameter byte is pinned");

        // Every structural mutation of this real W.
        let later_rlp = header_rlp(&later);
        attack(&w, &executed.journal, &p, header_rlp(&parent), later_rlp);
    }
    drop(broker);
}

/// A header's RLP from anvil's JSON (anvil serves no raw headers).
fn header_rlp(b: &Value) -> Vec<u8> {
    let header = common::header_from_json(b);
    let rlp = header.encode().unwrap();
    assert_eq!(keccak256(&rlp).0.to_vec(), h(&b["hash"]), "anvil's header encodes to its hash");
    rlp
}
