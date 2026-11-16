//! The SDK's example builder (`sdk/examples/latest-block`), built with cargo for
//! wasm32-unknown-unknown under the SDK's pinned target features, then put through the pre-pass and
//! run end to end against a fake broker.

mod common;

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

use common::*;
use wasmparser::{Parser, Payload, TypeRef};
use zkminer_witness::abi;
use zkminer_witness::context::{build_context, encode_context, DescriptorFields};
use zkminer_witness::envelope::{
    encode_evm_rpc_config, BuilderContextV1, Capability, Limits, CLASS_BLOB_V1, CLASS_EVM_RPC_V1, METHOD_SET_STATE_READ,
};
use zkminer_witness::ipc::{exit, FetchStatus};
use zkminer_witness::WitnessJobV1;
use zkminer_witness_builder::{prepass, PROFILE_FEATURES};

const REQUEST: &[u8] = br#"{"jsonrpc":"2.0","id":1,"method":"eth_getBlockByNumber","params":["finalized",false]}"#;
const HASH: &str = "0x9b83c12c69edb74f6c8dd5d052765c1adf940e320bd1291696e6fa07829eee71";

fn sdk_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../sdk").canonicalize().unwrap()
}

/// Builds the SDK workspace's builders once per test binary, from the SDK directory (so its
/// `.cargo/config.toml` applies), into this test's own target dir, with no inherited flags that would
/// replace the pinned target features. Returns `name`'s module.
fn built(name: &str) -> &'static [u8] {
    static WASM: OnceLock<(Vec<u8>, Vec<u8>)> = OnceLock::new();
    let (example, faults) = WASM.get_or_init(|| {
        let target = Path::new(env!("CARGO_TARGET_TMPDIR")).join("sdk-target");
        let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
        let out = Command::new(cargo)
            .current_dir(sdk_dir())
            .args(["build", "--locked", "--release", "--target", "wasm32-unknown-unknown"])
            .args(["-p", "latest-block", "-p", "faults", "--target-dir"])
            .arg(&target)
            .env_remove("RUSTFLAGS")
            .env_remove("CARGO_ENCODED_RUSTFLAGS")
            .env_remove("CARGO_BUILD_RUSTFLAGS")
            .env_remove("CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUSTFLAGS")
            .env_remove("CARGO_BUILD_TARGET")
            .env_remove("CARGO_TARGET_DIR")
            .output()
            .expect("cargo runs");
        assert!(out.status.success(), "building the SDK builders failed:\n{}", String::from_utf8_lossy(&out.stderr));
        let read = |n: &str| std::fs::read(target.join("wasm32-unknown-unknown/release").join(n)).unwrap();
        (read("latest_block.wasm"), read("faults.wasm"))
    });
    match name {
        "latest-block" => example,
        "faults" => faults,
        _ => unreachable!(),
    }
}

fn example_wasm() -> &'static [u8] {
    built("latest-block")
}

fn context(sources: Vec<Capability>) -> Vec<u8> {
    context_with(sources, vec![1, 2, 3])
}

fn context_with(sources: Vec<Capability>, params: Vec<u8>) -> Vec<u8> {
    let job = WitnessJobV1 {
        builderType: 1,
        builderId: [0x11; 32].into(),
        builderURIs: vec![],
        builderParams: params.into(),
        sources,
        limits: Limits {
            maxFetches: 100,
            maxFetchBytes: 1 << 24,
            maxRequestBytes: 65_536,
            maxResponseBytes: 1 << 22,
            maxBuilderFuel: 1 << 32,
            maxBuilderMemoryBytes: 1 << 28,
            maxBuilderSeconds: 60,
            maxWitnessBytes: 1 << 24,
            maxGuestCycles: 1 << 28,
        },
    };
    let d = DescriptorFields {
        program_id: [1; 32].into(),
        proof_system_id: [2; 32].into(),
        expected_journal_hash: [3; 32].into(),
        journal_fields: [4; 32].into(),
    };
    let ctx: BuilderContextV1 = build_context(743_111, [5; 20].into(), &d, &job);
    encode_context(&ctx)
}

fn evm_rpc(chain: u64) -> Capability {
    Capability {
        class: CLASS_EVM_RPC_V1,
        config: encode_evm_rpc_config(chain, true, METHOD_SET_STATE_READ, 300).into(),
    }
}

fn block_response(number: &str) -> Vec<u8> {
    format!(
        r#"{{"jsonrpc":"2.0","id":1,"result":{{"baseFeePerGas":"0x3b9aca00","difficulty":"0x0","extraData":"0x","gasLimit":"0x1c9c380","gasUsed":"0x0","hash":"{HASH}","logsBloom":"0x00","miner":"0x0000000000000000000000000000000000000000","nonce":"0x0000000000000000","number":"{number}","parentHash":"0x1111111111111111111111111111111111111111111111111111111111111111","timestamp":"0x6553f100","transactions":["0x2222222222222222222222222222222222222222222222222222222222222222"],"uncles":[],"withdrawals":[{{"address":"0x0000000000000000000000000000000000000001","amount":"0x1","index":"0x0","validatorIndex":"0x5"}}]}}}}"#
    )
    .into_bytes()
}

#[test]
fn the_example_passes_the_prepass_under_exactly_the_profile() {
    let wasm = example_wasm();
    let info = prepass(wasm, 16 << 20).unwrap_or_else(|e| panic!("the example fails the pre-pass: {e}"));
    assert!(info.initial_memory_bytes <= 2 << 20, "initial memory {}", info.initial_memory_bytes);
    // And a validator with exactly the profile, independently of the pre-pass's own checks.
    wasmparser::Validator::new_with_features(PROFILE_FEATURES).validate_all(wasm).unwrap();
}

#[test]
fn the_example_imports_only_hemiprove_builder_v1_functions() {
    let wasm = example_wasm();
    let mut imports = Vec::new();
    for payload in Parser::new(0).parse_all(wasm) {
        if let Payload::ImportSection(reader) = payload.unwrap() {
            for import in reader.into_imports() {
                let import = import.unwrap();
                assert!(matches!(import.ty, TypeRef::Func(_)), "{}::{} is not a function", import.module, import.name);
                imports.push((import.module.to_string(), import.name.to_string()));
            }
        }
    }
    assert!(!imports.is_empty());
    for (module, name) in &imports {
        assert_eq!(module, abi::MODULE);
        assert!(abi::IMPORTS.contains(&name.as_str()), "{name}");
    }
    // The pre-pass agrees, signatures included.
    let info = prepass(wasm, 16 << 20).unwrap();
    assert_eq!(info.imports, imports);
    // Everything the example uses: the SDK reads the context, fetches, reads the response, writes W
    // and logs.
    let mut names: Vec<_> = imports.iter().map(|(_, n)| n.as_str()).collect();
    names.sort();
    assert_eq!(names, ["fetch", "input_len", "input_read", "log", "response_read", "witness_write"]);
}

#[test]
fn the_example_writes_the_block_number_and_hash() {
    let o = run_full(
        example_wasm(),
        &context(vec![evm_rpc(8453)]),
        cfg(),
        vec![Reply::Result(FetchStatus::Ok, block_response("0x1406f40"))],
    );
    let log = String::from_utf8_lossy(&o.log);
    assert_eq!(o.code(), exit::OK, "log: {log}");
    let mut want = 0x1406f40u64.to_be_bytes().to_vec();
    want.extend_from_slice(&hex::decode(&HASH[2..]).unwrap());
    assert_eq!(o.w, want);
    assert_eq!(o.requests, vec![(0, REQUEST.to_vec())]);
    assert_eq!(o.summary.fetches, 1);
    assert_eq!(o.summary.fetch_bytes, block_response("0x1406f40").len() as u64);
    assert_eq!(o.summary.witness_bytes, 40);
    assert!(!o.summary.transient);
    assert!(o.summary.fuel_used > 0);
    // The context decoded as the miner encoded it.
    assert!(
        log.contains("latest-block: hemi chain 743111, capability 0 = evm-rpc/v1 chain 8453, 3 builder param bytes\n"),
        "{log}"
    );
    assert!(log.contains("latest-block: block 21000000\n"), "{log}");
}

#[test]
fn the_example_fails_cleanly() {
    let ctx = context(vec![evm_rpc(1)]);
    let cases: Vec<(&str, Vec<Reply>, &str)> = vec![
        ("denied", vec![Reply::Result(FetchStatus::Denied, vec![])], "builder failed: fetch denied"),
        ("exhausted", vec![Reply::Result(FetchStatus::Exhausted, vec![])], "builder failed: fetch budget exhausted"),
        (
            "rpc error",
            vec![Reply::Result(FetchStatus::Ok, br#"{"jsonrpc":"2.0","id":1,"error":{"code":-32000}}"#.to_vec())],
            "JSON-RPC error",
        ),
        ("not json", vec![Reply::Result(FetchStatus::Ok, b"<html>".to_vec())], "malformed JSON"),
        (
            "short hash",
            vec![Reply::Result(
                FetchStatus::Ok,
                br#"{"jsonrpc":"2.0","id":1,"result":{"number":"0x1","hash":"0x12"}}"#.to_vec(),
            )],
            "not 0x-prefixed hex",
        ),
    ];
    for (name, replies, want) in cases {
        let o = run_full(example_wasm(), &ctx, cfg(), replies);
        assert_eq!(o.code(), exit::NONZERO_RETURN, "{name}");
        assert!(String::from_utf8_lossy(&o.log).contains(want), "{name}: {}", String::from_utf8_lossy(&o.log));
        assert!(o.w.is_empty(), "{name}");
    }
    // Status 2 marks the run transient.
    let o = run_full(example_wasm(), &ctx, cfg(), vec![Reply::Result(FetchStatus::Failed, vec![])]);
    assert_eq!(o.code(), exit::NONZERO_RETURN);
    assert!(o.summary.transient);
    // Capability 0 of the wrong class: no fetch at all.
    let blob = Capability { class: CLASS_BLOB_V1, config: vec![0u8; 32].into() };
    let o = run_full(example_wasm(), &context(vec![blob]), cfg(), vec![]);
    assert_eq!(o.code(), exit::NONZERO_RETURN);
    assert!(o.requests.is_empty());
    // A W limit below 40 bytes.
    let mut c = cfg();
    c.max_witness_bytes = 39;
    let o = run_full(example_wasm(), &ctx, c, vec![Reply::Result(FetchStatus::Ok, block_response("0x1"))]);
    assert_eq!(o.code(), exit::WITNESS_TOO_LARGE);
    // Too little fuel, and too little memory for the module's own initial memory.
    let mut c = cfg();
    c.fuel = 1_000;
    assert_eq!(run_full(example_wasm(), &ctx, c, vec![]).code(), exit::FUEL);
    let mut c = cfg();
    c.memory_bytes = 64 << 10;
    assert_eq!(run_full(example_wasm(), &ctx, c, vec![]).code(), exit::INVALID_MODULE);
    // A malformed context: the SDK's decoder refuses it.
    let o = run_full(example_wasm(), b"\x01\x02", cfg(), vec![]);
    assert_eq!(o.code(), exit::NONZERO_RETURN);
    assert!(String::from_utf8_lossy(&o.log).contains("builder failed: context: malformed ABI encoding"));
}

#[test]
fn a_rust_panic_traps_after_logging_and_running_out_of_memory_is_memory() {
    let faults = built("faults");
    prepass(faults, 16 << 20).unwrap();
    let o = run_full(faults, &context_with(vec![evm_rpc(1)], vec![0]), cfg(), vec![]);
    assert_eq!(o.code(), exit::OK);

    let o = run_full(faults, &context_with(vec![evm_rpc(1)], vec![1]), cfg(), vec![]);
    assert_eq!(o.code(), exit::TRAP);
    let log = String::from_utf8_lossy(&o.log);
    assert!(log.contains("panic: ") && log.contains("faults: asked to panic"), "{log}");

    // Allocation fails once the clamp refuses memory.grow; Rust aborts (a trap) and the runner
    // reports MEMORY.
    let mut c = cfg();
    c.memory_bytes = 8 << 20;
    let o = run_full(faults, &context_with(vec![evm_rpc(1)], vec![2]), c, vec![]);
    assert_eq!(o.code(), exit::MEMORY, "{}", String::from_utf8_lossy(&o.log));
    assert!(String::from_utf8_lossy(&o.log).contains("faults: 5 MiB"));
}

#[test]
fn the_broker_vanishing_mid_fetch_is_internal() {
    let o = run_full(example_wasm(), &context(vec![evm_rpc(1)]), cfg(), vec![Reply::Close]);
    assert_eq!(o.code(), exit::INTERNAL);
}
