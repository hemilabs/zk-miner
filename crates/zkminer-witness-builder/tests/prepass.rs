//! Every pre-pass rejection, each just over its limit with the at-limit module accepted, and the
//! proposals outside the profile.

mod common;

use common::*;
use zkminer_witness::ipc::exit;
use zkminer_witness_builder::prepass::{
    MAX_BR_TABLE_TARGETS, MAX_FUNCTIONS, MAX_FUNCTION_BODY_BYTES, MAX_LOCALS, MAX_MODULE_BYTES, MAX_TABLE_ELEMENTS,
};
use zkminer_witness_builder::{prepass, PrepassError};

const RUN: &str = r#"(func (export "run") (result i32) (i32.const 0))"#;
const CLAMP: u64 = 16 << 20;

fn wat_module(items: &str) -> Vec<u8> {
    raw(&format!(r#"(module (memory (export "memory") 1) {RUN} {items})"#))
}

fn rejected(bytes: &[u8], clamp: u64) -> String {
    match prepass(bytes, clamp) {
        Err(PrepassError::Invalid(why)) => why,
        other => panic!("expected an invalid module, got {other:?}"),
    }
}

fn accepted(bytes: &[u8], clamp: u64) {
    prepass(bytes, clamp).unwrap_or_else(|e| panic!("expected acceptance, got {e}"));
}

/// A function body of exactly `size` encoded bytes: `size = 1 (local decl count) + nops + 1 (end)`.
fn body_of(size: usize) -> Vec<u8> {
    let nops = "nop ".repeat(size - 2);
    wat_module(&format!("(func {nops})"))
}

#[test]
fn function_bodies_over_256_kib() {
    accepted(&body_of(MAX_FUNCTION_BODY_BYTES), CLAMP);
    let why = rejected(&body_of(MAX_FUNCTION_BODY_BYTES + 1), CLAMP);
    assert!(why.contains("function body"), "{why}");
    // And through `run`, as INVALID_MODULE.
    assert_eq!(run_module(&body_of(MAX_FUNCTION_BODY_BYTES + 1), cfg()).code(), exit::INVALID_MODULE);
}

#[test]
fn more_than_4096_locals() {
    let locals = |n: u64| wat_module(&format!("(func {})", "(local i32) ".repeat(n as usize)));
    accepted(&locals(MAX_LOCALS), CLAMP);
    assert!(rejected(&locals(MAX_LOCALS + 1), CLAMP).contains("locals"));
    // Split over several declarations of different types.
    let mixed = wat_module(&format!("(func {} {})", "(local i64) ".repeat(2048), "(local f32) ".repeat(2049)));
    assert!(rejected(&mixed, CLAMP).contains("locals"));
}

#[test]
fn more_than_100000_functions() {
    // `run` is one of them.
    let funcs = |n: u64| wat_module(&"(func)".repeat(n as usize - 1));
    accepted(&funcs(MAX_FUNCTIONS), CLAMP);
    assert!(rejected(&funcs(MAX_FUNCTIONS + 1), CLAMP).contains("functions"));
}

#[test]
fn br_table_with_more_than_65536_targets() {
    let table = |n: u32| wat_module(&format!("(func (block (br_table {} 0 (i32.const 0))))", "0 ".repeat(n as usize)));
    accepted(&table(MAX_BR_TABLE_TARGETS), CLAMP);
    assert!(rejected(&table(MAX_BR_TABLE_TARGETS + 1), CLAMP).contains("br_table"));
}

#[test]
fn more_than_one_memory_or_table() {
    let two_memories = raw(&format!(r#"(module (memory (export "memory") 1) (memory 1) {RUN})"#));
    rejected(&two_memories, CLAMP);
    let two_tables = wat_module("(table 1 funcref) (table 1 funcref)");
    assert!(rejected(&two_tables, CLAMP).contains("more than one table"));
    accepted(&wat_module("(table 1 funcref)"), CLAMP);
}

#[test]
fn memory64() {
    rejected(&raw(&format!(r#"(module (memory (export "memory") i64 1) {RUN})"#)), CLAMP);
}

#[test]
fn shared_memory() {
    rejected(&raw(&format!(r#"(module (memory (export "memory") 1 1 shared) {RUN})"#)), CLAMP);
}

#[test]
fn initial_memory_above_the_clamp() {
    let pages = |n: u32| raw(&format!(r#"(module (memory (export "memory") {n}) {RUN})"#));
    accepted(&pages(16), 16 * 65_536);
    assert!(rejected(&pages(17), 16 * 65_536).contains("initial memory"));
    // The clamp is whole pages: 16 pages and a byte still only allows 16.
    let mut c = cfg();
    c.memory_bytes = 16 * 65_536 + 1;
    assert_eq!(run_module(&pages(17), c).code(), exit::INVALID_MODULE);
    assert_eq!(run_module(&pages(16), c).code(), exit::OK);
}

#[test]
fn oversized_data_segments() {
    let clamp = 65_536;
    let seg = |n: usize| format!(r#"(data (i32.const 0) "{}")"#, "x".repeat(n));
    accepted(&wat_module(&seg(65_536)), clamp);
    assert!(rejected(&wat_module(&seg(65_537)), clamp).contains("data"));
    // In total, across segments (passive ones included).
    let two = format!(r#"{} (data "{}")"#, seg(40_000), "y".repeat(30_000));
    assert!(rejected(&wat_module(&two), clamp).contains("data"));
}

#[test]
fn oversized_element_segments_and_tables() {
    let elems = |n: u64| {
        wat_module(&format!(
            "(table {MAX_TABLE_ELEMENTS} funcref) (func $f) (elem (i32.const 0) func {})",
            "$f ".repeat(n as usize)
        ))
    };
    accepted(&elems(MAX_TABLE_ELEMENTS), CLAMP);
    assert!(rejected(&elems(MAX_TABLE_ELEMENTS + 1), CLAMP).contains("element"));
    // Passive segments count too, in total.
    let passive =
        wat_module(&format!("(func $f) (elem func {}) (elem func {})", "$f ".repeat(40_000), "$f ".repeat(30_000)));
    assert!(rejected(&passive, CLAMP).contains("element"));
    let big_table = wat_module(&format!("(table {} funcref)", MAX_TABLE_ELEMENTS + 1));
    assert!(rejected(&big_table, CLAMP).contains("table of"));
}

#[test]
fn table_growth_is_capped_at_65536_elements() {
    let m = module(
        r#"(table 1 funcref)
        (func (export "run") (result i32)
          (call $emit32 (table.grow (ref.null func) (i32.const 65535)))
          (call $emit32 (table.grow (ref.null func) (i32.const 1)))
          (i32.const 0))"#,
    );
    let o = run_module(&m, cfg());
    assert_eq!(o.code(), exit::OK);
    assert_eq!(o.w_i32s(), vec![1, -1]);
}

#[test]
fn proposals_outside_the_profile() {
    let cases = [
        ("simd", r#"(func (drop (v128.const i64x2 0 0)))"#),
        ("simd type", r#"(func (param v128))"#),
        ("relaxed simd", r#"(func (drop (i8x16.relaxed_swizzle (v128.const i64x2 0 0) (v128.const i64x2 0 0))))"#),
        ("externref", r#"(func (param externref))"#),
        ("externref table", r#"(table 1 externref)"#),
        ("tail call", r#"(func $t (return_call $t))"#),
        ("atomics", r#"(func (drop (i32.atomic.load (i32.const 0))))"#),
        ("exceptions", r#"(tag $e) (func (throw $e))"#),
        ("extended const", r#"(global i32 (i32.add (i32.const 1) (i32.const 2)))"#),
        ("function references", r#"(type $t (func)) (func (param (ref $t)))"#),
        ("gc", r#"(type $s (struct (field i32)))"#),
        ("wide arithmetic", r#"(func (i64.add128 (i64.const 0) (i64.const 0) (i64.const 0) (i64.const 0)) drop drop)"#),
    ];
    for (name, items) in cases {
        let m = wat_module(items);
        let why = rejected(&m, CLAMP);
        assert_eq!(run_module(&m, cfg()).code(), exit::INVALID_MODULE, "{name}: {why}");
    }
}

#[test]
fn features_inside_the_profile() {
    let cases = [
        ("sign extension", r#"(func (drop (i32.extend8_s (i32.const 1))))"#),
        ("saturating float-to-int", r#"(func (drop (i32.trunc_sat_f32_s (f32.const 1))))"#),
        (
            "bulk memory",
            r#"(func (memory.copy (i32.const 0) (i32.const 1) (i32.const 2)) (memory.fill (i32.const 0) (i32.const 0) (i32.const 1)))"#,
        ),
        ("multi-value", r#"(func (result i32 i64) (i32.const 0) (i64.const 0))"#),
        ("mutable global", r#"(global (mut i32) (i32.const 0))"#),
        (
            "funcref table ops",
            r#"(table 1 funcref) (func (table.set (i32.const 0) (ref.null func)) (drop (table.size)))"#,
        ),
        ("floats", r#"(func (drop (f64.sqrt (f64.const 2))))"#),
    ];
    for (name, items) in cases {
        prepass(&wat_module(items), CLAMP).unwrap_or_else(|e| panic!("{name}: {e}"));
    }
}

#[test]
fn malformed_modules() {
    for bytes in [&b""[..], b"\0asm", b"\0asm\x01\0\0\0\x01", b"not wasm at all", b"\0asm\x0d\0\x01\0"] {
        assert!(matches!(prepass(bytes, CLAMP), Err(PrepassError::Invalid(_))), "{bytes:?}");
        assert_eq!(run_module(bytes, cfg()).code(), exit::INVALID_MODULE);
    }
}

#[test]
fn a_component_is_rejected() {
    let component = wat::parse_str("(component)").unwrap();
    rejected(&component, CLAMP);
}

#[test]
fn modules_over_the_artifact_size_are_rejected_before_parsing() {
    let mut big = wat_module("");
    big.resize(MAX_MODULE_BYTES + 1, 0);
    assert!(rejected(&big, CLAMP).contains("module of"));
}

#[test]
fn unknown_imports_are_reported_before_later_invalid_bodies() {
    let m = raw(&format!(
        r#"(module (import "env" "x" (func)) (memory (export "memory") 1) {RUN} (func (drop (v128.const i64x2 0 0))))"#
    ));
    assert!(matches!(prepass(&m, CLAMP), Err(PrepassError::UnknownImport(_))));
}
