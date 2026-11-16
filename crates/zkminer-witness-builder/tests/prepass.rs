//! Every pre-pass rejection, each just over its limit with the at-limit module accepted, and the
//! proposals outside the profile.

mod common;

use common::*;
use zkminer_witness::ipc::exit;
use zkminer_witness_builder::prepass::{
    COMPILE_BUDGET_NS, MAX_BR_TABLE_TARGETS, MAX_CONTROL_DEPTH, MAX_FUNCTIONS, MAX_FUNCTION_BODY_BYTES, MAX_LOCALS,
    MAX_MODULE_BYTES, MAX_TABLE_ELEMENTS, MAX_TYPES,
};
use zkminer_witness_builder::{prepass, prepass_with_caps, CompileCost, CostCaps, PrepassError};

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
    // `run` is one of them. The compile budget refuses far fewer (see `many_functions_and_locals`):
    // the structural limit alone is checked here.
    let funcs = |n: u64| wat_module(&"(func)".repeat(n as usize - 1));
    prepass_with_caps(&funcs(MAX_FUNCTIONS), CLAMP, &CostCaps::UNLIMITED).unwrap();
    let why = rejected(&funcs(MAX_FUNCTIONS + 1), CLAMP);
    assert!(why.contains("100001 functions (max 100000)"), "{why}");
}

#[test]
fn br_table_with_more_than_65520_targets() {
    let table = |n: u32| wat_module(&format!("(func (block (br_table {} 0 (i32.const 0))))", "0 ".repeat(n as usize)));
    assert_eq!(MAX_BR_TABLE_TARGETS, 65_520);
    accepted(&table(MAX_BR_TABLE_TARGETS), CLAMP);
    assert!(rejected(&table(MAX_BR_TABLE_TARGETS + 1), CLAMP).contains("br_table"));
}

#[test]
fn the_br_table_limit_is_wasmtimes_own() {
    // A `run` whose br_table has `n` targets, all but the last to the outer block.
    let table = |n: usize| {
        module(&format!(
            r#"(func (export "run") (result i32)
                (block $out (block $in (br_table {} $in (i32.const 7))) (return (i32.const 1)))
                (i32.const 0))"#,
            "$out ".repeat(n)
        ))
    };
    // At the limit: through the pre-pass, compiled and run end to end (index 7 goes to $out).
    let o = run_module(&table(65_520), cfg());
    assert_eq!(o.code(), exit::OK, "{}", String::from_utf8_lossy(&o.log));
    // One more: the pre-pass refuses it, and so would wasmtime, so the two agree.
    let o = run_module(&table(65_521), cfg());
    assert_eq!(o.code(), exit::INVALID_MODULE);
    assert!(String::from_utf8_lossy(&o.log).contains("br_table with 65521 targets"));
    let engine = zkminer_witness_builder::engine::engine().unwrap();
    let err = wasmtime::Module::from_binary(&engine, &table(65_521)).unwrap_err();
    assert!(format!("{err:#}").contains("br_table"), "{err:#}");
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

// The compile-cost budget (`zkminer_witness_builder::cost`): one test per bomb class from the runner
// review, each refused, next to the largest module of its class the pre-pass accepts. Only the
// pre-pass runs here: the modules at the edge each compile in ~2 s in a release build (the
// calibration table in `cost.rs`), far longer with this test build's unoptimized Cranelift.

/// `fns` functions, each with `locals` i32 locals all read inside `depth` nested loops.
fn nested_loops(fns: usize, locals: usize, depth: usize) -> Vec<u8> {
    let reads: String = (0..locals).map(|i| format!("(drop (local.get {i})) ")).collect();
    let f =
        format!("(func (local {}) {} {reads} {})", "i32 ".repeat(locals), "(loop ".repeat(depth), ")".repeat(depth));
    wat_module(&f.repeat(fns))
}

/// `fns` functions of `depth` nested `if`/`else`, each arm reading param 0.
fn nested_ifs(fns: usize, depth: usize) -> Vec<u8> {
    let f = format!(
        "(func (param i32) (result i32) local.get 0 {} {})",
        "if (result i32) local.get 0 ".repeat(depth),
        "else local.get 0 end ".repeat(depth)
    );
    wat_module(&f.repeat(fns))
}

/// `fns` functions of `joins` sequential `(block (br_if 0 …))` joins, then every one of `locals`
/// locals read.
fn joins(fns: usize, locals: usize, joins: usize) -> Vec<u8> {
    let reads: String = (0..locals).map(|i| format!("(drop (local.get {i})) ")).collect();
    let f = format!(
        "(func (local {}) {} {reads})",
        "i32 ".repeat(locals),
        "(block (br_if 0 (local.get 0))) ".repeat(joins)
    );
    wat_module(&f.repeat(fns))
}

/// `n` function types of `params` params each (the module's own `run` type adds one more).
fn types(n: usize, params: usize) -> Vec<u8> {
    let t = format!("(type (func (param {})))", "i64 ".repeat(params));
    wat_module(&t.repeat(n))
}

/// `n` empty functions with `locals` i32 locals each, plus `run`, encoded directly (as text, 100,000 ×
/// 4,096 locals would be 1.6 GB).
fn empty_functions(n: u32, locals: u32) -> Vec<u8> {
    fn leb(mut v: u32, out: &mut Vec<u8>) {
        loop {
            let b = (v & 0x7f) as u8;
            v >>= 7;
            out.push(if v == 0 { b } else { b | 0x80 });
            if v == 0 {
                break;
            }
        }
    }
    fn section(id: u8, body: Vec<u8>, out: &mut Vec<u8>) {
        out.push(id);
        leb(body.len() as u32, out);
        out.extend(body);
    }
    let mut m = b"\0asm\x01\0\0\0".to_vec();
    // Types: 0 = () -> i32 (run), 1 = () -> ().
    section(1, vec![2, 0x60, 0, 1, 0x7f, 0x60, 0, 0], &mut m);
    let mut funcs = Vec::new();
    leb(n + 1, &mut funcs);
    funcs.extend(std::iter::repeat_n(1u8, n as usize));
    funcs.push(0);
    section(3, funcs, &mut m);
    section(5, vec![1, 0, 1], &mut m);
    let mut exports = vec![2, 6];
    exports.extend(b"memory\x02\x00\x03run\x00");
    leb(n, &mut exports);
    section(7, exports, &mut m);
    let mut body = Vec::new();
    if locals == 0 {
        body.push(0);
    } else {
        body.push(1);
        leb(locals, &mut body);
        body.push(0x7f);
    }
    body.push(0x0b);
    let mut code = Vec::new();
    leb(n + 1, &mut code);
    for _ in 0..n {
        leb(body.len() as u32, &mut code);
        code.extend(&body);
    }
    code.extend([4, 0, 0x41, 0, 0x0b]);
    section(10, code, &mut m);
    m
}

fn cost_of(bytes: &[u8]) -> CompileCost {
    prepass_with_caps(bytes, CLAMP, &CostCaps::UNLIMITED).unwrap().cost
}

#[test]
fn nested_loops_over_many_locals() {
    // The review's 16.5 KB module: 4,096 locals read inside 64 loops (1.96 s, release); 20 of them
    // (39.5 s); 1,024 loops (30.7 s).
    for m in [nested_loops(1, 4_096, 64), nested_loops(20, 4_096, 64), nested_loops(1, 4_096, 1_024)] {
        assert!(rejected(&m, CLAMP).contains("over the budget"));
    }
    // 5,000 loops (156 s, 1.8 GiB): deeper than any function may nest.
    assert!(rejected(&nested_loops(1, 4_096, 5_000), CLAMP).contains("nesting deeper than 1024"));
    // The edge: 58 loops (1.78 s), and 1,024 locals in 945 loops (2.1 s).
    accepted(&nested_loops(1, 4_096, 58), CLAMP);
    assert!(rejected(&nested_loops(1, 4_096, 59), CLAMP).contains("over the budget"));
    accepted(&nested_loops(1, 1_024, 945), CLAMP);
    // And through the runner: refused before anything is compiled.
    let o = run_module(&nested_loops(1, 4_096, 64), cfg());
    assert_eq!(o.code(), exit::INVALID_MODULE);
    assert!(o.elapsed < std::time::Duration::from_secs(1), "{:?}", o.elapsed);
}

#[test]
fn deeply_nested_ifs() {
    // 32,000 nested if/else (7.6 s, 5.9 GiB).
    assert!(rejected(&nested_ifs(1, 32_000), CLAMP).contains("nesting deeper than 1024"));
    accepted(&nested_ifs(1, MAX_CONTROL_DEPTH as usize), CLAMP);
    assert!(rejected(&nested_ifs(1, MAX_CONTROL_DEPTH as usize + 1), CLAMP).contains("nesting deeper"));
    // At the depth cap, the budget bounds how many: 156 functions (1.95 s) but not 157.
    accepted(&nested_ifs(156, 1_024), CLAMP);
    assert!(rejected(&nested_ifs(157, 1_024), CLAMP).contains("control depth²"));
}

#[test]
fn joins_before_many_locals() {
    // 35,124 sequential joins, then 4,096 locals read (15.9 s, 3.9 GiB in one function).
    assert!(rejected(&joins(1, 4_096, 35_124), CLAMP).contains("branch targets × locals"));
    // The per-function memory cap (0.96 s, 315 MiB) …
    accepted(&joins(1, 1_024, 9_765), CLAMP);
    assert!(rejected(&joins(1, 1_024, 9_766), CLAMP).contains("a function with branch targets × locals"));
    // … and the budget across functions (1.75 s, 359 MiB).
    accepted(&joins(2, 256, 26_000), CLAMP);
    assert!(rejected(&joins(3, 256, 26_000), CLAMP).contains("over the budget"));
}

#[test]
fn many_functions_and_locals() {
    // 100,000 empty functions × 4,096 locals (37.5 s), and without the locals (7.7 s, 611 MiB).
    let empty = empty_functions;
    assert!(rejected(&empty(99_999, 4_096), CLAMP).contains("over the budget"));
    assert!(rejected(&empty(99_999, 0), CLAMP).contains("functions"));
    // With `run`: 24,999 functions (1.88 s) is the most.
    accepted(&empty(24_998, 0), CLAMP);
    assert!(rejected(&empty(24_999, 0), CLAMP).contains("over the budget"));
    // Loop-free functions with many locals are priced as if they had one loop.
    accepted(&empty(58, 4_096), CLAMP);
    assert!(rejected(&empty(60, 4_096), CLAMP).contains("over the budget"));
}

#[test]
fn function_types() {
    // 4,000 unused types × 1,000 params (59 s): no type may have more than 128 params + results.
    assert!(rejected(&types(1, 129), CLAMP).contains("function type with 129 params"));
    // (The review's 4,000 such types are refused at the first; four make the point.)
    assert!(rejected(&types(4, 1_000), CLAMP).contains("params and results (max 128)"));
    let results = wat_module(&format!("(type (func (param {}) (result i32)))", "i64 ".repeat(128)));
    assert!(rejected(&results, CLAMP).contains("129 params and results"));
    accepted(&types(1, 128), CLAMP);
    // 10,000 distinct types × 127 params (6.6 s): the budget allows 2,900 × 128 (1.89 s) …
    accepted(&types(2_899, 128), CLAMP);
    assert!(rejected(&types(2_950, 128), CLAMP).contains("type arity²"));
    // … and no module more than 10,000 types.
    accepted(&types(MAX_TYPES as usize - 1, 0), CLAMP);
    assert!(rejected(&types(MAX_TYPES as usize, 0), CLAMP).contains("function types (max 10000)"));
}

#[test]
fn one_budget_for_every_term() {
    // Each about 60% of the budget: fine alone, refused together.
    let loops = "(func (local i32 i32 i32 i32) (loop (loop (drop (local.get 3)))))";
    let half_loops = format!(
        "(func (local {}) {} (drop (local.get 0)) {})",
        "i32 ".repeat(4_096),
        "(loop ".repeat(35),
        ")".repeat(35)
    );
    let ifs = format!(
        "(func (param i32) (result i32) local.get 0 {} {})",
        "if (result i32) local.get 0 ".repeat(1_024),
        "else local.get 0 end ".repeat(1_024)
    );
    let half_ifs = ifs.repeat(95);
    let a = wat_module(&format!("{loops}{half_loops}"));
    let b = wat_module(&format!("{loops}{half_ifs}"));
    for m in [&a, &b] {
        let c = cost_of(m);
        assert!(c.estimate_ns() > COMPILE_BUDGET_NS / 2 && c.estimate_ns() < COMPILE_BUDGET_NS, "{c:?}");
        accepted(m, CLAMP);
    }
    let both = wat_module(&format!("{loops}{half_loops}{half_ifs}"));
    assert!(cost_of(&both).estimate_ns() > COMPILE_BUDGET_NS);
    assert!(rejected(&both, CLAMP).contains("over the budget"));
}

#[test]
fn the_cost_terms_are_counted_as_documented() {
    // Two params and three locals; a loop inside a block inside an if; a br, a br_if, a br_table of
    // two targets and a default, and the if: 1 + 1 + 3 + 1 = 6 branch targets.
    let m = wat_module(
        r#"(type $t (func (param i32 i64) (result f32)))
           (func (type $t) (local i32 i32) (local f64)
             (if (local.get 0) (then (block (loop
               (br_if 1 (local.get 0))
               (br_table 0 1 1 (local.get 0))
               (br 0)))))
             (f32.const 0))"#,
    );
    let c = cost_of(&m);
    // Types: run's () -> i32 and $t (arity 3).
    assert_eq!((c.types, c.type_arity_sq, c.max_type_arity), (2, 1 + 9, 3));
    // Functions: run (no locals) and this one (5 locals, depth 3, one loop).
    assert_eq!((c.functions, c.locals, c.max_function_locals), (2, 5, 5));
    assert_eq!((c.max_depth, c.max_loop_depth), (3, 1));
    assert_eq!(c.depth_sq, 9);
    assert_eq!(c.loop_locals_sq, 2 * 25);
    assert_eq!(c.branch_locals, 6 * 5);
    let w = zkminer_witness_builder::cost::weight::FUNCTION * 2
        + 5 * zkminer_witness_builder::cost::weight::LOCAL
        + 50 * zkminer_witness_builder::cost::weight::LOOP_LOCALS_SQ
        + 9 * zkminer_witness_builder::cost::weight::DEPTH_SQ
        + 30 * zkminer_witness_builder::cost::weight::BRANCH_LOCALS
        + 10 * zkminer_witness_builder::cost::weight::TYPE_ARITY_SQ;
    assert_eq!(c.estimate_ns(), w);
}
