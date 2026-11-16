//! Every exit class, and every host function's edge cases, from WAT modules.

mod common;

use std::time::{Duration, Instant};

use common::*;
use zkminer_witness::abi::{LOG_CAP_BYTES, W_CHUNK_BYTES};
use zkminer_witness::ipc::exit;
use zkminer_witness_builder::{run, RunnerIo, FUEL_PER_BYTE, PROFILE_FEATURES};

#[test]
fn engine_features_are_exactly_the_profile() {
    let engine = zkminer_witness_builder::engine::engine().unwrap();
    assert_eq!(engine.get_wasm_features(), PROFILE_FEATURES);
}

#[test]
fn ok_when_run_returns_zero() {
    let o = run_module(&module(r#"(func (export "run") (result i32) (i32.const 0))"#), cfg());
    assert_eq!(o.code(), exit::OK);
    assert!(o.summary.fuel_used > 0);
    assert_eq!((o.summary.fetches, o.summary.witness_bytes, o.summary.transient), (0, 0, false));
}

#[test]
fn nonzero_return() {
    let o = run_module(&module(r#"(func (export "run") (result i32) (i32.const 7))"#), cfg());
    assert_eq!(o.code(), exit::NONZERO_RETURN);
    let o = run_module(&module(r#"(func (export "run") (result i32) (i32.const -1))"#), cfg());
    assert_eq!(o.code(), exit::NONZERO_RETURN);
}

#[test]
fn trap() {
    let o = run_module(&module(r#"(func (export "run") (result i32) unreachable)"#), cfg());
    assert_eq!(o.code(), exit::TRAP);
    let o = run_module(&module(r#"(func (export "run") (result i32) (i32.div_u (i32.const 1) (i32.const 0)))"#), cfg());
    assert_eq!(o.code(), exit::TRAP);
    // Native stack exhaustion (max_wasm_stack) is a trap too.
    let o = run_module(&module(r#"(func $f (export "run") (result i32) (call $f))"#), cfg());
    assert_eq!(o.code(), exit::TRAP);
}

#[test]
fn trap_in_the_start_function() {
    let o = run_module(
        &module(r#"(func $s unreachable) (start $s) (func (export "run") (result i32) (i32.const 0))"#),
        cfg(),
    );
    assert_eq!(o.code(), exit::TRAP);
}

#[test]
fn memory_grow_beyond_the_clamp_fails_then_a_trap_is_memory() {
    let mut c = cfg();
    c.memory_bytes = 4 * 65_536;
    // Within the clamp: the old size; beyond it: -1, and the run goes on.
    let body = r#"(func (export "run") (result i32)
        (call $emit32 (memory.grow (i32.const 2)))
        (call $emit32 (memory.grow (i32.const 2)))
        (call $emit32 (memory.size))
        unreachable)"#;
    let o = run_module(&module(body), c);
    assert_eq!(o.w_i32s(), vec![1, -1, 3]);
    assert_eq!(o.code(), exit::MEMORY);

    // A denied growth alone does not fail a run that then succeeds.
    let body = r#"(func (export "run") (result i32) (drop (memory.grow (i32.const 100))) (i32.const 0))"#;
    assert_eq!(run_module(&module(body), c).code(), exit::OK);
    // Nor does it turn a non-zero return or fuel into MEMORY.
    let body = r#"(func (export "run") (result i32) (drop (memory.grow (i32.const 100))) (i32.const 3))"#;
    assert_eq!(run_module(&module(body), c).code(), exit::NONZERO_RETURN);
    // A host function's trap after a denied growth is MEMORY as well.
    let body = r#"(func (export "run") (result i32)
        (drop (memory.grow (i32.const 100)))
        (drop (call $witness_write (i32.const 65530) (i32.const 100)))
        (i32.const 0))"#;
    assert_eq!(run_module(&module(body), c).code(), exit::MEMORY);
    // The module's own declared maximum is a denial too.
    let o = run_module(
        &raw(&format!(
            r#"(module {PRELUDE} (memory (export "memory") 1 2)
                (func (export "run") (result i32) (drop (memory.grow (i32.const 2))) unreachable))"#
        )),
        c,
    );
    assert_eq!(o.code(), exit::MEMORY);
}

#[test]
fn fuel() {
    let mut c = cfg();
    c.fuel = 100_000;
    let o = run_module(&module(r#"(func (export "run") (result i32) (loop (br 0)) (i32.const 0))"#), c);
    assert_eq!(o.code(), exit::FUEL);
    assert_eq!(o.summary.fuel_used, 100_000);
    c.fuel = 0;
    let o = run_module(&module(r#"(func (export "run") (result i32) (i32.const 0))"#), c);
    assert_eq!(o.code(), exit::FUEL);
}

#[test]
fn an_infinite_loop_in_the_start_function_exhausts_fuel() {
    let mut c = cfg();
    c.fuel = 200_000;
    let body = r#"(func $s (loop (br 0))) (start $s) (func (export "run") (result i32) (i32.const 0))"#;
    let o = run_module(&module(body), c);
    assert_eq!(o.code(), exit::FUEL);
    assert_eq!(o.summary.fuel_used, 200_000);
}

#[test]
fn an_infinite_loop_with_huge_fuel_hits_the_wall_clock() {
    let mut c = cfg();
    c.fuel = u64::MAX;
    c.deadline = Instant::now() + Duration::from_millis(400);
    let o = run_module(&module(r#"(func (export "run") (result i32) (loop (br 0)) (i32.const 0))"#), c);
    assert_eq!(o.code(), exit::WALL_CLOCK);
    assert!(o.elapsed >= Duration::from_millis(350), "{:?}", o.elapsed);
    assert!(o.elapsed < Duration::from_millis(400) + Duration::from_secs(2), "{:?}", o.elapsed);

    // Also in a start function, and in a loop that only calls functions.
    c.deadline = Instant::now() + Duration::from_millis(300);
    let body = r#"(func $s (loop (br 0))) (start $s) (func (export "run") (result i32) (i32.const 0))"#;
    assert_eq!(run_module(&module(body), c).code(), exit::WALL_CLOCK);
}

#[test]
fn a_deadline_spent_before_instantiation_is_wall_clock() {
    let mut c = cfg();
    c.deadline = Instant::now();
    let o = run_module(&module(r#"(func (export "run") (result i32) (i32.const 0))"#), c);
    assert_eq!(o.code(), exit::WALL_CLOCK);
}

#[test]
fn witness_bytes_reach_the_sink_and_are_counted() {
    let body = r#"(data (i32.const 0) "hello, witness")
        (func (export "run") (result i32)
          (call $emit32 (call $witness_write (i32.const 0) (i32.const 14)))
          (call $emit32 (call $witness_write (i32.const 0) (i32.const 0)))
          (i32.const 0))"#;
    let o = run_module(&module(body), cfg());
    assert_eq!(o.code(), exit::OK);
    assert_eq!(&o.w[..14], b"hello, witness");
    assert_eq!(&o.w[14..], &[0, 0, 0, 0, 0, 0, 0, 0]);
    assert_eq!(o.summary.witness_bytes, 22);
}

#[test]
fn witness_over_the_limit_returns_1_and_fails_the_run() {
    let mut c = cfg();
    c.max_witness_bytes = 12;
    // 8 bytes fit; the next 8 do not (nothing of them is written); after that even 1 byte is
    // refused; the run still returns 0.
    let body = r#"(func (export "run") (result i32)
        (i64.store (i32.const 0) (i64.const 0x0807060504030201))
        (i32.store (i32.const 100) (call $witness_write (i32.const 0) (i32.const 8)))
        (i32.store (i32.const 104) (call $witness_write (i32.const 0) (i32.const 8)))
        (i32.store (i32.const 108) (call $witness_write (i32.const 0) (i32.const 1)))
        (if (i32.ne (i32.load (i32.const 100)) (i32.const 0)) (then unreachable))
        (if (i32.ne (i32.load (i32.const 104)) (i32.const 1)) (then unreachable))
        (if (i32.ne (i32.load (i32.const 108)) (i32.const 1)) (then unreachable))
        (i32.const 0))"#;
    let o = run_module(&module(body), c);
    assert_eq!(o.code(), exit::WITNESS_TOO_LARGE);
    assert_eq!(o.w, vec![1, 2, 3, 4, 5, 6, 7, 8]);
    assert_eq!(o.summary.witness_bytes, 8);

    // It overrides a trap or a non-zero return that follows.
    let body = r#"(func (export "run") (result i32)
        (drop (call $witness_write (i32.const 0) (i32.const 100))) unreachable)"#;
    assert_eq!(run_module(&module(body), c).code(), exit::WITNESS_TOO_LARGE);
}

#[test]
fn witness_len_over_the_cap_is_refused_before_memory_is_touched() {
    let mut c = cfg();
    c.max_witness_bytes = 100;
    // An out-of-bounds (even overflowing) pointer with a length over the cap: result 1, no trap.
    let body = r#"(func (export "run") (result i32)
        (if (i32.ne (call $witness_write (i32.const -16) (i32.const 1000)) (i32.const 1)) (then unreachable))
        (i32.const 0))"#;
    let o = run_module(&module(body), c);
    assert_eq!(o.code(), exit::WITNESS_TOO_LARGE);
    assert!(o.w.is_empty());
}

#[test]
fn witness_out_of_bounds_pointers_trap() {
    for (ptr, len) in [(65_530, 100), (-1, 2), (65_536, 1), (-16, 32)] {
        let body = format!(
            r#"(func (export "run") (result i32) (drop (call $witness_write (i32.const {ptr}) (i32.const {len}))) (i32.const 0))"#
        );
        let o = run_module(&module(&body), cfg());
        assert_eq!(o.code(), exit::TRAP, "ptr {ptr} len {len}");
        assert!(o.w.is_empty());
    }
    // The last byte of memory is in bounds; a zero-length write at the end is too.
    let body = r#"(func (export "run") (result i32)
        (drop (call $witness_write (i32.const 65535) (i32.const 1)))
        (drop (call $witness_write (i32.const 65536) (i32.const 0)))
        (i32.const 0))"#;
    assert_eq!(run_module(&module(body), cfg()).code(), exit::OK);
}

#[test]
fn witness_is_streamed_in_chunks_of_at_most_w_chunk_bytes() {
    let mut c = cfg();
    c.max_witness_bytes = 3 << 20;
    let len = (5 << 20) / 2;
    let body = format!(
        r#"(func (export "run") (result i32)
        (memory.fill (i32.const 0) (i32.const 0xab) (i32.const {len}))
        (if (call $witness_write (i32.const 0) (i32.const {len})) (then unreachable))
        (i32.const 0))"#
    );
    let o = run_full(&module_with_pages(48, &body), b"", c, vec![]);
    assert_eq!(o.code(), exit::OK);
    assert_eq!(o.w.len(), len);
    assert!(o.w.iter().all(|&b| b == 0xab));
    assert!(o.w_writes.iter().all(|&n| n <= W_CHUNK_BYTES), "{:?}", o.w_writes);
    assert_eq!(o.w_writes.len(), 3);
    assert_eq!(o.summary.witness_bytes, len as u64);
}

#[test]
fn host_copies_are_charged_fuel_per_byte() {
    let fuel_for = |n: u32| {
        let body = format!(
            r#"(func (export "run") (result i32) (drop (call $witness_write (i32.const 0) (i32.const {n}))) (i32.const 0))"#
        );
        let o = run_module(&module(&body), cfg());
        assert_eq!(o.code(), exit::OK);
        o.summary.fuel_used
    };
    assert_eq!(fuel_for(5_000) - fuel_for(1_000), 4_000 * FUEL_PER_BYTE);
    // And a copy the fuel cannot pay for stops with FUEL, before anything is written.
    let mut c = cfg();
    c.fuel = 30_000;
    let body = r#"(func (export "run") (result i32) (drop (call $witness_write (i32.const 0) (i32.const 60000))) (i32.const 0))"#;
    let o = run_module(&module(body), c);
    assert_eq!(o.code(), exit::FUEL);
    assert!(o.w.is_empty());
}

#[test]
fn input_len_and_input_read() {
    let context: Vec<u8> = (0..100u8).collect();
    let body = r#"(func (export "run") (result i32)
        (call $emit32 (call $input_len))
        ;; everything, into a 1000-byte buffer: 100
        (call $emit32 (call $input_read (i32.const 0) (i32.const 1000) (i32.const 1000)))
        (drop (call $witness_write (i32.const 1000) (i32.const 100)))
        ;; the tail from offset 90: 10
        (call $emit32 (call $input_read (i32.const 90) (i32.const 2000) (i32.const 50)))
        (drop (call $witness_write (i32.const 2000) (i32.const 10)))
        ;; a short read in the middle: exactly len
        (call $emit32 (call $input_read (i32.const 10) (i32.const 3000) (i32.const 3)))
        (drop (call $witness_write (i32.const 3000) (i32.const 3)))
        ;; at and past the end: 0, and the (out-of-bounds) pointer is never checked
        (call $emit32 (call $input_read (i32.const 100) (i32.const -1) (i32.const 10)))
        (call $emit32 (call $input_read (i32.const 5000) (i32.const 70000) (i32.const 10)))
        (call $emit32 (call $input_read (i32.const -1) (i32.const 0) (i32.const 10)))
        ;; len 0 inside the buffer: 0
        (call $emit32 (call $input_read (i32.const 5) (i32.const 0) (i32.const 0)))
        (i32.const 0))"#;
    let o = run_full(&module(body), &context, cfg(), vec![]);
    assert_eq!(o.code(), exit::OK);
    let w = &o.w;
    let at = |i: usize| i32::from_le_bytes(w[i..i + 4].try_into().unwrap());
    assert_eq!(at(0), 100);
    assert_eq!(at(4), 100);
    assert_eq!(&w[8..108], &context[..]);
    assert_eq!(at(108), 10);
    assert_eq!(&w[112..122], &context[90..]);
    assert_eq!(at(122), 3);
    assert_eq!(&w[126..129], &context[10..13]);
    assert_eq!([at(129), at(133), at(137), at(141)], [0, 0, 0, 0]);
    assert_eq!(w.len(), 145);
}

#[test]
fn input_read_out_of_bounds_traps() {
    let context = vec![7u8; 100];
    for (ptr, len) in [(65_530, 10), (-1, 2), (-4, 100)] {
        let body = format!(
            r#"(func (export "run") (result i32) (drop (call $input_read (i32.const 0) (i32.const {ptr}) (i32.const {len}))) (i32.const 0))"#
        );
        let o = run_full(&module(&body), &context, cfg(), vec![]);
        assert_eq!(o.code(), exit::TRAP, "ptr {ptr} len {len}");
    }
    // Only the bytes actually copied must be in bounds: 4 bytes are left from offset 96.
    let body = r#"(func (export "run") (result i32) (call $emit32 (call $input_read (i32.const 96) (i32.const 65532) (i32.const 1000))) (i32.const 0))"#;
    let o = run_full(&module(body), &context, cfg(), vec![]);
    assert_eq!(o.code(), exit::OK);
    assert_eq!(o.w_i32s(), vec![4]);
}

#[test]
fn response_read_before_any_fetch_is_empty() {
    let body = r#"(func (export "run") (result i32)
        (call $emit32 (call $response_read (i32.const 0) (i32.const 0) (i32.const 10)))
        (call $emit32 (call $response_read (i32.const 0) (i32.const -1) (i32.const -1)))
        (i32.const 0))"#;
    let o = run_module(&module(body), cfg());
    assert_eq!(o.code(), exit::OK);
    assert_eq!(o.w_i32s(), vec![0, 0]);
}

#[test]
fn log_keeps_at_most_log_cap_bytes_in_total() {
    // 100 calls of 1,000 bytes: the first 65,536 bytes are kept, the rest dropped. Once the budget is
    // spent, even an out-of-bounds pointer is dropped without a trap.
    let body = r#"(func (export "run") (result i32) (local $i i32)
        (memory.fill (i32.const 0) (i32.const 0x41) (i32.const 1000))
        (loop $l
          (call $log (i32.const 0) (i32.const 1000))
          (local.set $i (i32.add (local.get $i) (i32.const 1)))
          (br_if $l (i32.lt_u (local.get $i) (i32.const 100))))
        (call $log (i32.const -1) (i32.const 1000))
        (i32.const 0))"#;
    let o = run_module(&module(body), cfg());
    assert_eq!(o.code(), exit::OK);
    assert_eq!(o.log.len(), LOG_CAP_BYTES);
    assert!(o.log.iter().all(|&b| b == b'A'));
}

#[test]
fn log_out_of_bounds_within_the_budget_traps() {
    for (ptr, len) in [(65_530, 10), (-1, 2)] {
        let body = format!(
            r#"(func (export "run") (result i32) (call $log (i32.const {ptr}) (i32.const {len})) (i32.const 0))"#
        );
        assert_eq!(run_module(&module(&body), cfg()).code(), exit::TRAP, "ptr {ptr} len {len}");
    }
    // A length past the budget is cut to the budget first: only what is kept must be in bounds.
    let body = r#"(func (export "run") (result i32) (call $log (i32.const 0) (i32.const -1)) (i32.const 0))"#;
    let o = run_full(&module_with_pages(2, body), b"", cfg(), vec![]);
    assert_eq!(o.code(), exit::OK);
    assert_eq!(o.log.len(), LOG_CAP_BYTES);
}

#[test]
fn a_request_over_the_cap_traps_and_never_reaches_the_broker() {
    let mut c = cfg();
    c.max_request_bytes = 100;
    for ptr in [0, -1] {
        let body = format!(
            r#"(func (export "run") (result i32) (drop (call $fetch (i32.const 0) (i32.const {ptr}) (i32.const 101))) (i32.const 0))"#
        );
        let o = run_full(&module(&body), b"", c, vec![]);
        assert_eq!(o.code(), exit::TRAP);
        assert!(o.requests.is_empty());
        assert_eq!(o.summary.fetches, 0);
    }
    // The hard ceiling applies whatever the configuration says.
    c.max_request_bytes = u32::MAX;
    let body = r#"(func (export "run") (result i32) (drop (call $fetch (i32.const 0) (i32.const 0) (i32.const 65537))) (i32.const 0))"#;
    let o = run_full(&module_with_pages(2, body), b"", c, vec![]);
    assert_eq!(o.code(), exit::TRAP);
    assert!(o.requests.is_empty());
}

#[test]
fn a_request_out_of_bounds_traps_and_never_reaches_the_broker() {
    let body = r#"(func (export "run") (result i32) (drop (call $fetch (i32.const 0) (i32.const 65500) (i32.const 100))) (i32.const 0))"#;
    let o = run_full(&module(body), b"", cfg(), vec![]);
    assert_eq!(o.code(), exit::TRAP);
    assert!(o.requests.is_empty());
}

#[test]
fn internal_when_the_w_sink_fails() {
    let (broker, fake) = FakeBroker::spawn(vec![]);
    let log = SharedBuf::default();
    let body =
        r#"(func (export "run") (result i32) (drop (call $witness_write (i32.const 0) (i32.const 8))) (i32.const 0))"#;
    let s = run(&module(body), b"", &cfg(), RunnerIo { witness: FailingSink, broker, log: log.clone() });
    fake.finish();
    assert_eq!(s.exit_code, exit::INTERNAL);
    assert!(String::from_utf8_lossy(&log.take()).contains("[runner] internal: runner: W sink"));
}

#[test]
fn the_runner_explains_a_rejected_module_in_the_log() {
    let o = run_module(b"\0asm\x01\0\0\0garbage", cfg());
    assert_eq!(o.code(), exit::INVALID_MODULE);
    assert!(String::from_utf8_lossy(&o.log).starts_with("[runner] invalid module:"));
}

// Imports and exports.

#[test]
fn unknown_imports() {
    let cases = [
        r#"(import "wasi_snapshot_preview1" "fd_write" (func (param i32 i32 i32 i32) (result i32)))"#,
        r#"(import "env" "input_len" (func (result i32)))"#,
        r#"(import "hemiprove_builder_v1" "clock" (func (result i64)))"#,
        r#"(import "hemiprove_builder_v2" "log" (func (param i32 i32)))"#,
        // Wrong signatures.
        r#"(import "hemiprove_builder_v1" "fetch" (func (param i32 i32 i32) (result i32)))"#,
        r#"(import "hemiprove_builder_v1" "log" (func (param i32 i32) (result i32)))"#,
        r#"(import "hemiprove_builder_v1" "input_len" (func (result i64)))"#,
        r#"(import "hemiprove_builder_v1" "witness_write" (func (param i64 i32) (result i32)))"#,
        // Right name, not a function.
        r#"(import "hemiprove_builder_v1" "memory" (memory 1))"#,
        r#"(import "hemiprove_builder_v1" "log" (global i32))"#,
        r#"(import "hemiprove_builder_v1" "log" (table 1 funcref))"#,
    ];
    for import in cases {
        let m = raw(&format!(
            r#"(module {import} (memory (export "memory") 1) (func (export "run") (result i32) (i32.const 0)))"#
        ));
        let o = run_module(&m, cfg());
        assert_eq!(o.code(), exit::UNKNOWN_IMPORT, "{import}");
        assert!(String::from_utf8_lossy(&o.log).contains("unknown import"), "{import}");
    }
}

#[test]
fn every_abi_import_with_its_exact_signature_is_accepted_even_twice() {
    let m = raw(&format!(
        r#"(module (import "hemiprove_builder_v1" "log" (func $log2 (param i32 i32)))
            {PRELUDE}
            (memory (export "memory") 1) (func (export "run") (result i32) (i32.const 0)))"#
    ));
    assert_eq!(run_module(&m, cfg()).code(), exit::OK);
}

#[test]
fn missing_or_mistyped_exports_are_invalid() {
    let cases = [
        r#"(module (memory 1) (func (export "run") (result i32) (i32.const 0)))"#,
        r#"(module (func (export "run") (result i32) (i32.const 0)))"#,
        r#"(module (memory (export "memory") 1))"#,
        r#"(module (memory (export "memory") 1) (func (export "run") (result i64) (i64.const 0)))"#,
        r#"(module (memory (export "memory") 1) (func (export "run") (param i32) (result i32) (i32.const 0)))"#,
        r#"(module (memory (export "memory") 1) (func (export "run")))"#,
        r#"(module (memory (export "mem") 1) (func (export "memory") (result i32) (i32.const 0)) (func (export "run") (result i32) (i32.const 0)))"#,
        r#"(module (memory (export "memory") 1) (global (export "run") i32 (i32.const 0)))"#,
    ];
    for wat in cases {
        assert_eq!(run_module(&raw(wat), cfg()).code(), exit::INVALID_MODULE, "{wat}");
    }
}

#[test]
fn other_exports_are_tolerated() {
    // What a Rust cdylib exports besides `memory` and `run`, and a few more.
    let m = raw(r#"(module (memory (export "memory") 1) (table (export "tbl") 1 funcref)
            (global (export "__heap_base") i32 (i32.const 1024)) (global (export "__data_end") i32 (i32.const 1024))
            (func (export "run") (result i32) (i32.const 0)) (func (export "other") (param i64)))"#);
    assert_eq!(run_module(&m, cfg()).code(), exit::OK);
}
