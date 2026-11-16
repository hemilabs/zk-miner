//! `fetch` and `response_read` against a fake broker on a `UnixStream` pair.

mod common;

use std::time::{Duration, Instant};

use common::*;
use zkminer_witness::abi::{pack_fetch, unpack_fetch};
use zkminer_witness::ipc::{self, exit, FetchStatus};

/// `$do_fetch (cap, ptr, len)`: fetches, emits the packed result (8 bytes), then copies up to 64
/// bytes of the held response to 2048 and emits the count (4 bytes) and those bytes.
const DO_FETCH: &str = r#"
  (func $do_fetch (param $cap i32) (param $ptr i32) (param $len i32) (local $n i32)
    (call $emit64 (call $fetch (local.get $cap) (local.get $ptr) (local.get $len)))
    (local.set $n (call $response_read (i32.const 0) (i32.const 2048) (i32.const 64)))
    (call $emit32 (local.get $n))
    (drop (call $witness_write (i32.const 2048) (local.get $n))))
"#;

/// Parses W written by `$do_fetch` calls.
fn fetch_records(mut w: &[u8]) -> Vec<(i64, Vec<u8>)> {
    let mut out = Vec::new();
    while !w.is_empty() {
        let packed = i64::from_le_bytes(w[..8].try_into().unwrap());
        let n = u32::from_le_bytes(w[8..12].try_into().unwrap()) as usize;
        out.push((packed, w[12..12 + n].to_vec()));
        w = &w[12 + n..];
    }
    out
}

fn fetch_module(calls: &str) -> Vec<u8> {
    module(&format!(
        r#"(data (i32.const 0) "req-0req-1req-2req-3")
        {DO_FETCH}
        (func (export "run") (result i32) {calls} (i32.const 0))"#
    ))
}

#[test]
fn statuses_0_1_2_3_round_trip() {
    let m = fetch_module(
        "(call $do_fetch (i32.const 0) (i32.const 0) (i32.const 5))
         (call $do_fetch (i32.const 1) (i32.const 5) (i32.const 5))
         (call $do_fetch (i32.const 2) (i32.const 10) (i32.const 5))
         (call $do_fetch (i32.const 3) (i32.const 15) (i32.const 5))",
    );
    let replies = vec![
        Reply::Result(FetchStatus::Ok, b"hello".to_vec()),
        Reply::Result(FetchStatus::Denied, vec![]),
        Reply::Result(FetchStatus::Failed, vec![]),
        Reply::Result(FetchStatus::Exhausted, vec![]),
    ];
    let o = run_full(&m, b"", cfg(), replies);
    assert_eq!(o.code(), exit::OK);
    let records = fetch_records(&o.w);
    assert_eq!(
        records,
        vec![
            (pack_fetch(0, 5), b"hello".to_vec()),
            (pack_fetch(1, 0), vec![]),
            (pack_fetch(2, 0), vec![]),
            (pack_fetch(3, 0), vec![]),
        ]
    );
    for (i, (packed, _)) in records.iter().enumerate() {
        assert_eq!(unpack_fetch(*packed).unwrap().0, i as u8);
    }
    assert_eq!(
        o.requests,
        vec![(0, b"req-0".to_vec()), (1, b"req-1".to_vec()), (2, b"req-2".to_vec()), (3, b"req-3".to_vec())]
    );
    assert_eq!(o.summary.fetches, 4);
    assert_eq!(o.summary.fetch_bytes, 5);
    assert!(o.summary.transient, "a status-2 fetch marks the run transient");
}

#[test]
fn not_transient_without_a_status_2() {
    let m = fetch_module("(call $do_fetch (i32.const 0) (i32.const 0) (i32.const 5)) (call $do_fetch (i32.const 0) (i32.const 0) (i32.const 5))");
    let replies = vec![Reply::Result(FetchStatus::Denied, vec![]), Reply::Result(FetchStatus::Exhausted, vec![])];
    let o = run_full(&m, b"", cfg(), replies);
    assert_eq!(o.code(), exit::OK);
    assert!(!o.summary.transient);
}

#[test]
fn a_new_fetch_replaces_the_held_response() {
    let body = r#"(data (i32.const 0) "ab")
        (func (export "run") (result i32)
          (call $emit64 (call $fetch (i32.const 0) (i32.const 0) (i32.const 2)))
          (call $emit64 (call $fetch (i32.const 0) (i32.const 0) (i32.const 2)))
          ;; the second response only: 2 bytes, then nothing at and past its end
          (call $emit32 (call $response_read (i32.const 0) (i32.const 4096) (i32.const 10)))
          (drop (call $witness_write (i32.const 4096) (i32.const 2)))
          (call $emit32 (call $response_read (i32.const 1) (i32.const 4096) (i32.const 10)))
          (call $emit32 (call $response_read (i32.const 2) (i32.const 4096) (i32.const 10)))
          (call $emit32 (call $response_read (i32.const 4) (i32.const -1) (i32.const 10)))
          ;; a denied fetch clears it
          (call $emit64 (call $fetch (i32.const 0) (i32.const 0) (i32.const 2)))
          (call $emit32 (call $response_read (i32.const 0) (i32.const 4096) (i32.const 10)))
          (i32.const 0))"#;
    let replies = vec![
        Reply::Result(FetchStatus::Ok, b"AAAA".to_vec()),
        Reply::Result(FetchStatus::Ok, b"BB".to_vec()),
        Reply::Result(FetchStatus::Denied, vec![]),
    ];
    let o = run_full(&module(body), b"", cfg(), replies);
    assert_eq!(o.code(), exit::OK);
    let mut want = Vec::new();
    want.extend_from_slice(&pack_fetch(0, 4).to_le_bytes());
    want.extend_from_slice(&pack_fetch(0, 2).to_le_bytes());
    want.extend_from_slice(&2i32.to_le_bytes());
    want.extend_from_slice(b"BB");
    want.extend_from_slice(&1i32.to_le_bytes());
    want.extend_from_slice(&0i32.to_le_bytes());
    want.extend_from_slice(&0i32.to_le_bytes());
    want.extend_from_slice(&pack_fetch(1, 0).to_le_bytes());
    want.extend_from_slice(&0i32.to_le_bytes());
    assert_eq!(o.w, want);
    assert_eq!(o.summary.fetch_bytes, 6);
}

#[test]
fn a_response_is_read_in_pieces_and_out_of_bounds_reads_trap() {
    let response: Vec<u8> = (0..=255u8).cycle().take(10_000).collect();
    let body = r#"(func (export "run") (result i32) (local $off i32) (local $n i32)
        (drop (call $fetch (i32.const 0) (i32.const 0) (i32.const 0)))
        (loop $l
          (local.set $n (call $response_read (local.get $off) (i32.const 4096) (i32.const 3000)))
          (drop (call $witness_write (i32.const 4096) (local.get $n)))
          (local.set $off (i32.add (local.get $off) (local.get $n)))
          (br_if $l (local.get $n)))
        (drop (call $response_read (i32.const 0) (i32.const 65000) (i32.const 1000)))
        (i32.const 0))"#;
    let o = run_full(&module(body), b"", cfg(), vec![Reply::Result(FetchStatus::Ok, response.clone())]);
    assert_eq!(o.code(), exit::TRAP, "the last read is out of bounds");
    assert_eq!(o.w, response);
}

#[test]
fn a_request_of_exactly_the_cap_reaches_the_broker() {
    let mut c = cfg();
    c.max_request_bytes = 100;
    let body = r#"(func (export "run") (result i32)
        (memory.fill (i32.const 0) (i32.const 0x7a) (i32.const 100))
        (call $emit64 (call $fetch (i32.const 7) (i32.const 0) (i32.const 100))) (i32.const 0))"#;
    let o = run_full(&module(body), b"", c, vec![Reply::Result(FetchStatus::Ok, vec![])]);
    assert_eq!(o.code(), exit::OK);
    assert_eq!(o.requests, vec![(7, vec![0x7a; 100])]);
    // A negative cap index travels as its u32 bit pattern; the broker judges it.
    let body = r#"(func (export "run") (result i32) (drop (call $fetch (i32.const -1) (i32.const 0) (i32.const 0))) (i32.const 0))"#;
    let o = run_full(&module(body), b"", c, vec![Reply::Result(FetchStatus::Denied, vec![])]);
    assert_eq!(o.requests, vec![(u32::MAX, vec![])]);
}

#[test]
fn a_broker_that_never_answers_hits_the_deadline_as_wall_clock() {
    let mut c = cfg();
    c.deadline = Instant::now() + Duration::from_millis(400);
    let m = fetch_module("(call $do_fetch (i32.const 0) (i32.const 0) (i32.const 5))");
    let o = run_full(&m, b"", c, vec![Reply::Silent]);
    assert_eq!(o.code(), exit::WALL_CLOCK);
    assert_eq!(o.summary.fetches, 1);
    assert!(o.elapsed >= Duration::from_millis(350), "{:?}", o.elapsed);
    assert!(
        o.elapsed < Duration::from_millis(400) + Duration::from_millis(400),
        "returns at the deadline, not the grace: {:?}",
        o.elapsed
    );
    assert_eq!(o.requests.len(), 1);
}

#[test]
fn fuel_does_not_advance_while_a_fetch_waits() {
    let m = fetch_module("(call $do_fetch (i32.const 0) (i32.const 0) (i32.const 5))");
    let quick = run_full(&m, b"", cfg(), vec![Reply::Result(FetchStatus::Ok, b"x".to_vec())]);
    let slow =
        run_full(&m, b"", cfg(), vec![Reply::Delayed(Duration::from_millis(300), FetchStatus::Ok, b"x".to_vec())]);
    assert_eq!((quick.code(), slow.code()), (exit::OK, exit::OK));
    assert!(slow.elapsed >= Duration::from_millis(300));
    assert_eq!(quick.summary.fuel_used, slow.summary.fuel_used);
}

#[test]
fn broker_protocol_failures_are_internal() {
    let m = fetch_module("(call $do_fetch (i32.const 0) (i32.const 0) (i32.const 5))");
    let mut c = cfg();
    c.max_response_bytes = 16;
    let cases = [
        ("closed", Reply::Close),
        ("wrong kind", Reply::Raw(ipc::KIND_FETCH, vec![0])),
        ("empty payload", Reply::Raw(ipc::KIND_FETCH_RESULT, vec![])),
        ("unknown status", Reply::Raw(ipc::KIND_FETCH_RESULT, vec![9])),
        ("over max_response_bytes", Reply::Result(FetchStatus::Ok, vec![0; 17])),
    ];
    for (name, reply) in cases {
        let o = run_full(&m, b"", c, vec![reply]);
        assert_eq!(o.code(), exit::INTERNAL, "{name}");
        assert!(String::from_utf8_lossy(&o.log).contains("[runner] internal"), "{name}");
    }
    // Exactly max_response_bytes is fine.
    let o = run_full(&m, b"", c, vec![Reply::Result(FetchStatus::Ok, vec![1; 16])]);
    assert_eq!(o.code(), exit::OK);
}
