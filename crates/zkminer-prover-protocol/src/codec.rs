//! Length-prefixed bincode codec for worker IPC.
//!
//! Wire format: `[4-byte BE length][bincode payload]`
//! Max frame size: 256 MB (see [`MAX_FRAME_SIZE`]).

use serde::{de::DeserializeOwned, Serialize};
use std::io::{Read, Write};

use crate::types::MAX_FRAME_SIZE;

/// Errors from the framing codec.
#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("bincode error: {0}")]
    Bincode(#[from] bincode::Error),
    #[error("frame too large: {size} bytes (max {MAX_FRAME_SIZE})")]
    FrameTooLarge { size: u32 },
    #[error("unexpected EOF")]
    UnexpectedEof,
}

/// Write a length-prefixed bincode message. Always flushes to prevent deadlocks.
pub fn write_message<W: Write, T: Serialize>(writer: &mut W, msg: &T) -> Result<(), FrameError> {
    let payload = bincode::serialize(msg)?;
    let len = payload.len() as u32;
    if len > MAX_FRAME_SIZE {
        return Err(FrameError::FrameTooLarge { size: len });
    }
    writer.write_all(&len.to_be_bytes())?;
    writer.write_all(&payload)?;
    writer.flush()?;
    Ok(())
}

/// Read a length-prefixed bincode message.
pub fn read_message<R: Read, T: DeserializeOwned>(reader: &mut R) -> Result<T, FrameError> {
    let mut len_buf = [0u8; 4];
    match reader.read_exact(&mut len_buf) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
            return Err(FrameError::UnexpectedEof);
        }
        Err(e) => return Err(FrameError::Io(e)),
    }
    let len = u32::from_be_bytes(len_buf);
    if len > MAX_FRAME_SIZE {
        return Err(FrameError::FrameTooLarge { size: len });
    }
    let mut payload = vec![0u8; len as usize];
    reader.read_exact(&mut payload)?;
    let msg = bincode::deserialize(&payload)?;
    Ok(msg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{WorkerCommand, WorkerResponse, PROTOCOL_VERSION};
    use std::io::Cursor;

    #[test]
    fn round_trip_command() {
        let cmd = WorkerCommand::Hello {
            protocol_version: PROTOCOL_VERSION,
        };
        let mut buf = Vec::new();
        write_message(&mut buf, &cmd).unwrap();

        let mut cursor = Cursor::new(buf);
        let decoded: WorkerCommand = read_message(&mut cursor).unwrap();
        match decoded {
            WorkerCommand::Hello { protocol_version } => {
                assert_eq!(protocol_version, PROTOCOL_VERSION);
            }
            _ => panic!("wrong variant"),
        }
    }

    /// `wrap_secs` must survive the wire both measured and unmeasured.
    ///
    /// The codec is bincode, which is positional and cannot skip a field: a
    /// `#[serde(skip_serializing_if = "Option::is_none")]` — the natural way to keep JSON tidy —
    /// would make an unmeasured entry encode one field short and garble everything after it.
    #[test]
    fn a_benchmark_entry_round_trips_with_and_without_a_wrap() {
        for wrap in [Some(55.25), None] {
            let entry = crate::types::BenchmarkEntry {
                program_name: "chacha-mix".to_string(),
                prover_backend: "sp1".to_string(),
                cycles: 32_484_958,
                duration_secs: 8.5,
                throughput: 32_484_958.0 / 8.5,
                weight: 0.20,
                precompile: false,
                wrap_secs: wrap,
            };
            let resp = WorkerResponse::BenchmarkResult {
                results: vec![entry.clone(), entry],
            };
            let mut buf = Vec::new();
            write_message(&mut buf, &resp).unwrap();
            let decoded: WorkerResponse = read_message(&mut Cursor::new(buf)).unwrap();
            match decoded {
                WorkerResponse::BenchmarkResult { results } => {
                    assert_eq!(results.len(), 2);
                    for r in results {
                        assert_eq!(r.wrap_secs, wrap);
                        assert_eq!(r.duration_secs, 8.5, "a field after it must not shift");
                    }
                }
                _ => panic!("wrong variant"),
            }
        }
    }

    /// Why `PROTOCOL_VERSION` had to move when `wrap_secs` was added: a v3 worker's entry is one field
    /// short under bincode, so without the bump it would reach the decoder and fail mid-benchmark
    /// instead of being refused cleanly at the handshake.
    #[test]
    fn a_v3_benchmark_entry_does_not_decode_as_v4() {
        #[derive(serde::Serialize)]
        struct V3Entry {
            program_name: String,
            prover_backend: String,
            cycles: u64,
            duration_secs: f64,
            throughput: f64,
            weight: f64,
            precompile: bool,
        }
        let bytes = bincode::serialize(&V3Entry {
            program_name: "fibonacci".to_string(),
            prover_backend: "risc0".to_string(),
            cycles: 32_768,
            duration_secs: 0.42,
            throughput: 78_000.0,
            weight: 0.10,
            precompile: false,
        })
        .unwrap();
        assert!(
            bincode::deserialize::<crate::types::BenchmarkEntry>(&bytes).is_err(),
            "a v3 entry must NOT silently decode as v4; if it ever does, the version bump is moot"
        );
        assert!(PROTOCOL_VERSION >= 4);
    }

    /// v5 added `Warmup` / `WarmupDone`, appended so no older variant's index moved.
    #[test]
    fn warmup_round_trips() {
        let mut buf = Vec::new();
        write_message(&mut buf, &WorkerCommand::Warmup { request_id: 7 }).unwrap();
        match read_message::<_, WorkerCommand>(&mut Cursor::new(buf)).unwrap() {
            WorkerCommand::Warmup { request_id } => assert_eq!(request_id, 7),
            other => panic!("wrong variant: {other:?}"),
        }
        let resp = WorkerResponse::WarmupDone {
            request_id: 7,
            summary: "groth16 artifacts present".to_string(),
            groth16_helper: true,
        };
        let mut buf = Vec::new();
        write_message(&mut buf, &resp).unwrap();
        match read_message::<_, WorkerResponse>(&mut Cursor::new(buf)).unwrap() {
            WorkerResponse::WarmupDone {
                request_id,
                summary,
                groth16_helper,
            } => {
                assert_eq!(
                    (request_id, summary.as_str(), groth16_helper),
                    (7, "groth16 artifacts present", true)
                );
            }
            other => panic!("wrong variant: {other:?}"),
        }
        const _: () = assert!(PROTOCOL_VERSION >= 5);
    }

    /// v11 added `ProgramId` / `ProgramIdResult`, appended so no older variant's bincode index moved:
    /// a co-built host and worker agree either way, but the indices below are what a v10 frame used.
    #[test]
    fn program_id_round_trips_and_moves_no_older_variant() {
        let mut buf = Vec::new();
        let elf = vec![0x7f, b'E', b'L', b'F', 1, 2, 3];
        write_message(
            &mut buf,
            &WorkerCommand::ProgramId {
                request_id: 9,
                elf: elf.clone(),
            },
        )
        .unwrap();
        // Frame: 4-byte big-endian length, then bincode's u32 little-endian variant index.
        assert_eq!(&buf[4..8], &9u32.to_le_bytes(), "ProgramId is the 10th command");
        match read_message::<_, WorkerCommand>(&mut Cursor::new(buf)).unwrap() {
            WorkerCommand::ProgramId { request_id, elf: e } => {
                assert_eq!((request_id, e), (9, elf));
            }
            other => panic!("wrong variant: {other:?}"),
        }

        let id: [u8; 32] = std::array::from_fn(|i| i as u8);
        let mut buf = Vec::new();
        write_message(
            &mut buf,
            &WorkerResponse::ProgramIdResult {
                request_id: 9,
                program_id: id,
                duration_secs: 1.5,
            },
        )
        .unwrap();
        assert_eq!(&buf[4..8], &11u32.to_le_bytes(), "ProgramIdResult is the 12th response");
        match read_message::<_, WorkerResponse>(&mut Cursor::new(buf)).unwrap() {
            WorkerResponse::ProgramIdResult {
                request_id,
                program_id,
                duration_secs,
            } => assert_eq!((request_id, program_id, duration_secs), (9, id, 1.5)),
            other => panic!("wrong variant: {other:?}"),
        }

        // The variants a v10 peer knew keep their indices.
        let index = |cmd: &WorkerCommand| {
            let mut b = Vec::new();
            write_message(&mut b, cmd).unwrap();
            u32::from_le_bytes(b[4..8].try_into().unwrap())
        };
        assert_eq!(
            index(&WorkerCommand::Execute {
                request_id: 1,
                elf: vec![],
                input_data: vec![],
                program_id: None,
                po2: None,
            }),
            4
        );
        assert_eq!(index(&WorkerCommand::Warmup { request_id: 1 }), 8);
        const _: () = assert!(PROTOCOL_VERSION >= 11);
    }

    /// v11 also gave `ExecuteResult` its last field, `host_entropy_reads`: every value round-trips,
    /// `None` included (an unknown count, which a reader must not take for zero), and the fields
    /// before it keep their places.
    #[test]
    fn an_execute_result_carries_its_host_entropy_reads() {
        for reads in [None, Some(0), Some(1), Some(u64::MAX)] {
            let mut buf = Vec::new();
            write_message(
                &mut buf,
                &WorkerResponse::ExecuteResult {
                    request_id: 3,
                    cycles: 1 << 20,
                    duration_secs: 0.5,
                    journal_len: 2,
                    peak_host_bytes: 7,
                    journal: Some(vec![0xab, 0xcd]),
                    host_entropy_reads: reads,
                },
            )
            .unwrap();
            match read_message::<_, WorkerResponse>(&mut Cursor::new(buf)).unwrap() {
                WorkerResponse::ExecuteResult {
                    request_id,
                    cycles,
                    journal_len,
                    peak_host_bytes,
                    journal,
                    host_entropy_reads,
                    ..
                } => {
                    assert_eq!(
                        (request_id, cycles, journal_len, peak_host_bytes),
                        (3, 1 << 20, 2, 7)
                    );
                    assert_eq!(journal.as_deref(), Some(&[0xab, 0xcd][..]));
                    assert_eq!(host_entropy_reads, reads);
                }
                other => panic!("wrong variant: {other:?}"),
            }
        }
        const _: () = assert!(PROTOCOL_VERSION >= 11);
    }

    fn witness() -> crate::types::WitnessProve {
        crate::types::WitnessProve {
            input_path: "/retention/job/v1/w.bin".to_string(),
            prefix: (0..64).collect(),
            input_sha256: [0x11; 32],
            w_len: 1 << 20,
            expect_journal_sha256: [0x22; 32],
            segment_dir: "/segments/risc0-cuda-0".to_string(),
        }
    }

    /// v13 appended `witness` to `Prove`: it round-trips both ways, the fields before it keep their
    /// places (a `None` frame is a v12 frame plus one byte), and a v12 frame no longer decodes, which
    /// is why the version moved.
    #[test]
    fn a_witness_prove_round_trips_and_appends_last() {
        use crate::types::WitnessProve;
        for w in [None, Some(witness())] {
            let cmd = WorkerCommand::Prove {
                request_id: 5,
                elf: vec![0x7f, b'E'],
                input_data: vec![],
                po2: Some(19),
                program_id: Some([3u8; 32]),
                witness: w.clone(),
            };
            let mut buf = Vec::new();
            write_message(&mut buf, &cmd).unwrap();
            assert_eq!(
                &buf[4..8],
                &3u32.to_le_bytes(),
                "Prove is still the 4th command"
            );
            match read_message::<_, WorkerCommand>(&mut Cursor::new(buf)).unwrap() {
                WorkerCommand::Prove {
                    request_id,
                    po2,
                    program_id,
                    witness,
                    ..
                } => {
                    assert_eq!(
                        (request_id, po2, program_id),
                        (5, Some(19), Some([3u8; 32]))
                    );
                    assert_eq!(witness, w);
                }
                other => panic!("wrong variant: {other:?}"),
            }
        }

        #[derive(serde::Serialize)]
        enum V12Command {
            _Hello,
            _Capabilities,
            _Benchmark,
            Prove {
                request_id: u64,
                elf: Vec<u8>,
                input_data: Vec<u8>,
                po2: Option<u8>,
                program_id: Option<[u8; 32]>,
            },
        }
        let v12 = bincode::serialize(&V12Command::Prove {
            request_id: 5,
            elf: vec![1],
            input_data: vec![2],
            po2: None,
            program_id: None,
        })
        .unwrap();
        let v13 = bincode::serialize(&WorkerCommand::Prove {
            request_id: 5,
            elf: vec![1],
            input_data: vec![2],
            po2: None,
            program_id: None,
            witness: None,
        })
        .unwrap();
        assert_eq!(
            &v13[..v12.len()],
            &v12[..],
            "every earlier field keeps its place"
        );
        assert_eq!(
            &v13[v12.len()..],
            &[0u8],
            "and `witness: None` is one trailing byte"
        );
        assert!(
            bincode::deserialize::<WorkerCommand>(&v12).is_err(),
            "a v12 Prove must not decode as v13"
        );
        // The struct round-trips on its own too (the dispatcher clones it into the frame).
        let w: WitnessProve =
            bincode::deserialize(&bincode::serialize(&witness()).unwrap()).unwrap();
        assert_eq!(w, witness());
        const _: () = assert!(PROTOCOL_VERSION >= 13);
    }

    /// v13's `JournalDiverged` is appended after `SetupProgress`, and `InputMismatch` after
    /// `Internal`: no older index moved.
    #[test]
    fn journal_diverged_and_input_mismatch_are_appended() {
        use crate::types::{ErrorKind, GUEST_EXIT_PAUSED};
        let resp = WorkerResponse::JournalDiverged {
            request_id: 8,
            journal: vec![1, 2, 3],
            journal_len: 3,
            journal_sha256: [9u8; 32],
            exit_kind: GUEST_EXIT_PAUSED,
            exit_code: 7,
            cycles: 3 << 20,
        };
        let mut buf = Vec::new();
        write_message(&mut buf, &resp).unwrap();
        assert_eq!(
            &buf[4..8],
            &13u32.to_le_bytes(),
            "JournalDiverged is the 14th response"
        );
        match read_message::<_, WorkerResponse>(&mut Cursor::new(buf)).unwrap() {
            WorkerResponse::JournalDiverged {
                request_id,
                journal,
                journal_len,
                journal_sha256,
                exit_kind,
                exit_code,
                cycles,
            } => {
                assert_eq!((request_id, journal, journal_len), (8, vec![1, 2, 3], 3));
                assert_eq!(journal_sha256, [9u8; 32]);
                assert_eq!(
                    (exit_kind, exit_code, cycles),
                    (GUEST_EXIT_PAUSED, 7, 3 << 20)
                );
            }
            other => panic!("wrong variant: {other:?}"),
        }
        let index = |resp: &WorkerResponse| {
            let mut b = Vec::new();
            write_message(&mut b, resp).unwrap();
            u32::from_le_bytes(b[4..8].try_into().unwrap())
        };
        assert_eq!(
            index(&WorkerResponse::SetupProgress {
                request_id: 1,
                status: String::new(),
                done_bytes: None,
                total_bytes: None,
            }),
            12
        );

        let kind = |k: ErrorKind| bincode::serialize(&k).unwrap();
        assert_eq!(kind(ErrorKind::Internal), 5u32.to_le_bytes());
        assert_eq!(kind(ErrorKind::InputMismatch), 6u32.to_le_bytes());
        let mut buf = Vec::new();
        write_message(
            &mut buf,
            &WorkerResponse::Error {
                request_id: 4,
                kind: ErrorKind::InputMismatch,
                message: "sha256 mismatch".to_string(),
            },
        )
        .unwrap();
        assert_eq!(
            &buf[4..8],
            &8u32.to_le_bytes(),
            "Error is still the 9th response"
        );
        match read_message::<_, WorkerResponse>(&mut Cursor::new(buf)).unwrap() {
            WorkerResponse::Error {
                request_id, kind, ..
            } => {
                assert_eq!(request_id, 4);
                assert!(matches!(kind, ErrorKind::InputMismatch));
            }
            other => panic!("wrong variant: {other:?}"),
        }
    }

    /// The sandboxed execute's request and response are single frames of their own.
    #[test]
    fn a_witness_execute_request_and_response_round_trip() {
        use crate::types::{
            WitnessExecutePo2, WitnessExecuteRequest, WitnessExecuteResponse, GUEST_EXIT_HALTED,
        };
        let req = WitnessExecuteRequest {
            elf: vec![0x7f, b'E', b'L', b'F'],
            prefix: vec![],
            w_len: 12,
            input_sha256: [1; 32],
            sys_rand_seed: [2; 32],
            po2s: vec![16, 20, 22],
            keccak_po2: 17,
            max_cycles: Some(1 << 30),
        };
        let mut buf = Vec::new();
        write_message(&mut buf, &req).unwrap();
        let got: WitnessExecuteRequest = read_message(&mut Cursor::new(buf)).unwrap();
        assert_eq!(got, req);

        let po2 = |p: u8| WitnessExecutePo2 {
            po2: p,
            cycles: 1 << p,
            journal: vec![p; 8],
            journal_len: 8,
            journal_sha256: [p; 32],
            exit_kind: GUEST_EXIT_HALTED,
            exit_code: 0,
            segment_bytes: 4096,
            peak_host_bytes: 1 << 28,
        };
        let resp = WitnessExecuteResponse {
            image_id: [3; 32],
            results: vec![po2(16), po2(20)],
            sdk_version: "risc0-zkvm 3.1.0".to_string(),
            worker_version: "0.1.0".to_string(),
        };
        let mut buf = Vec::new();
        write_message(&mut buf, &resp).unwrap();
        let got: WitnessExecuteResponse = read_message(&mut Cursor::new(buf)).unwrap();
        assert_eq!(got, resp);
    }

    #[test]
    fn round_trip_response() {
        let resp = WorkerResponse::HelloAck {
            protocol_version: PROTOCOL_VERSION,
            backend: "risc0".to_string(),
            sdk_version: "risc0-zkvm 3.0.5".to_string(),
            worker_version: "0.1.0".to_string(),
        };
        let mut buf = Vec::new();
        write_message(&mut buf, &resp).unwrap();

        let mut cursor = Cursor::new(buf);
        let decoded: WorkerResponse = read_message(&mut cursor).unwrap();
        match decoded {
            WorkerResponse::HelloAck { backend, .. } => {
                assert_eq!(backend, "risc0");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn eof_returns_error() {
        let mut cursor = Cursor::new(Vec::<u8>::new());
        let result: Result<WorkerCommand, _> = read_message(&mut cursor);
        assert!(matches!(result, Err(FrameError::UnexpectedEof)));
    }

    #[test]
    fn frame_too_large_rejects_oversized_header() {
        // Verify that read_message rejects frames with a length header exceeding
        // MAX_FRAME_SIZE. We craft a header without allocating the full payload.
        let header = (MAX_FRAME_SIZE + 1).to_be_bytes();
        let mut data = Vec::new();
        data.extend_from_slice(&header);
        data.extend_from_slice(&[0u8; 100]); // small payload, doesn't matter
        let mut cursor = Cursor::new(data);
        let result: Result<WorkerCommand, _> = read_message(&mut cursor);
        assert!(matches!(result, Err(FrameError::FrameTooLarge { .. })));
    }

    #[test]
    fn multiple_messages() {
        let mut buf = Vec::new();
        let cmd1 = WorkerCommand::Capabilities;
        let cmd2 = WorkerCommand::Shutdown;
        write_message(&mut buf, &cmd1).unwrap();
        write_message(&mut buf, &cmd2).unwrap();

        let mut cursor = Cursor::new(buf);
        let d1: WorkerCommand = read_message(&mut cursor).unwrap();
        let d2: WorkerCommand = read_message(&mut cursor).unwrap();
        assert!(matches!(d1, WorkerCommand::Capabilities));
        assert!(matches!(d2, WorkerCommand::Shutdown));
    }
}
