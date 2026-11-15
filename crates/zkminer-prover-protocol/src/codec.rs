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
                power_state: None,
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

    fn v12_entry(
        power_state: Option<crate::types::BenchPowerState>,
    ) -> crate::types::BenchmarkEntry {
        crate::types::BenchmarkEntry {
            program_name: "memory-merkle".to_string(),
            prover_backend: "risc0".to_string(),
            cycles: 6_291_456,
            duration_secs: 8.7,
            throughput: 6_291_456.0 / 8.7,
            weight: 0.15,
            precompile: true,
            wrap_secs: Some(1.5),
            power_state,
        }
    }

    /// v12: `power_state` round-trips in every shape (unread, all unknown, full, reduced), in a
    /// progress frame and a final result, and no field before it moves.
    #[test]
    fn a_benchmark_entry_carries_its_power_state() {
        use crate::types::BenchPowerState;
        let full = BenchPowerState {
            low_power_mode: Some(false),
            on_battery: Some(false),
            thermal: Some(0),
        };
        let lpm = BenchPowerState {
            low_power_mode: Some(true),
            ..full
        };
        for ps in [
            None,
            Some(BenchPowerState::default()),
            Some(full),
            Some(lpm),
        ] {
            let mut buf = Vec::new();
            write_message(
                &mut buf,
                &WorkerResponse::BenchmarkProgress {
                    entry: v12_entry(ps),
                    program_index: 5,
                    total_programs: 6,
                },
            )
            .unwrap();
            write_message(
                &mut buf,
                &WorkerResponse::BenchmarkResult {
                    results: vec![v12_entry(ps), v12_entry(None)],
                },
            )
            .unwrap();
            let mut c = Cursor::new(buf);
            match read_message::<_, WorkerResponse>(&mut c).unwrap() {
                WorkerResponse::BenchmarkProgress {
                    entry,
                    program_index,
                    total_programs,
                } => {
                    assert_eq!(entry.power_state, ps);
                    assert_eq!(
                        entry.wrap_secs,
                        Some(1.5),
                        "a field before it must not shift"
                    );
                    assert_eq!((program_index, total_programs), (5, 6));
                }
                other => panic!("wrong variant: {other:?}"),
            }
            match read_message::<_, WorkerResponse>(&mut c).unwrap() {
                WorkerResponse::BenchmarkResult { results } => {
                    assert_eq!(results[0].power_state, ps);
                    assert_eq!(results[1].power_state, None);
                    assert_eq!(results[1].duration_secs, 8.7);
                }
                other => panic!("wrong variant: {other:?}"),
            }
        }
        assert_eq!(lpm.reduced().as_deref(), Some("Low Power Mode"));
        assert_eq!(full.reduced(), None);
        assert_eq!(
            BenchPowerState::default().reduced(),
            None,
            "unknown is not reduced"
        );
        const _: () = assert!(PROTOCOL_VERSION >= 12);
    }

    /// The old-version side of v12: a v11 worker's entry (no `power_state`) does not decode as a
    /// v12 one, alone or inside its progress frame, so it can only be refused, never misread. What
    /// a v11 worker sends first, its `HelloAck`, still decodes, which is what lets the host read its
    /// version and refuse it at the handshake (`worker.rs`: "Protocol version mismatch").
    #[test]
    fn a_v11_benchmark_entry_does_not_decode_as_v12_but_its_hello_does() {
        #[derive(serde::Serialize)]
        struct V11Entry {
            program_name: String,
            prover_backend: String,
            cycles: u64,
            duration_secs: f64,
            throughput: f64,
            weight: f64,
            precompile: bool,
            wrap_secs: Option<f64>,
        }
        #[derive(serde::Serialize)]
        enum V11Response {
            #[allow(dead_code)]
            HelloAck {
                protocol_version: u32,
                backend: String,
                sdk_version: String,
                worker_version: String,
            },
            #[allow(dead_code)]
            CapabilitiesReport {
                backend: String,
                version: String,
                supported_benchmarks: Vec<String>,
                gpu_available: bool,
                gpu_name: Option<String>,
            },
            #[allow(dead_code)]
            BenchmarkResult { results: Vec<V11Entry> },
            BenchmarkProgress {
                entry: V11Entry,
                program_index: u32,
                total_programs: u32,
            },
        }
        let v11 = || V11Entry {
            program_name: "fibonacci".to_string(),
            prover_backend: "risc0".to_string(),
            cycles: 1 << 20,
            duration_secs: 2.0,
            throughput: (1u64 << 20) as f64 / 2.0,
            weight: 0.1,
            precompile: false,
            wrap_secs: Some(1.4),
        };
        let bytes = bincode::serialize(&v11()).unwrap();
        assert!(
            bincode::deserialize::<crate::types::BenchmarkEntry>(&bytes).is_err(),
            "a v11 entry must NOT silently decode as v12"
        );
        // The last program's progress frame is the case that could have been misread: nothing
        // follows it in the frame for the missing field to swallow.
        let progress = bincode::serialize(&V11Response::BenchmarkProgress {
            entry: v11(),
            program_index: 6,
            total_programs: 6,
        })
        .unwrap();
        let mut framed = (progress.len() as u32).to_be_bytes().to_vec();
        framed.extend_from_slice(&progress);
        assert!(read_message::<_, WorkerResponse>(&mut Cursor::new(framed)).is_err());
        // A v11 HelloAck is unchanged in v12.
        let hello = bincode::serialize(&V11Response::HelloAck {
            protocol_version: 11,
            backend: "risc0".to_string(),
            sdk_version: "risc0-zkvm 3.0.5".to_string(),
            worker_version: "0.1.0".to_string(),
        })
        .unwrap();
        let mut framed = (hello.len() as u32).to_be_bytes().to_vec();
        framed.extend_from_slice(&hello);
        match read_message::<_, WorkerResponse>(&mut Cursor::new(framed)).unwrap() {
            WorkerResponse::HelloAck {
                protocol_version, ..
            } => assert_eq!(protocol_version, 11),
            other => panic!("wrong variant: {other:?}"),
        }
        assert_ne!(
            PROTOCOL_VERSION, 11,
            "the bump is what refuses the v11 worker"
        );
    }

    #[test]
    fn the_worse_power_reading_wins() {
        use crate::types::BenchPowerState as P;
        let full = P {
            low_power_mode: Some(false),
            on_battery: Some(false),
            thermal: Some(1),
        };
        let hot = P {
            thermal: Some(2),
            ..full
        };
        assert_eq!(full.merge(hot), hot);
        assert_eq!(hot.merge(full), hot);
        assert_eq!(hot.reduced().as_deref(), Some("thermal serious"));
        assert_eq!(full.reduced(), None, "fair is normal under load");
        let battery = P {
            on_battery: Some(true),
            ..P::default()
        };
        let m = full.merge(battery);
        assert_eq!(
            (m.low_power_mode, m.on_battery, m.thermal),
            (Some(false), Some(true), Some(1))
        );
        assert_eq!(P::default().merge(P::default()), P::default());
        let crit = P {
            thermal: Some(3),
            low_power_mode: Some(true),
            on_battery: Some(true),
        };
        assert_eq!(
            crit.reduced().as_deref(),
            Some("Low Power Mode, on battery, thermal critical")
        );
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
        assert_eq!(
            &buf[4..8],
            &9u32.to_le_bytes(),
            "ProgramId is the 10th command"
        );
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
        assert_eq!(
            &buf[4..8],
            &11u32.to_le_bytes(),
            "ProgramIdResult is the 12th response"
        );
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
