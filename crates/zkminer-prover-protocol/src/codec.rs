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
