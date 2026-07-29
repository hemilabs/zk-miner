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
