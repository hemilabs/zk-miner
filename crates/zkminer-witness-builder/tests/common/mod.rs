//! Shared helpers: WAT modules with the ABI v1 imports, in-memory sinks, and a fake broker on one
//! end of a `UnixStream` pair.
#![allow(dead_code)]

use std::io::{self, Write};
use std::os::unix::net::UnixStream;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use zkminer_witness::ipc::{self, BuilderSummary, FetchStatus};
use zkminer_witness_builder::{run, RunnerConfig, RunnerIo};

/// All six imports, one page of exported memory, and `$emit32`/`$emit64`, which append a
/// little-endian value to W through a scratch slot at the top of the first page.
pub const PRELUDE: &str = r#"
  (import "hemiprove_builder_v1" "input_len" (func $input_len (result i32)))
  (import "hemiprove_builder_v1" "input_read" (func $input_read (param i32 i32 i32) (result i32)))
  (import "hemiprove_builder_v1" "fetch" (func $fetch (param i32 i32 i32) (result i64)))
  (import "hemiprove_builder_v1" "response_read" (func $response_read (param i32 i32 i32) (result i32)))
  (import "hemiprove_builder_v1" "witness_write" (func $witness_write (param i32 i32) (result i32)))
  (import "hemiprove_builder_v1" "log" (func $log (param i32 i32)))
  (func $emit32 (param i32)
    (i32.store (i32.const 65520) (local.get 0))
    (drop (call $witness_write (i32.const 65520) (i32.const 4))))
  (func $emit64 (param i64)
    (i64.store (i32.const 65520) (local.get 0))
    (drop (call $witness_write (i32.const 65520) (i32.const 8))))
"#;

/// A module: the prelude, `(memory (export "memory") <pages>)` and `body`.
pub fn module_with_pages(pages: u32, body: &str) -> Vec<u8> {
    wat::parse_str(format!("(module {PRELUDE} (memory (export \"memory\") {pages}) {body})")).expect("test WAT parses")
}

pub fn module(body: &str) -> Vec<u8> {
    module_with_pages(1, body)
}

/// A bare module from raw WAT (no prelude).
pub fn raw(wat: &str) -> Vec<u8> {
    wat::parse_str(wat).expect("test WAT parses")
}

pub fn cfg() -> RunnerConfig {
    RunnerConfig {
        fuel: 50_000_000,
        memory_bytes: 16 << 20,
        deadline: Instant::now() + Duration::from_secs(20),
        max_witness_bytes: 1 << 20,
        max_request_bytes: 1024,
        max_response_bytes: 1 << 20,
    }
}

/// A `Write` into a shared buffer that also records the size of every write.
#[derive(Clone, Default)]
pub struct SharedBuf {
    pub bytes: Arc<Mutex<Vec<u8>>>,
    pub writes: Arc<Mutex<Vec<usize>>>,
}

impl Write for SharedBuf {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.bytes.lock().unwrap().extend_from_slice(buf);
        self.writes.lock().unwrap().push(buf.len());
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl SharedBuf {
    pub fn take(&self) -> Vec<u8> {
        self.bytes.lock().unwrap().clone()
    }
}

/// A sink whose every write fails.
pub struct FailingSink;

impl Write for FailingSink {
    fn write(&mut self, _: &[u8]) -> io::Result<usize> {
        Err(io::Error::from(io::ErrorKind::BrokenPipe))
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// What the fake broker does with each fetch frame, in order.
#[derive(Clone)]
pub enum Reply {
    Result(FetchStatus, Vec<u8>),
    /// Waits, then answers.
    Delayed(Duration, FetchStatus, Vec<u8>),
    /// Reads the frame and never answers.
    Silent,
    /// Closes the socket.
    Close,
    /// A raw frame (kind, payload).
    Raw(u8, Vec<u8>),
}

/// The frames a fake broker received: (cap, request).
pub type Requests = Arc<Mutex<Vec<(u32, Vec<u8>)>>>;

/// A broker on one end of a socket pair, answering fetch frames from a script.
pub struct FakeBroker {
    pub requests: Requests,
    handle: thread::JoinHandle<()>,
}

impl FakeBroker {
    /// Spawns the broker on one end of a pair; returns the runner's end. Once `replies` is used up,
    /// further frames are recorded but not answered. It ends at EOF.
    pub fn spawn(replies: Vec<Reply>) -> (UnixStream, FakeBroker) {
        let (runner_end, mut ours) = UnixStream::pair().unwrap();
        let requests: Requests = Arc::new(Mutex::new(Vec::new()));
        let rec = requests.clone();
        let handle = thread::spawn(move || {
            let mut replies = replies.into_iter();
            loop {
                let Ok((kind, payload)) = ipc::read_frame(&mut ours, ipc::fetch_frame_max(1 << 20)) else { return };
                assert_eq!(kind, ipc::KIND_FETCH);
                let (cap, req) = ipc::decode_fetch(&payload).unwrap();
                rec.lock().unwrap().push((cap, req.to_vec()));
                match replies.next() {
                    Some(Reply::Result(s, body)) => {
                        let _ =
                            ipc::write_frame(&mut ours, ipc::KIND_FETCH_RESULT, &ipc::encode_fetch_result(s, &body));
                    }
                    Some(Reply::Delayed(d, s, body)) => {
                        thread::sleep(d);
                        let _ =
                            ipc::write_frame(&mut ours, ipc::KIND_FETCH_RESULT, &ipc::encode_fetch_result(s, &body));
                    }
                    Some(Reply::Raw(kind, payload)) => {
                        let _ = ipc::write_frame(&mut ours, kind, &payload);
                    }
                    Some(Reply::Close) => return,
                    Some(Reply::Silent) | None => {}
                }
            }
        });
        (runner_end, FakeBroker { requests, handle })
    }

    /// Waits for EOF (the runner dropped its end) and returns what was received.
    pub fn finish(self) -> Vec<(u32, Vec<u8>)> {
        self.handle.join().unwrap();
        Arc::try_unwrap(self.requests).unwrap().into_inner().unwrap()
    }
}

pub struct Outcome {
    pub summary: BuilderSummary,
    /// What the runner wrote to the marker sink: `[MODULE_STARTED_MARKER]` once instantiation began.
    pub marker: Vec<u8>,
    pub w: Vec<u8>,
    pub w_writes: Vec<usize>,
    pub log: Vec<u8>,
    pub requests: Vec<(u32, Vec<u8>)>,
    pub elapsed: Duration,
}

impl Outcome {
    pub fn code(&self) -> i32 {
        self.summary.exit_code
    }
    /// Whether the runner wrote the started marker (exactly once).
    pub fn started(&self) -> bool {
        match self.marker.as_slice() {
            [] => false,
            [zkminer_witness::abi::MODULE_STARTED_MARKER] => true,
            other => panic!("marker sink holds {other:?}"),
        }
    }
    /// W as little-endian i32s.
    pub fn w_i32s(&self) -> Vec<i32> {
        self.w.chunks(4).map(|c| i32::from_le_bytes(c.try_into().unwrap())).collect()
    }
}

/// Runs a module with a context, against a fake broker with `replies`.
pub fn run_full(module: &[u8], context: &[u8], cfg: RunnerConfig, replies: Vec<Reply>) -> Outcome {
    let (broker, fake) = FakeBroker::spawn(replies);
    let w = SharedBuf::default();
    let log = SharedBuf::default();
    let marker = SharedBuf::default();
    let t = Instant::now();
    let io = RunnerIo { witness: w.clone(), broker, log: log.clone(), marker: marker.clone() };
    let summary = run(module, context, &cfg, io);
    let elapsed = t.elapsed();
    let requests = fake.finish();
    let w_writes = w.writes.lock().unwrap().clone();
    Outcome { summary, marker: marker.take(), w: w.take(), w_writes, log: log.take(), requests, elapsed }
}

pub fn run_module(module: &[u8], cfg: RunnerConfig) -> Outcome {
    run_full(module, b"", cfg, vec![])
}

/// A sink that sleeps before every write, then keeps the bytes (a miner slow to drain a pipe).
#[derive(Clone)]
pub struct SlowSink {
    pub delay: Duration,
    pub inner: SharedBuf,
}

impl Write for SlowSink {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        thread::sleep(self.delay);
        self.inner.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// A sink whose every write panics: a stand-in for a runner bug on the execution thread.
pub struct PanickingSink;

impl Write for PanickingSink {
    fn write(&mut self, _: &[u8]) -> io::Result<usize> {
        panic!("test sink panics on purpose");
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Runs a module with the given W and log sinks against a broker that never answers, without
/// waiting for the execution thread (which a test may leave stuck): (summary, marker, elapsed).
pub fn run_with_sinks<W, L>(module: &[u8], cfg: RunnerConfig, witness: W, log: L) -> (BuilderSummary, Vec<u8>, Duration)
where
    W: Write + Send + 'static,
    L: Write + Send + 'static,
{
    let (broker, _fake) = FakeBroker::spawn(vec![]);
    let marker = SharedBuf::default();
    let t = Instant::now();
    let summary = run(module, b"", &cfg, RunnerIo { witness, broker, log, marker: marker.clone() });
    (summary, marker.take(), t.elapsed())
}
