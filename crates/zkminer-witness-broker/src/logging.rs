//! Log hygiene (plan §11.4): every line the broker writes passes through
//! `redact_urls(sanitize_log(…))` at the writer, whatever a crate put in it (a dependency's debug
//! output, a field the broker forgot to redact), and the HTTP and TLS stacks log at `warn` at most
//! whatever `RUST_LOG` says (their trace output is where URLs and headers live).
//!
//! ```text
//! tracing_subscriber::fmt()
//!     .with_writer(Redacting(std::io::stderr))
//!     .with_ansi(false)
//!     .with_env_filter(env_filter(std::env::var("RUST_LOG").ok().as_deref()))
//!     .init();
//! ```

use std::io::{self, Write};

use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::EnvFilter;

use crate::egress::{redact_urls, sanitize_log};

/// The longest log line, after escaping.
pub const LOG_LINE_MAX: usize = 4096;

/// Directives forced on top of any `RUST_LOG` (an exact-target directive replaces the user's).
pub const FORCED_DIRECTIVES: &[&str] = &["hyper=warn", "hyper_util=warn", "reqwest=warn", "rustls=warn"];

/// `spec` (`RUST_LOG`; `info` when absent or invalid) with [`FORCED_DIRECTIVES`] applied.
pub fn env_filter(spec: Option<&str>) -> EnvFilter {
    let mut f = spec.and_then(|s| EnvFilter::try_new(s).ok()).unwrap_or_else(|| EnvFilter::new("info"));
    for d in FORCED_DIRECTIVES {
        f = f.add_directive(d.parse().expect("a static directive"));
    }
    f
}

/// One line, sanitized (control characters and non-ASCII escaped, bounded) and redacted.
pub fn redact_line(line: &[u8]) -> String {
    redact_urls(&sanitize_log(line, LOG_LINE_MAX))
}

/// A `MakeWriter` whose writers redact every line before it reaches `M`'s writer.
#[derive(Debug, Clone, Copy)]
pub struct Redacting<M>(pub M);

impl<'a, M: MakeWriter<'a>> MakeWriter<'a> for Redacting<M> {
    type Writer = RedactingWriter<M::Writer>;

    fn make_writer(&'a self) -> Self::Writer {
        RedactingWriter { inner: self.0.make_writer(), buf: Vec::new() }
    }
}

/// Buffers one event's output and writes it, line by line redacted, when flushed or dropped.
pub struct RedactingWriter<W: Write> {
    inner: W,
    buf: Vec<u8>,
}

impl<W: Write> RedactingWriter<W> {
    fn emit(&mut self) -> io::Result<()> {
        if self.buf.is_empty() {
            return Ok(());
        }
        let buf = std::mem::take(&mut self.buf);
        let mut out = Vec::with_capacity(buf.len() + 16);
        let body = buf.strip_suffix(b"\n").unwrap_or(&buf);
        for line in body.split(|&b| b == b'\n') {
            out.extend_from_slice(redact_line(line).as_bytes());
            out.push(b'\n');
        }
        self.inner.write_all(&out)
    }
}

impl<W: Write> Write for RedactingWriter<W> {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        self.buf.extend_from_slice(b);
        Ok(b.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.emit()?;
        self.inner.flush()
    }
}

impl<W: Write> Drop for RedactingWriter<W> {
    fn drop(&mut self) {
        let _ = self.emit();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Default)]
    struct Sink(Arc<Mutex<Vec<u8>>>);
    impl Write for Sink {
        fn write(&mut self, b: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn every_line_is_sanitized_and_redacted() {
        let sink = Sink::default();
        let s2 = sink.clone();
        let make = Redacting(move || s2.clone());
        {
            let mut w = make.make_writer();
            w.write_all(b"connect https://node.example/v2/SECRETKEY failed\nnext \x1b[31mline\n").unwrap();
        }
        let out = String::from_utf8(sink.0.lock().unwrap().clone()).unwrap();
        assert_eq!(out, "connect <url> failed\nnext \\x1b[31mline\n");
    }

    #[test]
    fn the_http_stack_is_capped_at_warn() {
        for spec in [None, Some("trace"), Some("hyper=trace,reqwest=trace,rustls=trace,hyper_util=trace"), Some("[[bad")] {
            let f = env_filter(spec).to_string();
            for d in FORCED_DIRECTIVES {
                assert!(f.contains(d), "{spec:?}: {f}");
            }
            assert!(!f.contains("hyper=trace") && !f.contains("reqwest=trace"), "{spec:?}: {f}");
        }
    }
}
