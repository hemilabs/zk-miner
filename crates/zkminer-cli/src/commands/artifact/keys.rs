//! The publisher's key (§13.5 "Key"): an encrypted keystore (Web3 Secret Storage) whose password
//! comes from the terminal (echo off) or from a file descriptor, never from the environment or
//! argv. The miner's own key is refused by path, the configured prover by address, and every
//! address staked as a prover or authorized as one's operator by the chain (`super::check_key`):
//! under the DA throttle a stuck chunk blocks every later nonce of its sender, so a chunk signed by
//! a prover key would stall that prover's fulfils.
//!
//! The keystore is decrypted here, not by eth-keystore: every parameter is checked before it is
//! used (a short `dklen` or IV made eth-keystore panic, an enormous scrypt `n` or PBKDF2 count
//! would exhaust memory or time), and the password, the derived key and the decrypted key live
//! only in buffers that are zeroed when dropped. From the password on, the process leaves no core
//! dump, piped ones included.

use std::io::Read;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::Path;
use std::sync::atomic::{AtomicI32, Ordering};

use alloy::primitives::keccak256;
use alloy::signers::local::PrivateKeySigner;
use anyhow::{bail, Context, Result};
use serde_json::Value;
use zeroize::Zeroizing;
use zkminer_config::ZkMinerConfig;

/// Where the keystore's password comes from.
#[derive(Debug)]
pub enum PasswordSource {
    /// `/dev/tty`, with echo off.
    Tty,
    /// A pipe or file the caller opened for this (from a secrets manager), taken by
    /// [`take_password_fd`] at the start of `main`: read to its end or its first newline.
    Fd(OwnedFd),
}

/// The longest password read.
const MAX_PASSWORD_BYTES: usize = 4096;

/// Takes `--password-fd N` before anything of this process opens a descriptor (the start of
/// `main`, before the async runtime): a number the caller did not open is refused here instead of
/// later naming (and closing) one of the runtime's own. It must be 3 or above (a password on stdin
/// is too easy to leave in a shell history or a redirect), open, readable, and a pipe or a regular
/// file: never a terminal (use the prompt) or a socket. It is marked close-on-exec.
pub fn take_password_fd(fd: RawFd) -> Result<OwnedFd> {
    if fd <= 2 {
        bail!("--password-fd {fd}: name a descriptor of its own (3 or above), not stdin, stdout or stderr");
    }
    // SAFETY: F_GETFD only reads the descriptor's flags; any number is a valid argument.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        bail!(
            "--password-fd {fd} is not an open descriptor: open it for this command (`{fd}<file` or a pipe), \
             or leave the flag out to be asked on the terminal"
        );
    }
    // SAFETY: stat is plain data, filled by fstat before use.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: an open descriptor and a valid pointer.
    if unsafe { libc::fstat(fd, &mut st) } != 0 {
        bail!("--password-fd {fd}: {}", std::io::Error::last_os_error());
    }
    match st.st_mode & libc::S_IFMT {
        libc::S_IFIFO | libc::S_IFREG => {}
        libc::S_IFCHR => bail!("--password-fd {fd} is a terminal or another device: leave the flag out to be asked on the terminal"),
        libc::S_IFSOCK => bail!("--password-fd {fd} is a socket: pass a pipe or a file"),
        _ => bail!("--password-fd {fd} is not a pipe or a regular file"),
    }
    // SAFETY: as F_GETFD.
    let fl = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if fl < 0 || fl & libc::O_ACCMODE == libc::O_WRONLY {
        bail!("--password-fd {fd} is not open for reading");
    }
    // SAFETY: setting the close-on-exec flag of an open descriptor.
    if unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } != 0 {
        bail!("--password-fd {fd}: {}", std::io::Error::last_os_error());
    }
    // SAFETY: the caller handed this process `fd` for exactly this read, and nothing in this process
    // has opened or owns a descriptor yet (this runs first in `main`), so it is ours to own and close.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Reads up to `max` bytes into a zeroed buffer, stopping at the first newline or the end; the
/// line, without `\r\n`. No intermediate buffer holds a copy (`read_to_end` and `BufReader`
/// would leave one in freed memory).
fn read_line_zeroized(mut r: impl Read, max: usize, what: &str) -> Result<Zeroizing<String>> {
    let mut buf = Zeroizing::new(vec![0u8; max + 1]);
    let mut n = 0;
    while n < buf.len() && !buf[..n].contains(&b'\n') {
        match r.read(&mut buf[n..]) {
            Ok(0) => break,
            Ok(k) => n += k,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e).with_context(|| format!("reading the password from {what}")),
        }
    }
    let end = buf[..n].iter().position(|&b| b == b'\n');
    if end.is_none() && n > max {
        bail!("the password on {what} is longer than {max} bytes");
    }
    let mut line = &buf[..end.unwrap_or(n)];
    if line.last() == Some(&b'\r') {
        line = &line[..line.len() - 1];
    }
    if line.len() > max {
        bail!("the password on {what} is longer than {max} bytes");
    }
    let s = std::str::from_utf8(line).context("the password is not UTF-8")?;
    Ok(Zeroizing::new(s.to_string()))
}

/// Reads the password from `fd` (closed afterwards): to the first newline or the end, at most
/// [`MAX_PASSWORD_BYTES`].
pub fn read_password_fd(fd: OwnedFd) -> Result<Zeroizing<String>> {
    let what = format!("fd {}", fd.as_raw_fd());
    read_line_zeroized(std::fs::File::from(fd), MAX_PASSWORD_BYTES, &what)
}

/// The terminal whose echo a signal handler restores (−1: none), and the attributes it restores.
static PROMPT_TTY: AtomicI32 = AtomicI32::new(-1);
struct SavedTermios(std::cell::UnsafeCell<std::mem::MaybeUninit<libc::termios>>);
// SAFETY: written only while `PROMPT_TTY` is −1 (no handler reads it), read by the handler only after
// it observed the descriptor that was stored after the write.
unsafe impl Sync for SavedTermios {}
static PROMPT_SAVED: SavedTermios = SavedTermios(std::cell::UnsafeCell::new(std::mem::MaybeUninit::uninit()));
/// The signals that end the process at the prompt (Ctrl-C, Ctrl-\, a closed terminal, `kill`).
const PROMPT_SIGNALS: [libc::c_int; 4] = [libc::SIGINT, libc::SIGQUIT, libc::SIGHUP, libc::SIGTERM];

/// Restores the terminal's attributes, then ends the process as the signal would have.
extern "C" fn restore_echo_and_reraise(sig: libc::c_int) {
    let fd = PROMPT_TTY.load(Ordering::Acquire);
    if fd >= 0 {
        // SAFETY: tcsetattr, signal and raise are async-signal-safe; the attributes were written
        // before `fd` was published.
        unsafe {
            libc::tcsetattr(fd, libc::TCSANOW, (*PROMPT_SAVED.0.get()).as_ptr());
        }
    }
    // SAFETY: as above. The signal is blocked while its handler runs, so the raised one is delivered,
    // with its default action, when this returns.
    unsafe {
        libc::signal(sig, libc::SIG_DFL);
        libc::raise(sig);
    }
}

/// Echo off on a terminal, and back on when dropped or when a signal ends the process.
struct EchoOff {
    fd: RawFd,
    saved: libc::termios,
    previous: Vec<(libc::c_int, libc::sigaction)>,
}

impl EchoOff {
    fn new(fd: RawFd) -> Result<Self> {
        // SAFETY: termios is plain data, filled by tcgetattr before use.
        let mut term: libc::termios = unsafe { std::mem::zeroed() };
        // SAFETY: a valid fd and a valid pointer.
        if unsafe { libc::tcgetattr(fd, &mut term) } != 0 {
            bail!("the terminal: {}", std::io::Error::last_os_error());
        }
        if PROMPT_TTY.load(Ordering::Acquire) >= 0 {
            bail!("a password prompt is already open");
        }
        // SAFETY: no handler reads the attributes while `PROMPT_TTY` is −1.
        unsafe { (*PROMPT_SAVED.0.get()).write(term) };
        PROMPT_TTY.store(fd, Ordering::Release);
        let mut guard = EchoOff { fd, saved: term, previous: Vec::new() };
        for sig in PROMPT_SIGNALS {
            // SAFETY: sigaction structs are plain data; the handler is async-signal-safe.
            unsafe {
                let mut act: libc::sigaction = std::mem::zeroed();
                act.sa_sigaction = restore_echo_and_reraise as *const () as libc::sighandler_t;
                libc::sigemptyset(&mut act.sa_mask);
                let mut old: libc::sigaction = std::mem::zeroed();
                if libc::sigaction(sig, &act, &mut old) == 0 {
                    guard.previous.push((sig, old));
                }
            }
        }
        term.c_lflag &= !libc::ECHO;
        term.c_lflag |= libc::ECHONL;
        // SAFETY: as tcgetattr.
        if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &term) } != 0 {
            bail!("the terminal: {}", std::io::Error::last_os_error());
        }
        Ok(guard)
    }
}

impl Drop for EchoOff {
    fn drop(&mut self) {
        // SAFETY: restoring the attributes read from the same fd, then the handlers saved above.
        unsafe {
            libc::tcsetattr(self.fd, libc::TCSANOW, &self.saved);
            PROMPT_TTY.store(-1, Ordering::Release);
            for (sig, old) in &self.previous {
                libc::sigaction(*sig, old, std::ptr::null_mut());
            }
        }
    }
}

/// Prompts on `tty` and reads one line with echo off; echo comes back however the read ends,
/// a signal (Ctrl-C) included.
fn read_password_from(tty: &std::fs::File, prompt: &str) -> Result<Zeroizing<String>> {
    use std::io::Write;
    let guard = EchoOff::new(tty.as_raw_fd())?;
    let mut out = tty;
    out.write_all(prompt.as_bytes())?;
    out.flush()?;
    let line = read_line_zeroized(tty, MAX_PASSWORD_BYTES, "the terminal");
    drop(guard);
    line
}

/// Prompts on `/dev/tty` and reads one line with echo off.
pub fn read_password_tty(prompt: &str) -> Result<Zeroizing<String>> {
    let tty = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .context("no terminal to read the keystore password from (use --password-fd)")?;
    read_password_from(&tty, prompt)
}

/// Refuses the miner's own key file as a keystore: a publisher never signs with the miner's key.
pub fn refuse_miner_key_file(keystore: &Path, config: &ZkMinerConfig) -> Result<()> {
    let Some(miner) = config.wallet.key_file_path.as_deref() else { return Ok(()) };
    let same = match (std::fs::canonicalize(keystore), std::fs::canonicalize(miner)) {
        (Ok(a), Ok(b)) => a == b,
        _ => Path::new(miner) == keystore,
    };
    if same {
        bail!("{} is the miner's [wallet] key file: publish with a key of its own (§13.5)", keystore.display());
    }
    Ok(())
}

/// The largest keystore file read.
const MAX_KEYSTORE_BYTES: u64 = 64 << 10;
/// scrypt's memory, `128 × n × r` bytes, at most this (geth's "standard" n = 2^18, r = 8 is 256 MiB).
const MAX_SCRYPT_MEMORY: u64 = 512 << 20;
/// scrypt's work, `n × r × p`, at most this.
const MAX_SCRYPT_WORK: u64 = 1 << 24;
/// PBKDF2's iteration count, at most this.
const MAX_PBKDF2_ROUNDS: u32 = 10_000_000;

/// A keystore's KDF, its parameters checked.
enum Kdf {
    Scrypt { log_n: u8, r: u32, p: u32 },
    Pbkdf2 { rounds: u32 },
}

/// A Web3 Secret Storage (version 3) keystore, every field checked.
struct Keystore {
    kdf: Kdf,
    dklen: usize,
    salt: Vec<u8>,
    iv: [u8; 16],
    ciphertext: [u8; 32],
    mac: [u8; 32],
}

fn hex_field(v: &Value, name: &str) -> Result<Vec<u8>> {
    let s = v.get(name).and_then(Value::as_str).with_context(|| format!("the keystore has no {name}"))?;
    alloy::hex::decode(s.strip_prefix("0x").unwrap_or(s)).with_context(|| format!("the keystore's {name} is not hex"))
}

fn uint_field(v: &Value, name: &str) -> Result<u64> {
    v.get(name).and_then(Value::as_u64).with_context(|| format!("the keystore's kdfparams.{name} is missing or not a positive integer"))
}

impl Keystore {
    fn parse(text: &[u8]) -> Result<Self> {
        let v: Value = serde_json::from_slice(text).context("the keystore is not JSON")?;
        if v.get("version").and_then(Value::as_u64) != Some(3) {
            bail!("the keystore is not version 3 (Web3 Secret Storage)");
        }
        let c = v.get("crypto").or_else(|| v.get("Crypto")).context("the keystore has no crypto section")?;
        let cipher = c.get("cipher").and_then(Value::as_str).unwrap_or("");
        if cipher != "aes-128-ctr" {
            bail!("the keystore's cipher is {cipher:?}; only aes-128-ctr is supported");
        }
        let iv = hex_field(c.get("cipherparams").unwrap_or(&Value::Null), "iv")?;
        let iv: [u8; 16] = iv.as_slice().try_into().map_err(|_| anyhow::anyhow!("the keystore's IV is {} bytes, not 16", iv.len()))?;
        let ct = hex_field(c, "ciphertext")?;
        let ciphertext: [u8; 32] =
            ct.as_slice().try_into().map_err(|_| anyhow::anyhow!("the keystore's ciphertext is {} bytes, not a 32-byte key", ct.len()))?;
        let mac = hex_field(c, "mac")?;
        let mac: [u8; 32] = mac.as_slice().try_into().map_err(|_| anyhow::anyhow!("the keystore's MAC is {} bytes, not 32", mac.len()))?;
        let params = c.get("kdfparams").context("the keystore has no kdfparams")?;
        let dklen = uint_field(params, "dklen")?;
        if !(32..=64).contains(&dklen) {
            bail!("the keystore's kdfparams.dklen is {dklen}: it must be 32 (at most 64)");
        }
        let salt = hex_field(params, "salt")?;
        if salt.len() > 1024 {
            bail!("the keystore's salt is {} bytes (at most 1024)", salt.len());
        }
        let kdf = match c.get("kdf").and_then(Value::as_str).unwrap_or("") {
            "scrypt" => {
                let n = uint_field(params, "n")?;
                let r = uint_field(params, "r")?;
                let p = uint_field(params, "p")?;
                if n < 2 || !n.is_power_of_two() {
                    bail!("the keystore's scrypt n is {n}: it must be a power of two, at least 2");
                }
                if r == 0 || p == 0 {
                    bail!("the keystore's scrypt r and p must be at least 1");
                }
                let memory = 128u128 * u128::from(n) * u128::from(r);
                if memory > u128::from(MAX_SCRYPT_MEMORY) || u128::from(n) * u128::from(r) * u128::from(p) > u128::from(MAX_SCRYPT_WORK) {
                    bail!(
                        "the keystore's scrypt parameters (n {n}, r {r}, p {p}) need more than {} MiB or {MAX_SCRYPT_WORK} blocks of work",
                        MAX_SCRYPT_MEMORY >> 20
                    );
                }
                Kdf::Scrypt { log_n: n.trailing_zeros() as u8, r: r as u32, p: p as u32 }
            }
            "pbkdf2" => {
                let prf = params.get("prf").and_then(Value::as_str).unwrap_or("");
                if prf != "hmac-sha256" {
                    bail!("the keystore's PBKDF2 prf is {prf:?}; only hmac-sha256 is supported");
                }
                let c = uint_field(params, "c")?;
                if c == 0 || c > u64::from(MAX_PBKDF2_ROUNDS) {
                    bail!("the keystore's PBKDF2 count is {c} (1..={MAX_PBKDF2_ROUNDS})");
                }
                Kdf::Pbkdf2 { rounds: c as u32 }
            }
            other => bail!("the keystore's kdf is {other:?}; only scrypt and pbkdf2 are supported"),
        };
        Ok(Keystore { kdf, dklen: dklen as usize, salt, iv, ciphertext, mac })
    }

    /// The private key, or an error for a wrong password.
    fn decrypt(&self, password: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
        use aes::cipher::{KeyIvInit, StreamCipher};
        let mut dk = Zeroizing::new(vec![0u8; self.dklen]);
        match self.kdf {
            Kdf::Scrypt { log_n, r, p } => {
                let params = scrypt::Params::new(log_n, r, p).map_err(|e| anyhow::anyhow!("the keystore's scrypt parameters: {e}"))?;
                scrypt::scrypt(password, &self.salt, &params, &mut dk).map_err(|e| anyhow::anyhow!("scrypt: {e}"))?;
            }
            Kdf::Pbkdf2 { rounds } => pbkdf2::pbkdf2::<hmac::Hmac<sha2::Sha256>>(password, &self.salt, rounds, &mut dk),
        }
        let mut mac_input = Zeroizing::new(Vec::with_capacity(16 + 32));
        mac_input.extend_from_slice(&dk[16..32]);
        mac_input.extend_from_slice(&self.ciphertext);
        let mac = keccak256(&mac_input[..]);
        // Compared in full, whatever differs first.
        if mac.iter().zip(self.mac.iter()).fold(0u8, |acc, (a, b)| acc | (a ^ b)) != 0 {
            bail!("wrong password (the keystore's MAC does not match)");
        }
        let mut key = Zeroizing::new(self.ciphertext);
        let mut ctr = ctr::Ctr128BE::<aes::Aes128>::new(dk[..16].into(), (&self.iv).into());
        ctr.apply_keystream(&mut key[..]);
        Ok(key)
    }
}

/// Decrypts the keystore with `password`.
pub fn decrypt(keystore: &Path, password: &Zeroizing<String>) -> Result<PrivateKeySigner> {
    let what = || format!("the keystore {}", keystore.display());
    let f = std::fs::File::open(keystore).with_context(what)?;
    let mut text = Vec::new();
    f.take(MAX_KEYSTORE_BYTES + 1).read_to_end(&mut text).with_context(what)?;
    if text.len() as u64 > MAX_KEYSTORE_BYTES {
        bail!("{} is larger than {MAX_KEYSTORE_BYTES} bytes: not a keystore", keystore.display());
    }
    let ks = Keystore::parse(&text).with_context(what)?;
    let key = ks.decrypt(password.as_bytes()).with_context(what)?;
    PrivateKeySigner::from_slice(&key[..]).map_err(|e| anyhow::anyhow!("{}: not a valid secp256k1 key: {e}", what()))
}

/// No core dump of this process from here on: it is about to hold the password and the key.
/// `PR_SET_DUMPABLE(0)` (set at the start of `main`) stops core files and same-user reads, but on a
/// host with `fs.suid_dumpable = 2` and a piped `core_pattern` (apport, systemd-coredump) a crash
/// still hands a core to that program. The kernel aborts a piped dump when the soft `RLIMIT_CORE`
/// is exactly 1 (and writes no core file smaller than a page), so 1 stops both.
fn no_core_dumps() {
    // SAFETY: rlimit is plain data, filled by getrlimit before use.
    let mut lim: libc::rlimit = unsafe { std::mem::zeroed() };
    // SAFETY: valid pointers to plain data.
    unsafe {
        if libc::getrlimit(libc::RLIMIT_CORE, &mut lim) == 0 {
            lim.rlim_cur = lim.rlim_max.min(1);
            libc::setrlimit(libc::RLIMIT_CORE, &lim);
        }
    }
}

/// Loads the publisher's key: the keystore (never the miner's key file), its password from
/// `source`, and the address checked against `[witness] prover_address` (a non-secret field).
pub fn load(keystore: &Path, source: PasswordSource, config: &ZkMinerConfig) -> Result<PrivateKeySigner> {
    refuse_miner_key_file(keystore, config)?;
    no_core_dumps();
    let password = match source {
        PasswordSource::Fd(fd) => read_password_fd(fd)?,
        PasswordSource::Tty => read_password_tty(&format!("Password for {}: ", keystore.display()))?,
    };
    let signer = decrypt(keystore, &password)?;
    refuse_configured_prover(signer.address(), config)?;
    Ok(signer)
}

/// Refuses the configured prover address.
pub fn refuse_configured_prover(address: alloy::primitives::Address, config: &ZkMinerConfig) -> Result<()> {
    if config.witness.prover_address == Some(address) {
        bail!("{address} is this miner's prover ([witness] prover_address): publish with a key of its own (§13.5)");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::fd::IntoRawFd;

    fn pipe_with(bytes: &[u8]) -> OwnedFd {
        let mut fds = [0i32; 2];
        // SAFETY: a valid array of two fds.
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        // SAFETY: the write end is ours.
        let mut w = unsafe { std::fs::File::from_raw_fd(fds[1]) };
        w.write_all(bytes).unwrap();
        drop(w);
        take_password_fd(fds[0]).unwrap()
    }

    #[test]
    fn a_password_is_read_from_an_fd_to_its_first_newline() {
        assert_eq!(read_password_fd(pipe_with(b"hunter2\nrest")).unwrap().as_str(), "hunter2");
        assert_eq!(read_password_fd(pipe_with(b"crlf\r\n")).unwrap().as_str(), "crlf");
        assert_eq!(read_password_fd(pipe_with(b"no newline")).unwrap().as_str(), "no newline");
        assert_eq!(read_password_fd(pipe_with(b"")).unwrap().as_str(), "");
        assert!(read_password_fd(pipe_with(&vec![b'a'; MAX_PASSWORD_BYTES + 1])).is_err());
        let mut exact = vec![b'a'; MAX_PASSWORD_BYTES];
        assert_eq!(read_password_fd(pipe_with(&exact)).unwrap().len(), MAX_PASSWORD_BYTES);
        exact.extend_from_slice(b"\nmore");
        assert_eq!(read_password_fd(pipe_with(&exact)).unwrap().len(), MAX_PASSWORD_BYTES);
        assert!(read_password_fd(pipe_with(b"\xff\xfe\n")).is_err(), "not UTF-8");
    }

    #[test]
    fn only_an_open_readable_pipe_or_file_is_taken_as_the_password_fd() {
        for fd in [0, 1, 2, -1] {
            assert!(take_password_fd(fd).unwrap_err().to_string().contains("3 or above"), "{fd}");
        }
        // Not open (no descriptor table is this large).
        assert!(take_password_fd(i32::MAX).unwrap_err().to_string().contains("not an open descriptor"));
        // A regular file is taken (and marked close-on-exec).
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("pw"), "pw\n").unwrap();
        let fd = std::fs::File::open(dir.path().join("pw")).unwrap().into_raw_fd();
        // SAFETY: clearing the flag on our own descriptor, to see it set again.
        unsafe { libc::fcntl(fd, libc::F_SETFD, 0) };
        let owned = take_password_fd(fd).unwrap();
        // SAFETY: reading the flags of an open descriptor.
        assert_ne!(unsafe { libc::fcntl(owned.as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC, 0);
        assert_eq!(read_password_fd(owned).unwrap().as_str(), "pw");
        // A device, a socket, a directory and a write-only file are not taken (and stay the caller's).
        let refused = |file: std::fs::File, what: &str| {
            let fd = file.into_raw_fd();
            let e = take_password_fd(fd).unwrap_err().to_string();
            assert!(e.contains(what), "{e}");
            // SAFETY: still ours: the refusal did not take it.
            drop(unsafe { std::fs::File::from_raw_fd(fd) });
        };
        refused(std::fs::File::open("/dev/null").unwrap(), "terminal or another device");
        let (a, b) = std::os::unix::net::UnixStream::pair().unwrap();
        refused(std::fs::File::from(OwnedFd::from(a)), "socket");
        drop(b);
        refused(std::fs::File::open(dir.path()).unwrap(), "not a pipe or a regular file");
        refused(std::fs::OpenOptions::new().write(true).open(dir.path().join("pw")).unwrap(), "not open for reading");
    }

    /// Ctrl-C at the prompt: the terminal's echo comes back. The prompt runs in a child (this test
    /// binary again, on a pseudo-terminal), which is then sent SIGINT.
    #[test]
    fn a_signal_at_the_prompt_restores_the_terminals_echo() {
        if let Some(fd) = std::env::var_os("ZKMINER_TEST_PROMPT_TTY") {
            // The child: prompt on the pseudo-terminal until the parent's signal ends the process.
            let fd: RawFd = fd.to_str().unwrap().parse().unwrap();
            // SAFETY: the parent put the pseudo-terminal at this descriptor for this read.
            let tty = unsafe { std::fs::File::from_raw_fd(fd) };
            let _ = read_password_from(&tty, "Password: ");
            std::process::exit(3);
        }
        use std::os::unix::process::{CommandExt, ExitStatusExt};
        let (mut master, mut slave) = (-1, -1);
        // SAFETY: valid pointers; the name, attributes and size are optional.
        let rc = unsafe { libc::openpty(&mut master, &mut slave, std::ptr::null_mut(), std::ptr::null(), std::ptr::null()) };
        assert_eq!(rc, 0, "openpty: {}", std::io::Error::last_os_error());
        let echo = || {
            // SAFETY: as in EchoOff.
            let mut t: libc::termios = unsafe { std::mem::zeroed() };
            assert_eq!(unsafe { libc::tcgetattr(slave, &mut t) }, 0);
            t.c_lflag & libc::ECHO != 0
        };
        assert!(echo());
        let mut cmd = std::process::Command::new(std::env::current_exe().unwrap());
        cmd.args(["--exact", "commands::artifact::keys::tests::a_signal_at_the_prompt_restores_the_terminals_echo", "--test-threads=1"])
            .env("ZKMINER_TEST_PROMPT_TTY", "3")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        // SAFETY: only async-signal-safe calls between fork and exec.
        unsafe {
            cmd.pre_exec(move || {
                if libc::dup2(slave, 3) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut child = cmd.spawn().unwrap();
        let start = std::time::Instant::now();
        while echo() {
            assert!(start.elapsed() < std::time::Duration::from_secs(60), "the child never turned echo off");
            assert!(child.try_wait().unwrap().is_none(), "the child ended before prompting");
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        // SAFETY: signalling our own child by pid.
        assert_eq!(unsafe { libc::kill(child.id() as i32, libc::SIGINT) }, 0);
        let status = child.wait().unwrap();
        assert_eq!(status.signal(), Some(libc::SIGINT), "{status:?}");
        assert!(echo(), "echo is back on after Ctrl-C");
        // SAFETY: our own descriptors.
        unsafe {
            libc::close(master);
            libc::close(slave);
        }
    }

    #[test]
    fn the_miner_key_file_and_prover_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("k.json");
        std::fs::write(&path, "{}").unwrap();
        let mut c = ZkMinerConfig::default();
        c.wallet.key_file_path = Some(path.display().to_string());
        assert!(refuse_miner_key_file(&path, &c).is_err());
        assert!(refuse_miner_key_file(&dir.path().join("other.json"), &c).is_ok());
        let a = alloy::primitives::Address::repeat_byte(5);
        c.witness.prover_address = Some(a);
        assert!(refuse_configured_prover(a, &c).is_err());
        assert!(refuse_configured_prover(alloy::primitives::Address::repeat_byte(6), &c).is_ok());
    }

    #[test]
    fn a_keystore_round_trips_and_a_wrong_password_fails() {
        let dir = tempfile::tempdir().unwrap();
        let key = alloy::primitives::B256::repeat_byte(0x11);
        // Written by eth-keystore (scrypt), read here.
        let (signer, _uuid) =
            PrivateKeySigner::encrypt_keystore(dir.path(), &mut rand::thread_rng(), key, "pw", Some("k")).unwrap();
        let path = dir.path().join("k");
        let pw = Zeroizing::new("pw".to_string());
        assert_eq!(decrypt(&path, &pw).unwrap().address(), signer.address());
        assert!(format!("{:#}", decrypt(&path, &Zeroizing::new("no".into())).unwrap_err()).contains("wrong password"));
        let c = ZkMinerConfig::default();
        assert_eq!(load(&path, PasswordSource::Fd(pipe_with(b"pw\n")), &c).unwrap().address(), signer.address());
        // Loading turned core dumps off (piped ones included).
        // SAFETY: plain data, filled by getrlimit.
        let mut lim: libc::rlimit = unsafe { std::mem::zeroed() };
        assert_eq!(unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut lim) }, 0);
        assert!(lim.rlim_cur <= 1, "{}", lim.rlim_cur);
    }

    /// The Web3 Secret Storage definition's PBKDF2 test vector, and a scrypt keystore written by
    /// another implementation (Python's OpenSSL scrypt and AES-CTR).
    #[test]
    fn the_reference_keystores_decrypt() {
        let want: alloy::primitives::B256 = "7a28b5ba57c53603b0b07b56bba752f7784bf506fa95edc395f5cf6c7514fe9d".parse().unwrap();
        let pbkdf2 = r#"{"crypto":{"cipher":"aes-128-ctr","cipherparams":{"iv":"6087dab2f9fdbbfaddc31a909735c1e6"},
            "ciphertext":"5318b4d5bcd28de64ee5559e671353e16f075ecae9f99c7a79a38af5f869aa46","kdf":"pbkdf2",
            "kdfparams":{"c":262144,"dklen":32,"prf":"hmac-sha256","salt":"ae3cd4e7013836a3df6bd7241b12db061dbe2c6785853cce422d148a624ce0bd"},
            "mac":"517ead924a9d0dc3124507e3393d175ce3ff7c1e96529c6c555ce9e51205e9b2"},"id":"3198bc9c-6672-5ab3-d995-4942343ae5b6","version":3}"#;
        let scrypt = r#"{"crypto":{"cipher":"aes-128-ctr","cipherparams":{"iv":"6465666768696a6b6c6d6e6f70717273"},
            "ciphertext":"35b5919214ec0d19e5071c46c0422a4144c69f3d7145760c3c3def69f2186591","kdf":"scrypt",
            "kdfparams":{"dklen":32,"n":1024,"p":2,"r":8,"salt":"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"},
            "mac":"a94151605769cb72ebfbe2afcf354c2f12f84a01f8a7042c690dc00927e29697"},"id":"3198bc9c-6672-5ab3-d995-4942343ae5b6","version":3}"#;
        for ks in [pbkdf2, scrypt] {
            let k = Keystore::parse(ks.as_bytes()).unwrap();
            assert_eq!(k.decrypt(b"testpassword").unwrap()[..], want[..]);
            assert!(k.decrypt(b"wrongpassword").is_err());
        }
    }

    /// Malformed keystores are errors, never panics or unbounded work (eth-keystore panicked on a
    /// short `dklen` or IV).
    #[test]
    fn malformed_keystores_are_refused_before_any_work() {
        let good: Value = serde_json::from_str(
            r#"{"crypto":{"cipher":"aes-128-ctr","cipherparams":{"iv":"0074eb7a9cff2fba33fbf7fa96400077"},
            "ciphertext":"e1edac2785a9b7cc7c35e9061731c746bd9bcddd83e8195dacef44af7fb4e1b8","kdf":"scrypt",
            "kdfparams":{"dklen":32,"n":8192,"p":1,"r":8,"salt":"7bad0d030ca5f4d5a87946522a513649c481d7e847b6daa6ca49538d0bca8f91"},
            "mac":"c2a7b26bed4c9df6a5e88cfc92e5f62d55355b37db6adda5d6b13a19ff5b3f18"},"id":"6d37343b-09e0-453d-9571-365f285a67eb","version":3}"#,
        )
        .unwrap();
        assert!(Keystore::parse(good.to_string().as_bytes()).is_ok());
        let with = |path: &[&str], v: Value| {
            let mut k = good.clone();
            let mut at = &mut k;
            for p in &path[..path.len() - 1] {
                at = &mut at[*p];
            }
            at[path[path.len() - 1]] = v;
            Keystore::parse(k.to_string().as_bytes()).err().map(|e| e.to_string()).unwrap_or_default()
        };
        assert!(with(&["crypto", "kdfparams", "dklen"], 16.into()).contains("dklen"));
        assert!(with(&["crypto", "kdfparams", "dklen"], 0.into()).contains("dklen"));
        assert!(with(&["crypto", "cipherparams", "iv"], "00".into()).contains("IV is 1 bytes"));
        assert!(with(&["crypto", "cipherparams", "iv"], "".into()).contains("IV is 0 bytes"));
        assert!(with(&["crypto", "ciphertext"], "00".into()).contains("ciphertext"));
        assert!(with(&["crypto", "mac"], "00".into()).contains("MAC"));
        assert!(with(&["crypto", "cipher"], "aes-256-gcm".into()).contains("cipher"));
        assert!(with(&["crypto", "kdfparams", "n"], 0.into()).contains("power of two"));
        assert!(with(&["crypto", "kdfparams", "n"], 1000.into()).contains("power of two"));
        assert!(with(&["crypto", "kdfparams", "n"], (1u64 << 31).into()).contains("MiB"));
        assert!(with(&["crypto", "kdfparams", "r"], 0.into()).contains("at least 1"));
        assert!(with(&["crypto", "kdfparams", "p"], 1_000_000.into()).contains("work"));
        assert!(with(&["crypto", "kdfparams", "n"], (-5).into()).contains("not a positive integer"));
        assert!(with(&["crypto", "kdf"], "argon2".into()).contains("kdf"));
        assert!(with(&["version"], 1.into()).contains("version 3"));
        // PBKDF2's count and PRF.
        let pb = |c: Value, prf: &str| {
            let mut k = good.clone();
            k["crypto"]["kdf"] = "pbkdf2".into();
            k["crypto"]["kdfparams"] = serde_json::json!({"c": c, "dklen": 32, "prf": prf, "salt": "00"});
            Keystore::parse(k.to_string().as_bytes()).err().map(|e| e.to_string()).unwrap_or_default()
        };
        assert_eq!(pb(1000.into(), "hmac-sha256"), "");
        assert!(pb(0.into(), "hmac-sha256").contains("count"));
        assert!(pb(u64::from(u32::MAX).into(), "hmac-sha256").contains("count"));
        assert!(pb(1000.into(), "hmac-sha512").contains("prf"));
        assert!(Keystore::parse(b"not json").is_err());
    }

    /// The reviewer's malformed keystores (`dklen` 16, a 1-byte IV): errors from `decrypt`.
    #[test]
    fn a_short_dklen_or_iv_is_an_error_from_decrypt() {
        let dir = tempfile::tempdir().unwrap();
        let base = r#"{"crypto": {"cipher": "aes-128-ctr", "cipherparams": {"iv": "IV"}, "ciphertext": "e1edac2785a9b7cc7c35e9061731c746bd9bcddd83e8195dacef44af7fb4e1b8", "kdf": "scrypt", "kdfparams": {"dklen": DKLEN, "n": 8192, "p": 1, "r": 8, "salt": "7bad0d030ca5f4d5a87946522a513649c481d7e847b6daa6ca49538d0bca8f91"}, "mac": "c2a7b26bed4c9df6a5e88cfc92e5f62d55355b37db6adda5d6b13a19ff5b3f18"}, "id": "6d37343b-09e0-453d-9571-365f285a67eb", "version": 3}"#;
        let pw = Zeroizing::new("pw".to_string());
        for (iv, dklen, what) in [("0074eb7a9cff2fba33fbf7fa96400077", "16", "dklen"), ("00", "32", "IV")] {
            let path = dir.path().join(what);
            std::fs::write(&path, base.replace("IV", iv).replace("DKLEN", dklen)).unwrap();
            let e = format!("{:#}", decrypt(&path, &pw).unwrap_err());
            assert!(e.contains(what), "{e}");
        }
        let big = dir.path().join("big");
        std::fs::write(&big, vec![b' '; MAX_KEYSTORE_BYTES as usize + 1]).unwrap();
        assert!(decrypt(&big, &pw).unwrap_err().to_string().contains("not a keystore"));
    }
}
