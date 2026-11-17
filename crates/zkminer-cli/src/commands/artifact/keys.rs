//! The publisher's key (§13.5 "Key"): an encrypted keystore (Web3 Secret Storage) whose password
//! comes from the terminal (echo off) or from a file descriptor, never from the environment or
//! argv. The miner's own key is refused by path, the configured prover by address, and every
//! address staked as a prover or authorized as one's operator by the chain (`super::checks`): under
//! the DA throttle a stuck chunk blocks every later nonce of its sender, so a chunk signed by a
//! prover key would stall that prover's fulfils.

use std::io::Read;
use std::os::fd::{AsRawFd, FromRawFd};
use std::path::Path;

use alloy::signers::local::PrivateKeySigner;
use anyhow::{bail, Context, Result};
use zeroize::Zeroizing;
use zkminer_config::ZkMinerConfig;

/// Where the keystore's password comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasswordSource {
    /// `/dev/tty`, with echo off.
    Tty,
    /// A file descriptor the caller opened (a pipe from a secrets manager): read to its end or its
    /// first newline.
    Fd(i32),
}

/// The longest password read.
const MAX_PASSWORD_BYTES: usize = 4096;

/// Reads the password from `fd` (closed afterwards): to the first newline or the end, at most
/// [`MAX_PASSWORD_BYTES`]. fds 0–2 are refused (a password on stdin is too easy to leave in a
/// shell history or a process listing's redirect).
pub fn read_password_fd(fd: i32) -> Result<Zeroizing<String>> {
    if fd <= 2 {
        bail!("--password-fd {fd}: name a descriptor of its own (3 or above), not stdin, stdout or stderr");
    }
    // SAFETY: the caller handed this process `fd` for exactly this read; it is closed when `f` drops.
    let f = unsafe { std::fs::File::from_raw_fd(fd) };
    let mut buf = Zeroizing::new(Vec::with_capacity(64));
    f.take(MAX_PASSWORD_BYTES as u64 + 1)
        .read_to_end(&mut buf)
        .with_context(|| format!("reading the password from fd {fd}"))?;
    if buf.len() > MAX_PASSWORD_BYTES {
        bail!("the password on fd {fd} is longer than {MAX_PASSWORD_BYTES} bytes");
    }
    let end = buf.iter().position(|&b| b == b'\n').unwrap_or(buf.len());
    let mut line = &buf[..end];
    if line.last() == Some(&b'\r') {
        line = &line[..line.len() - 1];
    }
    let s = std::str::from_utf8(line).context("the password is not UTF-8")?;
    Ok(Zeroizing::new(s.to_string()))
}

/// Restores a terminal's attributes when dropped.
struct EchoOff {
    fd: i32,
    saved: libc::termios,
}

impl Drop for EchoOff {
    fn drop(&mut self) {
        // SAFETY: restoring attributes read from the same fd.
        unsafe {
            libc::tcsetattr(self.fd, libc::TCSANOW, &self.saved);
        }
    }
}

/// Prompts on `/dev/tty` and reads one line with echo off.
pub fn read_password_tty(prompt: &str) -> Result<Zeroizing<String>> {
    use std::io::{BufRead, Write};
    let mut tty = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .context("no terminal to read the keystore password from (use --password-fd)")?;
    let fd = tty.as_raw_fd();
    // SAFETY: termios is plain data, filled by tcgetattr before use.
    let mut term: libc::termios = unsafe { std::mem::zeroed() };
    // SAFETY: a valid fd and a valid pointer.
    if unsafe { libc::tcgetattr(fd, &mut term) } != 0 {
        bail!("/dev/tty: {}", std::io::Error::last_os_error());
    }
    let guard = EchoOff { fd, saved: term };
    term.c_lflag &= !libc::ECHO;
    term.c_lflag |= libc::ECHONL;
    // SAFETY: as above.
    if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &term) } != 0 {
        bail!("/dev/tty: {}", std::io::Error::last_os_error());
    }
    tty.write_all(prompt.as_bytes())?;
    tty.flush()?;
    let mut line = Zeroizing::new(String::new());
    std::io::BufReader::new(&tty).take(MAX_PASSWORD_BYTES as u64).read_line(&mut line)?;
    drop(guard);
    let trimmed = line.trim_end_matches(['\n', '\r']).to_string();
    Ok(Zeroizing::new(trimmed))
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

/// Decrypts the keystore with `password`.
pub fn decrypt(keystore: &Path, password: &Zeroizing<String>) -> Result<PrivateKeySigner> {
    PrivateKeySigner::decrypt_keystore(keystore, password.as_bytes())
        .map_err(|e| anyhow::anyhow!("decrypting the keystore {}: {e}", keystore.display()))
}

/// Loads the publisher's key: the keystore (never the miner's key file), its password from
/// `source`, and the address checked against `[witness] prover_address` (a non-secret field).
pub fn load(keystore: &Path, source: PasswordSource, config: &ZkMinerConfig) -> Result<PrivateKeySigner> {
    refuse_miner_key_file(keystore, config)?;
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

    fn pipe_with(bytes: &[u8]) -> i32 {
        let mut fds = [0i32; 2];
        // SAFETY: a valid array of two fds.
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        // SAFETY: the write end is ours.
        let mut w = unsafe { std::fs::File::from_raw_fd(fds[1]) };
        w.write_all(bytes).unwrap();
        drop(w);
        fds[0]
    }

    #[test]
    fn a_password_is_read_from_an_fd_to_its_first_newline() {
        assert_eq!(read_password_fd(pipe_with(b"hunter2\nrest")).unwrap().as_str(), "hunter2");
        assert_eq!(read_password_fd(pipe_with(b"crlf\r\n")).unwrap().as_str(), "crlf");
        assert_eq!(read_password_fd(pipe_with(b"no newline")).unwrap().as_str(), "no newline");
        assert!(read_password_fd(pipe_with(&vec![b'a'; MAX_PASSWORD_BYTES + 1])).is_err());
        assert!(read_password_fd(0).is_err() && read_password_fd(2).is_err(), "stdio is refused");
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
        let (signer, _uuid) =
            PrivateKeySigner::encrypt_keystore(dir.path(), &mut rand::thread_rng(), key, "pw", Some("k")).unwrap();
        let path = dir.path().join("k");
        let pw = Zeroizing::new("pw".to_string());
        assert_eq!(decrypt(&path, &pw).unwrap().address(), signer.address());
        assert!(decrypt(&path, &Zeroizing::new("no".into())).is_err());
        let fd = pipe_with(b"pw\n");
        let c = ZkMinerConfig::default();
        assert_eq!(load(&path, PasswordSource::Fd(fd), &c).unwrap().address(), signer.address());
    }
}
