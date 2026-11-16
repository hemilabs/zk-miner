//! The key the risc0 workers seed the guest's `sys_rand` with, one per host, kept in
//! `~/.zkminer/risc0-sys-rand.key`. The miner loads it once and hands it to every risc0 worker it
//! spawns through [`SYS_RAND_KEY_ENV`], so they all seed alike for as long as the miner's
//! measurements live, whatever happens to the file meanwhile. A worker started on its own (a
//! benchmark) reads the file itself.

use std::io;
use std::path::{Path, PathBuf};

/// Carries the key, hex-encoded, from the miner to each risc0 worker it spawns.
pub const SYS_RAND_KEY_ENV: &str = "ZKMINER_RISC0_SYS_RAND_KEY";

/// Set to `1` beside [`SYS_RAND_KEY_ENV`] when the key is for this miner run only (the file was
/// unusable): the workers still agree with each other, but a lock re-proved after a restart would
/// not, so they report no journal to check a binding against.
pub const SYS_RAND_KEY_EPHEMERAL_ENV: &str = "ZKMINER_RISC0_SYS_RAND_EPHEMERAL";

/// Where the key lives under `home`.
pub fn key_path(home: &Path) -> PathBuf {
    home.join(".zkminer").join("risc0-sys-rand.key")
}

/// Read the 32-byte key at `path`, first creating it with fresh OS randomness if it doesn't exist.
///
/// A new key is written to a private temporary file and then hard-linked into place, so processes
/// starting together agree: one link wins and the rest read the winner's complete file.
pub fn load_or_create_key(path: &Path) -> io::Result<[u8; 32]> {
    use std::io::Write;
    use std::sync::atomic::{AtomicU64, Ordering};

    let annotate = |what: &str, e: io::Error| io::Error::new(e.kind(), format!("{what}: {e}"));
    if !path.exists() {
        let dir = path
            .parent()
            .ok_or_else(|| io::Error::other("key path has no directory"))?;
        std::fs::create_dir_all(dir)
            .map_err(|e| annotate(&format!("create {}", dir.display()), e))?;
        let mut key = [0u8; 32];
        getrandom::fill(&mut key).map_err(|e| io::Error::other(format!("OS randomness: {e}")))?;

        static TMP: AtomicU64 = AtomicU64::new(0);
        let tmp = dir.join(format!(
            ".risc0-sys-rand.key.{}.{}",
            std::process::id(),
            TMP.fetch_add(1, Ordering::Relaxed)
        ));
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
        let written = opts.open(&tmp).and_then(|mut f| {
            f.write_all(&key)?;
            f.sync_all()
        });
        let linked = written.and_then(|()| std::fs::hard_link(&tmp, path));
        let _ = std::fs::remove_file(&tmp);
        match linked {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(annotate(&format!("create {}", path.display()), e)),
        }
    }
    let bytes =
        std::fs::read(path).map_err(|e| annotate(&format!("read {}", path.display()), e))?;
    <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{} holds {} bytes, not 32", path.display(), bytes.len()),
        )
    })
}

/// This host's key from the file under `home`, else (with the reason) a fresh one for this process
/// alone: workers given it still all agree with each other for as long as this process runs.
pub fn host_key(home: Option<&Path>) -> ([u8; 32], Option<io::Error>) {
    let loaded = match home {
        Some(home) => load_or_create_key(&key_path(home)),
        None => Err(io::Error::other("no home directory")),
    };
    match loaded {
        Ok(key) => (key, None),
        Err(e) => {
            let mut key = [0u8; 32];
            getrandom::fill(&mut key).expect("no OS randomness for the sys_rand key");
            (key, Some(e))
        }
    }
}

/// The key as [`SYS_RAND_KEY_ENV`] carries it.
pub fn encode_key(key: &[u8; 32]) -> String {
    key.iter().map(|b| format!("{b:02x}")).collect()
}

/// The domain tag of [`risc0_seed`].
pub const RISC0_SEED_TAG: &[u8] = b"zkminer/risc0/sys_rand/v2";

/// The guest's `sys_rand` seed for one (program, input): `HMAC-SHA256(key, RISC0_SEED_TAG ‖
/// image_id ‖ input_sha256)`, where `input_sha256` is `sha256` of the guest's whole input (for a
/// witness job, the bundle's `sha256(prefix ‖ W)`).
///
/// The risc0 prove workers derive the same seed from the key they hold (`sys_rand_seed` in
/// zkminer-prove-risc0); the miner derives it here and hands the SEED, never the key, to a sandboxed
/// witness execute (`WitnessExecuteRequest::sys_rand_seed`), so the execute and every later proof
/// of the bundle run the guest alike.
pub fn risc0_seed(key: &[u8; 32], image_id: &[u8; 32], input_sha256: &[u8; 32]) -> [u8; 32] {
    use hmac::{Hmac, Mac};
    let mut mac =
        <Hmac<sha2::Sha256> as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(RISC0_SEED_TAG);
    mac.update(image_id);
    mac.update(input_sha256);
    mac.finalize().into_bytes().into()
}

/// The domain tag of [`key_fingerprint`].
pub const KEY_FINGERPRINT_TAG: &[u8] = b"zkminer/risc0/sys_rand/key-fingerprint/v1";

/// A public fingerprint of the host key: `HMAC-SHA256(key, KEY_FINGERPRINT_TAG)`. A witness bundle
/// records it (`BundleV1::sys_rand_key_fingerprint`), and revalidation compares it with the host's
/// (plan §15.2), so a bundle executed under another key is never proven as if its journals still
/// held. It reveals nothing about the key, and no seed can collide with it (a different tag).
pub fn key_fingerprint(key: &[u8; 32]) -> [u8; 32] {
    use hmac::{Hmac, Mac};
    let mut mac =
        <Hmac<sha2::Sha256> as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(KEY_FINGERPRINT_TAG);
    mac.finalize().into_bytes().into()
}

/// The key from [`SYS_RAND_KEY_ENV`]'s value; `None` unless it is exactly 64 hex digits.
pub fn decode_key(s: &str) -> Option<[u8; 32]> {
    let s = s.as_bytes();
    if s.len() != 64 {
        return None;
    }
    let nibble = |c: u8| char::from(c).to_digit(16);
    let mut key = [0u8; 32];
    for (i, pair) in s.chunks(2).enumerate() {
        key[i] = (nibble(pair[0])? * 16 + nibble(pair[1])?) as u8;
    }
    Some(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_file_is_created_once_and_shared() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("key");
        let keys: Vec<[u8; 32]> = std::thread::scope(|s| {
            let racers: Vec<_> = (0..8)
                .map(|_| s.spawn(|| load_or_create_key(&path).unwrap()))
                .collect();
            racers.into_iter().map(|r| r.join().unwrap()).collect()
        });
        assert!(keys.iter().all(|k| *k == keys[0]));
        assert_eq!(load_or_create_key(&path).unwrap(), keys[0]);
        assert_eq!(std::fs::read(&path).unwrap(), keys[0]);
        // No temporary file is left behind.
        assert_eq!(
            std::fs::read_dir(path.parent().unwrap()).unwrap().count(),
            1
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }

    #[test]
    fn a_key_file_of_the_wrong_size_is_refused_and_left_alone() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("key");
        std::fs::write(&path, [0u8; 31]).unwrap();
        assert!(load_or_create_key(&path).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), [0u8; 31]);
    }

    #[test]
    fn the_seed_is_fixed_by_key_image_id_and_input_hash() {
        let (key, image, input) = ([1u8; 32], [7u8; 32], [9u8; 32]);
        let seed = risc0_seed(&key, &image, &input);
        assert_eq!(risc0_seed(&key, &image, &input), seed);
        assert_ne!(risc0_seed(&[2u8; 32], &image, &input), seed);
        assert_ne!(risc0_seed(&key, &[8u8; 32], &input), seed);
        assert_ne!(risc0_seed(&key, &image, &[10u8; 32]), seed);
        // RFC 2104 over the documented message, computed independently of the function.
        use hmac::{Hmac, Mac};
        let mut mac = <Hmac<sha2::Sha256> as Mac>::new_from_slice(&key).unwrap();
        mac.update(&[RISC0_SEED_TAG, &image[..], &input[..]].concat());
        assert_eq!(<[u8; 32]>::from(mac.finalize().into_bytes()), seed);
    }

    #[test]
    fn the_fingerprint_is_fixed_by_the_key_and_is_no_seed() {
        let key = [3u8; 32];
        let fp = key_fingerprint(&key);
        assert_eq!(key_fingerprint(&key), fp);
        assert_ne!(key_fingerprint(&[4u8; 32]), fp);
        assert_ne!(fp, key);
        use hmac::{Hmac, Mac};
        let mut mac = <Hmac<sha2::Sha256> as Mac>::new_from_slice(&key).unwrap();
        mac.update(KEY_FINGERPRINT_TAG);
        assert_eq!(<[u8; 32]>::from(mac.finalize().into_bytes()), fp);
        assert_ne!(KEY_FINGERPRINT_TAG, RISC0_SEED_TAG);
    }

    #[test]
    fn the_key_round_trips_through_its_env_encoding() {
        let key: [u8; 32] = std::array::from_fn(|i| (i * 37 + 5) as u8);
        assert_eq!(decode_key(&encode_key(&key)), Some(key));
        assert_eq!(decode_key(&encode_key(&key).to_uppercase()), Some(key));
        assert_eq!(decode_key(&encode_key(&key)[2..]), None);
        assert_eq!(decode_key(&format!("{}0", encode_key(&key))), None);
        assert_eq!(decode_key(&"zz".repeat(32)), None);
        assert_eq!(decode_key(&"+1".repeat(32)), None);
    }
}
