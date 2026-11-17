//! SP1's executor runner, placed before the worker confines itself ([`place_executor_runner`]).

/// The prefix of the name SP1's executor gives its runner in the temporary directory, followed by
/// the SHA-256 of the runner's bytes in hex.
pub(crate) const RUNNER_PREFIX: &str = "sp1-native-runner-bin-";

/// SP1's executor runs every guest in a runner binary embedded in this executable, which it unpacks
/// on first use into the temporary directory as `sp1-native-runner-bin-<sha256>` and makes
/// executable with a `chmod`, which a confined worker may not make. So, before the confinement, the
/// worker puts the runner there itself, without running anything: the executor then finds a file
/// with exactly its bytes in place and uses it as it is.
///
/// The runner is found in this executable (`/proc/self/exe`): the one ELF image of this machine
/// whose SHA-256 the executable also holds as 64 hex digits (the name the SDK gives it). Anything
/// else (no such image, two) is an error, and the worker then runs no guest. Its path.
pub(crate) fn place_executor_runner(dir: &std::path::Path) -> Result<std::path::PathBuf, String> {
    use sha2::{Digest, Sha256};
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let exe =
        std::fs::read("/proc/self/exe").map_err(|e| format!("reading this executable: {e}"))?;
    let (hash, image) = embedded_runner(&exe)?;
    let target = dir.join(format!("{RUNNER_PREFIX}{hash}"));
    let executable = std::fs::Permissions::from_mode(0o755);
    if std::fs::read(&target).is_ok_and(|existing| existing == image) {
        std::fs::set_permissions(&target, executable)
            .map_err(|e| format!("{}: {e}", target.display()))?;
        return Ok(target);
    }
    let tmp = dir.join(format!(".{RUNNER_PREFIX}{hash}.{}", std::process::id()));
    let _ = std::fs::remove_file(&tmp);
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o700)
        .open(&tmp)
        .map_err(|e| format!("{}: {e}", tmp.display()))?;
    f.write_all(image)
        .and_then(|()| f.set_permissions(executable))
        .and_then(|()| f.sync_all())
        .map_err(|e| format!("{}: {e}", tmp.display()))?;
    drop(f);
    std::fs::rename(&tmp, &target).map_err(|e| format!("{}: {e}", target.display()))?;
    // What the SDK will compare: the bytes, by hash.
    let written = std::fs::read(&target).map_err(|e| format!("{}: {e}", target.display()))?;
    if hex32(&Sha256::digest(&written)) != hash {
        return Err(format!("{} does not hold the runner", target.display()));
    }
    Ok(target)
}

pub(crate) fn hex32(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The embedded runner in `exe`: its SHA-256 (hex) and its bytes. See [`place_executor_runner`].
pub(crate) fn embedded_runner(exe: &[u8]) -> Result<(String, &[u8]), String> {
    use sha2::{Digest, Sha256};
    #[cfg(target_arch = "x86_64")]
    const MACHINE: u16 = 62;
    #[cfg(target_arch = "aarch64")]
    const MACHINE: u16 = 183;
    // Every run of exactly 64 lowercase hex digits.
    let is_hex = |b: u8| b.is_ascii_digit() || (b'a'..=b'f').contains(&b);
    let mut hashes = std::collections::HashSet::new();
    let mut i = 0;
    while i < exe.len() {
        if !is_hex(exe[i]) {
            i += 1;
            continue;
        }
        let start = i;
        while i < exe.len() && is_hex(exe[i]) {
            i += 1;
        }
        if i - start == 64 {
            hashes.insert(&exe[start..i]);
        }
    }
    let u16_at = |o: usize| exe.get(o..o + 2).map(|b| u16::from_le_bytes([b[0], b[1]]));
    let u64_at = |o: usize| {
        exe.get(o..o + 8)
            .map(|b| u64::from_le_bytes(b.try_into().expect("8 bytes")))
    };
    let mut found: Vec<(String, &[u8])> = Vec::new();
    const MAGIC: &[u8] = b"\x7fELF\x02\x01\x01";
    let mut at = 1;
    while let Some(off) = exe[at..].iter().position(|&b| b == MAGIC[0]) {
        let start = at + off;
        at = start + 1;
        if exe.get(start..start + MAGIC.len()) != Some(MAGIC) {
            continue;
        }
        // An executable or shared object of this machine (the guests embedded beside it are
        // RISC-V).
        if u16_at(start + 0x12) != Some(MACHINE) {
            continue;
        }
        let (Some(phoff), Some(shoff), Some(phentsize), Some(phnum), Some(shentsize), Some(shnum)) = (
            u64_at(start + 0x20),
            u64_at(start + 0x28),
            u16_at(start + 0x36),
            u16_at(start + 0x38),
            u16_at(start + 0x3a),
            u16_at(start + 0x3c),
        ) else {
            continue;
        };
        // Its size: the end of the section headers or of the last segment, whichever is later.
        let mut end = shoff.saturating_add(u64::from(shnum) * u64::from(shentsize));
        for k in 0..u64::from(phnum) {
            let ph = phoff.saturating_add(k * u64::from(phentsize));
            let (Some(offset), Some(filesz)) = (
                usize::try_from(ph.saturating_add(8))
                    .ok()
                    .and_then(|o| u64_at(start + o)),
                usize::try_from(ph.saturating_add(32))
                    .ok()
                    .and_then(|o| u64_at(start + o)),
            ) else {
                continue;
            };
            end = end.max(offset.saturating_add(filesz));
        }
        let Some(image) = usize::try_from(end)
            .ok()
            .and_then(|end| exe.get(start..start.checked_add(end)?))
        else {
            continue;
        };
        let hash = hex32(&Sha256::digest(image));
        if hashes.contains(hash.as_bytes()) && !found.iter().any(|(h, _)| *h == hash) {
            found.push((hash, image));
        }
    }
    match found.len() {
        1 => Ok(found.remove(0)),
        0 => Err("no embedded executor runner found in this executable".into()),
        n => Err(format!(
            "{n} images in this executable could be the executor runner"
        )),
    }
}

#[cfg(test)]
mod tests {
    use sha2::{Digest, Sha256};

    /// A minimal ELF header of `machine` (no sections, no segments: 64 bytes long), marked by `tag`.
    fn elf(machine: u16, tag: u8) -> Vec<u8> {
        let mut h = vec![0u8; 64];
        h[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        h[0x12..0x14].copy_from_slice(&machine.to_le_bytes());
        h[0x28..0x30].copy_from_slice(&64u64.to_le_bytes());
        h[0x3a..0x3c].copy_from_slice(&64u16.to_le_bytes());
        h[0x10] = tag;
        h
    }

    fn hex(b: &[u8]) -> Vec<u8> {
        super::hex32(&Sha256::digest(b)).into_bytes()
    }

    #[test]
    fn the_runner_is_the_one_image_named_by_a_hash_in_the_executable() {
        #[cfg(target_arch = "x86_64")]
        let (host, other) = (62u16, 243u16);
        #[cfg(target_arch = "aarch64")]
        let (host, other) = (183u16, 243u16);
        let runner = elf(host, 1);
        let guest = elf(other, 2);
        let unnamed = elf(host, 3);
        let mut exe = b"\x7fELF-of-the-executable-itself ".to_vec();
        for part in [&runner, &guest, &unnamed] {
            exe.extend_from_slice(part);
            exe.push(b' ');
        }
        exe.extend_from_slice(&hex(&runner));
        exe.extend_from_slice(b" ");
        exe.extend_from_slice(&hex(&guest));
        let (hash, image) = super::embedded_runner(&exe).unwrap();
        assert_eq!(image, &runner[..]);
        assert_eq!(hash.into_bytes(), hex(&runner));
        // A hash inside a longer hex run names nothing.
        let mut longer = exe.clone();
        let at = longer.len() - 64 - 1 - 64;
        longer.insert(at, b'a');
        assert!(super::embedded_runner(&longer).is_err());
        // Two candidates: refused.
        exe.extend_from_slice(b" ");
        exe.extend_from_slice(&hex(&unnamed));
        assert!(super::embedded_runner(&exe).is_err());
        assert!(super::embedded_runner(b"nothing here").is_err());
    }

    /// This test binary embeds the SDK's runner as the worker does: it is found and placed, and a
    /// later call leaves it as it is.
    #[test]
    fn the_runner_is_placed_where_the_sdk_looks_for_it() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = super::place_executor_runner(dir.path()).unwrap();
        let name = path.file_name().unwrap().to_str().unwrap().to_string();
        let bytes = std::fs::read(&path).unwrap();
        assert_eq!(
            name,
            format!(
                "{}{}",
                super::RUNNER_PREFIX,
                super::hex32(&Sha256::digest(&bytes))
            )
        );
        assert!(bytes.starts_with(b"\x7fELF"));
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o755);
        let again = super::place_executor_runner(dir.path()).unwrap();
        assert_eq!(again, path);
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
        // A file of the name with other bytes is replaced.
        std::fs::write(&path, b"not the runner").unwrap();
        super::place_executor_runner(dir.path()).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
        assert_eq!(
            std::fs::read_dir(dir.path()).unwrap().count(),
            1,
            "no temporary file left"
        );
    }
}
