//! Which NVIDIA GPUs a CUDA binary can run on, read from the device code it carries.
//!
//! nvcc embeds device code in "fatbin" containers: one or more entries, each either native code
//! (SASS) for one architecture or PTX, which the driver compiles for the card at load time. A card of
//! compute capability `X.y` can run:
//!
//! * SASS built for `X.z` with `z <= y` — native code runs within its major architecture, upward
//!   only (sm_80 code runs on an sm_86 card; sm_89 code does not run on sm_86, nor on sm_90);
//! * PTX built for any compute capability `<= X.y`.
//!
//! A card that can run neither for some container fails every kernel launch in it with
//! `no kernel image is available for execution on the device`. Nothing notices that earlier: CUDA
//! initialises lazily, so the worker handshakes, the `sp1-gpu-server --version` probe passes, and the
//! first REAL proof is the first thing to touch the device code. A slot on such a card is advertised
//! as healthy and claims work it can never prove — which is why the dispatcher reads this before
//! starting a worker at all.
//!
//! Only `.nv_fatbin` counts. It is what the CUDA runtime registers and loads. A binary built with
//! relocatable device code (`-rdc`) also carries each object's own fatbin in `__nv_relfatbin`, which
//! only the device linker consumes; it can hold PTX the loaded image does not. In the sp1-gpu-server
//! built for sm_89 and sm_120, all 41 of those objects carry PTX for compute 8.9 and 12.0, while the
//! one container in `.nv_fatbin` carries SASS only — so counting them would wrongly clear an sm_90
//! card to run it.
//!
//! Every container must be runnable, not merely one. Each is a separately loaded module, and a
//! kernel in a module the card cannot load fails however many others it can.
//!
//! Anything this cannot read — not a 64-bit little-endian ELF (a wrapper script, say), no
//! `.nv_fatbin`, or a container laid out in a way it does not recognise — is reported as unknown,
//! never as unrunnable. The cost of a wrong "no" is a card left idle; the caller must not pay that
//! for a binary it simply failed to parse.

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;

/// The section whose fatbins the CUDA runtime registers and loads.
const LOADED_SECTION: &[u8] = b".nv_fatbin";
/// A fatbin container's first four bytes.
const FATBIN_MAGIC: u32 = 0xBA55_ED50;
/// Entry kinds. Others (LTO IR, for one) cannot be run as they stand, so they count for nothing.
const KIND_PTX: u16 = 1;
const KIND_SASS: u16 = 2;
/// Bounds on what this will read, so a corrupt header cannot make it allocate the moon.
const MAX_SECTIONS: u64 = 1 << 16;
const MAX_SECTION_NAMES: u64 = 16 << 20;

/// The device code a binary loads at runtime: one container per loaded module.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmbeddedGpuCode {
    containers: Vec<Container>,
}

/// One fatbin container: the architectures its entries were built for, as nvcc numbers them
/// (`89` for sm_89, `120` for sm_120).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Container {
    sass: Vec<u32>,
    ptx: Vec<u32>,
}

impl Container {
    fn runs_on(&self, (major, minor): (u32, u32)) -> bool {
        self.sass
            .iter()
            .any(|&a| a / 10 == major && a % 10 <= minor)
            || self.ptx.iter().any(|&a| a <= major * 10 + minor)
    }
}

impl EmbeddedGpuCode {
    /// The device code `path` loads, or `None` if it carries none this can see (see the module docs).
    pub fn read(path: &Path) -> io::Result<Option<Self>> {
        Self::from_reader(&mut File::open(path)?)
    }

    fn from_reader<R: Read + Seek>(r: &mut R) -> io::Result<Option<Self>> {
        let Some((offset, size)) = find_section(r, LOADED_SECTION)? else {
            return Ok(None);
        };
        let Some(containers) = read_containers(r, offset, size)? else {
            return Ok(None);
        };
        Ok((!containers.is_empty()).then_some(Self { containers }))
    }

    /// Whether a card of compute capability `(major, minor)` can run every module this carries.
    pub fn runs_on(&self, cap: (u32, u32)) -> bool {
        self.containers.iter().all(|c| c.runs_on(cap))
    }

    /// The architectures carried, for a log line: `sm_89, sm_120` and any PTX after it.
    pub fn describe(&self) -> String {
        let collect = |pick: fn(&Container) -> &Vec<u32>| {
            let mut archs: Vec<u32> = self.containers.iter().flat_map(pick).copied().collect();
            archs.sort_unstable();
            archs.dedup();
            archs
        };
        let list = |prefix: &str, archs: &[u32]| {
            archs
                .iter()
                .map(|a| format!("{prefix}_{a}"))
                .collect::<Vec<_>>()
                .join(", ")
        };
        let (sass, ptx) = (collect(|c| &c.sass), collect(|c| &c.ptx));
        match (sass.is_empty(), ptx.is_empty()) {
            (_, true) => list("sm", &sass),
            (true, false) => format!("PTX {}", list("compute", &ptx)),
            (false, false) => format!("{}, PTX {}", list("sm", &sass), list("compute", &ptx)),
        }
    }
}

fn read_at<R: Read + Seek>(r: &mut R, offset: u64, buf: &mut [u8]) -> io::Result<bool> {
    r.seek(SeekFrom::Start(offset))?;
    match r.read_exact(buf) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => Ok(false),
        Err(e) => Err(e),
    }
}

fn u16_at(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes(b[at..at + 2].try_into().unwrap())
}
fn u32_at(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
}
fn u64_at(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().unwrap())
}

/// `(file offset, size)` of the named section of a 64-bit little-endian ELF, or `None` if `r` is no
/// such ELF or has no such section.
fn find_section<R: Read + Seek>(r: &mut R, name: &[u8]) -> io::Result<Option<(u64, u64)>> {
    let mut eh = [0u8; 64];
    if !read_at(r, 0, &mut eh)? || &eh[..4] != b"\x7fELF" || eh[4] != 2 || eh[5] != 1 {
        return Ok(None);
    }
    let (shoff, shentsize) = (u64_at(&eh, 0x28), u64::from(u16_at(&eh, 0x3A)));
    let (mut shnum, mut shstrndx) = (u64::from(u16_at(&eh, 0x3C)), u64::from(u16_at(&eh, 0x3E)));
    if shoff == 0 || shentsize < 64 {
        return Ok(None);
    }
    // Section 0 holds the real count and string-table index when they overflow 16 bits.
    let mut sh0 = [0u8; 64];
    if !read_at(r, shoff, &mut sh0)? {
        return Ok(None);
    }
    if shnum == 0 {
        shnum = u64_at(&sh0, 32);
    }
    if shstrndx == 0xFFFF {
        shstrndx = u64::from(u32_at(&sh0, 40));
    }
    if shnum == 0 || shnum > MAX_SECTIONS || shstrndx >= shnum {
        return Ok(None);
    }
    let mut headers = vec![0u8; (shnum * shentsize) as usize];
    if !read_at(r, shoff, &mut headers)? {
        return Ok(None);
    }
    let header = |i: u64| &headers[(i * shentsize) as usize..(i * shentsize + 64) as usize];
    let (names_off, names_len) = (u64_at(header(shstrndx), 24), u64_at(header(shstrndx), 32));
    if names_len > MAX_SECTION_NAMES {
        return Ok(None);
    }
    let mut names = vec![0u8; names_len as usize];
    if !read_at(r, names_off, &mut names)? {
        return Ok(None);
    }
    for i in 0..shnum {
        let h = header(i);
        let at = u32_at(h, 0) as usize;
        let Some(rest) = names.get(at..) else {
            continue;
        };
        let this = rest.split(|&c| c == 0).next().unwrap_or_default();
        // SHT_NOBITS has no bytes in the file to read.
        if this == name && u32_at(h, 4) != 8 {
            return Ok(Some((u64_at(h, 24), u64_at(h, 32))));
        }
    }
    Ok(None)
}

/// The containers in `size` bytes at `offset`, or `None` if they are not laid out as expected.
///
/// Container header: `u32 magic, u16 version, u16 header size, u64 size of the entries after it`.
/// Entry header: `u16 kind, u16 _, u32 header size, u64 payload size, ..., u32 arch at byte 28`.
/// Only headers are read; the code itself is skipped over.
fn read_containers<R: Read + Seek>(
    r: &mut R,
    offset: u64,
    size: u64,
) -> io::Result<Option<Vec<Container>>> {
    let end = offset.saturating_add(size);
    let mut containers = Vec::new();
    let mut pos = offset;
    while pos + 16 <= end {
        let mut ch = [0u8; 16];
        if !read_at(r, pos, &mut ch)? {
            return Ok(None);
        }
        if u32_at(&ch, 0) != FATBIN_MAGIC {
            // Containers are aligned, and the gap between two is zero padding. Anything else means
            // this is not a section of containers after all.
            if ch[..8].iter().all(|&b| b == 0) {
                pos += 8;
                continue;
            }
            return Ok(None);
        }
        let (version, header_len, entries_len) =
            (u16_at(&ch, 4), u64::from(u16_at(&ch, 6)), u64_at(&ch, 8));
        let container_end = pos.saturating_add(header_len).saturating_add(entries_len);
        if version != 1 || header_len < 16 || container_end > end {
            return Ok(None);
        }
        let mut container = Container::default();
        let mut e = pos + header_len;
        while e + 32 <= container_end {
            let mut eh = [0u8; 32];
            if !read_at(r, e, &mut eh)? {
                return Ok(None);
            }
            let (kind, entry_header_len, payload_len) =
                (u16_at(&eh, 0), u64::from(u32_at(&eh, 4)), u64_at(&eh, 8));
            let entry_end = e
                .saturating_add(entry_header_len)
                .saturating_add(payload_len);
            if entry_header_len < 32 || entry_end > container_end {
                return Ok(None);
            }
            match kind {
                KIND_SASS => container.sass.push(u32_at(&eh, 28)),
                KIND_PTX => container.ptx.push(u32_at(&eh, 28)),
                _ => {}
            }
            e = entry_end;
        }
        containers.push(container);
        pos = container_end;
    }
    Ok(Some(containers))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// One fatbin entry: a 64-byte header and `payload` bytes of stand-in code.
    fn entry(kind: u16, arch: u32, payload: usize) -> Vec<u8> {
        let mut h = vec![0u8; 64];
        h[0..2].copy_from_slice(&kind.to_le_bytes());
        h[2..4].copy_from_slice(&0x0101u16.to_le_bytes());
        h[4..8].copy_from_slice(&64u32.to_le_bytes());
        h[8..16].copy_from_slice(&(payload as u64).to_le_bytes());
        h[28..32].copy_from_slice(&arch.to_le_bytes());
        h.extend(std::iter::repeat_n(0xAB, payload));
        h
    }

    fn container(entries: &[(u16, u32)]) -> Vec<u8> {
        let body: Vec<u8> = entries.iter().flat_map(|&(k, a)| entry(k, a, 40)).collect();
        let mut c = Vec::new();
        c.extend(FATBIN_MAGIC.to_le_bytes());
        c.extend(1u16.to_le_bytes());
        c.extend(16u16.to_le_bytes());
        c.extend((body.len() as u64).to_le_bytes());
        c.extend(body);
        c
    }

    /// A minimal ELF64 LE: section 0, the named sections in order, then `.shstrtab`.
    fn elf(sections: &[(&str, Vec<u8>)]) -> Vec<u8> {
        let mut names = vec![0u8];
        let mut name_at = Vec::new();
        for (n, _) in sections {
            name_at.push(names.len() as u32);
            names.extend(n.as_bytes());
            names.push(0);
        }
        let strtab_name = names.len() as u32;
        names.extend(b".shstrtab\0");

        let mut file = vec![0u8; 64];
        let mut placed = Vec::new();
        for (_, data) in sections {
            placed.push((file.len() as u64, data.len() as u64));
            file.extend(data);
            file.extend(std::iter::repeat_n(0u8, (8 - file.len() % 8) % 8));
        }
        let names_at = file.len() as u64;
        file.extend(&names);
        file.extend(std::iter::repeat_n(0u8, (8 - file.len() % 8) % 8));

        let shoff = file.len() as u64;
        let mut sh = |name: u32, kind: u32, off: u64, size: u64| {
            let mut h = vec![0u8; 64];
            h[0..4].copy_from_slice(&name.to_le_bytes());
            h[4..8].copy_from_slice(&kind.to_le_bytes());
            h[24..32].copy_from_slice(&off.to_le_bytes());
            h[32..40].copy_from_slice(&size.to_le_bytes());
            file.extend(h);
        };
        sh(0, 0, 0, 0);
        for (i, (off, size)) in placed.iter().enumerate() {
            sh(name_at[i], 1, *off, *size);
        }
        sh(strtab_name, 3, names_at, names.len() as u64);

        let count = sections.len() as u16 + 2;
        file[0..4].copy_from_slice(b"\x7fELF");
        file[4] = 2;
        file[5] = 1;
        file[0x28..0x30].copy_from_slice(&shoff.to_le_bytes());
        file[0x3A..0x3C].copy_from_slice(&64u16.to_le_bytes());
        file[0x3C..0x3E].copy_from_slice(&count.to_le_bytes());
        file[0x3E..0x40].copy_from_slice(&(count - 1).to_le_bytes());
        file
    }

    fn parse(bytes: Vec<u8>) -> Option<EmbeddedGpuCode> {
        EmbeddedGpuCode::from_reader(&mut Cursor::new(bytes)).unwrap()
    }

    /// The layout of the sp1-gpu-server the release shipped before this check existed: one loaded
    /// container with SASS for sm_89 and sm_120, and relocatable objects that also carry PTX.
    fn shipped_sp1_server() -> Vec<u8> {
        let relocatable: Vec<u8> = (0..3)
            .flat_map(|_| {
                container(&[
                    (KIND_PTX, 89),
                    (KIND_SASS, 89),
                    (KIND_PTX, 120),
                    (KIND_SASS, 120),
                ])
            })
            .collect();
        elf(&[
            (".text", vec![0x90; 32]),
            ("__nv_relfatbin", relocatable),
            (
                ".nv_fatbin",
                container(&[(KIND_SASS, 89), (KIND_SASS, 120)]),
            ),
        ])
    }

    #[test]
    fn sass_runs_within_its_major_architecture_and_upward_only() {
        let code = parse(elf(&[(".nv_fatbin", container(&[(KIND_SASS, 80)]))])).unwrap();
        assert!(code.runs_on((8, 0)), "A100 runs its own code");
        assert!(code.runs_on((8, 6)), "sm_80 code runs on a 3090");
        assert!(code.runs_on((8, 9)), "and on a 4090");
        assert!(!code.runs_on((7, 5)), "but not down on Turing");
        assert!(!code.runs_on((9, 0)), "nor across to Hopper");
        assert!(!code.runs_on((12, 0)), "nor Blackwell");
    }

    #[test]
    fn ptx_runs_on_its_own_capability_and_every_later_one() {
        let code = parse(elf(&[(".nv_fatbin", container(&[(KIND_PTX, 89)]))])).unwrap();
        assert!(code.runs_on((8, 9)));
        assert!(code.runs_on((9, 0)));
        assert!(code.runs_on((12, 1)));
        assert!(!code.runs_on((8, 6)));
    }

    /// The case this module exists for, on the binary layout that shipped.
    #[test]
    fn the_shipped_sp1_server_runs_only_on_ada_and_blackwell() {
        let code = parse(shipped_sp1_server()).unwrap();
        assert!(code.runs_on((8, 9)), "4090");
        assert!(code.runs_on((12, 0)), "5080/5090");
        assert!(code.runs_on((12, 1)), "sm_120 SASS also runs on 12.1");
        assert!(!code.runs_on((8, 6)), "3090");
        assert!(!code.runs_on((8, 0)), "A100");
        // The relocatable objects' PTX for 8.9 would clear these if it counted. It does not: the
        // runtime never loads it.
        assert!(!code.runs_on((9, 0)), "H100");
        assert!(!code.runs_on((10, 0)), "B200");
        assert_eq!(code.describe(), "sm_89, sm_120");
    }

    #[test]
    fn every_loaded_module_must_be_runnable() {
        let mut both = container(&[(KIND_SASS, 89), (KIND_SASS, 86)]);
        both.extend(container(&[(KIND_SASS, 89)]));
        let code = parse(elf(&[(".nv_fatbin", both)])).unwrap();
        assert!(code.runs_on((8, 9)));
        assert!(
            !code.runs_on((8, 6)),
            "the second module has nothing for sm_86, so its kernels would fail"
        );
    }

    #[test]
    fn padding_between_containers_is_skipped() {
        let mut section = container(&[(KIND_SASS, 89)]);
        section.extend([0u8; 16]);
        section.extend(container(&[(KIND_SASS, 120)]));
        let code = parse(elf(&[(".nv_fatbin", section)])).unwrap();
        assert_eq!(code.containers.len(), 2);
        assert!(!code.runs_on((8, 9)), "the second module is sm_120 only");
    }

    #[test]
    fn entries_that_cannot_run_as_they_stand_count_for_nothing() {
        // Kind 4 is not SASS or PTX (LTO IR, which must be linked before it can run).
        let code = parse(elf(&[(
            ".nv_fatbin",
            container(&[(4, 75), (KIND_SASS, 89)]),
        )]))
        .unwrap();
        assert!(!code.runs_on((7, 5)));
        assert_eq!(code.describe(), "sm_89");
    }

    #[test]
    fn describe_lists_sass_then_ptx() {
        let code = parse(elf(&[(
            ".nv_fatbin",
            container(&[(KIND_SASS, 120), (KIND_SASS, 89), (KIND_PTX, 120)]),
        )]))
        .unwrap();
        assert_eq!(code.describe(), "sm_89, sm_120, PTX compute_120");
        let ptx_only = parse(elf(&[(".nv_fatbin", container(&[(KIND_PTX, 75)]))])).unwrap();
        assert_eq!(ptx_only.describe(), "PTX compute_75");
    }

    /// Unknown is never "cannot run": each of these must come back `None`, not an empty code set
    /// that `runs_on` would refuse every card for.
    #[test]
    fn what_cannot_be_read_is_unknown_not_unrunnable() {
        assert_eq!(
            parse(b"#!/bin/sh\nexec zkminer-prove-sp1.real \"$@\"\n".to_vec()),
            None
        );
        assert_eq!(parse(Vec::new()), None);
        assert_eq!(
            parse(elf(&[(".text", vec![0x90; 64])])),
            None,
            "no device code"
        );
        assert_eq!(
            parse(elf(&[(".nv_fatbin", Vec::new())])),
            None,
            "empty section"
        );
        assert_eq!(
            parse(elf(&[(".nv_fatbin", vec![0x11; 64])])),
            None,
            "not a container"
        );
        let mut truncated = container(&[(KIND_SASS, 89)]);
        truncated.truncate(40);
        assert_eq!(parse(elf(&[(".nv_fatbin", truncated)])), None);
        let mut big_endian = shipped_sp1_server();
        big_endian[5] = 2;
        assert_eq!(parse(big_endian), None);
    }

    /// Reads real binaries, which a unit test cannot ship. Run by hand:
    /// `ZKMINER_GPU_CODE_PROBE=/path/a:/path/b cargo test -p zkminer-prover --lib \
    ///   gpu_code::tests::probe -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn probe() {
        let paths = std::env::var("ZKMINER_GPU_CODE_PROBE").expect("set ZKMINER_GPU_CODE_PROBE");
        let cards = [
            (7, 5),
            (8, 0),
            (8, 6),
            (8, 9),
            (9, 0),
            (10, 0),
            (10, 3),
            (12, 0),
            (12, 1),
        ];
        for path in paths.split(':') {
            match EmbeddedGpuCode::read(Path::new(path)).unwrap() {
                None => println!("{path}: no loaded device code found"),
                Some(code) => {
                    let ok: Vec<String> = cards
                        .iter()
                        .filter(|&&c| code.runs_on(c))
                        .map(|(a, b)| format!("{a}.{b}"))
                        .collect();
                    println!(
                        "{path}: {} module(s), {}; runs on {}",
                        code.containers.len(),
                        code.describe(),
                        ok.join(" ")
                    );
                }
            }
        }
    }
}
