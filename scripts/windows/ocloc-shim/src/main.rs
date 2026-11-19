//! Stands in for Intel's `ocloc` in build-windows.yml's Intel risc0 build.
//!
//! The SYCL compiler runs `ocloc -output OUT -file IN.spv -output_no_suffix -spirv_input -device D
//! [-options ...]` to compile each kernel library's SPIR-V into a device image ahead of time. On
//! Windows that is oneAPI's ocloc, whose IGC has a quadratic (MergeAllocas) that takes hours per
//! target for risc0's rv32im kernels; on Linux, zk-miner builds IGC from source with it fixed. So
//! the Windows build records what it would compile, a Linux job compiles it with the fixed ocloc
//! (`compile-ocloc-records.sh`), and the Windows build replays the results.
//!
//! Every call is keyed by the SHA-256 of its SPIR-V and its arguments other than the two paths, so
//! a replayed image is the one for exactly that input. `ZKMINER_OCLOC_MODE`:
//!
//! - `record`: saves `<store>/<key>/input.spv` and `args` (one per line), and writes the SPIR-V
//!   as the output so the build completes; a build made this way is never shipped.
//! - `replay`: copies `<store>/<key>/output.bin` to the output. A key with no image is compiled
//!   by the real ocloc, as without the shim, unless `ZKMINER_OCLOC_STRICT=1`.
//! - unset: runs the real ocloc.
//!
//! `ZKMINER_OCLOC_REAL` is the real ocloc; `ZKMINER_OCLOC_STORE` the record directory. Calls that
//! are not a single SPIR-V file compiled to one output always run the real ocloc.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

fn main() -> ExitCode {
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    let real = match std::env::var_os("ZKMINER_OCLOC_REAL") {
        Some(real) => PathBuf::from(real),
        None => {
            eprintln!("ocloc-shim: ZKMINER_OCLOC_REAL is not set");
            return ExitCode::from(2);
        }
    };
    let mode = std::env::var("ZKMINER_OCLOC_MODE").unwrap_or_default();
    let store = std::env::var_os("ZKMINER_OCLOC_STORE").map(PathBuf::from);
    let call = (mode == "record" || mode == "replay")
        .then(|| Call::parse(&args))
        .flatten();
    let (Some(call), Some(store)) = (call, store) else {
        return run_real(&real, &args);
    };
    let spirv = match std::fs::read(&call.input) {
        Ok(spirv) => spirv,
        Err(e) => {
            eprintln!("ocloc-shim: reading {}: {e}", call.input.display());
            return ExitCode::from(2);
        }
    };
    let key = call.key(&spirv);
    let dir = store.join(&key);
    let result = if mode == "record" {
        record(&dir, &call, &spirv)
    } else {
        let image = dir.join("output.bin");
        if image.is_file() {
            std::fs::copy(&image, &call.output).map(|_| ())
        } else if std::env::var("ZKMINER_OCLOC_STRICT").as_deref() == Ok("1") {
            eprintln!("ocloc-shim: no image for {key} ({})", call.describe());
            return ExitCode::from(1);
        } else {
            eprintln!("ocloc-shim: no image for {key} ({}); compiling it here", call.describe());
            return run_real(&real, &args);
        }
    };
    match result {
        Ok(()) => {
            eprintln!("ocloc-shim: {mode} {key} ({})", call.describe());
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("ocloc-shim: {mode} {key}: {e}");
            ExitCode::from(2)
        }
    }
}

fn run_real(real: &Path, args: &[OsString]) -> ExitCode {
    match Command::new(real).args(args).status() {
        Ok(status) => ExitCode::from(status.code().unwrap_or(1).clamp(0, 255) as u8),
        Err(e) => {
            eprintln!("ocloc-shim: running {}: {e}", real.display());
            ExitCode::from(2)
        }
    }
}

fn record(dir: &Path, call: &Call, spirv: &[u8]) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    std::fs::write(dir.join("input.spv"), spirv)?;
    std::fs::write(dir.join("args"), call.rest.join("\n") + "\n")?;
    // The output is never used: write the SPIR-V so the steps after ocloc have a file.
    std::fs::write(&call.output, spirv)
}

/// A single-file SPIR-V compile: `-file`, `-output`, and the rest of the arguments.
struct Call {
    input: PathBuf,
    output: PathBuf,
    /// Every other argument, in order, which determines the image.
    rest: Vec<String>,
}

impl Call {
    fn parse(args: &[OsString]) -> Option<Self> {
        let mut input = None;
        let mut output = None;
        let mut rest = Vec::new();
        let mut it = args.iter();
        while let Some(arg) = it.next() {
            let arg = arg.to_str()?;
            match arg {
                "-file" => input = Some(PathBuf::from(it.next()?)),
                "-output" => output = Some(PathBuf::from(it.next()?)),
                _ => rest.push(arg.to_string()),
            }
        }
        let wanted = ["-spirv_input", "-output_no_suffix", "-device"];
        if !wanted.iter().all(|w| rest.iter().any(|a| a == w)) {
            return None;
        }
        // One device per call: a list (`-device a,b`) produces an archive this does not model.
        let device = rest.iter().position(|a| a == "-device").and_then(|i| rest.get(i + 1))?;
        if device.contains(',') {
            return None;
        }
        Some(Self { input: input?, output: output?, rest })
    }

    fn key(&self, spirv: &[u8]) -> String {
        let mut data = spirv.to_vec();
        for arg in &self.rest {
            data.push(0);
            data.extend_from_slice(arg.as_bytes());
        }
        sha256_hex(&data)
    }

    fn describe(&self) -> String {
        self.rest.join(" ")
    }
}

/// SHA-256 (FIPS 180-4), so the shim needs no dependencies.
fn sha256_hex(data: &[u8]) -> String {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    let mut msg = data.to_vec();
    let bits = (data.len() as u64).wrapping_mul(8);
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bits.to_be_bytes());
    for block in msg.chunks_exact(64) {
        let mut w = [0u32; 64];
        for (i, word) in block.chunks_exact(4).enumerate() {
            w[i] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = h;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ (!e & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        for (x, y) in h.iter_mut().zip([a, b, c, d, e, f, g, hh]) {
            *x = x.wrapping_add(y);
        }
    }
    h.iter().map(|x| format!("{x:08x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_matches_the_standard_vectors() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        let long = vec![b'a'; 1_000_000];
        assert_eq!(
            sha256_hex(&long),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        );
    }

    #[test]
    fn a_compile_call_is_parsed_without_its_paths() {
        let args: Vec<OsString> = [
            "-output", "out.bin", "-file", "in.spv", "-output_no_suffix", "-spirv_input",
            "-device", "acm_g10", "-options", "-cl-intel-256-GRF-per-thread",
        ]
        .iter()
        .map(OsString::from)
        .collect();
        let call = Call::parse(&args).unwrap();
        assert_eq!(call.input, PathBuf::from("in.spv"));
        assert_eq!(call.output, PathBuf::from("out.bin"));
        assert_eq!(
            call.rest,
            ["-output_no_suffix", "-spirv_input", "-device", "acm_g10", "-options",
             "-cl-intel-256-GRF-per-thread"]
        );
        // The key does not depend on the paths.
        let moved: Vec<OsString> = args
            .iter()
            .map(|a| match a.to_str().unwrap() {
                "out.bin" => OsString::from("elsewhere.out"),
                _ => a.clone(),
            })
            .collect();
        assert_eq!(call.key(b"spv"), Call::parse(&moved).unwrap().key(b"spv"));
    }

    #[test]
    fn a_device_list_runs_the_real_ocloc() {
        let args: Vec<OsString> = ["-output", "o", "-file", "i", "-output_no_suffix", "-spirv_input",
            "-device", "bmg-g21,bmg-g31"]
            .iter()
            .map(OsString::from)
            .collect();
        assert!(Call::parse(&args).is_none());
    }
}
