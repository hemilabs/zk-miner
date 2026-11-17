//! The public rule the risc0 workers seed a guest's `sys_rand` with.
//!
//! A guest's random bytes are a public function of its program and input, with no key:
//! `seed = SHA-256(SYS_RAND_DOMAIN || image id || SHA-256(the exact bytes the guest reads))`, and
//! the guest's stream is the fork's `SeedStream` over that seed (block `i` is
//! `SHA-256("risc0-zkvm/sys_rand/v1" || seed || i as a little-endian u64)`; its runtime takes the
//! first 16 bytes before `main`). So a pre-claim measurement, every proof zkminer makes under this
//! rule on any machine, and `zkminer simulate` run a guest alike, and anyone can reproduce the run
//! from public data.
//!
//! The proof does not bind any of this: a prover running other software can answer `sys_rand` with
//! anything, and a job proven before this rule (protocol 13) was seeded by its miner's own key. The
//! rule says what a zkminer run under it is, not what every proof was.
//!
//! The seed covers every input byte on purpose. A seed an input could be crafted against (a job id,
//! chain data) would let whoever writes the input collide a guest's `HashMap`: with the seed bound
//! to the input, changing the input changes the seed.

/// The rule's name, as `zkminer simulate` reports it. A new rule is a new name, a new
/// [`SYS_RAND_DOMAIN`] and a new `PROTOCOL_VERSION`, and it re-seeds any lock held across it (see the
/// README's upgrade note).
pub const SYS_RAND_RULE: &str = "risc0-public-v3";

/// What the seed hashes first.
pub const SYS_RAND_DOMAIN: &[u8] = b"zkminer/risc0/sys_rand/v3";

/// The other host setting a risc0 guest can see that a miner may change: the keccak proof size, read
/// by the SDK from this variable, decides when `sys_keccak` reports full.
pub const RISC0_KECCAK_PO2_ENV: &str = "RISC0_KECCAK_PO2";

/// The size `zkminer simulate` always measures at: the SDK's default, what an untuned miner runs at.
pub const RISC0_CANONICAL_KECCAK_PO2: &str = "17";

/// The guest's `sys_rand` seed for one (program, input) under the rule:
/// `SHA-256(SYS_RAND_DOMAIN ‖ image_id ‖ input_sha256)`, where `input_sha256` is SHA-256 of the exact
/// bytes the guest reads (for a witness job, the bundle's `sha256(prefix ‖ W)`).
///
/// The one implementation of the rule: the risc0 workers' `sys_rand_seed` calls it with the hash of
/// their input, and the miner calls it for a witness job and hands the SEED to the sandboxed witness
/// execute (`WitnessExecuteRequest::sys_rand_seed`), so the execute and every later proof of the
/// bundle run the guest alike.
pub fn risc0_seed(image_id: &[u8; 32], input_sha256: &[u8; 32]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(SYS_RAND_DOMAIN);
    h.update(image_id);
    h.update(input_sha256);
    h.finalize().into()
}

/// The rule as a witness bundle records it (`BundleV1::sys_rand_rule`): `SHA-256(SYS_RAND_DOMAIN)`.
/// A new rule has a new domain (see [`SYS_RAND_RULE`]), so a new id. Revalidation compares a bundle's
/// with the host's, so a bundle executed under another rule is executed again, never proven as if its
/// journals still held.
pub fn rule_id() -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(SYS_RAND_DOMAIN).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    fn hex(b: [u8; 32]) -> String {
        b.map(|b| format!("{b:02x}")).concat()
    }

    #[test]
    fn the_seed_is_fixed_by_image_id_and_input_hash() {
        let (image, input) = ([7u8; 32], [9u8; 32]);
        let seed = risc0_seed(&image, &input);
        assert_eq!(risc0_seed(&image, &input), seed);
        assert_ne!(risc0_seed(&[8u8; 32], &input), seed);
        assert_ne!(risc0_seed(&image, &[10u8; 32]), seed);
    }

    /// The same known answer as the risc0 worker's `the_seed_rule_known_answer` (its `sys_rand_seed`
    /// hashes the input and calls this): it changes only together with `SYS_RAND_RULE`. From Python's
    /// hashlib.
    #[test]
    fn the_seed_rule_known_answer() {
        let input_sha256: [u8; 32] = Sha256::digest(b"input").into();
        assert_eq!(
            hex(risc0_seed(&[7u8; 32], &input_sha256)),
            "ba157a4c0fd9382ff3e51b1f758c75061651e6374ca1dfd38a5d648a4a37bce8"
        );
    }

    /// What a bundle records for this rule; it changes only together with `SYS_RAND_DOMAIN`. From
    /// Python's hashlib.
    #[test]
    fn the_rule_id_known_answer() {
        assert_eq!(
            hex(rule_id()),
            "911380c3d3de466621dc79ce06a0518947083991b584b4b8ec2dae35646df562"
        );
    }
}
