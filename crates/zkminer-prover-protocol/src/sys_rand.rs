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
//! anything, and a job proven before this rule (protocol 12) was seeded by its miner's own key. The
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
