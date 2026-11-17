//! Requester tooling for witness-construction jobs (docs/witness-construction-jobs.md §7, §21.1
//! item 3), under `zkminer witness`:
//!
//! - `envelope encode`: `inputData = WITNESS_JOB_TAG_V1 ‖ abi.encode(WitnessJobV1)` from a TOML or
//!   JSON spec ([`EnvelopeSpec`]), or a whole job ([`JobSpec`]: the envelope, the program and the
//!   binding), which also writes the descriptor file `zkminer simulate --descriptor` reads;
//! - `envelope decode`: an existing `inputData` explained, as the miner's decoder reads it;
//! - `binding compute`: `journalFields` and `expectedJournalHash` from the requester's own
//!   parameters (§7.2: never from a prover's journal);
//! - `binding check`: the automated mutation check of a binding: which statement bytes it leaves
//!   free, judged by changing each byte and recomputing the router's hash. It fails unless the
//!   header (its length given, or the words) is fully pinned, and on a binding the router refuses
//!   at submit, a NONE binding without `--assigned`, or no `expectedJournalHash` to check.
//!
//! Text output escapes control characters (`printable`): an envelope's URIs are the requester's
//! bytes, and must not reach the operator's terminal as escape sequences.
//!
//! Every encoder and hash is the miner's own (`zkminer_witness::requester`, `zkminer_witness::binding`,
//! `zkminer_chain::binding::full_hash`): a spec the miner would skip is refused with its reason.
//! Nothing here reads a key or the network.

use std::path::{Path, PathBuf};

use alloy::primitives::{keccak256, Address, Bytes, B256};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use zkminer_chain::binding::full_hash;
use zkminer_contracts::bindings::JobDescriptor;
use zkminer_witness::binding::{
    clear_marker, fields_slots, journal_fields_for_header, marker, pinned_by_mutation, runs, FieldsSlot,
    JOURNAL_PREFIX_MARKER, MAX_JOURNAL_BYTES, MAX_STATEMENT_BYTES_WITH_PREFIX, PREFIX_BYTES, PROOF_NONCE_MARKER,
};
use zkminer_witness::requester::{encode_words, explain, EnvelopeSpec};

/// The descriptor-file format version.
pub const DESCRIPTOR_FILE_SCHEMA: u32 = 1;

/// A job that is not on chain, as `zkminer simulate --descriptor` reads it: the descriptor's fields
/// (camelCase, as the contracts name them) plus the identities a simulation needs and the chain has
/// not assigned. `inputData` and the other byte fields are `0x` hex.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DescriptorFile {
    pub schema: u32,
    /// The job id the journal prefix names; default [`DescriptorFile::job_id_or_default`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub job_id: Option<B256>,
    /// The submitter (admission and verdicts are keyed by it); default the zero address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub caller: Option<Address>,
    pub program_id: B256,
    pub proof_system_id: B256,
    #[serde(default)]
    pub callback_contract: Address,
    #[serde(default)]
    pub assigned_prover: Address,
    #[serde(default)]
    pub tag: B256,
    pub input_data: Bytes,
    #[serde(default)]
    pub callback_extra_data: Bytes,
    #[serde(default)]
    pub extra_verifier_data: Bytes,
    pub expected_journal_hash: B256,
    pub journal_fields: B256,
}

impl DescriptorFile {
    pub fn descriptor(&self) -> JobDescriptor {
        JobDescriptor {
            programId: self.program_id,
            proofSystemId: self.proof_system_id,
            callbackContract: self.callback_contract,
            assignedProver: self.assigned_prover,
            tag: self.tag,
            inputData: self.input_data.clone(),
            callbackExtraData: self.callback_extra_data.clone(),
            extraVerifierData: self.extra_verifier_data.clone(),
            expectedJournalHash: self.expected_journal_hash,
            journalFields: self.journal_fields,
        }
    }

    /// The file's `jobId`, else one derived from the descriptor hash (stable for one descriptor, and
    /// never a real job's: real ids come from the router's counter).
    pub fn job_id_or_default(&self) -> B256 {
        self.job_id.unwrap_or_else(|| {
            let dh = zkminer_chain::descriptor::compute_descriptor_hash(&self.descriptor());
            keccak256([b"zkminer/simulate/descriptor-job".as_slice(), dh.as_slice()].concat())
        })
    }

    /// Reads a descriptor file and refuses one the router would refuse at submit
    /// ([`submit_binding_refusal`]): a simulation of a job that cannot exist would pass for nothing.
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let f: DescriptorFile = if path.extension().is_some_and(|e| e == "toml") {
            toml::from_str(&text).with_context(|| format!("{} is not a descriptor file", path.display()))?
        } else {
            serde_json::from_str(&text).with_context(|| format!("{} is not a descriptor file", path.display()))?
        };
        if f.schema != DESCRIPTOR_FILE_SCHEMA {
            bail!("{}: descriptor file schema {} (this build reads {DESCRIPTOR_FILE_SCHEMA})", path.display(), f.schema);
        }
        f.check_submit_rules().with_context(|| format!("{}", path.display()))?;
        Ok(f)
    }

    /// The router's submit rules for this descriptor's binding ([`submit_binding_refusal`]).
    pub fn check_submit_rules(&self) -> Result<()> {
        match submit_binding_refusal(
            self.journal_fields,
            self.expected_journal_hash,
            self.proof_system_id,
            self.assigned_prover,
        ) {
            None => Ok(()),
            Some((code, why)) => {
                bail!("the router refuses this binding at submit (InvalidJournalBinding({code})): {why}")
            }
        }
    }
}

/// The router's submit rules for a journal binding (`HemiProveCore._bindingMode`, hemiprove-contracts
/// 3bc441d), in its order: `Some((reason, why))` when `submitJob` would revert
/// `InvalidJournalBinding(reason)`. A descriptor file carries no bid configuration, so reason 4 (NONE
/// with an underbid window) is the caller's to avoid.
pub fn submit_binding_refusal(
    journal_fields: B256,
    expected_journal_hash: B256,
    proof_system_id: B256,
    assigned_prover: Address,
) -> Option<(u8, &'static str)> {
    use zkminer_chain::auction::{openvm_halo2_v1_id, sp1_groth16_v1_id, sp1_plonk_v1_id};
    let open_vm = proof_system_id == openvm_halo2_v1_id();
    let mut room = if open_vm { 32 } else { MAX_JOURNAL_BYTES };
    let mut fields = journal_fields;
    if let Some(m) = marker(journal_fields) {
        fields = clear_marker(journal_fields);
        if m == JOURNAL_PREFIX_MARKER {
            if open_vm {
                return Some((7, "OpenVM's verifier takes 32 public-value bytes: no room for the journal prefix"));
            }
            room -= PREFIX_BYTES;
        } else if proof_system_id != sp1_groth16_v1_id() && proof_system_id != sp1_plonk_v1_id() {
            return Some((6, "a binding marker this proof system does not carry"));
        }
    }
    if expected_journal_hash == B256::ZERO {
        if fields != B256::ZERO {
            return Some((1, "FIELDS ranges without an expectedJournalHash"));
        }
        if assigned_prover == Address::ZERO {
            return Some((3, "NONE binds nothing: only with an assigned prover"));
        }
        return None;
    }
    if fields != B256::ZERO {
        let slots = fields_slots(journal_fields);
        if slots.is_empty() {
            return Some((2, "FIELDS with no used slot binds the empty string"));
        }
        if slots.iter().any(|s| s.end() > room) {
            return Some((if open_vm { 7 } else { 5 }, "a FIELDS range ends past the journal room"));
        }
    }
    None
}

/// `s` with every control character (C0, DEL and C1: ESC, CSI, OSC, …) and the bidirectional
/// formatting characters escaped as `\u{…}`: text from an envelope or a requester's file cannot move
/// the cursor, rewrite earlier lines, write the clipboard or hide what follows on a terminal.
pub fn printable(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        let bidi =
            matches!(c, '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}');
        if c.is_control() || bidi {
            out.push_str(&format!("\\u{{{:x}}}", c as u32));
        } else {
            out.push(c);
        }
    }
    out
}

/// The proof system by name (`risc0`, the only one witness jobs are served on in Phase 1) or id.
pub fn parse_proof_system(s: &str) -> Result<B256> {
    match s {
        "risc0" | "risczero.groth16.v1" => Ok(zkminer_chain::auction::risc_zero_groth16_v1_id()),
        _ => s.parse().with_context(|| format!("{s:?}: a proof system is `risc0` or a 0x… 32-byte id")),
    }
}

/// How a job binds its journal (plan §7.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BindingSpec {
    /// The journal-prefix marker (the default for open risc0 witness jobs).
    #[serde(default = "yes")]
    pub prefix: bool,
    /// FIELDS over the whole header: each word `type:value` (`zkminer_witness::requester::parse_word`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub header: Option<Vec<String>>,
    /// FULL over the whole statement (after any prefix), `0x` hex: only for a journal known in full
    /// at submit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub full_statement: Option<String>,
    /// NONE: only with an assigned prover.
    #[serde(default)]
    pub none: bool,
}

fn yes() -> bool {
    true
}

/// A whole job: what `envelope encode` turns into `inputData` and a descriptor file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobSpec {
    pub program_id: B256,
    /// `risc0` (default) or an id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof_system: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assigned_prover: Option<Address>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub callback_contract: Option<Address>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub job_id: Option<B256>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub caller: Option<Address>,
    pub binding: BindingSpec,
    pub envelope: EnvelopeSpec,
}

/// What `binding compute` computed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ComputedBinding {
    pub mode: &'static str,
    pub prefix: bool,
    pub journal_fields: B256,
    pub expected_journal_hash: B256,
    /// FIELDS: the pinned header's length `H` (32 × the words).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub header_bytes: Option<usize>,
}

/// `journalFields` and `expectedJournalHash` from the requester's own parameters.
pub fn compute_binding(b: &BindingSpec, proof_system_id: B256, program_id: B256) -> Result<ComputedBinding> {
    let marker_only = || {
        let mut w = [0u8; 32];
        if b.prefix {
            w[..4].copy_from_slice(&JOURNAL_PREFIX_MARKER.to_be_bytes());
        }
        B256::from(w)
    };
    match (&b.header, &b.full_statement, b.none) {
        (Some(words), None, false) => {
            let header = encode_words(words).map_err(anyhow::Error::msg)?;
            let fields = journal_fields_for_header(header.len(), b.prefix).map_err(|e| anyhow::anyhow!("the header: {e}"))?;
            Ok(ComputedBinding {
                mode: "fields",
                prefix: b.prefix,
                journal_fields: fields,
                expected_journal_hash: keccak256(&header),
                header_bytes: Some(header.len()),
            })
        }
        (None, Some(hex), false) => {
            let statement = parse_hex(hex).context("full_statement")?;
            let cap = if b.prefix { MAX_STATEMENT_BYTES_WITH_PREFIX } else { MAX_JOURNAL_BYTES };
            if statement.len() > cap {
                bail!("a {}-byte statement is over the {cap}-byte journal cap", statement.len());
            }
            Ok(ComputedBinding {
                mode: "full",
                prefix: b.prefix,
                journal_fields: marker_only(),
                expected_journal_hash: full_hash(proof_system_id, program_id, &statement),
                header_bytes: None,
            })
        }
        (None, None, true) => Ok(ComputedBinding {
            mode: "none",
            prefix: b.prefix,
            journal_fields: marker_only(),
            expected_journal_hash: B256::ZERO,
            header_bytes: None,
        }),
        _ => bail!("a binding is exactly one of: header (FIELDS), full_statement (FULL), none = true"),
    }
}

fn parse_hex(s: &str) -> Result<Vec<u8>> {
    let h = s.trim().strip_prefix("0x").context("expected 0x-prefixed hex")?;
    alloy::hex::decode(h).context("not hex")
}

/// A file of bytes: `0x` hex text (whitespace allowed around it), else the raw bytes.
pub fn read_bytes_file(path: &Path) -> Result<Vec<u8>> {
    let raw = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    if let Ok(text) = std::str::from_utf8(&raw) {
        if text.trim_start().starts_with("0x") {
            return parse_hex(text);
        }
    }
    Ok(raw)
}

/// A spec file: TOML by its extension, else JSON.
fn read_spec<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    let text = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    if path.extension().is_some_and(|e| e == "toml") {
        toml::from_str(&text).with_context(|| format!("{}", path.display()))
    } else {
        serde_json::from_str(&text).with_context(|| format!("{}", path.display()))
    }
}

// ---------------------------------------------------------------------------------------------
// The mutation check.

/// A half-open byte range, as reports print it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ByteRange {
    pub start: usize,
    pub end: usize,
}

fn ranges(r: Vec<std::ops::Range<usize>>) -> Vec<ByteRange> {
    r.into_iter().map(|r| ByteRange { start: r.start, end: r.end }).collect()
}

/// One header word's bytes the binding leaves free.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WordCheck {
    pub index: usize,
    pub word: String,
    /// Offsets within the word (0–31) the hash does not cover.
    pub free_bytes: Vec<ByteRange>,
}

/// The mutation check's report (plan §7.2, §21.1): offsets are into the statement, the journal after
/// any prefix, which is what FIELDS ranges index.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BindingReport {
    /// `fields`, `full`, `none`, or `sp1-proof-nonce` (not served for witness jobs).
    pub mode: &'static str,
    pub prefix: bool,
    pub slots: Vec<FieldsSlot>,
    pub statement_bytes: usize,
    /// Statement bytes the router's hash covers, and those it leaves free (FULL: all, NONE: none).
    pub pinned: Vec<ByteRange>,
    pub free: Vec<ByteRange>,
    /// The header's length `H` (the words given, `--header-bytes`, or a scheme-1 `W`'s
    /// `32 × nWords`): `[0, H)` must be pinned.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub header_bytes: Option<usize>,
    /// Free bytes inside the header `[0, H)`: each is a soundness hole in the requester's statement.
    pub header_free: Vec<ByteRange>,
    pub words: Vec<WordCheck>,
    /// `expectedJournalHash` given: whether this statement satisfies it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_hash_matches: Option<bool>,
    pub warnings: Vec<String>,
    /// The mode is known, the router would accept the binding at submit (NONE: assigned), the
    /// header's length is known and within the statement, no header byte is free, no range ends past
    /// the statement, and the expected hash matched.
    pub ok: bool,
}

/// What `binding check` is asked.
pub struct CheckInput<'a> {
    pub journal_fields: B256,
    pub expected_journal_hash: Option<B256>,
    /// FULL needs these to recompute the hash.
    pub proof_system_id: B256,
    pub program_id: B256,
    /// The statement (journal after any prefix).
    pub statement: &'a [u8],
    /// The header's length, when known (the words given, or `--header-bytes`).
    pub header_bytes: Option<usize>,
    /// The header words, for per-word results.
    pub words: &'a [String],
    /// The job's assigned prover, for NONE (zero: an open job, which the router refuses with NONE).
    pub assigned_prover: Address,
}

/// The mutation check: see the module docs.
pub fn check_binding(c: &CheckInput<'_>) -> BindingReport {
    let m = marker(c.journal_fields);
    let prefix = m == Some(JOURNAL_PREFIX_MARKER);
    let slots = fields_slots(c.journal_fields);
    let fields = clear_marker(c.journal_fields);
    let mut warnings = Vec::new();
    // Without the expected hash, FULL and NONE look the same and nothing can be matched: never
    // assume one.
    let mode = match (m, c.expected_journal_hash) {
        (Some(PROOF_NONCE_MARKER), _) => "sp1-proof-nonce",
        (_, None) => "unknown",
        (_, Some(h)) if h == B256::ZERO => "none",
        _ if fields == B256::ZERO => "full",
        _ => "fields",
    };
    let len = c.statement.len();
    let mut ok = true;
    let fields_mask =
        |ok: &mut bool, warnings: &mut Vec<String>| match pinned_by_mutation(c.statement, c.journal_fields) {
            Some(mask) => mask,
            None => {
                *ok = false;
                warnings.push(format!(
                    "a pinned range ends past this {len}-byte statement: the router rejects every journal this \
                 short (a range past the journal is a mismatch, never a truncation)"
                ));
                let mut mask = vec![false; len];
                for s in &slots {
                    for b in mask.iter_mut().take(s.end().min(len)).skip(s.offset) {
                        *b = true;
                    }
                }
                mask
            }
        };
    let mask: Vec<bool> = match mode {
        "fields" => fields_mask(&mut ok, &mut warnings),
        "unknown" if fields != B256::ZERO => fields_mask(&mut ok, &mut warnings),
        "full" => vec![true; len],
        _ => vec![false; len],
    };
    let expected_hash_matches = c.expected_journal_hash.filter(|h| *h != B256::ZERO).map(|h| {
        let computed = if mode == "full" {
            full_hash(c.proof_system_id, c.program_id, c.statement)
        } else {
            zkminer_witness::binding::fields_hash(c.statement, fields)
        };
        computed == h
    });
    if expected_hash_matches == Some(false) {
        ok = false;
        warnings.push("expectedJournalHash does not match this statement under these journalFields".into());
    }
    if let Some(h) = c.expected_journal_hash {
        if let Some((code, why)) = submit_binding_refusal(c.journal_fields, h, c.proof_system_id, c.assigned_prover) {
            ok = false;
            warnings.push(format!("the router refuses this binding at submit (InvalidJournalBinding({code})): {why}"));
        }
    }
    match mode {
        "unknown" => {
            ok = false;
            warnings.push(
                "no expectedJournalHash given (give it or --descriptor): FULL and NONE cannot be told apart and \
                 nothing can be matched"
                    .into(),
            );
        }
        "sp1-proof-nonce" => {
            ok = false;
            warnings.push("the SP1 proof-nonce marker: SP1 witness jobs are not served until Phase 2 (plan §7.2)".into());
        }
        "none" => warnings.push(
            "NONE binds nothing: allowed only with assignedProver, as bilateral trust (plan §7.2)".into(),
        ),
        "full" => warnings.push(
            "FULL binds the whole journal: only for a journal known in full at submit; on live input it is \
             unsatisfiable and the job stays Open (plan §7.2)"
                .into(),
        ),
        _ => warnings.push(
            "FIELDS binds the pinned bytes and nothing else, not the journal length: outputs after the header \
             are the prover's to choose unless the guest derives them (plan §7.2)"
                .into(),
        ),
    }
    if !prefix && m.is_none() && mode != "none" {
        warnings.push(
            "no journal-prefix marker: a public proof of the same statement settles any sibling job, so a copier \
             can settle duplicates without proving (plan §7.2)"
                .into(),
        );
    }
    if mode == "fields" {
        if slots.first().is_some_and(|s| s.offset != 0) || !slots.iter().any(|s| s.offset == 0) {
            warnings.push("no range starts at offset 0: pin the header where no witness can move it (plan §7.2)".into());
        }
        let limit = if prefix { MAX_STATEMENT_BYTES_WITH_PREFIX } else { MAX_JOURNAL_BYTES };
        if let Some(s) = slots.iter().find(|s| s.end() > limit) {
            ok = false;
            warnings.push(format!("slot {} ends at {}, past the {limit}-byte limit for this layout", s.index, s.end()));
        }
    }
    let header_bytes = c.header_bytes.or((!c.words.is_empty()).then_some(32 * c.words.len()));
    let header_free = match header_bytes {
        Some(h) if h > len => {
            // The header is the start of the statement: one longer than it cannot have been checked.
            ok = false;
            warnings.push(format!(
                "the header is {h} bytes, longer than this {len}-byte statement: check the whole statement \
                 (--statement or --journal), or the header's own length"
            ));
            let mut free = ranges(runs(&mask, false));
            free.push(ByteRange { start: len, end: h });
            free
        }
        Some(h) => ranges(runs(&mask[..h], false)),
        None => Vec::new(),
    };
    if !header_free.is_empty() && mode != "none" && header_bytes.is_some_and(|h| h <= len) {
        ok = false;
        warnings.push(format!(
            "the header is not fully pinned: {} of its bytes are free ({:?}); every free header byte is a value the \
             prover chooses",
            header_free.iter().map(|r| r.end - r.start).sum::<usize>(),
            header_free.iter().map(|r| (r.start, r.end)).collect::<Vec<_>>()
        ));
    }
    if header_bytes.is_none() && (mode == "fields" || (mode == "unknown" && fields != B256::ZERO)) {
        ok = false;
        warnings.push(
            "the header length is unknown (give the words, --header-bytes, or a scheme-1 W): a FIELDS binding \
             cannot be shown to pin the whole header"
                .into(),
        );
    }
    let words = c
        .words
        .iter()
        .enumerate()
        .filter(|(i, _)| 32 * (i + 1) <= len)
        .map(|(i, w)| WordCheck {
            index: i,
            word: w.clone(),
            free_bytes: ranges(runs(&mask[32 * i..32 * (i + 1)], false)),
        })
        .collect();
    BindingReport {
        mode,
        prefix,
        slots,
        statement_bytes: len,
        pinned: ranges(runs(&mask, true)),
        free: ranges(runs(&mask, false)),
        header_bytes,
        header_free,
        words,
        expected_hash_matches,
        warnings,
        ok,
    }
}

// ---------------------------------------------------------------------------------------------
// The commands.

/// `zkminer witness envelope encode`.
pub fn envelope_encode(
    spec_path: &Path,
    builder: Option<&Path>,
    out: Option<&Path>,
    descriptor_out: Option<&Path>,
    json: bool,
) -> Result<()> {
    let text = std::fs::read_to_string(spec_path).with_context(|| format!("reading {}", spec_path.display()))?;
    // A whole job has an `envelope` table; a bare envelope spec does not.
    let is_job = if spec_path.extension().is_some_and(|e| e == "toml") {
        toml::from_str::<toml::Value>(&text).ok().and_then(|v| v.get("envelope").cloned()).is_some()
    } else {
        serde_json::from_str::<serde_json::Value>(&text).ok().and_then(|v| v.get("envelope").cloned()).is_some()
    };
    let artifact = builder
        .map(|p| -> Result<B256> {
            let bytes = std::fs::read(p).with_context(|| format!("reading {}", p.display()))?;
            Ok(B256::from(zkminer_witness::manifest::sha256(&bytes)))
        })
        .transpose()?;
    let (input, descriptor) = if is_job {
        let job: JobSpec = read_spec(spec_path)?;
        let input = job.envelope.encode(artifact)?;
        let psid = parse_proof_system(job.proof_system.as_deref().unwrap_or("risc0"))?;
        let b = compute_binding(&job.binding, psid, job.program_id)?;
        let assigned = job.assigned_prover.unwrap_or(Address::ZERO);
        if b.mode == "none" && assigned == Address::ZERO {
            bail!("a NONE binding needs assigned_prover (plan §7.2)");
        }
        if let Some((code, why)) = submit_binding_refusal(b.journal_fields, b.expected_journal_hash, psid, assigned) {
            bail!("the router would refuse this binding at submit (InvalidJournalBinding({code})): {why}");
        }
        let d = DescriptorFile {
            schema: DESCRIPTOR_FILE_SCHEMA,
            job_id: job.job_id,
            caller: job.caller,
            program_id: job.program_id,
            proof_system_id: psid,
            callback_contract: job.callback_contract.unwrap_or(Address::ZERO),
            assigned_prover: assigned,
            tag: B256::ZERO,
            input_data: input.clone().into(),
            callback_extra_data: Bytes::new(),
            extra_verifier_data: Bytes::new(),
            expected_journal_hash: b.expected_journal_hash,
            journal_fields: b.journal_fields,
        };
        (input, Some((d, b)))
    } else {
        if descriptor_out.is_some() {
            bail!("--descriptor-out needs a job spec (program_id, [binding], [envelope])");
        }
        let spec: EnvelopeSpec = read_spec(spec_path)?;
        (spec.encode(artifact)?, None)
    };
    let hex_input = format!("0x{}", alloy::hex::encode(&input));
    if let Some(p) = out {
        std::fs::write(p, &hex_input).with_context(|| format!("writing {}", p.display()))?;
    }
    if let (Some(p), Some((d, _))) = (descriptor_out, &descriptor) {
        std::fs::write(p, serde_json::to_string_pretty(d)? + "\n").with_context(|| format!("writing {}", p.display()))?;
    }
    if json {
        let mut v = serde_json::json!({
            "inputData": hex_input,
            "inputBytes": input.len(),
            "inputKeccak256": keccak256(&input),
        });
        if let Some((d, b)) = &descriptor {
            v["descriptor"] = serde_json::to_value(d)?;
            v["binding"] = serde_json::to_value(b)?;
        }
        println!("{}", serde_json::to_string_pretty(&v)?);
    } else {
        if out.is_none() {
            println!("{hex_input}");
        }
        eprintln!("inputData: {} bytes, keccak256 {}", input.len(), keccak256(&input));
        if input.len() > zkminer_witness::requester::ENVELOPE_SIZE_ADVICE_BYTES {
            eprintln!(
                "warning: keep the envelope under about {} bytes (plan §7.1)",
                zkminer_witness::requester::ENVELOPE_SIZE_ADVICE_BYTES
            );
        }
        if let Some((_, b)) = &descriptor {
            eprintln!(
                "binding: {} (prefix {}), journalFields {}, expectedJournalHash {}",
                b.mode, b.prefix, b.journal_fields, b.expected_journal_hash
            );
        }
    }
    Ok(())
}

/// `zkminer witness envelope decode`.
pub fn envelope_decode(input: &str, chain_id: u64, json: bool) -> Result<()> {
    let bytes = if input.starts_with("0x") { parse_hex(input)? } else { read_bytes_file(Path::new(input))? };
    let r = explain(&bytes, chain_id);
    if json {
        println!("{}", serde_json::to_string_pretty(&r)?);
    } else {
        // Every field through `printable`: the URIs and the spec are the requester's bytes.
        println!("inputData: {} bytes, keccak256 {}", r.input_bytes, r.input_keccak256);
        println!("witness job: {}", r.witness_job);
        if let Some(e) = &r.error {
            println!("refused by the miner's decoder: {}", printable(e));
        }
        for u in &r.uris {
            println!("builderURI {}: {}", printable(&u.uri), printable(&u.status));
        }
        if let Some(s) = &r.spec {
            println!("{}", spec_text(s)?);
        }
        for w in &r.warnings {
            println!("warning: {}", printable(w));
        }
    }
    if r.error.is_some() {
        bail!("the miner would skip this envelope");
    }
    Ok(())
}

/// The spec as `envelope decode` prints it: TOML, which `envelope encode` reads back; or, when a
/// value is above 2^63 − 1 (the miner's decoder takes any u64, TOML holds only i64), JSON, which it
/// reads back as well. Each line escaped.
fn spec_text(s: &zkminer_witness::requester::EnvelopeSpec) -> Result<String> {
    let (title, body) = match toml::to_string_pretty(s) {
        Ok(t) => ("--- spec (TOML) ---".to_string(), t),
        Err(_) => (
            "--- spec (JSON: a value is above 2^63 - 1, which TOML cannot hold; `envelope encode` reads a .json spec) ---"
                .to_string(),
            serde_json::to_string_pretty(s)?,
        ),
    };
    Ok(std::iter::once(title).chain(body.lines().map(printable)).collect::<Vec<_>>().join("\n"))
}

/// `zkminer witness binding compute`.
pub fn binding_compute(
    b: &BindingSpec,
    proof_system: &str,
    program_id: Option<B256>,
    assigned: Option<Address>,
    json: bool,
) -> Result<()> {
    let psid = parse_proof_system(proof_system)?;
    if b.full_statement.is_some() && program_id.is_none() {
        bail!("FULL hashes the program id: give --program-id");
    }
    let c = compute_binding(b, psid, program_id.unwrap_or_default())?;
    // The computed binding, checked against the statement it was computed from.
    let words = b.header.clone().unwrap_or_default();
    let statement = match (&b.header, &b.full_statement) {
        (Some(w), _) => encode_words(w).map_err(anyhow::Error::msg)?,
        (_, Some(h)) => parse_hex(h)?,
        _ => Vec::new(),
    };
    let report = check_binding(&CheckInput {
        journal_fields: c.journal_fields,
        expected_journal_hash: Some(c.expected_journal_hash),
        proof_system_id: psid,
        program_id: program_id.unwrap_or_default(),
        statement: &statement,
        header_bytes: c.header_bytes,
        words: &words,
        assigned_prover: assigned.unwrap_or(Address::ZERO),
    });
    if json {
        println!("{}", serde_json::to_string_pretty(&serde_json::json!({ "binding": c, "check": report }))?);
    } else {
        println!("mode:                {} (journal-prefix marker: {})", c.mode, c.prefix);
        println!("journalFields:       {}", c.journal_fields);
        println!("expectedJournalHash: {}", c.expected_journal_hash);
        if let Some(h) = c.header_bytes {
            println!("header:              {h} bytes ({} words), pinned at statement offset 0", h / 32);
        }
        print_warnings(&report);
    }
    if !report.ok {
        bail!("the binding does not pin what it should (see the warnings)");
    }
    Ok(())
}

fn print_warnings(r: &BindingReport) {
    for w in &r.warnings {
        println!("warning: {}", printable(w));
    }
}

/// What `binding check` reads.
pub struct CheckArgs {
    pub descriptor: Option<PathBuf>,
    pub journal_fields: Option<B256>,
    pub expected_journal_hash: Option<B256>,
    pub program_id: Option<B256>,
    pub proof_system: String,
    pub words: Vec<String>,
    pub journal: Option<String>,
    pub statement: Option<String>,
    pub header_bytes: Option<usize>,
    /// The job's assigned prover (a NONE binding fails without one; default the descriptor's).
    pub assigned: Option<Address>,
    pub json: bool,
}

/// `zkminer witness binding check`.
pub fn binding_check(a: CheckArgs) -> Result<()> {
    let d = a.descriptor.as_deref().map(DescriptorFile::load).transpose()?;
    let journal_fields = a
        .journal_fields
        .or(d.as_ref().map(|d| d.journal_fields))
        .context("give --journal-fields or --descriptor")?;
    let expected = a.expected_journal_hash.or(d.as_ref().map(|d| d.expected_journal_hash));
    let program_id = a.program_id.or(d.as_ref().map(|d| d.program_id)).unwrap_or_default();
    let psid = match &d {
        Some(d) if a.proof_system == "risc0" => d.proof_system_id,
        _ => parse_proof_system(&a.proof_system)?,
    };
    let prefix = marker(journal_fields) == Some(JOURNAL_PREFIX_MARKER);
    let load = |s: &str| -> Result<Vec<u8>> {
        if s.starts_with("0x") {
            parse_hex(s)
        } else {
            read_bytes_file(Path::new(s))
        }
    };
    let statement = match (&a.journal, &a.statement, a.words.is_empty()) {
        (Some(j), None, _) => {
            let j = load(j)?;
            if prefix {
                if j.len() < PREFIX_BYTES {
                    bail!("a journal-prefix job's journal starts with its 64-byte prefix; this one is {} bytes", j.len());
                }
                j[PREFIX_BYTES..].to_vec()
            } else {
                j
            }
        }
        (None, Some(s), _) => load(s)?,
        (None, None, false) => encode_words(&a.words).map_err(anyhow::Error::msg)?,
        _ => bail!("give the statement: --word … (the header), --statement, or --journal (a whole journal)"),
    };
    let assigned = a.assigned.or(d.as_ref().map(|d| d.assigned_prover)).unwrap_or(Address::ZERO);
    let report = check_binding(&CheckInput {
        journal_fields,
        expected_journal_hash: expected,
        proof_system_id: psid,
        program_id,
        statement: &statement,
        header_bytes: a.header_bytes,
        words: &a.words,
        assigned_prover: assigned,
    });
    if a.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("mode {} (journal-prefix marker: {}), statement {} bytes", report.mode, report.prefix, report.statement_bytes);
        for s in &report.slots {
            println!("slot {}: bytes {}..{}", s.index, s.offset, s.end());
        }
        println!("pinned: {:?}", report.pinned.iter().map(|r| (r.start, r.end)).collect::<Vec<_>>());
        println!("free:   {:?}", report.free.iter().map(|r| (r.start, r.end)).collect::<Vec<_>>());
        match report.header_bytes {
            Some(h) => println!(
                "header: {h} bytes, free {:?}",
                report.header_free.iter().map(|r| (r.start, r.end)).collect::<Vec<_>>()
            ),
            None => println!("header: length unknown"),
        }
        for w in &report.words {
            if !w.free_bytes.is_empty() {
                println!(
                    "word {} ({}): free bytes {:?}",
                    w.index,
                    printable(&w.word),
                    w.free_bytes.iter().map(|r| (r.start, r.end)).collect::<Vec<_>>()
                );
            }
        }
        if let Some(m) = report.expected_hash_matches {
            println!("expectedJournalHash matches this statement: {m}");
        }
        print_warnings(&report);
    }
    if !report.ok {
        bail!("the binding check failed");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words() -> Vec<String> {
        vec![
            "uint:1".into(),
            format!("bytes32:0x{}", "11".repeat(32)),
            "address:0x00000000000000000000000000000000000000c0".into(),
            "keccak:layout-rule".into(),
            "uint:3".into(),
        ]
    }

    #[test]
    fn the_section_12_binding_pins_the_160_byte_header() {
        let b = BindingSpec { prefix: true, header: Some(words()), full_statement: None, none: false };
        let c = compute_binding(&b, parse_proof_system("risc0").unwrap(), B256::ZERO).unwrap();
        assert_eq!(c.header_bytes, Some(160));
        // §7.2: bytes32((0xffffffff << 224) | (H << 192)).
        let mut want = [0u8; 32];
        want[..4].copy_from_slice(&[0xff; 4]);
        want[4..8].copy_from_slice(&160u32.to_be_bytes());
        assert_eq!(c.journal_fields, B256::from(want));
        let header = encode_words(&words()).unwrap();
        assert_eq!(c.expected_journal_hash, keccak256(&header));
        // The router's own check of prefix ‖ header ‖ outputs.
        let d = JobDescriptor {
            programId: B256::ZERO,
            proofSystemId: parse_proof_system("risc0").unwrap(),
            callbackContract: Address::ZERO,
            assignedProver: Address::ZERO,
            tag: B256::ZERO,
            inputData: Bytes::new(),
            callbackExtraData: Bytes::new(),
            extraVerifierData: Bytes::new(),
            expectedJournalHash: c.expected_journal_hash,
            journalFields: c.journal_fields,
        };
        let (job, prover) = (B256::repeat_byte(9), Address::repeat_byte(8));
        let mut journal = zkminer_witness::binding::journal_prefix(job, prover).to_vec();
        journal.extend_from_slice(&header);
        journal.extend_from_slice(b"outputs are free");
        assert!(zkminer_chain::binding::check_journal_binding(&d, &journal, job, prover).is_ok());
        // And the check agrees: the whole header pinned, the outputs free.
        let mut statement = header.clone();
        statement.extend_from_slice(b"outputs");
        let r = check_binding(&CheckInput {
            journal_fields: c.journal_fields,
            expected_journal_hash: Some(c.expected_journal_hash),
            proof_system_id: d.proofSystemId,
            program_id: B256::ZERO,
            statement: &statement,
            header_bytes: None,
            words: &words(),
            assigned_prover: Address::ZERO,
        });
        assert!(r.ok, "{:?}", r.warnings);
        assert_eq!(r.pinned, vec![ByteRange { start: 0, end: 160 }]);
        assert_eq!(r.free, vec![ByteRange { start: 160, end: 167 }]);
        assert!(r.header_free.is_empty());
        assert_eq!(r.expected_hash_matches, Some(true));
    }

    #[test]
    fn a_header_left_partly_free_is_flagged_word_by_word() {
        // The requester pinned only the first 4 words of a 5-word header.
        let fields = journal_fields_for_header(128, true).unwrap();
        let statement = encode_words(&words()).unwrap();
        let r = check_binding(&CheckInput {
            journal_fields: fields,
            expected_journal_hash: Some(keccak256(&statement[..128])),
            proof_system_id: B256::ZERO,
            program_id: B256::ZERO,
            statement: &statement,
            header_bytes: None,
            words: &words(),
            assigned_prover: Address::ZERO,
        });
        assert!(!r.ok);
        assert_eq!(r.header_free, vec![ByteRange { start: 128, end: 160 }]);
        assert_eq!(r.words[4].free_bytes, vec![ByteRange { start: 0, end: 32 }]);
        assert!(r.words[..4].iter().all(|w| w.free_bytes.is_empty()));
        assert!(r.warnings.iter().any(|w| w.contains("not fully pinned")));
        // A range past a short statement.
        let r = check_binding(&CheckInput {
            journal_fields: journal_fields_for_header(192, true).unwrap(),
            expected_journal_hash: None,
            proof_system_id: B256::ZERO,
            program_id: B256::ZERO,
            statement: &statement,
            header_bytes: Some(160),
            words: &[],
            assigned_prover: Address::ZERO,
        });
        assert!(!r.ok);
        assert!(r.warnings.iter().any(|w| w.contains("past this")));
    }

    #[test]
    fn full_none_and_the_markers_are_judged_as_the_router_judges_them() {
        let psid = parse_proof_system("risc0").unwrap();
        let pid = B256::repeat_byte(5);
        let statement = b"the whole journal".to_vec();
        let b = BindingSpec {
            prefix: false,
            header: None,
            full_statement: Some(format!("0x{}", alloy::hex::encode(&statement))),
            none: false,
        };
        let c = compute_binding(&b, psid, pid).unwrap();
        assert_eq!(c.journal_fields, B256::ZERO);
        assert_eq!(c.expected_journal_hash, full_hash(psid, pid, &statement));
        let r = check_binding(&CheckInput {
            journal_fields: c.journal_fields,
            expected_journal_hash: Some(c.expected_journal_hash),
            proof_system_id: psid,
            program_id: pid,
            statement: &statement,
            header_bytes: None,
            words: &[],
            assigned_prover: Address::ZERO,
        });
        assert_eq!(r.mode, "full");
        assert_eq!(r.expected_hash_matches, Some(true));
        assert!(r.free.is_empty());
        assert!(r.warnings.iter().any(|w| w.contains("no journal-prefix marker")));
        // NONE.
        let none = compute_binding(&BindingSpec { prefix: true, header: None, full_statement: None, none: true }, psid, pid).unwrap();
        assert_eq!(none.expected_journal_hash, B256::ZERO);
        assert_eq!(marker(none.journal_fields), Some(JOURNAL_PREFIX_MARKER));
        // The SP1 proof-nonce marker is not served.
        let mut nonce = [0u8; 32];
        nonce[..4].copy_from_slice(&PROOF_NONCE_MARKER.to_be_bytes());
        let r = check_binding(&CheckInput {
            journal_fields: B256::from(nonce),
            expected_journal_hash: Some(B256::repeat_byte(1)),
            proof_system_id: psid,
            program_id: pid,
            statement: &statement,
            header_bytes: None,
            words: &[],
            assigned_prover: Address::ZERO,
        });
        assert!(!r.ok && r.mode == "sp1-proof-nonce");
        // Exactly one binding form.
        assert!(compute_binding(&BindingSpec { prefix: true, header: Some(words()), full_statement: None, none: true }, psid, pid).is_err());
    }

    /// The §12 header (scheme, B, C, R, k) as `--word word:0x…` values.
    fn section12_words() -> Vec<String> {
        [
            format!("{:064x}", 1),
            "11".repeat(32),
            format!("{:0>64}", "c0".repeat(20)),
            format!("01{:062x}", 10),
            format!("{:064x}", 3),
        ]
        .iter()
        .map(|h| format!("word:0x{h}"))
        .collect()
    }

    fn fields(h: usize) -> B256 {
        journal_fields_for_header(h, true).unwrap()
    }

    fn check(
        fields: B256,
        expected: Option<B256>,
        statement: &[u8],
        header_bytes: Option<usize>,
        words: &[String],
        assigned: Address,
    ) -> BindingReport {
        check_binding(&CheckInput {
            journal_fields: fields,
            expected_journal_hash: expected,
            proof_system_id: parse_proof_system("risc0").unwrap(),
            program_id: B256::ZERO,
            statement,
            header_bytes,
            words,
            assigned_prover: assigned,
        })
    }

    #[test]
    fn bindings_that_leave_the_header_free_or_unknown_fail() {
        let words = section12_words();
        let h160 = encode_words(&words).unwrap();
        let h96 = h160[..96].to_vec();
        // A: only word 0 pinned, the header's length not given: unknown, so a failure.
        let a = check(fields(32), Some(keccak256(&h160[..32])), &h160, None, &[], Address::ZERO);
        assert!(!a.ok && a.warnings.iter().any(|w| w.contains("header length is unknown")), "{:?}", a.warnings);
        // … and with the length, the 128 free bytes.
        let a = check(fields(32), Some(keccak256(&h160[..32])), &h160, Some(160), &[], Address::ZERO);
        assert!(!a.ok);
        assert_eq!(a.header_free, vec![ByteRange { start: 32, end: 160 }]);
        // B: five words but a 96-byte statement: the header is longer than the statement.
        let b = check(fields(96), Some(keccak256(&h96)), &h96, None, &words, Address::ZERO);
        assert!(
            !b.ok && b.warnings.iter().any(|w| w.contains("longer than this 96-byte statement")),
            "{:?}",
            b.warnings
        );
        assert_eq!(b.header_free.last(), Some(&ByteRange { start: 96, end: 160 }));
        // C: the same with --header-bytes 160.
        let c = check(fields(96), Some(keccak256(&h96)), &h96, Some(160), &[], Address::ZERO);
        assert!(!c.ok);
        // Control: the 96-byte binding against the five words, as statement.
        let ctl = check(fields(96), Some(keccak256(&h96)), &h160, None, &words, Address::ZERO);
        assert!(!ctl.ok);
        assert_eq!(ctl.header_free, vec![ByteRange { start: 96, end: 160 }]);
        // And the whole header pinned passes.
        let good = check(fields(160), Some(keccak256(&h160)), &h160, None, &words, Address::ZERO);
        assert!(good.ok, "{:?}", good.warnings);
    }

    #[test]
    fn none_needs_an_assigned_prover_and_no_hash_is_no_mode() {
        let words = section12_words();
        let h160 = encode_words(&words).unwrap();
        let marker_only = clear_marker(fields(160)) ^ fields(160);
        // D: NONE (expectedJournalHash 0) of an open job: the router refuses it, and so does the check.
        let d = check(marker_only, Some(B256::ZERO), &h160, None, &words, Address::ZERO);
        assert_eq!(d.mode, "none");
        assert!(!d.ok && d.warnings.iter().any(|w| w.contains("InvalidJournalBinding(3)")), "{:?}", d.warnings);
        // Assigned: bilateral trust, allowed (and still nothing pinned).
        let assigned = check(marker_only, Some(B256::ZERO), &h160, None, &words, Address::repeat_byte(0xb0));
        assert!(assigned.ok, "{:?}", assigned.warnings);
        assert_eq!(assigned.header_free, vec![ByteRange { start: 0, end: 160 }]);
        // E: no expectedJournalHash: neither FULL nor NONE assumed.
        let e = check(marker_only, None, &h160, None, &words, Address::ZERO);
        assert_eq!(e.mode, "unknown");
        assert!(!e.ok && e.expected_hash_matches.is_none());
        // FIELDS ranges without the hash: still unknown, ranges reported.
        let e = check(fields(160), None, &h160, None, &words, Address::ZERO);
        assert_eq!(e.mode, "unknown");
        assert!(!e.ok);
        assert_eq!(e.pinned, vec![ByteRange { start: 0, end: 160 }]);
    }

    #[test]
    fn descriptors_follow_the_routers_submit_rules() {
        let risc0 = parse_proof_system("risc0").unwrap();
        let hash = B256::repeat_byte(1);
        let none = clear_marker(fields(32)) ^ fields(32);
        assert_eq!(submit_binding_refusal(none, B256::ZERO, risc0, Address::ZERO).map(|r| r.0), Some(3));
        assert_eq!(submit_binding_refusal(none, B256::ZERO, risc0, Address::repeat_byte(2)), None);
        assert_eq!(submit_binding_refusal(B256::ZERO, B256::ZERO, risc0, Address::ZERO).map(|r| r.0), Some(3));
        assert_eq!(
            submit_binding_refusal(fields(32), B256::ZERO, risc0, Address::repeat_byte(2)).map(|r| r.0),
            Some(1)
        );
        assert_eq!(submit_binding_refusal(fields(32), hash, risc0, Address::ZERO), None);
        assert_eq!(submit_binding_refusal(B256::ZERO, hash, risc0, Address::ZERO), None, "FULL");
        // A used range past the room under the prefix.
        let mut past = [0u8; 32];
        past[..4].copy_from_slice(&JOURNAL_PREFIX_MARKER.to_be_bytes());
        past[4..8].copy_from_slice(&((((MAX_STATEMENT_BYTES_WITH_PREFIX - 10) as u32) << 16) | 32).to_be_bytes());
        assert_eq!(submit_binding_refusal(B256::from(past), hash, risc0, Address::ZERO).map(|r| r.0), Some(5));
        // The proof-nonce marker outside SP1, and the prefix on OpenVM.
        let mut nonce = [0u8; 32];
        nonce[..4].copy_from_slice(&PROOF_NONCE_MARKER.to_be_bytes());
        assert_eq!(submit_binding_refusal(B256::from(nonce), hash, risc0, Address::ZERO).map(|r| r.0), Some(6));
        let openvm = zkminer_chain::auction::openvm_halo2_v1_id();
        assert_eq!(submit_binding_refusal(fields(32), hash, openvm, Address::ZERO).map(|r| r.0), Some(7));
        // A descriptor file with NONE and no assigned prover does not load.
        let dir = tempfile::tempdir().unwrap();
        let d = DescriptorFile {
            schema: DESCRIPTOR_FILE_SCHEMA,
            job_id: None,
            caller: None,
            program_id: B256::ZERO,
            proof_system_id: risc0,
            callback_contract: Address::ZERO,
            assigned_prover: Address::ZERO,
            tag: B256::ZERO,
            input_data: Bytes::new(),
            callback_extra_data: Bytes::new(),
            extra_verifier_data: Bytes::new(),
            expected_journal_hash: B256::ZERO,
            journal_fields: none,
        };
        let path = dir.path().join("none.json");
        std::fs::write(&path, serde_json::to_string(&d).unwrap()).unwrap();
        let e = DescriptorFile::load(&path).unwrap_err();
        assert!(format!("{e:#}").contains("InvalidJournalBinding(3)"), "{e:#}");
        let assigned = DescriptorFile { assigned_prover: Address::repeat_byte(0xb0), ..d };
        std::fs::write(&path, serde_json::to_string(&assigned).unwrap()).unwrap();
        assert!(DescriptorFile::load(&path).is_ok());
    }

    #[test]
    fn text_output_escapes_terminal_controls() {
        let hostile = "hemi-code://1/0x00\x1b[1A\x1b[2Kwitness job: false\x1b]52;c;Y3VybA==\x07\u{9b}31m\u{202e}txt";
        let p = printable(hostile);
        assert!(!p.chars().any(|c| c.is_control()), "{p}");
        assert!(
            p.contains("\\u{1b}[1A") && p.contains("\\u{7}") && p.contains("\\u{9b}") && p.contains("\\u{202e}"),
            "{p}"
        );
        assert_eq!(printable("plain ascii, ünïcode"), "plain ascii, ünïcode");
    }

    #[test]
    fn a_u64_above_i64_max_prints_as_a_json_spec() {
        let mut spec = zkminer_witness::requester::EnvelopeSpec {
            builder_type: 1,
            builder_id: Some(B256::repeat_byte(1)),
            builder_uris: vec!["hemi-code://743111/0x00112233445566778899aabbccddeeff00112233".into()],
            builder_params: Some("0x".into()),
            builder_params_abi: None,
            sources: vec![],
            limits: zkminer_witness::requester::LimitsSpec {
                max_fetches: 1,
                max_fetch_bytes: 1,
                max_request_bytes: 1,
                max_response_bytes: 1,
                max_builder_fuel: 1,
                max_builder_memory_bytes: 1,
                max_builder_seconds: 1,
                max_witness_bytes: 1,
                max_guest_cycles: 1,
            },
        };
        assert!(spec_text(&spec).unwrap().starts_with("--- spec (TOML) ---"));
        spec.limits.max_builder_fuel = u64::MAX;
        let text = spec_text(&spec).unwrap();
        assert!(text.starts_with("--- spec (JSON"), "{text}");
        assert!(text.contains(&u64::MAX.to_string()));
        // The JSON spec reads back.
        let body: String = text.lines().skip(1).collect::<Vec<_>>().join("\n");
        let back: zkminer_witness::requester::EnvelopeSpec = serde_json::from_str(&body).unwrap();
        assert_eq!(back.limits.max_builder_fuel, u64::MAX);
    }

    #[test]
    fn a_job_spec_makes_inputdata_and_a_descriptor_simulate_reads() {
        let dir = tempfile::tempdir().unwrap();
        let spec = dir.path().join("job.toml");
        std::fs::write(
            &spec,
            format!(
                r#"
program_id = "0x{pid}"
[binding]
header = ["uint:1", "bytes32:0x{b}"]
[envelope]
builder_id = "0x{bid}"
builder_uris = ["hemi-code://743111/0x00112233445566778899aabbccddeeff00112233"]
builder_params = "0x0a000000"
[[envelope.sources]]
class = "evm-rpc/v1"
chain_id = 31337
archive = true
method_set = "state-read"
max_proof_age = 0
[envelope.limits]
max_fetches = 4
max_fetch_bytes = 1048576
max_request_bytes = 65536
max_response_bytes = 1048576
max_builder_fuel = 1000000000
max_builder_memory_bytes = 67108864
max_builder_seconds = 30
max_witness_bytes = 65536
max_guest_cycles = 16777216
"#,
                pid = "ab".repeat(32),
                b = "11".repeat(32),
                bid = "42".repeat(32)
            ),
        )
        .unwrap();
        let out = dir.path().join("d.json");
        envelope_encode(&spec, None, None, Some(&out), true).unwrap();
        let d = DescriptorFile::load(&out).unwrap();
        assert_eq!(d.program_id, B256::repeat_byte(0xab));
        assert_eq!(d.proof_system_id, zkminer_chain::auction::risc_zero_groth16_v1_id());
        let env = zkminer_witness::envelope::decode(&d.input_data).unwrap();
        assert_eq!(env.job.builderId, B256::repeat_byte(0x42));
        assert_eq!(marker(d.journal_fields), Some(JOURNAL_PREFIX_MARKER));
        // A stable synthetic job id, and the file's own when it names one.
        assert_eq!(d.job_id_or_default(), d.job_id_or_default());
        let mut named = d.clone();
        named.job_id = Some(B256::repeat_byte(7));
        assert_eq!(named.job_id_or_default(), B256::repeat_byte(7));
        // An unknown field is refused.
        let mut v: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&out).unwrap()).unwrap();
        v["surprise"] = 1.into();
        std::fs::write(&out, v.to_string()).unwrap();
        assert!(DescriptorFile::load(&out).is_err());
    }

    #[test]
    fn byte_files_are_hex_text_or_raw() {
        let dir = tempfile::tempdir().unwrap();
        let hex = dir.path().join("a.hex");
        std::fs::write(&hex, "  0x0102ff\n").unwrap();
        assert_eq!(read_bytes_file(&hex).unwrap(), vec![1, 2, 0xff]);
        let raw = dir.path().join("a.bin");
        std::fs::write(&raw, [0u8, 0x78, 1]).unwrap();
        assert_eq!(read_bytes_file(&raw).unwrap(), vec![0, 0x78, 1]);
    }
}
