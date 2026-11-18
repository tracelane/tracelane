//! `tracelane-audit` — public verifier CLI for Tracelane tamper-evident
//! agent ledgers (ADR-034).
//!
//! Composes the shipped `tracelane-audit-verifier` crate with an HTTP
//! fetch step against `/v1/audit/export`, an argument parser, and a
//! PASS/FAIL renderer with field-level diff on failure. Intended to
//! be distributed as a single static (musl-linked) binary that an EU
//! regulator can `curl | sha256sum | run` without trusting Tracelane's
//! HTTPS endpoints — the binary itself is Cosign-signed via the
//! release workflow.
//!
//! ## Exit codes
//!
//! - `0` PASS — every check passed AND at least one publicly-included Rekor
//!   anchor covers the verified range. This is the only exit that means
//!   "a third party can trust this ledger".
//! - `1` FAIL — at least one check failed; field-level diff printed.
//! - `2` I/O or network failure before verification could run.
//! - `3` CHAIN-ONLY — the hash chain is internally consistent and nothing is
//!   positively wrong, but NO publicly-included anchor covers it. **B-381
//!   (2026-09-12):** before this exit existed, a ledger fabricated from scratch
//!   — two rows, a real-looking tenant id, no key, no anchor, produced in twenty
//!   lines of Python from the public hashing code — printed `PASS — every check
//!   passed.` and exited 0. Consistency is not evidence. A brand-new tenant whose
//!   first anchor has not landed yet gets this exit too, honestly: not tampered,
//!   not yet verifiable by anyone but us.
//!
//! ## V1 deferrals (ADR-034)
//!
//! `--format pdf` is not available; the text + json formats carry the full
//! report. On dates: the pages read on 2026-11-13 (artificialintelligenceact.eu)
//! give 2 December 2027 as the date the EU AI Act's high-risk obligations,
//! Article 12 record-keeping among them, apply to Annex III systems. Check the
//! Official Journal. This tool does not decide whether a system is high-risk
//! and makes no statement of conformity.

use std::io::{BufRead, BufReader, BufWriter, Cursor, Read, Write as _};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use anyhow::{Context as _, Result, bail};
use clap::{Parser, Subcommand, ValueEnum};
use tracelane_audit_verifier::{
    FormatVersion, VerifyOptions, VerifyReport, verify_ledger, verify_ledger_reader,
};
use uuid::Uuid;

mod evidence_pack;

#[derive(Debug, Parser)]
#[command(
    name = "tracelane-audit",
    version,
    about = "Verify a Tracelane tamper-evident audit ledger, offline.",
    long_about = "Independently verify the integrity of a Tracelane tamper-evident audit \
                  ledger range. Fetches NDJSON from /v1/audit/export (or reads a local file \
                  with --file), recomputes the per-tenant hash chain and the Merkle root \
                  per anchor batch, verifies the per-batch Ed25519 signature against the \
                  workspace's own public key (--tenant-pubkey), and for anchored batches \
                  verifies the Sigstore Rekor v2 inclusion proof + signed checkpoint from \
                  the exported bundle — all offline, no live Sigstore call required."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Verify an audit range. PASS prints a summary + exits 0;
    /// FAIL prints field-level diffs + exits 1.
    Verify(Box<VerifyArgs>),
    /// Offline: check that one ledger row is in a signed tree checkpoint
    /// (RFC 6962 inclusion proof against a C2SP checkpoint note).
    VerifyInclusion(InclusionArgs),
    /// Offline: check that a later signed tree checkpoint extends an earlier one
    /// (RFC 6962 consistency proof). No witness cosignature is checked.
    VerifyConsistency(ConsistencyArgs),
    /// Verify an action bundle offline, then write a control-mapping pack
    /// (CSV, OSCAL JSON, HTML). A bundle that fails verification gets no pack.
    /// The pack is a mapping, not an assessment.
    EvidencePack(EvidencePackArgs),
}

#[derive(Debug, clap::Args)]
struct TreeArgs {
    /// Independently pinned Ed25519 public-key FILE (hex or base64), as for `verify --pubkey`.
    #[arg(long, value_name = "PATH")]
    pubkey: PathBuf,
    /// Workspace UUID the checkpoint must be for.
    #[arg(long, value_name = "UUID")]
    workspace: Uuid,
    /// Proof FILE: one hex SHA-256 hash per line.
    #[arg(long, value_name = "PATH", required_unless_present = "ledger")]
    proof: Option<PathBuf>,
    /// Build the proof from this `ledger.ndjson` instead and print it. Its hash
    /// chain is NOT checked here; run `verify` on the bundle for that.
    #[arg(long, value_name = "PATH", conflicts_with = "proof")]
    ledger: Option<PathBuf>,
}

#[derive(Debug, clap::Args)]
struct InclusionArgs {
    /// The `tree-checkpoint.note` member of an action bundle.
    #[arg(long, value_name = "PATH")]
    checkpoint: PathBuf,
    /// Zero-based ledger sequence number of the row.
    #[arg(long)]
    index: u64,
    /// The row's `row_hash` (hex). Required with --proof; checked against --ledger.
    #[arg(long, value_name = "HEX", required_unless_present = "ledger")]
    row_hash: Option<String>,
    #[command(flatten)]
    tree: TreeArgs,
}

#[derive(Debug, clap::Args)]
struct ConsistencyArgs {
    /// The earlier checkpoint note.
    #[arg(long, value_name = "PATH")]
    old: PathBuf,
    /// The later checkpoint note.
    #[arg(long, value_name = "PATH")]
    new: PathBuf,
    #[command(flatten)]
    tree: TreeArgs,
}

#[derive(Debug, clap::Args)]
struct EvidencePackArgs {
    /// Action bundle ZIP to verify.
    #[arg(long, value_name = "PATH")]
    file: PathBuf,
    /// Independently pinned Ed25519 public-key FILE (base64 or hex). Required.
    #[arg(long, value_name = "PATH")]
    pubkey: Option<PathBuf>,
    /// Independently obtained TSA leaf certificate, DER or PEM. Repeatable.
    #[arg(long, value_name = "PATH")]
    tsa_cert: Vec<PathBuf>,
    /// New or empty directory to write the pack into.
    #[arg(long, value_name = "DIR")]
    out: PathBuf,
}

#[derive(Debug, clap::Args)]
struct VerifyArgs {
    /// Workspace UUID (the `tenant_id` on every audit row).
    #[arg(long, value_name = "UUID")]
    workspace: Option<Uuid>,

    /// ISO8601 lower bound (inclusive). Required unless --file.
    #[arg(long, value_name = "ISO8601")]
    from: Option<String>,

    /// ISO8601 upper bound (exclusive). Required unless --file.
    #[arg(long, value_name = "ISO8601")]
    to: Option<String>,

    /// Tracelane API base URL.
    // 2026-09-21: was `https://api.tracelane.dev`, a host that does not resolve —
    // the documented independent-verification quick-start failed at step 2 for
    // anyone who followed it. The production gateway is gateway.tracelane.dev.
    #[arg(
        long,
        value_name = "URL",
        default_value = "https://gateway.tracelane.dev"
    )]
    api_url: String,

    /// Workspace API key used for the online fetch. NOTE: API keys are
    /// workspace-scoped and revocable, but carry NO per-scope restriction and
    /// NO expiry — a key handed to a third party grants the workspace's full
    /// API surface. Prefer `--file` with an export you produced yourself.
    #[arg(long, value_name = "KEY", env = "TRACELANE_AUDIT_READ_KEY")]
    read_key: Option<String>,

    /// Offline mode: skip HTTP, verify a local NDJSON file. When set,
    /// --workspace / --from / --to are ignored.
    #[arg(long, value_name = "PATH")]
    file: Option<PathBuf>,

    /// Independently pinned Ed25519 public-key FILE for an offline action ZIP.
    #[arg(long, value_name = "PATH")]
    pubkey: Option<PathBuf>,

    /// Independently obtained TSA leaf certificate, DER or PEM. Repeat for rotation.
    #[arg(long, value_name = "PATH")]
    tsa_cert: Vec<PathBuf>,

    /// Report every interval longer than this many seconds between consecutive signed
    /// checkpoints of an action ZIP as a gap. Set it to your heartbeat cadence plus slack.
    #[arg(long, value_name = "SECONDS", value_parser = clap::value_parser!(u64).range(1..=3_153_600_000))]
    max_gap: Option<u64>,

    /// Public Sigstore Rekor v2 transparency-log base URL. Only used to
    /// display the queryable anchor location; anchor verification is
    /// fully offline from the bundled inclusion proof + checkpoint.
    #[arg(
        long,
        value_name = "URL",
        default_value = "https://log2025-1.rekor.sigstore.dev"
    )]
    rekor_url: String,

    /// The workspace's Ed25519 public key — the TRUST ROOT for anchor
    /// verification (ADR-062). base64 (44 chars) or hex (64 chars).
    /// Obtain it out-of-band from `/settings/audit` or
    /// `GET /v1/audit/pubkey`. REQUIRED to verify Rekor anchors: an
    /// anchor is accepted only when the batch signature verifies against
    /// THIS key (which binds the anchor's ECDSA key + log index) — so a
    /// real-but-attacker-planted Rekor entry is rejected. Without it the
    /// chain + Merkle structure still verify offline, but anchors are
    /// reported unverified.
    #[arg(long, value_name = "PUBKEY")]
    tenant_pubkey: Option<String>,

    /// AUD-29: Tracelane's PLATFORM Ed25519 pubkey (base64) — the key a
    /// workspace's batches are signed with before the workspace has its own
    /// (`GET /v1/audit/platform-pubkey`). Batches it signed verify as
    /// platform-signed and are counted apart; a platform-signed batch after a
    /// workspace-signed one FAILS. Defaults to the key pinned in this release.
    #[arg(long, value_name = "PUBKEY")]
    platform_pubkey: Option<String>,

    /// AUD-29: the first ledger seq your workspace key signed —
    /// `workspace_key_since_seq` from `GET /v1/audit/pubkey?tenant_id=…`. With it, a
    /// platform-signed batch at or past that seq FAILS even when the range you
    /// verify contains no workspace-signed batch.
    #[arg(long, value_name = "SEQ")]
    workspace_key_since_seq: Option<u64>,

    /// Skip anchor (inclusion-proof) verification entirely. Useful for
    /// air-gapped verification of the chain + Merkle structure only —
    /// with this flag no transparency-log anchor is checked.
    #[arg(long)]
    offline: bool,

    /// Legacy pin of the Rekor log's own signing pubkey as 32 raw bytes
    /// hex-encoded (64 hex chars). The public-log key is already pinned
    /// in the verifier; this override is retained for self-hosted Rekor
    /// (R1 H2 / ADR-018). For the anchor TRUST ROOT use --tenant-pubkey.
    #[arg(long, value_name = "HEX32")]
    pinned_pubkey: Option<String>,

    /// Output format.
    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    format: OutputFormat,

    /// Format-version override. v2 (default) matches the shipped
    /// ledger; v1 is for pre-Phase-3 historical chains.
    #[arg(long, value_enum, default_value_t = FormatVersionArg::V2)]
    format_version: FormatVersionArg,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum OutputFormat {
    /// Human-readable PASS/FAIL with field-level diffs.
    Text,
    /// Raw VerifyReport as JSON. Pipe through `jq`.
    Json,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum FormatVersionArg {
    V1,
    V2,
}

impl From<FormatVersionArg> for FormatVersion {
    fn from(v: FormatVersionArg) -> Self {
        match v {
            FormatVersionArg::V1 => FormatVersion::V1,
            FormatVersionArg::V2 => FormatVersion::V2,
        }
    }
}

/// Decode a 32-byte Ed25519 public key from base64 (standard, 44 chars —
/// the format published at `/settings/audit` + `GET /v1/audit/pubkey`) or
/// hex (64 chars, for symmetry with `--pinned-pubkey`).
///
/// # Errors
/// Returns `Err` if the string is neither valid base64 nor 64-char hex, or
/// decodes to a length other than 32 bytes.
fn decode_pubkey32(s: &str) -> Result<[u8; 32]> {
    use base64::Engine as _;
    let s = s.trim();
    let raw = if s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()) {
        hex::decode(s).context("is not valid hex")?
    } else {
        base64::engine::general_purpose::STANDARD
            .decode(s)
            .context("is not valid base64 (nor 64-char hex)")?
    };
    if raw.len() != 32 {
        bail!("must decode to exactly 32 bytes (got {})", raw.len());
    }
    let mut pk = [0u8; 32];
    pk.copy_from_slice(&raw);
    Ok(pk)
}

/// The three things a verified ledger can be, and the exit code each maps to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Verdict {
    /// Chain valid, signatures valid, no errors, no unverified anchors, AND at
    /// least one publicly-included anchor — exit 0.
    Pass,
    /// Nothing positively wrong, but no publicly-included anchor — exit 3.
    ChainOnly,
    /// Positive evidence of a problem, or anchors present but unverifiable — exit 1.
    Fail,
}

impl Verdict {
    /// The ONE place the report becomes a verdict. Kept pure so the fabricated-
    /// ledger case is a unit test rather than a regulator's discovery.
    fn of(report: &VerifyReport) -> Self {
        // B-483 (2026-09-21): rows inside no anchor batch below the anchor watermark
        // are unsigned and un-anchored — a hole every other counter reads green over.
        // Stated explicitly, though the verifier also emits an `anchor_coverage_gap`
        // error per hole, so `errors.is_empty()` would already refuse.
        let clean = report.anchors_unverified == 0
            && report.hash_chain_valid
            && report.signatures_valid
            && !report.strip_detected
            && report.rows_uncovered_by_anchors == 0
            && report.errors.is_empty();
        if !clean {
            return Verdict::Fail;
        }
        if report.anchors_included == 0 {
            return Verdict::ChainOnly;
        }
        Verdict::Pass
    }

    fn exit_code(self) -> ExitCode {
        match self {
            Verdict::Pass => ExitCode::from(0),
            Verdict::Fail => ExitCode::from(1),
            Verdict::ChainOnly => ExitCode::from(3),
        }
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Command::Verify(args) => {
            if let Some(code) = run_action_bundle(&args) {
                return code;
            }
            match run_verify(*args) {
                Ok(report) => Verdict::of(&report).exit_code(),
                Err(e) => {
                    eprintln!("tracelane-audit: error: {e:#}");
                    ExitCode::from(2)
                }
            }
        }
        Command::EvidencePack(args) => run_evidence_pack(&args),
        Command::VerifyInclusion(args) => tree_exit(verify_inclusion(&args)),
        Command::VerifyConsistency(args) => tree_exit(verify_consistency(&args)),
    }
}

use tracelane_audit_verifier::action::tree;
/// Exit code plus cause: 5 = the note does not verify under the pin, 4 = anything else.
type TreeFailure = (u8, anyhow::Error);
fn tree_exit(result: Result<String, TreeFailure>) -> ExitCode {
    match result {
        Ok(text) => {
            println!("{text}");
            ExitCode::SUCCESS
        }
        Err((code, e)) => {
            eprintln!("FAIL ({code}): {e:#}");
            ExitCode::from(code)
        }
    }
}
fn hash32(text: &str) -> Result<tree::Hash> {
    hex::decode(text.trim())
        .ok()
        .and_then(|raw| raw.try_into().ok())
        .context("expected a 32-byte hex hash")
}
impl TreeArgs {
    /// Errors fail CLOSED; trust comes only from the external --pubkey file.
    fn checkpoint(&self, path: &Path) -> Result<tree::Checkpoint, TreeFailure> {
        let pin = std::fs::read_to_string(&self.pubkey)
            .context("read external --pubkey")
            .and_then(|s| decode_pubkey32(&s))
            .map_err(|e| (5, e))?;
        let note = std::fs::read(path)
            .with_context(|| format!("read {}", path.display()))
            .map_err(|e| (4, e))?;
        tree::open_checkpoint(&note, &tree::origin(self.workspace), &pin).map_err(|e| (5, e))
    }
    /// The first `size` leaves of --ledger, when one was given.
    fn leaves(&self, size: u64) -> Result<Option<Vec<tree::Hash>>> {
        let Some(path) = &self.ledger else {
            return Ok(None);
        };
        let mut leaves = tree::ledger_leaves(&std::fs::read(path).context("read --ledger")?)?;
        if (leaves.len() as u64) < size {
            bail!("--ledger has fewer rows than the checkpoint tree size {size}");
        }
        leaves.truncate(usize::try_from(size)?);
        Ok(Some(leaves))
    }
    fn proof_file(&self) -> Result<Vec<tree::Hash>> {
        let path = self
            .proof
            .as_ref()
            .context("--proof or --ledger required")?;
        std::fs::read_to_string(path)
            .context("read --proof")?
            .lines()
            .map(hash32)
            .collect()
    }
}
fn proof_text(proof: &[tree::Hash]) -> String {
    proof
        .iter()
        .map(|h| format!("\n{}", hex::encode(h)))
        .collect()
}
fn verify_inclusion(args: &InclusionArgs) -> Result<String, TreeFailure> {
    let cp = args.tree.checkpoint(&args.checkpoint)?;
    (|| {
        let given = args.row_hash.as_deref().map(hash32).transpose()?;
        let (leaf, proof) = match args.tree.leaves(cp.size)? {
            Some(leaves) => {
                let index = usize::try_from(args.index)?;
                let leaf = *leaves.get(index).context("--index outside the tree")?;
                (leaf, tree::inclusion_proof(&leaves, index)?)
            }
            None => (
                tree::leaf_hash(&given.context("--row-hash required with --proof")?),
                args.tree.proof_file()?,
            ),
        };
        if given.is_some_and(|row| tree::leaf_hash(&row) != leaf) {
            bail!("--row-hash is not the row at --index in --ledger");
        }
        tree::verify_inclusion(&leaf, args.index, cp.size, &proof, &cp.root)?;
        Ok(format!(
            "PASS — row {} is included in the signed tree of size {} (root {}); proof:{}",
            args.index,
            cp.size,
            hex::encode(cp.root),
            proof_text(&proof)
        ))
    })()
    .map_err(|e| (4, e))
}
fn verify_consistency(args: &ConsistencyArgs) -> Result<String, TreeFailure> {
    let old = args.tree.checkpoint(&args.old)?;
    let new = args.tree.checkpoint(&args.new)?;
    (|| {
        let proof = match args.tree.leaves(new.size)? {
            Some(leaves) => tree::consistency_proof(&leaves, usize::try_from(old.size)?)?,
            None => args.tree.proof_file()?,
        };
        tree::verify_consistency(old.size, new.size, &old.root, &new.root, &proof)?;
        Ok(format!(
            "PASS — signed tree of size {} extends the signed tree of size {}; proof:{}",
            new.size,
            old.size,
            proof_text(&proof)
        ))
    })()
    .map_err(|e| (4, e))
}

/// Fail-CLOSED: the same offline verify as `verify`, and nothing is written
/// unless it passes and the shipped control map validates.
fn run_evidence_pack(args: &EvidencePackArgs) -> ExitCode {
    let report = match std::fs::File::open(&args.file)
        .map_err(|e| (2, format!("tracelane-audit: error: {e}")))
        .and_then(|file| verify_action_zip(file, args.pubkey.as_deref(), &args.tsa_cert, None))
    {
        Ok(report) => report,
        Err((code, message)) => {
            eprintln!("{message}");
            return ExitCode::from(code);
        }
    };
    let written = evidence_pack::shipped_map()
        .and_then(|map| evidence_pack::render(&map, &report))
        .and_then(|pack| evidence_pack::write(&args.out, &pack));
    if let Err(e) = written {
        eprintln!("tracelane-audit: error: {e:#}");
        return ExitCode::from(2);
    }
    println!("{report}");
    println!(
        "evidence pack written to {} ({}); a mapping only, not an assessment",
        args.out.display(),
        evidence_pack::FILES.join(", ")
    );
    ExitCode::SUCCESS
}

fn run_action_bundle(args: &VerifyArgs) -> Option<ExitCode> {
    if (args.pubkey.is_some() || !args.tsa_cert.is_empty() || args.max_gap.is_some())
        && args.file.is_none()
    {
        eprintln!(
            "--pubkey, --tsa-cert and --max-gap require --file; action bundles verify offline"
        );
        return Some(ExitCode::from(2));
    }
    let path = args.file.as_ref()?;
    let mut file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(_) => return None, // Preserve the legacy I/O diagnostic path.
    };
    // Exactly four magic bytes, without seeking or reopening a FIFO/stdin.
    let mut prefix = Vec::with_capacity(4);
    if let Err(e) = Read::by_ref(&mut file).take(4).read_to_end(&mut prefix) {
        eprintln!("tracelane-audit: error: {e}");
        return Some(ExitCode::from(2));
    }
    let is_zip = prefix == b"PK\x03\x04"
        || prefix == b"PK\x05\x06"
        || prefix == b"PK\x07\x08"
        || path.extension().is_some_and(|e| e == "zip");
    if !is_zip {
        if args.pubkey.is_some() || !args.tsa_cert.is_empty() || args.max_gap.is_some() {
            eprintln!("--pubkey, --tsa-cert and --max-gap require an action ZIP");
            return Some(ExitCode::from(4));
        }
        // Replay the sniffed bytes into the unchanged legacy verifier.
        let reader = BufReader::new(Cursor::new(prefix).chain(file));
        return Some(match run_verify_source(args, Some(Box::new(reader))) {
            Ok(report) => Verdict::of(&report).exit_code(),
            Err(e) => {
                eprintln!("tracelane-audit: error: {e:#}");
                ExitCode::from(2)
            }
        });
    }
    if file
        .metadata()
        .is_ok_and(|m| m.is_file() && m.len() > MAX_BUNDLE_BYTES)
    {
        eprintln!("FAIL (4): action bundle exceeds {MAX_BUNDLE_BYTES} byte limit");
        return Some(ExitCode::from(4));
    }
    let reader = Cursor::new(prefix).chain(file);
    Some(
        match verify_action_zip(reader, args.pubkey.as_deref(), &args.tsa_cert, args.max_gap) {
            Ok(report) => {
                match args.format {
                    OutputFormat::Json => match serde_json::to_string_pretty(&report) {
                        Ok(s) => println!("{s}"),
                        Err(e) => {
                            eprintln!("{e}");
                            return Some(ExitCode::from(2));
                        }
                    },
                    OutputFormat::Text => println!("{report}"),
                };
                ExitCode::SUCCESS
            }
            Err((code, message)) => {
                eprintln!("{message}");
                ExitCode::from(code)
            }
        },
    )
}

/// The one offline action-bundle verify, shared by `verify` and `evidence-pack`.
///
/// # Errors
/// Fails CLOSED with the exit code and the stderr line: 4 format, 5 trust, 6 semantics.
fn verify_action_zip(
    reader: impl Read,
    pubkey: Option<&Path>,
    tsa_cert: &[PathBuf],
    max_gap_secs: Option<u64>,
) -> std::result::Result<tracelane_audit_verifier::action::bundle::Report, (u8, String)> {
    let raw = read_bundle(reader).map_err(|e| (4, format!("FAIL (4): {e}")))?;
    let pin = pubkey
        .map(|p| {
            std::fs::read_to_string(p)
                .context("read external --pubkey")
                .and_then(|s| decode_pubkey32(&s))
        })
        .transpose()
        .map_err(|e| (5, format!("TRUST FAIL: {e}")))?;
    let tsa_pins = tsa_cert
        .iter()
        .map(std::fs::read)
        .collect::<std::io::Result<Vec<_>>>()
        .map_err(|e| (5, format!("TRUST FAIL: cannot read --tsa-cert: {e}")))?;
    if !tsa_pins
        .iter()
        .all(|p| tracelane_audit_verifier::action::timestamp::validate_pin(p).is_ok())
    {
        return Err((
            5,
            "TRUST FAIL: --tsa-cert is not a PEM or DER X.509 certificate".into(),
        ));
    }
    tracelane_audit_verifier::action::bundle::verify_with_options(
        &raw,
        pin,
        &tsa_pins,
        max_gap_secs.map(std::time::Duration::from_secs),
    )
    .map_err(|e| (e.code, format!("FAIL ({}): {}", e.code, e.detail)))
}

// Local resource bound for untrusted ZIP input, independent of plan entitlements.
use tracelane_audit_verifier::action::archive::MAX_BUNDLE_BYTES;
fn read_bundle(reader: impl Read) -> Result<Vec<u8>> {
    let mut raw = Vec::new();
    reader.take(MAX_BUNDLE_BYTES + 1).read_to_end(&mut raw)?;
    anyhow::ensure!(
        raw.len() as u64 <= MAX_BUNDLE_BYTES,
        "action bundle exceeds {MAX_BUNDLE_BYTES} byte limit"
    );
    Ok(raw)
}

fn run_verify(args: VerifyArgs) -> Result<VerifyReport> {
    run_verify_source(&args, None)
}
fn run_verify_source(args: &VerifyArgs, source: Option<Box<dyn BufRead>>) -> Result<VerifyReport> {
    // ── Source the NDJSON (file or HTTP fetch) ────────────────────────
    let ledger_path: PathBuf = match args.file.clone() {
        Some(path) => {
            eprintln!("tracelane-audit: verifying local file {}", path.display());
            path
        }
        None => fetch_audit_range(args).context("fetch /v1/audit/export")?,
    };

    // ── Build VerifyOptions ───────────────────────────────────────────
    let mut opts = VerifyOptions::default()
        .with_rekor_url(args.rekor_url.clone())
        .with_format(args.format_version.into());
    opts.offline = args.offline;
    opts.rekor_timeout = Duration::from_secs(10);
    if let Some(hex_pub) = args.pinned_pubkey.as_deref() {
        let raw = hex::decode(hex_pub).context("--pinned-pubkey is not valid hex")?;
        if raw.len() != 32 {
            bail!(
                "--pinned-pubkey must decode to exactly 32 bytes (got {})",
                raw.len()
            );
        }
        let mut pk = [0u8; 32];
        pk.copy_from_slice(&raw);
        opts.pinned_pubkey = Some(pk);
    }
    if let Some(tp) = args.tenant_pubkey.as_deref() {
        opts.tenant_pubkey = Some(decode_pubkey32(tp).context("--tenant-pubkey")?);
    }
    // AUD-29: an explicit flag wins; otherwise EVERY key pinned in this release (a
    // rotation keeps the retired key). Never a key read from the ledger itself.
    let platform_source = if let Some(pk) = args.platform_pubkey.as_deref() {
        opts.platform_pubkeys = vec![decode_pubkey32(pk).context("--platform-pubkey")?];
        "--platform-pubkey"
    } else {
        for pk in tracelane_audit_verifier::TRACELANE_PLATFORM_PUBKEYS_B64 {
            opts.platform_pubkeys
                .push(decode_pubkey32(pk).context("pinned platform key")?);
        }
        "pinned in this release"
    };
    if let Some(seq) = args.workspace_key_since_seq {
        opts.workspace_key_since_seq = Some(seq);
    }

    // ── Verify ────────────────────────────────────────────────────────
    let report = match source {
        Some(reader) => verify_ledger_reader(reader, &ledger_path.display().to_string(), &opts),
        None => verify_ledger(&ledger_path, &opts),
    }
    .context("verify_ledger")?;

    // ── Render ────────────────────────────────────────────────────────
    match args.format {
        OutputFormat::Json => print_json(&report)?,
        OutputFormat::Text => print_text(&report, platform_source),
    }

    Ok(report)
}

/// Stream the NDJSON range from the Tracelane API to a tempfile and
/// return its path. The path lives as long as the `TempPath` we leak
/// into the caller's scope — for a CLI the process exit cleans up.
fn fetch_audit_range(args: &VerifyArgs) -> Result<PathBuf> {
    let workspace = args
        .workspace
        .ok_or_else(|| anyhow::anyhow!("--workspace is required unless --file is given"))?;
    let from = args
        .from
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("--from is required unless --file is given"))?;
    let to = args
        .to
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("--to is required unless --file is given"))?;

    // The online fetch targets the endpoint the gateway actually mounts:
    // GET /v1/audit/export?since=&until= (crates/gateway/src/audit_export.rs).
    // It previously pointed at a route that has never existed —
    // so every online verify 404'd. The tenant is derived from the validated
    // credential, so `--workspace` is not a query parameter; it is kept only to
    // label the report. The endpoint is gated on the Enterprise export entitlement and returns 403
    // `entitlement_required` without it.
    let _ = workspace;
    let url = format!(
        "{base}/v1/audit/export?since={from}&until={to}",
        base = args.api_url.trim_end_matches('/'),
        from = urlencode(from),
        to = urlencode(to),
    );

    eprintln!("tracelane-audit: GET {url}");

    let agent = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(30))
        .build();
    let mut req = agent.get(&url);
    if let Some(key) = args.read_key.as_deref() {
        req = req.set("authorization", &format!("Bearer {key}"));
    }
    req = req.set("accept", "application/x-ndjson");

    let resp = req.call().with_context(|| format!("GET {url}"))?;
    if resp.status() != 200 {
        bail!("HTTP {} from {}", resp.status(), url);
    }

    // Stream to a tempfile.
    let temp = tempfile::Builder::new()
        .prefix("tracelane-audit-")
        .suffix(".ndjson")
        .tempfile()
        .context("create tempfile for NDJSON")?;
    let (file, path) = temp.keep().context("persist tempfile (keep)")?;
    let mut writer = BufWriter::new(file);
    let mut reader = resp.into_reader();
    std::io::copy(&mut reader, &mut writer).context("stream NDJSON to tempfile")?;
    writer.flush().ok();

    Ok(path)
}

/// Minimal URL component encoder. Only escapes chars that show up in
/// ISO8601 + UUIDs that aren't already URL-safe (`:` and `+`).
fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '_' | '.' | '~' => out.push(c),
            _ => {
                for b in c.to_string().as_bytes() {
                    out.push_str(&format!("%{b:02X}"));
                }
            }
        }
    }
    out
}

fn print_json(report: &VerifyReport) -> Result<()> {
    let stdout = std::io::stdout();
    let mut lock = stdout.lock();
    serde_json::to_writer_pretty(&mut lock, report)?;
    writeln!(lock).ok();
    Ok(())
}

fn print_text(report: &VerifyReport, platform_source: &str) {
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    let _ = writeln!(out, "Tracelane audit verification report");
    let _ = writeln!(out, "===================================");
    let _ = writeln!(out, "Ledger:                {}", report.ledger_path);
    let _ = writeln!(out, "Rows seen:             {}", report.rows_seen);
    let _ = writeln!(out, "Hash chain valid:      {}", report.hash_chain_valid);
    let _ = writeln!(
        out,
        "Signatures valid:      {}",
        if report.anchors_unverified > 0 {
            "NOT CHECKED — no --tenant-pubkey".to_string()
        } else {
            report.signatures_valid.to_string()
        }
    );
    let _ = writeln!(
        out,
        "Rekor anchors seen:    {} (resolved {})",
        report.rekor_anchors_seen, report.rekor_anchors_resolved
    );
    if report.platform_signed_batches > 0 {
        let _ = writeln!(
            out,
            "Platform-signed:       {} batch(es) verified against Tracelane's platform key \
             ({platform_source}) — before this workspace had its own key; Tracelane vouches \
             for these, not your key",
            report.platform_signed_batches
        );
    }
    let _ = writeln!(out);

    if report.anchors_unverified > 0 {
        // FAIL CLOSED (P0, 2026-08-07): anchor records were present but signature
        // and anchor verification never ran, so a forged anchor would not have
        // been caught. `signatures_valid` is vacuously true in chain-only mode.
        let _ = writeln!(
            out,
            "INCOMPLETE — {} anchor record(s) NOT verified: no trusted tenant key supplied.\n\
             The hash chain checked out, but signature and Rekor-anchor verification did not run.\n\
             Re-run with --tenant-pubkey <base64> (obtain out-of-band from the Tracelane\n\
             dashboard Settings → Audit signing key, or GET /v1/audit/pubkey).",
            report.anchors_unverified
        );
    } else if Verdict::of(report) == Verdict::Pass {
        let _ = writeln!(
            out,
            "PASS — every check passed; {} publicly-included anchor(s) cover the verified range.",
            report.anchors_included
        );
    } else if Verdict::of(report) == Verdict::ChainOnly {
        let _ = writeln!(
            out,
            "CHAIN-ONLY — the hash chain is internally consistent and nothing is positively wrong,\n\
             but NO publicly-included Rekor anchor covers this range. A consistent chain can be\n\
             produced by anyone holding the hashing code; only an anchor lets a third party trust\n\
             it. Not tampered — not yet verifiable. (exit 3)"
        );
    } else {
        let _ = writeln!(out, "FAIL — {} error(s) detected:", report.errors.len());
        for err in &report.errors {
            let seq = err.seq.map(|s| s.to_string()).unwrap_or_else(|| "-".into());
            let _ = writeln!(
                out,
                "  seq {seq}: [{kind}] {detail}",
                kind = err.kind,
                detail = err.detail,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// Minimal NDJSON ledger with one v2 row pointing at the genesis
    /// seed. Verification should produce hash_chain_valid=true and
    /// signatures_valid=true (no Rekor anchors → trivially valid).
    fn write_minimal_ledger_to(path: &Path) {
        // tenant_uuid bytes — deterministic for the test.
        let tenant_uuid = "00000000-0000-0000-0000-00000000000a";
        let tenant_bytes = uuid::Uuid::parse_str(tenant_uuid).unwrap().into_bytes();

        // Genesis seed: SHA256("tracelane-audit-v2-genesis\0" || tenant_uuid_bytes)
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(b"tracelane-audit-v2-genesis\0");
        h.update(tenant_bytes);
        let prev = h.finalize();
        let prev_hex = hex::encode(prev);

        // Build the canonical row-hash payload manually.
        let seq: u64 = 0;
        let event_type = "test.event";
        let actor = "test-actor";
        let payload_json = "{}";

        let mut buf = Vec::new();
        buf.extend_from_slice(b"tracelane-audit-row-v2\0");
        // lp(tenant_bytes) — 8-byte BE length prefix
        buf.extend_from_slice(&(tenant_bytes.len() as u64).to_be_bytes());
        buf.extend_from_slice(&tenant_bytes);
        // u64_be(seq)
        buf.extend_from_slice(&seq.to_be_bytes());
        // lp(event_type)
        buf.extend_from_slice(&(event_type.len() as u64).to_be_bytes());
        buf.extend_from_slice(event_type.as_bytes());
        // lp(actor)
        buf.extend_from_slice(&(actor.len() as u64).to_be_bytes());
        buf.extend_from_slice(actor.as_bytes());
        // lp(payload)
        buf.extend_from_slice(&(payload_json.len() as u64).to_be_bytes());
        buf.extend_from_slice(payload_json.as_bytes());
        // lp(prev_hash)
        buf.extend_from_slice(&(prev.len() as u64).to_be_bytes());
        buf.extend_from_slice(&prev);
        let row = {
            let mut hh = Sha256::new();
            hh.update(&buf);
            hh.finalize()
        };
        let row_hex = hex::encode(row);

        let line = serde_json::json!({
            "tenant_id": tenant_uuid,
            "seq": seq,
            "event_time": "2026-05-26T00:00:00Z",
            "event_type": event_type,
            "actor": actor,
            "payload": serde_json::json!({}),
            "prev_hash": prev_hex,
            "row_hash": row_hex,
        });
        let mut f = std::fs::File::create(path).unwrap();
        writeln!(f, "{}", serde_json::to_string(&line).unwrap()).unwrap();
    }

    /// B-381 — THE PROBE THE REVIEW RAN, as a test. A ledger built from the public
    /// hashing code alone (rows chained from the deterministic genesis seed, no key,
    /// no anchor) is exactly what `write_minimal_ledger_to` produces. It must never
    /// be PASS / exit 0; it is CHAIN-ONLY / exit 3.
    #[test]
    fn a_fabricated_unanchored_ledger_is_chain_only_never_pass() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        write_minimal_ledger_to(tmp.path());
        let args = VerifyArgs {
            workspace: None,
            from: None,
            to: None,
            api_url: String::new(),
            read_key: None,
            file: Some(tmp.path().to_path_buf()),
            rekor_url: "http://localhost:0".into(),
            pubkey: None,
            tsa_cert: Vec::new(),
            max_gap: None,
            tenant_pubkey: None,
            platform_pubkey: None,
            workspace_key_since_seq: None,
            offline: true,
            pinned_pubkey: None,
            format: OutputFormat::Json,
            format_version: FormatVersionArg::V2,
        };
        let report = run_verify(args).expect("verify runs");
        assert!(
            report.hash_chain_valid && report.errors.is_empty(),
            "the fabrication IS consistent"
        );
        assert_eq!(
            report.anchors_included, 0,
            "…and nothing external vouches for it"
        );
        assert_eq!(
            Verdict::of(&report),
            Verdict::ChainOnly,
            "a consistent, unanchored ledger must be CHAIN-ONLY, never PASS"
        );
        assert_ne!(Verdict::of(&report), Verdict::Pass);
    }

    /// The verdict table, every row — including that an included anchor is what
    /// separates PASS from CHAIN-ONLY, and that positive evidence outranks both.
    #[test]
    fn verdict_table() {
        fn base() -> VerifyReport {
            VerifyReport {
                ledger_path: "x".into(),
                rows_seen: 2,
                hash_chain_valid: true,
                signatures_valid: true,
                batch_signatures_verified: 1,
                rekor_anchors_seen: 1,
                rekor_anchors_resolved: 1,
                anchors_included: 1,
                anchors_unverified: 0,
                strip_detected: false,
                verified_from_seq: 0,
                trust_established: true,
                rows_uncovered_by_anchors: 0,
                rows_unanchored_tail: 0,
                platform_signed_batches: 0,
                platform_signed_ranges: Vec::new(),
                errors: Vec::new(),
            }
        }
        assert_eq!(Verdict::of(&base()), Verdict::Pass);
        // B-483: a hole below the anchor watermark is never green — even with every
        // other counter clean and an included anchor present, as prod had.
        let mut r = base();
        r.rows_uncovered_by_anchors = 100;
        assert_eq!(
            Verdict::of(&r),
            Verdict::Fail,
            "100 rows inside no anchor batch → fail, whatever anchors_included says"
        );
        let mut r = base();
        r.rows_unanchored_tail = 37;
        assert_eq!(
            Verdict::of(&r),
            Verdict::Pass,
            "the un-anchored TAIL past the last anchor is expected, not a hole"
        );
        let mut r = base();
        r.anchors_included = 0;
        assert_eq!(
            Verdict::of(&r),
            Verdict::ChainOnly,
            "no included anchor → chain-only"
        );
        let mut r = base();
        r.hash_chain_valid = false;
        assert_eq!(
            Verdict::of(&r),
            Verdict::Fail,
            "broken chain → fail, anchors or not"
        );
        let mut r = base();
        r.strip_detected = true;
        assert_eq!(Verdict::of(&r), Verdict::Fail, "a stripped anchor → fail");
        let mut r = base();
        r.anchors_unverified = 1;
        assert_eq!(
            Verdict::of(&r),
            Verdict::Fail,
            "unverifiable anchors → fail, never pass"
        );
        let mut r = base();
        r.anchors_included = 0;
        r.hash_chain_valid = false;
        assert_eq!(
            Verdict::of(&r),
            Verdict::Fail,
            "positive evidence outranks chain-only"
        );
    }

    #[test]
    fn offline_file_mode_passes_on_known_good_ledger() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        write_minimal_ledger_to(tmp.path());

        let args = VerifyArgs {
            workspace: None,
            from: None,
            to: None,
            api_url: String::new(),
            read_key: None,
            file: Some(tmp.path().to_path_buf()),
            rekor_url: "http://localhost:0".into(),
            pubkey: None,
            tsa_cert: Vec::new(),
            max_gap: None,
            tenant_pubkey: None,
            platform_pubkey: None,
            workspace_key_since_seq: None,
            offline: true,
            pinned_pubkey: None,
            format: OutputFormat::Json,
            format_version: FormatVersionArg::V2,
        };
        let report = run_verify(args).expect("verify should succeed");
        assert!(report.hash_chain_valid, "good ledger must pass chain check");
        assert!(report.signatures_valid, "no anchors → trivially valid sigs");
        assert!(
            report.errors.is_empty(),
            "no errors expected: {:?}",
            report.errors
        );
        // B-381: "passes" above means the CHECKS pass. With no anchor the
        // VERDICT is chain-only — the test's name predates that distinction.
        assert_eq!(Verdict::of(&report), Verdict::ChainOnly);
    }

    #[test]
    fn offline_file_mode_fails_on_tampered_row_hash() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        write_minimal_ledger_to(tmp.path());
        // Mutate the first hex digit of `row_hash` to a guaranteed-different
        // value. The previous implementation assumed the digit was `'0'`,
        // which broke whenever the fixture's deterministic hash changed
        // upstream. This version reads the current first digit and replaces
        // it with the next hex digit modulo 16, so the mutation always flips
        // a bit regardless of what the canonical fixture happens to produce.
        let raw = std::fs::read_to_string(tmp.path()).unwrap();
        let needle = "\"row_hash\":\"";
        let pos = raw.find(needle).expect("row_hash field present in fixture");
        let first_digit_idx = pos + needle.len();
        let first_digit_byte = raw.as_bytes()[first_digit_idx];
        let replacement_byte = match first_digit_byte {
            b'0'..=b'8' => first_digit_byte + 1,
            b'9' => b'a',
            b'a'..=b'e' => first_digit_byte + 1,
            b'f' => b'0',
            other => panic!("row_hash first char is not hex: 0x{other:02x}"),
        };
        let mut bytes = raw.into_bytes();
        bytes[first_digit_idx] = replacement_byte;
        let mutated = String::from_utf8(bytes).expect("hex-only mutation preserves utf-8");
        std::fs::write(tmp.path(), &mutated).unwrap();

        let args = VerifyArgs {
            workspace: None,
            from: None,
            to: None,
            api_url: String::new(),
            read_key: None,
            file: Some(tmp.path().to_path_buf()),
            rekor_url: "http://localhost:0".into(),
            pubkey: None,
            tsa_cert: Vec::new(),
            max_gap: None,
            tenant_pubkey: None,
            platform_pubkey: None,
            workspace_key_since_seq: None,
            offline: true,
            pinned_pubkey: None,
            format: OutputFormat::Json,
            format_version: FormatVersionArg::V2,
        };
        let report = run_verify(args).expect("verify call should not error");
        assert!(
            !report.hash_chain_valid || !report.errors.is_empty(),
            "tampered ledger must FAIL — got hash_chain_valid={} errors.len()={}",
            report.hash_chain_valid,
            report.errors.len()
        );
    }

    #[test]
    fn pinned_pubkey_parse_rejects_wrong_length() {
        let args = VerifyArgs {
            workspace: None,
            from: None,
            to: None,
            api_url: String::new(),
            read_key: None,
            file: Some(PathBuf::from("/dev/null")),
            rekor_url: "http://localhost:0".into(),
            pubkey: None,
            tsa_cert: Vec::new(),
            max_gap: None,
            tenant_pubkey: None,
            platform_pubkey: None,
            workspace_key_since_seq: None,
            offline: true,
            pinned_pubkey: Some("dead".into()), // 2 bytes; not 32
            format: OutputFormat::Json,
            format_version: FormatVersionArg::V2,
        };
        let err = run_verify(args).unwrap_err();
        assert!(
            err.to_string().contains("32 bytes"),
            "wrong-length pubkey must surface a 32-byte error, got: {err}"
        );
    }

    #[test]
    fn decode_pubkey32_accepts_base64_and_hex_rejects_bad() {
        use base64::Engine as _;
        let key = [7u8; 32];
        let b64 = base64::engine::general_purpose::STANDARD.encode(key);
        let hexed = hex::encode(key);
        // The published trust-root format (base64, 44 chars) round-trips…
        assert_eq!(decode_pubkey32(&b64).unwrap(), key);
        // …and the hex form (64 chars) decodes to the same 32 bytes.
        assert_eq!(decode_pubkey32(&hexed).unwrap(), key);
        // Whitespace is tolerated (copy-paste from a settings page).
        assert_eq!(decode_pubkey32(&format!("  {b64}\n")).unwrap(), key);
        // Wrong length (16-byte base64) is rejected with the byte-count error.
        let short = base64::engine::general_purpose::STANDARD.encode([1u8; 16]);
        assert!(
            decode_pubkey32(&short)
                .unwrap_err()
                .to_string()
                .contains("32 bytes")
        );
        // Garbage that is neither hex nor base64 is rejected.
        assert!(decode_pubkey32("not a key!!!").is_err());
    }

    #[test]
    fn urlencode_handles_iso8601() {
        // Plus signs (timezones), colons, slashes, dashes — common in ISO8601.
        assert_eq!(
            urlencode("2026-05-26T00:00:00Z"),
            "2026-05-26T00%3A00%3A00Z"
        );
        assert_eq!(
            urlencode("2026-05-26T00:00:00+05:30"),
            "2026-05-26T00%3A00%3A00%2B05%3A30"
        );
        // UUIDs are URL-safe as-is.
        assert_eq!(
            urlencode("00000000-0000-0000-0000-00000000000a"),
            "00000000-0000-0000-0000-00000000000a"
        );
    }
    #[test]
    fn tsa_pin_requires_local_file() {
        let Command::Verify(args) =
            Cli::try_parse_from(["tracelane-audit", "verify", "--tsa-cert", "synthetic.der"])
                .unwrap()
                .command
        else {
            panic!("verify subcommand expected");
        };
        assert_eq!(run_action_bundle(&args), Some(ExitCode::from(2)));
    }
    #[test]
    fn tsa_pin_requires_action_zip() {
        let temp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(temp.path(), b"{}").unwrap();
        let Command::Verify(args) = Cli::try_parse_from([
            "tracelane-audit",
            "verify",
            "--tsa-cert",
            "synthetic.der",
            "--file",
            temp.path().to_str().unwrap(),
        ])
        .unwrap()
        .command
        else {
            panic!("verify subcommand expected");
        };
        assert_eq!(run_action_bundle(&args), Some(ExitCode::from(4)));
    }
    // AUD-06: a 5-row ledger and two signed checkpoints (sizes 3 and 5), files only.
    fn tree_fixture(dir: &Path) -> String {
        let workspace = Uuid::from_u128(6);
        let key = ring::signature::Ed25519KeyPair::from_seed_unchecked(&[6; 32]).unwrap();
        let pin: [u8; 32] = ring::signature::KeyPair::public_key(&key)
            .as_ref()
            .try_into()
            .unwrap();
        let ledger: String = (0u8..5)
            .map(|i| {
                let hash = hex::encode([i; 32]);
                format!("{{\"seq\":{i},\"row_hash\":\"{hash}\"}}\n")
            })
            .collect();
        let leaves = tree::ledger_leaves(ledger.as_bytes()).unwrap();
        let origin = tree::origin(workspace);
        for (name, size) in [("old.note", 3), ("new.note", 5)] {
            let body = tree::checkpoint_body(&origin, size as u64, &tree::root(&leaves[..size]));
            let signature = key.sign(body.as_bytes());
            let note = tree::signed_note(&body, &origin, &pin, signature.as_ref());
            std::fs::write(dir.join(name), note).unwrap();
        }
        std::fs::write(dir.join("ledger.ndjson"), ledger).unwrap();
        std::fs::write(dir.join("pin.txt"), hex::encode(pin)).unwrap();
        std::fs::write(dir.join("other.txt"), hex::encode([9u8; 32])).unwrap();
        workspace.to_string()
    }
    /// Run a tree subcommand; `@name` arguments resolve inside `dir`.
    fn tree_run(dir: &Path, args: &[&str]) -> Result<String, TreeFailure> {
        let args = args.iter().map(|a| match a.strip_prefix('@') {
            Some(file) => dir.join(file).to_str().unwrap().to_owned(),
            None => (*a).to_owned(),
        });
        match Cli::try_parse_from(std::iter::once("tracelane-audit".to_owned()).chain(args))
            .unwrap()
            .command
        {
            Command::VerifyInclusion(args) => verify_inclusion(&args),
            Command::VerifyConsistency(args) => verify_consistency(&args),
            Command::Verify(_) | Command::EvidencePack(_) => {
                unreachable!("tree fixture runs tree subcommands only")
            }
        }
    }
    const INCLUSION: [&str; 5] = [
        "verify-inclusion",
        "--checkpoint",
        "@new.note",
        "--ledger",
        "@ledger.ndjson",
    ];
    const CONSISTENCY: [&str; 5] = [
        "verify-consistency",
        "--old",
        "@old.note",
        "--new",
        "@new.note",
    ];
    #[test]
    fn tree_proofs_verify_offline() {
        let dir = tempfile::tempdir().unwrap();
        let ws = tree_fixture(dir.path());
        let trust = ["--pubkey", "@pin.txt", "--workspace", ws.as_str()];
        let run = |args: &[&str]| tree_run(dir.path(), &[args, &trust[..]].concat());
        let out = run(&[&INCLUSION[..], &["--index", "3"]].concat()).unwrap();
        assert!(
            out.starts_with("PASS — row 3 is included in the signed tree of size 5"),
            "{out}"
        );
        // The printed proof, saved to a file, verifies without the ledger.
        let proof: Vec<&str> = out.lines().skip(1).collect();
        assert_eq!(proof.len(), 3, "{out}");
        std::fs::write(dir.path().join("proof.txt"), proof.join("\n")).unwrap();
        let row = hex::encode([3u8; 32]);
        run(&[
            &INCLUSION[..3],
            &["--index", "3", "--row-hash", &row, "--proof", "@proof.txt"],
        ]
        .concat())
        .unwrap();
        // A longer ledger still proves a row against the earlier, smaller checkpoint.
        run(&[
            "verify-inclusion",
            "--checkpoint",
            "@old.note",
            "--index",
            "2",
            "--ledger",
            "@ledger.ndjson",
        ])
        .unwrap();
        let out = run(&[&CONSISTENCY[..], &["--ledger", "@ledger.ndjson"]].concat()).unwrap();
        assert!(
            out.starts_with("PASS — signed tree of size 5 extends the signed tree of size 3"),
            "{out}"
        );
        let proof: Vec<&str> = out.lines().skip(1).collect();
        std::fs::write(dir.path().join("consistency.txt"), proof.join("\n")).unwrap();
        run(&[&CONSISTENCY[..], &["--proof", "@consistency.txt"]].concat()).unwrap();
    }
    #[test]
    fn tree_proofs_refuse_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let ws = tree_fixture(dir.path());
        let code = |args: &[&str], pin: &str, ws: &str| {
            let trust = ["--pubkey", pin, "--workspace", ws];
            tree_run(dir.path(), &[args, &trust[..]].concat())
                .unwrap_err()
                .0
        };
        // A row hash that is not the row at that index.
        let absent = hex::encode([7u8; 32]);
        let wrong_row = [&INCLUSION[..], &["--index", "3", "--row-hash", &absent]].concat();
        assert_eq!(code(&wrong_row, "@pin.txt", &ws), 4);
        // An index outside the signed tree, even though the ledger file is longer.
        let outside = [
            "verify-inclusion",
            "--checkpoint",
            "@old.note",
            "--ledger",
            "@ledger.ndjson",
            "--index",
            "4",
        ];
        assert_eq!(code(&outside, "@pin.txt", &ws), 4);
        // Another key, and another workspace, are trust failures.
        let at3 = [&INCLUSION[..], &["--index", "3"]].concat();
        assert_eq!(code(&at3, "@other.txt", &ws), 5);
        assert_eq!(code(&at3, "@pin.txt", &Uuid::from_u128(7).to_string()), 5);
        // A valid proof for row 2 does not verify for row 3.
        let ledger = std::fs::read(dir.path().join("ledger.ndjson")).unwrap();
        let proof = tree::inclusion_proof(&tree::ledger_leaves(&ledger).unwrap(), 2).unwrap();
        std::fs::write(
            dir.path().join("proof.txt"),
            proof_text(&proof).trim_start(),
        )
        .unwrap();
        let row = hex::encode([3u8; 32]);
        let stale = [
            &INCLUSION[..3],
            &["--index", "3", "--row-hash", &row, "--proof", "@proof.txt"],
        ]
        .concat();
        assert_eq!(code(&stale, "@pin.txt", &ws), 4);
        // Swapped checkpoints: the "new" tree is smaller than the "old" one.
        let swapped = [
            "verify-consistency",
            "--old",
            "@new.note",
            "--new",
            "@old.note",
            "--ledger",
            "@ledger.ndjson",
        ];
        assert_eq!(code(&swapped, "@pin.txt", &ws), 4);
        // A rewritten early row: the ledger no longer reproduces the signed roots.
        let text = String::from_utf8(ledger).unwrap();
        let rewritten = text.replacen("0101", "0f0f", 1);
        assert_ne!(rewritten, text);
        std::fs::write(dir.path().join("ledger.ndjson"), rewritten).unwrap();
        let args = [&CONSISTENCY[..], &["--ledger", "@ledger.ndjson"]].concat();
        assert_eq!(code(&args, "@pin.txt", &ws), 4);
    }
}
