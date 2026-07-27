//! `tracelane-audit` — public verifier CLI for Tracelane tamper-evident
//! agent ledgers (ADR-034).
//!
//! Composes the shipped `tracelane-audit-verifier` crate with an HTTP
//! fetch step against `/api/audit/range`, an argument parser, and a
//! PASS/FAIL renderer with field-level diff on failure. Intended to
//! be distributed as a single static (musl-linked) binary that an EU
//! regulator can `curl | sha256sum | run` without trusting Tracelane's
//! HTTPS endpoints — the binary itself is Cosign-signed via the
//! release workflow.
//!
//! ## Exit codes
//!
//! - `0` PASS — every check passed.
//! - `1` FAIL — at least one check failed; field-level diff printed.
//! - `2` I/O or network failure before verification could run.
//!
//! ## V1 deferrals (ADR-034)
//!
//! `--format pdf` is queued for V1.1; the text + json formats cover
//! the regulator-runnable invariant for V1 launch (2026-06-16) +
//! Article 12 enforcement date (2026-08-02).

use std::io::{BufWriter, Write as _};
#[cfg(test)]
use std::path::Path;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use anyhow::{Context as _, Result, bail};
use clap::{Parser, Subcommand, ValueEnum};
use tracelane_audit_verifier::{FormatVersion, VerifyOptions, VerifyReport, verify_ledger};
use uuid::Uuid;

#[derive(Debug, Parser)]
#[command(
    name = "tracelane-audit",
    version,
    about = "Verify a Tracelane tamper-evident audit ledger (EU AI Act Article 12).",
    long_about = "Independently verify the integrity of a Tracelane tamper-evident audit \
                  ledger range. Fetches NDJSON from /api/audit/range (or reads a local file \
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
    Verify(VerifyArgs),
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
    #[arg(long, value_name = "URL", default_value = "https://api.tracelane.dev")]
    api_url: String,

    /// Audit-read API key (issued by Tracelane support; scope:
    /// audit:read for one workspace).
    #[arg(long, value_name = "KEY", env = "TRACELANE_AUDIT_READ_KEY")]
    read_key: Option<String>,

    /// Offline mode: skip HTTP, verify a local NDJSON file. When set,
    /// --workspace / --from / --to are ignored.
    #[arg(long, value_name = "PATH")]
    file: Option<PathBuf>,

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

    /// Skip anchor (inclusion-proof) verification entirely. Useful for
    /// air-gapped verification of the chain + Merkle structure only —
    /// does NOT satisfy Article 12 transparency-log conformance on its
    /// own.
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

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Command::Verify(args) => match run_verify(args) {
            Ok(report) => {
                if report.hash_chain_valid && report.signatures_valid && report.errors.is_empty() {
                    ExitCode::from(0)
                } else {
                    ExitCode::from(1)
                }
            }
            Err(e) => {
                eprintln!("tracelane-audit: error: {e:#}");
                ExitCode::from(2)
            }
        },
    }
}

fn run_verify(args: VerifyArgs) -> Result<VerifyReport> {
    // ── Source the NDJSON (file or HTTP fetch) ────────────────────────
    let ledger_path: PathBuf = match args.file.clone() {
        Some(path) => {
            eprintln!("tracelane-audit: verifying local file {}", path.display());
            path
        }
        None => fetch_audit_range(&args).context("fetch /api/audit/range")?,
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

    // ── Verify ────────────────────────────────────────────────────────
    let report = verify_ledger(&ledger_path, &opts).context("verify_ledger")?;

    // ── Render ────────────────────────────────────────────────────────
    match args.format {
        OutputFormat::Json => print_json(&report)?,
        OutputFormat::Text => print_text(&report),
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

    let url = format!(
        "{base}/api/audit/range?workspace={ws}&from={from}&to={to}",
        base = args.api_url.trim_end_matches('/'),
        ws = workspace,
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

fn print_text(report: &VerifyReport) {
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    let _ = writeln!(out, "Tracelane audit verification report");
    let _ = writeln!(out, "===================================");
    let _ = writeln!(out, "Ledger:                {}", report.ledger_path);
    let _ = writeln!(out, "Rows seen:             {}", report.rows_seen);
    let _ = writeln!(out, "Hash chain valid:      {}", report.hash_chain_valid);
    let _ = writeln!(out, "Signatures valid:      {}", report.signatures_valid);
    let _ = writeln!(
        out,
        "Rekor anchors seen:    {} (resolved {})",
        report.rekor_anchors_seen, report.rekor_anchors_resolved
    );
    let _ = writeln!(out);

    if report.errors.is_empty() && report.hash_chain_valid && report.signatures_valid {
        let _ = writeln!(out, "PASS — every check passed.");
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
            tenant_pubkey: None,
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
            tenant_pubkey: None,
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
            tenant_pubkey: None,
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
}
