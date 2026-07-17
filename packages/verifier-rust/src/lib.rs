//! Reference verifier for Tracelane tamper-evident audit ledgers.
//!
//! Reads an NDJSON ledger (one [`AuditRow`] per line) and produces a
//! deterministic [`VerifyReport`] with four independent checks:
//!
//! 1. **Hash chain replay** — recompute every `row_hash` from the
//!    canonical format (see "Format versions" below), and verify each
//!    row's `prev_hash` matches the previous row's recomputed hash.
//!
//! 2. **Sequence monotonicity** — `seq` must start at zero (or at the
//!    persisted resume point if the export includes a manifest) and
//!    increment by 1 on every row.
//!
//! 3. **Merkle anchor verification** — for each contiguous run of rows
//!    sharing the same `rekor_entry_id`, recompute the Merkle root over
//!    those rows' `row_hash`es. Fetch the Rekor entry by UUID, parse
//!    the embedded `hashedrekord` body, and **verify the Ed25519
//!    signature against the recomputed root using the public key the
//!    Rekor body carries**. This is the real cryptographic check that
//!    was a stub before R1 H1.
//!
//! 4. **Pinned root pubkey** *(optional)* — when [`VerifyOptions::pinned_pubkey`]
//!    is set, every anchor's pubkey must match. Defends against a
//!    malicious Rekor mirror that might substitute a different key
//!    (R1 H2). Operators source the pinned key from their out-of-band
//!    Tracelane root attestation.
//!
//! ## Format versions
//!
//! Each row may carry a `format` marker (`"v2.1"` / `"v2"` / `"v1"`) that
//! selects its verification path; unmarked rows fall back to
//! [`VerifyOptions::format_version`] (default `V2`, for pre-ADR-050 packs).
//!
//! - **v2.1 (ADR-050, current)**: `payload` is the **verbatim stored
//!   canonical JSON string** (the exact `row_hash` preimage). The verifier
//!   SHA-256s it byte-for-byte and never re-derives it. Same length-prefixed
//!   framing + RFC-6962 tree + genesis seed as v2. Because no component
//!   re-canonicalizes, the Rust / Python / TypeScript verifiers are
//!   **identical by construction** — the numeric-canonicalization parity bug
//!
//! - **v2 (legacy re-derive)**: length-prefixed, domain-separated framing per
//!   `crates/gateway/src/audit_format/mod.rs`:
//!   ```text
//!   row_hash = SHA256(
//!       "tracelane-audit-row-v2\0"
//!       || lp(tenant_id_bytes)        // 16-byte UUID
//!       || u64_be(seq)
//!       || lp(event_type) || lp(actor) || lp(canonical_payload)
//!       || lp(prev_hash)              // 32 raw bytes
//!   )
//!   ```
//!   Merkle tree is RFC 6962 §2.1 (leaf=0x00, node=0x01, raw bytes,
//!   lone-odd-leaf promoted not duplicated). Genesis `prev_hash` is
//!   `SHA256("tracelane-audit-v2-genesis\0" || tenant_id_bytes)`.
//!
//! - **v1 (legacy)**: `format!("{tenant_id}|{seq}|...")`, Bitcoin-style
//!   duplicated-tail Merkle. Vulnerable to field-boundary + second-
//!   pre-Phase-3 logs only.
//!
//! The default `format_version` (via [`VerifyOptions::format_version`]) is
//! the fallback for unmarked rows; per-row `format` markers override it. The
//! Python and TypeScript verifiers mirror this exactly.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormatVersion {
    /// v2.1 (ADR-050) — **authoritative-once**. `payload` is the verbatim
    /// stored canonical JSON string (the exact `row_hash` preimage); it is
    /// SHA-256'd byte-for-byte, never re-derived. This eliminates the
    /// three reference verifiers identical by construction. The format for
    /// new exports; selected per-row via the `format` marker.
    V2_1,
    /// v2 — length-prefixed, domain-separated framing, but `payload` is a
    /// nested object the verifier RE-canonicalizes. That re-derivation is
    /// lossy for JS-unsafe numbers (`1.0`, `>2^53`, `1e2`, `0.50`) across
    V2,
    /// Pre-Phase-3 legacy format. Vulnerable to documented attacks;
    /// supported only so existing customers can verify already-anchored
    /// historical chains during migration.
    V1,
}

impl FormatVersion {
    /// v2 and v2.1 share identical framing (length-prefixed row hash,
    /// RFC-6962 Merkle, per-tenant genesis seed) — they differ ONLY in how
    /// the canonical payload string is obtained (verbatim vs re-derived).
    fn is_v2_family(self) -> bool {
        matches!(self, FormatVersion::V2 | FormatVersion::V2_1)
    }
}

/// Resolve the effective format for a single row. The per-row `format`
/// marker is authoritative (the export self-describes — ADR-050: "branch
/// on the marker, not type-sniffing"); rows without a marker fall back to
/// the caller's `default` (which stays `V2` for pre-ADR-050 packs).
fn resolve_format(row: &AuditRow, default: FormatVersion) -> FormatVersion {
    match row.format.as_deref() {
        Some("v2.1") => FormatVersion::V2_1,
        Some("v2") => FormatVersion::V2,
        Some("v1") => FormatVersion::V1,
        _ => default,
    }
}

#[derive(Debug, Clone)]
pub struct VerifyOptions {
    pub format_version: FormatVersion,
    /// Skip Rekor fetches. Hash-chain + Merkle reconstruction still
    /// run; signature verification is recorded as "skipped".
    pub offline: bool,
    /// Rekor base URL. Default `https://rekor.sigstore.dev`.
    pub rekor_url: String,
    /// Per-request HTTP timeout for Rekor.
    pub rekor_timeout: std::time::Duration,
    /// When `Some(pubkey)`, every anchor's pubkey MUST byte-match.
    /// Closes R1 H2 — without this, a malicious Rekor mirror could
    /// substitute a different key.
    pub pinned_pubkey: Option<[u8; 32]>,
    /// ADR-062 C2: the TRUSTED tenant Ed25519 pubkey (32 raw bytes), obtained
    /// out-of-band from Tracelane's TLS-authenticated domain. Anchor records whose
    /// embedded pubkey differs are REJECTED (fail closed). `None` → chain-only:
    /// signatures/anchors are reported UNVERIFIED (never green).
    pub tenant_pubkey: Option<[u8; 32]>,
}

impl Default for VerifyOptions {
    fn default() -> Self {
        Self {
            format_version: FormatVersion::V2,
            offline: false,
            rekor_url: "https://rekor.sigstore.dev".to_string(),
            rekor_timeout: std::time::Duration::from_secs(10),
            pinned_pubkey: None,
            tenant_pubkey: None,
        }
    }
}

impl VerifyOptions {
    pub fn offline() -> Self {
        Self {
            offline: true,
            ..Self::default()
        }
    }

    pub fn with_rekor_url(mut self, url: impl Into<String>) -> Self {
        self.rekor_url = url.into();
        self
    }

    pub fn with_format(mut self, v: FormatVersion) -> Self {
        self.format_version = v;
        self
    }

    pub fn with_pinned_pubkey(mut self, pubkey: [u8; 32]) -> Self {
        self.pinned_pubkey = Some(pubkey);
        self
    }

    /// Set the TRUSTED tenant Ed25519 pubkey (ADR-062 C2) — the single external
    /// trust root for signature + anchor verification.
    pub fn with_tenant_pubkey(mut self, pubkey: [u8; 32]) -> Self {
        self.tenant_pubkey = Some(pubkey);
        self
    }
}

/// Single line of an audit ledger NDJSON.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRow {
    /// Per-row wire-format marker (ADR-050): `"v2.1"` (payload is the
    /// verbatim canonical string), `"v2"`, or `"v1"`. Absent on
    /// pre-ADR-050 exports → the caller's default format applies.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    pub tenant_id: String,
    pub seq: u64,
    pub event_time: String,
    pub event_type: String,
    pub actor: String,
    /// For `v2.1` this is a JSON **string** (the verbatim canonical
    /// payload); for `v2`/`v1` it is the nested payload object.
    pub payload: serde_json::Value,
    /// Hex-encoded SHA-256 of the previous row, or the per-tenant
    /// genesis seed for `seq=0` (v2). v1 used `""` for genesis.
    pub prev_hash: String,
    /// Hex-encoded SHA-256 of this row.
    pub row_hash: String,
    /// Rekor entry UUID. Multiple consecutive rows share the same UUID
    /// to identify the Merkle anchor batch they belong to.
    #[serde(default)]
    pub rekor_entry_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VerifyError {
    pub seq: Option<u64>,
    pub kind: String,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VerifyReport {
    pub ledger_path: String,
    pub rows_seen: u64,
    pub hash_chain_valid: bool,
    /// Aggregate of every anchor's Ed25519 verification. `true` iff
    /// every anchor's signature validated against the recomputed
    /// Merkle root using the embedded (or pinned) pubkey.
    pub signatures_valid: bool,
    pub rekor_anchors_seen: u64,
    /// How many anchors successfully verified end-to-end (recomputed
    /// Merkle root matched the signed payload AND the Ed25519
    /// signature validated AND the pinned-pubkey check passed).
    pub rekor_anchors_resolved: u64,
    /// Anchors whose FULL public-inclusion proof + checkpoint verified
    /// (ADR-062 Layer 2+3). `> 0` is the only basis for a green "publicly
    /// anchored" claim.
    pub anchors_included: u64,
    /// An anchor committed to "anchored" but its rekor bundle is absent
    /// (a strip/downgrade attack — ADR-062 H3).
    pub strip_detected: bool,
    pub errors: Vec<VerifyError>,
}

impl VerifyReport {
    fn empty_labeled(ledger_path: &str) -> Self {
        Self {
            ledger_path: ledger_path.to_owned(),
            rows_seen: 0,
            hash_chain_valid: true,
            signatures_valid: true,
            rekor_anchors_seen: 0,
            rekor_anchors_resolved: 0,
            anchors_included: 0,
            strip_detected: false,
            errors: Vec::new(),
        }
    }
}

// ---------------------------------------------------------------------
// Hash format implementations
// ---------------------------------------------------------------------

const DOMAIN_ROW_V2: &[u8] = b"tracelane-audit-row-v2\0";
const DOMAIN_GENESIS_V2: &[u8] = b"tracelane-audit-v2-genesis\0";
const MERKLE_LEAF_PREFIX: u8 = 0x00;
const MERKLE_NODE_PREFIX: u8 = 0x01;

/// v2 row hash. Mirrors `audit_format::row_hash_v2`.
fn row_hash_v2(
    prev_hash: &[u8; 32],
    tenant_uuid_bytes: &[u8; 16],
    seq: u64,
    event_type: &str,
    actor: &str,
    canonical_payload_json: &str,
) -> [u8; 32] {
    let mut buf = Vec::with_capacity(
        DOMAIN_ROW_V2.len()
            + 8
            + 16
            + 8
            + 8
            + event_type.len()
            + 8
            + actor.len()
            + 8
            + canonical_payload_json.len()
            + 8
            + prev_hash.len(),
    );
    buf.extend_from_slice(DOMAIN_ROW_V2);
    write_lp(&mut buf, tenant_uuid_bytes);
    buf.extend_from_slice(&seq.to_be_bytes());
    write_lp(&mut buf, event_type.as_bytes());
    write_lp(&mut buf, actor.as_bytes());
    write_lp(&mut buf, canonical_payload_json.as_bytes());
    write_lp(&mut buf, prev_hash);
    sha256(&buf)
}

/// v2 genesis seed.
fn genesis_v2(tenant_uuid_bytes: &[u8; 16]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(DOMAIN_GENESIS_V2.len() + 16);
    buf.extend_from_slice(DOMAIN_GENESIS_V2);
    buf.extend_from_slice(tenant_uuid_bytes);
    sha256(&buf)
}

/// RFC 6962 §2.1 Merkle root over a slice of leaf hashes.
fn merkle_root_v2(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() {
        return sha256(b"");
    }
    let mut level: Vec<[u8; 32]> = leaves
        .iter()
        .map(|leaf| {
            let mut buf = Vec::with_capacity(1 + 32);
            buf.push(MERKLE_LEAF_PREFIX);
            buf.extend_from_slice(leaf);
            sha256(&buf)
        })
        .collect();

    while level.len() > 1 {
        let mut next: Vec<[u8; 32]> = Vec::with_capacity(level.len().div_ceil(2));
        let mut chunks = level.chunks_exact(2);
        for pair in &mut chunks {
            let mut buf = Vec::with_capacity(1 + 64);
            buf.push(MERKLE_NODE_PREFIX);
            buf.extend_from_slice(&pair[0]);
            buf.extend_from_slice(&pair[1]);
            next.push(sha256(&buf));
        }
        if let [lone] = chunks.remainder() {
            next.push(*lone);
        }
        level = next;
    }
    level[0]
}

/// v1 (legacy) row hash. Vulnerable; supported for historical chains.
fn row_hash_v1(
    prev_hash_hex: &str,
    tenant_id_str: &str,
    seq: u64,
    event_type: &str,
    actor: &str,
    payload_json: &str,
) -> String {
    let input =
        format!("{tenant_id_str}|{seq}|{event_type}|{actor}|{payload_json}|{prev_hash_hex}");
    hex::encode(sha256(input.as_bytes()))
}

/// Canonical JSON for v2 (JCS subset — sorted keys, no whitespace).
fn canonical_payload_v2(value: &serde_json::Value) -> String {
    let mut out = String::new();
    canon_into(value, &mut out);
    out
}

fn canon_into(value: &serde_json::Value, out: &mut String) {
    match value {
        serde_json::Value::Null => out.push_str("null"),
        serde_json::Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        serde_json::Value::Number(n) => out.push_str(&n.to_string()),
        serde_json::Value::String(s) => {
            out.push('"');
            for c in s.chars() {
                match c {
                    '"' => out.push_str("\\\""),
                    '\\' => out.push_str("\\\\"),
                    '\n' => out.push_str("\\n"),
                    '\r' => out.push_str("\\r"),
                    '\t' => out.push_str("\\t"),
                    '\x08' => out.push_str("\\b"),
                    '\x0c' => out.push_str("\\f"),
                    c if (c as u32) < 0x20 => {
                        use std::fmt::Write as _;
                        let _ = write!(out, "\\u{:04x}", c as u32);
                    }
                    c => out.push(c),
                }
            }
            out.push('"');
        }
        serde_json::Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                canon_into(item, out);
            }
            out.push(']');
        }
        serde_json::Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            out.push('{');
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                canon_into(&serde_json::Value::String((*k).clone()), out);
                out.push(':');
                canon_into(&map[*k], out);
            }
            out.push('}');
        }
    }
}

/// v1 canonical payload — `serde_json::to_string` (whatever order
/// the input map happened to have).
fn canonical_payload_v1(value: &serde_json::Value) -> String {
    serde_json::to_string(value).unwrap_or_default()
}

// ---------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------

fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

fn write_lp(buf: &mut Vec<u8>, bytes: &[u8]) {
    buf.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    buf.extend_from_slice(bytes);
}

fn hex_decode_32(s: &str) -> Result<[u8; 32], String> {
    if s.len() != 64 {
        return Err(format!("hex hash must be 64 chars, got {}", s.len()));
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        let hi = hex_nibble(s.as_bytes()[2 * i]).ok_or_else(|| "non-hex char".to_string())?;
        let lo = hex_nibble(s.as_bytes()[2 * i + 1]).ok_or_else(|| "non-hex char".to_string())?;
        *byte = (hi << 4) | lo;
    }
    Ok(out)
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn uuid_str_to_bytes(s: &str) -> Result<[u8; 16], String> {
    let cleaned: String = s.chars().filter(|c| *c != '-').collect();
    if cleaned.len() != 32 {
        return Err(format!("tenant_id is not a UUID: {s}"));
    }
    let mut out = [0u8; 16];
    for (i, byte) in out.iter_mut().enumerate() {
        let hi = hex_nibble(cleaned.as_bytes()[2 * i])
            .ok_or_else(|| "non-hex char in UUID".to_string())?;
        let lo = hex_nibble(cleaned.as_bytes()[2 * i + 1])
            .ok_or_else(|| "non-hex char in UUID".to_string())?;
        *byte = (hi << 4) | lo;
    }
    Ok(out)
}

// ---------------------------------------------------------------------
// Public legacy helpers (used by the verifier-python / -typescript
// crates' Rust-FFI bindings; kept as `pub` for compat)
// ---------------------------------------------------------------------

/// **v1 only** — public for cross-language reference. Vulnerable to
/// field-boundary attack; new code should not call this.
pub fn compute_row_hash(
    prev_hash: &str,
    tenant_id: &str,
    seq: u64,
    event_type: &str,
    actor: &str,
    payload_json: &str,
) -> String {
    row_hash_v1(prev_hash, tenant_id, seq, event_type, actor, payload_json)
}

// ---------------------------------------------------------------------
// ADR-062 Amendment 1 — offline anchor verification (Rekor v2 has no online
// lookup; the inclusion proof + checkpoint are bundled in the export).
// ---------------------------------------------------------------------

/// FROZEN anchor domain tags (must match the gateway).
const DOMAIN_ANCHOR: &[u8] = b"tracelane-anchor-ecdsa-v1\0";
const DOMAIN_ATTEST: &[u8] = b"tracelane-audit-ed25519-v1\0";
/// The public Rekor v2 log this verifier trusts — HARDCODED (ADR-062 H5), never
/// read from the bundle. Source: Sigstore TUF trusted_root tlogs[log2025-1].
const LOG_HOST: &str = "log2025-1.rekor.sigstore.dev";

/// log2025-1 Ed25519 checkpoint key, raw 32 bytes
/// (base64 "t8rlp1knGwjfbcXAYPYAkn0XiLz1x8O4t0YkEhie244=").
fn log_ed25519_pubkey() -> [u8; 32] {
    // Decodes a compile-time constant; the expect is on a fixed literal, never
    // runtime input, so it can only fire on a source-edit typo (a test covers it).
    let bytes = base64_decode("t8rlp1knGwjfbcXAYPYAkn0XiLz1x8O4t0YkEhie244=")
        .expect("pinned log key base64");
    let mut k = [0u8; 32];
    k.copy_from_slice(&bytes);
    k
}

/// One exported anchor record (ADR-062) — the per-batch offline bundle.
#[derive(Debug, Clone, Deserialize)]
struct AnchorRecord {
    tenant_id: String,
    batch_start_seq: u64,
    batch_end_seq: u64,
    merkle_root: String,
    anchor_state: String,
    ed25519: Ed25519Block,
    #[serde(default)]
    rekor: Option<RekorBlock>,
}

#[derive(Debug, Clone, Deserialize)]
struct Ed25519Block {
    signature: String,
    pubkey: String,
}

#[derive(Debug, Clone, Deserialize)]
struct RekorBlock {
    log_url: String,
    log_index: String,
    canonicalized_body: String,
    inclusion_proof: InclusionProof,
    checkpoint: Checkpoint,
}

#[derive(Debug, Clone, Deserialize)]
struct InclusionProof {
    log_index: String,
    tree_size: String,
    hashes: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct Checkpoint {
    envelope: String,
}

fn node_hash(l: &[u8; 32], r: &[u8; 32]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(1 + 64);
    buf.push(MERKLE_NODE_PREFIX);
    buf.extend_from_slice(l);
    buf.extend_from_slice(r);
    sha256(&buf)
}

/// P-256 SPKI (91 bytes) → raw uncompressed SEC1 point (65 bytes, 0x04‖X‖Y).
fn spki_to_point(spki: &[u8]) -> Result<Vec<u8>, String> {
    if spki.len() != 91 || spki[26] != 0x04 {
        return Err("not a P-256 SubjectPublicKeyInfo".to_string());
    }
    Ok(spki[26..].to_vec())
}

/// `anchor_commitment` (ADR-062): `None` → `[0x00]`; anchored →
/// `0x01 ‖ SHA256(ecdsa_spki) ‖ SHA256(log_url) ‖ u64_be(log_index)`.
fn anchor_commitment(anchored: Option<(&[u8], &str, u64)>) -> Vec<u8> {
    match anchored {
        None => vec![0x00],
        Some((spki, url, idx)) => {
            let mut v = Vec::with_capacity(1 + 32 + 32 + 8);
            v.push(0x01);
            v.extend_from_slice(&sha256(spki));
            v.extend_from_slice(&sha256(url.as_bytes()));
            v.extend_from_slice(&idx.to_be_bytes());
            v
        }
    }
}

/// RFC 6962 §2.1.1 inclusion-proof root recomputation. `leaf` is the RFC6962
/// leaf hash `SHA256(0x00 ‖ body)`.
fn rfc6962_root(
    leaf: [u8; 32],
    index: u64,
    size: u64,
    proof: &[[u8; 32]],
) -> Result<[u8; 32], String> {
    if index >= size {
        return Err("leaf index >= tree size".to_string());
    }
    let mut fnv = index;
    let mut sn = size - 1;
    let mut r = leaf;
    for p in proof {
        if sn == 0 {
            return Err("inclusion proof too long".to_string());
        }
        if (fnv & 1) == 1 || fnv == sn {
            r = node_hash(p, &r);
            while fnv != 0 && (fnv & 1) == 0 {
                fnv >>= 1;
                sn >>= 1;
            }
        } else {
            r = node_hash(&r, p);
        }
        fnv >>= 1;
        sn >>= 1;
    }
    if sn != 0 {
        return Err("inclusion proof too short".to_string());
    }
    Ok(r)
}

/// Verify an Ed25519 signature over arbitrary `msg` with a raw 32-byte pubkey.
fn verify_ed25519_raw(pubkey: &[u8; 32], msg: &[u8], signature: &[u8; 64]) -> Result<(), String> {
    let vk =
        VerifyingKey::from_bytes(pubkey).map_err(|e| format!("invalid Ed25519 pubkey: {e}"))?;
    let sig = Signature::from_bytes(signature);
    vk.verify(msg, &sig)
        .map_err(|e| format!("Ed25519 verification failed: {e}"))
}

/// Verify an ECDSA-P256 DER signature over a 32-byte prehash, given the SEC1
/// point. High-S accepted (Rekor does not enforce low-S on submission).
fn ecdsa_p256_verify(point: &[u8], prehash: &[u8; 32], sig_der: &[u8]) -> bool {
    use p256::ecdsa::signature::hazmat::PrehashVerifier;
    let Ok(vk) = p256::ecdsa::VerifyingKey::from_sec1_bytes(point) else {
        return false;
    };
    let Ok(sig) = p256::ecdsa::Signature::from_der(sig_der) else {
        return false;
    };
    vk.verify_prehash(prehash, &sig).is_ok()
}

/// Parse + verify a C2SP signed-note checkpoint against the PINNED log key
/// (ADR-062 H5). Returns `(tree_size, root)`. Errors on any mismatch.
fn verify_checkpoint(envelope: &str) -> Result<(u64, [u8; 32]), String> {
    let sep = envelope
        .find("\n\n")
        .ok_or("checkpoint has no signature separator")?;
    // Signed text = body up to (and incl the \n before) the blank line.
    let body_text = &envelope[..sep + 1];
    let sig_block = &envelope[sep + 2..];
    let mut lines = body_text.split('\n');
    let origin = lines.next().unwrap_or("");
    let tree_size: u64 = lines
        .next()
        .unwrap_or("")
        .parse()
        .map_err(|_| "checkpoint tree size not a u64".to_string())?;
    let root_b64 = lines.next().unwrap_or("");
    if origin != LOG_HOST {
        return Err(format!("checkpoint origin {origin} != pinned {LOG_HOST}"));
    }
    let sig_line = sig_block
        .lines()
        .find(|l| l.starts_with("\u{2014} "))
        .ok_or("checkpoint has no signature line")?;
    let token = sig_line
        .split(' ')
        .nth(2)
        .ok_or("checkpoint signature line malformed")?;
    let sig_blob = base64_decode(token).map_err(|e| format!("checkpoint sig base64: {e}"))?;
    if sig_blob.len() != 4 + 64 {
        return Err("checkpoint sig blob wrong length".to_string());
    }
    let logpk = log_ed25519_pubkey();
    // keyhint = SHA256(name ‖ 0x0A ‖ 0x01 ‖ pubkey)[:4].
    let mut hint_input = Vec::with_capacity(LOG_HOST.len() + 2 + 32);
    hint_input.extend_from_slice(LOG_HOST.as_bytes());
    hint_input.push(0x0A);
    hint_input.push(0x01);
    hint_input.extend_from_slice(&logpk);
    if sig_blob[..4] != sha256(&hint_input)[..4] {
        return Err("checkpoint key hint != pinned log key".to_string());
    }
    let mut sig64 = [0u8; 64];
    sig64.copy_from_slice(&sig_blob[4..]);
    verify_ed25519_raw(&logpk, body_text.as_bytes(), &sig64)
        .map_err(|e| format!("checkpoint signature: {e}"))?;
    let root_bytes = base64_decode(root_b64).map_err(|e| format!("checkpoint root base64: {e}"))?;
    if root_bytes.len() != 32 {
        return Err("checkpoint root not 32 bytes".to_string());
    }
    let mut root = [0u8; 32];
    root.copy_from_slice(&root_bytes);
    Ok((tree_size, root))
}

/// Minimal stdlib-free base64 decode. We only consume base64 from
/// trusted Rekor responses + a couple of test fixtures; using the
/// `base64` crate would balloon the dep tree for one function.
fn base64_decode(input: &str) -> Result<Vec<u8>, &'static str> {
    fn val(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let trimmed = input.trim().trim_end_matches('=');
    let bytes = trimmed.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    for &b in bytes {
        if b.is_ascii_whitespace() {
            continue;
        }
        let v = val(b).ok_or("invalid base64 char")?;
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------
// Main verifier entry point
// ---------------------------------------------------------------------

/// Verify an NDJSON audit ledger file end-to-end and return a structured report.
///
/// Thin wrapper over [`verify_ledger_reader`]: opens `path`, wraps it in a
/// `BufReader`, and delegates. There is exactly ONE verification implementation
/// (the reader-based one) — a file path and an in-memory buffer verify through
/// the identical code, so a server-side verdict and an offline `tlane verify`
/// verdict over the same bytes are equal by construction.
pub fn verify_ledger(path: &Path, opts: &VerifyOptions) -> std::io::Result<VerifyReport> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    verify_ledger_reader(reader, &path.to_string_lossy(), opts)
}

/// Verify an NDJSON audit ledger from any [`BufRead`] source and return a
/// structured report.
///
/// This is the single, canonical verification entry point — [`verify_ledger`]
/// (file path) delegates here, and an in-process caller (e.g. the gateway's
/// free-tier self-verify endpoint) passes an in-memory `Cursor` over the exact
/// NDJSON the export would produce. Reusing one implementation is what makes the
/// server-computed verdict byte-for-byte identical to what the customer computes
/// offline with the OSS verifier over the same payload.
///
/// `ledger_label` is a display-only string stamped into
/// [`VerifyReport::ledger_path`] (e.g. `"self-verify"` for the in-memory path).
/// It never affects any check.
///
/// # Errors
/// Propagates the underlying reader's I/O error (fail-closed: a truncated read is
/// never silently a passing verdict). In-memory `Cursor` sources do not error.
pub fn verify_ledger_reader<R: BufRead>(
    reader: R,
    ledger_label: &str,
    opts: &VerifyOptions,
) -> std::io::Result<VerifyReport> {
    let mut report = VerifyReport::empty_labeled(ledger_label);

    // Split records: row records (no `type`) vs anchor records (`type:"anchor"`).
    let mut rows: Vec<AuditRow> = Vec::new();
    let mut anchors: Vec<AnchorRecord> = Vec::new();
    for (line_idx, line_result) in reader.lines().enumerate() {
        let line = line_result?;
        if line.trim().is_empty() {
            continue;
        }
        let value: serde_json::Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(e) => {
                report.errors.push(VerifyError {
                    seq: None,
                    kind: "parse_error".into(),
                    detail: format!("line {}: {}", line_idx + 1, e),
                });
                report.hash_chain_valid = false;
                continue;
            }
        };
        if value.get("type").and_then(|t| t.as_str()) == Some("anchor") {
            match serde_json::from_value::<AnchorRecord>(value) {
                Ok(a) => anchors.push(a),
                Err(e) => report.errors.push(VerifyError {
                    seq: None,
                    kind: "anchor_parse_error".into(),
                    detail: format!("line {}: {}", line_idx + 1, e),
                }),
            }
        } else {
            match serde_json::from_value::<AuditRow>(value) {
                Ok(r) => rows.push(r),
                Err(e) => {
                    report.errors.push(VerifyError {
                        seq: None,
                        kind: "parse_error".into(),
                        detail: format!("line {}: {}", line_idx + 1, e),
                    });
                    report.hash_chain_valid = false;
                }
            }
        }
    }
    report.rows_seen = rows.len() as u64;

    // Pass 1: hash-chain replay + sequence check.
    verify_chain(&mut report, &rows, opts);

    // Pass 2: ADR-062 OFFLINE anchor verification (Rekor v2 has no online
    // lookup — the inclusion proof + checkpoint are bundled). The trusted tenant
    // pubkey is the single external trust root; absent → chain-only (anchors
    // reported UNVERIFIED, never green). `opts.offline` no longer gates anything.
    verify_anchors_offline(&mut report, &rows, &anchors, opts);

    Ok(report)
}

fn verify_chain(report: &mut VerifyReport, rows: &[AuditRow], opts: &VerifyOptions) {
    // Per-tenant chain state, keyed by tenant_id string. The export
    // may interleave tenants (e.g. a regulator's multi-tenant pack)
    // so we track each one separately.
    let mut tenant_state: BTreeMap<String, (u64, [u8; 32])> = BTreeMap::new();

    for row in rows {
        // Per-row format (the `format` marker wins; else the caller default).
        let fmt = resolve_format(row, opts.format_version);
        let v2_family = fmt.is_v2_family();

        let tenant_uuid = match uuid_str_to_bytes(&row.tenant_id) {
            Ok(b) => b,
            Err(e) => {
                report.errors.push(VerifyError {
                    seq: Some(row.seq),
                    kind: "bad_tenant_id".into(),
                    detail: e,
                });
                report.hash_chain_valid = false;
                continue;
            }
        };

        let entry = tenant_state
            .entry(row.tenant_id.clone())
            .or_insert_with(|| {
                // First time we see this tenant — initialize with
                // genesis seed (v2 / v2.1) or empty string (v1).
                let genesis = if v2_family {
                    genesis_v2(&tenant_uuid)
                } else {
                    [0u8; 32] // sentinel — v1 uses string ""
                };
                (0u64, genesis)
            });

        let (expected_seq, expected_prev_hash) = (entry.0, entry.1);

        if row.seq != expected_seq {
            report.errors.push(VerifyError {
                seq: Some(row.seq),
                kind: "seq_out_of_order".into(),
                detail: format!(
                    "tenant {}: expected seq {}, got {}",
                    row.tenant_id, expected_seq, row.seq
                ),
            });
            report.hash_chain_valid = false;
        }

        // Compare prev_hash. v2/v2.1 compare 32 raw bytes; v1 compares
        // the hex string (with `""` for the genesis row).
        let prev_hash_ok = if v2_family {
            if row.seq == 0 && row.prev_hash.is_empty() {
                // Some exporters omit the genesis row's prev_hash field.
                true
            } else {
                match hex_decode_32(&row.prev_hash) {
                    Ok(bytes) => bytes == expected_prev_hash,
                    Err(_) => false,
                }
            }
        } else {
            let expected = if row.seq == 0 {
                String::new()
            } else {
                hex::encode(expected_prev_hash)
            };
            row.prev_hash == expected
        };

        if !prev_hash_ok {
            report.errors.push(VerifyError {
                seq: Some(row.seq),
                kind: "prev_hash_mismatch".into(),
                detail: format!(
                    "tenant {}: prev_hash does not chain to previous row",
                    row.tenant_id
                ),
            });
            report.hash_chain_valid = false;
        }

        // Obtain the canonical payload STRING (the row_hash preimage).
        //   v2.1 — the payload IS the verbatim canonical string; hash it
        //   v2   — re-canonicalize the object (legacy; lossy for
        //   v1   — legacy pipe format.
        let canon: Option<String> = match fmt {
            FormatVersion::V2_1 => match row.payload.as_str() {
                Some(s) => Some(s.to_string()),
                None => {
                    report.errors.push(VerifyError {
                        seq: Some(row.seq),
                        kind: "v2_1_payload_not_string".into(),
                        detail: format!(
                            "tenant {}: v2.1 payload must be the verbatim canonical \
                             JSON string, not a re-parsed object/number",
                            row.tenant_id
                        ),
                    });
                    report.hash_chain_valid = false;
                    None
                }
            },
            FormatVersion::V2 => Some(canonical_payload_v2(&row.payload)),
            FormatVersion::V1 => Some(canonical_payload_v1(&row.payload)),
        };

        let stored = match hex_decode_32(&row.row_hash) {
            Ok(b) => b,
            Err(_) => {
                report.errors.push(VerifyError {
                    seq: Some(row.seq),
                    kind: "bad_row_hash_encoding".into(),
                    detail: format!("row_hash is not 64-hex: {}", row.row_hash),
                });
                report.hash_chain_valid = false;
                continue;
            }
        };

        if let Some(canon) = canon {
            let recomputed = if v2_family {
                row_hash_v2(
                    &expected_prev_hash,
                    &tenant_uuid,
                    row.seq,
                    &row.event_type,
                    &row.actor,
                    &canon,
                )
            } else {
                let h = row_hash_v1(
                    &row.prev_hash,
                    &row.tenant_id,
                    row.seq,
                    &row.event_type,
                    &row.actor,
                    &canon,
                );
                hex_decode_32(&h).unwrap_or([0u8; 32])
            };

            if recomputed != stored {
                report.errors.push(VerifyError {
                    seq: Some(row.seq),
                    kind: "row_hash_mismatch".into(),
                    detail: format!(
                        "tenant {}: expected row_hash {}, got {}",
                        row.tenant_id,
                        hex::encode(recomputed),
                        row.row_hash
                    ),
                });
                report.hash_chain_valid = false;
            }
        }

        // Advance tenant state with the row's CLAIMED stored hash even when an
        // error fired above (v2_1_payload_not_string / row_hash_mismatch). This
        // is deliberate continue-on-error so every downstream break is reported,
        // not just the first. It cannot hide a break: `hash_chain_valid` is
        // already `false`, and consumers gate on that boolean (never on
        // `errors.is_empty()`). Do NOT change consumers to trust the error list
        // alone. (ADR-050 security review, MED note.)
        let entry = tenant_state.get_mut(&row.tenant_id).unwrap();
        entry.0 = row.seq + 1;
        entry.1 = stored;
    }
}

/// Parse the anchored Rekor entry body → (ecdsa_spki, artifact_digest, sig_der,
/// sec1_point, log_index), binding it to `root` (Layer 1: digest ==
/// SHA256(DOMAIN_ANCHOR ‖ root); keyDetails == ECDSA-P256).
/// Parsed anchored Rekor entry — the ADR-062 Layer-1 material.
struct AnchorEntry {
    spki: Vec<u8>,
    digest: [u8; 32],
    sig: Vec<u8>,
    point: Vec<u8>,
    log_index: u64,
}

fn extract_anchor_entry(root: &[u8; 32], rekor: &RekorBlock) -> Result<AnchorEntry, String> {
    let body_bytes = base64_decode(&rekor.canonicalized_body)
        .map_err(|e| format!("canonicalized_body base64: {e}"))?;
    let body: serde_json::Value =
        serde_json::from_slice(&body_bytes).map_err(|e| format!("canonicalized_body JSON: {e}"))?;
    let spec = body
        .pointer("/spec/hashedRekordV002")
        .ok_or("missing spec.hashedRekordV002")?;
    let key_details = spec
        .pointer("/signature/verifier/keyDetails")
        .and_then(|v| v.as_str())
        .ok_or("missing keyDetails")?;
    if key_details != "PKIX_ECDSA_P256_SHA_256" {
        return Err(format!("unexpected keyDetails {key_details}"));
    }
    let digest_b64 = spec
        .pointer("/data/digest")
        .and_then(|v| v.as_str())
        .ok_or("missing data.digest")?;
    let sig_b64 = spec
        .pointer("/signature/content")
        .and_then(|v| v.as_str())
        .ok_or("missing signature.content")?;
    let raw_bytes_b64 = spec
        .pointer("/signature/verifier/publicKey/rawBytes")
        .and_then(|v| v.as_str())
        .ok_or("missing publicKey.rawBytes")?;

    let spki = base64_decode(raw_bytes_b64).map_err(|e| format!("spki base64: {e}"))?;
    let point = spki_to_point(&spki)?;

    let mut artifact = Vec::with_capacity(DOMAIN_ANCHOR.len() + 32);
    artifact.extend_from_slice(DOMAIN_ANCHOR);
    artifact.extend_from_slice(root);
    let digest = sha256(&artifact);
    let claimed_digest = base64_decode(digest_b64).map_err(|e| format!("digest base64: {e}"))?;
    if claimed_digest[..] != digest[..] {
        return Err("entry digest != SHA256(anchor artifact)".to_string());
    }
    let sig = base64_decode(sig_b64).map_err(|e| format!("sig base64: {e}"))?;
    let log_index: u64 = rekor
        .log_index
        .parse()
        .map_err(|_| "log_index not a u64".to_string())?;
    Ok(AnchorEntry {
        spki,
        digest,
        sig,
        point,
        log_index,
    })
}

/// Layer 2 (RFC6962 inclusion proof) + Layer 3' (C2SP checkpoint, pinned key).
fn verify_inclusion(rekor: &RekorBlock) -> Result<(), String> {
    let body = base64_decode(&rekor.canonicalized_body).map_err(|e| format!("body base64: {e}"))?;
    let mut leaf_input = Vec::with_capacity(1 + body.len());
    leaf_input.push(MERKLE_LEAF_PREFIX);
    leaf_input.extend_from_slice(&body);
    let leaf = sha256(&leaf_input);
    let idx: u64 = rekor
        .inclusion_proof
        .log_index
        .parse()
        .map_err(|_| "proof log_index not a u64".to_string())?;
    let tree_size: u64 = rekor
        .inclusion_proof
        .tree_size
        .parse()
        .map_err(|_| "proof tree_size not a u64".to_string())?;
    let mut proof: Vec<[u8; 32]> = Vec::with_capacity(rekor.inclusion_proof.hashes.len());
    for h in &rekor.inclusion_proof.hashes {
        let b = base64_decode(h).map_err(|e| format!("proof hash base64: {e}"))?;
        if b.len() != 32 {
            return Err("proof hash not 32 bytes".to_string());
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&b);
        proof.push(arr);
    }
    let computed = rfc6962_root(leaf, idx, tree_size, &proof)?;
    let (cp_size, cp_root) = verify_checkpoint(&rekor.checkpoint.envelope)?;
    if cp_size != tree_size {
        return Err(format!(
            "checkpoint tree_size {cp_size} != proof {tree_size}"
        ));
    }
    if cp_root != computed {
        return Err("inclusion-proof root != verified checkpoint root".to_string());
    }
    Ok(())
}

/// ADR-062 Amendment 1 — OFFLINE anchor verification. For each anchor record:
/// (0) recompute the batch Merkle root over rows [start..end]; (2) trusted-key
/// gate (bundle Ed25519 pubkey MUST == the trusted `tenant_pubkey`, else fail
/// closed; absent → chain-only); (3) bound Ed25519 attestation over
/// `DOMAIN_ATTEST ‖ root ‖ anchor_commitment`; when anchored also (1) ECDSA entry
/// sig binds the root, (2) RFC6962 inclusion proof, (3') C2SP checkpoint.
fn verify_anchors_offline(
    report: &mut VerifyReport,
    rows: &[AuditRow],
    anchors: &[AnchorRecord],
    opts: &VerifyOptions,
) {
    if anchors.is_empty() {
        return;
    }

    let mut row_hash_by_key: BTreeMap<String, [u8; 32]> = BTreeMap::new();
    for row in rows {
        if let Ok(h) = hex_decode_32(&row.row_hash) {
            row_hash_by_key.insert(format!("{}/{}", row.tenant_id, row.seq), h);
        }
    }

    for a in anchors {
        let committed = a.anchor_state == "anchored";
        let label = format!("batch {}-{}", a.batch_start_seq, a.batch_end_seq);

        // H3: committed-anchored but no bundle = a strip/downgrade.
        if committed && a.rekor.is_none() {
            report.strip_detected = true;
            report.errors.push(VerifyError {
                seq: None,
                kind: "anchor_stripped".into(),
                detail: format!("{label}: claims anchored but the rekor bundle is absent"),
            });
            report.signatures_valid = false;
            continue;
        }

        // Layer 0: recompute the batch Merkle root over the chain rows.
        let mut leaves: Vec<[u8; 32]> = Vec::new();
        let mut missing = false;
        for seq in a.batch_start_seq..=a.batch_end_seq {
            match row_hash_by_key.get(&format!("{}/{}", a.tenant_id, seq)) {
                Some(h) => leaves.push(*h),
                None => {
                    missing = true;
                    break;
                }
            }
        }
        if missing {
            report.errors.push(VerifyError {
                seq: None,
                kind: "anchor_rows_missing".into(),
                detail: format!("{label}: not all covered rows are present"),
            });
            report.signatures_valid = false;
            continue;
        }
        let root = merkle_root_v2(&leaves);
        let claimed_root = match hex_decode_32(&a.merkle_root) {
            Ok(r) => r,
            Err(_) => {
                report.errors.push(VerifyError {
                    seq: None,
                    kind: "bad_merkle_root".into(),
                    detail: format!("{label}: merkle_root is not hex"),
                });
                report.signatures_valid = false;
                continue;
            }
        };
        if root != claimed_root {
            report.errors.push(VerifyError {
                seq: None,
                kind: "merkle_root_mismatch".into(),
                detail: format!("{label}: recomputed root != anchor.merkle_root"),
            });
            report.signatures_valid = false;
            continue;
        }

        // Layer 2 (trusted-key gate, C2). No trusted key → chain-only.
        let Some(tenant_pubkey) = opts.tenant_pubkey else {
            continue;
        };
        let bundle_pubkey = match base64_decode(&a.ed25519.pubkey) {
            Ok(b) if b.len() == 32 => b,
            _ => {
                report.errors.push(VerifyError {
                    seq: None,
                    kind: "bad_tenant_pubkey".into(),
                    detail: format!("{label}: ed25519.pubkey is not a 32-byte base64 key"),
                });
                report.signatures_valid = false;
                continue;
            }
        };
        if bundle_pubkey[..] != tenant_pubkey[..] {
            report.errors.push(VerifyError {
                seq: None,
                kind: "untrusted_tenant_key".into(),
                detail: format!(
                    "{label}: anchor Ed25519 pubkey != trusted --tenant-pubkey (rejected — ADR-062 C2)"
                ),
            });
            report.signatures_valid = false;
            continue;
        }

        // Extract ECDSA material from the canonicalized body (anchored only).
        let mut anchored_meta: Option<(Vec<u8>, String, u64)> = None;
        let mut artifact_hash: Option<[u8; 32]> = None;
        let mut entry_sig: Option<Vec<u8>> = None;
        let mut entry_point: Option<Vec<u8>> = None;
        if committed {
            if let Some(rekor) = &a.rekor {
                match extract_anchor_entry(&root, rekor) {
                    Ok(entry) => {
                        anchored_meta = Some((entry.spki, rekor.log_url.clone(), entry.log_index));
                        artifact_hash = Some(entry.digest);
                        entry_sig = Some(entry.sig);
                        entry_point = Some(entry.point);
                    }
                    Err(e) => {
                        report.errors.push(VerifyError {
                            seq: None,
                            kind: "anchor_body_invalid".into(),
                            detail: format!("{label}: {e}"),
                        });
                        report.signatures_valid = false;
                        continue;
                    }
                }
            }
        }

        // Layer 3 (bound Ed25519 attestation) — the load-bearing check.
        let commitment = match &anchored_meta {
            Some((spki, url, idx)) => anchor_commitment(Some((spki, url, *idx))),
            None => anchor_commitment(None),
        };
        let mut msg = Vec::with_capacity(DOMAIN_ATTEST.len() + 32 + commitment.len());
        msg.extend_from_slice(DOMAIN_ATTEST);
        msg.extend_from_slice(&root);
        msg.extend_from_slice(&commitment);
        let att_sig = match base64_decode(&a.ed25519.signature) {
            Ok(s) if s.len() == 64 => {
                let mut arr = [0u8; 64];
                arr.copy_from_slice(&s);
                arr
            }
            _ => {
                report.errors.push(VerifyError {
                    seq: None,
                    kind: "bad_attestation_sig".into(),
                    detail: format!("{label}: ed25519.signature is not a 64-byte base64 sig"),
                });
                report.signatures_valid = false;
                continue;
            }
        };
        if verify_ed25519_raw(&tenant_pubkey, &msg, &att_sig).is_err() {
            report.errors.push(VerifyError {
                seq: None,
                kind: "attestation_invalid".into(),
                detail: format!(
                    "{label}: bound Ed25519 attestation failed (tamper/strip/downgrade)"
                ),
            });
            report.signatures_valid = false;
            continue;
        }

        // Honest signed-but-unanchored batch: attestation verified, nothing more.
        let (Some(rekor), Some(digest), Some(sig), Some(point)) =
            (&a.rekor, artifact_hash, entry_sig, entry_point)
        else {
            continue;
        };
        report.rekor_anchors_seen += 1;

        // Layer 1: ECDSA entry signature over the anchor-artifact hash.
        if !ecdsa_p256_verify(&point, &digest, &sig) {
            report.errors.push(VerifyError {
                seq: None,
                kind: "entry_signature_invalid".into(),
                detail: format!(
                    "{label}: Rekor entry ECDSA sig did not verify over the anchor artifact"
                ),
            });
            report.signatures_valid = false;
            continue;
        }
        report.rekor_anchors_resolved += 1;

        // Layer 2 (inclusion proof) + Layer 3' (checkpoint sig, pinned key).
        match verify_inclusion(rekor) {
            Ok(()) => report.anchors_included += 1,
            Err(e) => {
                report.errors.push(VerifyError {
                    seq: None,
                    kind: "inclusion_proof_invalid".into(),
                    detail: format!("{label}: {e}"),
                });
                report.signatures_valid = false;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    fn write_temp_ndjson(rows: &[AuditRow]) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        for r in rows {
            writeln!(f, "{}", serde_json::to_string(r).unwrap()).unwrap();
        }
        f
    }

    fn tenant_a() -> &'static str {
        "11111111-2222-3333-4444-555555555555"
    }

    fn make_v2_row(
        seq: u64,
        prev: &[u8; 32],
        event_type: &str,
        actor: &str,
        payload_str: &str,
    ) -> ([u8; 32], AuditRow) {
        let payload: serde_json::Value = serde_json::from_str(payload_str).unwrap();
        let tenant_uuid = uuid_str_to_bytes(tenant_a()).unwrap();
        let canon = canonical_payload_v2(&payload);
        let h = row_hash_v2(prev, &tenant_uuid, seq, event_type, actor, &canon);
        let row = AuditRow {
            format: None,
            tenant_id: tenant_a().into(),
            seq,
            event_time: "2026-01-01T00:00:00Z".into(),
            event_type: event_type.into(),
            actor: actor.into(),
            payload,
            prev_hash: hex::encode(prev),
            row_hash: hex::encode(h),
            rekor_entry_id: None,
        };
        (h, row)
    }

    #[test]
    fn v2_chain_valid_two_rows() {
        let tenant_uuid = uuid_str_to_bytes(tenant_a()).unwrap();
        let g = genesis_v2(&tenant_uuid);
        let (h0, r0) = make_v2_row(0, &g, "request", "u1", r#"{"q":1}"#);
        let (_h1, r1) = make_v2_row(1, &h0, "response", "u1", r#"{"r":"ok"}"#);

        let f = write_temp_ndjson(&[r0, r1]);
        let report = verify_ledger(f.path(), &VerifyOptions::offline()).unwrap();
        assert!(report.hash_chain_valid, "errors: {:?}", report.errors);
        assert_eq!(report.rows_seen, 2);
        assert!(report.errors.is_empty());
    }

    /// The reader-based entry (`verify_ledger_reader`, used by the gateway's
    /// in-process self-verify) and the file-based entry (`verify_ledger`, used by
    /// the offline CLI) MUST produce byte-identical reports over the same bytes —
    /// there is one verification implementation, so a server verdict equals an
    /// offline verdict by construction. `ledger_path` is normalized out (it is a
    /// display label only, never a check input).
    #[test]
    fn reader_and_file_entries_agree_byte_for_byte() {
        let tenant_uuid = uuid_str_to_bytes(tenant_a()).unwrap();
        let g = genesis_v2(&tenant_uuid);
        let (h0, r0) = make_v2_row(0, &g, "request", "u1", r#"{"q":1}"#);
        let (_h1, r1) = make_v2_row(1, &h0, "response", "u1", r#"{"r":"ok"}"#);
        let rows = [r0, r1];

        // File path.
        let f = write_temp_ndjson(&rows);
        let mut file_report = verify_ledger(f.path(), &VerifyOptions::offline()).unwrap();

        // In-memory reader over the identical bytes.
        let ndjson: String = rows
            .iter()
            .map(|r| format!("{}\n", serde_json::to_string(r).unwrap()))
            .collect();
        let mut reader_report = verify_ledger_reader(
            std::io::Cursor::new(ndjson.into_bytes()),
            "self-verify",
            &VerifyOptions::offline(),
        )
        .unwrap();

        // Normalize the display-only label, then require the serialized reports
        // to be byte-equal.
        file_report.ledger_path.clear();
        reader_report.ledger_path.clear();
        assert_eq!(
            serde_json::to_string(&file_report).unwrap(),
            serde_json::to_string(&reader_report).unwrap(),
            "reader and file verifier entries diverged",
        );
    }

    #[test]
    fn v2_chain_detects_tampered_payload() {
        let tenant_uuid = uuid_str_to_bytes(tenant_a()).unwrap();
        let g = genesis_v2(&tenant_uuid);
        let (_h0, mut r0) = make_v2_row(0, &g, "request", "u1", r#"{"q":1}"#);
        // Tamper the payload but keep the (now-incorrect) row_hash.
        r0.payload = serde_json::json!({"q": 9999});

        let f = write_temp_ndjson(&[r0]);
        let report = verify_ledger(f.path(), &VerifyOptions::offline()).unwrap();
        assert!(!report.hash_chain_valid);
        assert!(report.errors.iter().any(|e| e.kind == "row_hash_mismatch"));
    }

    #[test]
    fn v2_chain_detects_swapped_seq() {
        let tenant_uuid = uuid_str_to_bytes(tenant_a()).unwrap();
        let g = genesis_v2(&tenant_uuid);
        let (h0, r0) = make_v2_row(0, &g, "a", "u", r#"{}"#);
        // seq=2 instead of 1
        let (_h1, mut r1) = make_v2_row(1, &h0, "b", "u", r#"{}"#);
        r1.seq = 2;
        // recompute row_hash so the row_hash check itself doesn't fire
        let canon = canonical_payload_v2(&r1.payload);
        let h_new = row_hash_v2(&h0, &tenant_uuid, 2, &r1.event_type, &r1.actor, &canon);
        r1.row_hash = hex::encode(h_new);

        let f = write_temp_ndjson(&[r0, r1]);
        let report = verify_ledger(f.path(), &VerifyOptions::offline()).unwrap();
        assert!(report.errors.iter().any(|e| e.kind == "seq_out_of_order"));
    }

    #[test]
    fn v2_chain_detects_prev_hash_break() {
        let tenant_uuid = uuid_str_to_bytes(tenant_a()).unwrap();
        let g = genesis_v2(&tenant_uuid);
        let (h0, r0) = make_v2_row(0, &g, "a", "u", r#"{}"#);
        // Build row 1 with a wrong prev_hash; recompute row_hash so
        // only the prev_hash_mismatch fires, not row_hash_mismatch
        // alongside.
        let mut wrong_prev = h0;
        wrong_prev[0] ^= 0xff;
        let payload = serde_json::json!({});
        let canon = canonical_payload_v2(&payload);
        let h1_wrong = row_hash_v2(&wrong_prev, &tenant_uuid, 1, "b", "u", &canon);
        let r1 = AuditRow {
            format: None,
            tenant_id: tenant_a().into(),
            seq: 1,
            event_time: "2026".into(),
            event_type: "b".into(),
            actor: "u".into(),
            payload,
            prev_hash: hex::encode(wrong_prev),
            row_hash: hex::encode(h1_wrong),
            rekor_entry_id: None,
        };

        let f = write_temp_ndjson(&[r0, r1]);
        let report = verify_ledger(f.path(), &VerifyOptions::offline()).unwrap();
        assert!(report.errors.iter().any(|e| e.kind == "prev_hash_mismatch"));
    }

    #[test]
    fn v1_legacy_chain_still_verifies() {
        // Build a v1-style ledger using the legacy helpers.
        let tenant = tenant_a();
        let prev0 = "";
        let payload0 = r#"{"q":1}"#;
        let p0: serde_json::Value = serde_json::from_str(payload0).unwrap();
        let canon0 = canonical_payload_v1(&p0);
        let h0 = row_hash_v1(prev0, tenant, 0, "request", "u1", &canon0);
        let r0 = AuditRow {
            format: None,
            tenant_id: tenant.into(),
            seq: 0,
            event_time: "2026".into(),
            event_type: "request".into(),
            actor: "u1".into(),
            payload: p0,
            prev_hash: prev0.into(),
            row_hash: h0.clone(),
            rekor_entry_id: None,
        };

        let f = write_temp_ndjson(&[r0]);
        let opts = VerifyOptions::offline().with_format(FormatVersion::V1);
        let report = verify_ledger(f.path(), &opts).unwrap();
        assert!(report.hash_chain_valid, "errors: {:?}", report.errors);
    }

    #[test]
    fn v2_merkle_root_two_leaves_matches_spec() {
        // RFC 6962 §2.1: root(L0, L1) = SHA256(0x01 || leaf(L0) || leaf(L1))
        // Cross-check by computing both ways.
        let l0 = [0xAAu8; 32];
        let l1 = [0xBBu8; 32];
        let root = merkle_root_v2(&[l0, l1]);

        let mut leaf0_buf = vec![MERKLE_LEAF_PREFIX];
        leaf0_buf.extend_from_slice(&l0);
        let n0 = sha256(&leaf0_buf);
        let mut leaf1_buf = vec![MERKLE_LEAF_PREFIX];
        leaf1_buf.extend_from_slice(&l1);
        let n1 = sha256(&leaf1_buf);
        let mut node_buf = vec![MERKLE_NODE_PREFIX];
        node_buf.extend_from_slice(&n0);
        node_buf.extend_from_slice(&n1);
        let expected = sha256(&node_buf);
        assert_eq!(root, expected);
    }

    /// Build a deterministic ed25519 signing key from a 32-byte seed.
    /// Tests don't need a real CSPRNG — they need a known key so the
    /// assertion is reproducible. `SigningKey::from_bytes` is always
    /// available without enabling the `rand_core` feature.
    fn signing_key_from_seed(seed: [u8; 32]) -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&seed)
    }

    #[test]
    fn ed25519_sig_verification_succeeds_on_known_good() {
        use ed25519_dalek::Signer;
        let sk = signing_key_from_seed([7u8; 32]);
        let pubkey = sk.verifying_key().to_bytes();
        let root: [u8; 32] = [42; 32];
        let sig = sk.sign(&root).to_bytes();
        assert!(verify_ed25519_raw(&pubkey, &root, &sig).is_ok());
    }

    #[test]
    fn ed25519_sig_verification_rejects_tampered() {
        use ed25519_dalek::Signer;
        let sk = signing_key_from_seed([7u8; 32]);
        let pubkey = sk.verifying_key().to_bytes();
        let root: [u8; 32] = [42; 32];
        let mut sig = sk.sign(&root).to_bytes();
        sig[0] ^= 0xff; // tamper
        assert!(verify_ed25519_raw(&pubkey, &root, &sig).is_err());
    }

    #[test]
    fn ed25519_sig_verification_rejects_wrong_pubkey() {
        use ed25519_dalek::Signer;
        let sk = signing_key_from_seed([7u8; 32]);
        let other = signing_key_from_seed([8u8; 32]);
        let root: [u8; 32] = [42; 32];
        let sig = sk.sign(&root).to_bytes();
        // Use the OTHER key's pubkey, sig is from the original.
        assert!(verify_ed25519_raw(&other.verifying_key().to_bytes(), &root, &sig).is_err());
    }

    #[test]
    fn base64_decode_roundtrip() {
        // Known: "hello" → "aGVsbG8="
        let decoded = base64_decode("aGVsbG8=").unwrap();
        assert_eq!(decoded, b"hello");
        // Without padding
        let decoded = base64_decode("aGVsbG8").unwrap();
        assert_eq!(decoded, b"hello");
    }

    #[test]
    fn merkle_root_lone_odd_leaf_is_promoted_not_duplicated() {
        // RFC 6962 §2.1: an odd leaf at any level is promoted as-is to
        // the next level, NOT duplicated (that was the v1/Bitcoin bug).
        let l0 = [0x11u8; 32];
        let l1 = [0x22u8; 32];
        let l2 = [0x33u8; 32];
        let root_3 = merkle_root_v2(&[l0, l1, l2]);

        // Build the expected value by hand.
        let mut leaf0 = vec![MERKLE_LEAF_PREFIX];
        leaf0.extend_from_slice(&l0);
        let h0 = sha256(&leaf0);
        let mut leaf1 = vec![MERKLE_LEAF_PREFIX];
        leaf1.extend_from_slice(&l1);
        let h1 = sha256(&leaf1);
        let mut leaf2 = vec![MERKLE_LEAF_PREFIX];
        leaf2.extend_from_slice(&l2);
        let h2 = sha256(&leaf2);

        let mut pair = vec![MERKLE_NODE_PREFIX];
        pair.extend_from_slice(&h0);
        pair.extend_from_slice(&h1);
        let n01 = sha256(&pair);

        // Lone-odd: h2 is promoted unchanged.
        let mut top = vec![MERKLE_NODE_PREFIX];
        top.extend_from_slice(&n01);
        top.extend_from_slice(&h2);
        let expected = sha256(&top);

        assert_eq!(root_3, expected);
    }

    #[test]
    fn uuid_str_to_bytes_accepts_both_hyphenated_and_bare() {
        let with_h = uuid_str_to_bytes("11111111-2222-3333-4444-555555555555").unwrap();
        let bare = uuid_str_to_bytes("11111111222233334444555555555555").unwrap();
        assert_eq!(with_h, bare);
        assert_eq!(with_h[0], 0x11);
        assert_eq!(with_h[15], 0x55);
    }

    #[test]
    fn canonical_payload_sorts_keys_deterministically() {
        let a = serde_json::json!({"b": 1, "a": 2, "c": 3});
        let b = serde_json::json!({"c": 3, "a": 2, "b": 1});
        assert_eq!(canonical_payload_v2(&a), canonical_payload_v2(&b));
        assert_eq!(canonical_payload_v2(&a), r#"{"a":2,"b":1,"c":3}"#);
    }

    // ---- v2.1 (ADR-050 — authoritative-once verbatim string) -----------

    /// Build a v2.1 row: `payload` is the VERBATIM canonical string (as the
    /// writer stores it in the `payload` column), `row_hash` is computed over
    /// that exact string, and the `format` marker is `"v2.1"`.
    fn make_v2_1_row(
        seq: u64,
        prev: &[u8; 32],
        event_type: &str,
        actor: &str,
        canonical_payload: &str,
    ) -> ([u8; 32], AuditRow) {
        let tenant_uuid = uuid_str_to_bytes(tenant_a()).unwrap();
        let h = row_hash_v2(
            prev,
            &tenant_uuid,
            seq,
            event_type,
            actor,
            canonical_payload,
        );
        let row = AuditRow {
            format: Some("v2.1".into()),
            tenant_id: tenant_a().into(),
            seq,
            event_time: "2026-01-01T00:00:00Z".into(),
            event_type: event_type.into(),
            actor: actor.into(),
            payload: serde_json::Value::String(canonical_payload.to_string()),
            prev_hash: hex::encode(prev),
            row_hash: hex::encode(h),
            rekor_entry_id: None,
        };
        (h, row)
    }

    #[test]
    fn v2_1_verbatim_string_chain_verifies() {
        let tenant_uuid = uuid_str_to_bytes(tenant_a()).unwrap();
        let g = genesis_v2(&tenant_uuid);
        let (h0, r0) = make_v2_1_row(0, &g, "request", "u1", r#"{"max_tokens":8}"#);
        let (_h1, r1) = make_v2_1_row(1, &h0, "response", "u1", r#"{"ok":true}"#);
        let f = write_temp_ndjson(&[r0, r1]);
        let report = verify_ledger(f.path(), &VerifyOptions::offline()).unwrap();
        assert!(report.hash_chain_valid, "errors: {:?}", report.errors);
        assert_eq!(report.rows_seen, 2);
    }

    #[test]
    fn v2_1_verifies_js_unsafe_numbers_that_broke_b066() {
        // >2^53 (JS loses precision), an exponent (1e2), and a trailing zero
        // (0.50). Under v2.1 the verifier hashes the STORED canonical string
        // verbatim, so these verify green regardless of any language's number
        // re-formatting. The canonical string is what the gateway writer
        // stores (`audit_format::canonical_payload`); we mirror that exact
        // byte sequence here.
        let tenant_uuid = uuid_str_to_bytes(tenant_a()).unwrap();
        let g = genesis_v2(&tenant_uuid);
        // Keys pre-sorted (JCS): big_int, exp, temperature, top_p.
        let canonical = r#"{"big_int":9007199254740993,"exp":1e2,"temperature":1.0,"top_p":0.50}"#;
        let (_h, r0) = make_v2_1_row(0, &g, "chat.completions.request", "u1", canonical);
        let f = write_temp_ndjson(&[r0]);
        let report = verify_ledger(f.path(), &VerifyOptions::offline()).unwrap();
        assert!(
            report.hash_chain_valid,
            "v2.1 must verify JS-unsafe numbers verbatim; errors: {:?}",
            report.errors
        );
    }

    #[test]
    fn v2_1_tamper_of_the_string_is_detected() {
        let tenant_uuid = uuid_str_to_bytes(tenant_a()).unwrap();
        let g = genesis_v2(&tenant_uuid);
        let (_h, mut r0) = make_v2_1_row(0, &g, "request", "u1", r#"{"max_tokens":8}"#);
        // Mutate the canonical string but keep the (now-stale) row_hash.
        r0.payload = serde_json::Value::String(r#"{"max_tokens":9}"#.into());
        let f = write_temp_ndjson(&[r0]);
        let report = verify_ledger(f.path(), &VerifyOptions::offline()).unwrap();
        assert!(!report.hash_chain_valid);
        assert!(report.errors.iter().any(|e| e.kind == "row_hash_mismatch"));
    }

    /// Generator for the shared conformance vectors (run manually):
    /// `cargo test -p tracelane-audit-verifier gen_boundary_vectors -- --ignored --nocapture`.
    /// Emits, using the SAME canonical + row-hash the gateway writer uses
    /// (`canonical_payload_v2` / `row_hash_v2` are byte-identical to
    /// `audit_format`), two ledgers over the JS-unsafe number class that
    ///   • `===V2_1===`     — v2.1 (payload = verbatim canonical string).
    ///   • `===V2LEGACY===` — v2 (payload = object, no marker; same row_hash).
    #[test]
    #[ignore = "vector generator — run with --ignored --nocapture, output committed under evals/audit-ledger"]
    fn gen_boundary_vectors() {
        let tenant = "00000000-0000-0000-0000-000000000009";
        let uuid = uuid_str_to_bytes(tenant).unwrap();
        let g = genesis_v2(&uuid);

        // serde produces the REAL canonical bytes the writer would store.
        let p0 = serde_json::json!({
            "temperature": 1.0,
            "top_p": 0.50,
            "big_int": 9_007_199_254_740_993_u64, // > 2^53
            "exp": 1e2,
        });
        let p1 = serde_json::json!({ "status": "ok", "tokens": 7 });

        let canon0 = canonical_payload_v2(&p0);
        let canon1 = canonical_payload_v2(&p1);
        let h0 = row_hash_v2(&g, &uuid, 0, "chat.completions.request", "user1", &canon0);
        let h1 = row_hash_v2(
            &h0,
            &uuid,
            1,
            "chat.completions.response",
            "assistant",
            &canon1,
        );

        eprintln!("canon0 = {canon0}");

        let mk = |seq,
                  fmt: Option<&str>,
                  payload: serde_json::Value,
                  prev: &[u8; 32],
                  h: &[u8; 32],
                  et: &str,
                  actor: &str| AuditRow {
            format: fmt.map(str::to_string),
            tenant_id: tenant.into(),
            seq,
            event_time: format!("2026-05-14T00:00:0{seq}.000000Z"),
            event_type: et.into(),
            actor: actor.into(),
            payload,
            prev_hash: hex::encode(prev),
            row_hash: hex::encode(h),
            rekor_entry_id: None,
        };

        // v2.1: payload is the verbatim canonical STRING.
        let v21_0 = mk(
            0,
            Some("v2.1"),
            serde_json::Value::String(canon0.clone()),
            &g,
            &h0,
            "chat.completions.request",
            "user1",
        );
        let v21_1 = mk(
            1,
            Some("v2.1"),
            serde_json::Value::String(canon1.clone()),
            &h0,
            &h1,
            "chat.completions.response",
            "assistant",
        );
        println!("===V2_1===");
        println!("{}", serde_json::to_string(&v21_0).unwrap());
        println!("{}", serde_json::to_string(&v21_1).unwrap());

        // legacy v2: payload is the OBJECT, no marker, SAME row_hash.
        let leg0 = mk(
            0,
            None,
            p0.clone(),
            &g,
            &h0,
            "chat.completions.request",
            "user1",
        );
        let leg1 = mk(
            1,
            None,
            p1.clone(),
            &h0,
            &h1,
            "chat.completions.response",
            "assistant",
        );
        println!("===V2LEGACY===");
        println!("{}", serde_json::to_string(&leg0).unwrap());
        println!("{}", serde_json::to_string(&leg1).unwrap());
        println!("===END===");
    }

    #[test]
    fn v2_1_marker_with_object_payload_is_rejected() {
        // A v2.1-marked row whose payload is a nested object (not the verbatim
        // string) is malformed — the verifier must refuse it explicitly rather
        let tenant_uuid = uuid_str_to_bytes(tenant_a()).unwrap();
        let g = genesis_v2(&tenant_uuid);
        let (_h, mut r0) = make_v2_1_row(0, &g, "request", "u1", r#"{"max_tokens":8}"#);
        r0.payload = serde_json::json!({"max_tokens": 8}); // object, not string
        let f = write_temp_ndjson(&[r0]);
        let report = verify_ledger(f.path(), &VerifyOptions::offline()).unwrap();
        assert!(!report.hash_chain_valid);
        assert!(
            report
                .errors
                .iter()
                .any(|e| e.kind == "v2_1_payload_not_string")
        );
    }
}
