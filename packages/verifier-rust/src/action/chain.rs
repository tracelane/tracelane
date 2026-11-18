//! Checkpoint chain (`checkpoints.ndjson`): every signed head statement for the tenant, in
//! order, ending at the covering head. Signed heartbeats make silence between two checkpoints
//! evidence that the recorder was alive; an interval longer than the expected cadence is a GAP.
//! Every number here is computed from signed statements, never estimated. Errors fail CLOSED.
use super::{archive::Files, canonical_json};
use anyhow::{Context, Result, ensure};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// One line of `checkpoints.ndjson`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Line {
    statement: String,
    /// Hex Ed25519 signature over the statement bytes.
    signature: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Statement {
    domain: String,
    schema_version: u32,
    tenant_id: Uuid,
    seq: Option<String>,
    head_hash: Option<String>,
    created_at: DateTime<Utc>,
    key_id: String,
    previous_checkpoint_digest: Option<String>,
}
/// An interval between two consecutive signed checkpoints longer than the requested maximum.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Gap {
    pub from: DateTime<Utc>,
    pub to: DateTime<Utc>,
}
#[derive(Debug, Default, Serialize)]
pub struct ChainReport {
    /// Signed checkpoints verified, including the covering head.
    pub checkpoints: u64,
    /// Signed `created_at` of the first checkpoint in the bundle. Gaps are computed from here on.
    pub chain_start: Option<DateTime<Utc>>,
    /// True when the first checkpoint is the workspace's first (links no predecessor). False
    /// when the export carries only the most recent window of the chain.
    pub from_genesis: bool,
    /// Longest interval between consecutive checkpoints, in whole seconds.
    pub max_interval_secs: Option<i64>,
    /// Intervals longer than `--max-gap`; empty when no maximum was given.
    pub gaps: Vec<Gap>,
    /// Chain checkpoints whose RFC 3161 token verified against a pinned TSA certificate.
    pub timestamped: u64,
}
fn seq(s: &Statement) -> Result<Option<u64>> {
    s.seq
        .as_deref()
        .map(str::parse)
        .transpose()
        .context("invalid checkpoint sequence")
}
#[derive(Debug)]
struct Untrusted;
impl std::fmt::Display for Untrusted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("chain checkpoint does not verify under external pin")
    }
}
impl std::error::Error for Untrusted {}
/// Verifies the chain against the pinned key and the covering head bytes. `Ok(None)` when the
/// bundle predates the chain member. Errors fail CLOSED (code 4 format/link, 5 trust).
pub(super) fn verify(
    files: &Files,
    tenant: Uuid,
    pin: [u8; 32],
    head: &[u8],
    certs: &[Vec<u8>],
    max_gap: Option<chrono::Duration>,
) -> std::result::Result<Option<ChainReport>, (u8, anyhow::Error)> {
    let Some(raw) = files.get("checkpoints.ndjson") else {
        // Stripping the (unsigned-manifest) member must not turn a requested gap check into a pass.
        if max_gap.is_some() {
            return Err((
                4,
                anyhow::anyhow!(
                    "--max-gap requires checkpoints.ndjson; the bundle has no checkpoint chain"
                ),
            ));
        }
        return Ok(None);
    };
    check(files, raw, tenant, pin, head, certs, max_gap)
        .map(Some)
        .map_err(|e| (if e.is::<Untrusted>() { 5 } else { 4 }, e))
}
fn check(
    files: &Files,
    raw: &[u8],
    tenant: Uuid,
    pin: [u8; 32],
    head: &[u8],
    certs: &[Vec<u8>],
    max_gap: Option<chrono::Duration>,
) -> Result<ChainReport> {
    let key_id = hex::encode(crate::sha256(&pin));
    let key = ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, pin);
    let mut report = ChainReport::default();
    let mut prev: Option<(Statement, String)> = None;
    let mut last: Option<String> = None;
    let mut digests = std::collections::BTreeMap::new();
    for line in std::str::from_utf8(raw)?.lines() {
        let l: Line = serde_json::from_str(line)?;
        let text = l.statement;
        ensure!(
            canonical_json(&text)? == text,
            "checkpoint statement not JCS"
        );
        let s: Statement = serde_json::from_str(&text)?;
        ensure!(
            s.domain == "tracelane.action-head.v1"
                && s.schema_version == 1
                && s.tenant_id == tenant,
            "checkpoint domain/version/tenant"
        );
        let signature = hex::decode(&l.signature)?;
        if s.key_id != key_id || key.verify(text.as_bytes(), &signature).is_err() {
            return Err(Untrusted.into());
        }
        let digest = hex::encode(crate::sha256(text.as_bytes()));
        match &prev {
            // A windowed export starts mid-chain: the first line may link a predecessor that is
            // not in the bundle. The report says so (`from_genesis`) and where it starts.
            None => {
                report.from_genesis = s.previous_checkpoint_digest.is_none();
                report.chain_start = Some(s.created_at);
            }
            Some((p, pd)) => {
                ensure!(
                    s.previous_checkpoint_digest.as_deref() == Some(pd.as_str()),
                    "checkpoint chain link broken"
                );
                ensure!(s.created_at >= p.created_at, "checkpoint time regressed");
                let (a, b) = (seq(p)?, seq(&s)?);
                ensure!(b >= a, "checkpoint sequence regressed");
                ensure!(
                    b != a || s.head_hash == p.head_hash,
                    "checkpoint head conflict at equal sequence"
                );
                let interval = s.created_at - p.created_at;
                let secs = interval.num_seconds();
                report.max_interval_secs =
                    Some(report.max_interval_secs.map_or(secs, |m| m.max(secs)));
                if max_gap.is_some_and(|g| interval > g) {
                    report.gaps.push(Gap {
                        from: p.created_at,
                        to: s.created_at,
                    });
                }
            }
        }
        digests.insert(digest.clone(), text.clone());
        last = Some(text);
        prev = Some((s, digest));
        report.checkpoints += 1;
    }
    ensure!(
        last.as_deref().map(str::as_bytes) == Some(head),
        "checkpoint chain does not end at the covering head"
    );
    for (name, token) in files {
        let Some(digest) = name
            .strip_prefix("timestamps/")
            .and_then(|n| n.strip_suffix(".tsr"))
        else {
            continue;
        };
        let statement = digests
            .get(digest)
            .context("timestamp names no chain checkpoint")?;
        if super::timestamp::verify_optional(Some(token), statement.as_bytes(), certs)?.is_some() {
            report.timestamped += 1;
        }
    }
    Ok(report)
}
