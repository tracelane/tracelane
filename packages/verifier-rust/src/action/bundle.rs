//! Action ZIP verification is fully offline. Bundle keys never establish trust.
use super::{Envelope, Semantics, archive::*, canonical_json, semantics};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use uuid::Uuid;
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    domain: String,
    files: BTreeMap<String, String>,
}
#[derive(Debug, Serialize)]
pub struct Report {
    pub tenant_id: Uuid,
    /// Inclusive signed sequence boundary, null for an explicitly empty head.
    pub head_seq: Option<String>,
    pub head_hash: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub rows: u64,
    pub chain: bool,
    pub head: bool,
    pub actions: Semantics,
    /// Default-path tool/model approvals replayed from the ledger.
    pub approvals: crate::approval::Semantics,
    pub batch_signatures: u64,
    pub rekor_included: u64,
    pub timestamped: bool,
    pub timestamp_reason: Option<&'static str>,
    pub gen_time: Option<chrono::DateTime<chrono::Utc>>,
    /// Leaves in the signed RFC 6962 tree checkpoint; null when the bundle carries none.
    pub tree_size: Option<u64>,
    /// Hex tree root, recomputed from the ledger rows and equal to the signed one.
    pub tree_root: Option<String>,
    /// A `checkpoint.cose` COSE_Sign1 over the checkpoint was present and verified under the pin.
    pub cose_statement: bool,
    /// The signed checkpoint chain; `None` for a bundle that predates `checkpoints.ndjson`.
    pub checkpoint_chain: Option<super::chain::ChainReport>,
}
impl std::fmt::Display for Report {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "PASS — chain, covering head and action semantics verified; tenant: {}; rows: {}; ",
            self.tenant_id, self.rows
        )?;
        if let (Some(seq), Some(hash)) = (&self.head_seq, &self.head_hash) {
            write!(
                f,
                "signed range: 0..={seq}; head seq: {seq}; head hash: {hash}; "
            )?;
        } else {
            write!(f, "EMPTY signed head; head seq: null; head hash: null; ")?;
        }
        write!(
            f,
            "checkpoint created_at: {}; UNKNOWN outcomes: {}",
            self.created_at.to_rfc3339(),
            self.actions.unknown.len()
        )?;
        for id in &self.actions.unknown {
            write!(f, " {id}")?;
        }
        write!(
            f,
            "; denied approvals: {}; batch signatures: {}; Rekor included: {}",
            self.actions.denied.len(),
            self.batch_signatures,
            self.rekor_included
        )?;
        // Consistent with the recorded policy and evidence; not a judgement that the policy is right.
        write!(
            f,
            "; policy replay: {} replayed, {} not replayable (opaque field)",
            self.actions.replayed,
            self.actions.not_replayable.len()
        )?;
        for id in &self.actions.not_replayable {
            write!(f, " {id}")?;
        }
        write!(
            f,
            "; gateway-attested principals: {}",
            self.actions.principals.len()
        )?;
        for (id, principal) in &self.actions.principals {
            write!(
                f,
                "; action={id} issuer={:?} sub_digest={} roles={:?}",
                principal.iss, principal.sub_digest, principal.roles
            )?;
        }
        if !self.actions.principals.is_empty() {
            write!(
                f,
                "; principal evidence is a gateway assertion; IdP token omitted"
            )?;
        }
        // A countersignature shows the registered key signed this attestation; not who holds it.
        write!(
            f,
            "; tool receipts: {} countersigned, {} uncountersigned",
            self.actions.countersigned, self.actions.uncountersigned
        )?;
        // Only when present, so a ledger without approvals prints exactly as before.
        let a = &self.approvals;
        if a.requested > 0 {
            write!(
                f,
                "; approvals: {} requested, {} approved, {} denied, {} consumed, {} expired, {} open, {} self-decided",
                a.requested, a.approved, a.denied, a.consumed, a.expired, a.open, a.self_decided
            )?;
        }
        write!(f, "; timestamped: {}", self.timestamped)?;
        if let Some(reason) = self.timestamp_reason {
            write!(f, "; timestamp_reason: {reason}")?;
        }
        if let Some(time) = self.gen_time {
            write!(f, "; TSA gen_time: {}", time.to_rfc3339())?;
        }
        match (self.tree_size, &self.tree_root) {
            (Some(size), Some(root)) => write!(f, "; tree checkpoint: size {size} root {root}")?,
            _ => write!(f, "; tree checkpoint: absent")?,
        }
        write!(f, "; COSE statement: {}", self.cose_statement)?;
        match &self.checkpoint_chain {
            None => write!(f, "; checkpoint chain: absent")?,
            Some(c) => {
                write!(
                    f,
                    "; checkpoint chain: {} signed checkpoints, {} timestamped",
                    c.checkpoints, c.timestamped
                )?;
                if let Some(start) = c.chain_start {
                    write!(
                        f,
                        "; chain {} {}",
                        if c.from_genesis {
                            "from genesis at"
                        } else {
                            "window starts at"
                        },
                        start.to_rfc3339()
                    )?;
                }
                if let Some(max) = c.max_interval_secs {
                    write!(f, "; longest interval: {max}s")?;
                }
                write!(f, "; gaps: {}", c.gaps.len())?;
                for g in &c.gaps {
                    write!(f, " [{} .. {}]", g.from.to_rfc3339(), g.to.to_rfc3339())?;
                }
            }
        }
        Ok(())
    }
}
#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum FailureKind {
    Other,
    ReferenceOutsideRange,
}
#[derive(Debug)]
#[non_exhaustive]
pub struct Failure {
    pub kind: FailureKind,
    pub code: u8,
    pub detail: String,
}
impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.detail)
    }
}
impl std::error::Error for Failure {}
fn failure(code: u8, e: impl std::fmt::Display) -> Failure {
    Failure {
        kind: FailureKind::Other,
        code,
        detail: e.to_string(),
    }
}
fn semantic_failure(e: anyhow::Error) -> Failure {
    let kind = if e.is::<super::ReferenceOutsideRange>() {
        FailureKind::ReferenceOutsideRange
    } else {
        FailureKind::Other
    };
    Failure {
        kind,
        code: 6,
        detail: e.to_string(),
    }
}
fn get<'a>(files: &'a Files, name: &str) -> Result<&'a [u8]> {
    Ok(files.get(name).context(format!("missing {name}"))?)
}
/// Exact JCS manifest, SHA256 for every member. Errors fail CLOSED.
pub fn seal(mut files: Files) -> Result<Vec<u8>> {
    ensure!(!files.contains_key("manifest.json"), "duplicate manifest");
    let manifest = Manifest {
        domain: "tracelane.action-bundle.v1".into(),
        files: files
            .iter()
            .map(|(n, b)| (n.clone(), hex::encode(crate::sha256(b))))
            .collect(),
    };
    files.insert(
        "manifest.json".into(),
        canonical_json(&serde_json::to_string(&manifest)?)?.into_bytes(),
    );
    pack(&files)
}
/// Errors fail CLOSED: 4 format/timestamp proof, 5 missing/wrong tenant key trust, 6 semantics.
pub fn verify(raw: &[u8], pinned: Option<[u8; 32]>) -> std::result::Result<Report, Failure> {
    verify_with_tsa(raw, pinned, &[])
}
/// Verify timestamps against external TSA leaf-certificate pins. Errors fail CLOSED.
pub fn verify_with_tsa(
    raw: &[u8],
    pinned: Option<[u8; 32]>,
    certs: &[Vec<u8>],
) -> std::result::Result<Report, Failure> {
    verify_with_options(raw, pinned, certs, None)
}
/// Verify the bundle normally, then require its verified tree checkpoint when requested.
/// Legacy callers retain optional-tree behavior through the existing entry points.
/// # Errors
/// Fail-CLOSED: code 4 when the tree is required and no verified tree checkpoint exists, and
/// every code of [`verify_with_options`] otherwise.
pub fn verify_with_tree_requirement(
    raw: &[u8],
    pinned: Option<[u8; 32]>,
    certs: &[Vec<u8>],
    max_gap: Option<std::time::Duration>,
    require_tree: bool,
) -> std::result::Result<Report, Failure> {
    let report = verify_with_options(raw, pinned, certs, max_gap)?;
    if require_tree && (report.tree_size.is_none() || report.tree_root.is_none()) {
        return Err(failure(4, "required tree checkpoint is absent"));
    }
    Ok(report)
}
/// As [`verify_with_tsa`], and reports every interval between consecutive signed checkpoints
/// longer than `max_gap` as a gap. Errors fail CLOSED.
pub fn verify_with_options(
    raw: &[u8],
    pinned: Option<[u8; 32]>,
    certs: &[Vec<u8>],
    max_gap: Option<std::time::Duration>,
) -> std::result::Result<Report, Failure> {
    let max_gap = max_gap
        .map(chrono::Duration::from_std)
        .transpose()
        .map_err(|_| failure(4, "max_gap out of range"))?;
    let pin = pinned.ok_or_else(|| {
        failure(
            5,
            "external --pubkey file required; bundle keys are not trust roots",
        )
    })?;
    let files = unpack(raw).map_err(|e| failure(4, e))?;
    let (head, statement, signature) = (|| -> Result<_> {
        let bytes = get(&files, "manifest.json")?;
        let text = std::str::from_utf8(bytes)?;
        ensure!(canonical_json(text)? == text, "manifest is not JCS");
        let manifest: Manifest = serde_json::from_slice(bytes)?;
        ensure!(
            files.keys().all(|n| matches!(
                n.as_str(),
                "manifest.json"
                    | "ledger.ndjson"
                    | "checkpoint.json"
                    | "checkpoint.sig"
                    | "checkpoint.tsr"
                    | super::tree::MEMBER
                    | "checkpoint.cose"
                    | "checkpoints.ndjson"
            ) || [("artifacts/", ".json"), ("timestamps/", ".tsr")]
                .iter()
                .any(|(dir, ext)| n
                    .strip_prefix(dir)
                    .and_then(|n| n.strip_suffix(ext))
                    .is_some_and(|h| h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit())))),
            "unexpected bundle member"
        );
        ensure!(
            manifest.domain == "tracelane.action-bundle.v1"
                && manifest.files.len() + 1 == files.len(),
            "manifest member mismatch"
        );
        for (name, hash) in manifest.files {
            ensure!(
                name != "manifest.json" && hex::encode(crate::sha256(get(&files, &name)?)) == hash,
                "manifest hash mismatch: {name}"
            );
        }
        let statement = get(&files, "checkpoint.json")?;
        let text = std::str::from_utf8(statement)?;
        ensure!(canonical_json(text)? == text, "checkpoint not JCS");
        let h = super::head::parse(text)?;
        let _ = &h.previous_checkpoint_digest;
        Ok((h, statement, get(&files, "checkpoint.sig")?))
    })()
    .map_err(|e| failure(4, e))?;
    if head.key_id != hex::encode(crate::sha256(&pin))
        || ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, pin)
            .verify(statement, signature)
            .is_err()
    {
        return Err(failure(5, "checkpoint does not verify under external pin"));
    }
    // Optional second envelope over the same bytes; checkpoint.sig above stays authoritative.
    let cose_statement = match files.get("checkpoint.cose") {
        Some(cose) => {
            super::cose::verify(cose, statement, &pin).map_err(|e| {
                let code = if matches!(e, super::cose::Error::Signature) {
                    5
                } else {
                    4
                };
                failure(code, e)
            })?;
            true
        }
        None => false,
    };
    let (events, approvals, rows, coverage, leaves) = (|| -> Result<_> {
        let ledger = get(&files, "ledger.ndjson")?;
        let mut prev = crate::genesis_v2(head.tenant_id.as_bytes());
        let mut seq = 0;
        let mut events = Vec::new();
        let mut approvals = Vec::new();
        let mut leaves = Vec::new();
        for line in std::str::from_utf8(ledger)?.lines() {
            let value: serde_json::Value = serde_json::from_str(line)?;
            if value.get("type").and_then(|v| v.as_str()) == Some("anchor") {
                continue;
            }
            let row: crate::AuditRow = serde_json::from_value(value)?;
            ensure!(
                row.format.as_deref() == Some("v2.1"),
                "legacy object envelope is unverifiable in action bundles"
            );
            let payload = row
                .payload
                .as_str()
                .context("verbatim payload required; legacy envelope unverifiable")?;
            ensure!(
                canonical_json(payload)
                    .context("unverifiable legacy payload: floats/non-JCS bytes")?
                    == payload,
                "unverifiable legacy payload: non-JCS bytes"
            );
            ensure!(
                row.tenant_id == head.tenant_id.to_string()
                    && row.seq == seq
                    && row.prev_hash == hex::encode(prev),
                "tenant/sequence/previous hash mismatch at {seq}"
            );
            prev = crate::row_hash_v2(
                &prev,
                head.tenant_id.as_bytes(),
                seq,
                &row.event_type,
                &row.actor,
                payload,
            );
            ensure!(
                hex::encode(prev) == row.row_hash,
                "row hash mismatch at {seq}"
            );
            let v: serde_json::Value = serde_json::from_str(payload)?;
            if v.get("schema_version").is_some() || is_action(&row.event_type) {
                ensure!(
                    canonical_json(payload)? == payload,
                    "action payload not original JCS"
                );
                let e: Envelope = serde_json::from_str(payload)?;
                let body = serde_json::to_value(&e.body)?;
                ensure!(
                    body["event_type"] == row.event_type && e.tenant_id == head.tenant_id,
                    "action envelope identity mismatch"
                );
                if let Some(key) = e.agent_key_id {
                    ensure!(row.actor == key.to_string(), "actor/key mismatch");
                }
                events.push(e);
            } else if crate::approval::is_record(&row.event_type) {
                approvals.push(crate::approval::Record::from_row(
                    head.tenant_id,
                    &row.event_type,
                    &row.actor,
                    payload,
                )?);
            }
            leaves.push(super::tree::leaf_hash(&prev));
            seq += 1;
        }
        ensure!(
            if seq == 0 {
                head.seq.is_none() && head.head_hash.is_none()
            } else {
                head.seq.as_deref() == Some(&(seq - 1).to_string())
                    && head.head_hash.as_deref() == Some(&hex::encode(prev))
            },
            "covering head does not equal final row"
        );
        let mut opts = crate::VerifyOptions::default().with_tenant_pubkey(pin);
        for key in crate::TRACELANE_PLATFORM_PUBKEYS_B64 {
            opts.platform_pubkeys.push(
                crate::base64_decode(key)
                    .map_err(anyhow::Error::msg)?
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("invalid release key"))?,
            );
        }
        let coverage =
            crate::verify_ledger_reader(std::io::Cursor::new(ledger), "action-bundle", &opts)?;
        Ok((events, approvals, seq, coverage, leaves))
    })()
    .map_err(|e| failure(4, e))?;
    if !coverage.errors.is_empty() || !coverage.signatures_valid || coverage.strip_detected {
        let trust_failure = coverage.errors.iter().any(|e| {
            matches!(
                e.kind.as_str(),
                "untrusted_tenant_key" | "bad_tenant_pubkey"
            )
        });
        return Err(failure(
            if trust_failure { 5 } else { 4 },
            format!("batch verification failed: {:?}", coverage.errors),
        ));
    }
    if head.tree.is_some() && !files.contains_key(super::tree::MEMBER) {
        return Err(failure(4, "signed tree head requires tree-checkpoint.note"));
    }
    let tree = super::tree::check_member(&files, head.tenant_id, &pin, &leaves)
        .map_err(|(code, detail)| failure(code, detail))?;
    if let Some((size, root)) = head.tree {
        if size != rows || tree != Some(root) {
            return Err(failure(4, "signed tree head does not match ledger prefix"));
        }
    }
    let artifacts = files
        .iter()
        .filter_map(|(name, bytes)| {
            name.strip_prefix("artifacts/")
                .and_then(|n| n.strip_suffix(".json"))
                .map(|h| (h.to_owned(), bytes.clone()))
        })
        .collect();
    let actions = semantics(&events, &artifacts).map_err(semantic_failure)?;
    let approvals = crate::approval::semantics(&approvals).map_err(semantic_failure)?;
    let gen_time = super::timestamp::verify_optional(
        files.get("checkpoint.tsr").map(Vec::as_slice),
        statement,
        certs,
    )
    .map_err(|e| failure(4, e))?;
    let checkpoint_chain = super::chain::verify(
        &files,
        head.tenant_id,
        pin,
        statement,
        certs,
        max_gap,
        &leaves,
    )
    .map_err(|(code, e)| failure(code, e))?;
    Ok(Report {
        tenant_id: head.tenant_id,
        head_seq: head.seq,
        head_hash: head.head_hash,
        created_at: head.created_at,
        rows,
        chain: true,
        head: true,
        actions,
        approvals,
        batch_signatures: coverage.batch_signatures_verified,
        rekor_included: coverage.anchors_included,
        timestamped: gen_time.is_some(),
        timestamp_reason: (files.contains_key("checkpoint.tsr") && gen_time.is_none())
            .then_some("tsa_unpinned"),
        gen_time,
        tree_size: tree.map(|_| rows),
        tree_root: tree.map(hex::encode),
        cose_statement,
        checkpoint_chain,
    })
}
pub fn is_action(name: &str) -> bool {
    matches!(
        name,
        "policy_activated"
            | "action_proposed"
            | "decision_made"
            | "approval_requested"
            | "approval_granted"
            | "approval_denied"
            | "approval_attempt_rejected"
            | "approval_consumed"
            | "approval_expired"
            | "approval_invalidated"
            | "execution_started"
            | "execution_succeeded"
            | "execution_failed"
            | "execution_unknown"
            | "denied_runtime"
            | "legacy_forward_attempted"
            | "tool_receipt_key_registered"
    )
}
#[cfg(test)]
mod approval_tests;
#[cfg(test)]
mod tests;
