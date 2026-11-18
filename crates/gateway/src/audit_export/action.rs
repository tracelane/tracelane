//! Frozen canonical action evidence; no alternate export endpoint.
use super::*;
use crate::action_control::{canonical_json, checkpoint_for_head_tx, checkpoint_head_tx, sha};
use anyhow::{Context, ensure};
use tokio_postgres::Transaction;
use tracelane_audit_verifier::action::{ActionPayload, Envelope, archive::Files, bundle, tree};

#[cfg(test)]
tokio::task_local! {
    pub(crate) static BUILD_NOW: DateTime<Utc>;
    pub(crate) static READ_PAUSE: std::cell::RefCell<Option<Arc<(tokio::sync::Notify,tokio::sync::Notify)>>>;
}

#[derive(Debug, thiserror::Error)]
pub enum ExportError {
    #[error("action_snapshot_retry")]
    StaleHead,
    #[error("action_bundle_busy")]
    Busy,
    #[error("action_checkpoint_rate_limited")]
    CheckpointRateLimited(u64),
    #[error("action_reference_outside_export_range")]
    ReferenceOutsideRange,
    #[error("action_bundle_too_large")]
    TooLarge,
    #[error("action_evidence_invalid ({code}): {detail}")]
    InvalidEvidence { code: u8, detail: String },
}

pub(crate) fn refusal(err: &anyhow::Error) -> axum::response::Response {
    let (status, code, retry) = match err.downcast_ref::<ExportError>() {
        Some(ExportError::CheckpointRateLimited(seconds)) => (
            StatusCode::TOO_MANY_REQUESTS,
            "action_checkpoint_rate_limited",
            Some(*seconds),
        ),
        Some(ExportError::StaleHead) => (
            StatusCode::SERVICE_UNAVAILABLE,
            "action_snapshot_retry",
            Some(1),
        ),
        Some(ExportError::Busy) => (
            StatusCode::SERVICE_UNAVAILABLE,
            "action_bundle_busy",
            Some(1),
        ),
        Some(ExportError::TooLarge) => (
            StatusCode::PAYLOAD_TOO_LARGE,
            "action_bundle_too_large",
            None,
        ),
        Some(ExportError::ReferenceOutsideRange) => (
            StatusCode::UNPROCESSABLE_ENTITY,
            "action_reference_outside_export_range",
            None,
        ),
        _ if retryable_sqlstate(
            err.downcast_ref::<tokio_postgres::Error>()
                .and_then(|e| e.code()),
        ) =>
        {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "action_snapshot_retry",
                Some(1),
            )
        }
        _ => (
            StatusCode::SERVICE_UNAVAILABLE,
            "action_evidence_unavailable",
            None,
        ),
    };
    let mut response = error_response(status, code);
    if let Some(seconds) = retry
        && let Ok(value) = seconds.to_string().parse()
    {
        response.headers_mut().insert(header::RETRY_AFTER, value);
    }
    response
}

fn retryable_sqlstate(code: Option<&tokio_postgres::error::SqlState>) -> bool {
    code == Some(&tokio_postgres::error::SqlState::T_R_SERIALIZATION_FAILURE)
}
/// Errors fail CLOSED. No new SQL at all while the tenant flag is OFF.
#[tracing::instrument(skip_all, fields(tenant_id=%tenant))]
pub(super) async fn export(
    reader: &PgExportReader,
    tenant: &TenantId,
    resolved: &crate::entitlement_cache::ResolvedEntitlements,
) -> Result<Vec<u8>> {
    crate::action_control::require_enabled(Some(resolved))?;
    let now = build_now();
    admit_tenant(
        &mut *STARTS
            .lock()
            .map_err(|_| anyhow::anyhow!("bundle limiter unavailable"))?,
        tenant,
        now,
    )?;
    let permit = build_slot()?;
    // An open transaction pins PgBouncer's backend; detach prevents reuse on cancellation.
    let admission = deadpool_postgres::Object::take(reader.pool.get().await?);
    admission
        .batch_execute("BEGIN ISOLATION LEVEL READ COMMITTED")
        .await?;
    let acquired: bool = admission
        .query_one(
            "SELECT pg_try_advisory_xact_lock(hashtextextended($1::text || ':action_bundle', 0))",
            &[&tenant.to_string()],
        )
        .await?
        .get(0);
    ensure!(acquired, ExportError::CheckpointRateLimited(1));
    let previous = admission.query_opt("SELECT statement,(SELECT last_seq FROM audit_chain_state WHERE tenant_id=$1) FROM audit_head_checkpoints WHERE tenant_id=$1 ORDER BY checkpoint_order DESC LIMIT 1", &[tenant.as_uuid()]).await?;
    if let Some(row) = previous {
        crate::action_control::checkpoint_interval(
            &serde_json::from_str::<serde_json::Value>(row.get(0))?,
            now,
        )?;
    }
    let keys = reader
        .action_keys
        .as_ref()
        .context("tenant audit signer unavailable")?;
    let key = keys.get_or_create(tenant).await?;
    let mut db = reader.pool.get().await?;
    let tx = db
        .build_transaction()
        .isolation_level(tokio_postgres::IsolationLevel::RepeatableRead)
        .read_only(true)
        .start()
        .await?;
    let head = checkpoint_head_tx(&tx, tenant).await?; // FIRST snapshot SELECT; no row locks.
    let mut files = snapshot_files_tx(&tx, tenant, head, EvidenceBuffer::new()).await?;
    tx.commit().await?;
    let tx = db
        .build_transaction()
        .isolation_level(crate::action_control::CHECKPOINT_ISOLATION)
        .start()
        .await?;
    let cp = checkpoint_for_head_tx(&tx, tenant, head, &key, None).await?;
    let timestamp: Option<Vec<u8>> = tx.query_one(
        "SELECT timestamp_response FROM audit_head_checkpoints WHERE tenant_id=$1 AND checkpoint_id=$2",
        &[tenant.as_uuid(), &cp.id],
    ).await?.get(0);
    // The most recent window of the signed chain, ending at this head, so a verifier can tell
    // signed silence (heartbeats) from a gap. Bounded: rows are immutable, so an unbounded
    // chain would eventually exceed the archive limits and refuse every export for good.
    let mut chain = tx.query(
        "SELECT statement,signature,timestamp_response FROM audit_head_checkpoints WHERE tenant_id=$1 AND checkpoint_order<=(SELECT checkpoint_order FROM audit_head_checkpoints WHERE tenant_id=$1 AND checkpoint_id=$2) ORDER BY checkpoint_order DESC LIMIT $3",
        &[tenant.as_uuid(), &cp.id, &CHECKPOINT_CHAIN_WINDOW],
    ).await?;
    chain.reverse();
    tx.commit().await?;
    if let Some(timestamp) = timestamp {
        files.insert("checkpoint.tsr".into(), timestamp);
    }
    let mut lines = String::new();
    for row in chain {
        let statement: String = row.get(0);
        let signature: Vec<u8> = row.get(1);
        if let Some(token) = row.get::<_, Option<Vec<u8>>>(2) {
            files.insert(
                format!(
                    "timestamps/{}.tsr",
                    hex::encode(ring::digest::digest(
                        &ring::digest::SHA256,
                        statement.as_bytes()
                    ))
                ),
                token,
            );
        }
        lines.push_str(&serde_json::to_string(
            &serde_json::json!({"statement": statement, "signature": hex::encode(signature)}),
        )?);
        lines.push('\n');
    }
    files.insert("checkpoints.ndjson".into(), lines.into_bytes());
    let tsa_certs = reader.tsa_certs.clone();
    checkpoint_members(&mut files, cp, &key)?;
    drop(db);
    blocking_build(move || {
        let _admission = admission;
        let _permit = permit;
        seal_verified_with_tsa(files, &key, &tsa_certs)
    })
    .await
}

/// The signed head in its native form plus a COSE_Sign1 envelope over the same bytes
/// (aligned to draft-ietf-scitt-architecture-22; no Receipt). Errors fail CLOSED.
fn checkpoint_members(
    files: &mut Files,
    cp: crate::action_control::SignedCheckpoint,
    key: &crate::audit_keys::TenantAuditKeypair,
) -> Result<()> {
    let cose =
        tracelane_audit_verifier::action::cose::sign1(cp.statement.as_bytes(), |m| key.sign(m))?;
    files.insert("checkpoint.cose".into(), cose);
    files.insert("checkpoint.json".into(), cp.statement.into_bytes());
    files.insert("checkpoint.sig".into(), cp.signature);
    Ok(())
}

type BuildStarts = std::collections::HashMap<uuid::Uuid, DateTime<Utc>>;
static STARTS: std::sync::LazyLock<std::sync::Mutex<BuildStarts>> =
    std::sync::LazyLock::new(Default::default);
fn build_now() -> DateTime<Utc> {
    #[cfg(test)]
    if let Ok(now) = BUILD_NOW.try_with(|t| *t) {
        return now;
    }
    Utc::now()
}
fn admit_tenant(starts: &mut BuildStarts, tenant: &TenantId, now: DateTime<Utc>) -> Result<()> {
    let interval = crate::action_control::CHECKPOINT_MIN_INTERVAL_SECS;
    starts.retain(|_, start| now.signed_duration_since(*start).num_seconds() < interval);
    if let Some(start) = starts.get(tenant.as_uuid()) {
        return Err(ExportError::CheckpointRateLimited(u64::try_from(
            interval - now.signed_duration_since(*start).num_seconds(),
        )?)
        .into());
    }
    starts.insert(*tenant.as_uuid(), now);
    Ok(())
}

// No audit-bundle limits reference table exists. 2000 checkpoints is ~7 days at the 301 s
// heartbeat floor (~83 days hourly); worst case with a TSA token on each is ~11 MB and 4,000
// members, inside MAX_BUNDLE_BYTES (64 MiB) and the ZIP u16 member count.
const CHECKPOINT_CHAIN_WINDOW: i64 = 2000;
// No audit-bundle build-limit reference table exists; bound node memory/CPU globally.
const MAX_BUNDLE_BUILDS: usize = 2;
static BUILDS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(MAX_BUNDLE_BUILDS);
fn build_slot() -> Result<tokio::sync::SemaphorePermit<'static>> {
    BUILDS.try_acquire().map_err(|_| ExportError::Busy.into())
}
async fn blocking_build<T: Send + 'static>(
    build: impl FnOnce() -> Result<T> + Send + 'static,
) -> Result<T> {
    tokio::task::spawn_blocking(build).await?
}
fn archive_size(bytes: u64) -> Result<()> {
    tracelane_audit_verifier::action::archive::check_size(bytes)
        .map_err(|_| ExportError::TooLarge)?;
    Ok(())
}
/// Original immutable bytes only; missing, non-JCS or corrupt artifacts refuse CLOSED.
#[tracing::instrument(skip_all, fields(tenant_id=%tenant))]
async fn artifacts_bounded_tx(
    tx: &Transaction<'_>,
    tenant: &TenantId,
    policies: &[String],
    contracts: &[String],
    budget: &mut EvidenceBuffer,
) -> Result<Files> {
    let raw: i64 = tx.query_one(
        "SELECT ((SELECT COALESCE(SUM(octet_length(body_jcs)::bigint+512),0) FROM action_policies WHERE tenant_id=$1 AND policy_hash=ANY($2)) + (SELECT COALESCE(SUM(octet_length(body_jcs)::bigint+512),0) FROM action_tool_contracts WHERE tenant_id=$1 AND contract_hash=ANY($3)))::bigint",
        &[tenant.as_uuid(), &policies, &contracts]).await?.try_get(0)?;
    budget.check(raw)?;
    let policies_rows = tx.bind(
        "SELECT policy_hash,body_jcs FROM action_policies WHERE tenant_id=$1 AND policy_hash=ANY($2)",
        &[tenant.as_uuid(), &policies]).await?;
    let contracts_rows = tx.bind(
        "SELECT contract_hash,body_jcs FROM action_tool_contracts WHERE tenant_id=$1 AND contract_hash=ANY($2)",
        &[tenant.as_uuid(), &contracts]).await?;
    let mut files = Files::new();
    for portal in [policies_rows, contracts_rows] {
        loop {
            let batch = tx.query_portal(&portal, 500).await?;
            if batch.is_empty() {
                break;
            }
            for row in batch {
                let hash: &str = row.try_get(0)?;
                let original: &str = row.try_get(1)?;
                // Each artifact adds <= 400 bytes of ZIP headers, name copies and manifest.
                budget.charge(original.len().saturating_add(512))?;
                ensure!(
                    sha(original.as_bytes()) == hash && canonical_json(original)? == original,
                    "invalid original artifact bytes"
                );
                files.insert(
                    format!("artifacts/{hash}.json"),
                    original.as_bytes().to_vec(),
                );
            }
        }
    }
    for hash in policies.iter().chain(contracts) {
        ensure!(
            files.contains_key(&format!("artifacts/{hash}.json")),
            "missing original artifact"
        );
    }
    Ok(files)
}

#[cfg(test)]
pub(crate) async fn artifacts_tx(
    tx: &Transaction<'_>,
    tenant: &TenantId,
    policies: &[String],
    contracts: &[String],
) -> Result<Files> {
    artifacts_bounded_tx(tx, tenant, policies, contracts, &mut EvidenceBuffer::new()).await
}

/// Build from one read-only snapshot; the final checkpoint signs this exact head. Errors fail CLOSED; no network.
#[tracing::instrument(skip_all, fields(tenant_id=%tenant))]
pub(crate) async fn snapshot_files_tx(
    tx: &Transaction<'_>,
    tenant: &TenantId,
    head: Option<(u64, [u8; 32])>,
    mut ledger: EvidenceBuffer,
) -> Result<Files> {
    // An early estimate, not the bound: ZIP/manifest overhead, the tree checkpoint note
    // (under 512 B) and the FINAL checkpoint in both forms (checkpoint.json ~420 B, checkpoint.cose = the same bytes + ~235 B, .sig 64 B;
    // ~1.2 KB together, read from the 2026-11-14 review). The hard bound is `archive_size`
    // after `seal` plus the re-verify, so an overrun is refused, never released.
    ledger.charge(4096 + 512)?;
    let through = head.map(|h| i64::try_from(h.0)).transpose()?;
    let raw: i64 = tx.query_one(
        "SELECT COALESCE(SUM(octet_length(event_type)::bigint+octet_length(actor)+octet_length(payload)+octet_length(prev_hash)+octet_length(row_hash)+COALESCE(octet_length(rekor_entry_id),0)),0)::bigint FROM audit_log_rows WHERE tenant_id=$1",
        &[tenant.as_uuid()]).await?.try_get(0)?;
    ledger.check(raw)?;
    let rows = tx.bind(
        "SELECT tenant_id,seq,event_time,event_type,actor,payload,prev_hash,row_hash,rekor_entry_id FROM audit_log_rows WHERE tenant_id=$1 ORDER BY seq",
        &[tenant.as_uuid()]).await?;
    let mut policies = Vec::new();
    let mut contracts = Vec::new();
    let mut last = None;
    loop {
        let batch = tx.query_portal(&rows, 500).await?;
        if batch.is_empty() {
            break;
        }
        #[cfg(test)]
        if let Some(pause) = READ_PAUSE
            .try_with(|p| p.borrow_mut().take())
            .ok()
            .flatten()
        {
            pause.0.notify_one();
            pause.1.notified().await;
        }
        for r in batch {
            // Check borrowed payload before cloning/decoding; escaped JSON is budgeted on write.
            ensure!(
                r.try_get::<_, &str>("payload")?.len() <= ledger.remaining,
                ExportError::TooLarge
            );
            let et: DateTime<Utc> = r.try_get("event_time")?;
            let row = ExportRow {
                format: EXPORT_FORMAT.into(),
                tenant_id: r.try_get::<_, uuid::Uuid>("tenant_id")?.to_string(),
                seq: u64::try_from(r.try_get::<_, i64>("seq")?)?,
                event_time: micros_to_iso8601(et.timestamp_micros()),
                event_type: r.try_get("event_type")?,
                actor: r.try_get("actor")?,
                payload: r.try_get("payload")?,
                prev_hash: r.try_get("prev_hash")?,
                row_hash: r.try_get("row_hash")?,
                rekor_entry_id: r.try_get("rekor_entry_id")?,
            };
            if bundle::is_action(&row.event_type) {
                let event: Envelope = serde_json::from_str(&row.payload)?;
                if let ActionPayload::PolicyActivated {
                    policy_hash,
                    contract_hash,
                    ..
                } = event.body
                {
                    policies.push(policy_hash);
                    contracts.push(contract_hash);
                }
            }
            last = Some((row.seq, row.row_hash.clone()));
            ledger.record(&row)?;
        }
    }
    ensure!(
        last.as_ref().map(|r| r.0) == head.map(|h| h.0)
            && last.as_ref().map(|r| r.1.clone()) == head.map(|h| hex::encode(h.1)),
        ExportError::InvalidEvidence {
            code: 4,
            detail: "snapshot head mismatch".into()
        }
    );
    let raw: i64 = tx.query_one(
        "SELECT COALESCE(SUM(octet_length(merkle_root)::bigint+octet_length(anchor_state)+octet_length(ed25519_sig)+octet_length(ed25519_pubkey)+octet_length(rekor_log_url)+octet_length(rekor_log_index)+octet_length(canonicalized_body)+octet_length(inclusion_proof)+octet_length(checkpoint_envelope)),0)::bigint FROM audit_anchor_records WHERE tenant_id=$1 AND batch_start_seq>=0 AND batch_end_seq<=$2",
        &[tenant.as_uuid(), &through]).await?.try_get(0)?;
    ledger.check(raw)?;
    let anchors = tx.bind(
        "SELECT tenant_id,batch_start_seq,batch_end_seq,merkle_root,anchor_state,ed25519_sig,ed25519_pubkey,rekor_log_url,rekor_log_index,canonicalized_body,inclusion_proof,checkpoint_envelope FROM audit_anchor_records WHERE tenant_id=$1 AND batch_start_seq>=0 AND batch_end_seq <= $2 ORDER BY batch_start_seq",
        &[tenant.as_uuid(), &through]).await?;
    loop {
        let batch = tx.query_portal(&anchors, 500).await?;
        if batch.is_empty() {
            break;
        }
        for r in batch {
            let state: String = r.try_get("anchor_state")?;
            let record = AnchorExportRecord {
                kind: "anchor",
                tenant_id: r.try_get::<_, uuid::Uuid>("tenant_id")?.to_string(),
                batch_start_seq: u64::try_from(r.try_get::<_, i64>("batch_start_seq")?)?,
                batch_end_seq: u64::try_from(r.try_get::<_, i64>("batch_end_seq")?)?,
                merkle_root: r.try_get("merkle_root")?,
                ed25519: Ed25519Block {
                    signature: r.try_get("ed25519_sig")?,
                    pubkey: r.try_get("ed25519_pubkey")?,
                },
                rekor: if state == "anchored" {
                    Some(RekorBlock {
                        log_url: r.try_get("rekor_log_url")?,
                        log_index: r.try_get("rekor_log_index")?,
                        canonicalized_body: r.try_get("canonicalized_body")?,
                        inclusion_proof: serde_json::from_str(
                            r.try_get::<_, &str>("inclusion_proof")?,
                        )?,
                        checkpoint: CheckpointBlock {
                            envelope: r.try_get("checkpoint_envelope")?,
                        },
                    })
                } else {
                    None
                },
                anchor_state: state,
            };
            ledger.record(&record)?;
        }
    }
    let mut files = artifacts_bounded_tx(tx, tenant, &policies, &contracts, &mut ledger).await?;
    files.insert("ledger.ndjson".into(), ledger.bytes);
    Ok(files)
}
/// Errors fail CLOSED; no transaction or head lock is held during these CPU/buffer operations.
#[cfg(test)]
pub(crate) fn seal_verified(
    files: Files,
    key: &crate::audit_keys::TenantAuditKeypair,
) -> Result<Vec<u8>> {
    seal_verified_with_tsa(files, key, &[])
}
fn seal_verified_with_tsa(
    files: Files,
    key: &crate::audit_keys::TenantAuditKeypair,
    tsa_certs: &[Vec<u8>],
) -> Result<Vec<u8>> {
    let files = with_tree_checkpoint(files, key)?;
    let zip = bundle::seal(files)?;
    archive_size(u64::try_from(zip.len())?)?;
    let pin = key
        .public_key_bytes()
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid tenant audit public key"))?;
    // Reuse the existing causal machine. Error classification NEVER authorizes a bundle.
    let report = bundle::verify_with_tsa(&zip, Some(pin), tsa_certs).map_err(|e| {
        if e.kind == bundle::FailureKind::ReferenceOutsideRange {
            ExportError::ReferenceOutsideRange
        } else {
            ExportError::InvalidEvidence {
                code: e.code,
                detail: e.detail,
            }
        }
    })?;
    // The verifier treats the note as optional (older bundles); a new export must carry it.
    ensure!(
        report.tree_size == Some(report.rows),
        "tree checkpoint missing from sealed bundle"
    );
    Ok(zip)
}
/// Add the C2SP checkpoint over every ledger row in `files` (RFC 6962 tree of row
/// hashes), signed with the tenant audit key. The origin binds it to the tenant named
/// in the signed head. Tamper-evident only; no witness cosigns it.
///
/// # Errors
/// Fails CLOSED: a ledger or head that cannot be read refuses the bundle.
pub(crate) fn with_tree_checkpoint(
    mut files: Files,
    key: &crate::audit_keys::TenantAuditKeypair,
) -> Result<Files> {
    #[derive(serde::Deserialize)]
    struct Head {
        tenant_id: uuid::Uuid,
    }
    let head: Head = serde_json::from_slice(files.get("checkpoint.json").context("no head")?)?;
    let leaves = tree::ledger_leaves(files.get("ledger.ndjson").context("no ledger")?)?;
    let pin: [u8; 32] = key
        .public_key_bytes()
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid tenant audit public key"))?;
    let origin = tree::origin(head.tenant_id);
    let body = tree::checkpoint_body(&origin, u64::try_from(leaves.len())?, &tree::root(&leaves));
    let note = tree::signed_note(&body, &origin, &pin, &key.sign(body.as_bytes()));
    files.insert(tree::MEMBER.into(), note.into_bytes());
    Ok(files)
}

// Shared producer serialization buffer; the regression below exercises its byte limit.
pub(crate) struct EvidenceBuffer {
    bytes: Vec<u8>,
    remaining: usize,
}
impl std::io::Write for EvidenceBuffer {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.charge(bytes.len()).map_err(std::io::Error::other)?;
        let needed = self.bytes.len() + bytes.len();
        if needed > self.bytes.capacity() {
            let capacity = self
                .bytes
                .capacity()
                .saturating_mul(2)
                .max(needed)
                .min(needed + self.remaining);
            self.bytes.reserve_exact(capacity - self.bytes.len());
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
impl EvidenceBuffer {
    pub(crate) fn new() -> Self {
        Self {
            bytes: Vec::new(),
            remaining: tracelane_audit_verifier::action::archive::MAX_BUNDLE_BYTES as usize,
        }
    }
    #[cfg(test)]
    pub(crate) fn with_limit(mut self, bytes: usize) -> Self {
        self.remaining = bytes;
        self
    }
    fn check(&self, bytes: i64) -> Result<()> {
        ensure!(
            usize::try_from(bytes)? <= self.remaining,
            ExportError::TooLarge
        );
        Ok(())
    }
    fn charge(&mut self, bytes: usize) -> Result<()> {
        self.remaining = self
            .remaining
            .checked_sub(bytes)
            .ok_or(ExportError::TooLarge)?;
        Ok(())
    }
    fn record(&mut self, row: &impl serde::Serialize) -> Result<()> {
        serde_json::to_writer(&mut *self, row).map_err(|e| {
            if e.is_io() {
                anyhow::Error::from(ExportError::TooLarge)
            } else {
                e.into()
            }
        })?;
        std::io::Write::write_all(self, b"\n").map_err(|_| ExportError::TooLarge)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::audit_export::{AuditExportReader, PgExportReader};
    #[test]
    fn checkpoint_members_carry_cose() {
        let tenant = tracelane_shared::TenantId::from_jwt_claim(uuid::Uuid::new_v4());
        let key = crate::audit_keys::TenantAuditKeypair::generate(tenant.clone()).unwrap();
        let cp = crate::action_control::sign_checkpoint(&key, &tenant, None, None).unwrap();
        let statement = cp.statement.clone();
        let mut files = super::Files::from([("ledger.ndjson".to_owned(), vec![])]);
        super::checkpoint_members(&mut files, cp, &key).unwrap();
        assert_eq!(files["checkpoint.json"], statement.as_bytes());
        let pin: [u8; 32] = key.public_key_bytes().try_into().unwrap();
        tracelane_audit_verifier::action::cose::verify(
            &files["checkpoint.cose"],
            statement.as_bytes(),
            &pin,
        )
        .unwrap();
        // The sealed bundle is re-verified before release, COSE member included.
        let zip = super::seal_verified(files, &key).unwrap();
        let report = super::bundle::verify(&zip, Some(pin)).unwrap();
        assert!(report.cose_statement && report.head);
    }
    #[test]
    fn fix3_unchanged_build_interval() {
        use super::*;
        let tenant = TenantId::from_jwt_claim(uuid::Uuid::new_v4());
        let now = Utc::now();
        let mut starts = std::collections::HashMap::new();
        admit_tenant(&mut starts, &tenant, now).unwrap();
        let e = admit_tenant(&mut starts, &tenant, now).unwrap_err();
        assert_eq!(refusal(&e).status().as_u16(), 429);
        admit_tenant(
            &mut starts,
            &TenantId::from_jwt_claim(uuid::Uuid::new_v4()),
            now,
        )
        .unwrap();
        admit_tenant(&mut starts, &tenant, now + chrono::Duration::seconds(60)).unwrap();
    }
    #[test]
    fn fix_retry_responses() {
        use super::*;
        use tokio_postgres::error::SqlState;
        assert!(retryable_sqlstate(Some(
            &SqlState::T_R_SERIALIZATION_FAILURE
        )));
        assert!(!retryable_sqlstate(Some(&SqlState::UNIQUE_VIOLATION)));
        for (error, status, retry) in [
            (ExportError::Busy, 503, 1),
            (ExportError::CheckpointRateLimited(23), 429, 23),
        ] {
            let response = refusal(&error.into());
            assert_eq!(response.status().as_u16(), status);
            assert_eq!(response.headers()["retry-after"], retry.to_string());
        }
    }
    #[test]
    fn fix_build_admission_is_two() {
        let a = super::build_slot().unwrap();
        let b = super::build_slot().unwrap();
        assert!(super::build_slot().is_err(), "third build admitted");
        drop((a, b));
        assert!(super::build_slot().is_ok());
    }
    #[tokio::test(flavor = "current_thread")]
    async fn fix_seal_runs_off_runtime() {
        let runtime = std::thread::current().id();
        let worker = super::blocking_build(|| Ok(std::thread::current().id()))
            .await
            .unwrap();
        assert_ne!(runtime, worker, "CPU build ran on runtime worker");
    }
    #[test]
    fn fix_archive_overflow_is_typed() {
        let error =
            super::archive_size(tracelane_audit_verifier::action::archive::MAX_BUNDLE_BYTES + 1)
                .unwrap_err();
        assert!(
            matches!(error.downcast_ref(), Some(super::ExportError::TooLarge)),
            "{error}"
        );
        assert_eq!(super::refusal(&error).status().as_u16(), 413);
    }
    #[test]
    fn producer_refuses_oversize_before_next_row() {
        let mut buffer = super::EvidenceBuffer {
            bytes: Vec::new(),
            remaining: 12,
        };
        assert!(buffer.check(13).is_err());
        assert!(buffer.bytes.is_empty());
        let mut fetched = 0;
        let result: anyhow::Result<()> = (0..3).try_for_each(|_| {
            fetched += 1;
            buffer.record(&"abcdef")
        });
        assert!(matches!(
            result.unwrap_err().downcast_ref(),
            Some(super::ExportError::TooLarge)
        ));
        assert_eq!(fetched, 2, "must refuse before fetching the next row");
        assert!(buffer.bytes.capacity() <= 12, "allocated past byte budget");
        let mut exact = super::EvidenceBuffer::new().with_limit(4);
        exact.record(&123).unwrap();
        assert_eq!(exact.bytes, b"123\n");
        assert!(exact.bytes.capacity() <= 4);
        assert!(exact.record(&0).is_err());
    }
    // AUD-06: an empty signed head is the smallest real input; no Postgres needed.
    #[test]
    fn seal_adds_tree_checkpoint() {
        use super::*;
        let tenant = TenantId::from_jwt_claim(uuid::Uuid::new_v4());
        let key = crate::audit_keys::TenantAuditKeypair::generate(tenant.clone()).unwrap();
        let pin: [u8; 32] = key.public_key_bytes().try_into().unwrap();
        let head = canonical_json(
            &serde_json::json!({"domain":"tracelane.action-head.v1","schema_version":1,
                "tenant_id":tenant.as_uuid(),"seq":null,"head_hash":null,
                "created_at":"2026-11-13T12:00:00Z","key_id":sha(&pin),
                "previous_checkpoint_digest":null})
            .to_string(),
        )
        .unwrap();
        let files: Files = [
            ("ledger.ndjson".to_owned(), Vec::new()),
            ("checkpoint.sig".to_owned(), key.sign(head.as_bytes())),
            ("checkpoint.json".to_owned(), head.into_bytes()),
        ]
        .into();
        let zip = seal_verified(files.clone(), &key).unwrap();
        let report = bundle::verify(&zip, Some(pin)).unwrap();
        assert_eq!(report.tree_size, Some(0));
        assert_eq!(report.tree_root, Some(hex::encode(tree::root(&[]))));
        let unpacked = tracelane_audit_verifier::action::archive::unpack(&zip).unwrap();
        let note = std::str::from_utf8(&unpacked[tree::MEMBER]).unwrap();
        let origin = tree::origin(*tenant.as_uuid());
        assert!(note.starts_with(&format!("{origin}\n0\n")), "{note}");
        tree::open_checkpoint(note.as_bytes(), &origin, &pin).unwrap();
        // No signed head, no bundle.
        let mut wrong = files;
        wrong.remove("checkpoint.json");
        assert!(seal_verified(wrong, &key).is_err());
    }
    #[tokio::test]
    async fn disabled_export_refuses_before_pool_or_keys() {
        let mut config = deadpool_postgres::Config::new();
        config.host = Some("127.0.0.1".into());
        config.port = Some(1);
        config.user = Some("synthetic".into());
        config.dbname = Some("synthetic".into());
        let pool = config
            .create_pool(
                Some(deadpool_postgres::Runtime::Tokio1),
                tokio_postgres::NoTls,
            )
            .unwrap();
        let reader = PgExportReader::new(pool);
        let e = reader
            .action_bundle(
                &tracelane_shared::TenantId::from_jwt_claim(uuid::Uuid::new_v4()),
                &crate::entitlement_cache::ResolvedEntitlements::deny_all(),
            )
            .await
            .unwrap_err();
        assert_eq!(e.to_string(), "action control disabled");
    }
}
