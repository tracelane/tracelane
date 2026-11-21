//! Protected action evidence. Consumers opt in explicitly; ordinary traffic is untouched.
// C1-2..5 consume this foundation; no protected dispatch route is enabled by this module.
#![allow(dead_code)] // Governed C1 foundation API; production consumers land in C1-2..5.
use anyhow::{Context, Result, ensure};
use chrono::{DateTime, SecondsFormat, Utc};
use ring::{
    digest, hmac,
    rand::{SecureRandom, SystemRandom},
};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use tokio_postgres::Transaction;
use tracelane_shared::TenantId;
use uuid::Uuid;

const SAFE_INTEGER: i64 = 9_007_199_254_740_991;

#[cfg(test)]
mod approval_pg_tests;

pub mod authority;
#[cfg(test)]
mod authority_pg_tests;
pub mod execution;
#[cfg(test)]
mod execution_pg_tests;
#[cfg(test)]
mod execution_tests;
pub mod heartbeat;
pub mod paused_evidence;
pub mod policy;
pub mod policy_api;
#[cfg(test)]
mod policy_pg_tests;
pub mod policy_store;
pub mod principal;
pub mod principal_api;
#[cfg(test)]
mod principal_pg_tests;
pub mod receipt_keys;
pub mod timeline;
/// RFC 8785 bytes for new action contracts only. Errors fail CLOSED.
pub fn canonical_json(raw: &str) -> Result<String> {
    tracelane_audit_verifier::action::canonical_json(raw)
}
pub(crate) fn canonical(value: &impl Serialize) -> Result<String> {
    canonical_json(&serde_json::to_string(value).context("serialize typed action")?)
}
pub(crate) fn sha(value: &[u8]) -> String {
    hex::encode(digest::digest(&digest::SHA256, value).as_ref())
}
#[derive(Clone, Copy)]
pub enum EvidenceMode {
    Tokenize,
    DigestOnly,
}
pub use tracelane_audit_verifier::action::{
    ActionPayload, ClearValue, Decision, EvidenceField, ReasonCode, Usd,
};
/// Minimize before canonicalization. Errors fail CLOSED; values/secrets are never logged.
pub fn minimize(secret: &SecretString, mode: EvidenceMode, value: &str) -> Result<EvidenceField> {
    let bytes = canonical(&value)?;
    Ok(match mode {
        EvidenceMode::Tokenize => {
            ensure!(
                value.chars().count() > 4,
                "tokenized value must exceed last4"
            );
            let key = hmac::Key::new(hmac::HMAC_SHA256, secret.expose_secret().as_bytes());
            EvidenceField::Tokenize {
                hmac: hex::encode(hmac::sign(&key, value.as_bytes()).as_ref()),
                last4: value
                    .chars()
                    .rev()
                    .take(4)
                    .collect::<Vec<_>>()
                    .into_iter()
                    .rev()
                    .collect(),
            }
        }
        EvidenceMode::DigestOnly => EvidenceField::DigestOnly {
            sha256: sha(bytes.as_bytes()),
        },
    })
}
#[derive(Clone)]
pub struct ActionEvent {
    pub event_id: Uuid,
    pub action_id: Uuid,
    pub occurred_at: DateTime<Utc>,
    pub request_digest: String,
    pub body: ActionPayload,
}
impl ActionEvent {
    pub fn event_type(&self) -> &'static str {
        match self.body {
            ActionPayload::ActionProposed { .. } => "action_proposed",
            ActionPayload::DecisionMade { .. } => "decision_made",
            ActionPayload::ApprovalRequested { .. } => "approval_requested",
            ActionPayload::ApprovalGranted { .. } => "approval_granted",
            ActionPayload::ApprovalDenied { .. } => "approval_denied",
            ActionPayload::ApprovalAttemptRejected { .. } => "approval_attempt_rejected",
            ActionPayload::ApprovalConsumed { .. } => "approval_consumed",
            ActionPayload::ApprovalExpired { .. } => "approval_expired",
            ActionPayload::ApprovalInvalidated { .. } => "approval_invalidated",
            ActionPayload::LegacyForwardAttempted { .. } => "legacy_forward_attempted",
            ActionPayload::ExecutionStarted { .. } => "execution_started",
            ActionPayload::ExecutionSucceeded { .. } => "execution_succeeded",
            ActionPayload::ExecutionFailed { .. } => "execution_failed",
            ActionPayload::ExecutionUnknown { .. } => "execution_unknown",
            ActionPayload::DeniedRuntime { .. } => "denied_runtime",
            ActionPayload::PolicyActivated { .. } => "policy_activated",
            ActionPayload::ToolReceiptKeyRegistered { .. } => "tool_receipt_key_registered",
        }
    }
    pub fn canonical(&self, tenant: &TenantId, key: Option<Uuid>) -> Result<String> {
        let body = serde_json::to_value(&self.body)?;
        validate_fields(&body)?;
        crate::db::ledger::decode_hash_hex(&self.request_digest)?;
        let version = match &self.body {
            ActionPayload::ActionProposed {
                principal: Some(_), ..
            }
            | ActionPayload::DeniedRuntime {
                reason:
                    ReasonCode::PrincipalRequired
                    | ReasonCode::PrincipalInvalid
                    | ReasonCode::PrincipalUnverifiable,
            } => 2,
            _ => 1,
        };
        canonical(
            &json!({"schema_version":version,"event_id":self.event_id,"action_id":self.action_id,"tenant_id":tenant.to_string(),"agent_key_id":key,"occurred_at":self.occurred_at.to_rfc3339_opts(SecondsFormat::Millis,true),"request_digest":self.request_digest,"body":body}),
        )
    }
}
fn validate_field_name(name: &str) -> Result<()> {
    ensure!(
        !name.is_empty()
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b)),
        "invalid evidence field name"
    );
    Ok(())
}
fn validate_fields(v: &Value) -> Result<()> {
    match v {
        Value::Object(map) => {
            for (name, value) in map {
                validate_field_name(name)?;
                if name == "principal" {
                    let p: tracelane_audit_verifier::action::Principal =
                        serde_json::from_value(value.clone())?;
                    p.validate()?;
                    continue;
                }
                if matches!(name.as_str(), "evidence_fields" | "agent_claimed_labels") {
                    // These names identify maps in the typed ActionPayload. Their
                    // customer-chosen keys label EvidenceField objects, not digests.
                    for (field_name, field) in
                        value.as_object().context("evidence must be a map")?
                    {
                        validate_field_name(field_name)?;
                        validate_fields(field)?;
                    }
                    continue;
                }
                if matches!(
                    name.as_str(),
                    "args_digest"
                        | "policy_hash"
                        | "contract_hash"
                        | "decider_digest"
                        | "note_digest"
                        | "receipt_digest"
                        | "publisher_digest"
                        | "hmac"
                        | "sha256"
                ) && !value.is_null()
                {
                    crate::db::ledger::decode_hash_hex(
                        value.as_str().context("digest must be text")?,
                    )?;
                } else if let Value::String(s) = value {
                    if name != "last4" && name != "expires_at" {
                        ensure!(
                            !s.is_empty()
                                && s.bytes()
                                    .all(|b| b.is_ascii_alphanumeric() || b"_.:-".contains(&b)),
                            "invalid evidence code"
                        );
                    } else if name == "last4" {
                        ensure!(s.chars().count() == 4, "invalid last4");
                    }
                }
                validate_fields(value)?;
            }
        }
        Value::Array(a) => {
            for v in a {
                validate_fields(v)?;
            }
        }
        _ => {}
    }
    Ok(())
}
/// The DATABASE's clock, read inside the caller's transaction (2026-10-29 SRE review).
/// `revoked_at`, `expires_at` and every consume/decide UPDATE are written and checked
/// with `clock_timestamp()`; comparing them with the gateway's `Utc::now()` opens a
/// skew-sized window where a revoked key or an expired approval still passes.
///
/// # Errors
/// Fail-CLOSED: the caller rolls back.
pub(crate) async fn db_now(tx: &Transaction<'_>) -> Result<DateTime<Utc>> {
    Ok(tx.query_one("SELECT clock_timestamp()", &[]).await?.get(0))
}
/// No control-plane cache means OFF; this never queries an action table.
pub fn enabled(resolved: Option<&crate::entitlement_cache::ResolvedEntitlements>) -> bool {
    resolved.is_some_and(|r| r.action_control)
}
pub(crate) fn require_enabled(
    resolved: Option<&crate::entitlement_cache::ResolvedEntitlements>,
) -> Result<()> {
    ensure!(enabled(resolved), "action control disabled");
    Ok(())
}
fn actor_for(key: Option<Uuid>, method: Option<crate::auth::AuthMethod>) -> String {
    key.map_or_else(
        || {
            match method {
                Some(crate::auth::AuthMethod::JwtBearer) => "human",
                Some(crate::auth::AuthMethod::SelfHostMasterKey) => "self_host_master_key",
                Some(crate::auth::AuthMethod::ApiKey) => "api_key",
                Some(crate::auth::AuthMethod::Mtls) => "mtls",
                None => "system",
            }
            .to_owned()
        },
        |k| k.to_string(),
    )
}
fn rows_for(
    t: &TenantId,
    key: Option<Uuid>,
    method: Option<crate::auth::AuthMethod>,
    events: &[ActionEvent],
    first: u64,
    mut prev: [u8; 32],
    kept: &[usize],
) -> Result<Vec<crate::db::ledger::AuditLogRow>> {
    let mut rows = Vec::with_capacity(kept.len());
    for (offset, index) in kept.iter().enumerate() {
        let e = &events[*index];
        let payload = e.canonical(t, key)?;
        ensure!(
            payload.len() <= crate::mcp_policy::settings()?.limits.max_event_bytes,
            "action evidence too large"
        );
        let seq = first + offset as u64;
        let actor = actor_for(key, method);
        let hash =
            crate::audit_format::row_hash_v2(&prev, t, seq, e.event_type(), &actor, &payload);
        rows.push(crate::db::ledger::AuditLogRow {
            tenant_id: t.to_string(),
            seq,
            event_time: e.occurred_at.timestamp_micros(),
            event_type: e.event_type().into(),
            actor,
            payload,
            prev_hash: hex::encode(prev),
            row_hash: hex::encode(hash),
            rekor_entry_id: None,
            signature: String::new(),
            signing_pubkey: String::new(),
        });
        prev = hash;
    }
    Ok(rows)
}
/// Append on the caller's transaction. Errors fail CLOSED: caller MUST roll back.
/// Returns candidate rows, never a commit acknowledgment. Forward only after outer commit.
#[tracing::instrument(skip_all)]
pub async fn append_actions_tx(
    tx: &Transaction<'_>,
    claims: &crate::auth::Claims,
    resolved: Option<&crate::entitlement_cache::ResolvedEntitlements>,
    events: &[ActionEvent],
) -> Result<Option<crate::db::audit_chain_state::AtomicBatchAppend>> {
    if !enabled(resolved) {
        return Ok(None);
    }
    append_committed_actions_tx(tx, claims, events).await
}
/// Existing durable reservations must record outcomes even after admission is disabled.
async fn append_committed_actions_tx(
    tx: &Transaction<'_>,
    claims: &crate::auth::Claims,
    events: &[ActionEvent],
) -> Result<Option<crate::db::audit_chain_state::AtomicBatchAppend>> {
    let key = claims
        .api_key_id()
        .map(Uuid::parse_str)
        .transpose()
        .context("invalid authenticated key ID")?;
    append_for_actor_tx(tx, &claims.tenant_id, key, Some(claims.auth_method), events).await
}
/// Existing grants still expire when admission is OFF. Only lifecycle events can
/// use this system actor; it cannot propose or authorize an execution.
pub(crate) async fn append_lifecycle_tx(
    tx: &Transaction<'_>,
    tenant: &TenantId,
    events: &[ActionEvent],
) -> Result<Option<crate::db::audit_chain_state::AtomicBatchAppend>> {
    ensure!(
        events.iter().all(|e| matches!(
            e.body,
            ActionPayload::ApprovalExpired { .. } | ActionPayload::ApprovalInvalidated { .. }
        )),
        "invalid lifecycle event"
    );
    append_for_actor_tx(tx, tenant, None, None, events).await
}
async fn append_for_actor_tx(
    tx: &Transaction<'_>,
    tenant: &TenantId,
    key: Option<Uuid>,
    method: Option<crate::auth::AuthMethod>,
    events: &[ActionEvent],
) -> Result<Option<crate::db::audit_chain_state::AtomicBatchAppend>> {
    for e in events {
        if matches!(
            e.body,
            ActionPayload::ActionProposed { .. } | ActionPayload::ExecutionStarted { .. }
        ) {
            ensure!(
                key.is_some(),
                "protected action requires authenticated API key"
            );
        }
        e.canonical(tenant, key)?;
    }
    let ids: Vec<String> = events
        .iter()
        .map(|e| format!("action:{}:{}", tenant, e.event_id))
        .collect();
    let recordings = events
        .iter()
        .map(|e| {
            // Protected writes use the same reserved-envelope contract as the consumer.
            // Current protected payloads have no recording member; producers remain off.
            crate::gateway_recording::Recording::parse(
                tenant,
                Some(&e.event_id.to_string()),
                e.event_type(),
                &actor_for(key, method),
                &e.canonical(tenant, key)?,
            )
        })
        .collect::<Result<Vec<_>>>()?;
    crate::db::audit_chain_state::append_atomic_batch_tx(
        tx,
        tenant,
        crate::audit_format::genesis_prev_hash(tenant),
        Some(&ids),
        events.len(),
        &recordings,
        |seq, prev, kept| rows_for(tenant, key, method, events, seq, prev, kept),
    )
    .await
}
/// Tenant-bound encrypted token secret. Cached flag is checked before SQL.
/// Errors fail CLOSED; plaintext custody is SecretString, AAD purpose separated.
#[tracing::instrument(skip_all)]
pub async fn tokenization_secret_tx(
    tx: &Transaction<'_>,
    tenant: &TenantId,
    resolved: Option<&crate::entitlement_cache::ResolvedEntitlements>,
    master: &crate::byok::ByokMasterKey,
) -> Result<SecretString> {
    require_enabled(resolved)?;
    let aad = format!("tracelane.action-tokenization.v1:{tenant}");
    if let Some(row) = tx
        .query_opt(
            "SELECT encrypted_secret FROM action_tokenization_secrets WHERE tenant_id=$1",
            &[tenant.as_uuid()],
        )
        .await?
    {
        return master.decrypt_with_context(row.get::<_, String>(0).as_str(), aad.as_bytes());
    }
    let mut bytes = [0u8; 32];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| anyhow::anyhow!("token secret RNG unavailable"))?;
    let secret = SecretString::from(hex::encode(bytes));
    bytes.fill(0);
    let encrypted = master.encrypt_with_context(&secret, aad.as_bytes())?;
    tx.execute("INSERT INTO action_tokenization_secrets (tenant_id,encrypted_secret) VALUES ($1,$2) ON CONFLICT (tenant_id) DO NOTHING", &[tenant.as_uuid(),&encrypted]).await?;
    let row = tx
        .query_one(
            "SELECT encrypted_secret FROM action_tokenization_secrets WHERE tenant_id=$1",
            &[tenant.as_uuid()],
        )
        .await?;
    master.decrypt_with_context(row.get::<_, String>(0).as_str(), aad.as_bytes())
}
// Minting must see the winner after waiting for the predecessor lock.
pub(crate) const CHECKPOINT_ISOLATION: tokio_postgres::IsolationLevel =
    tokio_postgres::IsolationLevel::ReadCommitted;
#[derive(Clone)]
pub struct SignedCheckpoint {
    pub id: Uuid,
    pub statement: String,
    pub signature: Vec<u8>,
}
/// Sign tenant head with explicit purpose and public key ID. Errors fail CLOSED.
pub(crate) fn sign_checkpoint(
    key: &crate::audit_keys::TenantAuditKeypair,
    tenant: &TenantId,
    head: Option<(u64, [u8; 32])>,
    previous: Option<String>,
) -> Result<SignedCheckpoint> {
    let id = Uuid::new_v4();
    let statement = canonical(
        &json!({"domain":"tracelane.action-head.v1","schema_version":1,"tenant_id":tenant.to_string(),"seq":head.map(|h|h.0.to_string()),"head_hash":head.map(|h|hex::encode(h.1)),"created_at":Utc::now().to_rfc3339_opts(SecondsFormat::Millis,true),"key_id":sha(&key.public_key_bytes()),"previous_checkpoint_digest":previous}),
    )?;
    Ok(SignedCheckpoint {
        id,
        signature: key.sign(statement.as_bytes()),
        statement,
    })
}
/// Age of a stored checkpoint from its signed `created_at`. Errors on a malformed statement.
fn checkpoint_age(cp: &SignedCheckpoint) -> Result<std::time::Duration> {
    let statement: Value = serde_json::from_str(&cp.statement)?;
    let created: DateTime<Utc> = statement["created_at"]
        .as_str()
        .context("checkpoint created_at")?
        .parse()?;
    // silent-fallback-ok: a future created_at (clock skew) reads as age 0, so no heartbeat
    // mints early; the next tick re-reads it.
    Ok((Utc::now() - created).to_std().unwrap_or_default())
}
// No audit-checkpoint limits reference table exists; conservative operational floor.
pub(crate) const CHECKPOINT_MIN_INTERVAL_SECS: i64 = 60;
fn reuse_checkpoint(
    cp: &SignedCheckpoint,
    head: Option<(u64, [u8; 32])>,
    now: DateTime<Utc>,
    key_id: &str,
) -> Result<bool> {
    let statement: Value = serde_json::from_str(&cp.statement)?;
    let seq = match &statement["seq"] {
        Value::Null => None,
        Value::String(seq) => Some(seq.parse::<u64>()?),
        _ => anyhow::bail!("invalid checkpoint sequence"),
    };
    ensure!(
        head.map(|h| h.0) >= seq,
        crate::audit_export::action::ExportError::StaleHead
    );
    if head.map(|h| h.0) == seq {
        ensure!(
            statement["head_hash"] == json!(head.map(|h| hex::encode(h.1))),
            crate::audit_export::action::ExportError::InvalidEvidence {
                code: 4,
                detail: "checkpoint head conflict".into()
            }
        );
        ensure!(
            statement["key_id"] == key_id,
            crate::audit_export::action::ExportError::InvalidEvidence {
                code: 5,
                detail: "checkpoint key conflict".into()
            }
        );
        return Ok(true);
    }
    checkpoint_interval(&statement, now)?;
    Ok(false)
}
pub(crate) fn checkpoint_interval(statement: &Value, now: DateTime<Utc>) -> Result<()> {
    let created = DateTime::parse_from_rfc3339(
        statement["created_at"]
            .as_str()
            .context("invalid checkpoint time")?,
    )?;
    let remaining = CHECKPOINT_MIN_INTERVAL_SECS - now.signed_duration_since(created).num_seconds();
    ensure!(
        remaining <= 0,
        crate::audit_export::action::ExportError::CheckpointRateLimited(u64::try_from(remaining)?)
    );
    Ok(())
}
#[cfg(test)]
#[test]
fn fix_checkpoint_reuse_and_interval() {
    let tenant = TenantId::from_jwt_claim(Uuid::new_v4());
    let key = crate::audit_keys::TenantAuditKeypair::generate(tenant.clone()).unwrap();
    let head = Some((3, [7; 32]));
    let cp = sign_checkpoint(&key, &tenant, head, None).unwrap();
    for (head, after, expected) in [
        (head, 0, Some(true)),
        (Some((3, [8; 32])), 0, None),
        (Some((4, [8; 32])), 0, None),
        (Some((4, [8; 32])), 120, Some(false)),
    ] {
        assert_eq!(
            reuse_checkpoint(
                &cp,
                head,
                Utc::now() + chrono::Duration::seconds(after),
                &sha(&key.public_key_bytes())
            )
            .ok(),
            expected
        );
    }
}
#[cfg(test)]
#[test]
fn fix3_checkpoint_never_regresses_or_equivocates() {
    let tenant = TenantId::from_jwt_claim(Uuid::new_v4());
    let key = crate::audit_keys::TenantAuditKeypair::generate(tenant.clone()).unwrap();
    let cp = sign_checkpoint(&key, &tenant, Some((6, [7; 32])), None).unwrap();
    let later = Utc::now() + chrono::Duration::seconds(120);
    for head in [Some((5, [7; 32])), None, Some((6, [8; 32]))] {
        let error = reuse_checkpoint(&cp, head, later, &sha(&key.public_key_bytes())).unwrap_err();
        let response = crate::audit_export::action::refusal(&error);
        assert_eq!(response.status().as_u16(), 503);
        if head.map(|h| h.0) == Some(6) {
            assert!(matches!(
                error.downcast_ref(),
                Some(crate::audit_export::action::ExportError::InvalidEvidence { .. })
            ));
        } else {
            assert_eq!(response.headers()["retry-after"], "1");
        }
    }
}
#[cfg(test)]
#[test]
fn fix3_checkpoint_reuse_requires_current_key() {
    let tenant = TenantId::from_jwt_claim(Uuid::new_v4());
    let key = crate::audit_keys::TenantAuditKeypair::generate(tenant.clone()).unwrap();
    let head = Some((6, [7; 32]));
    let cp = sign_checkpoint(&key, &tenant, head, None).unwrap();
    let error = reuse_checkpoint(&cp, head, Utc::now(), "other-key").unwrap_err();
    assert!(matches!(
        error.downcast_ref(),
        Some(crate::audit_export::action::ExportError::InvalidEvidence { code: 5, .. })
    ));
}
/// On-demand export checkpoint. Key MUST come from this tenant's existing keystore.
/// No network signer/global fallback. Errors fail CLOSED, no unsigned export.
#[tracing::instrument(skip_all)]
pub async fn create_checkpoint(
    pool: &deadpool_postgres::Pool,
    tenant: &TenantId,
    resolved: Option<&crate::entitlement_cache::ResolvedEntitlements>,
    keys: &crate::audit_keys::TenantAuditKeyStore,
) -> Result<SignedCheckpoint> {
    require_enabled(resolved)?;
    let key = keys.get_or_create(tenant).await?;
    let mut c = pool.get().await?;
    let tx = c
        .build_transaction()
        .isolation_level(CHECKPOINT_ISOLATION)
        .start()
        .await?;
    let cp = create_checkpoint_tx(&tx, tenant, resolved, &key).await?;
    tx.commit().await?;
    Ok(cp)
}
/// Compose the existing checkpoint with a caller's export snapshot.
/// Errors fail CLOSED; caller MUST roll back on error and commit before serving bytes.
#[tracing::instrument(skip_all, fields(tenant_id=%tenant))]
pub(crate) async fn create_checkpoint_tx(
    tx: &Transaction<'_>,
    tenant: &TenantId,
    resolved: Option<&crate::entitlement_cache::ResolvedEntitlements>,
    key: &crate::audit_keys::TenantAuditKeypair,
) -> Result<SignedCheckpoint> {
    require_enabled(resolved)?;
    let head = checkpoint_head_tx(tx, tenant).await?;
    checkpoint_for_head_tx(tx, tenant, head, key, None).await
}
#[tracing::instrument(skip_all)]
pub(crate) async fn checkpoint_head_tx(
    tx: &Transaction<'_>,
    tenant: &TenantId,
) -> Result<Option<(u64, [u8; 32])>> {
    let row = tx
        .query_opt(
            "SELECT last_seq,last_row_hash FROM audit_chain_state WHERE tenant_id=$1",
            &[tenant.as_uuid()],
        )
        .await?;
    let head = row
        .map(|r| -> Result<_> {
            let seq: i64 = r.get(0);
            let hash: Vec<u8> = r.get(1);
            Ok((
                u64::try_from(seq)?,
                <[u8; 32]>::try_from(hash.as_slice()).context("invalid checkpoint head")?,
            ))
        })
        .transpose()?;
    Ok(head)
}
/// Separate short transaction only: serialize predecessor/reuse checks and INSERT.
#[tracing::instrument(skip_all)]
pub(crate) async fn checkpoint_for_head_tx(
    tx: &Transaction<'_>,
    tenant: &TenantId,
    head: Option<(u64, [u8; 32])>,
    key: &crate::audit_keys::TenantAuditKeypair,
    heartbeat: Option<std::time::Duration>,
) -> Result<SignedCheckpoint> {
    tx.query_one(
        "SELECT id FROM tenants WHERE id=$1 FOR NO KEY UPDATE",
        &[tenant.as_uuid()],
    )
    .await?;
    let previous = tx.query_opt("SELECT checkpoint_id,statement,signature FROM audit_head_checkpoints WHERE tenant_id=$1 ORDER BY checkpoint_order DESC LIMIT 1", &[tenant.as_uuid()]).await?.map(|r| SignedCheckpoint {id:r.get(0),statement:r.get(1),signature:r.get(2)});
    if let Some(cp) = &previous {
        match reuse_checkpoint(cp, head, Utc::now(), &sha(&key.public_key_bytes())) {
            // AUD-32: a heartbeat re-signs an unchanged head once the last checkpoint is a
            // full period old, so silence between heartbeats is itself signed evidence.
            Ok(true) if !heartbeat.is_some_and(|p| checkpoint_age(cp).is_ok_and(|a| a >= p)) => {
                return Ok(cp.clone());
            }
            Ok(_) => {}
            Err(error) => {
                if matches!(
                    error.downcast_ref(),
                    Some(crate::audit_export::action::ExportError::InvalidEvidence { .. })
                ) {
                    tracing::error!(tenant_id=%tenant, "checkpoint head conflict; refusing mint");
                }
                return Err(error);
            }
        }
    }
    let previous = previous.map(|cp| sha(cp.statement.as_bytes()));
    let cp = sign_checkpoint(key, tenant, head, previous)?;
    tx.execute("INSERT INTO audit_head_checkpoints (tenant_id,checkpoint_id,statement,signature) VALUES ($1,$2,$3,$4)", &[tenant.as_uuid(),&cp.id,&cp.statement,&cp.signature]).await?;
    Ok(cp)
}
/// Tenant-scoped checkpoint lookup. Errors fail CLOSED.
#[tracing::instrument(skip_all)]
pub async fn load_checkpoint(
    pool: &deadpool_postgres::Pool,
    tenant: &TenantId,
    resolved: Option<&crate::entitlement_cache::ResolvedEntitlements>,
    id: Uuid,
) -> Result<Option<SignedCheckpoint>> {
    require_enabled(resolved)?;
    let c = pool.get().await?;
    Ok(c.query_opt("SELECT statement,signature FROM audit_head_checkpoints WHERE tenant_id=$1 AND checkpoint_id=$2", &[tenant.as_uuid(),&id]).await?.map(|r|SignedCheckpoint{id,statement:r.get(0),signature:r.get(1)}))
}
#[cfg(test)]
mod tests;

#[cfg(test)]
mod pg_tests;
