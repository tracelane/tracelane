//! Durable single-use approvals. Every transition is conditional and audited atomically.
pub(crate) mod protected;
use crate::{
    admission::ControlDenial,
    auth::Claims,
    db::{
        DbPool,
        control_audit::{self, Actor, Change},
    },
    server::AppState,
};
use anyhow::Result;
use chrono::{DateTime, Utc};
use serde_json::{Value, json};
use std::{collections::HashMap, sync::OnceLock, time::Duration};
use tracelane_shared::TenantId;
use uuid::Uuid;

pub struct Request<'a> {
    pub kind: &'static str,
    pub server: Option<Uuid>,
    pub subject: &'a str,
    pub rule: Option<Uuid>,
    pub ttl_secs: i32,
    pub body: &'a Value,
    pub trace_id: Uuid,
}
#[derive(Debug)]
struct Approval {
    id: Uuid,
    status: String,
    expires_at: DateTime<Utc>,
    decided_by: Option<String>,
}
fn denial(code: &'static str) -> ControlDenial {
    ControlDenial {
        status: 403,
        code,
        message: code.replace('_', " "),
        detail: vec![],
        retry_after_secs: None,
    }
}
fn unavailable() -> ControlDenial {
    let mut d = denial("approval_unavailable");
    d.status = 503;
    d
}

/// Full-width, purpose-separated keyed digest. An observation fingerprint is not a grant.
fn fingerprint(claims: &Claims, request: &Request<'_>) -> Result<String> {
    use secrecy::ExposeSecret;
    let key = crate::tool_fingerprint::workspace_key(&claims.tenant_id)
        .ok_or_else(|| anyhow::anyhow!("approval key unavailable"))?;
    let mut canonical = json!({"purpose":"approval-v1","requester":claims.sub,"kind":request.kind,"server":request.server,"subject":request.subject,"rule":request.rule,"body":request.body});
    canonical.sort_all_objects();
    Ok(
        blake3::keyed_hash(key.expose_secret(), canonical.to_string().as_bytes())
            .to_hex()
            .to_string(),
    )
}
async fn audit(
    tx: &tokio_postgres::Transaction<'_>,
    tenant: &TenantId,
    actor: &Actor,
    id: Uuid,
    action: &str,
    before: Option<&str>,
    after: &str,
) -> Result<()> {
    control_audit::record(
        tx,
        tenant,
        actor,
        Change {
            action,
            target_type: "approval",
            target_id: id.to_string(),
            before: before.map(|s| json!({"status":s})),
            after: Some(json!({"status":after})),
        },
    )
    .await?;
    Ok(())
}
#[derive(Debug, thiserror::Error)]
#[error("approval capacity")]
struct Capacity;

async fn find_or_create(
    pool: &DbPool,
    claims: &Claims,
    request: &Request<'_>,
    preview: Option<String>,
) -> Result<Approval> {
    let fp = fingerprint(claims, request)?;
    let mut client = pool.get().await?;
    let tx = client.transaction().await?;
    // Serialize creation per workspace so the cap and identical-request reuse are atomic.
    tx.query_one(
        "SELECT id FROM tenants WHERE id=$1 FOR UPDATE",
        &[claims.tenant_id.as_uuid()],
    )
    .await?;
    let expired = tx.query(
        "UPDATE approvals SET status='expired' WHERE action_id IS NULL AND tenant_id=$1 AND requester_sub=$2 AND args_fp=$3 AND ((status='pending' AND expires_at<=clock_timestamp()) OR (status='approved' AND grant_expires_at<=clock_timestamp())) RETURNING id",
        &[claims.tenant_id.as_uuid(), &claims.sub, &fp],
    ).await?;
    for row in expired {
        audit(
            &tx,
            &claims.tenant_id,
            &Actor::system(&claims.sub),
            row.get(0),
            "approval.expire",
            None,
            "expired",
        )
        .await?;
    }
    if let Some(row) = tx.query_opt(
        "SELECT id,status,expires_at,decided_by FROM approvals WHERE action_id IS NULL AND tenant_id=$1 AND requester_sub=$2 AND args_fp=$3 AND status IN ('pending','approved')",
        &[claims.tenant_id.as_uuid(), &claims.sub, &fp],
    ).await? {
        let result = approval_row(&row);
        tx.commit().await?;
        return Ok(result);
    }
    let count: i64 = tx.query_one("SELECT count(*) FROM approvals WHERE tenant_id=$1 AND status='pending' AND expires_at>clock_timestamp()", &[claims.tenant_id.as_uuid()]).await?.get(0);
    if count
        >= i64::try_from(
            crate::mcp_policy::settings()?
                .approvals
                .max_pending_per_workspace,
        )?
    {
        return Err(Capacity.into());
    }
    let key = claims.api_key_id().and_then(|s| Uuid::parse_str(s).ok());
    let creator = if let Some(key) = key {
        tx.query_opt(
            "SELECT minted_by FROM api_keys WHERE tenant_id=$1 AND id=$2",
            &[claims.tenant_id.as_uuid(), &key],
        )
        .await?
        .and_then(|r| r.get::<_, Option<String>>(0))
    } else {
        Some(claims.sub.clone())
    };
    let bytes = i64::try_from(request.body.to_string().len())?;
    let inserted=tx.query_opt("INSERT INTO approvals (tenant_id,subject_kind,server_id,subject,key_id,requester_sub,requester_creator,args_fp,args_bytes,rule_id,expires_at,trace_id,args_preview) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,clock_timestamp()+make_interval(secs=>$11::double precision),$12,$13) ON CONFLICT(tenant_id,requester_sub,args_fp) WHERE status IN ('pending','approved') DO NOTHING RETURNING id",&[claims.tenant_id.as_uuid(),&request.kind,&request.server,&request.subject,&key,&claims.sub,&creator,&fp,&bytes,&request.rule,&f64::from(request.ttl_secs),&request.trace_id,&preview]).await?;
    if let Some(row) = inserted {
        let id: Uuid = row.get(0);
        audit(
            &tx,
            &claims.tenant_id,
            &Actor::system(&claims.sub),
            id,
            "approval.request",
            None,
            "pending",
        )
        .await?;
        crate::db::spend_alerts::enqueue_with(&*tx,*claims.tenant_id.as_uuid(),&format!("approval:{id}"),&json!({"type":"approval.requested","approval_id":id,"subject":request.subject,"subject_kind":request.kind,"queue_path":"/settings/gateway/approvals"})).await?;
    }
    let row=tx.query_one("SELECT id,status,expires_at,decided_by FROM approvals WHERE action_id IS NULL AND tenant_id=$1 AND requester_sub=$2 AND args_fp=$3 AND status IN ('pending','approved')",&[claims.tenant_id.as_uuid(),&claims.sub,&fp]).await?;
    let result = approval_row(&row);
    tx.commit().await?;
    Ok(result)
}
fn approval_row(row: &tokio_postgres::Row) -> Approval {
    Approval {
        id: row.get(0),
        status: row.get(1),
        expires_at: row.get(2),
        decided_by: row.get(3),
    }
}

/// Conditional UPDATE is the grant. A concurrent request losing it cannot execute.
async fn consume(pool: &DbPool, claims: &Claims, id: Uuid) -> Result<Option<String>> {
    let mut client = pool.get().await?;
    let tx = client.transaction().await?;
    // PostgreSQL can evaluate an UPDATE predicate before waiting for its row lock.
    // Acquire that lock first so wall-clock grant expiry is checked after the wait.
    tx.query_opt("SELECT id FROM approvals WHERE action_id IS NULL AND tenant_id=$1 AND id=$2 AND requester_sub=$3 FOR UPDATE",
        &[claims.tenant_id.as_uuid(), &id, &claims.sub]).await?;
    let row=tx.query_opt("UPDATE approvals SET status='consumed', consumed_at=clock_timestamp() WHERE action_id IS NULL AND tenant_id=$1 AND id=$2 AND requester_sub=$3 AND status='approved' AND consumed_at IS NULL AND grant_expires_at>clock_timestamp() RETURNING decided_by",&[claims.tenant_id.as_uuid(),&id,&claims.sub]).await?;
    let Some(row) = row else { return Ok(None) };
    audit(
        &tx,
        &claims.tenant_id,
        &Actor::system(&claims.sub),
        id,
        "approval.consume",
        Some("approved"),
        "consumed",
    )
    .await?;
    let by = row
        .get::<_, Option<String>>(0)
        .ok_or_else(|| anyhow::anyhow!("approval has no approver"))?;
    tx.commit().await?;
    Ok(Some(by))
}
#[derive(Default)]
struct Holds {
    tenants: HashMap<Uuid, usize>,
    signals: HashMap<Uuid, Vec<tokio::sync::watch::Sender<()>>>,
    total: usize,
}
fn holds() -> &'static parking_lot::Mutex<Holds> {
    static H: OnceLock<parking_lot::Mutex<Holds>> = OnceLock::new();
    H.get_or_init(Default::default)
}
struct Hold {
    tenant: Uuid,
    id: Uuid,
    receiver: tokio::sync::watch::Receiver<()>,
    sender: tokio::sync::watch::Sender<()>,
}
impl Drop for Hold {
    fn drop(&mut self) {
        let mut h = holds().lock();
        h.total -= 1;
        if let Some(n) = h.tenants.get_mut(&self.tenant) {
            *n -= 1;
            if *n == 0 {
                h.tenants.remove(&self.tenant);
            }
        }
        if let Some(s) = h.signals.get_mut(&self.id) {
            // The receiver is still alive during Drop; remove this exact channel.
            s.retain(|s| !s.same_channel(&self.sender));
            if s.is_empty() {
                h.signals.remove(&self.id);
            }
        }
    }
}
pub fn held_now(tenant: Uuid) -> usize {
    holds().lock().tenants.get(&tenant).copied().unwrap_or(0)
}
pub fn wake(id: Uuid) {
    if let Some(s) = holds().lock().signals.get(&id) {
        for s in s {
            let _ = s.send(());
        }
    }
}
fn hold(tenant: Uuid, id: Uuid) -> Result<Hold, ControlDenial> {
    let limits = crate::mcp_policy::settings().map_err(|_| unavailable())?;
    let mut h = holds().lock();
    if h.total >= limits.approvals.max_held_total
        || h.tenants.get(&tenant).copied().unwrap_or(0) >= limits.approvals.max_held_per_workspace
    {
        let mut d = denial("approval_capacity");
        d.status = 429;
        d.retry_after_secs = Some(limits.approvals.capacity_retry_secs);
        return Err(d);
    }
    h.total += 1;
    *h.tenants.entry(tenant).or_default() += 1;
    let (sender, receiver) = tokio::sync::watch::channel(());
    h.signals.entry(id).or_default().push(sender.clone());
    Ok(Hold {
        tenant,
        id,
        receiver,
        sender,
    })
}
async fn read(pool: &DbPool, tenant: &TenantId, id: Uuid) -> Result<Approval> {
    let client = pool.get().await?;
    let r=client.query_one("SELECT id,CASE WHEN status='pending' AND expires_at<=now() THEN 'expired' WHEN status='approved' AND grant_expires_at<=now() THEN 'expired' ELSE status END,expires_at,decided_by FROM approvals WHERE action_id IS NULL AND tenant_id=$1 AND id=$2",&[tenant.as_uuid(),&id]).await?;
    Ok(Approval {
        id: r.get(0),
        status: r.get(1),
        expires_at: r.get(2),
        decided_by: r.get(3),
    })
}
/// Security path: only a successfully consumed approved row returns an approver.
pub async fn gate(
    state: &AppState,
    claims: &Claims,
    request: Request<'_>,
    supplied: Option<&str>,
    headers: &axum::http::HeaderMap,
    expected: Option<&std::sync::Arc<crate::entitlement_cache::ResolvedEntitlements>>,
) -> Result<String, ControlDenial> {
    let pool = state.pg.as_ref().ok_or_else(unavailable)?;
    let capture = crate::server::config::capture_decision(
        crate::server::config::trace_content(),
        expected.map(|e| e.content_capture),
        &claims.tenant_id,
        claims.key_capture,
        Some(headers),
    );
    let preview = capture.input.then(|| {
        let mut text = request
            .body
            .get("params")
            .and_then(|p| p.get("arguments"))
            .unwrap_or(request.body)
            .to_string();
        crate::server::store_safe(
            &mut text,
            crate::mcp_policy::settings().map_or(0, |l| l.approvals.preview_max_bytes),
        );
        text
    });
    let mut row = if let Some(supplied) = supplied {
        // A selector is a read/consume request, never permission to create a replacement.
        let id = Uuid::parse_str(supplied).map_err(|_| denial("approval_mismatch"))?;
        let fp = fingerprint(claims, &request).map_err(|_| unavailable())?;
        let client = pool.get().await.map_err(|_| unavailable())?;
        let row = client.query_opt(
            "SELECT id,CASE WHEN (status='pending' AND expires_at<=clock_timestamp()) OR (status='approved' AND (grant_expires_at IS NULL OR grant_expires_at<=clock_timestamp())) THEN 'expired' ELSE status END,expires_at,decided_by FROM approvals WHERE action_id IS NULL AND tenant_id=$1 AND requester_sub=$2 AND args_fp=$3 AND id=$4",
            &[claims.tenant_id.as_uuid(), &claims.sub, &fp, &id],
        ).await.map_err(|_| unavailable())?.ok_or_else(|| denial("approval_mismatch"))?;
        approval_row(&row)
    } else {
        find_or_create(pool, claims, &request, preview)
            .await
            .map_err(|e| {
                if e.is::<Capacity>() {
                    let mut refusal = denial("approval_capacity");
                    refusal.status = 429;
                    refusal.retry_after_secs = crate::mcp_policy::settings()
                        .ok()
                        .map(|l| l.approvals.capacity_retry_secs);
                    refusal
                } else {
                    unavailable()
                }
            })?
    };
    if request.kind == "tool" && row.status == "pending" && row.expires_at > Utc::now() {
        let mut slot = hold(*claims.tenant_id.as_uuid(), row.id)?;
        row = read(pool, &claims.tenant_id, row.id)
            .await
            .map_err(|_| unavailable())?;
        if row.status == "pending" {
            let duration = Duration::from_secs(
                crate::mcp_policy::settings()
                    .map_err(|_| unavailable())?
                    .approvals
                    .hold_secs,
            );
            let _ = tokio::time::timeout(duration, slot.receiver.changed()).await;
            row = read(pool, &claims.tenant_id, row.id)
                .await
                .map_err(|_| unavailable())?;
        }
    }
    if row.status == "approved" && row.decided_by.is_some() {
        // Holds may outlive a scope edit. Refresh only on grant consumption, by
        // the already-authenticated identity (native wires need no Bearer header).
        if let Some(key) = claims.api_key_id() {
            let key = Uuid::parse_str(key).map_err(|_| unavailable())?;
            let client = pool.get().await.map_err(|_| unavailable())?;
            let row = client.query_opt("SELECT scope FROM api_keys WHERE tenant_id=$1 AND id=$2 AND (revoked_at IS NULL OR revoked_at>clock_timestamp()) AND (expires_at IS NULL OR expires_at>clock_timestamp())",
                &[claims.tenant_id.as_uuid(), &key]).await.map_err(|_| unavailable())?
                .ok_or_else(|| denial("approval_caller_changed"))?;
            let scopes: Option<Vec<String>> = row.get(0);
            if crate::auth::scope::KeyScope::from_column(scopes.as_deref()) != claims.key_scope {
                return Err(denial("approval_caller_changed"));
            }
        }
        crate::mcp_policy::ensure_fresh(state, headers, claims, expected)
            .await
            .map_err(|r| match r {
                crate::admission::Refusal::Control(d) => d,
                _ => unavailable(),
            })?;
        return consume(pool, claims, row.id)
            .await
            .map_err(|_| unavailable())?
            .ok_or_else(|| denial("approval_consumed"));
    }
    let code = match row.status.as_str() {
        "pending" if row.expires_at > Utc::now() => "approval_required",
        "denied" => "approval_denied",
        "consumed" => "approval_consumed",
        _ => "approval_expired",
    };
    let mut d = denial(code);
    d.detail = vec![
        ("approval_id", json!(row.id)),
        ("status", json!(row.status)),
        ("expires_at", json!(row.expires_at)),
    ];
    Err(d)
}

/// Sweep bounded batches; a failure rolls back and never grants a request.
pub async fn expire(
    pool: &DbPool,
    chain: Option<&std::sync::Arc<crate::audit::AuditChain>>,
) -> Result<usize> {
    let limit = i64::try_from(crate::mcp_policy::settings()?.approvals.sweep_batch)?;
    let mut client = pool.get().await?;
    let tx = client.transaction().await?;
    let rows=tx.query("SELECT tenant_id,id,status,action_id FROM approvals WHERE (status='pending' AND expires_at<=now()) OR (status='approved' AND CASE WHEN action_id IS NULL THEN grant_expires_at ELSE expires_at END<=now()) ORDER BY expires_at LIMIT $1 FOR UPDATE SKIP LOCKED",&[&limit]).await?;
    let mut copies = Vec::new();
    for r in &rows {
        let tenant = TenantId::from_jwt_claim(r.get(0));
        let id: Uuid = r.get(1);
        let previous: String = r.get(2);
        if r.get::<_, Option<Uuid>>(3).is_some() {
            // Canonical evidence rolls back with the batch; copies wait for commit.
            let batch = protected::expire_tx(&tx, &tenant, id)
                .await?
                .ok_or_else(|| anyhow::anyhow!("approval_expired"))?;
            copies.push((tenant.clone(), batch));
        } else {
            tx.execute(
                "UPDATE approvals SET status='expired' WHERE tenant_id=$1 AND id=$2 AND status IN ('pending','approved')",
                &[tenant.as_uuid(), &id],
            ).await?;
        }
        audit(
            &tx,
            &tenant,
            &Actor::system("approval-expiry"),
            id,
            "approval.expire",
            Some(&previous),
            "expired",
        )
        .await?;
    }
    tx.commit().await?;
    let timeout = Duration::from_secs(crate::mcp_policy::settings()?.limits.call_timeout_secs);
    for (tenant, batch) in copies {
        crate::action_control::execution::after_commit_for_tenant(
            chain,
            &tenant,
            vec![batch],
            timeout,
        );
    }
    for r in &rows {
        // Protected grants are polled; expiry must never resume an agent call.
        if r.get::<_, Option<Uuid>>(3).is_none() {
            wake(r.get(1));
        }
    }
    Ok(rows.len())
}
pub fn spawn_sweeper(pool: DbPool, chain: std::sync::Arc<crate::audit::AuditChain>) {
    tokio::spawn(async move {
        let Ok(l) = crate::mcp_policy::settings() else {
            return;
        };
        let mut tick = tokio::time::interval(Duration::from_secs(l.approvals.sweep_secs));
        loop {
            tick.tick().await;
            if expire(&pool, Some(&chain)).await.is_err() {
                tracing::warn!(
                    event = "approval_expiry_failed",
                    "Approval expiry batch rolled back"
                );
            }
        }
    });
}

#[cfg(test)]
mod capacity_tests {
    use super::*;
    #[test]
    fn mcp_approval_hold_capacity_and_disconnect_cleanup() {
        let tenant = Uuid::new_v4();
        let max = crate::mcp_policy::settings()
            .unwrap()
            .approvals
            .max_held_per_workspace;
        let mut pending = Vec::new();
        for _ in 0..max {
            pending.push(hold(tenant, Uuid::new_v4()).unwrap());
        }
        assert_eq!(held_now(tenant), max);
        let refusal = hold(tenant, Uuid::new_v4()).err().expect("workspace bound");
        assert_eq!(refusal.code, "approval_capacity");
        assert_eq!(refusal.status, 429);
        drop(pending.pop());
        let replacement = hold(tenant, Uuid::new_v4()).unwrap();
        drop(pending);
        drop(replacement);
        assert_eq!(held_now(tenant), 0);
    }
}

#[cfg(all(test, debug_assertions))]
#[path = "approvals_fix_tests.rs"]
mod fix_tests;

#[cfg(test)]
mod expiry_sql_tests {
    #[test]
    fn past_expiry_protected_grants_are_swept() {
        let result = std::process::Command::new("python3")
            .arg(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/src/approvals/expiry_sql_tests.py"
            ))
            .output()
            .expect("Python stdlib SQL regression harness");
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
    }
}
