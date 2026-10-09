//! `spend_alert_channels` + `spend_alert_events` — OG-24 (`specs/OG-24-spend-alerts.md`),
//! migration 0061.
//!
//! `spend_alert_events` is the OUTBOX and the dedup at once: one row per (channel, dedup
//! key), `UNIQUE (tenant_id, channel_id, dedup_key)`, inserted `ON CONFLICT DO NOTHING`
//! so a threshold fires at most once per window per channel — across restarts — and the
//! row count is the decision (never a read-then-write). Rows are delivered by the
//! background task (`crate::spend_alerts`) and marked `delivered` only AFTER a 2xx
//! (at-least-once).
//!
//! Secrets (a Slack URL, a webhook signing secret) are stored ONLY as `secret_enc`
//! (AES-256-GCM under the BYOK master key, AAD `spend-alert-channel:<tenant>:<id>`);
//! `target` holds the email address, the webhook URL, or a redacted Slack display.
//!
//! Tenant isolation: every route-facing statement filters `tenant_id = $1` from the
//! validated claim. The delivery claim is cross-tenant by design (one background worker)
//! and never returns a row to a caller.

use anyhow::{Context, Result, anyhow};
use chrono::{DateTime, Utc};
use serde_json::Value;
use tracelane_shared::TenantId;
use uuid::Uuid;

use crate::db::DbPool as Pool;

/// One channel, as the routes list it (`secret_enc` never leaves the gateway).
#[derive(Debug, Clone, PartialEq)]
pub struct Channel {
    pub id: Uuid,
    pub kind: String,
    pub name: String,
    pub target: String,
    pub created_at: DateTime<Utc>,
}

/// A channel to insert. The id is chosen by the caller so the secret's AAD can bind it.
#[derive(Debug, Clone)]
pub struct NewChannel {
    pub id: Uuid,
    pub kind: &'static str,
    pub name: String,
    pub target: String,
    pub secret_enc: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum CreateOutcome {
    Created(Channel),
    LimitReached { max: usize },
}

/// List a tenant's channels.
///
/// # Errors
/// Pool or SELECT failure.
pub async fn list_channels(pool: &Pool, tenant: &TenantId) -> Result<Vec<Channel>> {
    let client = pool.get().await.map_err(|e| anyhow!("pool: {e}"))?;
    let rows = client
        .query(
            "SELECT id, kind, name, target, created_at FROM spend_alert_channels \
             WHERE tenant_id = $1 ORDER BY created_at",
            &[tenant.as_uuid()],
        )
        .await
        .context("SELECT spend_alert_channels failed")?;
    Ok(rows
        .iter()
        .map(|r| Channel {
            id: r.get(0),
            kind: r.get(1),
            name: r.get(2),
            target: r.get(3),
            created_at: r.get(4),
        })
        .collect())
}

/// Create a channel under the per-tenant cap (a per-tenant advisory lock serialises two
/// creates so both cannot pass the count). Records the control change.
///
/// # Errors
/// Fail-CLOSED: any failure rolls back.
pub async fn create_channel(
    pool: &Pool,
    tenant: &TenantId,
    new: &NewChannel,
    max: usize,
    actor: &str,
) -> Result<CreateOutcome> {
    let mut client = pool.get().await.map_err(|e| anyhow!("pool: {e}"))?;
    let tx = client.transaction().await?;
    let t = tenant.as_uuid();
    tx.execute(
        "SELECT pg_advisory_xact_lock(hashtext('spend_alert_channels:' || $1::uuid::text))",
        &[t],
    )
    .await
    .context("spend_alert_channels lock failed")?;
    let n: i64 = tx
        .query_one(
            "SELECT count(*) FROM spend_alert_channels WHERE tenant_id = $1",
            &[t],
        )
        .await
        .context("count spend_alert_channels failed")?
        .get(0);
    if usize::try_from(n).unwrap_or(usize::MAX) >= max {
        return Ok(CreateOutcome::LimitReached { max });
    }
    let row = tx
        .query_one(
            "INSERT INTO spend_alert_channels (id, tenant_id, kind, name, target, secret_enc, created_by) \
             VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING created_at",
            &[
                &new.id,
                t,
                &new.kind,
                &new.name,
                &new.target,
                &new.secret_enc,
                &actor,
            ],
        )
        .await
        .context("INSERT spend_alert_channels failed")?;
    let channel = Channel {
        id: new.id,
        kind: new.kind.to_owned(),
        name: new.name.clone(),
        target: new.target.clone(),
        created_at: row.get(0),
    };
    crate::db::controls::record_control_change(
        &tx,
        &crate::db::controls::ControlChange {
            tenant: *t,
            actor,
            action: "spend_alert_channel.create",
            target_type: "spend_alert_channel",
            target_id: new.id.to_string(),
            before: None,
            // rev5 L4: the trail (readable by every holder of `read_control_audit`)
            // records the webhook's host, never its path or query.
            after: Some(serde_json::json!({
                "kind": channel.kind, "name": channel.name,
                "target": redacted_target(&channel.kind, &channel.target),
            })),
        },
    )
    .await?;
    tx.commit()
        .await
        .context("spend_alert_channels commit failed")?;
    Ok(CreateOutcome::Created(channel))
}

/// rev5 L4: a channel's target as anyone but an admin sees it, and as the control-change
/// trail records it. A webhook URL's path and query can carry a token (and its authority a
/// userinfo), so a `webhook` shows `scheme://host[:port]/…` only; an email address is
/// shown (it is not a credential); a Slack URL is already stored redacted
/// (`alerts::routes::redact_destination_url`). An unparseable webhook target shows `…`.
pub(crate) fn redacted_target(kind: &str, target: &str) -> String {
    if kind != "webhook" {
        return target.to_owned();
    }
    match reqwest::Url::parse(target) {
        Ok(u) => {
            let port = u.port().map(|p| format!(":{p}")).unwrap_or_default();
            format!("{}://{}{port}/…", u.scheme(), u.host_str().unwrap_or(""))
        }
        Err(_) => "…".to_owned(),
    }
}

/// Delete a channel (its pending events cascade). `Ok(false)` = not this tenant's.
///
/// # Errors
/// Fail-CLOSED: any failure rolls back.
pub async fn delete_channel(pool: &Pool, tenant: &TenantId, id: Uuid, actor: &str) -> Result<bool> {
    let mut client = pool.get().await.map_err(|e| anyhow!("pool: {e}"))?;
    let tx = client.transaction().await?;
    let Some(row) = tx
        .query_opt(
            "DELETE FROM spend_alert_channels WHERE tenant_id = $1 AND id = $2 \
             RETURNING kind, name, target",
            &[tenant.as_uuid(), &id],
        )
        .await
        .context("DELETE spend_alert_channels failed")?
    else {
        return Ok(false);
    };
    let (kind, name, target): (String, String, String) = (row.get(0), row.get(1), row.get(2));
    crate::db::controls::record_control_change(
        &tx,
        &crate::db::controls::ControlChange {
            tenant: *tenant.as_uuid(),
            actor,
            action: "spend_alert_channel.delete",
            target_type: "spend_alert_channel",
            target_id: id.to_string(),
            before: Some(serde_json::json!({
                "kind": kind, "name": name,
                "target": redacted_target(&kind, &target),
            })),
            after: None,
        },
    )
    .await?;
    tx.commit()
        .await
        .context("spend_alert_channels delete commit failed")?;
    Ok(true)
}

/// A channel with its sealed secret, for a delivery.
#[derive(Debug, Clone)]
pub struct Sealed {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub kind: String,
    pub target: String,
    pub secret_enc: Option<String>,
}

/// One channel with its secret (the test-fire route), tenant-scoped.
///
/// # Errors
/// Pool or SELECT failure.
pub async fn get_sealed(pool: &Pool, tenant: &TenantId, id: Uuid) -> Result<Option<Sealed>> {
    let client = pool.get().await.map_err(|e| anyhow!("pool: {e}"))?;
    let row = client
        .query_opt(
            "SELECT id, tenant_id, kind, target, secret_enc FROM spend_alert_channels \
             WHERE tenant_id = $1 AND id = $2",
            &[tenant.as_uuid(), &id],
        )
        .await
        .context("SELECT spend_alert_channel failed")?;
    Ok(row.map(|r| Sealed {
        id: r.get(0),
        tenant_id: r.get(1),
        kind: r.get(2),
        target: r.get(3),
        secret_enc: r.get(4),
    }))
}

/// Queue one crossing for every channel of the tenant. Returns the rows inserted (0 =
/// already queued this window, or no channels) — the row count IS the dedup decision.
///
/// # Errors
/// Pool or INSERT failure (the caller retries the crossing later).
pub async fn enqueue(pool: &Pool, tenant: Uuid, dedup_key: &str, payload: &Value) -> Result<u64> {
    let client = pool.get().await.map_err(|e| anyhow!("pool: {e}"))?;
    client
        .execute(
            "INSERT INTO spend_alert_events (tenant_id, channel_id, dedup_key, payload) \
             SELECT $1, c.id, $2, $3 FROM spend_alert_channels c WHERE c.tenant_id = $1 \
             ON CONFLICT (tenant_id, channel_id, dedup_key) DO NOTHING",
            &[&tenant, &dedup_key, payload],
        )
        .await
        .context("INSERT spend_alert_events failed")
}

/// A due delivery.
#[derive(Debug, Clone)]
pub struct Due {
    pub event_id: Uuid,
    pub payload: Value,
    pub attempts: i32,
    pub channel: Sealed,
}

/// Claim up to `limit` due deliveries: their `next_attempt_at` moves `lease_secs` ahead
/// (a crashed worker's claim comes back on its own), `FOR UPDATE SKIP LOCKED` so two
/// claimers never take one row.
///
/// # Errors
/// Pool or UPDATE failure.
pub async fn claim_due(pool: &Pool, limit: i64, lease_secs: i64) -> Result<Vec<Due>> {
    let client = pool.get().await.map_err(|e| anyhow!("pool: {e}"))?;
    let rows = client
        .query(
            "WITH due AS ( \
               SELECT id FROM spend_alert_events \
               WHERE status = 'pending' AND next_attempt_at <= now() \
               ORDER BY created_at LIMIT $1 FOR UPDATE SKIP LOCKED) \
             UPDATE spend_alert_events e \
               SET next_attempt_at = now() + make_interval(secs => $2::double precision) \
             FROM due, spend_alert_channels c \
             WHERE e.id = due.id AND c.id = e.channel_id AND c.tenant_id = e.tenant_id \
             RETURNING e.id, e.payload, e.attempts, c.id, c.tenant_id, c.kind, c.target, c.secret_enc",
            &[&limit, &(lease_secs as f64)],
        )
        .await
        .context("claim spend_alert_events failed")?;
    Ok(rows
        .iter()
        .map(|r| Due {
            event_id: r.get(0),
            payload: r.get(1),
            attempts: r.get(2),
            channel: Sealed {
                id: r.get(3),
                tenant_id: r.get(4),
                kind: r.get(5),
                target: r.get(6),
                secret_enc: r.get(7),
            },
        })
        .collect())
}

/// Record a delivery's outcome: `delivered` after a 2xx; otherwise `attempts + 1`, the
/// error, and either a retry at `retry_in_secs` or `failed` when `give_up`.
///
/// # Errors
/// Pool or UPDATE failure (the claim's lease returns the row to `pending` delivery).
pub async fn record_outcome(
    pool: &Pool,
    event_id: Uuid,
    outcome: Result<(), String>,
    retry_in_secs: i64,
    give_up: bool,
) -> Result<()> {
    let client = pool.get().await.map_err(|e| anyhow!("pool: {e}"))?;
    match outcome {
        Ok(()) => client
            .execute(
                "UPDATE spend_alert_events SET status = 'delivered', delivered_at = now(), \
                 attempts = attempts + 1, last_error = NULL WHERE id = $1",
                &[&event_id],
            )
            .await
            .context("UPDATE spend_alert_events delivered failed")?,
        Err(e) => client
            .execute(
                "UPDATE spend_alert_events SET attempts = attempts + 1, last_error = $2, \
                 status = CASE WHEN $3 THEN 'failed' ELSE 'pending' END, \
                 next_attempt_at = now() + make_interval(secs => $4::double precision) \
                 WHERE id = $1",
                &[&event_id, &e, &give_up, &(retry_in_secs as f64)],
            )
            .await
            .context("UPDATE spend_alert_events failed-attempt failed")?,
    };
    Ok(())
}

/// The tenant's most recent alert deliveries.
///
/// # Errors
/// Pool or SELECT failure.
pub async fn list_events(pool: &Pool, tenant: &TenantId, limit: i64) -> Result<Vec<Value>> {
    let client = pool.get().await.map_err(|e| anyhow!("pool: {e}"))?;
    let rows = client
        .query(
            "SELECT id, channel_id, dedup_key, payload, status, attempts, last_error, \
             created_at, delivered_at FROM spend_alert_events WHERE tenant_id = $1 \
             ORDER BY created_at DESC LIMIT $2",
            &[tenant.as_uuid(), &limit],
        )
        .await
        .context("SELECT spend_alert_events failed")?;
    Ok(rows
        .iter()
        .map(|r| {
            let created: DateTime<Utc> = r.get(7);
            let delivered: Option<DateTime<Utc>> = r.get(8);
            serde_json::json!({
                "id": r.get::<_, Uuid>(0).to_string(),
                "channelId": r.get::<_, Uuid>(1).to_string(),
                "dedupKey": r.get::<_, String>(2),
                "payload": r.get::<_, Value>(3),
                "status": r.get::<_, String>(4),
                "attempts": r.get::<_, i32>(5),
                "lastError": r.get::<_, Option<String>>(6),
                "createdAt": created.to_rfc3339(),
                "deliveredAt": delivered.map(|d| d.to_rfc3339()),
            })
        })
        .collect())
}
