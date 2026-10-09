//! `otel_exports` — OG-50 (`specs/OG-50-otel-export.md`), migration 0076.
//!
//! A workspace's OTLP/HTTP export destinations. The customer's header values (an API key
//! for their collector) are stored ONLY as `headers_enc`: a JSON object sealed with
//! AES-256-GCM under the gateway's BYOK master key, AAD `otel-export:<tenant>:<id>` (see
//! [`aad`]) — the same envelope as a provider key. `header_names` carries the NAMES for
//! display; no statement here ever returns the sealed blob to a route handler.
//!
//! Every write records ONE control change through `record_control_change` in the SAME
//! transaction (fail-CLOSED). Tenant isolation: every route-facing statement filters
//! `tenant_id = $1` from the validated claim; [`directory`] and [`flush_status`] are the
//! background worker's, cross-tenant by design, and never return a row to a caller.
//!
//! Self-contained on purpose (`tests/postgres_tenant_integration.rs` mounts this tree by
//! `#[path]`): nothing here reaches a gateway module outside `db`.

use anyhow::{Context, Result, anyhow};
use chrono::{DateTime, Utc};
use serde_json::json;
use tracelane_shared::TenantId;
use uuid::Uuid;

use crate::db::DbPool as Pool;

/// The AAD binding a sealed header map to its row: a blob copied into another export (or
/// another tenant's) fails the GCM tag.
#[must_use]
pub fn aad(tenant: Uuid, id: Uuid) -> Vec<u8> {
    format!("otel-export:{tenant}:{id}").into_bytes()
}

/// One export as a route lists it. **No sealed blob, no header value** — names only.
#[derive(Debug, Clone, PartialEq)]
pub struct Export {
    pub id: Uuid,
    pub name: String,
    pub url: String,
    pub header_names: Vec<String>,
    pub enabled: bool,
    pub include_content: bool,
    pub sample_ratio: f64,
    pub only_errors: bool,
    pub status: String,
    pub last_success_at: Option<DateTime<Utc>>,
    pub last_error_class: Option<String>,
    pub delivered: i64,
    pub dropped: i64,
    pub failed: i64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

const COLUMNS: &str = "id, name, url, header_names, enabled, include_content, sample_ratio, \
     only_errors, status, last_success_at, last_error_class, delivered, dropped, failed, \
     created_at, updated_at";

fn from_row(r: &tokio_postgres::Row) -> Export {
    Export {
        id: r.get(0),
        name: r.get(1),
        url: r.get(2),
        header_names: r.get(3),
        enabled: r.get(4),
        include_content: r.get(5),
        sample_ratio: r.get(6),
        only_errors: r.get(7),
        status: r.get(8),
        last_success_at: r.get(9),
        last_error_class: r.get(10),
        delivered: r.get(11),
        dropped: r.get(12),
        failed: r.get(13),
        created_at: r.get(14),
        updated_at: r.get(15),
    }
}

/// The audit-safe view of an export: the URL as host + path (a query or userinfo can carry
/// a token) and header NAMES — never a value.
#[must_use]
pub fn audit_view(e: &Export) -> serde_json::Value {
    json!({
        "name": e.name,
        "url": redacted_url(&e.url),
        "header_names": e.header_names,
        "enabled": e.enabled,
        "include_content": e.include_content,
        "sample_ratio": e.sample_ratio,
        "only_errors": e.only_errors,
    })
}

/// `scheme://host[:port]/path` — no userinfo, no query, no fragment. Unparseable → `…`.
#[must_use]
pub fn redacted_url(raw: &str) -> String {
    match reqwest::Url::parse(raw) {
        Ok(u) => {
            let port = u.port().map(|p| format!(":{p}")).unwrap_or_default();
            format!(
                "{}://{}{port}{}",
                u.scheme(),
                u.host_str().unwrap_or(""),
                u.path()
            )
        }
        Err(_) => "…".to_owned(),
    }
}

/// The tenant's exports, oldest first.
///
/// # Errors
/// Pool or SELECT failure.
pub async fn list(pool: &Pool, tenant: &TenantId) -> Result<Vec<Export>> {
    let client = pool.get().await.map_err(|e| anyhow!("pool: {e}"))?;
    let rows = client
        .query(
            &format!(
                "SELECT {COLUMNS} FROM otel_exports WHERE tenant_id = $1 ORDER BY created_at, id"
            ),
            &[tenant.as_uuid()],
        )
        .await
        .context("SELECT otel_exports failed")?;
    Ok(rows.iter().map(from_row).collect())
}

/// An export to insert. The id is chosen by the caller so the sealed headers' AAD can bind it.
#[derive(Debug, Clone)]
pub struct NewExport {
    pub id: Uuid,
    pub name: String,
    pub url: String,
    pub headers_enc: Option<String>,
    pub header_names: Vec<String>,
    pub include_content: bool,
    pub sample_ratio: f64,
    pub only_errors: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub enum CreateOutcome {
    Created(Export),
    LimitReached { max: usize },
}

/// Create an export under the plan's cap (a per-tenant advisory lock serialises two creates so
/// both cannot pass the count). Records `otel_export.create`.
///
/// # Errors
/// Fail-CLOSED: any failure rolls back.
pub async fn create(
    pool: &Pool,
    tenant: &TenantId,
    new: &NewExport,
    max: usize,
    actor: &str,
) -> Result<CreateOutcome> {
    let mut client = pool.get().await.map_err(|e| anyhow!("pool: {e}"))?;
    let tx = client.transaction().await?;
    let t = tenant.as_uuid();
    tx.execute(
        "SELECT pg_advisory_xact_lock(hashtext('otel_exports:' || $1::uuid::text))",
        &[t],
    )
    .await
    .context("otel_exports lock failed")?;
    let n: i64 = tx
        .query_one(
            "SELECT count(*) FROM otel_exports WHERE tenant_id = $1",
            &[t],
        )
        .await
        .context("count otel_exports failed")?
        .get(0);
    if usize::try_from(n).unwrap_or(usize::MAX) >= max {
        return Ok(CreateOutcome::LimitReached { max });
    }
    let row = tx
        .query_one(
            &format!(
                "INSERT INTO otel_exports (id, tenant_id, name, url, headers_enc, header_names, \
                   include_content, sample_ratio, only_errors, created_by) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING {COLUMNS}"
            ),
            &[
                &new.id,
                t,
                &new.name,
                &new.url,
                &new.headers_enc,
                &new.header_names,
                &new.include_content,
                &new.sample_ratio,
                &new.only_errors,
                &actor,
            ],
        )
        .await
        .context("INSERT otel_exports failed")?;
    let export = from_row(&row);
    crate::db::controls::record_control_change(
        &tx,
        &crate::db::controls::ControlChange {
            tenant: *t,
            actor,
            action: "otel_export.create",
            target_type: "otel_export",
            target_id: new.id.to_string(),
            before: None,
            after: Some(audit_view(&export)),
        },
    )
    .await?;
    tx.commit()
        .await
        .context("otel_exports create commit failed")?;
    Ok(CreateOutcome::Created(export))
}

/// A validated merge patch. Absent = unchanged. `headers` replaces BOTH the sealed map and
/// the names.
#[derive(Debug, Clone, Default)]
pub struct Patch {
    pub enabled: Option<bool>,
    pub include_content: Option<bool>,
    pub sample_ratio: Option<f64>,
    pub only_errors: Option<bool>,
    /// `Some((sealed, names))` replaces the headers; `Some((None, []))` clears them.
    pub headers: Option<(Option<String>, Vec<String>)>,
}

/// Apply a patch under the row lock and record `otel_export.update` (the audit row carries
/// the CHANGED fields, header NAMES only). `Ok(None)` = not this tenant's export.
///
/// # Errors
/// Fail-CLOSED: any failure rolls back.
pub async fn update(
    pool: &Pool,
    tenant: &TenantId,
    id: Uuid,
    patch: &Patch,
    actor: &str,
) -> Result<Option<Export>> {
    let mut client = pool.get().await.map_err(|e| anyhow!("pool: {e}"))?;
    let tx = client.transaction().await?;
    let t = tenant.as_uuid();
    let Some(row) = tx
        .query_opt(
            &format!(
                "SELECT {COLUMNS} FROM otel_exports WHERE tenant_id = $1 AND id = $2 FOR UPDATE"
            ),
            &[t, &id],
        )
        .await
        .context("SELECT otel_exports FOR UPDATE failed")?
    else {
        return Ok(None);
    };
    let before = from_row(&row);
    let enabled = patch.enabled.unwrap_or(before.enabled);
    let include_content = patch.include_content.unwrap_or(before.include_content);
    let sample_ratio = patch.sample_ratio.unwrap_or(before.sample_ratio);
    let only_errors = patch.only_errors.unwrap_or(before.only_errors);
    let (set_headers, headers_enc, header_names) = match &patch.headers {
        Some((enc, names)) => (true, enc.clone(), names.clone()),
        None => (false, None, Vec::new()),
    };
    let updated = from_row(
        &tx.query_one(
            &format!(
                "UPDATE otel_exports SET enabled = $3, include_content = $4, sample_ratio = $5, \
                   only_errors = $6, \
                   headers_enc = CASE WHEN $7 THEN $8::text ELSE headers_enc END, \
                   header_names = CASE WHEN $7 THEN $9::text[] ELSE header_names END, \
                   updated_at = now() \
                 WHERE tenant_id = $1 AND id = $2 RETURNING {COLUMNS}"
            ),
            &[
                t,
                &id,
                &enabled,
                &include_content,
                &sample_ratio,
                &only_errors,
                &set_headers,
                &headers_enc,
                &header_names,
            ],
        )
        .await
        .context("UPDATE otel_exports failed")?,
    );
    crate::db::controls::record_control_change(
        &tx,
        &crate::db::controls::ControlChange {
            tenant: *t,
            actor,
            action: "otel_export.update",
            target_type: "otel_export",
            target_id: id.to_string(),
            before: Some(audit_view(&before)),
            after: Some(audit_view(&updated)),
        },
    )
    .await?;
    tx.commit()
        .await
        .context("otel_exports update commit failed")?;
    Ok(Some(updated))
}

/// Delete an export. Records `otel_export.delete`. `Ok(false)` = not this tenant's.
///
/// # Errors
/// Fail-CLOSED: any failure rolls back.
pub async fn delete(pool: &Pool, tenant: &TenantId, id: Uuid, actor: &str) -> Result<bool> {
    let mut client = pool.get().await.map_err(|e| anyhow!("pool: {e}"))?;
    let tx = client.transaction().await?;
    let t = tenant.as_uuid();
    let Some(row) = tx
        .query_opt(
            &format!(
                "DELETE FROM otel_exports WHERE tenant_id = $1 AND id = $2 RETURNING {COLUMNS}"
            ),
            &[t, &id],
        )
        .await
        .context("DELETE otel_exports failed")?
    else {
        return Ok(false);
    };
    crate::db::controls::record_control_change(
        &tx,
        &crate::db::controls::ControlChange {
            tenant: *t,
            actor,
            action: "otel_export.delete",
            target_type: "otel_export",
            target_id: id.to_string(),
            before: Some(audit_view(&from_row(&row))),
            after: None,
        },
    )
    .await?;
    tx.commit()
        .await
        .context("otel_exports delete commit failed")?;
    Ok(true)
}

/// One export with its sealed headers, for a delivery.
#[derive(Debug, Clone)]
pub struct Sealed {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub url: String,
    pub headers_enc: Option<String>,
    pub enabled: bool,
    pub include_content: bool,
    pub sample_ratio: f64,
    pub only_errors: bool,
    pub updated_at: DateTime<Utc>,
}

const SEALED_COLUMNS: &str = "id, tenant_id, url, headers_enc, enabled, include_content, \
     sample_ratio, only_errors, updated_at";

fn sealed_from_row(r: &tokio_postgres::Row) -> Sealed {
    Sealed {
        id: r.get(0),
        tenant_id: r.get(1),
        url: r.get(2),
        headers_enc: r.get(3),
        enabled: r.get(4),
        include_content: r.get(5),
        sample_ratio: r.get(6),
        only_errors: r.get(7),
        updated_at: r.get(8),
    }
}

/// One of the tenant's exports with its sealed headers (the test-delivery route).
///
/// # Errors
/// Pool or SELECT failure.
pub async fn get_sealed(pool: &Pool, tenant: &TenantId, id: Uuid) -> Result<Option<Sealed>> {
    let client = pool.get().await.map_err(|e| anyhow!("pool: {e}"))?;
    Ok(client
        .query_opt(
            &format!("SELECT {SEALED_COLUMNS} FROM otel_exports WHERE tenant_id = $1 AND id = $2"),
            &[tenant.as_uuid(), &id],
        )
        .await
        .context("SELECT otel_exports (sealed) failed")?
        .map(|r| sealed_from_row(&r)))
}

/// Every ENABLED export of every tenant, with sealed headers — the background directory's
/// read. Cross-tenant by design (one worker serves them all); it returns nothing to a caller.
///
/// # Errors
/// Pool or SELECT failure (the directory keeps its previous contents).
pub async fn directory(pool: &Pool) -> Result<Vec<Sealed>> {
    let client = pool.get().await.map_err(|e| anyhow!("pool: {e}"))?;
    let rows = client
        .query(
            &format!(
                "SELECT {SEALED_COLUMNS} FROM otel_exports WHERE enabled ORDER BY tenant_id, id"
            ),
            &[],
        )
        .await
        .context("SELECT otel_exports (directory) failed")?;
    Ok(rows.iter().map(sealed_from_row).collect())
}

/// One export's in-process counters and status, to flush to its row.
#[derive(Debug, Clone)]
pub struct StatusUpdate {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub status: &'static str,
    pub last_success_at: Option<DateTime<Utc>>,
    pub last_error_class: Option<String>,
    pub delivered: i64,
    pub dropped: i64,
    pub failed: i64,
}

/// Flush counters and status for the given exports — ONE background writer, never per batch.
/// `last_success_at` only ever moves forward.
///
/// # Errors
/// Pool failure or the first failing UPDATE (the writer retries on its next tick).
pub async fn flush_status(pool: &Pool, updates: &[StatusUpdate]) -> Result<()> {
    if updates.is_empty() {
        return Ok(());
    }
    let client = pool.get().await.map_err(|e| anyhow!("pool: {e}"))?;
    for u in updates {
        client
            .execute(
                "UPDATE otel_exports SET status = $3, \
                   last_success_at = GREATEST(last_success_at, $4), \
                   last_error_class = $5, delivered = $6, dropped = $7, failed = $8 \
                 WHERE id = $1 AND tenant_id = $2",
                &[
                    &u.id,
                    &u.tenant_id,
                    &u.status,
                    &u.last_success_at,
                    &u.last_error_class,
                    &u.delivered,
                    &u.dropped,
                    &u.failed,
                ],
            )
            .await
            .context("UPDATE otel_exports status failed")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn og50_the_aad_binds_tenant_and_row() {
        let (t, i) = (Uuid::new_v4(), Uuid::new_v4());
        assert_eq!(aad(t, i), format!("otel-export:{t}:{i}").into_bytes());
        assert_ne!(aad(t, i), aad(Uuid::new_v4(), i), "another tenant");
        assert_ne!(aad(t, i), aad(t, Uuid::new_v4()), "another export");
    }

    #[test]
    fn og50_a_url_is_shown_as_host_and_path_only() {
        assert_eq!(
            redacted_url("https://user:pw@otel.example.com:4318/v1/traces?token=SECRET#frag"),
            "https://otel.example.com:4318/v1/traces"
        );
        assert_eq!(redacted_url("not a url"), "…");
        let e = Export {
            id: Uuid::new_v4(),
            name: "n".into(),
            url: "https://c.example.com/v1/traces?key=abc".into(),
            header_names: vec!["authorization".into()],
            enabled: true,
            include_content: false,
            sample_ratio: 1.0,
            only_errors: false,
            status: "ok".into(),
            last_success_at: None,
            last_error_class: None,
            delivered: 0,
            dropped: 0,
            failed: 0,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        let text = audit_view(&e).to_string();
        assert!(!text.contains("abc") && !text.contains("key="), "{text}");
        assert!(text.contains("authorization"), "names are fine");
    }
}
