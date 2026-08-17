//! DSH-01 — the tenant's in-app inbox: what happened while nobody was looking.
//!
//! `GET /v1/notifications` · `POST /v1/notifications/{id}/read`.
//!
//! Alerting until now could only leave the building (webhook), so a signal
//! either interrupted someone or was lost. This is the place in the product
//! that answers "what happened while I was away".
//!
//! ## Read state is TENANT-WIDE and the UI says so
//!
//! Not per-user. Per-user read state needs a per-user join for little benefit at
//! this scale, and a half-built per-user feature that silently is not one is
//! worse than a disclosed tenant-wide one.
//!
//! ## `link` is a RELATIVE in-app path
//!
//! Producers write these rows and the dashboard renders them as anchors, so an
//! absolute URL here would be an open redirect with extra steps. Rejected in
//! **both** the gateway and the database (`notifications_link_relative_chk`),
//! including the protocol-relative `//host` form that a naive "starts with /"
//! check lets through.

use anyhow::Result;
use axum::{
    Json, Router,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

use crate::auth::Claims;
use tracelane_shared::TenantId;

/// Closed vocabularies, mirrored by CHECK constraints in migration 0026.
const KINDS: [&str; 3] = ["quota", "alert", "promotion"];
const SEVERITIES: [&str; 3] = ["info", "warning", "critical"];
/// The panel is a catch-up list, not an archive. Bounded so one tenant with a
/// noisy rule cannot make the request unbounded.
const LIST_CAP: i64 = 50;

/// A relative in-app path, or empty.
///
/// **`//host` must be rejected**: it is protocol-relative and leaves the app
/// just as effectively as `https://host`, while satisfying a "starts with `/`"
/// check. That single character is the whole bug.
pub fn is_relative_link(link: &str) -> bool {
    link.is_empty() || (link.starts_with('/') && !link.starts_with("//"))
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Notification {
    pub id: String,
    pub kind: String,
    pub title: String,
    pub body: String,
    pub severity: String,
    pub link: String,
    /// `None` = unread.
    pub read_at: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct NotificationList {
    pub notifications: Vec<Notification>,
    pub unread: i64,
    /// Echoed so the UI can say "showing the latest N" honestly.
    pub cap: i64,
}

#[async_trait::async_trait]
pub trait NotificationStore: Send + Sync {
    async fn list(&self, tenant: &TenantId) -> Result<(Vec<Notification>, i64)>;
    /// Returns whether a row was actually marked.
    async fn mark_read(&self, tenant: &TenantId, id: Uuid) -> Result<bool>;
}

pub struct PgNotificationStore {
    pub pool: deadpool_postgres::Pool,
}

#[async_trait::async_trait]
impl NotificationStore for PgNotificationStore {
    async fn list(&self, tenant: &TenantId) -> Result<(Vec<Notification>, i64)> {
        let c = self
            .pool
            .get()
            .await
            .map_err(|e| anyhow::anyhow!("pool: {e}"))?;
        let rows = c
            .query(
                "SELECT id::text, kind, title, body, severity, link,
                        read_at::text, created_at::text
                   FROM notifications
                  WHERE tenant_id = $1
                  ORDER BY created_at DESC
                  LIMIT $2",
                &[tenant.as_uuid(), &LIST_CAP],
            )
            .await?;
        // Counted separately and NOT from the capped page: the badge must say
        // how many are unread, not how many unread happen to be on this page.
        let unread: i64 = c
            .query_one(
                "SELECT count(*) FROM notifications
                  WHERE tenant_id = $1 AND read_at IS NULL",
                &[tenant.as_uuid()],
            )
            .await?
            .get(0);
        Ok((
            rows.iter()
                .map(|r| Notification {
                    id: r.get(0),
                    kind: r.get(1),
                    title: r.get(2),
                    body: r.get(3),
                    severity: r.get(4),
                    link: r.get(5),
                    read_at: r.get(6),
                    created_at: r.get(7),
                })
                .collect(),
            unread,
        ))
    }

    async fn mark_read(&self, tenant: &TenantId, id: Uuid) -> Result<bool> {
        let c = self
            .pool
            .get()
            .await
            .map_err(|e| anyhow::anyhow!("pool: {e}"))?;
        // `tenant_id` in the predicate, not just the id: without it a guessed
        // UUID would mark another tenant's row.
        let n = c
            .execute(
                "UPDATE notifications SET read_at = now()
                  WHERE tenant_id = $1 AND id = $2 AND read_at IS NULL",
                &[tenant.as_uuid(), &id],
            )
            .await?;
        Ok(n > 0)
    }
}

/// Write one notification. **Producer-facing**, called from the alert checker
/// and (later) the quota and promotion paths.
///
/// Fails OPEN by design and says so: a producer must never be taken down by the
/// inbox. A failure here is logged once with the reason — never swallowed —
/// because an inbox that silently stops filling looks exactly like a quiet week.
pub async fn notify(
    pool: &deadpool_postgres::Pool,
    tenant: Uuid,
    kind: &str,
    title: &str,
    body: &str,
    severity: &str,
    link: &str,
) {
    if !KINDS.contains(&kind) || !SEVERITIES.contains(&severity) || !is_relative_link(link) {
        tracing::error!(
            kind,
            severity,
            link,
            "refusing to write a malformed notification"
        );
        return;
    }
    let res = async {
        let c = pool.get().await.map_err(|e| anyhow::anyhow!("pool: {e}"))?;
        c.execute(
            "INSERT INTO notifications (tenant_id, kind, title, body, severity, link)
             VALUES ($1, $2, $3, $4, $5, $6)",
            &[&tenant, &kind, &title, &body, &severity, &link],
        )
        .await
        .map_err(anyhow::Error::from)
    }
    .await;
    if let Err(e) = res {
        tracing::warn!(error = %e, kind, "notification write failed — the event still fired");
    }
}

#[derive(Clone)]
pub struct NotificationRoutesState {
    pub store: Arc<dyn NotificationStore>,
}

pub fn routes() -> Router<NotificationRoutesState> {
    Router::new()
        .route("/v1/notifications", get(list_handler))
        .route("/v1/notifications/{id}/read", post(read_handler))
}

async fn claims_from_auth(headers: &HeaderMap) -> Result<Claims, (StatusCode, String)> {
    let h = headers.get("authorization").ok_or((
        StatusCode::UNAUTHORIZED,
        "missing Authorization header".to_string(),
    ))?;
    let s = h.to_str().map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            "Authorization must be ASCII".to_string(),
        )
    })?;
    crate::auth::validate_authorization(s)
        .await
        .map_err(|e| (StatusCode::UNAUTHORIZED, format!("auth failed: {e}")))
}

#[tracing::instrument(skip_all, fields(tenant_id = tracing::field::Empty))]
async fn list_handler(
    State(state): State<NotificationRoutesState>,
    headers: HeaderMap,
) -> Result<Json<NotificationList>, (StatusCode, String)> {
    let claims = claims_from_auth(&headers).await?;
    tracing::Span::current().record("tenant_id", claims.tenant_id.to_string());
    // Every role may read the inbox, viewers included — it is catch-up, not
    // configuration.
    let (notifications, unread) = state.store.list(&claims.tenant_id).await.map_err(|e| {
        tracing::error!(error = %e, "notification list failed");
        (
            StatusCode::BAD_GATEWAY,
            "notification read failed".to_string(),
        )
    })?;
    Ok(Json(NotificationList {
        notifications,
        unread,
        cap: LIST_CAP,
    }))
}

#[tracing::instrument(skip_all, fields(tenant_id = tracing::field::Empty))]
async fn read_handler(
    State(state): State<NotificationRoutesState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<StatusCode, (StatusCode, String)> {
    let claims = claims_from_auth(&headers).await?;
    tracing::Span::current().record("tenant_id", claims.tenant_id.to_string());
    let uuid = Uuid::parse_str(&id).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            "invalid notification id".to_string(),
        )
    })?;
    let marked = state
        .store
        .mark_read(&claims.tenant_id, uuid)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "notification mark-read failed");
            (
                StatusCode::BAD_GATEWAY,
                "notification write failed".to_string(),
            )
        })?;
    // 404 covers BOTH "no such id" and "already read" and "another tenant's" —
    // deliberately one answer, so the endpoint cannot confirm that a foreign id
    // exists.
    Ok(if marked {
        StatusCode::NO_CONTENT
    } else {
        StatusCode::NOT_FOUND
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The single character that separates an in-app link from an open redirect.
    #[test]
    fn protocol_relative_link_is_rejected() {
        assert!(is_relative_link("/slo"));
        assert!(is_relative_link("/billing?tab=usage"));
        assert!(is_relative_link(""), "empty = not linkable, allowed");
        assert!(
            !is_relative_link("//evil.example"),
            "protocol-relative escapes the app"
        );
        assert!(!is_relative_link("https://evil.example"));
        assert!(!is_relative_link("http://evil.example"));
        assert!(!is_relative_link("javascript:alert(1)"));
        assert!(!is_relative_link("slo"), "bare relative is not an app path");
    }

    #[test]
    fn vocabularies_are_closed() {
        for k in KINDS {
            assert!(KINDS.contains(&k));
        }
        assert!(!KINDS.contains(&"gossip"));
        assert!(!SEVERITIES.contains(&"apocalyptic"));
    }

    /// The cap must travel to the client, so the panel can say "showing the
    /// latest N" instead of implying it has everything.
    ///
    /// (The previous version of this test asserted `LIST_CAP == 50` and
    /// `LIST_CAP > 0` — a constant compared with itself, which clippy correctly
    /// called out as a constant-value assertion. It proved nothing and was
    /// deleted rather than silenced.)
    #[test]
    fn the_cap_is_carried_in_the_response_not_just_in_the_query() {
        let list = NotificationList {
            notifications: vec![],
            unread: 3,
            cap: LIST_CAP,
        };
        let json = serde_json::to_value(&list).expect("serialises");
        assert_eq!(json["cap"], serde_json::json!(LIST_CAP));
        assert_eq!(json["unread"], serde_json::json!(3));
    }
}
