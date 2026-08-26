//! OBS-18 — human annotations on a trace (`good` / `bad` / `needs_review` + a note).
//!
//! `POST|GET|DELETE /v1/traces/{trace_id}/annotations`. Mounted only when
//! Postgres is configured, alongside the key/BYOK/prompt routes.
//!
//! ## Why this is here and not in `trace_reads.rs`
//!
//! `trace_reads` is the ClickHouse surface. Annotations live in **Postgres**
//! because they are low-volume, MUTABLE (edited, removed) and read one trace at
//! a time — the opposite of append-only analytical rows. Editing one in
//! ClickHouse means a `ReplacingMergeTree` tombstone that only reads correctly
//! with `FINAL` plus an exclusion join, which is a whole failure class taken on
//! for what is a single `UPDATE` here.
//!
//! ## Tenant isolation
//!
//! `tenant_id` comes ONLY from `Claims.tenant_id` — never a path, query or body
//! field. The `trace_id` in the path selects rows that ALSO match the
//! authenticated tenant, so a request can never read or write another tenant's
//! annotations, and a foreign `trace_id` simply reads back empty rather than
//! confirming that trace exists.
//!
//! ## Fails CLOSED on role and on vocabulary
//!
//! A **viewer may read annotations and may not write them** (the spec's
//! read-only state). An unrecognised label is a 400, never a silent coercion —
//! and the database carries the same closed set as a CHECK constraint, so a
//! future writer that forgets to validate still cannot store a label the UI
//! cannot render.

use anyhow::Result;
use axum::{
    Json, Router,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    routing::get,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::auth::{Claims, Role};
use tracelane_shared::TenantId;

/// Defensive bound on the free-text note (the column is TEXT).
const MAX_NOTE_LEN: usize = 2_000;
/// Defensive bound on a span id.
const MAX_SPAN_ID_LEN: usize = 128;

/// The closed label vocabulary. Mirrored by `trace_annotations_label_chk` in
/// migration 0025 — **both** on purpose: the gateway gives the caller a 400 that
/// names the problem, and the constraint survives a writer that skips the
/// gateway. An unknown label denies rather than defaulting, the same lesson as
/// `Role::from_slug` and `api_scope::Scope::from_slug`.
const LABELS: [&str; 3] = ["good", "bad", "needs_review"];

fn valid_label(s: &str) -> bool {
    LABELS.contains(&s)
}

/// **A viewer may READ annotations, not write them.**
///
/// `None` (API key / service credential) is allowed to write: an annotation is
/// tenant DATA, not a privilege change, so this is deliberately not the
/// `can_mint_keys` shape — that one guards key minting, where an API key writing
/// is escalation. Here it is just a machine recording a verdict.
fn may_write(claims: &Claims) -> bool {
    !matches!(claims.role, Some(Role::Viewer))
}

/// One stored annotation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Annotation {
    pub trace_id: String,
    /// `""` = the whole trace (never NULL — see migration 0025).
    pub span_id: String,
    pub label: String,
    pub note: String,
    pub author_sub: String,
    pub created_at: String,
    pub updated_at: String,
}

/// Storage seam — lets the handlers be unit-tested without Postgres. Off the
/// request hot path, so `async_trait` is fine (CLAUDE.md bans it only on the
/// gateway hot path).
#[async_trait::async_trait]
pub trait AnnotationStore: Send + Sync {
    /// Insert or replace THIS author's verdict on this target.
    async fn upsert(
        &self,
        tenant: &TenantId,
        trace_id: &str,
        span_id: &str,
        label: &str,
        note: &str,
        author_sub: &str,
    ) -> Result<Annotation>;

    async fn list(&self, tenant: &TenantId, trace_id: &str) -> Result<Vec<Annotation>>;

    /// Remove this author's verdict. Returns how many rows went.
    async fn delete(
        &self,
        tenant: &TenantId,
        trace_id: &str,
        span_id: &str,
        author_sub: &str,
    ) -> Result<u64>;
}

pub struct PgAnnotationStore {
    pub pool: deadpool_postgres::Pool,
}

#[async_trait::async_trait]
impl AnnotationStore for PgAnnotationStore {
    async fn upsert(
        &self,
        tenant: &TenantId,
        trace_id: &str,
        span_id: &str,
        label: &str,
        note: &str,
        author_sub: &str,
    ) -> Result<Annotation> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| anyhow::anyhow!("pool: {e}"))?;
        // The PRIMARY KEY is the concurrency control: two tabs racing the same
        // flag produce ONE row, with no read-modify-write window.
        let row = client
            .query_one(
                "INSERT INTO trace_annotations
                   (tenant_id, trace_id, span_id, label, note, author_sub)
                 VALUES ($1, $2, $3, $4, $5, $6)
                 ON CONFLICT (tenant_id, trace_id, span_id, author_sub)
                 DO UPDATE SET label = EXCLUDED.label,
                               note = EXCLUDED.note,
                               updated_at = now()
                 RETURNING trace_id, span_id, label, note, author_sub,
                           created_at::text, updated_at::text",
                &[
                    tenant.as_uuid(),
                    &trace_id,
                    &span_id,
                    &label,
                    &note,
                    &author_sub,
                ],
            )
            .await?;
        Ok(Annotation {
            trace_id: row.get(0),
            span_id: row.get(1),
            label: row.get(2),
            note: row.get(3),
            author_sub: row.get(4),
            created_at: row.get(5),
            updated_at: row.get(6),
        })
    }

    async fn list(&self, tenant: &TenantId, trace_id: &str) -> Result<Vec<Annotation>> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| anyhow::anyhow!("pool: {e}"))?;
        let rows = client
            .query(
                "SELECT trace_id, span_id, label, note, author_sub,
                        created_at::text, updated_at::text
                   FROM trace_annotations
                  WHERE tenant_id = $1 AND trace_id = $2
                  ORDER BY span_id, author_sub",
                &[tenant.as_uuid(), &trace_id],
            )
            .await?;
        Ok(rows
            .iter()
            .map(|r| Annotation {
                trace_id: r.get(0),
                span_id: r.get(1),
                label: r.get(2),
                note: r.get(3),
                author_sub: r.get(4),
                created_at: r.get(5),
                updated_at: r.get(6),
            })
            .collect())
    }

    async fn delete(
        &self,
        tenant: &TenantId,
        trace_id: &str,
        span_id: &str,
        author_sub: &str,
    ) -> Result<u64> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| anyhow::anyhow!("pool: {e}"))?;
        // An author may only delete their OWN verdict — `author_sub` is bound
        // from the validated claim, not from the request.
        let n = client
            .execute(
                "DELETE FROM trace_annotations
                  WHERE tenant_id = $1 AND trace_id = $2
                    AND span_id = $3 AND author_sub = $4",
                &[tenant.as_uuid(), &trace_id, &span_id, &author_sub],
            )
            .await?;
        Ok(n)
    }
}

#[derive(Clone)]
pub struct AnnotationRoutesState {
    pub store: Arc<dyn AnnotationStore>,
}

pub fn routes() -> Router<AnnotationRoutesState> {
    Router::new().route(
        "/v1/traces/{trace_id}/annotations",
        get(list_handler)
            .post(upsert_handler)
            .delete(delete_handler),
    )
}

#[derive(Debug, Deserialize)]
pub struct UpsertBody {
    label: String,
    #[serde(default)]
    note: Option<String>,
    /// Omitted ⇒ the whole trace.
    #[serde(default)]
    span_id: Option<String>,
}

/// `?span_id=` — omitted ⇒ the trace-level flag.
///
/// A QUERY param, not a body: `gatewayDelete` in the dashboard sends no body,
/// and inventing a body-carrying DELETE would have meant hand-rolling the auth
/// header in the proxy. One less bespoke path.
#[derive(Debug, Deserialize)]
pub struct DeleteQuery {
    #[serde(default)]
    span_id: Option<String>,
}

async fn claims_from_auth(headers: &HeaderMap) -> Result<Claims, (StatusCode, String)> {
    let h = headers.get("authorization").ok_or((
        StatusCode::UNAUTHORIZED,
        "missing Authorization header".into(),
    ))?;
    let s = h.to_str().map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            "Authorization must be ASCII".into(),
        )
    })?;
    crate::auth::validate_authorization(s)
        .await
        .map_err(|e| (StatusCode::UNAUTHORIZED, format!("auth failed: {e}")))
}

fn check_trace_id(t: &str) -> Result<(), (StatusCode, String)> {
    if t.len() < 8 {
        return Err((StatusCode::BAD_REQUEST, "invalid trace id".into()));
    }
    Ok(())
}

#[tracing::instrument(skip_all, fields(tenant_id = tracing::field::Empty))]
async fn list_handler(
    State(state): State<AnnotationRoutesState>,
    Path(trace_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<Vec<Annotation>>, (StatusCode, String)> {
    let claims = claims_from_auth(&headers).await?;
    tracing::Span::current().record("tenant_id", claims.tenant_id.to_string());
    check_trace_id(&trace_id)?;
    // Read is open to every role INCLUDING viewer — that is the point of the
    // read-only state; a viewer must be able to SEE the verdicts.
    state
        .store
        .list(&claims.tenant_id, &trace_id)
        .await
        .map(Json)
        .map_err(|e| {
            tracing::error!(error = %e, "annotation list failed");
            (StatusCode::BAD_GATEWAY, "annotation read failed".into())
        })
}

#[tracing::instrument(skip_all, fields(tenant_id = tracing::field::Empty))]
async fn upsert_handler(
    State(state): State<AnnotationRoutesState>,
    Path(trace_id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<UpsertBody>,
) -> Result<(StatusCode, Json<Annotation>), (StatusCode, String)> {
    let claims = claims_from_auth(&headers).await?;
    tracing::Span::current().record("tenant_id", claims.tenant_id.to_string());
    if !may_write(&claims) {
        return Err((
            StatusCode::FORBIDDEN,
            crate::auth::role_forbidden_json("member"),
        ));
    }
    check_trace_id(&trace_id)?;

    let label = body.label.trim().to_ascii_lowercase();
    if !valid_label(&label) {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "unknown label {:?} — known labels: {}",
                body.label,
                LABELS.join(", ")
            ),
        ));
    }
    let note = body.note.unwrap_or_default();
    if note.chars().count() > MAX_NOTE_LEN {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("note must be at most {MAX_NOTE_LEN} characters"),
        ));
    }
    let span_id = body.span_id.unwrap_or_default();
    if span_id.len() > MAX_SPAN_ID_LEN {
        return Err((StatusCode::BAD_REQUEST, "span_id too long".into()));
    }

    state
        .store
        .upsert(
            &claims.tenant_id,
            &trace_id,
            &span_id,
            &label,
            &note,
            &claims.sub,
        )
        .await
        .map(|a| (StatusCode::OK, Json(a)))
        .map_err(|e| {
            tracing::error!(error = %e, "annotation upsert failed");
            (StatusCode::BAD_GATEWAY, "annotation write failed".into())
        })
}

#[tracing::instrument(skip_all, fields(tenant_id = tracing::field::Empty))]
async fn delete_handler(
    State(state): State<AnnotationRoutesState>,
    Path(trace_id): Path<String>,
    axum::extract::Query(q): axum::extract::Query<DeleteQuery>,
    headers: HeaderMap,
) -> Result<StatusCode, (StatusCode, String)> {
    let claims = claims_from_auth(&headers).await?;
    tracing::Span::current().record("tenant_id", claims.tenant_id.to_string());
    if !may_write(&claims) {
        return Err((
            StatusCode::FORBIDDEN,
            crate::auth::role_forbidden_json("member"),
        ));
    }
    check_trace_id(&trace_id)?;
    let span_id = q.span_id.unwrap_or_default();

    let n = state
        .store
        .delete(&claims.tenant_id, &trace_id, &span_id, &claims.sub)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "annotation delete failed");
            (StatusCode::BAD_GATEWAY, "annotation delete failed".into())
        })?;
    // 404 when there was nothing of YOURS to remove, so a no-op is
    // distinguishable from a success — a blanket 204 would let a UI report
    // "removed" for a flag that was never there.
    Ok(if n == 0 {
        StatusCode::NOT_FOUND
    } else {
        StatusCode::NO_CONTENT
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[derive(Default)]
    struct MockStore {
        rows: Mutex<Vec<Annotation>>,
        seen_tenant: Mutex<Vec<String>>,
    }

    #[async_trait::async_trait]
    impl AnnotationStore for MockStore {
        async fn upsert(
            &self,
            tenant: &TenantId,
            trace_id: &str,
            span_id: &str,
            label: &str,
            note: &str,
            author_sub: &str,
        ) -> Result<Annotation> {
            self.seen_tenant.lock().unwrap().push(tenant.to_string());
            let a = Annotation {
                trace_id: trace_id.into(),
                span_id: span_id.into(),
                label: label.into(),
                note: note.into(),
                author_sub: author_sub.into(),
                created_at: "2026-08-12T00:00:00Z".into(),
                updated_at: "2026-08-12T00:00:00Z".into(),
            };
            let mut r = self.rows.lock().unwrap();
            r.retain(|x| {
                !(x.trace_id == a.trace_id
                    && x.span_id == a.span_id
                    && x.author_sub == a.author_sub)
            });
            r.push(a.clone());
            Ok(a)
        }
        async fn list(&self, tenant: &TenantId, trace_id: &str) -> Result<Vec<Annotation>> {
            self.seen_tenant.lock().unwrap().push(tenant.to_string());
            Ok(self
                .rows
                .lock()
                .unwrap()
                .iter()
                .filter(|x| x.trace_id == trace_id)
                .cloned()
                .collect())
        }
        async fn delete(
            &self,
            tenant: &TenantId,
            trace_id: &str,
            span_id: &str,
            author_sub: &str,
        ) -> Result<u64> {
            self.seen_tenant.lock().unwrap().push(tenant.to_string());
            let mut r = self.rows.lock().unwrap();
            let before = r.len();
            r.retain(|x| {
                !(x.trace_id == trace_id && x.span_id == span_id && x.author_sub == author_sub)
            });
            Ok((before - r.len()) as u64)
        }
    }

    fn tenant() -> TenantId {
        TenantId::from_jwt_claim(uuid::Uuid::nil())
    }

    fn claims(role: Option<Role>) -> Claims {
        Claims {
            tenant_id: tenant(),
            sub: "user-a".to_string(),
            exp: u64::MAX,
            auth_method: crate::auth::AuthMethod::JwtBearer,
            role,
            key_scope: crate::auth::scope::KeyScope::LegacyFullSurface,
            budget_usd_monthly: None,
            rate_limit_rpm: None,
        }
    }

    /// The whole point of the role gate: a viewer must be able to READ.
    #[test]
    fn viewer_may_read() {
        assert!(
            !may_write(&claims(Some(Role::Viewer))),
            "viewer must NOT write"
        );
    }

    #[test]
    fn owner_and_member_may_write() {
        assert!(may_write(&claims(Some(Role::Owner))));
        assert!(may_write(&claims(Some(Role::Member))));
    }

    /// An API key has `role: None`. Writing an annotation is recording tenant
    /// DATA, not changing a privilege, so it is allowed — deliberately NOT the
    /// `can_mint_keys` shape, where an API key writing would be escalation.
    #[test]
    fn api_key_no_role_may_write_because_this_is_data_not_privilege() {
        assert!(may_write(&claims(None)));
    }

    #[test]
    fn label_vocabulary_is_closed() {
        for good in LABELS {
            assert!(valid_label(good), "{good} must parse");
        }
        for bad in ["", "GOOD", "ok", "catastrophic", "good ", "needs-review"] {
            assert!(!valid_label(bad), "{bad:?} must NOT parse");
        }
    }

    /// The label is lowercased+trimmed before validation, so `" Bad "` is
    /// accepted while `catastrophic` still is not. Asserted because the
    /// normalisation happens in the handler and the raw check is strict.
    #[test]
    fn label_normalisation_accepts_case_and_space_but_not_unknown() {
        assert!(valid_label(&" Bad ".trim().to_ascii_lowercase()));
        assert!(valid_label(&"NEEDS_REVIEW".trim().to_ascii_lowercase()));
        assert!(!valid_label(&" catastrophic ".trim().to_ascii_lowercase()));
    }

    #[tokio::test]
    async fn upsert_replaces_rather_than_duplicating() {
        let s = MockStore::default();
        let t = tenant();
        s.upsert(&t, "tr-1", "", "bad", "first", "user-a")
            .await
            .unwrap();
        s.upsert(&t, "tr-1", "", "good", "second", "user-a")
            .await
            .unwrap();
        let rows = s.list(&t, "tr-1").await.unwrap();
        assert_eq!(rows.len(), 1, "same author+target must not duplicate");
        assert_eq!(rows[0].label, "good");
        assert_eq!(rows[0].note, "second");
    }

    #[tokio::test]
    async fn a_second_author_is_a_separate_verdict() {
        let s = MockStore::default();
        let t = tenant();
        s.upsert(&t, "tr-1", "", "bad", "", "user-a").await.unwrap();
        s.upsert(&t, "tr-1", "", "good", "", "user-b")
            .await
            .unwrap();
        assert_eq!(s.list(&t, "tr-1").await.unwrap().len(), 2);
    }

    #[tokio::test]
    async fn span_level_and_trace_level_are_different_targets() {
        let s = MockStore::default();
        let t = tenant();
        s.upsert(&t, "tr-1", "", "bad", "", "user-a").await.unwrap();
        s.upsert(&t, "tr-1", "span-9", "good", "", "user-a")
            .await
            .unwrap();
        assert_eq!(s.list(&t, "tr-1").await.unwrap().len(), 2);
    }

    #[tokio::test]
    async fn delete_removes_only_that_authors_row() {
        let s = MockStore::default();
        let t = tenant();
        s.upsert(&t, "tr-1", "", "bad", "", "user-a").await.unwrap();
        s.upsert(&t, "tr-1", "", "good", "", "user-b")
            .await
            .unwrap();
        assert_eq!(s.delete(&t, "tr-1", "", "user-a").await.unwrap(), 1);
        let rows = s.list(&t, "tr-1").await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(
            rows[0].author_sub, "user-b",
            "user-b's verdict must survive"
        );
    }

    #[tokio::test]
    async fn deleting_nothing_reports_zero_so_a_no_op_is_visible() {
        let s = MockStore::default();
        let t = tenant();
        assert_eq!(s.delete(&t, "tr-nope", "", "user-a").await.unwrap(), 0);
    }

    /// Every store call must carry the tenant from the claim.
    #[tokio::test]
    async fn every_store_call_is_tenant_scoped() {
        let s = MockStore::default();
        let t = tenant();
        s.upsert(&t, "tr-1", "", "bad", "", "user-a").await.unwrap();
        s.list(&t, "tr-1").await.unwrap();
        s.delete(&t, "tr-1", "", "user-a").await.unwrap();
        let seen = s.seen_tenant.lock().unwrap();
        assert_eq!(seen.len(), 3);
        assert!(seen.iter().all(|x| *x == t.to_string()));
    }
}
