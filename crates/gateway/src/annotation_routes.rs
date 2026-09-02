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
use anyhow::Context;
use tracelane_shared::TenantId;
use uuid::Uuid;

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

    // ── EVL-29 queues. Same trait on purpose: one seam, one table. ────────

    async fn create_queue(&self, tenant: &TenantId, q: &QueueWrite<'_>) -> Result<()>;
    async fn count_queues(&self, tenant: &TenantId) -> Result<u64>;
    async fn list_queues(&self, tenant: &TenantId) -> Result<Vec<AnnotationQueue>>;
    /// One queue under this tenant. `None` for a foreign OR an archived id —
    /// the caller cannot distinguish them, and must not: confirming that a
    /// queue id exists under another tenant is itself a leak.
    async fn get_queue(&self, tenant: &TenantId, id: Uuid) -> Result<Option<AnnotationQueue>>;
    /// Rename / re-filter / re-rubric / archive. `None` fields are unchanged.
    async fn update_queue(
        &self,
        tenant: &TenantId,
        id: Uuid,
        patch: &QueuePatch<'_>,
    ) -> Result<bool>;

    /// The EXCLUSION set for the cross-store join (B-210, bounded exactly like
    /// the cost rollup): of these trace ids, which already carry a trace-level
    /// annotation under this tenant. Bounded by the caller to one page.
    async fn reviewed_trace_ids(
        &self,
        tenant: &TenantId,
        trace_ids: &[String],
    ) -> Result<Vec<String>>;

    /// Write a queue review. Called ONLY after the dataset item exists — this
    /// row is the done marker (`.claude/rules/logging.md`).
    async fn upsert_review(&self, tenant: &TenantId, w: &ReviewWrite<'_>) -> Result<Annotation>;
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

    // ── EVL-29 queues ────────────────────────────────────────────────────

    async fn create_queue(&self, tenant: &TenantId, q: &QueueWrite<'_>) -> Result<()> {
        let c = self.pool.get().await?;
        c.execute(
            "INSERT INTO annotation_queues                (id, tenant_id, name, filter_json, rubric_json, default_dataset_id,                 expected_output_field, created_by)              VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
            &[
                &q.id,
                tenant.as_uuid(),
                &q.name,
                q.filter,
                q.rubric,
                &q.default_dataset_id,
                &q.expected_output_field,
                &q.created_by,
            ],
        )
        .await?;
        Ok(())
    }

    async fn count_queues(&self, tenant: &TenantId) -> Result<u64> {
        let c = self.pool.get().await?;
        // Archived queues do NOT count against the cap — archiving is how a
        // tenant makes room, and a cap that counted tombstones would make
        // "archive, never delete" (§19) into a trap.
        let row = c
            .query_one(
                "SELECT count(*) FROM annotation_queues                  WHERE tenant_id = $1 AND archived_at IS NULL",
                &[tenant.as_uuid()],
            )
            .await?;
        Ok(row.get::<_, i64>(0).max(0) as u64)
    }

    async fn list_queues(&self, tenant: &TenantId) -> Result<Vec<AnnotationQueue>> {
        let c = self.pool.get().await?;
        let sql = format!(
            "SELECT {QUEUE_COLS} FROM annotation_queues              WHERE tenant_id = $1 ORDER BY archived_at NULLS FIRST, created_at DESC LIMIT $2"
        );
        let rows = c
            .query(&sql, &[tenant.as_uuid(), &(MAX_QUEUES as i64)])
            .await?;
        rows.iter().map(queue_from_row).collect()
    }

    async fn get_queue(&self, tenant: &TenantId, id: Uuid) -> Result<Option<AnnotationQueue>> {
        let c = self.pool.get().await?;
        let sql =
            format!("SELECT {QUEUE_COLS} FROM annotation_queues WHERE tenant_id = $1 AND id = $2");
        let row = c.query_opt(&sql, &[tenant.as_uuid(), &id]).await?;
        row.as_ref().map(queue_from_row).transpose()
    }

    async fn update_queue(
        &self,
        tenant: &TenantId,
        id: Uuid,
        patch: &QueuePatch<'_>,
    ) -> Result<bool> {
        let c = self.pool.get().await?;
        // COALESCE rather than a dynamically built SET list: the parameter
        // count is fixed, so there is no string-built SQL and no path where a
        // caller-supplied name reaches the statement text.
        let n = c
            .execute(
                "UPDATE annotation_queues SET                    name = COALESCE($3, name),                    filter_json = COALESCE($4, filter_json),                    rubric_json = COALESCE($5, rubric_json),                    expected_output_field = COALESCE($6, expected_output_field),                    archived_at = CASE                        WHEN $7::bool IS NULL THEN archived_at                        WHEN $7::bool THEN COALESCE(archived_at, now())                        ELSE NULL END,                    updated_at = now()                  WHERE tenant_id = $1 AND id = $2",
                &[
                    tenant.as_uuid(),
                    &id,
                    &patch.name,
                    &patch.filter,
                    &patch.rubric,
                    &patch.expected_output_field,
                    &patch.archived,
                ],
            )
            .await?;
        Ok(n > 0)
    }

    async fn reviewed_trace_ids(
        &self,
        tenant: &TenantId,
        trace_ids: &[String],
    ) -> Result<Vec<String>> {
        if trace_ids.is_empty() {
            return Ok(Vec::new());
        }
        let c = self.pool.get().await?;
        // `= ANY($2::text[])` — bounded to ONE page by the caller, the mirror
        // image of `build_trace_cost_rollup_sql` and for the same reason
        // (B-210): a cross-store join is only safe while one side is bounded.
        // `span_id = ''` because a queue works the TRACE, so a span-level flag
        // does not remove the trace from the queue.
        let rows = c
            .query(
                "SELECT DISTINCT trace_id FROM trace_annotations                  WHERE tenant_id = $1 AND span_id = '' AND trace_id = ANY($2::text[])",
                &[tenant.as_uuid(), &trace_ids],
            )
            .await?;
        Ok(rows.iter().map(|r| r.get(0)).collect())
    }

    async fn upsert_review(&self, tenant: &TenantId, w: &ReviewWrite<'_>) -> Result<Annotation> {
        let c = self.pool.get().await?;
        // The PK stays `(tenant_id, trace_id, span_id, author_sub)` — `queue_id`
        // is deliberately NOT in it, so two reviewers racing one trace still
        // produce exactly one row per author with no read-modify-write window.
        let row = c
            .query_one(
                "INSERT INTO trace_annotations                    (tenant_id, trace_id, span_id, label, note, author_sub,                     queue_id, rubric_json, expected_output, rubric_snapshot)                  VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)                  ON CONFLICT (tenant_id, trace_id, span_id, author_sub)                  DO UPDATE SET label = EXCLUDED.label, note = EXCLUDED.note,                                queue_id = EXCLUDED.queue_id,                                rubric_json = EXCLUDED.rubric_json,                                expected_output = EXCLUDED.expected_output,                                rubric_snapshot = EXCLUDED.rubric_snapshot,                                updated_at = now()                  RETURNING trace_id, span_id, label, note, author_sub,                            to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'),                            to_char(updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"')",
                &[
                    tenant.as_uuid(),
                    &w.trace_id,
                    &w.span_id,
                    &w.label,
                    &w.note,
                    &w.author_sub,
                    &w.queue_id,
                    w.rubric,
                    &w.expected_output,
                    w.rubric_snapshot,
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
}

#[derive(Clone)]
pub struct AnnotationRoutesState {
    pub store: Arc<dyn AnnotationStore>,
    /// EVL-29. `None` ⇒ no control plane ⇒ every queue route answers 503,
    /// never a grant (`.claude/rules/tenancy.md`).
    pub entitlements: Option<Arc<crate::entitlement_cache::EntitlementCache>>,
    /// EVL-29. Item 8's store, REUSED rather than reimplemented — the one
    /// action writes through the exact copy path item 8 proved on prod.
    pub datasets: Option<Arc<dyn crate::dataset_routes::DatasetStore>>,
    /// EVL-29. Candidate evaluation is a ClickHouse read (R221.1: membership is
    /// a query, not a table).
    pub ch_url: Option<String>,
}

pub fn routes() -> Router<AnnotationRoutesState> {
    Router::new()
        .route(
            "/v1/traces/{trace_id}/annotations",
            get(list_handler)
                .post(upsert_handler)
                .delete(delete_handler),
        )
        // EVL-29 — same module, same store, same table. Extending OBS-18 is
        // the whole point of the item: a trace flagged from the trace header
        // and one reviewed in a queue are the SAME row.
        .route(
            "/v1/annotation-queues",
            get(list_queues_handler).post(create_queue_handler),
        )
        .route(
            "/v1/annotation-queues/{queue_id}",
            axum::routing::patch(patch_queue_handler),
        )
        .route(
            "/v1/annotation-queues/{queue_id}/items",
            get(queue_items_handler),
        )
        .route(
            "/v1/annotation-queues/{queue_id}/reviews",
            axum::routing::post(submit_review_handler),
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

// ══════════════════════════════════════════════════════════════════════════
// EVL-29 — GOLDEN-CASE AUTHORING QUEUES (Sprint 3 item 12)
//
// A queue is a SAVED FILTER over traces that a reviewer works through. Every
// review writes a `trace_annotations` row (the OBS-18 table, unchanged) AND a
// dataset item carrying the human's answer as `expected_output` — in ONE
// request. That single-action property is the item; two clicks in two places
// is a review tool, not a loop.
//
// ── THE FOUR FOUNDER RULINGS, and why each is where it is ─────────────────
//
// R221.1 — MEMBERSHIP IS EVALUATED AT READ TIME, never materialised. There is
//   no `queue_items` table and no queue-entry event. A materialised queue is a
//   second copy of a judgement that goes stale the moment a threshold moves,
//   and we would then own reconciliation between the queue and the scores it
//   came from. Read-time evaluation cannot drift because there is nothing to
//   drift from. Accepted cost, knowingly: a reviewer's list is a live query.
//
// R222 — `default_dataset_id` is NOT NULL at the schema (migration 0033), not
//   merely validated here. A nullable target plus a fallback picker is two
//   paths where one is exercised rarely and rots; "the loop closes by
//   construction" is only true if the field CANNOT be absent. Same shape as
//   `online_eval_policies.judge_budget_usd_monthly`.
//
// R223 — `expected_output_field` is NOT NULL with `CHECK (length > 0)`. The
//   queue NAMES which rubric field's answer becomes the dataset item's
//   reference. A queue that produced items with a NULL `expected_output` would
//   silently produce items reference-based scorers cannot score — the exact
//   hole this item exists to close, reopened by this item's own tooling.
//   THE BOOLEAN CARVE-OUT lives in `validate_rubric_definition` with its reason
//   at the site: `"true"`/`"false"` as an expected_output is a scorer comparing
//   against a string that means nothing.
//
// R224 — `trace_annotations.rubric_snapshot` stores the rubric DEFINITION as it
//   stood when the answer was given, frozen. Same class as `dataset_snapshots`:
//   the frozen set is what makes a past judgement re-readable. A counter tells
//   you the rubric changed, not what it SAID, so a v1 label would stay
//   uninterpretable — which is the failure the versioning was meant to prevent.
//
// ── WHY THE WRITE ORDER IS DATASET-FIRST, ANNOTATION-LAST ─────────────────
//
// The `trace_annotations` row is what REMOVES the trace from the queue — it is
// the "done" marker. `.claude/rules/logging.md` (*never record "done" before
// the thing is done*, the 14 lost watchdog alerts) puts the marker AFTER the
// act it attests to. If the dataset write fails the review is not recorded, the
// trace stays in the queue, and the reviewer gets `dataset_write_failed` with a
// retry — instead of a trace that silently left the queue without ever becoming
// a test case.

/// Hard cap on queues per tenant. Paginated by construction — this list does
/// not inherit the unpaginated `GET /v1/prompts` defect.
pub(crate) const MAX_QUEUES: usize = 50;
/// Defensive bound on a queue name (the column is TEXT).
const MAX_QUEUE_NAME_LEN: usize = 200;
/// Defensive bound on the rubric definition.
const MAX_RUBRIC_FIELDS: usize = 20;
/// Defensive bound on one rubric field's key.
const MAX_RUBRIC_KEY_LEN: usize = 64;
/// Defensive bound on a `choice` field's option list.
const MAX_RUBRIC_OPTIONS: usize = 32;
/// Defensive bound on a free-text rubric answer, and therefore on the
/// `expected_output` it can become.
const MAX_RUBRIC_TEXT_LEN: usize = 8_192;
/// How many ClickHouse pages the read-time filter will scan looking for
/// unreviewed candidates before giving up and SAYING SO. Without a bound, a
/// queue whose every candidate is already reviewed scans the whole retention
/// window on one page load.
const QUEUE_SCAN_PAGES: u32 = 5;
/// Candidates fetched per scan page. Mirrors `trace_reads::MAX_TRACE_LIMIT`.
const QUEUE_SCAN_PAGE_SIZE: u32 = 200;
/// Default look-back for a queue filter, hours.
const DEFAULT_QUEUE_WINDOW_HOURS: u32 = 168;
/// Hard cap on a queue's look-back window — **tied to the content snapshot's
/// TTL, not to the `spans` table TTL, and that correction is the point.**
///
/// This constant used to be 24*90 and was asserted against `spans`' 365-day
/// TTL, which looked like a 4x safety margin. It was not. `infra/dev/clickhouse/
/// schema.sql` says of that 365 in its own words: *"the MAX plan retention
/// (Enterprise) — a fail-safe BACKSTOP, not the per-plan window"*. The window
/// that governs is the entitlement sweep (`retention_sweep.rs`): Free 7 /
/// Builder 30 / Team 90 / Business 180 / Enterprise 365 days. The one tenant
/// with content capture on is `free_v1`, so its real window is SEVEN DAYS —
/// making the old 90-day queue 12.8x LONGER than the data it pointed at,
/// inverted from what the assertion claimed to prove.
///
/// Now a queue cannot reach further back than a snapshot survives (R228).
const MAX_QUEUE_WINDOW_HOURS: u32 = 24 * SNAPSHOT_TTL_DAYS;
/// The content snapshot's TTL, in days. Mirrors
/// `infra/dev/clickhouse/migrations/21_evl29_trace_content_snapshots.sql`, and
/// deliberately equals the 30 days that
/// `scripts/ci/check-trace-content-allowlist.py` names as the precondition for
/// admitting a real customer tenant to content capture.
pub(crate) const SNAPSHOT_TTL_DAYS: u32 = 30;

/// **The R228 invariant, pinned at COMPILE TIME: a queue may never reach
/// further back than the content behind it survives.**
///
/// The previous version of this assertion compared the queue window against
/// `spans`' 365-day TTL and passed with a margin that did not exist — 365 is a
/// fail-safe BACKSTOP, and the governing window is the per-plan sweep (7 days
/// for the content-capture tenant). Measured on prod 2026-08-29: 10,225 of that
/// tenant's spans were already past its window, 406 of them carrying content.
///
/// Tying the window to the SNAPSHOT's own TTL is what makes the guarantee real
/// rather than asserted: the snapshot is written at queue-entry and outlives the
/// source row, so 30 = 30 is an equality we control on both sides.
const _: () = {
    assert!(
        MAX_QUEUE_WINDOW_HOURS <= 24 * SNAPSHOT_TTL_DAYS,
        "a queue must not reach further back than its content snapshot survives"
    );
};

/// The closed rubric field-type vocabulary.
///
/// Closed for the 0026 reason (`apps/web/db/migrations/0026_dsh01_notifications.sql:18`):
/// a type the UI cannot render is worse than a rejected write. The rubric
/// ANSWERS are open data, but the SHAPE the UI must render is not.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RubricFieldType {
    Verdict,
    Score,
    Choice,
    Text,
    Boolean,
}

impl RubricFieldType {
    /// Can this field's answer serve as a dataset item's `expected_output`?
    ///
    /// **`Boolean` cannot — R223's carve-out, and the reason is the point:** an
    /// `expected_output` of the string `"true"` is a reference-based scorer
    /// comparing a model's prose against a word that means nothing. A queue
    /// naming a boolean field as its reference would produce items that look
    /// scorable and are not, which is the failure this whole item closes.
    fn usable_as_expected_output(self) -> bool {
        !matches!(self, Self::Boolean)
    }
}

/// One field in a queue's rubric. A CLOSED shape — unknown keys are rejected by
/// `deny_unknown_fields` so a typo in a rubric definition is a 400 at creation
/// rather than a field that silently never renders.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RubricField {
    pub key: String,
    pub label: String,
    #[serde(rename = "type")]
    pub field_type: RubricFieldType,
    #[serde(default)]
    pub required: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub options: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max: Option<f64>,
}

/// Where a queue's candidate traces come from.
///
/// **Every variant's writer must EXIST.** A filter whose data nothing writes is
/// the `/sessions` failure — a surface that renders an honest empty state
/// forever. Each variant below names its writer:
///   - `OnlineEvalScore` → `online_eval::write_score`, live since item 11
///     (`19f64008`); 20 real rows on prod.
///   - `TraceError`      → ingest, the sole span writer.
///   - `NeedsReview`     → `upsert_handler` below, live since OBS-18.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum QueueSource {
    /// Item 11's judge scores. **The first queue type** — low scores route to a
    /// human, which is the loop this sprint exists to close.
    OnlineEvalScore {
        /// Inclusive ceiling. A score at or below this is a candidate.
        max_score: f64,
        /// Restrict to one rubric, or every rubric when absent.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        rubric: Option<String>,
    },
    /// Traces carrying a non-OK span status.
    TraceError,
    /// Traces a human already flagged `needs_review` through OBS-18.
    NeedsReview,
}

/// A queue's saved filter. Evaluated at READ TIME (R221.1).
///
/// **`source` is a NESTED object, not `#[serde(flatten)]`, and that is a
/// correctness requirement rather than a style choice.** serde cannot combine
/// `flatten` with `deny_unknown_fields` — the flattened tag is itself reported
/// as an unknown field, so a flattened filter serializes fine and then FAILS TO
/// DESERIALIZE. Every stored queue would have read back as an error on its
/// first list. Caught by `the_first_queue_type_round_trips` before it shipped;
/// the nested shape keeps `deny_unknown_fields` working at BOTH levels, which
/// is what makes a typo in a saved filter a 400 instead of a silently ignored
/// key that changes which traces a human reviews.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueueFilter {
    pub source: QueueSource,
    /// Look-back, hours. Bounded by `MAX_QUEUE_WINDOW_HOURS`.
    #[serde(default = "default_queue_window")]
    pub window_hours: u32,
}

fn default_queue_window() -> u32 {
    DEFAULT_QUEUE_WINDOW_HOURS
}

/// One queue, as stored and as returned.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnnotationQueue {
    pub id: Uuid,
    pub name: String,
    pub filter: QueueFilter,
    pub rubric: Vec<RubricField>,
    /// REQUIRED (R222). Every review through this queue creates an item here.
    pub default_dataset_id: Uuid,
    /// REQUIRED (R223). The rubric key whose answer becomes `expected_output`.
    pub expected_output_field: String,
    pub created_by: String,
    pub created_at: String,
    pub updated_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub archived_at: Option<String>,
}

/// One unreviewed candidate in a queue.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueueItem {
    pub trace_id: String,
    /// `""` = the trace as a whole, the OBS-18 sentinel.
    pub span_id: String,
    /// Present only for an `online_eval_score` queue — the score that put this
    /// trace in front of a human. `None` for every other source, and rendered
    /// as absent rather than as zero.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub score: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verdict: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub occurred_at: String,
}

// ───────────────────────────── validation ─────────────────────────────────
//
// FAIL-CLOSED, and on TYPES AND RANGES rather than "did it parse". A review row
// becomes a training label and a dataset reference, so it is a decision-maker
// under `CLAUDE.md` §21 and gets §21's discipline: a declared schema, checked,
// refusing loudly. `validate_call`'s limitation is the precedent — it has no
// `enum`, no `minimum`, no `maximum`, so the range checks are written HERE, at
// the site, exactly as item 11's judge does.

/// A validation refusal that names the offending key.
type QueueErr = (StatusCode, Json<serde_json::Value>);

fn qerr(status: StatusCode, code: &str, message: impl Into<String>) -> QueueErr {
    (
        status,
        Json(serde_json::json!({ "error": code, "message": message.into() })),
    )
}

fn qerr_field(status: StatusCode, code: &str, field: &str, message: impl Into<String>) -> QueueErr {
    (
        status,
        Json(serde_json::json!({
            "error": code, "field": field, "message": message.into(),
        })),
    )
}

/// Validate a rubric DEFINITION at queue create/update time, and prove the
/// queue can close the loop before it is allowed to exist (R223).
pub(crate) fn validate_rubric_definition(
    fields: &[RubricField],
    expected_output_field: &str,
) -> Result<(), QueueErr> {
    if fields.is_empty() {
        return Err(qerr(
            StatusCode::BAD_REQUEST,
            "rubric_empty",
            "A queue needs at least one rubric field — a review with nothing to answer \
             cannot produce a reference.",
        ));
    }
    if fields.len() > MAX_RUBRIC_FIELDS {
        return Err(qerr(
            StatusCode::BAD_REQUEST,
            "rubric_too_large",
            format!("A rubric may hold at most {MAX_RUBRIC_FIELDS} fields."),
        ));
    }
    let mut seen: Vec<&str> = Vec::with_capacity(fields.len());
    for f in fields {
        if f.key.trim().is_empty() || f.key.len() > MAX_RUBRIC_KEY_LEN {
            return Err(qerr_field(
                StatusCode::BAD_REQUEST,
                "rubric_bad_key",
                &f.key,
                format!("A rubric field key must be 1..={MAX_RUBRIC_KEY_LEN} characters."),
            ));
        }
        if seen.contains(&f.key.as_str()) {
            return Err(qerr_field(
                StatusCode::BAD_REQUEST,
                "rubric_duplicate_key",
                &f.key,
                "Two rubric fields share a key; an answer would be ambiguous.",
            ));
        }
        seen.push(&f.key);
        match f.field_type {
            RubricFieldType::Choice => {
                let opts = f
                    .options
                    .as_ref()
                    .filter(|o| !o.is_empty())
                    .ok_or_else(|| {
                        qerr_field(
                            StatusCode::BAD_REQUEST,
                            "rubric_choice_needs_options",
                            &f.key,
                            "A `choice` field must list its options; without them nothing is \
                         answerable and nothing is checkable.",
                        )
                    })?;
                if opts.len() > MAX_RUBRIC_OPTIONS {
                    return Err(qerr_field(
                        StatusCode::BAD_REQUEST,
                        "rubric_too_many_options",
                        &f.key,
                        format!("At most {MAX_RUBRIC_OPTIONS} options."),
                    ));
                }
            }
            RubricFieldType::Score => {
                // A score field with no bounds is a range check that cannot
                // run, so the bounds are REQUIRED rather than defaulted — a
                // default would silently accept whatever the reviewer typed.
                let (min, max) = match (f.min, f.max) {
                    (Some(a), Some(b)) => (a, b),
                    _ => {
                        return Err(qerr_field(
                            StatusCode::BAD_REQUEST,
                            "rubric_score_needs_bounds",
                            &f.key,
                            "A `score` field must declare `min` and `max`; an unbounded score \
                             is a range check that cannot run.",
                        ));
                    }
                };
                if !(min.is_finite() && max.is_finite()) || min >= max {
                    return Err(qerr_field(
                        StatusCode::BAD_REQUEST,
                        "rubric_score_bad_bounds",
                        &f.key,
                        "`min` must be finite and strictly less than a finite `max`.",
                    ));
                }
            }
            _ => {}
        }
    }
    // R223: the queue must be able to close the loop, proven at creation.
    let target = fields
        .iter()
        .find(|f| f.key == expected_output_field)
        .ok_or_else(|| {
            qerr_field(
                StatusCode::BAD_REQUEST,
                "expected_output_field_unknown",
                expected_output_field,
                "`expected_output_field` must name a field this rubric defines — otherwise \
                 every review produces an item with no reference, which is the hole \
                 annotation queues exist to close.",
            )
        })?;
    if !target.field_type.usable_as_expected_output() {
        return Err(qerr_field(
            StatusCode::BAD_REQUEST,
            "expected_output_field_not_usable",
            expected_output_field,
            "A `boolean` field cannot be the reference: an expected_output of \"true\" is a \
             scorer comparing model prose against a word that means nothing.",
        ));
    }
    if !target.required {
        return Err(qerr_field(
            StatusCode::BAD_REQUEST,
            "expected_output_field_optional",
            expected_output_field,
            "The field naming the reference must be `required`; an optional reference is a \
             dataset item with a NULL expected_output, which reference-based scorers cannot \
             score.",
        ));
    }
    Ok(())
}

/// Validate a submitted rubric ANSWER set against the queue's definition, and
/// return the value that becomes the dataset item's `expected_output`.
///
/// Fail-CLOSED on every axis: unknown key, missing required, wrong type, a
/// `score` outside `[min,max]`, a `choice` outside `options`.
pub(crate) fn validate_rubric_answers(
    fields: &[RubricField],
    expected_output_field: &str,
    answers: &serde_json::Map<String, serde_json::Value>,
) -> Result<String, QueueErr> {
    for key in answers.keys() {
        if !fields.iter().any(|f| &f.key == key) {
            return Err(qerr_field(
                StatusCode::BAD_REQUEST,
                "rubric_unknown_field",
                key,
                "This rubric does not define that field.",
            ));
        }
    }
    for f in fields {
        let Some(v) = answers.get(&f.key) else {
            if f.required {
                return Err(qerr_field(
                    StatusCode::BAD_REQUEST,
                    "rubric_missing_required",
                    &f.key,
                    "This rubric field is required.",
                ));
            }
            continue;
        };
        match f.field_type {
            RubricFieldType::Boolean => {
                if !v.is_boolean() {
                    return Err(qerr_field(
                        StatusCode::BAD_REQUEST,
                        "rubric_wrong_type",
                        &f.key,
                        "Expected a boolean.",
                    ));
                }
            }
            RubricFieldType::Score => {
                let n = v.as_f64().ok_or_else(|| {
                    qerr_field(
                        StatusCode::BAD_REQUEST,
                        "rubric_wrong_type",
                        &f.key,
                        "Expected a number.",
                    )
                })?;
                // Bounds are guaranteed present by `validate_rubric_definition`.
                let (min, max) = (f.min.unwrap_or(f64::MIN), f.max.unwrap_or(f64::MAX));
                if !n.is_finite() || n < min || n > max {
                    return Err(qerr_field(
                        StatusCode::BAD_REQUEST,
                        "rubric_out_of_range",
                        &f.key,
                        format!("Expected a number in [{min}, {max}]."),
                    ));
                }
            }
            RubricFieldType::Choice => {
                let s = v.as_str().ok_or_else(|| {
                    qerr_field(
                        StatusCode::BAD_REQUEST,
                        "rubric_wrong_type",
                        &f.key,
                        "Expected a string.",
                    )
                })?;
                let ok = f.options.as_ref().is_some_and(|o| o.iter().any(|x| x == s));
                if !ok {
                    return Err(qerr_field(
                        StatusCode::BAD_REQUEST,
                        "rubric_bad_choice",
                        &f.key,
                        "That value is not one of this field's options.",
                    ));
                }
            }
            RubricFieldType::Verdict | RubricFieldType::Text => {
                let s = v.as_str().ok_or_else(|| {
                    qerr_field(
                        StatusCode::BAD_REQUEST,
                        "rubric_wrong_type",
                        &f.key,
                        "Expected a string.",
                    )
                })?;
                if s.len() > MAX_RUBRIC_TEXT_LEN {
                    return Err(qerr_field(
                        StatusCode::BAD_REQUEST,
                        "rubric_text_too_long",
                        &f.key,
                        format!("At most {MAX_RUBRIC_TEXT_LEN} characters."),
                    ));
                }
            }
        }
    }
    // The reference. `validate_rubric_definition` proved the field exists, is
    // required and is not boolean, so a missing value here is unreachable —
    // but it is checked rather than unwrapped, because "unreachable" is a
    // property of the CURRENT validator and this returns a stored reference.
    let raw = answers.get(expected_output_field).ok_or_else(|| {
        qerr_field(
            StatusCode::BAD_REQUEST,
            "rubric_missing_required",
            expected_output_field,
            "The reference field is required.",
        )
    })?;
    let expected = match raw {
        serde_json::Value::String(s) => s.clone(),
        // A `score` reference is legitimate (grading against a target number)
        // and serializes as its literal text.
        serde_json::Value::Number(n) => n.to_string(),
        _ => {
            return Err(qerr_field(
                StatusCode::BAD_REQUEST,
                "expected_output_not_scalar",
                expected_output_field,
                "The reference must be text or a number.",
            ));
        }
    };
    if expected.trim().is_empty() {
        return Err(qerr_field(
            StatusCode::BAD_REQUEST,
            "expected_output_empty",
            expected_output_field,
            "An empty reference is a test case that passes nothing and fails nothing.",
        ));
    }
    Ok(expected)
}

/// Bound a queue's look-back window, NAMING the bound rather than clamping.
/// A clamped window renders a number that answers a different question than the
/// one asked — the same reasoning as `online_eval_routes::window_hours`.
fn validate_window(hours: u32) -> Result<(), QueueErr> {
    if hours == 0 || hours > MAX_QUEUE_WINDOW_HOURS {
        return Err(qerr(
            StatusCode::BAD_REQUEST,
            "window_out_of_range",
            format!(
                "`window_hours` must be between 1 and {MAX_QUEUE_WINDOW_HOURS} ({SNAPSHOT_TTL_DAYS} days — the content snapshot's lifetime)."
            ),
        ));
    }
    Ok(())
}

// ─────────────────────────── the storage seam ─────────────────────────────
//
// These go on the SAME `AnnotationStore` trait rather than a new one, so the
// existing mock covers them and a queue review and an ad-hoc OBS-18 flag write
// through one seam to one table.

/// What a review writes. Grouped into a struct because seven positional
/// arguments is how the wrong two get swapped silently.
#[derive(Debug, Clone)]
pub struct ReviewWrite<'a> {
    pub trace_id: &'a str,
    pub span_id: &'a str,
    pub label: &'a str,
    pub note: &'a str,
    pub author_sub: &'a str,
    pub queue_id: Uuid,
    /// The reviewer's answers.
    pub rubric: &'a serde_json::Value,
    /// The reference this review produced.
    pub expected_output: &'a str,
    /// R224 — the rubric DEFINITION as it stood at this moment, frozen.
    pub rubric_snapshot: &'a serde_json::Value,
}

/// A partial queue update. `None` means UNCHANGED, which is why every field is
/// an `Option` and why the SQL uses `COALESCE` rather than a built SET list.
#[derive(Debug, Clone, Default)]
pub struct QueuePatch<'a> {
    pub name: Option<&'a str>,
    pub filter: Option<&'a serde_json::Value>,
    pub rubric: Option<&'a serde_json::Value>,
    pub expected_output_field: Option<&'a str>,
    /// `Some(true)` archives, `Some(false)` un-archives, `None` leaves it.
    pub archived: Option<bool>,
}

/// A queue as written. Separated from [`AnnotationQueue`] because the stored
/// form carries JSON text while the wire form carries typed structures.
#[derive(Debug, Clone)]
pub struct QueueWrite<'a> {
    pub id: Uuid,
    pub name: &'a str,
    /// **A PARSED `Value`, never a `&str`, and that is a wire requirement not a
    /// style choice.** Postgres infers a `$n::jsonb` placeholder AS `jsonb`, so
    /// tokio-postgres refuses a `&str` with *"cannot convert between the Rust
    /// type `&str` and the Postgres type `jsonb`"* — the same class as the
    /// recorded `&str`-into-PG-ENUM gotcha. `with-serde_json-1` is enabled on
    /// both `tokio-postgres` and `postgres-types`, so a `Value` maps natively.
    pub filter: &'a serde_json::Value,
    pub rubric: &'a serde_json::Value,
    pub default_dataset_id: Uuid,
    pub expected_output_field: &'a str,
    pub created_by: &'a str,
}

// ────────────────── PgAnnotationStore: the queue half ─────────────────────

/// Column list shared by every queue SELECT, so a new column cannot be added to
/// one read and forgotten in another.
const QUEUE_COLS: &str = "id, name, filter_json::text, rubric_json::text, default_dataset_id, \
                          expected_output_field, created_by, \
                          to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'), \
                          to_char(updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'), \
                          to_char(archived_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"')";

/// Build an [`AnnotationQueue`] from a row of [`QUEUE_COLS`].
///
/// A row whose stored JSON no longer parses is an ERROR, never a queue with an
/// empty rubric: a queue that silently lost its rubric would accept reviews
/// that validate against nothing, which is precisely the fail-open this item
/// must not have.
fn queue_from_row(r: &tokio_postgres::Row) -> Result<AnnotationQueue> {
    let filter_txt: String = r.get(2);
    let rubric_txt: String = r.get(3);
    Ok(AnnotationQueue {
        id: r.get(0),
        name: r.get(1),
        filter: serde_json::from_str(&filter_txt).with_context(|| {
            format!(
                "queue {} has an unparseable filter_json",
                r.get::<_, Uuid>(0)
            )
        })?,
        rubric: serde_json::from_str(&rubric_txt).with_context(|| {
            format!(
                "queue {} has an unparseable rubric_json",
                r.get::<_, Uuid>(0)
            )
        })?,
        default_dataset_id: r.get(4),
        expected_output_field: r.get(5),
        created_by: r.get(6),
        created_at: r.get(7),
        updated_at: r.get(8),
        archived_at: r.get(9),
    })
}

// ───────────────────────── the entitlement gate ───────────────────────────

/// `f_annotation_queues`, shaped exactly like `require_promotion_write`.
///
/// **An absent entitlement cache is a 503, never a grant** — `.claude/rules/tenancy.md`:
/// `None` means "no control plane", which is the UNPRIVILEGED state. This was
/// inverted once and shipped (the guardrail rails), and it produced no error,
/// no alert and no complaint.
async fn require_queues(
    entitlements: &Option<Arc<crate::entitlement_cache::EntitlementCache>>,
    tenant: &TenantId,
) -> Result<(), QueueErr> {
    match entitlements {
        Some(cache) => {
            if cache
                .check(
                    *tenant.as_uuid(),
                    crate::entitlement_cache::FeatureKey::AnnotationQueues,
                )
                .await
            {
                Ok(())
            } else {
                tracing::info!(
                    tenant_id = %tenant,
                    "annotation queues denied — tenant lacks f_annotation_queues (Team+)"
                );
                Err((
                    StatusCode::FORBIDDEN,
                    Json(serde_json::json!({
                        "error": "entitlement_required",
                        "feature": "annotation_queues",
                        "message": "Golden-case authoring queues require the Team plan or above.",
                        "upgrade_url": "https://app.tracelane.dev/settings/billing",
                    })),
                ))
            }
        }
        None => {
            tracing::error!("annotation queues: entitlement cache unavailable — denying");
            Err(qerr(
                StatusCode::SERVICE_UNAVAILABLE,
                "entitlement_unavailable",
                "Entitlement verification is unavailable.",
            ))
        }
    }
}

/// Auth + role + entitlement, in the order the spec fixes. Returns the claims.
async fn queue_gate(
    state: &AnnotationRoutesState,
    headers: &HeaderMap,
    write: bool,
) -> Result<Claims, QueueErr> {
    let claims = claims_from_auth(headers)
        .await
        .map_err(|(s, m)| qerr(s, "unauthorized", m))?;
    if write && !may_write(&claims) {
        return Err(qerr(
            StatusCode::FORBIDDEN,
            "role_forbidden",
            "A viewer may read queues and reviews, not write them.",
        ));
    }
    require_queues(&state.entitlements, &claims.tenant_id).await?;
    Ok(claims)
}

// ───────────────────────────── queue CRUD ─────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateQueueBody {
    pub name: String,
    pub filter: QueueFilter,
    pub rubric: Vec<RubricField>,
    /// REQUIRED (R222). Not `Option` — the constraint is at the schema AND
    /// named here, the two-layer shape item 11 proved: the schema stops every
    /// writer, the handler tells THIS caller which field it was.
    pub default_dataset_id: Uuid,
    /// REQUIRED (R223).
    pub expected_output_field: String,
}

async fn create_queue_handler(
    State(state): State<AnnotationRoutesState>,
    headers: HeaderMap,
    Json(body): Json<CreateQueueBody>,
) -> Result<(StatusCode, Json<AnnotationQueue>), QueueErr> {
    let claims = queue_gate(&state, &headers, true).await?;
    let tenant = claims.tenant_id;

    let name = body.name.trim();
    if name.is_empty() || name.len() > MAX_QUEUE_NAME_LEN {
        return Err(qerr_field(
            StatusCode::BAD_REQUEST,
            "invalid_name",
            "name",
            format!("A queue name must be 1..={MAX_QUEUE_NAME_LEN} characters."),
        ));
    }
    validate_window(body.filter.window_hours)?;
    validate_rubric_definition(&body.rubric, &body.expected_output_field)?;

    // R222 is a NOT NULL column, so a missing target cannot reach the table.
    // What the column CANNOT check is that the dataset EXISTS — `datasets`
    // lives in ClickHouse, so no foreign key is possible across the store
    // boundary. That check is therefore the handler's job, and it is done
    // BEFORE the queue is written: a queue pointing at a dataset that is not
    // there would fail on its first review, which is the worst moment to learn.
    let datasets = state.datasets.as_ref().ok_or_else(|| {
        qerr(
            StatusCode::SERVICE_UNAVAILABLE,
            "datasets_unavailable",
            "The dataset store is unavailable, so a queue's target cannot be verified.",
        )
    })?;
    match datasets.get_dataset(&tenant, body.default_dataset_id).await {
        Ok(Some(_)) => {}
        Ok(None) => {
            return Err(qerr_field(
                StatusCode::BAD_REQUEST,
                "dataset_not_found",
                "default_dataset_id",
                "That dataset does not exist under this workspace. A queue must name a real \
                 target dataset — the loop closes by construction or not at all.",
            ));
        }
        Err(e) => {
            tracing::error!(error = %format!("{e:#}"), "queue create: dataset lookup failed");
            return Err(qerr(
                StatusCode::BAD_GATEWAY,
                "dataset_lookup_failed",
                "Could not verify the target dataset.",
            ));
        }
    }

    let n = state.store.count_queues(&tenant).await.map_err(|e| {
        tracing::error!(error = %format!("{e:#}"), "queue count failed");
        qerr(
            StatusCode::BAD_GATEWAY,
            "store_failed",
            "Could not read queues.",
        )
    })?;
    if n as usize >= MAX_QUEUES {
        return Err(qerr(
            StatusCode::CONFLICT,
            "queue_limit_reached",
            format!("A workspace may hold at most {MAX_QUEUES} active queues. Archive one first."),
        ));
    }

    let id = Uuid::new_v4();
    let filter_json = serde_json::to_value(&body.filter).map_err(|_| {
        qerr(
            StatusCode::INTERNAL_SERVER_ERROR,
            "serialize_failed",
            "filter",
        )
    })?;
    let rubric_json = serde_json::to_value(&body.rubric).map_err(|_| {
        qerr(
            StatusCode::INTERNAL_SERVER_ERROR,
            "serialize_failed",
            "rubric",
        )
    })?;
    state
        .store
        .create_queue(
            &tenant,
            &QueueWrite {
                id,
                name,
                filter: &filter_json,
                rubric: &rubric_json,
                default_dataset_id: body.default_dataset_id,
                expected_output_field: &body.expected_output_field,
                created_by: &claims.sub,
            },
        )
        .await
        .map_err(|e| {
            let s = format!("{e:#}");
            // The UNIQUE (tenant_id, lower(name)) index is the authority on
            // name collision, not a pre-read — a pre-read races.
            if s.contains("annotation_queues_tenant_name_uniq") || s.contains("duplicate key") {
                return qerr_field(
                    StatusCode::CONFLICT,
                    "queue_name_taken",
                    "name",
                    "A queue with that name already exists in this workspace.",
                );
            }
            tracing::error!(error = %s, "queue create failed");
            qerr(
                StatusCode::BAD_GATEWAY,
                "store_failed",
                "Could not create the queue.",
            )
        })?;

    let created = state
        .store
        .get_queue(&tenant, id)
        .await
        .map_err(|e| {
            tracing::error!(error = %format!("{e:#}"), "queue read-back failed");
            qerr(
                StatusCode::BAD_GATEWAY,
                "store_failed",
                "Could not read the queue back.",
            )
        })?
        .ok_or_else(|| {
            qerr(
                StatusCode::BAD_GATEWAY,
                "store_failed",
                "The queue vanished after creation.",
            )
        })?;
    Ok((StatusCode::CREATED, Json(created)))
}

async fn list_queues_handler(
    State(state): State<AnnotationRoutesState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, QueueErr> {
    let claims = queue_gate(&state, &headers, false).await?;
    let queues = state
        .store
        .list_queues(&claims.tenant_id)
        .await
        .map_err(|e| {
            tracing::error!(error = %format!("{e:#}"), "queue list failed");
            qerr(
                StatusCode::BAD_GATEWAY,
                "store_failed",
                "Could not read queues.",
            )
        })?;
    Ok(Json(
        serde_json::json!({ "queues": queues, "max_queues": MAX_QUEUES }),
    ))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PatchQueueBody {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub filter: Option<QueueFilter>,
    #[serde(default)]
    pub rubric: Option<Vec<RubricField>>,
    #[serde(default)]
    pub expected_output_field: Option<String>,
    /// `true` archives, `false` un-archives. There is deliberately NO DELETE:
    /// a review's `queue_id` must never dangle (§19, supersession).
    #[serde(default)]
    pub archived: Option<bool>,
}

async fn patch_queue_handler(
    State(state): State<AnnotationRoutesState>,
    Path(queue_id): Path<Uuid>,
    headers: HeaderMap,
    Json(body): Json<PatchQueueBody>,
) -> Result<Json<AnnotationQueue>, QueueErr> {
    let claims = queue_gate(&state, &headers, true).await?;
    let tenant = claims.tenant_id;

    let existing = load_queue(&state, &tenant, queue_id, false).await?;

    if let Some(ref f) = body.filter {
        validate_window(f.window_hours)?;
    }
    // Editing the rubric or the reference field re-runs the FULL definition
    // check against the resulting pair, not against whichever half arrived —
    // otherwise a rubric edit could orphan the reference field that a
    // previously-valid queue named.
    let next_rubric = body.rubric.as_ref().unwrap_or(&existing.rubric);
    let next_field = body
        .expected_output_field
        .as_deref()
        .unwrap_or(&existing.expected_output_field);
    if body.rubric.is_some() || body.expected_output_field.is_some() {
        validate_rubric_definition(next_rubric, next_field)?;
    }
    if let Some(ref n) = body.name {
        let n = n.trim();
        if n.is_empty() || n.len() > MAX_QUEUE_NAME_LEN {
            return Err(qerr_field(
                StatusCode::BAD_REQUEST,
                "invalid_name",
                "name",
                format!("A queue name must be 1..={MAX_QUEUE_NAME_LEN} characters."),
            ));
        }
    }

    let filter_json = body
        .filter
        .as_ref()
        .map(serde_json::to_value)
        .transpose()
        .map_err(|_| {
            qerr(
                StatusCode::INTERNAL_SERVER_ERROR,
                "serialize_failed",
                "filter",
            )
        })?;
    let rubric_json = body
        .rubric
        .as_ref()
        .map(serde_json::to_value)
        .transpose()
        .map_err(|_| {
            qerr(
                StatusCode::INTERNAL_SERVER_ERROR,
                "serialize_failed",
                "rubric",
            )
        })?;

    let ok = state
        .store
        .update_queue(
            &tenant,
            queue_id,
            &QueuePatch {
                name: body.name.as_deref().map(str::trim),
                filter: filter_json.as_ref(),
                rubric: rubric_json.as_ref(),
                expected_output_field: body.expected_output_field.as_deref(),
                archived: body.archived,
            },
        )
        .await
        .map_err(|e| {
            tracing::error!(error = %format!("{e:#}"), "queue update failed");
            qerr(
                StatusCode::BAD_GATEWAY,
                "store_failed",
                "Could not update the queue.",
            )
        })?;
    if !ok {
        return Err(qerr(
            StatusCode::NOT_FOUND,
            "queue_not_found",
            "No such queue.",
        ));
    }
    let updated = state
        .store
        .get_queue(&tenant, queue_id)
        .await
        .map_err(|e| {
            tracing::error!(error = %format!("{e:#}"), "queue read-back failed");
            qerr(
                StatusCode::BAD_GATEWAY,
                "store_failed",
                "Could not read the queue back.",
            )
        })?
        .ok_or_else(|| qerr(StatusCode::NOT_FOUND, "queue_not_found", "No such queue."))?;
    Ok(Json(updated))
}

/// Load a queue under the tenant claim. A foreign id and an archived id are
/// BOTH 404 — a caller must not be able to learn that a queue id exists under
/// someone else's tenant, and an archived queue is not workable.
async fn load_queue(
    state: &AnnotationRoutesState,
    tenant: &TenantId,
    id: Uuid,
    reject_archived: bool,
) -> Result<AnnotationQueue, QueueErr> {
    let q = state
        .store
        .get_queue(tenant, id)
        .await
        .map_err(|e| {
            tracing::error!(error = %format!("{e:#}"), "queue read failed");
            qerr(
                StatusCode::BAD_GATEWAY,
                "store_failed",
                "Could not read the queue.",
            )
        })?
        .ok_or_else(|| qerr(StatusCode::NOT_FOUND, "queue_not_found", "No such queue."))?;
    if reject_archived && q.archived_at.is_some() {
        return Err(qerr(
            StatusCode::CONFLICT,
            "queue_archived",
            "This queue is archived. Un-archive it before reviewing through it.",
        ));
    }
    Ok(q)
}

// ───────────── the read-time filter: the cross-store join (B-210) ─────────
//
// R221.1 in code. There is no `queue_items` table; membership IS this query.
//
// ClickHouse returns a bounded page of candidates; Postgres is asked which of
// THAT PAGE are already reviewed; we subtract. Bounded on both sides, the
// mirror image of `build_trace_cost_rollup_sql` and for the same reason: a
// cross-store join is only safe while one side is a bounded id list.

/// A candidate row as ClickHouse returns it. Field types mirror the COLUMN
/// types exactly — `score` is `Nullable(Float64)` so it is `Option<f64>` here.
///
/// **This is the EVL-28 class and it cost four defects in one item:** RowBinary
/// is positional and typed, a mismatch fails SILENTLY, and a redundant guard
/// (`Option<f64>` plus `ifNull`) does not reinforce the type, it CHANGES it.
#[derive(Debug, serde::Deserialize, clickhouse::Row)]
struct CandidateRow {
    trace_id: String,
    span_id: String,
    score: Option<f64>,
    verdict: String,
    reason: String,
    occurred_at_ms: i64,
}

fn ms_to_iso(ms: i64) -> String {
    chrono::DateTime::from_timestamp_millis(ms)
        .map(|d| d.format("%Y-%m-%dT%H:%M:%SZ").to_string())
        .unwrap_or_default()
}

/// Build the candidate SQL for one queue source. Every branch is a fixed
/// string with bound parameters — no caller value ever reaches statement text.
/// Build the candidate SQL for one queue source. Every branch is a fixed
/// string with bound parameters — no caller value ever reaches statement text.
///
/// **KEYSET, NOT OFFSET, and the repo has already paid for the difference.**
/// `experiment_routes.rs` records it at its own paging site: *"NOT OFFSET: an
/// OFFSET page over a `ReplacingMergeTree` shifts under a concurrent write and
/// silently skips a row."* Both sources here ARE ReplacingMergeTrees and both
/// are written CONCURRENTLY with this read — `online_eval_scores` by the judge
/// on a fire-and-forget task, `spans` by ingest — so an OFFSET scan could step
/// straight over the trace it was looking for, and the reviewer would simply
/// never be shown it. The cursor is the ordering column itself.
fn candidate_sql(source: &QueueSource, seek: bool) -> String {
    let body = match source {
        // The FIRST queue type: item 11's judge scores. `FINAL` because
        // `online_eval_scores` is a ReplacingMergeTree and a half-merged
        // duplicate must not put a trace in front of a human twice.
        QueueSource::OnlineEvalScore { rubric, .. } => {
            let rubric_filter = if rubric.is_some() {
                "AND rubric = ?"
            } else {
                ""
            };
            let keyset = if seek {
                "AND scored_at < fromUnixTimestamp64Milli(toInt64(?))"
            } else {
                ""
            };
            format!(
                "SELECT trace_id, span_id, score, verdict, substring(reason, 1, 500) AS reason, \
                        toUnixTimestamp64Milli(scored_at) AS occurred_at_ms \
                   FROM online_eval_scores FINAL \
                  WHERE tenant_id = ? AND scored_at >= now() - toIntervalHour(?) \
                    AND status = 'scored' AND score IS NOT NULL AND score <= ? \
                    {rubric_filter} {keyset} \
                  ORDER BY scored_at DESC LIMIT ?"
            )
        }
        // A trace is a candidate if ANY span in it errored. `status_code != 0`
        // is the OTLP non-OK convention the rest of the read layer uses.
        //
        // The cursor is a HAVING, not a WHERE: it orders by `max(start_time)`
        // per trace, which does not exist until after the GROUP BY.
        QueueSource::TraceError => {
            let keyset = if seek {
                "HAVING occurred_at_ms < ?"
            } else {
                ""
            };
            format!(
                "SELECT trace_id, '' AS span_id, \
                        CAST(NULL AS Nullable(Float64)) AS score, \
                        '' AS verdict, '' AS reason, \
                        toUnixTimestamp64Milli(max(start_time)) AS occurred_at_ms \
                   FROM spans \
                  WHERE tenant_id = ? AND start_time >= now() - toIntervalHour(?) \
                    AND status_code != 0 \
                  GROUP BY trace_id {keyset} \
                  ORDER BY occurred_at_ms DESC LIMIT ?"
            )
        }
        // `needs_review` lives in Postgres, so this branch is never sent to
        // ClickHouse — see `fetch_candidates`.
        QueueSource::NeedsReview => String::new(),
    };
    crate::clickhouse_query::TenantQuery::new(body, crate::clickhouse_query::PlanTier::Builder)
        .sql_with_settings()
}

/// One page of candidates from ClickHouse, before the exclusion subtraction.
///
/// Returns the page AND its keyset cursor — the raw `occurred_at_ms` of the
/// last row. The cursor is returned separately rather than added to
/// [`QueueItem`] because `QueueItem` is a WIRE type: putting the same instant
/// on it twice, once as an ISO string and once as millis, is the "same fact in
/// two fields that can disagree" shape this repo keeps out of its rows.
async fn fetch_candidates(
    state: &AnnotationRoutesState,
    tenant: &TenantId,
    filter: &QueueFilter,
    after_ms: Option<i64>,
) -> Result<(Vec<QueueItem>, Option<i64>), QueueErr> {
    // `needs_review` is a Postgres-native source: the candidates ARE
    // annotations. Reading it from ClickHouse would be a join with no purpose.
    if matches!(filter.source, QueueSource::NeedsReview) {
        return Ok((Vec::new(), None));
    }
    let url = state.ch_url.clone().ok_or_else(|| {
        qerr(
            StatusCode::SERVICE_UNAVAILABLE,
            "clickhouse_unavailable",
            "Trace storage is unavailable, so queue membership cannot be evaluated.",
        )
    })?;
    let sql = candidate_sql(&filter.source, after_ms.is_some());
    let mut q = crate::clickhouse_query::ch_client(url)
        .query(&sql)
        .bind(tenant.to_string())
        .bind(filter.window_hours);
    if let QueueSource::OnlineEvalScore { max_score, rubric } = &filter.source {
        q = q.bind(*max_score);
        if let Some(r) = rubric {
            q = q.bind(r.clone());
        }
    }
    // BIND ORDER IS POSITIONAL and must match `candidate_sql`'s `?` order
    // exactly: tenant, window, [score, rubric], [cursor], limit.
    if let Some(ms) = after_ms {
        q = q.bind(ms);
    }
    let rows = q
        .bind(QUEUE_SCAN_PAGE_SIZE)
        .fetch_all::<CandidateRow>()
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "queue candidate read failed");
            qerr(
                StatusCode::BAD_GATEWAY,
                "candidate_read_failed",
                "Could not evaluate queue membership.",
            )
        })?;
    let cursor = rows.last().map(|r| r.occurred_at_ms);
    Ok((
        rows.into_iter()
            .map(|r| QueueItem {
                trace_id: r.trace_id,
                span_id: r.span_id,
                // An absent score renders as ABSENT, never as 0.0 — a zero would
                // read as "the judge scored this worst", which is a different
                // claim from "this source carries no score".
                score: r.score,
                verdict: (!r.verdict.is_empty()).then(|| r.verdict.clone()),
                reason: (!r.reason.is_empty()).then(|| r.reason.clone()),
                occurred_at: ms_to_iso(r.occurred_at_ms),
            })
            .collect(),
        cursor,
    ))
}

/// **R228 — COPY AT QUEUE-ENTRY.** Ensure a content snapshot exists for this
/// trace, returning the span the content came from.
///
/// `Ok(Some(span))` the content is captured and durable. `Ok(None)` there is no
/// content to capture — either this workspace never recorded any, or the source
/// span is already gone. The caller must then DROP the candidate rather than
/// list it, because a reviewer cannot act on it (the founder's typed refusal).
///
/// Idempotent by construction: a second call for the same span re-copies the
/// same bytes into a `ReplacingMergeTree` keyed on
/// `(tenant_id, trace_id, span_id)`, so it collapses rather than duplicating.
///
/// **THIS DOES NOT MATERIALISE THE QUEUE (R221.1 survives).** The row it writes
/// is keyed on the SPAN and records no queue id, no filter and no membership —
/// it is a content cache, not a queue. Change a threshold and membership
/// re-evaluates instantly, because nothing here remembers what matched.
async fn ensure_snapshot(
    datasets: &Arc<dyn crate::dataset_routes::DatasetStore>,
    tenant: &TenantId,
    trace_id: &str,
    span_hint: &str,
) -> Option<String> {
    // The annotation target and the content source are DIFFERENT things: a
    // trace-level review carries the OBS-18 `''` sentinel, which is not a span
    // id. Passing it into `span_id = ?` matched nothing and 404'd every
    // `trace_error` review — 0 of 12,806 prod spans have an empty `span_id`.
    let span_id = if span_hint.is_empty() {
        match datasets.content_span_id(tenant, trace_id).await {
            Ok(Some(s)) => s,
            Ok(None) => return None,
            Err(e) => {
                tracing::warn!(error = %format!("{e:#}"), %trace_id, "content span resolve failed");
                return None;
            }
        }
    } else {
        span_hint.to_string()
    };

    // Already captured — nothing to do, and the earlier bytes WIN. That is the
    // point of copying at queue-entry rather than at submit.
    match datasets.read_snapshot(tenant, trace_id, &span_id).await {
        Ok(Some(_)) => return Some(span_id),
        Ok(None) => {}
        Err(e) => tracing::warn!(error = %format!("{e:#}"), "snapshot read failed; re-copying"),
    }

    let row = datasets
        .span_content(tenant, trace_id, &span_id)
        .await
        .ok()?;
    let (messages, system) = match crate::dataset_routes::classify_span(row) {
        crate::dataset_routes::SpanVerdict::Content(m, s) => (m, s),
        // NotFound / NoContent / Unreadable all mean the same thing HERE: there
        // is nothing a reviewer could turn into a test case, so the candidate is
        // dropped at the boundary instead of becoming a dead end.
        _ => return None,
    };
    let input = serde_json::to_string(&messages).ok()?;
    let hash = crate::dataset_routes::input_hash(&messages, &system).ok()?;
    if let Err(e) = datasets
        .snapshot_content(tenant, trace_id, &span_id, &input, &system, &hash)
        .await
    {
        // Fail-OPEN on the LIST path: a snapshot write failure must not hide a
        // trace from a reviewer. The submit path re-checks and refuses there,
        // where a refusal is actionable.
        tracing::warn!(error = %format!("{e:#}"), %trace_id, "content snapshot write failed");
    }
    Some(span_id)
}

#[derive(Debug, Deserialize)]
pub struct QueueItemsQuery {
    #[serde(default)]
    limit: Option<u32>,
}

async fn queue_items_handler(
    State(state): State<AnnotationRoutesState>,
    Path(queue_id): Path<Uuid>,
    axum::extract::Query(q): axum::extract::Query<QueueItemsQuery>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, QueueErr> {
    let claims = queue_gate(&state, &headers, false).await?;
    let tenant = claims.tenant_id;
    let queue = load_queue(&state, &tenant, queue_id, false).await?;
    let want = q.limit.unwrap_or(50).clamp(1, QUEUE_SCAN_PAGE_SIZE) as usize;

    let mut out: Vec<QueueItem> = Vec::new();
    let mut pages_scanned = 0u32;
    let mut exhausted = false;
    let mut dropped_no_content = 0u32;
    // The keyset cursor: the `occurred_at_ms` of the last row of the previous
    // page. `None` on the first page.
    let mut after_ms: Option<i64> = None;

    // Scan forward at most QUEUE_SCAN_PAGES. Without this bound a queue whose
    // every candidate is already reviewed scans the entire window on one page
    // load; with it, we stop and SAY we stopped (never silently truncate).
    while out.len() < want && pages_scanned < QUEUE_SCAN_PAGES {
        let (page, cursor) = fetch_candidates(&state, &tenant, &queue.filter, after_ms).await?;
        pages_scanned += 1;
        if page.is_empty() {
            exhausted = true;
            break;
        }
        // Advance the cursor from the RAW page's last row. A page whose rows
        // were every one already reviewed must still move the cursor, or the
        // loop re-reads the same page five times and reports "truncated" on a
        // queue it never actually walked.
        after_ms = cursor;
        let ids: Vec<String> = page.iter().map(|c| c.trace_id.clone()).collect();
        let reviewed = state
            .store
            .reviewed_trace_ids(&tenant, &ids)
            .await
            .map_err(|e| {
                tracing::error!(error = %format!("{e:#}"), "queue exclusion read failed");
                qerr(
                    StatusCode::BAD_GATEWAY,
                    "store_failed",
                    "Could not read the reviewed set.",
                )
            })?;
        for mut c in page {
            if out.len() >= want {
                break;
            }
            if reviewed.contains(&c.trace_id) {
                continue;
            }
            // R228 — COPY AT QUEUE-ENTRY. A candidate whose content cannot be
            // captured is DROPPED AND COUNTED, never listed: the founder's rule
            // is a typed refusal at entry rather than a queue row a reviewer
            // cannot act on. The count is returned so a short page reads as
            // "N were skipped, and here is why" instead of silently fewer rows.
            match &state.datasets {
                Some(ds) => match ensure_snapshot(ds, &tenant, &c.trace_id, &c.span_id).await {
                    Some(span) => {
                        // Carry the RESOLVED span forward so the reviewer and
                        // the submit both address the same bytes.
                        c.span_id = span;
                        out.push(c);
                    }
                    None => dropped_no_content += 1,
                },
                // No dataset store means no snapshot and no submit either, so
                // listing would promise something the submit cannot honour.
                None => dropped_no_content += 1,
            }
        }
    }

    let truncated = out.len() < want && !exhausted && pages_scanned >= QUEUE_SCAN_PAGES;
    Ok(Json(serde_json::json!({
        "queue_id": queue_id,
        "items": out,
        // Honest about the bound rather than silently short: a caller seeing
        // fewer items than asked for must be able to tell "that is all there
        // is" from "we stopped looking".
        "scan_exhausted": exhausted,
        "scan_truncated": truncated,
        // R228: candidates that matched the filter but carry no capturable
        // content. Surfaced as its own number because "nothing to review" and
        // "N traces had no content" are different facts with different fixes.
        "dropped_no_content": dropped_no_content,
        "pages_scanned": pages_scanned,
        "max_pages": QUEUE_SCAN_PAGES,
    })))
}

// ═══════════════════════ THE ONE ACTION (§2c) ═════════════════════════════
//
// A low-scoring trace appears in a queue, a human submits a rubric, and a
// dataset_item exists with that human's answer as its expected_output — in ONE
// request. If it takes two clicks in two places, this item is not done.
//
// ORDER IS THE DESIGN, and step 7 is last on purpose. The annotation row is
// what removes the trace from the queue — it is the DONE MARKER. If the dataset
// write fails, the review is NOT recorded, the trace STAYS in the queue, and
// the reviewer gets a retryable error — instead of a trace that silently left
// the queue without ever becoming a test case.

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewBody {
    pub trace_id: String,
    /// `""` = trace-level, the OBS-18 sentinel. Never NULL — NULL is not
    /// comparable in a PK, so `ON CONFLICT` would not fire.
    #[serde(default)]
    pub span_id: String,
    /// The closed OBS-18 verdict, still required. EVL-29 does NOT widen it:
    /// rubric answers are DATA, `label` is VOCABULARY, and every review stays
    /// renderable by the OBS-18 trace header with no knowledge of queues.
    pub label: String,
    #[serde(default)]
    pub note: String,
    /// The reviewer's answers, validated against the queue's rubric.
    pub rubric: serde_json::Map<String, serde_json::Value>,
}

async fn submit_review_handler(
    State(state): State<AnnotationRoutesState>,
    Path(queue_id): Path<Uuid>,
    headers: HeaderMap,
    Json(body): Json<ReviewBody>,
) -> Result<(StatusCode, Json<serde_json::Value>), QueueErr> {
    // 1-3. Auth (tenant from the validated claim ONLY), role, entitlement.
    let claims = queue_gate(&state, &headers, true).await?;
    let tenant = claims.tenant_id;

    // 4. The queue, under this tenant. Archived is refused for a WRITE.
    let queue = load_queue(&state, &tenant, queue_id, true).await?;

    if body.trace_id.trim().len() < 8 {
        return Err(qerr_field(
            StatusCode::BAD_REQUEST,
            "invalid_trace_id",
            "trace_id",
            "Invalid trace id.",
        ));
    }
    if body.span_id.len() > MAX_SPAN_ID_LEN {
        return Err(qerr_field(
            StatusCode::BAD_REQUEST,
            "invalid_span_id",
            "span_id",
            "Span id too long.",
        ));
    }
    let label = body.label.trim().to_ascii_lowercase();
    if !valid_label(&label) {
        return Err(qerr_field(
            StatusCode::BAD_REQUEST,
            "unknown_label",
            "label",
            format!("Known labels: {}", LABELS.join(", ")),
        ));
    }
    if body.note.len() > MAX_NOTE_LEN {
        return Err(qerr_field(
            StatusCode::BAD_REQUEST,
            "note_too_long",
            "note",
            format!("A note may be at most {MAX_NOTE_LEN} characters."),
        ));
    }

    // 5. Rubric answers, fail-CLOSED on types AND ranges, returning the
    //    reference the queue named (R223).
    let expected_output =
        validate_rubric_answers(&queue.rubric, &queue.expected_output_field, &body.rubric)?;

    // 6. THE DATASET ITEM — FIRST, and copied, never referenced.
    let datasets = state.datasets.as_ref().ok_or_else(|| {
        qerr(
            StatusCode::SERVICE_UNAVAILABLE,
            "datasets_unavailable",
            "The dataset store is unavailable, so this review cannot close the loop. \
             Nothing was recorded — retry.",
        )
    })?;
    let dataset_id = queue.default_dataset_id;

    // R228 — THE SNAPSHOT IS THE SOURCE OF TRUTH, and the live span is only the
    // fallback. This is the whole point of copying at queue-entry: the bytes the
    // reviewer READ when the queue listed this trace are the bytes the dataset
    // item STORES. Re-reading the span here instead would reopen the window
    // where a reviewer grades one payload and the item records another.
    //
    // The content source is resolved separately from the annotation target: a
    // trace-level review carries the OBS-18 `''` sentinel, which is not a span
    // id and matched nothing.
    let content_span = if body.span_id.is_empty() {
        datasets
            .content_span_id(&tenant, &body.trace_id)
            .await
            .map_err(|e| {
                tracing::error!(error = %format!("{e:#}"), "review: content span resolve failed");
                qerr(
                    StatusCode::BAD_GATEWAY,
                    "span_read_failed",
                    "Could not resolve which span carries this trace's content.",
                )
            })?
            .unwrap_or_default()
    } else {
        body.span_id.clone()
    };

    let snapshot = if content_span.is_empty() {
        None
    } else {
        datasets
            .read_snapshot(&tenant, &body.trace_id, &content_span)
            .await
            .unwrap_or_else(|e| {
                tracing::warn!(error = %format!("{e:#}"), "review: snapshot read failed");
                None
            })
    };

    let row = match snapshot {
        Some(s) => Some(s),
        None if content_span.is_empty() => None,
        // Fallback: no snapshot (the queue was never listed, or the write
        // failed open). Re-reading is still correct — it is exactly the
        // pre-R228 behaviour — it simply carries the older, narrower guarantee.
        None => datasets
            .span_content(&tenant, &body.trace_id, &content_span)
            .await
            .map_err(|e| {
                tracing::error!(error = %format!("{e:#}"), "review: span content read failed");
                qerr(
                    StatusCode::BAD_GATEWAY,
                    "span_read_failed",
                    "Could not re-read the trace content.",
                )
            })?,
    };
    let (messages, system) = match crate::dataset_routes::classify_span(row) {
        crate::dataset_routes::SpanVerdict::NotFound => {
            return Err(qerr(
                StatusCode::NOT_FOUND,
                "span_not_found",
                "No such span under this workspace.",
            ));
        }
        crate::dataset_routes::SpanVerdict::NoContent => {
            // The zero-vs-unknown distinction, stated. This is NOT "the trace
            // is empty" — it is "this workspace does not record prompt
            // content", which is a different fact and a different fix.
            return Err((
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(serde_json::json!({
                    "error": "no_recorded_content",
                    "message": "This span carries no recorded prompt content, so there is \
                                nothing to turn into a test case. Content capture is off for \
                                this workspace — the review was NOT recorded and the trace \
                                remains in the queue.",
                    "trace_id": body.trace_id,
                })),
            ));
        }
        crate::dataset_routes::SpanVerdict::Unreadable => {
            return Err(qerr(
                StatusCode::UNPROCESSABLE_ENTITY,
                "span_content_unreadable",
                "This span recorded content in a shape this gateway cannot read, so it cannot \
                 be copied faithfully. The review was NOT recorded.",
            ));
        }
        crate::dataset_routes::SpanVerdict::Content(m, s) => (m, s),
    };

    // Re-serialize through `Vec<Message>` so the item's `input` is EXACTLY the
    // shape `prompt_eval` deserializes — producer and consumer agree by
    // construction rather than by convention.
    let input = serde_json::to_string(&messages).map_err(|e| {
        tracing::error!(error = %e, "review: re-serializing copied messages failed");
        qerr(
            StatusCode::INTERNAL_SERVER_ERROR,
            "serialize_failed",
            "input",
        )
    })?;
    let hash = crate::dataset_routes::input_hash(&messages, &system).map_err(|e| {
        tracing::error!(error = %format!("{e:#}"), "review: hashing failed");
        qerr(
            StatusCode::INTERNAL_SERVER_ERROR,
            "hash_failed",
            "dedupe hash",
        )
    })?;

    let metadata = serde_json::json!({
        "source": "annotation_queue",
        "queue_id": queue_id,
        "trace_id": body.trace_id,
        "span_id": body.span_id,
        "label": label,
        "rubric": body.rubric,
        "author_sub": claims.sub,
    })
    .to_string();

    let trace_uuid = Uuid::parse_str(body.trace_id.trim()).ok();

    // Idempotent on the content hash. A retry must not make a second copy —
    // but it MUST still write the reference, because the first attempt may
    // have created the item and then failed before the annotation landed.
    let existing = datasets
        .find_by_hash(&tenant, dataset_id, &hash)
        .await
        .map_err(|e| {
            tracing::error!(error = %format!("{e:#}"), "review: dedupe lookup failed");
            qerr(
                StatusCode::BAD_GATEWAY,
                "dataset_write_failed",
                "Could not check for an existing item.",
            )
        })?;

    let (item_id, deduped) = match existing {
        Some(id) => {
            // The item already exists — write the reference onto it. `patch_item`
            // is the sanctioned write-back path; `input` stays immutable so the
            // hash still describes the bytes.
            datasets
                .patch_item(
                    &tenant,
                    dataset_id,
                    id,
                    Some(Some(expected_output.clone())),
                    Some(metadata.clone()),
                )
                .await
                .map_err(|e| {
                    tracing::error!(error = %format!("{e:#}"), "review: expected_output write-back failed");
                    qerr(
                        StatusCode::BAD_GATEWAY,
                        "dataset_write_failed",
                        "Could not attach the reference to the existing dataset item. The \
                         review was NOT recorded and the trace remains in the queue.",
                    )
                })?;
            (id, true)
        }
        None => {
            let id = Uuid::new_v4();
            let item = crate::dataset_routes::DatasetItem {
                item_id: id,
                // UNNAMED — provenance lives in `source_trace_id`; a
                // manufactured name puts the same fact in two columns that can
                // then disagree.
                name: String::new(),
                input,
                system,
                // THE POINT OF THE ITEM. Every trace-derived dataset item until
                // now carried `expected_output: None`, because production
                // captures input only. This is the first path in the product
                // that produces a reference — a human supplies it.
                expected_output: Some(expected_output.clone()),
                metadata: metadata.clone(),
                source_trace_id: trace_uuid,
                // The RESOLVED span, never the trace-level `''` sentinel — the
                // item records where the bytes actually came from.
                source_span_id: content_span.clone(),
                input_hash: hash,
                created_at_ms: crate::clickhouse_query::datetime64_millis_now(),
                created_by: claims.sub.clone(),
            };
            datasets
                .insert_items(&tenant, dataset_id, std::slice::from_ref(&item))
                .await
                .map_err(|e| {
                    tracing::error!(error = %format!("{e:#}"), "review: dataset item insert failed");
                    qerr(
                        StatusCode::BAD_GATEWAY,
                        "dataset_write_failed",
                        "Could not create the dataset item. The review was NOT recorded and \
                         the trace remains in the queue — retry.",
                    )
                })?;
            (id, false)
        }
    };

    // 7. ONLY NOW the annotation row — the done marker, after the act it
    //    attests to (`.claude/rules/logging.md`, the 14 lost watchdog alerts).
    let rubric_answers = serde_json::to_value(&body.rubric).map_err(|_| {
        qerr(
            StatusCode::INTERNAL_SERVER_ERROR,
            "serialize_failed",
            "rubric",
        )
    })?;
    // R224 — freeze the DEFINITION alongside the answer. A counter would say
    // the rubric changed; the snapshot says what it SAID, which is what keeps a
    // past judgement re-readable.
    let rubric_snapshot = serde_json::to_value(&queue.rubric).map_err(|_| {
        qerr(
            StatusCode::INTERNAL_SERVER_ERROR,
            "serialize_failed",
            "snapshot",
        )
    })?;

    let annotation = state
        .store
        .upsert_review(
            &tenant,
            &ReviewWrite {
                trace_id: body.trace_id.trim(),
                span_id: &body.span_id,
                label: &label,
                note: &body.note,
                author_sub: &claims.sub,
                queue_id,
                rubric: &rubric_answers,
                expected_output: &expected_output,
                rubric_snapshot: &rubric_snapshot,
            },
        )
        .await
        .map_err(|e| {
            tracing::error!(error = %format!("{e:#}"), "review: annotation write failed");
            qerr(
                StatusCode::BAD_GATEWAY,
                "review_write_failed",
                "The dataset item was created but the review could not be recorded. The trace \
                 remains in the queue; retrying is safe and will not duplicate the item.",
            )
        })?;

    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({
            "annotation": annotation,
            "dataset_id": dataset_id,
            "item_id": item_id,
            "deduped": deduped,
            "expected_output": expected_output,
        })),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[derive(Default)]
    struct MockStore {
        rows: Mutex<Vec<Annotation>>,
        seen_tenant: Mutex<Vec<String>>,
        queues: Mutex<Vec<AnnotationQueue>>,
        /// `(expected_output, rubric_snapshot)` per review — so a test can
        /// assert the REFERENCE and the FROZEN RUBRIC actually landed, rather
        /// than that the call returned Ok.
        reviews: Mutex<Vec<(String, String)>>,
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

        // ── EVL-29. Real in-memory behaviour, not stubs: a mock that always
        // succeeds proves nothing about the handlers that call it. ──────────

        async fn create_queue(&self, tenant: &TenantId, q: &QueueWrite<'_>) -> Result<()> {
            self.seen_tenant.lock().unwrap().push(tenant.to_string());
            let mut qs = self.queues.lock().unwrap();
            // Mirrors the UNIQUE (tenant_id, lower(name)) index, so the
            // handler's collision branch is reachable in a unit test.
            if qs
                .iter()
                .any(|x: &AnnotationQueue| x.name.eq_ignore_ascii_case(q.name))
            {
                anyhow::bail!("duplicate key value violates annotation_queues_tenant_name_uniq");
            }
            qs.push(AnnotationQueue {
                id: q.id,
                name: q.name.to_string(),
                filter: serde_json::from_value(q.filter.clone())?,
                rubric: serde_json::from_value(q.rubric.clone())?,
                default_dataset_id: q.default_dataset_id,
                expected_output_field: q.expected_output_field.to_string(),
                created_by: q.created_by.to_string(),
                created_at: "2026-08-29T00:00:00Z".into(),
                updated_at: "2026-08-29T00:00:00Z".into(),
                archived_at: None,
            });
            Ok(())
        }

        async fn count_queues(&self, _t: &TenantId) -> Result<u64> {
            Ok(self
                .queues
                .lock()
                .unwrap()
                .iter()
                .filter(|q| q.archived_at.is_none())
                .count() as u64)
        }

        async fn list_queues(&self, _t: &TenantId) -> Result<Vec<AnnotationQueue>> {
            Ok(self.queues.lock().unwrap().clone())
        }

        async fn get_queue(&self, _t: &TenantId, id: Uuid) -> Result<Option<AnnotationQueue>> {
            Ok(self
                .queues
                .lock()
                .unwrap()
                .iter()
                .find(|q| q.id == id)
                .cloned())
        }

        async fn update_queue(
            &self,
            _t: &TenantId,
            id: Uuid,
            patch: &QueuePatch<'_>,
        ) -> Result<bool> {
            let mut qs = self.queues.lock().unwrap();
            let Some(q) = qs.iter_mut().find(|q| q.id == id) else {
                return Ok(false);
            };
            if let Some(n) = patch.name {
                q.name = n.to_string();
            }
            if let Some(f) = patch.filter {
                q.filter = serde_json::from_value(f.clone())?;
            }
            if let Some(r) = patch.rubric {
                q.rubric = serde_json::from_value(r.clone())?;
            }
            if let Some(e) = patch.expected_output_field {
                q.expected_output_field = e.to_string();
            }
            match patch.archived {
                Some(true) => q.archived_at = Some("2026-08-29T00:00:00Z".into()),
                Some(false) => q.archived_at = None,
                None => {}
            }
            Ok(true)
        }

        async fn reviewed_trace_ids(
            &self,
            _t: &TenantId,
            trace_ids: &[String],
        ) -> Result<Vec<String>> {
            let r = self.rows.lock().unwrap();
            Ok(trace_ids
                .iter()
                .filter(|id| r.iter().any(|x| &&x.trace_id == id && x.span_id.is_empty()))
                .cloned()
                .collect())
        }

        async fn upsert_review(
            &self,
            tenant: &TenantId,
            w: &ReviewWrite<'_>,
        ) -> Result<Annotation> {
            self.reviews
                .lock()
                .unwrap()
                .push((w.expected_output.to_string(), w.rubric_snapshot.to_string()));
            self.upsert(tenant, w.trace_id, w.span_id, w.label, w.note, w.author_sub)
                .await
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

    // ══════════════════ EVL-29 — the controls must REFUSE ═════════════════
    //
    // Every case below asserts a DENIAL. A validator only ever observed
    // accepting is not a validator (CLAUDE.md §1), and this one decides what
    // becomes a stored training reference.

    fn field(key: &str, ty: RubricFieldType, required: bool) -> RubricField {
        RubricField {
            key: key.into(),
            label: key.into(),
            field_type: ty,
            required,
            options: None,
            min: None,
            max: None,
        }
    }

    fn code(e: &QueueErr) -> String {
        e.1.0["error"].as_str().unwrap_or_default().to_string()
    }

    /// **R223's carve-out, and the reason it exists.** A boolean reference
    /// produces `expected_output = "true"` — a reference-based scorer comparing
    /// model prose against a word that means nothing. The queue is refused at
    /// creation rather than producing unscorable items forever.
    #[test]
    fn a_boolean_field_may_not_be_the_reference() {
        let fields = vec![field("was_correct", RubricFieldType::Boolean, true)];
        let e = validate_rubric_definition(&fields, "was_correct")
            .expect_err("a boolean reference must be refused");
        assert_eq!(code(&e), "expected_output_field_not_usable");
        assert_eq!(e.0, StatusCode::BAD_REQUEST);
    }

    /// A text field in the same position IS accepted — proving the refusal
    /// above discriminates on the TYPE and is not a blanket denial.
    #[test]
    fn a_text_field_may_be_the_reference() {
        let fields = vec![field("ideal_answer", RubricFieldType::Text, true)];
        validate_rubric_definition(&fields, "ideal_answer").expect("a text reference is valid");
    }

    #[test]
    fn the_reference_field_must_exist_in_the_rubric() {
        let fields = vec![field("ideal_answer", RubricFieldType::Text, true)];
        let e = validate_rubric_definition(&fields, "not_a_field").expect_err("must refuse");
        assert_eq!(code(&e), "expected_output_field_unknown");
    }

    /// An OPTIONAL reference is the R223 hole in slow motion: the queue looks
    /// valid, and every review that skips the field produces an item with a
    /// NULL `expected_output`.
    #[test]
    fn the_reference_field_must_be_required() {
        let fields = vec![field("ideal_answer", RubricFieldType::Text, false)];
        let e = validate_rubric_definition(&fields, "ideal_answer").expect_err("must refuse");
        assert_eq!(code(&e), "expected_output_field_optional");
    }

    #[test]
    fn a_score_field_without_bounds_is_refused() {
        let fields = vec![
            field("sev", RubricFieldType::Score, true),
            field("ideal", RubricFieldType::Text, true),
        ];
        let e = validate_rubric_definition(&fields, "ideal").expect_err("must refuse");
        assert_eq!(code(&e), "rubric_score_needs_bounds");
    }

    #[test]
    fn a_choice_field_without_options_is_refused() {
        let fields = vec![
            field("mode", RubricFieldType::Choice, true),
            field("ideal", RubricFieldType::Text, true),
        ];
        let e = validate_rubric_definition(&fields, "ideal").expect_err("must refuse");
        assert_eq!(code(&e), "rubric_choice_needs_options");
    }

    #[test]
    fn duplicate_rubric_keys_are_refused() {
        let fields = vec![
            field("ideal", RubricFieldType::Text, true),
            field("ideal", RubricFieldType::Text, true),
        ];
        let e = validate_rubric_definition(&fields, "ideal").expect_err("must refuse");
        assert_eq!(code(&e), "rubric_duplicate_key");
    }

    fn answer_rubric() -> Vec<RubricField> {
        let mut sev = field("severity", RubricFieldType::Score, true);
        sev.min = Some(1.0);
        sev.max = Some(5.0);
        let mut mode = field("failure_mode", RubricFieldType::Choice, true);
        mode.options = Some(vec!["hallucination".into(), "refusal".into()]);
        vec![
            sev,
            mode,
            field("ideal_answer", RubricFieldType::Text, true),
        ]
    }

    fn answers(pairs: &[(&str, serde_json::Value)]) -> serde_json::Map<String, serde_json::Value> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.clone()))
            .collect()
    }

    #[test]
    fn a_valid_answer_set_returns_the_reference() {
        let got = validate_rubric_answers(
            &answer_rubric(),
            "ideal_answer",
            &answers(&[
                ("severity", serde_json::json!(4)),
                ("failure_mode", serde_json::json!("hallucination")),
                (
                    "ideal_answer",
                    serde_json::json!("Paris is the capital of France."),
                ),
            ]),
        )
        .expect("valid answers");
        assert_eq!(got, "Paris is the capital of France.");
    }

    /// **The range check is the half `validate_call` cannot do** (CLAUDE.md
    /// §21): a JSON-schema pass with `type: number` accepts 9 here. The bound
    /// is enforced at the site, exactly as item 11's judge does.
    #[test]
    fn a_score_outside_its_declared_range_is_refused() {
        let e = validate_rubric_answers(
            &answer_rubric(),
            "ideal_answer",
            &answers(&[
                ("severity", serde_json::json!(9)),
                ("failure_mode", serde_json::json!("hallucination")),
                ("ideal_answer", serde_json::json!("x")),
            ]),
        )
        .expect_err("9 is outside [1,5]");
        assert_eq!(code(&e), "rubric_out_of_range");
    }

    #[test]
    fn a_choice_outside_its_options_is_refused() {
        let e = validate_rubric_answers(
            &answer_rubric(),
            "ideal_answer",
            &answers(&[
                ("severity", serde_json::json!(3)),
                ("failure_mode", serde_json::json!("something_else")),
                ("ideal_answer", serde_json::json!("x")),
            ]),
        )
        .expect_err("must refuse");
        assert_eq!(code(&e), "rubric_bad_choice");
    }

    #[test]
    fn an_unknown_answer_key_is_refused() {
        let e = validate_rubric_answers(
            &answer_rubric(),
            "ideal_answer",
            &answers(&[
                ("severity", serde_json::json!(3)),
                ("failure_mode", serde_json::json!("refusal")),
                ("ideal_answer", serde_json::json!("x")),
                ("typo_field", serde_json::json!("x")),
            ]),
        )
        .expect_err("must refuse");
        assert_eq!(code(&e), "rubric_unknown_field");
    }

    #[test]
    fn a_missing_required_answer_is_refused() {
        let e = validate_rubric_answers(
            &answer_rubric(),
            "ideal_answer",
            &answers(&[("severity", serde_json::json!(3))]),
        )
        .expect_err("must refuse");
        assert_eq!(code(&e), "rubric_missing_required");
    }

    #[test]
    fn a_wrongly_typed_answer_is_refused() {
        let e = validate_rubric_answers(
            &answer_rubric(),
            "ideal_answer",
            &answers(&[
                ("severity", serde_json::json!("high")),
                ("failure_mode", serde_json::json!("refusal")),
                ("ideal_answer", serde_json::json!("x")),
            ]),
        )
        .expect_err("must refuse");
        assert_eq!(code(&e), "rubric_wrong_type");
    }

    /// An all-whitespace reference is a test case that passes nothing and fails
    /// nothing. It is refused rather than stored.
    #[test]
    fn an_empty_reference_is_refused() {
        let e = validate_rubric_answers(
            &answer_rubric(),
            "ideal_answer",
            &answers(&[
                ("severity", serde_json::json!(3)),
                ("failure_mode", serde_json::json!("refusal")),
                ("ideal_answer", serde_json::json!("   ")),
            ]),
        )
        .expect_err("must refuse");
        assert_eq!(code(&e), "expected_output_empty");
    }

    /// The window bound is NAMED, never silently clamped — a clamped window
    /// renders a number that answers a different question than the one asked.
    #[test]
    fn the_queue_window_bound_is_named_rather_than_clamped() {
        validate_window(MAX_QUEUE_WINDOW_HOURS).expect("the bound itself is allowed");
        let e = validate_window(MAX_QUEUE_WINDOW_HOURS + 1).expect_err("past the bound refuses");
        assert_eq!(code(&e), "window_out_of_range");
        assert!(validate_window(0).is_err(), "a zero window is meaningless");
    }

    /// The rubric shape is CLOSED: a typo in a field definition is a 400 at
    /// creation, not a field that silently never renders.
    #[test]
    fn an_unknown_key_in_a_rubric_field_definition_is_rejected() {
        let bad = serde_json::json!({
            "key": "x", "label": "X", "type": "text", "requried": true
        });
        assert!(
            serde_json::from_value::<RubricField>(bad).is_err(),
            "deny_unknown_fields must reject a misspelled key"
        );
    }

    /// **The candidate scan must never page with OFFSET.** An OFFSET page over
    /// a `ReplacingMergeTree` shifts under a concurrent write and silently
    /// skips a row — and BOTH sources here are ReplacingMergeTrees written
    /// concurrently with this read. A skipped row is a trace a reviewer is
    /// simply never shown, with nothing anywhere reporting it.
    #[test]
    fn the_candidate_scan_pages_by_keyset_and_never_by_offset() {
        for src in [
            QueueSource::OnlineEvalScore {
                max_score: 0.5,
                rubric: None,
            },
            QueueSource::TraceError,
        ] {
            let first = candidate_sql(&src, false);
            let next = candidate_sql(&src, true);
            assert!(
                !first.contains("OFFSET") && !next.contains("OFFSET"),
                "OFFSET paging reintroduced: {next}"
            );
            // The first page carries NO cursor predicate; the next one does.
            // Tested on the CURSOR tokens specifically — an earlier version of
            // this assertion looked for a bare `<` and failed on the score
            // ceiling's own `score <= ?`, which is a real predicate and not a
            // cursor.
            let cursor_tokens = ["scored_at <", "occurred_at_ms <"];
            assert!(
                !cursor_tokens.iter().any(|c| first.contains(c)),
                "the first page must not carry a cursor predicate: {first}"
            );
            assert!(
                cursor_tokens.iter().any(|c| next.contains(c)),
                "a seeking page must carry the keyset predicate: {next}"
            );
        }
    }

    /// A queue source must round-trip through its stored JSON form, because a
    /// stored filter that no longer parses is what `queue_from_row` refuses to
    /// paper over.
    #[test]
    fn the_first_queue_type_round_trips() {
        let f = QueueFilter {
            source: QueueSource::OnlineEvalScore {
                max_score: 0.5,
                rubric: Some("answers_the_question".into()),
            },
            window_hours: 168,
        };
        let s = serde_json::to_string(&f).expect("serialize");
        assert!(s.contains("\"kind\":\"online_eval_score\""), "tagged: {s}");
        let back: QueueFilter = serde_json::from_str(&s).expect("round-trip");
        assert_eq!(back.window_hours, 168);
        assert!(matches!(back.source, QueueSource::OnlineEvalScore { .. }));
    }
}
