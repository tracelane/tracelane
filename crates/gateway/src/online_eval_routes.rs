//! HTTP surface for online evals (`EVL-28`, Sprint 3 item 11).
//!
//! The gateway VERTICAL — admission sampling, the fire-and-forget judge, the
//! two-counter cap — shipped in `online_eval.rs` and was **inert by
//! construction**: with no way to create a policy, `admission()` returned `None`
//! for every request, so nothing sampled and nothing spent. This module is what
//! makes it reachable, and that is the reason to read it carefully rather than
//! as boilerplate: **it is the first surface in this tree where a bad write
//! spends a customer's money without anyone asking.**
//!
//! ## The two-layer shape, and which layer is load-bearing
//!
//! Every money-relevant rule here exists TWICE — once as a named refusal in
//! `validate_policy`, once as a CHECK constraint in Neon migration 0031:
//!
//! | Rule | Route says | Schema says |
//! |---|---|---|
//! | a cap is required | `400 budget_required` | `judge_budget_usd_monthly NOT NULL`, **no default** |
//! | a cap of 0 is not a cap | `400 invalid_budget` | `..._budget_positive_chk` |
//! | the sample-rate ceiling | `400 invalid_sample_rate` | `..._sample_rate_chk (0.0 .. 0.10)` |
//! | the rubric-kind vocabulary | `400 unsupported_rubric_kind` | `..._rubric_kind_chk` |
//!
//! **They are not redundant and the duplication is the point.** The schema is
//! what holds when the writer is not this route — a backfill, a support script,
//! a future admin surface. The route is the only layer a USER ever sees, and a
//! raw `null value in column "judge_budget_usd_monthly" violates not-null
//! constraint` is not an error message anyone should be shown. So: refuse with a
//! named reason BEFORE the insert, and let the constraint catch everyone who is
//! not us.
//!
//! ## Two refusals the SCHEMA CANNOT make, and they are not decoration
//!
//! Both would create a policy that samples correctly and then errors on **every
//! single judge call** — spending nothing, scoring nothing, and looking exactly
//! like "no traffic":
//!
//! 1. **`rubric_kind = "prompt_version"`.** The table's CHECK admits it; the
//!    judge path does not — `online_eval::judge_one` bails with *"not resolvable
//!    from the online path yet"*. Accepting it here would store a policy whose
//!    every score is `errored`.
//! 2. **An unroutable `judge_model`.** `provider_id_for_model` fails closed
//!    (there is no default provider), so an unknown model is an error per sample
//!    rather than a refusal once.
//!
//! A constraint cannot know either fact. That asymmetry is why the route is a
//! real layer and not a nicer-looking copy of the schema.
//!
//! ## The salt is ours, never the caller's
//!
//! `sample_salt` is generated server-side on first write and **preserved across
//! updates**. It is not a settable field: a caller who could choose it could
//! choose which traces get scored, and "1% sampled" would stop being a sample.
//! Preserving it across an update means changing the RATE keeps the same trace
//! set at the low end rather than reshuffling — a customer who lowers 5% to 1%
//! keeps a subset of what they already had, which is what makes the two numbers
//! on the surface comparable over time.
//!
//! ## Tenancy
//!
//! `tenant_id` comes only from the validated claim. Every read and write binds
//! it. There is no path, query or body field that can name a workspace.

use std::sync::Arc;

use axum::{
    Json, Router,
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    routing::get,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::auth::Claims;
use crate::entitlement_cache::{EntitlementCache, FeatureKey};
use tracelane_shared::TenantId;

/// The founder-set ceiling on coverage (R208). Mirrored by
/// `online_eval_policies_sample_rate_chk`. Named here so the 400 can quote it
/// rather than hard-coding the number in a message string.
const MAX_SAMPLE_RATE: f64 = 0.10;

/// Longest window a summary or score list may ask for, hours.
///
/// 90 days, matching the retention the scores table is partitioned for. A
/// request past it is refused naming the bound rather than silently clamped: a
/// clamped window renders a number that answers a different question than the
/// one asked.
const MAX_WINDOW_HOURS: u32 = 24 * 90;
const DEFAULT_WINDOW_HOURS: u32 = 24;

/// Cap on a returned score page.
const MAX_SCORE_ROWS: u32 = 200;
const DEFAULT_SCORE_ROWS: u32 = 50;

#[derive(Clone)]
pub struct OnlineEvalRoutesState {
    pub pool: deadpool_postgres::Pool,
    /// The `f_online_evals` gate. **Not an `Option`** — this state is only
    /// constructed when the cache exists, and the mount site refuses otherwise.
    /// `.claude/rules/tenancy.md`: an absent cache is the UNPRIVILEGED state,
    /// and this one also spends money.
    pub entitlements: Arc<EntitlementCache>,
    /// `None` when `CLICKHOUSE_URL` is unset. The score reads then answer a
    /// typed `503` saying the deployment is not configured for them, rather
    /// than 404ing as though the feature did not exist — a feature that is
    /// configured-off and a feature that is absent are different facts.
    pub clickhouse_url: Option<String>,
}

pub fn routes() -> Router<OnlineEvalRoutesState> {
    Router::new()
        .route(
            "/v1/online-evals/policy",
            get(get_policy_handler)
                .post(upsert_policy_handler)
                .delete(disable_policy_handler),
        )
        .route("/v1/online-evals/scores", get(scores_handler))
        .route("/v1/online-evals/summary", get(summary_handler))
}

// ─────────────────────────────── errors ────────────────────────────────────

type ApiError = (StatusCode, Json<serde_json::Value>);

/// A typed refusal: a machine-readable `error` code plus a message a human can
/// act on. Never a bare string — the dashboard branches on the code, and
/// `role-403-as-generic-failure` is the class where a proxy collapsed every
/// non-ok upstream into one message and discarded the discriminator.
fn err(status: StatusCode, code: &str, message: impl Into<String>) -> ApiError {
    (
        status,
        Json(serde_json::json!({ "error": code, "message": message.into() })),
    )
}

async fn claims_from_auth(headers: &HeaderMap) -> Result<Claims, ApiError> {
    let h = headers.get("authorization").ok_or_else(|| {
        err(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "missing Authorization header",
        )
    })?;
    let s = h.to_str().map_err(|_| {
        err(
            StatusCode::BAD_REQUEST,
            "bad_request",
            "Authorization must be ASCII",
        )
    })?;
    crate::auth::validate_authorization(s).await.map_err(|e| {
        err(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            format!("auth failed: {e}"),
        )
    })
}

/// The `f_online_evals` gate. Applies to READS as well as writes.
///
/// **Deliberately not read-open.** Every other read surface in this tree is
/// open to any authenticated tenant, and this one is not, because the numbers it
/// returns only exist if the workspace is paying for the feature that produces
/// them: an unentitled workspace reading `/summary` gets an empty result that is
/// indistinguishable from "enabled and quiet", which is the exact confusion §4
/// of the spec exists to prevent.
async fn require_entitled(
    state: &OnlineEvalRoutesState,
    tenant: &TenantId,
) -> Result<(), ApiError> {
    if state
        .entitlements
        .check(*tenant.as_uuid(), FeatureKey::OnlineEvals)
        .await
    {
        return Ok(());
    }
    Err((
        StatusCode::FORBIDDEN,
        Json(serde_json::json!({
            "error": "entitlement_required",
            "feature": "online_evals",
            "message": "Online evals require a plan that includes them.",
            "upgrade_url": "https://app.tracelane.dev/settings/billing",
        })),
    ))
}

/// Who may CHANGE a policy that spends money.
///
/// `can_write_prompts` is reused rather than re-derived: it is already the
/// "may this caller change what runs in production" bar — an owner/admin human,
/// or a machine credential, and a `member`/`viewer` never. A viewer being able
/// to switch on a money path would be the A8/EVL-18 defect in a more expensive
/// place.
fn require_writer(claims: &Claims) -> Result<(), ApiError> {
    if claims.can_write_prompts() {
        return Ok(());
    }
    // `role_forbidden_json` returns a fully-formed OBJECT. Parse it back rather
    // than wrapping it in another `{"error": …}` — double-encoding is the
    // prod-observed defect `prompt_routes::write_err` documents, where
    // `required_role` arrived escaped inside a string.
    let body: serde_json::Value = serde_json::from_str(&crate::auth::role_forbidden_json("owner"))
        .unwrap_or_else(|_| serde_json::json!({ "error": "role_forbidden" }));
    Err((StatusCode::FORBIDDEN, Json(body)))
}

// ─────────────────────────────── the policy ────────────────────────────────

#[derive(Debug, Serialize)]
pub struct PolicyDto {
    pub id: Uuid,
    pub enabled: bool,
    pub rubric_kind: String,
    pub rubric: String,
    pub judge_model: String,
    pub sample_rate: f64,
    pub judge_budget_usd_monthly: f64,
    pub created_at: String,
    pub updated_at: String,
    // `sample_salt` is deliberately NOT returned. It is a sampling-integrity
    // secret: anyone who knows it can compute, offline, exactly which of their
    // trace ids will be scored — and therefore which to route elsewhere. The
    // determinism the salt buys is FOR the customer (they can re-run the same
    // set through us); it is not an invitation to pre-compute around it.
}

#[derive(Debug, Serialize)]
struct PolicyEnvelope {
    /// `null` when this workspace has never configured one. Distinct from a
    /// disabled policy, which is present with `enabled: false` — §4's
    /// "never had data" and "configured off" are different states and the
    /// surface renders them differently.
    policy: Option<PolicyDto>,
    /// The ceiling the caller may not exceed, echoed so the UI can bound its own
    /// control instead of hard-coding a number that drifts from the CHECK.
    max_sample_rate: f64,
    built_in_rubrics: Vec<&'static str>,
}

#[derive(Debug, Deserialize)]
pub struct UpsertPolicyBody {
    /// **Required. There is deliberately no default anywhere in this system.**
    /// `Option` here so its absence produces a NAMED 400 rather than a serde
    /// "missing field" 422 — the whole reason this route exists is to be the
    /// one place the no-default rule is legible to a human.
    #[serde(default)]
    pub judge_budget_usd_monthly: Option<f64>,
    #[serde(default)]
    pub sample_rate: Option<f64>,
    #[serde(default)]
    pub rubric_kind: Option<String>,
    #[serde(default)]
    pub rubric: Option<String>,
    #[serde(default)]
    pub judge_model: Option<String>,
    #[serde(default)]
    pub enabled: Option<bool>,
}

/// The whole of the write-side refusal logic, factored out so the unit tests
/// drive exactly what the handler drives.
///
/// Returns the validated tuple in insert order.
///
/// # Errors
/// A typed `400` naming the field and the bound, for every rule. Fail-CLOSED on
/// all of them: this is a money path, and an unvalidated field here is a policy
/// that spends.
fn validate_policy(
    body: &UpsertPolicyBody,
) -> Result<(f64, f64, String, String, String, bool), ApiError> {
    // ── THE CAP. First, because it is the one that matters. ─────────────────
    let Some(budget) = body.judge_budget_usd_monthly else {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "budget_required",
            "judge_budget_usd_monthly is required — an online-eval policy has no default \
             spend ceiling, because a policy that can spend without one is how a customer \
             meets eval spend for the first time on an invoice. Set a monthly USD cap.",
        ));
    };
    if !budget.is_finite() || budget <= 0.0 {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "invalid_budget",
            "judge_budget_usd_monthly must be a finite number greater than 0. A cap of 0 is \
             not a cap — use `enabled: false` to switch scoring off.",
        ));
    }

    // ── COVERAGE. The tenant's judgement, inside our ceiling. ───────────────
    let rate = body.sample_rate.unwrap_or(0.01);
    if !rate.is_finite() || rate <= 0.0 || rate > MAX_SAMPLE_RATE {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "invalid_sample_rate",
            format!(
                "sample_rate must be greater than 0 and at most {MAX_SAMPLE_RATE} \
                 ({:.0}% of requests). Coverage is your judgement; volume is our exposure.",
                MAX_SAMPLE_RATE * 100.0
            ),
        ));
    }

    // ── THE RUBRIC. Two refusals the SCHEMA CANNOT MAKE. ────────────────────
    let rubric_kind = body.rubric_kind.clone().unwrap_or_else(|| "builtin".into());
    if rubric_kind != "builtin" {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "unsupported_rubric_kind",
            "rubric_kind must be \"builtin\". The table admits \"prompt_version\", but the \
             online judge path cannot resolve one yet — storing such a policy would sample \
             correctly and then error on every score, which reads on the surface exactly \
             like no traffic.",
        ));
    }
    let rubric = body
        .rubric
        .clone()
        .unwrap_or_else(|| "answers_the_question".into());
    if crate::prompt_eval::judge::built_in(&rubric).is_none() {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "unknown_rubric",
            format!(
                "unknown built-in rubric {rubric:?} — expected one of: {}",
                crate::prompt_eval::judge::BUILT_IN_NAMES.join(", ")
            ),
        ));
    }

    // ── THE JUDGE MODEL. Routable, checked once here rather than failing per
    //    sample. Same fail-closed map the chat path uses: there is no default
    //    provider, so an unknown model has nowhere to go.
    let judge_model = body
        .judge_model
        .clone()
        .unwrap_or_else(|| "claude-haiku-4-5-20251001".into());
    if crate::providers::ProviderRegistry::provider_id_for_model(&judge_model).is_none() {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "unroutable_model",
            format!(
                "judge_model {judge_model:?} does not map to any provider. The judge runs on \
                 your own provider key, so the model must be one this gateway can route."
            ),
        ));
    }

    Ok((
        budget,
        rate,
        rubric_kind,
        rubric,
        judge_model,
        body.enabled.unwrap_or(true),
    ))
}

fn row_to_dto(row: &tokio_postgres::Row) -> PolicyDto {
    let created: chrono::DateTime<chrono::Utc> = row.get("created_at");
    let updated: chrono::DateTime<chrono::Utc> = row.get("updated_at");
    PolicyDto {
        id: row.get("id"),
        enabled: row.get("enabled"),
        rubric_kind: row.get("rubric_kind"),
        rubric: row.get("rubric"),
        judge_model: row.get("judge_model"),
        sample_rate: row.get("sample_rate"),
        judge_budget_usd_monthly: row.get("judge_budget_usd_monthly"),
        // RFC3339 with an explicit `Z`. A naive `to_string()` here is the
        // `naive-timestamp-local-parse` defect: the dashboard's `new Date()`
        // reads an unzoned string as LOCAL and shifts it per viewer.
        created_at: created.to_rfc3339(),
        updated_at: updated.to_rfc3339(),
    }
}

/// Named columns, in one place, so the `SELECT` and the `RETURNING` cannot
/// disagree — and so `row.get` is BY NAME everywhere. A positional read
/// mis-slots every field after it, which on this table would mis-state a
/// spending cap.
const POLICY_COLS: &str = "id, enabled, rubric_kind, rubric, judge_model, sample_rate, \
                           judge_budget_usd_monthly, created_at, updated_at";

#[tracing::instrument(skip_all, fields(tenant_id = tracing::field::Empty))]
async fn get_policy_handler(
    State(state): State<OnlineEvalRoutesState>,
    headers: HeaderMap,
) -> Result<Json<PolicyEnvelope>, ApiError> {
    let claims = claims_from_auth(&headers).await?;
    tracing::Span::current().record("tenant_id", claims.tenant_id.to_string());
    require_entitled(&state, &claims.tenant_id).await?;

    let client = state.pool.get().await.map_err(|e| {
        tracing::error!(error = %e, "online-eval policy read: pool");
        err(
            StatusCode::BAD_GATEWAY,
            "policy_read_failed",
            "could not read the online-eval policy",
        )
    })?;
    let row = client
        .query_opt(
            &format!("SELECT {POLICY_COLS} FROM online_eval_policies WHERE tenant_id = $1"),
            &[claims.tenant_id.as_uuid()],
        )
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "online-eval policy read");
            err(
                StatusCode::BAD_GATEWAY,
                "policy_read_failed",
                "could not read the online-eval policy",
            )
        })?;

    Ok(Json(PolicyEnvelope {
        policy: row.as_ref().map(row_to_dto),
        max_sample_rate: MAX_SAMPLE_RATE,
        built_in_rubrics: crate::prompt_eval::judge::BUILT_IN_NAMES.to_vec(),
    }))
}

#[tracing::instrument(skip_all, fields(tenant_id = tracing::field::Empty))]
async fn upsert_policy_handler(
    State(state): State<OnlineEvalRoutesState>,
    headers: HeaderMap,
    Json(body): Json<UpsertPolicyBody>,
) -> Result<Json<PolicyDto>, ApiError> {
    let claims = claims_from_auth(&headers).await?;
    tracing::Span::current().record("tenant_id", claims.tenant_id.to_string());
    require_entitled(&state, &claims.tenant_id).await?;
    require_writer(&claims)?;
    let (budget, rate, rubric_kind, rubric, judge_model, enabled) = validate_policy(&body)?;

    let client = state.pool.get().await.map_err(|e| {
        tracing::error!(error = %e, "online-eval policy write: pool");
        err(
            StatusCode::BAD_GATEWAY,
            "policy_write_failed",
            "could not save the online-eval policy",
        )
    })?;

    // ONE statement, and the salt clause is the interesting half:
    // `EXCLUDED.sample_salt` is used only on INSERT; on CONFLICT the stored
    // salt is kept (`online_eval_policies.sample_salt`), so an edit does not
    // reshuffle which traces are sampled. Lowering a rate then keeps a SUBSET
    // of the traces the old rate selected, which is what makes the surface's
    // configured-vs-achieved pair comparable across an edit.
    let salt = Uuid::new_v4().to_string();
    let row = client
        .query_one(
            &format!(
                "INSERT INTO online_eval_policies
                     (tenant_id, enabled, rubric_kind, rubric, judge_model,
                      sample_rate, sample_salt, judge_budget_usd_monthly)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                 ON CONFLICT (tenant_id) DO UPDATE SET
                     enabled                  = EXCLUDED.enabled,
                     rubric_kind              = EXCLUDED.rubric_kind,
                     rubric                   = EXCLUDED.rubric,
                     judge_model              = EXCLUDED.judge_model,
                     sample_rate              = EXCLUDED.sample_rate,
                     judge_budget_usd_monthly = EXCLUDED.judge_budget_usd_monthly,
                     sample_salt              = online_eval_policies.sample_salt,
                     updated_at               = now()
                 RETURNING {POLICY_COLS}"
            ),
            &[
                claims.tenant_id.as_uuid(),
                &enabled,
                &rubric_kind,
                &rubric,
                &judge_model,
                &rate,
                &salt,
                &budget,
            ],
        )
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "online-eval policy upsert");
            err(
                StatusCode::BAD_GATEWAY,
                "policy_write_failed",
                "could not save the online-eval policy",
            )
        })?;

    // The cache is what the hot path reads, and its TTL is 900s. Without this an
    // enable would take up to fifteen minutes to take effect and a DISABLE would
    // keep spending for the same fifteen — which is the direction that costs
    // money, so the invalidation is not a nicety.
    crate::online_eval::invalidate(&claims.tenant_id).await;

    tracing::info!(
        tenant_id = %claims.tenant_id,
        enabled, rate, budget,
        "online-eval policy saved"
    );
    Ok(Json(row_to_dto(&row)))
}

/// `DELETE` = **disable**, not destroy.
///
/// The row is kept with `enabled = false` so the salt survives. Deleting it
/// would mean a re-enable draws a brand-new salt and therefore a completely
/// different trace set — a customer who switched off for a week and back on
/// would silently lose comparability with everything they had scored before.
/// Turning something off should not quietly change what it means.
#[tracing::instrument(skip_all, fields(tenant_id = tracing::field::Empty))]
async fn disable_policy_handler(
    State(state): State<OnlineEvalRoutesState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, ApiError> {
    let claims = claims_from_auth(&headers).await?;
    tracing::Span::current().record("tenant_id", claims.tenant_id.to_string());
    require_entitled(&state, &claims.tenant_id).await?;
    require_writer(&claims)?;

    let client = state.pool.get().await.map_err(|e| {
        tracing::error!(error = %e, "online-eval policy disable: pool");
        err(
            StatusCode::BAD_GATEWAY,
            "policy_write_failed",
            "could not disable the online-eval policy",
        )
    })?;
    let n = client
        .execute(
            "UPDATE online_eval_policies SET enabled = false, updated_at = now()
              WHERE tenant_id = $1",
            &[claims.tenant_id.as_uuid()],
        )
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "online-eval policy disable");
            err(
                StatusCode::BAD_GATEWAY,
                "policy_write_failed",
                "could not disable the online-eval policy",
            )
        })?;
    crate::online_eval::invalidate(&claims.tenant_id).await;
    Ok(Json(serde_json::json!({ "disabled": n > 0 })))
}

// ─────────────────────────────── the scores ────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct WindowQuery {
    #[serde(default)]
    hours: Option<u32>,
    #[serde(default)]
    limit: Option<u32>,
    /// Optional single-trace filter — what the trace detail panel asks for.
    #[serde(default)]
    trace_id: Option<String>,
}

fn window_hours(q: &WindowQuery) -> Result<u32, ApiError> {
    let h = q.hours.unwrap_or(DEFAULT_WINDOW_HOURS);
    if h == 0 || h > MAX_WINDOW_HOURS {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "invalid_window",
            format!("hours must be between 1 and {MAX_WINDOW_HOURS} (90 days)"),
        ));
    }
    Ok(h)
}

fn require_ch(state: &OnlineEvalRoutesState) -> Result<String, ApiError> {
    state.clickhouse_url.clone().ok_or_else(|| {
        err(
            StatusCode::SERVICE_UNAVAILABLE,
            "online_evals_unavailable",
            "This deployment has no results store configured, so online-eval scores cannot \
             be read.",
        )
    })
}

#[derive(Debug, Serialize, serde::Deserialize, clickhouse::Row)]
pub struct ScoreDto {
    pub trace_id: String,
    pub span_id: String,
    pub rubric: String,
    pub judge_model: String,
    pub status: String,
    /// `None` = UNKNOWN, never 0. A judge whose response failed validation
    /// produces `status = "errored"` and NO score — rendering a 0 would be the
    /// §21 failure this whole feature sits downstream of.
    pub score: Option<f64>,
    pub verdict: String,
    pub reason: String,
    pub error: Option<String>,
    /// `None` = an unpriced model, never 0.
    pub cost_usd: Option<f64>,
    pub latency_ms: u32,
    /// Millis since epoch, UTC. Rendered by the client; see `format-date.ts`.
    pub scored_at: i64,
}

#[derive(Debug, Serialize)]
struct ScoresResponse {
    window_hours: u32,
    scores: Vec<ScoreDto>,
}

#[tracing::instrument(skip_all, fields(tenant_id = tracing::field::Empty))]
async fn scores_handler(
    State(state): State<OnlineEvalRoutesState>,
    Query(q): Query<WindowQuery>,
    headers: HeaderMap,
) -> Result<Json<ScoresResponse>, ApiError> {
    let claims = claims_from_auth(&headers).await?;
    tracing::Span::current().record("tenant_id", claims.tenant_id.to_string());
    require_entitled(&state, &claims.tenant_id).await?;
    let hours = window_hours(&q)?;
    let limit = q
        .limit
        .unwrap_or(DEFAULT_SCORE_ROWS)
        .clamp(1, MAX_SCORE_ROWS);
    let url = require_ch(&state)?;

    // FINAL: `online_eval_scores` is a ReplacingMergeTree keyed on
    // (tenant, trace, policy). Without it a retried insert renders twice until
    // a background merge happens to run, and "how many did we score" is the
    // number this table exists to answer.
    //
    // Every value is BOUND, never interpolated — `?` placeholders through the
    // ADR-031 cap wrapper, which is also what `no-raw-ch-query.sh` requires.
    let trace_filter = if q.trace_id.is_some() {
        "AND trace_id = ?"
    } else {
        ""
    };
    let sql = crate::clickhouse_query::TenantQuery::new(
        format!(
            "SELECT trace_id, span_id, rubric, judge_model, status, score, verdict, reason, \
                    error, cost_usd, latency_ms, toUnixTimestamp64Milli(scored_at) AS scored_at \
               FROM online_eval_scores FINAL \
              WHERE tenant_id = ? AND scored_at >= now() - toIntervalHour(?) {trace_filter} \
              ORDER BY scored_at DESC LIMIT ?"
        ),
        crate::clickhouse_query::PlanTier::Builder,
    )
    .sql_with_settings();

    let mut query = crate::clickhouse_query::ch_client(url)
        .query(&sql)
        .bind(claims.tenant_id.to_string())
        .bind(hours);
    if let Some(ref t) = q.trace_id {
        query = query.bind(t.clone());
    }
    let scores = query
        .bind(limit)
        .fetch_all::<ScoreDto>()
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "online-eval score read failed");
            err(
                StatusCode::BAD_GATEWAY,
                "score_read_failed",
                "could not read online-eval scores",
            )
        })?;

    Ok(Json(ScoresResponse {
        window_hours: hours,
        scores,
    }))
}

// ─────────────────────────── the summary numbers ───────────────────────────

#[derive(Debug, serde::Deserialize, clickhouse::Row)]
struct SummaryRow {
    scored: u64,
    errored: u64,
    sampled_traces: u64,
    mean_score: Option<f64>,
    judge_cost_usd: Option<f64>,
}

#[derive(Debug, serde::Deserialize, clickhouse::Row)]
struct EligibleRow {
    eligible: u64,
}

/// The surface's numbers, and the shape is the whole point.
///
/// **`configured_sample_rate` and `achieved_sample_rate` are two DIFFERENT
/// facts and both are always sent.** Configured is the policy. Achieved is
/// counted — sampled traces over eligible chat spans in the same window. Since
/// sampling is a keyed hash rather than an exact 1-in-N counter, the realised
/// rate WILL differ from the setting over any finite window, and a customer who
/// sets 1% and sees 0.7% must be able to read that as expected rather than as
/// drift. Sending only the setting hides a real observation; sending only the
/// realised rate fabricates the setting.
///
/// **`achieved_sample_rate` is `None` when `eligible == 0`.** A quiet window and
/// a broken sampler must not render identically, and `0 / 0` presented as
/// "0.0%" is exactly that collision. The surface renders `null` as "no traffic
/// in this window".
///
/// **`eligible_spans` counts only requests the sampler COULD have taken.** It
/// excludes eval work and — B-296 — responses served from the semantic cache,
/// which return before the judge hook and can never be scored. Counting an
/// unsamplable request would understate coverage without bound: measured on
/// prod, 193 of 222 traces were cache hits, and including them reported 1.35%
/// against a configured 10% when the sampler was actually achieving 10.34%.
#[derive(Debug, Serialize)]
struct SummaryResponse {
    window_hours: u32,
    /// `null` when no policy has ever been configured.
    configured_sample_rate: Option<f64>,
    enabled: bool,
    /// `null` = we could not compute it because nothing was eligible. NEVER 0.
    achieved_sample_rate: Option<f64>,
    eligible_spans: u64,
    sampled_traces: u64,
    scored: u64,
    errored: u64,
    /// `null` when nothing scored — never 0.0, which would read as "everything
    /// failed" rather than "nothing ran".
    mean_score: Option<f64>,
    /// Judge spend this window, summed from the durable rows. `null` when every
    /// row was unpriced.
    judge_cost_usd: Option<f64>,
    /// The policy's monthly ceiling — `null` with no policy.
    judge_budget_usd_monthly: Option<f64>,
}

#[tracing::instrument(skip_all, fields(tenant_id = tracing::field::Empty))]
async fn summary_handler(
    State(state): State<OnlineEvalRoutesState>,
    Query(q): Query<WindowQuery>,
    headers: HeaderMap,
) -> Result<Json<SummaryResponse>, ApiError> {
    let claims = claims_from_auth(&headers).await?;
    tracing::Span::current().record("tenant_id", claims.tenant_id.to_string());
    require_entitled(&state, &claims.tenant_id).await?;
    let hours = window_hours(&q)?;
    let url = require_ch(&state)?;

    // The policy half — Postgres. A missing policy is not an error: it is the
    // "never configured" state, and the summary still reports the traffic.
    let (configured, enabled, budget) = match state.pool.get().await {
        Ok(client) => client
            .query_opt(
                "SELECT sample_rate, enabled, judge_budget_usd_monthly \
                   FROM online_eval_policies WHERE tenant_id = $1",
                &[claims.tenant_id.as_uuid()],
            )
            .await
            .ok()
            .flatten()
            .map_or((None, false, None), |r| {
                (Some(r.get(0)), r.get(1), Some(r.get(2)))
            }),
        Err(e) => {
            tracing::error!(error = %e, "online-eval summary: pool");
            (None, false, None)
        }
    };

    let ch = crate::clickhouse_query::ch_client(url);

    let scores_sql = crate::clickhouse_query::TenantQuery::new(
        "SELECT toUInt64(countIf(status = 'scored')) AS scored, \
                toUInt64(countIf(status = 'errored')) AS errored, \
                toUInt64(uniqExact(trace_id)) AS sampled_traces, \
                avgIf(score, score IS NOT NULL) AS mean_score, \
                sum(cost_usd) AS judge_cost_usd \
           FROM online_eval_scores FINAL \
          WHERE tenant_id = ? AND scored_at >= now() - toIntervalHour(?)",
        crate::clickhouse_query::PlanTier::Builder,
    )
    .sql_with_settings();
    let s = ch
        .query(&scores_sql)
        .bind(claims.tenant_id.to_string())
        .bind(hours)
        .fetch_one::<SummaryRow>()
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "online-eval summary score read failed");
            err(
                StatusCode::BAD_GATEWAY,
                "summary_read_failed",
                "could not read online-eval scores",
            )
        })?;

    // ── THE DENOMINATOR. COUNTED, and it must be the population the sampler
    //    ACTUALLY DREW FROM — anything wider makes "achieved" a smaller number
    //    than the truth and reads as a broken sampler.
    //
    // `name = 'gen_ai.chat'` is the span `admission()` decides on, so OTLP-direct
    // and non-chat work is correctly out.
    //
    // **`tracelane_eval_run_id = ''` is the half that is easy to miss and was
    // wrong here first.** Eval work emits `gen_ai.chat` spans too — the offline
    // eval engine's cases, and, since this feature, THE JUDGE'S OWN CALL. Judge
    // spans are the sharp case: every sample this policy takes produces one, so
    // counting them would grow the denominator in proportion to the numerator
    // and push the achieved rate DOWN exactly as coverage went up. A customer
    // would watch their realised rate sag as the feature started working.
    // `admission()` is only ever reached from `chat_completions_handler`, so no
    // span carrying an eval-run id was ever a candidate. Same predicate
    // `CostScope::Production` uses, for the same reason.
    //
    // ── AND `tracelane_semantic_cache_hit` — B-296, MEASURED ON PROD ────────
    //
    // **A request served from the response cache CANNOT be scored, so counting
    // it as eligible states a coverage the sampler was never able to reach.**
    // `chat_completions_handler` returns at the cache hit (`server.rs:2427`)
    // BEFORE `buffer_provider_stream` / `provider_stream_to_sse`, which are the
    // only two sites that call `online_eval::spawn`. The `Pending` built at
    // Step 2e is simply dropped. A cache hit still publishes a `gen_ai.chat`
    // span — correctly, it is a real served request — so nothing else about it
    // distinguishes it here.
    //
    // THE NUMBERS, from the prod run that found this (2026-08-29, 2h window):
    // 222 chat traces, of which **193 were cache hits**. Reported achieved was
    // 3/222 = **1.35%** against a configured 10%. The true rate is 3/29 =
    // **10.34%** — the sampler was exactly right and the surface said it was
    // broken by a factor of 7.7. That is precisely the "a rate too low for the
    // traffic is the single most likely 'it's broken' report" failure this
    // pair of numbers exists to prevent, produced by the denominator rather
    // than by the sampler.
    //
    // `spans` already carries the flag (`server.rs:2396`), and it is
    // `skip_serializing_if = "Option::is_none"`, so PRESENCE is the hit —
    // verified on prod: `JSONHas` and `extract != ''` both take 222 to 29, and
    // the raw value reads `true`.
    let eligible_sql = crate::clickhouse_query::TenantQuery::new(
        "SELECT toUInt64(uniqExact(trace_id)) AS eligible FROM spans FINAL \
          WHERE tenant_id = ? AND name = 'gen_ai.chat' \
            AND JSONExtractString(attributes, 'tracelane_eval_run_id') = '' \
            AND NOT JSONHas(attributes, 'tracelane_semantic_cache_hit') \
            AND start_time >= now() - toIntervalHour(?)",
        crate::clickhouse_query::PlanTier::Builder,
    )
    .sql_with_settings();
    let e = ch
        .query(&eligible_sql)
        .bind(claims.tenant_id.to_string())
        .bind(hours)
        .fetch_one::<EligibleRow>()
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "online-eval summary eligible read failed");
            err(
                StatusCode::BAD_GATEWAY,
                "summary_read_failed",
                "could not read eligible traffic",
            )
        })?;

    Ok(Json(SummaryResponse {
        window_hours: hours,
        configured_sample_rate: configured,
        enabled,
        // `None`, NOT `Some(0.0)`, when nothing was eligible. See the struct doc.
        achieved_sample_rate: (e.eligible > 0).then(|| s.sampled_traces as f64 / e.eligible as f64),
        eligible_spans: e.eligible,
        sampled_traces: s.sampled_traces,
        scored: s.scored,
        errored: s.errored,
        mean_score: s.mean_score.filter(|v| v.is_finite()),
        judge_cost_usd: s.judge_cost_usd.filter(|v| v.is_finite()),
        judge_budget_usd_monthly: budget,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body(budget: Option<f64>) -> UpsertPolicyBody {
        UpsertPolicyBody {
            judge_budget_usd_monthly: budget,
            sample_rate: None,
            rubric_kind: None,
            rubric: None,
            judge_model: None,
            enabled: None,
        }
    }

    /// THE refusal this route exists for. A missing cap must be a NAMED 400,
    /// not a not-null violation surfaced as a 500.
    #[test]
    fn a_missing_cap_is_a_named_400() {
        let e = validate_policy(&body(None)).expect_err("a policy without a cap must be refused");
        assert_eq!(e.0, StatusCode::BAD_REQUEST);
        assert_eq!(e.1.0["error"], "budget_required");
    }

    #[test]
    fn a_zero_or_negative_cap_is_refused() {
        for bad in [0.0, -1.0, f64::NAN, f64::INFINITY] {
            let e = validate_policy(&body(Some(bad)))
                .unwrap_err_or_panic(&format!("budget {bad} must be refused"));
            assert_eq!(e.1.0["error"], "invalid_budget", "budget {bad}");
        }
    }

    #[test]
    fn the_sample_rate_ceiling_is_enforced_before_the_insert() {
        let mut b = body(Some(50.0));
        b.sample_rate = Some(0.11);
        let e = validate_policy(&b).expect_err("0.11 is above the ceiling");
        assert_eq!(e.1.0["error"], "invalid_sample_rate");
        // And exactly at the ceiling is ACCEPTED — a bound that refuses its own
        // limit is the off-by-one that makes a documented maximum unreachable.
        b.sample_rate = Some(MAX_SAMPLE_RATE);
        assert!(
            validate_policy(&b).is_ok(),
            "0.10 is the ceiling, not past it"
        );
    }

    /// The two refusals the SCHEMA CANNOT make. Both would produce a policy
    /// that samples correctly and errors on every score.
    #[test]
    fn a_rubric_kind_the_judge_cannot_resolve_is_refused() {
        let mut b = body(Some(50.0));
        b.rubric_kind = Some("prompt_version".into());
        let e = validate_policy(&b).expect_err("the online judge cannot resolve a prompt version");
        assert_eq!(e.1.0["error"], "unsupported_rubric_kind");
    }

    #[test]
    fn an_unroutable_judge_model_is_refused() {
        let mut b = body(Some(50.0));
        b.judge_model = Some("no-such-model-anywhere".into());
        let e = validate_policy(&b).expect_err("an unroutable model errors on every sample");
        assert_eq!(e.1.0["error"], "unroutable_model");
    }

    #[test]
    fn an_unknown_builtin_rubric_names_the_ones_that_exist() {
        let mut b = body(Some(50.0));
        b.rubric = Some("vibes".into());
        let e = validate_policy(&b).expect_err("unknown rubric");
        assert_eq!(e.1.0["error"], "unknown_rubric");
        let msg = e.1.0["message"].as_str().unwrap_or_default().to_string();
        assert!(
            msg.contains("answers_the_question"),
            "the refusal must NAME the valid rubrics, not just say no: {msg}"
        );
    }

    #[test]
    fn the_defaults_are_a_valid_policy_once_a_cap_is_given() {
        let (budget, rate, kind, rubric, model, enabled) =
            validate_policy(&body(Some(25.0))).expect("defaults + a cap must validate");
        assert!((budget - 25.0).abs() < f64::EPSILON);
        assert!((rate - 0.01).abs() < f64::EPSILON, "default coverage is 1%");
        assert_eq!(kind, "builtin");
        assert!(crate::prompt_eval::judge::built_in(&rubric).is_some());
        assert!(crate::providers::ProviderRegistry::provider_id_for_model(&model).is_some());
        assert!(enabled, "a policy written with a cap defaults to on");
    }

    #[test]
    fn the_window_bound_is_named_rather_than_clamped() {
        let q = WindowQuery {
            hours: Some(MAX_WINDOW_HOURS + 1),
            limit: None,
            trace_id: None,
        };
        let e = window_hours(&q).expect_err("past 90 days must refuse");
        assert_eq!(e.1.0["error"], "invalid_window");
        assert!(
            window_hours(&WindowQuery {
                hours: Some(MAX_WINDOW_HOURS),
                limit: None,
                trace_id: None
            })
            .is_ok()
        );
        assert!(
            window_hours(&WindowQuery {
                hours: Some(0),
                limit: None,
                trace_id: None
            })
            .is_err()
        );
    }

    /// Small helper so the loop above reads as an assertion rather than an
    /// unwrap chain.
    trait UnwrapErrOrPanic<T> {
        fn unwrap_err_or_panic(self, msg: &str) -> ApiError;
    }
    impl<T> UnwrapErrOrPanic<T> for Result<T, ApiError> {
        fn unwrap_err_or_panic(self, msg: &str) -> ApiError {
            match self {
                Err(e) => e,
                Ok(_) => panic!("{msg}"),
            }
        }
    }
}
