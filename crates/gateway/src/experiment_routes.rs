//! `EVL-02` — experiments: N arms over ONE frozen dataset snapshot, and the
//! side-by-side diff that answers *"is the candidate better, and where exactly
//! did it get worse?"*
//!
//! Mounted only when `CLICKHOUSE_URL` is set, matching `dataset_routes` and
//! `trace_reads` — every row this surface reads and writes lives in ClickHouse,
//! so with no connection the routes are ABSENT (a clean 404) rather than present
//! and unable to read.
//!
//! ## The one structural invariant, and why it is not a validation
//!
//! **Both arms of a comparison ran the SAME frozen snapshot.** The snapshot is
//! resolved ONCE, at create time, and pinned onto every arm's run; `compare` is
//! scoped to two arms *of one experiment*, so there is no request shape that can
//! ask for a diff across two different item sets. The rejected alternative — a
//! free-floating `GET /v1/evals/compare?a=<run>&b=<run>` across any two runs —
//! reads more general and is worse: two runs over different item sets produce an
//! alignment that is mostly `only_in_a`/`only_in_b` and an aggregate delta that
//! means nothing.
//!
//! That is also why the alignment key is EXACT. `OBS-10` aligns two traces
//! heuristically by `(name, depth, ordinal)` because span ids never match across
//! two executions (`trace_reads.rs`); here `dataset_item_id` is shared **by
//! construction**, so a heuristic would only invent mismatches.
//!
//! ## Arms run SEQUENTIALLY (founder ruling R82) — a decision, not a stage
//!
//! `PromptEvalEngine` holds ONE in-flight slot per `(tenant, prompt_name)`
//! because an eval run spends real money and two at once spends it twice,
//! invisibly. An N-arm experiment therefore runs its arms one after another, and
//! two things fall out that a parallel fan-out could not have:
//!
//! 1. **A real progress indicator.** `34 / 200, arm B of 3` is a true statement
//!    about a sequential run and a guess about a parallel one.
//! 2. **A budget cap enforceable MID-RUN.** The run checks the ceiling between
//!    items and aborts at item 300 of 800. With `arms` calls in flight the cap
//!    can be crossed by every one of them before any observes it, degrading the
//!    guarantee from *"we stop at the ceiling"* to *"we stop within `arms` calls
//!    of the ceiling"* — on someone else's provider bill.
//!
//! **Any future change that makes arms concurrent must first answer (2)** — not
//! "measure the speedup", but state how the mid-run cap stays exact.
//!
//! ## Money: the largest new risk in this sprint, and where it is stopped
//!
//! A 4-arm × 200-item experiment is up to **800 provider calls from one button**.
//! Three ceilings, in the order they fire:
//!
//! | Order | Ceiling | Refusal |
//! |---|---|---|
//! | 1 | the workspace's own monthly budget, checked BEFORE anything is claimed | `402 workspace_budget_exceeded`, the byte-identical body the chat path returns |
//! | 2 | `arms ≤ 4` and `snapshot items ≤ 200` | `400`, naming both numbers |
//! | 3 | the same budget, re-checked BETWEEN items mid-run | the arm stops, partial items are kept, the reason names both dollar figures |
//!
//! **(1) and (3) are the primary control and (2) is a blast-radius ceiling**, not
//! the other way round (founder ruling R83.2): 4 arms × 200 items of short
//! prompts is cheap and the same shape on long context is not, so a count
//! ceiling caps the wrong quantity.
//!
//! ## Zero is not unknown, and this surface is where it matters most
//!
//! An errored item has NO score. Rendering that as `0.00` manufactures a
//! regression that did not happen — on the screen a release decision is made on.
//! So `Δ score` is `null` whenever either side is unknown, `unknown` is its own
//! verdict with its own count and its own row style, and it is never folded into
//! `unchanged`.
//!
//! ## Tenant isolation
//!
//! `tenant_id` comes ONLY from `Claims.tenant_id`. Every SELECT and INSERT binds
//! it. An experiment or arm id that is unknown, malformed, or belongs to another
//! tenant returns the SAME 404 body — naming which one was missing would confirm
//! that the other exists.
//!
//! ## The schema this module is written against
//!
//! ClickHouse migrations `18_datasets_and_experiments.sql` (`experiments`,
//! `eval_run_items`) and `19_evl02_experiment_arms.sql` (`experiment_arms`, plus
//! `experiments.item_count` / `experiments.notes`). **Both are applied to prod
//! BEFORE the gateway that reads them deploys.**
//!
//! ```sql
//! experiments(tenant_id String, experiment_id UUID, name String,
//!             dataset_id UUID, snapshot_id UUID, status LowCardinality(String),
//!             created_at DateTime64(3,'UTC'), created_by String,
//!             updated_at DateTime64(3,'UTC'),
//!             item_count UInt32 DEFAULT 0, notes String DEFAULT '')
//!   ENGINE = ReplacingMergeTree(updated_at) ORDER BY (tenant_id, experiment_id)
//!
//! experiment_arms(tenant_id String, experiment_id UUID, arm_id UUID,
//!             arm_label String DEFAULT '', ordinal UInt8,
//!             eval_run_id Nullable(UUID), prompt_version_id UUID, model String,
//!             status LowCardinality(String),
//!             created_at DateTime64(3,'UTC'), updated_at DateTime64(3,'UTC'))
//!   ENGINE = ReplacingMergeTree(updated_at)
//!   ORDER BY (tenant_id, experiment_id, arm_id)
//! ```
//!
//! `experiment_arms.eval_run_id` is `Nullable` and **NULL means "this arm has not
//! started yet", never "the run is gone"** — arms are sequential, so the arms
//! behind the running one genuinely have no run id. The all-zero UUID was
//! rejected for the job: it is a legal value that reads as an id, and every
//! consumer would have to remember to test for it.

use std::sync::Arc;

use anyhow::{Context as _, Result};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::auth::Claims;
use crate::clickhouse_query::{PlanTier, TenantQuery, datetime64_millis_now};
use crate::dataset_routes::DatasetStore;
use crate::entitlement_cache::{EntitlementCache, FeatureKey};
use crate::prompt_eval::{
    ArmContext, Assertion, CaseSource, EvalRunRequest, PromptEvalEngine, RunContext,
};
use tracelane_shared::TenantId;

// ── Limits (spec §5) ─────────────────────────────────────────────────────────

pub mod limits {
    /// Arms per experiment. The compare view always diffs exactly TWO, chosen by
    /// a selector; this bounds how many an experiment may hold.
    pub const MAX_ARMS: usize = 4;
    /// Items an experiment may run per arm. Pinned EQUAL to
    /// `prompt_eval::limits::MAX_CASES` by the assertion below — a snapshot the
    /// engine would refuse must be refused HERE, at create time, with a message
    /// naming both numbers, rather than by a run that has already been recorded.
    pub const MAX_ITEMS: usize = crate::prompt_eval::limits::MAX_CASES;
    /// Experiment name. Free text, but bounded — it is stored verbatim and
    /// returned on every list read.
    pub const NAME_BYTES: usize = 200;
    pub const NOTES_BYTES: usize = 4 * 1024;
    /// List page sizes (spec §5 "List pages": experiments 100, items 200).
    pub const PAGE_DEFAULT: u32 = 25;
    pub const EXPERIMENTS_PAGE_MAX: u32 = 100;
    pub const ITEMS_PAGE_MAX: u32 = 200;
    /// Experiments retained per workspace before a create is refused. A blast
    /// radius, not a product decision — each one holds up to `MAX_ARMS`
    /// eval runs' worth of item rows.
    pub const EXPERIMENTS_PER_TENANT: u64 = 500;
}

/// A snapshot the engine would refuse must be refused at create time instead.
/// If these two ever diverge, an experiment could be accepted, recorded, and
/// then fail on its first arm with a message about a limit the create dialog
/// never mentioned.
const _: () = assert!(limits::MAX_ITEMS == crate::prompt_eval::limits::MAX_CASES);

// ── The comparison thresholds (spec §3c) ─────────────────────────────────────

/// Score is bounded `[0,1]`, so ONE assertion of twenty flipping is `0.05`.
///
/// **Absolute only, and this is a deliberate departure from `OBS-10`'s dual
/// margin.** A relative threshold is meaningless near zero — `0.02 → 0.01` is
/// "−50%" and is noise — so the score verdict uses an absolute margin and says
/// so. Deviating from a reused rule without writing down why is how a copied
/// surface drifts.
pub const SCORE_DELTA_MIN: f64 = 0.05;
/// An eval item is a whole provider round trip, not a sub-millisecond span, so
/// `OBS-10`'s `5_000µs` is the wrong scale here.
pub const LATENCY_DELTA_MIN_MS: f64 = 250.0;
/// The relative half of the pair is scale-free, so it carries over from `OBS-10`
/// unchanged.
pub const LATENCY_DELTA_MIN_PCT: f64 = 25.0;
/// Below a tenth of a cent per item is noise at any dataset size we cap at.
pub const COST_DELTA_MIN_USD: f64 = 0.001;
pub const COST_DELTA_MIN_PCT: f64 = 25.0;

// ── Errors ───────────────────────────────────────────────────────────────────

type ApiError = (StatusCode, Json<serde_json::Value>);

/// Emit a JSON body EXACTLY ONCE.
///
/// A caller that already built an object passes it through; anything else is
/// wrapped. Double-encoding is not cosmetic: a structured refusal nested inside
/// `{"error": …}` arrives escaped inside a string and every field on it reads as
/// `undefined` at the client. Observed on prod on the prompt surface, and the
/// tests there could not see it because `contains()` passes on either shape.
fn api_err(status: StatusCode, msg: impl Into<String>) -> ApiError {
    let msg = msg.into();
    match serde_json::from_str::<serde_json::Value>(&msg) {
        Ok(v) if v.is_object() => (status, Json(v)),
        _ => (status, Json(serde_json::json!({ "error": msg }))),
    }
}

fn coded_err(status: StatusCode, code: &str, message: &str, extra: serde_json::Value) -> ApiError {
    let mut body = serde_json::json!({ "error": code, "message": message });
    if let (Some(obj), Some(more)) = (body.as_object_mut(), extra.as_object()) {
        for (k, v) in more {
            obj.insert(k.clone(), v.clone());
        }
    }
    (status, Json(body))
}

/// The 404 for "no such experiment, arm or run **in this workspace**".
///
/// ONE function, so every caller emits BYTE-IDENTICAL bytes — a malformed id, an
/// unknown id and another tenant's id are indistinguishable from outside. Naming
/// which side was missing turns the endpoint into an existence oracle for another
/// tenant's ids, which is the discipline `trace_reads`' compare route already
/// writes down.
fn not_found() -> ApiError {
    (
        StatusCode::NOT_FOUND,
        Json(serde_json::json!({
            "error": "not_found",
            "message": "No such experiment in this workspace.",
        })),
    )
}

fn store_failed(what: &str, e: &anyhow::Error) -> ApiError {
    tracing::error!(error = format!("{e:#}"), "experiment store: {what} failed");
    api_err(
        StatusCode::BAD_GATEWAY,
        format!("Couldn't {what} — the gateway has logged the details."),
    )
}

/// Parse a path id. A malformed id gets the SAME 404 as an unknown one.
fn parse_id(s: &str) -> Result<Uuid, ApiError> {
    Uuid::parse_str(s).map_err(|_| not_found())
}

// ── Auth + entitlement seams ─────────────────────────────────────────────────

async fn claims_from_auth(headers: &HeaderMap) -> Result<Claims, ApiError> {
    let h = headers
        .get("authorization")
        .ok_or_else(|| api_err(StatusCode::UNAUTHORIZED, "missing Authorization header"))?;
    let s = h
        .to_str()
        .map_err(|_| api_err(StatusCode::BAD_REQUEST, "Authorization must be ASCII"))?;
    crate::auth::validate_authorization(s)
        .await
        .map_err(|e| api_err(StatusCode::UNAUTHORIZED, format!("auth failed: {e}")))
}

/// A13 scope gate for the READ surfaces.
///
/// An experiment's item rows hold a verbatim copy of the workspace's prompt
/// content and the model's answers, so this is exactly the asset `Scope::Read`
/// exists to fence: an `ingest`-scoped SDK key — the credential that ships inside
/// a customer's container image — must not read it back out.
fn authorize_read(claims: &Claims) -> Result<(), ApiError> {
    if !claims.allows_scope(crate::auth::scope::Scope::Read) {
        tracing::warn!(sub = %claims.sub, "api key lacks the `read` scope — refusing experiment read");
        return Err(api_err(
            StatusCode::FORBIDDEN,
            serde_json::json!({
                "error": "This API key is not scoped to read recorded data. An experiment \
                          holds a copy of your recorded prompt content and the model's \
                          answers; reading it needs the `read` scope.",
                "type": "insufficient_scope",
                "required_scope": "read",
            })
            .to_string(),
        ));
    }
    Ok(())
}

/// Role + scope gate for STARTING an experiment.
///
/// **Starting an experiment spends the tenant's money**, so it is gated exactly
/// as promotion and dataset writes are: `can_write_prompts()` for the role
/// (owner/admin JWTs and machine credentials in, `member`/`viewer` out, an
/// unrecognised slug fails CLOSED) AND the `admin` scope separately.
///
/// The two really are separate: `can_write_prompts` matches the `role: None` arm
/// for ANY `AuthMethod::ApiKey` *without reading `key_scope`*, so on its own it
/// would let a `read`-only key start an 800-call experiment.
fn authorize_write(claims: &Claims) -> Result<(), ApiError> {
    if !claims.can_write_prompts() {
        return Err(api_err(
            StatusCode::FORBIDDEN,
            crate::auth::role_forbidden_json("owner"),
        ));
    }
    if !claims.allows_scope(crate::auth::scope::Scope::Admin) {
        tracing::warn!(sub = %claims.sub, "api key lacks the `admin` scope — refusing experiment start");
        return Err(api_err(
            StatusCode::FORBIDDEN,
            serde_json::json!({
                "error": "This API key is not scoped to start experiments. An experiment \
                          spends this workspace's provider budget; it needs the `admin` scope.",
                "type": "insufficient_scope",
                "required_scope": "admin",
            })
            .to_string(),
        ));
    }
    Ok(())
}

/// The entitlement gate. **Absent cache ⇒ REFUSE.**
///
/// `state.entitlements` is `Some` iff a Postgres control plane exists, so `None`
/// is the unprivileged state (`.claude/rules/tenancy.md`). A no-cache path that
/// GRANTS produces no error, no alert and no complaint — which is exactly how the
/// guardrail rail gate shipped inverted and silently handed every paid rail to
/// OSS self-hosts. The refusal is a `503` rather than a `403` because the honest
/// fact is "we could not verify", not "you are not entitled".
async fn require_experiments(
    entitlements: &Option<Arc<EntitlementCache>>,
    tenant: &TenantId,
) -> Result<(), ApiError> {
    match entitlements {
        Some(cache) => {
            if cache
                .check(*tenant.as_uuid(), FeatureKey::Experiments)
                .await
            {
                Ok(())
            } else {
                Err(coded_err(
                    StatusCode::FORBIDDEN,
                    "entitlement_required",
                    "Experiments run one dataset against several prompt versions or models \
                     and diff the results. Your plan does not include them.",
                    serde_json::json!({
                        "feature": "experiments",
                        "upgrade_url": "https://app.tracelane.dev/settings/billing",
                    }),
                ))
            }
        }
        None => {
            tracing::error!("experiments: entitlement cache unavailable (no Postgres) — denying");
            Err(api_err(
                StatusCode::SERVICE_UNAVAILABLE,
                "entitlement verification unavailable",
            ))
        }
    }
}

async fn tenant_from_auth(
    state: &ExperimentRoutesState,
    headers: &HeaderMap,
) -> Result<TenantId, ApiError> {
    let claims = claims_from_auth(headers).await?;
    authorize_read(&claims)?;
    require_experiments(&state.entitlements, &claims.tenant_id).await?;
    Ok(claims.tenant_id)
}

async fn actor_from_auth(
    state: &ExperimentRoutesState,
    headers: &HeaderMap,
) -> Result<(TenantId, String), ApiError> {
    let claims = claims_from_auth(headers).await?;
    authorize_write(&claims)?;
    require_experiments(&state.entitlements, &claims.tenant_id).await?;
    Ok((claims.tenant_id, claims.sub))
}

// ── Domain rows ──────────────────────────────────────────────────────────────

/// The four strings an experiment's status may be.
///
/// An enum for the same reason `EvalStatus` is one: the column is
/// `LowCardinality(String)` and a fifth spelling would be written silently and
/// read by nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExperimentStatus {
    Running,
    Complete,
    Errored,
}

impl ExperimentStatus {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Running => "running",
            Self::Complete => "complete",
            Self::Errored => "errored",
        }
    }
}

/// An arm's state, which is `EvalStatus` **plus one**.
///
/// `pending` exists ONLY here: it is the state of an arm whose run has not been
/// created yet, which `eval_runs` cannot represent because it has no row. It is
/// never written into `eval_runs` and so can never reach
/// `ClickHouseEvalGate::status`, whose vocabulary is exactly four — a fifth
/// string there makes the gate return `None`, which blocks promotion silently
/// and permanently.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArmStatus {
    Pending,
    Running,
    Passed,
    Failed,
    Errored,
}

impl ArmStatus {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Running => "running",
            Self::Passed => "passed",
            Self::Failed => "failed",
            Self::Errored => "errored",
        }
    }

    fn parse(s: &str) -> Self {
        match s {
            "running" => Self::Running,
            "passed" => Self::Passed,
            "failed" => Self::Failed,
            "errored" => Self::Errored,
            // An UNRECOGNISED status is `errored`, never `pending`. `pending`
            // reads as "it will still run", which would leave a surface waiting
            // forever on a row nothing is going to touch again.
            _ => Self::Pending,
        }
    }

    /// Is this arm finished, one way or another? The compare action is disabled
    /// until BOTH arms are terminal — a diff against a partial arm reports every
    /// unfinished item as a regression, and refusing is the only honest answer.
    #[must_use]
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Passed | Self::Failed | Self::Errored)
    }
}

impl From<crate::prompt_eval::EvalStatus> for ArmStatus {
    fn from(s: crate::prompt_eval::EvalStatus) -> Self {
        match s {
            crate::prompt_eval::EvalStatus::Running => Self::Running,
            crate::prompt_eval::EvalStatus::Passed => Self::Passed,
            crate::prompt_eval::EvalStatus::Failed => Self::Failed,
            crate::prompt_eval::EvalStatus::Errored => Self::Errored,
        }
    }
}

/// One `experiments` row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Experiment {
    pub experiment_id: Uuid,
    pub name: String,
    pub dataset_id: Uuid,
    pub snapshot_id: Uuid,
    pub status: ExperimentStatus,
    /// The FROZEN snapshot's item count, copied at creation. A historical fact
    /// about an immutable set, so it cannot drift — and it is the denominator
    /// that makes `41 / 50` renderable. A run that stopped early would otherwise
    /// present as complete.
    pub item_count: u32,
    pub notes: String,
    pub created_at_ms: i64,
    pub created_by: String,
}

/// One `experiment_arms` row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Arm {
    pub arm_id: Uuid,
    pub arm_label: String,
    pub ordinal: u8,
    /// `None` = this arm has not started. NEVER "the run is gone".
    pub eval_run_id: Option<Uuid>,
    pub prompt_version_id: Uuid,
    pub model: String,
    pub status: ArmStatus,
}

/// One `eval_run_items` row, as this surface reads it.
#[derive(Debug, Clone, PartialEq)]
pub struct EvalItem {
    pub item_ordinal: u32,
    /// All-zero for an inline/trace-sourced case. Tested against nil EXPLICITLY
    /// wherever it is used as a key, and never rendered as an id.
    pub dataset_item_id: Uuid,
    pub case_name: String,
    pub status: String,
    pub output: String,
    pub output_truncated: bool,
    pub scores: String,
    /// `None` = UNKNOWN, never `0.0`.
    pub score: Option<f64>,
    pub latency_ms: u32,
    /// `None` = unpriced model, never `0.0`.
    pub cost_usd: Option<f64>,
    pub error: Option<String>,
}

// ── Storage seam ─────────────────────────────────────────────────────────────

/// Every method is fail-CLOSED at the handler: a store error becomes a `502` and
/// nothing is written. These are not fault-tolerance paths — an experiment write
/// that silently no-ops is worse than one that refuses.
#[async_trait::async_trait]
pub trait ExperimentStore: Send + Sync {
    async fn count_experiments(&self, tenant: &TenantId) -> Result<u64>;
    async fn create_experiment(&self, tenant: &TenantId, e: &Experiment) -> Result<()>;
    async fn set_experiment_status(
        &self,
        tenant: &TenantId,
        e: &Experiment,
        status: ExperimentStatus,
    ) -> Result<()>;
    async fn get_experiment(&self, tenant: &TenantId, id: Uuid) -> Result<Option<Experiment>>;
    async fn list_experiments(
        &self,
        tenant: &TenantId,
        cursor: Option<(i64, String)>,
        limit: u32,
    ) -> Result<Vec<(Experiment, u32)>>;

    async fn insert_arms(&self, tenant: &TenantId, experiment_id: Uuid, arms: &[Arm])
    -> Result<()>;
    async fn update_arm(&self, tenant: &TenantId, experiment_id: Uuid, arm: &Arm) -> Result<()>;
    async fn list_arms(&self, tenant: &TenantId, experiment_id: Uuid) -> Result<Vec<Arm>>;

    /// Every item row of ONE run, in ordinal order. Bounded by
    /// [`limits::MAX_ITEMS`] by construction — a run cannot hold more.
    async fn run_items(&self, tenant: &TenantId, eval_run_id: Uuid) -> Result<Vec<EvalItem>>;
    /// One page of item rows for a run outside an experiment.
    async fn page_run_items(
        &self,
        tenant: &TenantId,
        eval_run_id: Uuid,
        after_ordinal: Option<u32>,
        limit: u32,
    ) -> Result<Vec<EvalItem>>;
}

// ── ClickHouse implementation ────────────────────────────────────────────────

/// `experiments`, for INSERT. Field NAMES become the column list the
/// `clickhouse` crate emits, so a misspelling fails loudly at the server; what
/// fails SILENTLY is a wrong-width type, which is why every one below is written
/// against the DDL line by line and covered by a real-ClickHouse round trip
/// (B-273/B-274).
#[derive(Debug, Serialize, clickhouse::Row)]
struct ExperimentWriteRow {
    tenant_id: String,
    #[serde(with = "clickhouse::serde::uuid")]
    experiment_id: Uuid,
    name: String,
    #[serde(with = "clickhouse::serde::uuid")]
    dataset_id: Uuid,
    #[serde(with = "clickhouse::serde::uuid")]
    snapshot_id: Uuid,
    status: String,
    /// `DateTime64(3)` — MILLIS. Never `timestamp_micros()`: `clickhouse-rs`
    /// maps a plain `i64` onto the column's RAW TICKS with no unit conversion,
    /// so micros are accepted, never error, and read back as `2299-12-31`.
    created_at: i64,
    created_by: String,
    updated_at: i64,
    item_count: u32,
    notes: String,
}

#[derive(Debug, Deserialize, clickhouse::Row)]
struct ExperimentReadRow {
    /// `toString(experiment_id)` — width-agnostic against the `UUID` column, the
    /// same discipline `dataset_routes` uses. Parsed in Rust.
    experiment_id: String,
    name: String,
    dataset_id: String,
    snapshot_id: String,
    status: String,
    item_count: u32,
    notes: String,
    created_at: i64,
    created_by: String,
}

#[derive(Debug, Serialize, clickhouse::Row)]
struct ArmWriteRow {
    tenant_id: String,
    #[serde(with = "clickhouse::serde::uuid")]
    experiment_id: Uuid,
    #[serde(with = "clickhouse::serde::uuid")]
    arm_id: Uuid,
    arm_label: String,
    ordinal: u8,
    /// `Nullable(UUID)`. NULL = not started yet.
    #[serde(with = "clickhouse::serde::uuid::option")]
    eval_run_id: Option<Uuid>,
    #[serde(with = "clickhouse::serde::uuid")]
    prompt_version_id: Uuid,
    model: String,
    status: String,
    created_at: i64,
    updated_at: i64,
}

#[derive(Debug, Deserialize, clickhouse::Row)]
struct ArmReadRow {
    arm_id_text: String,
    arm_label: String,
    ordinal: u8,
    /// `''` when NULL — flattened at the server with `ifNull(toString(...), '')`
    /// so this reader never has to carry a `Nullable` through RowBinary. Empty
    /// means NOT STARTED, which is why it is mapped back to `None` and not to a
    /// zero UUID.
    eval_run_id_text: String,
    prompt_version_id_text: String,
    model: String,
    status: String,
}

#[derive(Debug, Deserialize, clickhouse::Row)]
struct ItemReadRow {
    item_ordinal: u32,
    /// `_text` rather than `dataset_item_id`, and the suffix is load-bearing —
    /// see the SELECT: an alias that reuses a column's own name shadows it for
    /// every other expression in the same SELECT list.
    dataset_item_id_text: String,
    case_name: String,
    status: String,
    output: String,
    output_truncated: u8,
    scores: String,
    /// `Nullable(Float64)` flattened to `(has, value)` at the server rather than
    /// decoded as an `Option<f64>`: the two-column form is unambiguous about
    /// zero-vs-unknown at every layer, and this is the one column where
    /// collapsing them would be the defect the whole surface exists to prevent.
    score_present: u8,
    score_value: f64,
    latency_ms: u32,
    cost_present: u8,
    cost_value: f64,
    error_present: u8,
    error_text: String,
}

#[derive(Debug, Deserialize, clickhouse::Row)]
struct CountRow {
    n: u64,
}

pub struct ClickHouseExperimentStore {
    ch: clickhouse::Client,
}

impl ClickHouseExperimentStore {
    #[must_use]
    pub fn new(ch: clickhouse::Client) -> Self {
        Self { ch }
    }

    fn write_row(
        tenant: &TenantId,
        e: &Experiment,
        status: ExperimentStatus,
    ) -> ExperimentWriteRow {
        ExperimentWriteRow {
            tenant_id: tenant.to_string(),
            experiment_id: e.experiment_id,
            name: e.name.clone(),
            dataset_id: e.dataset_id,
            snapshot_id: e.snapshot_id,
            status: status.as_str().to_string(),
            created_at: e.created_at_ms,
            created_by: e.created_by.clone(),
            // The VERSION column of a `ReplacingMergeTree(updated_at)`. It must
            // move on every rewrite or the status change is a coin flip between
            // two rows with equal versions.
            updated_at: datetime64_millis_now(),
            item_count: e.item_count,
            notes: e.notes.clone(),
        }
    }
}

/// Rows are projected with `toString(...)` on every UUID, so the reader is
/// width-agnostic; a row whose id does not parse is DROPPED rather than rendered
/// with a fabricated id — the same choice `dataset_routes` makes, and the reason
/// is that a wrong id in a comparison attributes a result to the wrong test case
/// silently.
#[async_trait::async_trait]
impl ExperimentStore for ClickHouseExperimentStore {
    async fn count_experiments(&self, tenant: &TenantId) -> Result<u64> {
        let sql = TenantQuery::new(
            "SELECT toUInt64(count()) AS n FROM experiments FINAL WHERE tenant_id = ?",
            PlanTier::Builder,
        )
        .sql_with_settings();
        Ok(self
            .ch
            .query(&sql)
            .bind(tenant.to_string())
            .fetch_one::<CountRow>()
            .await
            .context("counting experiments")?
            .n)
    }

    async fn create_experiment(&self, tenant: &TenantId, e: &Experiment) -> Result<()> {
        let mut insert = self
            .ch
            .insert("experiments")
            .context("clickhouse experiments insert init")?;
        insert
            .write(&Self::write_row(tenant, e, e.status))
            .await
            .context("clickhouse experiments insert write")?;
        insert
            .end()
            .await
            .context("clickhouse experiments insert end")
    }

    async fn set_experiment_status(
        &self,
        tenant: &TenantId,
        e: &Experiment,
        status: ExperimentStatus,
    ) -> Result<()> {
        let mut insert = self
            .ch
            .insert("experiments")
            .context("clickhouse experiments status insert init")?;
        insert
            .write(&Self::write_row(tenant, e, status))
            .await
            .context("clickhouse experiments status insert write")?;
        insert
            .end()
            .await
            .context("clickhouse experiments status insert end")
    }

    async fn get_experiment(&self, tenant: &TenantId, id: Uuid) -> Result<Option<Experiment>> {
        // `experiments.experiment_id` is QUALIFIED in the WHERE on purpose. The
        // projection aliases `toString(experiment_id) AS experiment_id`, and an
        // UNQUALIFIED `WHERE experiment_id = toUUID(?)` then compares the aliased
        // String against a UUID — ClickHouse answers Code 386 and EVERY read
        // 502s. That is B-272 exactly, on a different table.
        let sql = TenantQuery::new(
            "SELECT toString(experiment_id) AS experiment_id, name, \
                    toString(dataset_id) AS dataset_id, toString(snapshot_id) AS snapshot_id, \
                    status, item_count, notes, \
                    toUnixTimestamp64Milli(created_at) AS created_at, created_by \
             FROM experiments FINAL \
             WHERE tenant_id = ? AND experiments.experiment_id = toUUID(?) \
             LIMIT 1",
            PlanTier::Builder,
        )
        .sql_with_settings();
        let rows = self
            .ch
            .query(&sql)
            .bind(tenant.to_string())
            .bind(id.to_string())
            .fetch_all::<ExperimentReadRow>()
            .await
            .context("reading an experiment")?;
        Ok(rows.into_iter().next().and_then(row_to_experiment))
    }

    async fn list_experiments(
        &self,
        tenant: &TenantId,
        cursor: Option<(i64, String)>,
        limit: u32,
    ) -> Result<Vec<(Experiment, u32)>> {
        // Keyset pagination on `(created_at, experiment_id)`, the same
        // `"{millis}:{id}"` cursor shape the trace and dataset lists use. NOT
        // OFFSET: an OFFSET page over a `ReplacingMergeTree` shifts under a
        // concurrent write and silently skips a row.
        let (where_cursor, ts, id) = match &cursor {
            Some((ts, id)) => (
                "AND (created_at, experiments.experiment_id) < \
                 (fromUnixTimestamp64Milli(toInt64(?)), toUUID(?)) ",
                *ts,
                id.clone(),
            ),
            None => ("", 0_i64, Uuid::nil().to_string()),
        };
        let sql = TenantQuery::new(
            format!(
                "SELECT toString(experiment_id) AS experiment_id, name, \
                        toString(dataset_id) AS dataset_id, toString(snapshot_id) AS snapshot_id, \
                        status, item_count, notes, \
                        toUnixTimestamp64Milli(created_at) AS created_at, created_by \
                 FROM experiments FINAL \
                 WHERE tenant_id = ? {where_cursor}\
                 ORDER BY created_at DESC, experiments.experiment_id DESC \
                 LIMIT ?"
            ),
            PlanTier::Builder,
        )
        .sql_with_settings();
        let mut q = self.ch.query(&sql).bind(tenant.to_string());
        if cursor.is_some() {
            q = q.bind(ts).bind(id);
        }
        let rows = q
            .bind(limit)
            .fetch_all::<ExperimentReadRow>()
            .await
            .context("listing experiments")?;

        // The arm count per experiment, in ONE query rather than N. A per-row
        // query here would be `limit` round trips for a list page, which is the
        // fan-out shape that made `/dashboard` sample the WAN tail N times.
        let ids: Vec<String> = rows.iter().map(|r| r.experiment_id.clone()).collect();
        let counts = if ids.is_empty() {
            std::collections::HashMap::new()
        } else {
            #[derive(Deserialize, clickhouse::Row)]
            struct ArmCount {
                experiment_id: String,
                n: u32,
            }
            let sql = TenantQuery::new(
                "SELECT toString(experiment_id) AS experiment_id, toUInt32(count()) AS n \
                 FROM experiment_arms FINAL \
                 WHERE tenant_id = ? AND toString(experiment_arms.experiment_id) IN ? \
                 GROUP BY experiment_id",
                PlanTier::Builder,
            )
            .sql_with_settings();
            self.ch
                .query(&sql)
                .bind(tenant.to_string())
                .bind(&ids)
                .fetch_all::<ArmCount>()
                .await
                .context("counting experiment arms")?
                .into_iter()
                .map(|r| (r.experiment_id, r.n))
                .collect()
        };

        Ok(rows
            .into_iter()
            .filter_map(|r| {
                let key = r.experiment_id.clone();
                let arms = counts.get(&key).copied().unwrap_or(0);
                row_to_experiment(r).map(|e| (e, arms))
            })
            .collect())
    }

    async fn insert_arms(
        &self,
        tenant: &TenantId,
        experiment_id: Uuid,
        arms: &[Arm],
    ) -> Result<()> {
        if arms.is_empty() {
            return Ok(());
        }
        let now = datetime64_millis_now();
        let mut insert = self
            .ch
            .insert("experiment_arms")
            .context("clickhouse experiment_arms insert init")?;
        for a in arms {
            insert
                .write(&ArmWriteRow {
                    tenant_id: tenant.to_string(),
                    experiment_id,
                    arm_id: a.arm_id,
                    arm_label: a.arm_label.clone(),
                    ordinal: a.ordinal,
                    eval_run_id: a.eval_run_id,
                    prompt_version_id: a.prompt_version_id,
                    model: a.model.clone(),
                    status: a.status.as_str().to_string(),
                    created_at: now,
                    updated_at: now,
                })
                .await
                .context("clickhouse experiment_arms insert write")?;
        }
        insert
            .end()
            .await
            .context("clickhouse experiment_arms insert end")
    }

    async fn update_arm(&self, tenant: &TenantId, experiment_id: Uuid, arm: &Arm) -> Result<()> {
        // A REWRITE, not an ALTER UPDATE. `experiment_arms` is a
        // `ReplacingMergeTree(updated_at)` keyed on `(tenant, experiment, arm)`,
        // so writing the row again with a newer `updated_at` IS the update — and
        // it keeps the row with the highest version rather than "whichever landed
        // last", which is not the same thing when two status writes race.
        //
        // `created_at` is rewritten to `now` rather than preserved because this
        // table's ORDER BY does not include it and nothing reads it; carrying a
        // stale value through would require a read-before-write on the money path.
        //
        // THE VERSION-COLLISION SEAM, NAMED RATHER THAN ENGINEERED AROUND. Two
        // writes landing in the SAME millisecond would carry equal `updated_at`,
        // and `FINAL` then picks between them arbitrarily — an arm could render
        // `pending` after it had started. It cannot happen on the transitions this
        // surface makes: `pending -> running -> terminal` are separated by a
        // ClickHouse insert and a whole provider round trip respectively, each far
        // above a millisecond. It is written down because the mitigation is the
        // TIMING, not a mechanism, and a future caller that rewrote an arm twice
        // in a tight loop would lose that protection silently.
        self.insert_arms(tenant, experiment_id, std::slice::from_ref(arm))
            .await
    }

    async fn list_arms(&self, tenant: &TenantId, experiment_id: Uuid) -> Result<Vec<Arm>> {
        let sql = TenantQuery::new(
            // `_text` aliases, and every source column QUALIFIED — the same
            // discipline the item read states at length: a SELECT-list alias
            // that reuses a column's name shadows it for every other expression
            // in the same SELECT, and that is how a NULL flag came back as 1.
            // No expression here reads another's alias TODAY; the naming is what
            // keeps that true when someone adds one.
            "SELECT toString(experiment_arms.arm_id) AS arm_id_text, arm_label, ordinal, \
                    ifNull(toString(experiment_arms.eval_run_id), '') AS eval_run_id_text, \
                    toString(experiment_arms.prompt_version_id) AS prompt_version_id_text, \
                    model, status \
             FROM experiment_arms FINAL \
             WHERE tenant_id = ? AND experiment_arms.experiment_id = toUUID(?) \
             ORDER BY ordinal ASC \
             LIMIT ?",
            PlanTier::Builder,
        )
        .sql_with_settings();
        let rows = self
            .ch
            .query(&sql)
            .bind(tenant.to_string())
            .bind(experiment_id.to_string())
            .bind(u32::try_from(limits::MAX_ARMS).unwrap_or(4))
            .fetch_all::<ArmReadRow>()
            .await
            .context("listing experiment arms")?;
        Ok(rows
            .into_iter()
            .filter_map(|r| {
                Some(Arm {
                    arm_id: Uuid::parse_str(&r.arm_id_text).ok()?,
                    arm_label: r.arm_label,
                    ordinal: r.ordinal,
                    // EMPTY means NULL means NOT STARTED. A parse failure on a
                    // non-empty value is also `None` — an unreadable run id is
                    // "we cannot name the run", which is closer to not-started
                    // than to a fabricated id.
                    eval_run_id: if r.eval_run_id_text.is_empty() {
                        None
                    } else {
                        Uuid::parse_str(&r.eval_run_id_text).ok()
                    },
                    prompt_version_id: Uuid::parse_str(&r.prompt_version_id_text).ok()?,
                    model: r.model,
                    status: ArmStatus::parse(&r.status),
                })
            })
            .collect())
    }

    async fn run_items(&self, tenant: &TenantId, eval_run_id: Uuid) -> Result<Vec<EvalItem>> {
        self.page_run_items(
            tenant,
            eval_run_id,
            None,
            u32::try_from(limits::MAX_ITEMS).unwrap_or(200),
        )
        .await
    }

    async fn page_run_items(
        &self,
        tenant: &TenantId,
        eval_run_id: Uuid,
        after_ordinal: Option<u32>,
        limit: u32,
    ) -> Result<Vec<EvalItem>> {
        let where_cursor = if after_ordinal.is_some() {
            "AND item_ordinal > ? "
        } else {
            ""
        };
        let sql = TenantQuery::new(
            format!(
                // EVERY alias is a NEW name and every source column is QUALIFIED.
                // `ifNull(score, 0) AS score` looks harmless and is not: a
                // SELECT-list alias SHADOWS the column it is named after, and
                // `toUInt8(score IS NOT NULL)` in the same SELECT then reads the
                // ALIAS — which is never NULL — so the presence flag came back 1
                // for every row and a NULL score decoded as a measured 0.0.
                //
                // That is B-272's alias shadowing wearing a different hat, and
                // here it collapses UNKNOWN into ZERO on the one surface whose
                // entire purpose is telling those apart. Found by this module's
                // real-ClickHouse round trip on its FIRST run, behind 19 green
                // unit tests that could not see it — the mock stores what it is
                // handed and the SQL is the subject.
                "SELECT item_ordinal, \
                        toString(eval_run_items.dataset_item_id) AS dataset_item_id_text, \
                        case_name, status, output, output_truncated, scores, \
                        toUInt8(eval_run_items.score IS NOT NULL) AS score_present, \
                        ifNull(eval_run_items.score, 0) AS score_value, \
                        latency_ms, \
                        toUInt8(eval_run_items.cost_usd IS NOT NULL) AS cost_present, \
                        ifNull(eval_run_items.cost_usd, 0) AS cost_value, \
                        toUInt8(eval_run_items.error IS NOT NULL) AS error_present, \
                        ifNull(eval_run_items.error, '') AS error_text \
                 FROM eval_run_items FINAL \
                 WHERE tenant_id = ? AND eval_run_items.eval_run_id = toUUID(?) {where_cursor}\
                 ORDER BY item_ordinal ASC \
                 LIMIT ?"
            ),
            PlanTier::Builder,
        )
        .sql_with_settings();
        let mut q = self
            .ch
            .query(&sql)
            .bind(tenant.to_string())
            .bind(eval_run_id.to_string());
        if let Some(o) = after_ordinal {
            q = q.bind(o);
        }
        let rows = q
            .bind(limit)
            .fetch_all::<ItemReadRow>()
            .await
            .context("reading eval run items")?;
        Ok(rows.into_iter().map(row_to_item).collect())
    }
}

fn row_to_experiment(r: ExperimentReadRow) -> Option<Experiment> {
    Some(Experiment {
        experiment_id: Uuid::parse_str(&r.experiment_id).ok()?,
        name: r.name,
        dataset_id: Uuid::parse_str(&r.dataset_id).ok()?,
        snapshot_id: Uuid::parse_str(&r.snapshot_id).ok()?,
        status: match r.status.as_str() {
            "complete" => ExperimentStatus::Complete,
            "errored" => ExperimentStatus::Errored,
            // An unrecognised status is RUNNING only if it is literally
            // "running"; anything else is `errored`, because a surface that
            // renders an unknown state as "still going" waits forever.
            "running" => ExperimentStatus::Running,
            _ => ExperimentStatus::Errored,
        },
        item_count: r.item_count,
        notes: r.notes,
        created_at_ms: r.created_at,
        created_by: r.created_by,
    })
}

fn row_to_item(r: ItemReadRow) -> EvalItem {
    EvalItem {
        item_ordinal: r.item_ordinal,
        // A dataset_item_id that does not parse becomes NIL — the value that
        // already means "no frozen item" — rather than a fabricated id. The
        // alignment then falls back to the ordinal for that row instead of
        // matching two arms on a key that means "unknown".
        dataset_item_id: Uuid::parse_str(&r.dataset_item_id_text).unwrap_or_else(|_| Uuid::nil()),
        case_name: r.case_name,
        status: r.status,
        output: r.output,
        output_truncated: r.output_truncated == 1,
        scores: r.scores,
        // ZERO VS UNKNOWN, decided by the presence flag and never by the value.
        // `score = 0` with `score_present = 1` is a measured zero; `score = 0`
        // with `score_present = 0` is NULL and must render as `—`.
        score: (r.score_present == 1).then_some(r.score_value),
        latency_ms: r.latency_ms,
        cost_usd: (r.cost_present == 1).then_some(r.cost_value),
        error: (r.error_present == 1 && !r.error_text.is_empty()).then_some(r.error_text),
    }
}

// ── The comparison (spec §3) — PURE, so every rule is unit-testable ──────────

/// One row's verdict. **Six variants that PARTITION the rows exactly**, so a
/// reader can add the six counts up and get the row count — the cheapest possible
/// check that the surface is not lying about what it measured.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Regressed,
    /// Either side errored or produced no score. **Its own verdict, its own
    /// count, its own row style — never folded into `unchanged`.** An errored
    /// item that renders as `0.00` is indistinguishable from a genuine zero
    /// score, which is the failure this whole surface exists to prevent.
    Unknown,
    Improved,
    Unchanged,
    /// Present in arm A, absent from arm B — arm B stopped before reaching it.
    OnlyInA,
    OnlyInB,
}

impl Verdict {
    /// Sort rank. **`regressed → unknown → improved → unchanged`**, a deliberate
    /// departure from `OBS-10`'s structural sort, and the reason is the
    /// requirement itself: *a run scoring worse on 3 of 50 items must show those
    /// 3 immediately.* A structural sort buries them at row 37. `unknown` sits
    /// second because an errored item is actionable and must not be buried
    /// either. One-sided rows come last: they are excluded from every aggregate,
    /// so they are context rather than findings.
    fn rank(self) -> u8 {
        match self {
            Self::Regressed => 0,
            Self::Unknown => 1,
            Self::Improved => 2,
            Self::Unchanged => 3,
            Self::OnlyInA => 4,
            Self::OnlyInB => 5,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Regressed => "regressed",
            Self::Unknown => "unknown",
            Self::Improved => "improved",
            Self::Unchanged => "unchanged",
            Self::OnlyInA => "only_in_a",
            Self::OnlyInB => "only_in_b",
        }
    }
}

/// One side of a compared row, or nothing.
#[derive(Debug, Clone, Serialize)]
pub struct ComparedSide {
    pub case_name: String,
    pub status: String,
    /// `null` = UNKNOWN. `0.0` = measured zero. The client renders `—` for the
    /// first and `0.00` for the second, and must never collapse them.
    pub score: Option<f64>,
    pub latency_ms: u32,
    pub cost_usd: Option<f64>,
    /// First 240 chars is a CLIENT concern; the whole (already 8 KB-capped)
    /// output ships so the expander needs no second round trip.
    pub output: String,
    /// `true` = the output above is NOT complete, and the surface must say so
    /// explicitly rather than cutting silently.
    pub output_truncated: bool,
    pub error: Option<String>,
}

fn side(i: &EvalItem) -> ComparedSide {
    ComparedSide {
        case_name: i.case_name.clone(),
        status: i.status.clone(),
        score: i.score,
        latency_ms: i.latency_ms,
        cost_usd: i.cost_usd,
        output: i.output.clone(),
        output_truncated: i.output_truncated,
        error: i.error.clone(),
    }
}

/// One row of the diff table.
#[derive(Debug, Clone, Serialize)]
pub struct ComparedItem {
    /// The alignment key as a string, or `null` for a row aligned on ordinal
    /// because it carried no frozen item. **Never the all-zero UUID rendered as
    /// an id.**
    pub dataset_item_id: Option<String>,
    pub item_ordinal: u32,
    /// The label a reader recognises: the case name from whichever side exists.
    pub label: String,
    pub a: Option<ComparedSide>,
    pub b: Option<ComparedSide>,
    /// `b.score − a.score`. **`null` when EITHER side's score is unknown** — an
    /// errored item has NO delta, and treating it as one manufactures a
    /// regression that did not happen.
    pub delta_score: Option<f64>,
    pub delta_latency_ms: Option<i64>,
    /// `null` when `a.latency_ms == 0` — never `∞`, never a fake `0%`.
    pub delta_latency_pct: Option<f64>,
    pub delta_cost_usd: Option<f64>,
    pub delta_cost_pct: Option<f64>,
    /// Fires iff BOTH the absolute and the relative margin move. Percent alone
    /// flags noise on a fast item; absolute alone flags proportional growth on a
    /// slow one — the argument `OBS-10` writes down, unchanged.
    pub latency_slower: bool,
    pub latency_faster: bool,
    pub cost_higher: bool,
    pub cost_lower: bool,
    pub verdict: &'static str,
}

/// The echoed thresholds. **In the payload, not hardcoded in the page**, for the
/// reason `trace_reads` already states: the client must never carry a copy of a
/// rule it would then have to keep in step.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct CompareThresholds {
    pub score_delta_min: f64,
    pub latency_delta_min_ms: f64,
    pub latency_delta_min_pct: f64,
    pub cost_delta_min_usd: f64,
    pub cost_delta_min_pct: f64,
}

impl Default for CompareThresholds {
    fn default() -> Self {
        Self {
            score_delta_min: SCORE_DELTA_MIN,
            latency_delta_min_ms: LATENCY_DELTA_MIN_MS,
            latency_delta_min_pct: LATENCY_DELTA_MIN_PCT,
            cost_delta_min_usd: COST_DELTA_MIN_USD,
            cost_delta_min_pct: COST_DELTA_MIN_PCT,
        }
    }
}

/// Per-arm aggregate — the header strip.
///
/// **Computed over MATCHED items only**, and the surface says so. An aggregate
/// that mixed matched and one-sided items would compare two arms on different
/// denominators, which is the one thing a comparison must not do. The run-level
/// totals ride alongside in `items_run` / `item_count` so nothing is hidden.
#[derive(Debug, Clone, Serialize)]
pub struct ArmAggregate {
    pub arm_id: Uuid,
    pub arm_label: String,
    pub ordinal: u8,
    pub eval_run_id: Option<Uuid>,
    pub prompt_version_id: Uuid,
    pub model: String,
    pub status: &'static str,
    /// `passed / (passed + failed)` over matched items — **errors excluded from
    /// the denominator**, because an upstream outage must not read as a quality
    /// regression. `null` = no item was scored; rendered `—`, never `0%`.
    pub pass_rate: Option<f64>,
    pub passed: u32,
    pub failed: u32,
    /// Always measured — the column is written on every terminal row, so `0`
    /// here is a fact rather than an absence.
    pub errored: u32,
    /// Mean of the non-null scores. `null` = no scored items. `0.00` = measured,
    /// every scorer returned 0. The two must not render alike.
    pub mean_score: Option<f64>,
    /// Nearest-rank p95 over non-errored items. `null` when nothing completed —
    /// never `0ms`. A 60 s timeout is not a 60 s latency measurement and is
    /// excluded.
    pub p95_latency_ms: Option<u32>,
    /// Sum over items whose cost we KNOW, always paired with `unpriced_items`.
    /// An unknown cost is never summed as zero — the exact coercion that made the
    /// spend tile under-report silently.
    pub total_cost_usd: f64,
    pub unpriced_items: u32,
    /// Item rows this run actually produced, matched or not.
    pub items_run: u32,
    /// Items that aligned with the other arm — the denominator of everything
    /// above.
    pub items_matched: u32,
}

/// The compare payload. Shape-for-shape `OBS-10`'s envelope
/// (`{ a, b, rows[], counts, echoed thresholds }`) so the client renders the same
/// way and never hardcodes a rule.
#[derive(Debug, Clone, Serialize)]
pub struct CompareResponse {
    pub experiment_id: Uuid,
    pub name: String,
    pub dataset_id: Uuid,
    pub snapshot_id: Uuid,
    /// The frozen snapshot's size — the denominator of `41 / 50`.
    pub item_count: u32,
    pub a: ArmAggregate,
    pub b: ArmAggregate,
    pub rows: Vec<ComparedItem>,
    pub regressed_count: u32,
    pub improved_count: u32,
    pub unchanged_count: u32,
    pub unknown_count: u32,
    pub only_in_a: u32,
    pub only_in_b: u32,
    pub thresholds: CompareThresholds,
    /// One sentence, in words, for the top of the page: *"3 of 50 items regressed
    /// · 2 improved · 1 could not be scored"*. Built here so the page and the API
    /// cannot disagree about what the numbers mean.
    pub summary: String,
    /// Present when either arm produced fewer items than the snapshot holds.
    /// Names the split and the reason, so a partial comparison can never read as
    /// a complete one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub partial_note: Option<String>,
}

/// `b − a` as a percentage of `a`; `None` when `a == 0` — never `∞`, never a
/// fake `0%`.
fn delta_pct(a: f64, b: f64) -> Option<f64> {
    if a == 0.0 || !a.is_finite() {
        return None;
    }
    Some(((b - a) / a * 100.0 * 100.0).round() / 100.0)
}

/// Nearest-rank p95 — `ceil(0.95 * n)`-th smallest, 1-indexed.
///
/// Nearest-rank rather than interpolated because the value returned is then a
/// latency that ACTUALLY HAPPENED, not an average of two that did not. On the
/// small n an experiment produces (≤ 200) an interpolated percentile is mostly
/// an artefact of the interpolation.
fn p95(mut v: Vec<u32>) -> Option<u32> {
    if v.is_empty() {
        return None;
    }
    v.sort_unstable();
    let n = v.len();
    #[allow(
        clippy::cast_precision_loss,
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss
    )]
    let rank = ((0.95_f64 * n as f64).ceil() as usize).clamp(1, n);
    Some(v[rank - 1])
}

/// `(is_keyed, dataset_item_id, ordinal)`.
///
/// The leading `bool` is what keeps a keyed row and an ordinal-aligned row in
/// DISJOINT halves of the key space: without it, a nil-id row at ordinal 0 and a
/// keyed row would be ordered against each other on a field one of them does not
/// have.
type AlignKey = (bool, Uuid, u32);

/// The two sides collected for one alignment key. Either may be absent — that is
/// what `only_in_a` / `only_in_b` are.
type SidePair<'a> = (Option<&'a EvalItem>, Option<&'a EvalItem>);

/// The alignment key for one item row.
///
/// `dataset_item_id` when it is a real id — which, for an experiment, is ALWAYS,
/// because an experiment requires a dataset and both arms ran the same frozen
/// snapshot. The ordinal fallback exists for `GET /v1/evals/{id}/items`-shaped
/// data and for a defensive read of a row written before the provenance existed:
/// an inline-sourced pair still aligns instead of rendering every row as
/// one-sided.
fn align_key(i: &EvalItem) -> AlignKey {
    if i.dataset_item_id.is_nil() {
        (false, Uuid::nil(), i.item_ordinal)
    } else {
        (true, i.dataset_item_id, 0)
    }
}

/// Decide one row's verdict. **PURE, and the single most load-bearing function on
/// this surface** — every rule in spec §3b is here and nowhere else.
fn verdict_for(a: &EvalItem, b: &EvalItem, score_delta_min: f64) -> (Verdict, Option<f64>) {
    // UNKNOWN FIRST, and unconditionally. An errored item has no measurement, so
    // no threshold applies to it and no delta exists. Checking this last would
    // let a `0.0`-vs-`None` pair fall through to a numeric comparison.
    let (Some(sa), Some(sb)) = (a.score, b.score) else {
        return (Verdict::Unknown, None);
    };
    if a.status == "errored" || b.status == "errored" {
        return (Verdict::Unknown, None);
    }
    let d = sb - sa;
    // A pass→fail flip is a regression at ANY delta. A single-assertion case
    // moves the score by 1.0 and a twenty-assertion case by 0.05, so a threshold
    // alone would call the second one noise — while the item went from passing to
    // failing, which is the fact the reader came for.
    if (a.status == "passed" && b.status == "failed") || d <= -score_delta_min {
        return (Verdict::Regressed, Some(d));
    }
    if (a.status == "failed" && b.status == "passed") || d >= score_delta_min {
        return (Verdict::Improved, Some(d));
    }
    (Verdict::Unchanged, Some(d))
}

/// Align two arms' item rows and produce the diff.
///
/// Pure over `(Vec<EvalItem>, Vec<EvalItem>)`, so every ordering rule, every
/// threshold and every zero-vs-unknown decision is watched by `cargo test`
/// without a ClickHouse anywhere near it.
#[must_use]
pub fn compare_items(
    a_items: &[EvalItem],
    b_items: &[EvalItem],
    t: CompareThresholds,
) -> Vec<ComparedItem> {
    let mut by_key: std::collections::BTreeMap<AlignKey, SidePair<'_>> =
        std::collections::BTreeMap::new();
    for i in a_items {
        by_key.entry(align_key(i)).or_default().0 = Some(i);
    }
    for i in b_items {
        by_key.entry(align_key(i)).or_default().1 = Some(i);
    }

    let mut rows: Vec<ComparedItem> = by_key
        .into_iter()
        .map(|((keyed, id, ord), (a, b))| {
            let ordinal = a.or(b).map_or(ord, |i| i.item_ordinal);
            let label = a.or(b).map_or_else(String::new, |i| i.case_name.clone());
            let (verdict, delta_score) = match (a, b) {
                (Some(a), Some(b)) => verdict_for(a, b, t.score_delta_min),
                (Some(_), None) => (Verdict::OnlyInA, None),
                (None, Some(_)) => (Verdict::OnlyInB, None),
                // Unreachable: a key exists only because one side put it there.
                (None, None) => (Verdict::Unknown, None),
            };
            let (dl_ms, dl_pct) = match (a, b) {
                (Some(a), Some(b)) => (
                    Some(i64::from(b.latency_ms) - i64::from(a.latency_ms)),
                    delta_pct(f64::from(a.latency_ms), f64::from(b.latency_ms)),
                ),
                _ => (None, None),
            };
            let (dc, dc_pct) = match (a.and_then(|x| x.cost_usd), b.and_then(|x| x.cost_usd)) {
                // Both sides priced. Either side unpriced ⇒ NO delta — never
                // `$0.00`, which would read as "it cost the same".
                (Some(ca), Some(cb)) => (Some(cb - ca), delta_pct(ca, cb)),
                _ => (None, None),
            };
            // THE DUAL MARGIN. Both the absolute AND the relative margin must
            // move before a marker fires.
            let lat_fires = dl_ms.is_some_and(|d| {
                #[allow(clippy::cast_precision_loss)]
                let abs = (d as f64).abs();
                abs > t.latency_delta_min_ms
                    && dl_pct.is_some_and(|p| p.abs() > t.latency_delta_min_pct)
            });
            let cost_fires = dc.is_some_and(|d| {
                d.abs() > t.cost_delta_min_usd
                    && dc_pct.is_some_and(|p| p.abs() > t.cost_delta_min_pct)
            });
            ComparedItem {
                dataset_item_id: keyed.then(|| id.to_string()),
                item_ordinal: ordinal,
                label,
                a: a.map(side),
                b: b.map(side),
                delta_score,
                delta_latency_ms: dl_ms,
                delta_latency_pct: dl_pct,
                delta_cost_usd: dc,
                delta_cost_pct: dc_pct,
                latency_slower: lat_fires && dl_ms.is_some_and(|d| d > 0),
                latency_faster: lat_fires && dl_ms.is_some_and(|d| d < 0),
                cost_higher: cost_fires && dc.is_some_and(|d| d > 0.0),
                cost_lower: cost_fires && dc.is_some_and(|d| d < 0.0),
                verdict: verdict.as_str(),
            }
        })
        .collect();

    // ORDER: verdict rank, then Δscore ASCENDING (most-negative first), then the
    // ordinal so the order is TOTAL and two runs of the same data produce the
    // same page. A partial order here would make the surface's own output
    // unstable between requests.
    rows.sort_by(|x, y| {
        let rx = verdict_rank(x.verdict);
        let ry = verdict_rank(y.verdict);
        rx.cmp(&ry)
            .then_with(|| {
                let dx = x.delta_score.unwrap_or(f64::MAX);
                let dy = y.delta_score.unwrap_or(f64::MAX);
                dx.partial_cmp(&dy).unwrap_or(std::cmp::Ordering::Equal)
            })
            .then_with(|| x.item_ordinal.cmp(&y.item_ordinal))
    });
    rows
}

fn verdict_rank(s: &str) -> u8 {
    match s {
        "regressed" => Verdict::Regressed.rank(),
        "unknown" => Verdict::Unknown.rank(),
        "improved" => Verdict::Improved.rank(),
        "unchanged" => Verdict::Unchanged.rank(),
        "only_in_a" => Verdict::OnlyInA.rank(),
        _ => Verdict::OnlyInB.rank(),
    }
}

/// Fold one arm's MATCHED items into its header strip.
#[must_use]
pub fn aggregate_arm(arm: &Arm, items: &[EvalItem], matched: &[&EvalItem]) -> ArmAggregate {
    let passed = matched.iter().filter(|i| i.status == "passed").count();
    let failed = matched.iter().filter(|i| i.status == "failed").count();
    let errored = matched.iter().filter(|i| i.status == "errored").count();
    let scored: Vec<f64> = matched.iter().filter_map(|i| i.score).collect();
    let priced: Vec<f64> = matched.iter().filter_map(|i| i.cost_usd).collect();
    let latencies: Vec<u32> = matched
        .iter()
        .filter(|i| i.status != "errored")
        .map(|i| i.latency_ms)
        .collect();
    let denom = passed + failed;
    ArmAggregate {
        arm_id: arm.arm_id,
        arm_label: arm.arm_label.clone(),
        ordinal: arm.ordinal,
        eval_run_id: arm.eval_run_id,
        prompt_version_id: arm.prompt_version_id,
        model: arm.model.clone(),
        status: arm.status.as_str(),
        #[allow(clippy::cast_precision_loss)]
        pass_rate: (denom > 0).then(|| ((passed as f64 / denom as f64) * 10_000.0).round() / 100.0),
        passed: u32::try_from(passed).unwrap_or(u32::MAX),
        failed: u32::try_from(failed).unwrap_or(u32::MAX),
        errored: u32::try_from(errored).unwrap_or(u32::MAX),
        #[allow(clippy::cast_precision_loss)]
        mean_score: (!scored.is_empty()).then(|| scored.iter().sum::<f64>() / scored.len() as f64),
        p95_latency_ms: p95(latencies),
        total_cost_usd: priced.iter().sum(),
        unpriced_items: u32::try_from(matched.len().saturating_sub(priced.len()))
            .unwrap_or(u32::MAX),
        items_run: u32::try_from(items.len()).unwrap_or(u32::MAX),
        items_matched: u32::try_from(matched.len()).unwrap_or(u32::MAX),
    }
}

// ── Router ───────────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct ExperimentRoutesState {
    pub store: Arc<dyn ExperimentStore>,
    /// Reused, never re-implemented: an experiment must authorize the dataset and
    /// resolve its snapshot exactly as `POST .../evals` does, and a second
    /// resolution path is how two surfaces come to disagree about which snapshot
    /// "latest" meant.
    pub datasets: Arc<dyn DatasetStore>,
    /// THE ONE execution engine (`EVL-05` §"One engine, not three"). An
    /// experiment is a fan-out over it, never a second executor.
    pub engine: Arc<PromptEvalEngine>,
    /// `None` only when Postgres is unset. The gate then REFUSES — `None` is the
    /// unprivileged state, never a grant.
    pub entitlements: Option<Arc<EntitlementCache>>,
}

/// Mount the experiment routes. The caller mounts this only when
/// `CLICKHOUSE_URL` is set.
pub fn routes() -> Router<ExperimentRoutesState> {
    Router::new()
        .route(
            "/v1/experiments",
            get(list_experiments).post(create_experiment),
        )
        .route("/v1/experiments/{id}", get(get_experiment))
        .route("/v1/experiments/{id}/compare", get(compare_experiment))
        // Per-item detail for a run OUTSIDE an experiment. The same rows, the
        // same tenant bind — an experiment is not the only way to have produced
        // them, and a run started from `POST .../evals` would otherwise have
        // per-item data nothing could read.
        .route("/v1/evals/{eval_run_id}/items", get(list_run_items))
}

// ── DTOs ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ArmBody {
    #[serde(default)]
    label: Option<String>,
    prompt_version_id: Uuid,
    /// Falls back to the version's own `model_pin`. Resolved by the engine, not
    /// here, so there is one answer to "which model did this arm run".
    #[serde(default)]
    model: Option<String>,
}

/// `deny_unknown_fields` on purpose: a smuggled field is a refusal rather than a
/// silently-ignored one. Someone who posts `snapshot_id` misspelled must learn
/// it, not get a run against a snapshot they did not choose.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateExperimentBody {
    name: String,
    /// The prompt every arm's version must belong to. Verified per arm against
    /// `prompt_id_for(tenant, prompt_name)` — a version id in a request body is
    /// not evidence the caller owns it, and it is not evidence it belongs to this
    /// prompt either.
    prompt_name: String,
    dataset_id: Uuid,
    /// Omitted = the dataset's NEWEST snapshot, and the resolved id is written
    /// down. Resolving "latest" without recording the answer hands back exactly
    /// the moving target a snapshot exists to replace.
    #[serde(default)]
    snapshot_id: Option<Uuid>,
    #[serde(default)]
    notes: Option<String>,
    /// The scorers. **Shared across every arm, deliberately**: two arms scored by
    /// different assertions are not a comparison, they are two runs on one
    /// screen. Accepting a per-arm list would make that misuse expressible.
    assertions: Vec<Assertion>,
    arms: Vec<ArmBody>,
}

#[derive(Debug, Serialize)]
struct ExperimentDto {
    experiment_id: Uuid,
    name: String,
    dataset_id: Uuid,
    snapshot_id: Uuid,
    status: &'static str,
    item_count: u32,
    arms: u32,
    notes: String,
    created_at_ms: i64,
    created_by: String,
}

#[derive(Debug, Deserialize)]
struct PageQuery {
    #[serde(default)]
    limit: Option<u32>,
    #[serde(default)]
    cursor: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CompareQuery {
    a: String,
    b: String,
}

fn encode_cursor(ts: i64, id: &str) -> String {
    format!("{ts}:{id}")
}

fn decode_cursor(s: &str) -> Option<(i64, String)> {
    let (ts, id) = s.split_once(':')?;
    let ts = ts.parse::<i64>().ok()?;
    if id.is_empty() {
        return None;
    }
    Some((ts, id.to_string()))
}

// ── Handlers ─────────────────────────────────────────────────────────────────

/// `POST /v1/experiments` — **202 ACCEPTED**, because arms run for minutes.
#[tracing::instrument(skip_all, fields(tenant_id = tracing::field::Empty))]
async fn create_experiment(
    State(state): State<ExperimentRoutesState>,
    headers: HeaderMap,
    Json(body): Json<CreateExperimentBody>,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    let (tenant, actor) = actor_from_auth(&state, &headers).await?;
    tracing::Span::current().record("tenant_id", tenant.to_string());

    // ── Shape, before anything is read or spent ─────────────────────────────
    let name = body.name.trim().to_string();
    if name.is_empty() || name.len() > limits::NAME_BYTES {
        return Err(coded_err(
            StatusCode::BAD_REQUEST,
            "invalid_name",
            "An experiment needs a name.",
            serde_json::json!({ "max_bytes": limits::NAME_BYTES, "got_bytes": name.len() }),
        ));
    }
    let notes = body.notes.unwrap_or_default();
    if notes.len() > limits::NOTES_BYTES {
        return Err(coded_err(
            StatusCode::BAD_REQUEST,
            "notes_too_large",
            "The notes are longer than the limit.",
            serde_json::json!({ "max_bytes": limits::NOTES_BYTES, "got_bytes": notes.len() }),
        ));
    }
    if body.assertions.is_empty() {
        return Err(coded_err(
            StatusCode::BAD_REQUEST,
            "assertions_required",
            "An experiment needs at least one assertion — a run with none can only ever pass, \
             and a comparison of two runs that both always pass measures nothing.",
            serde_json::json!({}),
        ));
    }
    if body.arms.len() < 2 || body.arms.len() > limits::MAX_ARMS {
        return Err(coded_err(
            StatusCode::BAD_REQUEST,
            "invalid_arm_count",
            "An experiment compares between 2 and 4 arms.",
            serde_json::json!({
                "min_arms": 2,
                "max_arms": limits::MAX_ARMS,
                "got_arms": body.arms.len(),
            }),
        ));
    }

    // ── Object-level authorization on every version, before the dataset is
    // touched. A version id arriving in a body is not evidence the caller owns
    // it, and — separately — it is not evidence it belongs to `prompt_name`.
    // Both are checked, because an arm running a version of a DIFFERENT prompt
    // would produce a comparison whose two sides never shared a system prompt.
    let prompt_id = crate::prompt_router::prompt_id_for(&tenant, &body.prompt_name);
    for (i, a) in body.arms.iter().enumerate() {
        let Some(v) = state
            .engine
            .router()
            .version_for_tenant(&tenant, a.prompt_version_id)
        else {
            return Err(coded_err(
                StatusCode::BAD_REQUEST,
                "unknown_prompt_version",
                "One of the arms names a prompt version that is not registered in this \
                 workspace.",
                serde_json::json!({ "arm_index": i, "prompt_version_id": a.prompt_version_id }),
            ));
        };
        if v.prompt_id != prompt_id {
            return Err(coded_err(
                StatusCode::BAD_REQUEST,
                "version_prompt_mismatch",
                "One of the arms names a version of a different prompt. Every arm of an \
                 experiment must be a version of the same prompt, or the two sides never \
                 shared a system prompt and the diff means nothing.",
                serde_json::json!({
                    "arm_index": i,
                    "prompt_name": body.prompt_name,
                    "prompt_version_id": a.prompt_version_id,
                }),
            ));
        }
        if a.model.is_none() && v.model_pin.is_none() {
            return Err(coded_err(
                StatusCode::BAD_REQUEST,
                "no_model",
                "One of the arms has no model to run against: its version has no `model_pin`, \
                 so pass `model` on the arm.",
                serde_json::json!({ "arm_index": i }),
            ));
        }
    }

    // ── The dataset and its FROZEN snapshot, resolved ONCE ──────────────────
    //
    // Both arms are pinned to the id resolved here, which is what makes "same
    // item set" a structural property rather than a validation someone could
    // forget. An unknown dataset gets the same 404 as another tenant's.
    if state
        .datasets
        .get_dataset(&tenant, body.dataset_id)
        .await
        .map_err(|e| store_failed("read the dataset", &e))?
        .is_none()
    {
        return Err(not_found());
    }
    let snapshots = state
        .datasets
        .list_snapshots(&tenant, body.dataset_id)
        .await
        .map_err(|e| store_failed("list the dataset's snapshots", &e))?;
    let snapshot = match body.snapshot_id {
        Some(want) => snapshots.into_iter().find(|s| s.snapshot_id == want),
        // `list_snapshots` returns newest first; "latest" is the first row.
        None => snapshots.into_iter().next(),
    };
    let Some(snapshot) = snapshot else {
        return Err(coded_err(
            StatusCode::UNPROCESSABLE_ENTITY,
            if body.snapshot_id.is_some() {
                "snapshot_not_found"
            } else {
                "dataset_never_frozen"
            },
            "There is no frozen snapshot to run. Freeze one first — a run against the live \
             item list could not be reproduced, which is the only reason to run one.",
            serde_json::json!({ "dataset_id": body.dataset_id }),
        ));
    };
    if snapshot.item_count == 0 {
        return Err(coded_err(
            StatusCode::UNPROCESSABLE_ENTITY,
            "snapshot_empty",
            "That snapshot holds no items, so there is nothing to run.",
            serde_json::json!({ "snapshot_id": snapshot.snapshot_id }),
        ));
    }
    // REFUSED AT CREATE TIME, NEVER TRUNCATED. A truncated experiment that
    // renders as complete is the worst possible shape for an evidence product.
    if snapshot.item_count as usize > limits::MAX_ITEMS {
        return Err(coded_err(
            StatusCode::BAD_REQUEST,
            "dataset_too_large",
            "This snapshot has more items than an experiment runs. Create a smaller dataset \
             or a subset.",
            serde_json::json!({
                "items": snapshot.item_count,
                "max_items": limits::MAX_ITEMS,
            }),
        ));
    }

    // ── THE MONEY CEILING, before anything is claimed or written ────────────
    //
    // Seeded from the durable ClickHouse total first (: an in-memory
    // counter alone is not a cap — a redeploy forgives every dollar accrued).
    // This is up to `arms × items` provider calls from one button, which makes it
    // the single largest new money risk in this sprint.
    let budget_usd = crate::spend::workspace_budget_usd(state.entitlements.as_ref(), &tenant).await;
    if budget_usd.is_some() {
        crate::spend::seed_workspace(state.engine.clickhouse(), &tenant).await;
        let who = crate::spend::Subject::Workspace(*tenant.as_uuid());
        if let Some(refusal) = crate::spend::workspace_refusal(who, budget_usd) {
            return Err(api_err(StatusCode::PAYMENT_REQUIRED, refusal.to_string()));
        }
    }

    let existing = state
        .store
        .count_experiments(&tenant)
        .await
        .map_err(|e| store_failed("count experiments", &e))?;
    if existing >= limits::EXPERIMENTS_PER_TENANT {
        return Err(coded_err(
            StatusCode::CONFLICT,
            "experiment_limit",
            "This workspace is at its experiment limit.",
            serde_json::json!({ "limit": limits::EXPERIMENTS_PER_TENANT, "current": existing }),
        ));
    }

    // ── Durable BEFORE the first provider call ──────────────────────────────
    //
    // Same ordering rule the eval writer states: the alternative is spending the
    // tenant's money with no record that anything started, which is invisible in
    // exactly the way an audit product must never be.
    let experiment = Experiment {
        experiment_id: Uuid::new_v4(),
        name,
        dataset_id: body.dataset_id,
        snapshot_id: snapshot.snapshot_id,
        status: ExperimentStatus::Running,
        item_count: snapshot.item_count,
        notes,
        created_at_ms: datetime64_millis_now(),
        created_by: actor,
    };
    let arms: Vec<Arm> = body
        .arms
        .iter()
        .enumerate()
        .map(|(i, a)| Arm {
            arm_id: Uuid::new_v4(),
            // An empty label means UNLABELLED and the surface renders the
            // ordinal — it does not invent a name.
            arm_label: a.label.clone().unwrap_or_default().trim().to_string(),
            ordinal: u8::try_from(i).unwrap_or(u8::MAX),
            eval_run_id: None,
            prompt_version_id: a.prompt_version_id,
            model: a.model.clone().unwrap_or_default(),
            status: ArmStatus::Pending,
        })
        .collect();

    state
        .store
        .create_experiment(&tenant, &experiment)
        .await
        .map_err(|e| store_failed("create the experiment", &e))?;
    state
        .store
        .insert_arms(&tenant, experiment.experiment_id, &arms)
        .await
        .map_err(|e| store_failed("record the experiment's arms", &e))?;

    let dto = ExperimentDto {
        experiment_id: experiment.experiment_id,
        name: experiment.name.clone(),
        dataset_id: experiment.dataset_id,
        snapshot_id: experiment.snapshot_id,
        status: ExperimentStatus::Running.as_str(),
        item_count: experiment.item_count,
        arms: u32::try_from(arms.len()).unwrap_or(0),
        notes: experiment.notes.clone(),
        created_at_ms: experiment.created_at_ms,
        created_by: experiment.created_by.clone(),
    };

    let runner = ExperimentRunner {
        state: state.clone(),
        tenant,
        prompt_name: body.prompt_name,
        assertions: body.assertions,
        experiment,
        arms,
        budget_usd,
    };
    tokio::spawn(async move { runner.run().await });

    Ok((
        StatusCode::ACCEPTED,
        Json(serde_json::to_value(dto).unwrap_or(serde_json::Value::Null)),
    ))
}

/// `GET /v1/experiments` — cursor-paginated, `limit` capped at 100.
///
/// **Deliberately NOT the shape of `GET /v1/prompts`**, which is unpaginated and
/// is a named defect. A list that stops silently is worse than one that says
/// where it stopped.
#[tracing::instrument(skip_all, fields(tenant_id = tracing::field::Empty))]
async fn list_experiments(
    State(state): State<ExperimentRoutesState>,
    Query(q): Query<PageQuery>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, ApiError> {
    let tenant = tenant_from_auth(&state, &headers).await?;
    tracing::Span::current().record("tenant_id", tenant.to_string());
    let limit = q
        .limit
        .unwrap_or(limits::PAGE_DEFAULT)
        .clamp(1, limits::EXPERIMENTS_PAGE_MAX);
    let cursor = q.cursor.as_deref().and_then(decode_cursor);
    // One more than asked for, so "is there another page" is OBSERVED rather
    // than inferred from a full page — a full last page would otherwise render a
    // next-cursor that leads nowhere.
    let rows = state
        .store
        .list_experiments(&tenant, cursor, limit + 1)
        .await
        .map_err(|e| store_failed("list experiments", &e))?;
    let has_more = rows.len() > limit as usize;
    let page: Vec<(Experiment, u32)> = rows.into_iter().take(limit as usize).collect();
    let next_cursor = has_more.then(|| {
        page.last()
            .map(|(e, _)| encode_cursor(e.created_at_ms, &e.experiment_id.to_string()))
    });
    let items: Vec<ExperimentDto> = page
        .into_iter()
        .map(|(e, arms)| ExperimentDto {
            experiment_id: e.experiment_id,
            name: e.name,
            dataset_id: e.dataset_id,
            snapshot_id: e.snapshot_id,
            status: e.status.as_str(),
            item_count: e.item_count,
            arms,
            notes: e.notes,
            created_at_ms: e.created_at_ms,
            created_by: e.created_by,
        })
        .collect();
    Ok(Json(serde_json::json!({
        "experiments": items,
        "next_cursor": next_cursor.flatten(),
    })))
}

/// `GET /v1/experiments/{id}` — the experiment, its arms, and each arm's
/// aggregate over its OWN items (not over matched items: there is no other side
/// to match against here, and saying so is why the field is named
/// `items_matched` = `items_run` on this surface).
#[tracing::instrument(skip_all, fields(tenant_id = tracing::field::Empty))]
async fn get_experiment(
    State(state): State<ExperimentRoutesState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, ApiError> {
    let tenant = tenant_from_auth(&state, &headers).await?;
    tracing::Span::current().record("tenant_id", tenant.to_string());
    let id = parse_id(&id)?;
    let Some(e) = state
        .store
        .get_experiment(&tenant, id)
        .await
        .map_err(|err| store_failed("read the experiment", &err))?
    else {
        return Err(not_found());
    };
    let arms = state
        .store
        .list_arms(&tenant, id)
        .await
        .map_err(|err| store_failed("list the experiment's arms", &err))?;

    let mut aggregates = Vec::with_capacity(arms.len());
    for arm in &arms {
        let items = match arm.eval_run_id {
            Some(run) => state
                .store
                .run_items(&tenant, run)
                .await
                .map_err(|err| store_failed("read an arm's items", &err))?,
            // NOT STARTED. An empty vec here is the honest shape: every
            // aggregate over it is `null` or `0`, and `items_run = 0` beside a
            // `pending` status says why.
            None => Vec::new(),
        };
        let matched: Vec<&EvalItem> = items.iter().collect();
        aggregates.push(aggregate_arm(arm, &items, &matched));
    }

    Ok(Json(serde_json::json!({
        "experiment_id": e.experiment_id,
        "name": e.name,
        "dataset_id": e.dataset_id,
        "snapshot_id": e.snapshot_id,
        "status": e.status.as_str(),
        "item_count": e.item_count,
        "notes": e.notes,
        "created_at_ms": e.created_at_ms,
        "created_by": e.created_by,
        "arms": aggregates,
        // The compare action is disabled until BOTH arms are terminal, and the
        // API says so rather than leaving the client to re-derive it from five
        // status strings.
        "comparable": arms.iter().filter(|a| a.status.is_terminal()).count() >= 2,
    })))
}

/// `GET /v1/experiments/{id}/compare?a=<arm_id>&b=<arm_id>` — **the deliverable.**
#[tracing::instrument(skip_all, fields(tenant_id = tracing::field::Empty))]
async fn compare_experiment(
    State(state): State<ExperimentRoutesState>,
    Path(id): Path<String>,
    Query(q): Query<CompareQuery>,
    headers: HeaderMap,
) -> Result<Json<CompareResponse>, ApiError> {
    let tenant = tenant_from_auth(&state, &headers).await?;
    tracing::Span::current().record("tenant_id", tenant.to_string());
    let id = parse_id(&id)?;
    let a_id = parse_id(&q.a)?;
    let b_id = parse_id(&q.b)?;
    if a_id == b_id {
        return Err(coded_err(
            StatusCode::BAD_REQUEST,
            "same_arm",
            "Pick two different arms to compare.",
            serde_json::json!({}),
        ));
    }
    let Some(e) = state
        .store
        .get_experiment(&tenant, id)
        .await
        .map_err(|err| store_failed("read the experiment", &err))?
    else {
        return Err(not_found());
    };
    let arms = state
        .store
        .list_arms(&tenant, id)
        .await
        .map_err(|err| store_failed("list the experiment's arms", &err))?;
    // BOTH arms must belong to THIS experiment. An arm id from another
    // experiment — or another tenant — gets the same 404 as a fabricated one.
    let (Some(arm_a), Some(arm_b)) = (
        arms.iter().find(|x| x.arm_id == a_id),
        arms.iter().find(|x| x.arm_id == b_id),
    ) else {
        return Err(not_found());
    };
    // A diff against a still-running arm reports every unfinished item as a
    // regression. Refusing is the only honest answer, and the refusal names which
    // state it is in rather than saying "try again".
    if !arm_a.status.is_terminal() || !arm_b.status.is_terminal() {
        return Err(coded_err(
            StatusCode::CONFLICT,
            "arm_not_finished",
            "One of these arms is still running. Comparing now would compare an incomplete \
             set, and every item it has not reached yet would read as a regression.",
            serde_json::json!({
                "a_status": arm_a.status.as_str(),
                "b_status": arm_b.status.as_str(),
            }),
        ));
    }

    let a_items = match arm_a.eval_run_id {
        Some(run) => state
            .store
            .run_items(&tenant, run)
            .await
            .map_err(|err| store_failed("read arm A's items", &err))?,
        None => Vec::new(),
    };
    let b_items = match arm_b.eval_run_id {
        Some(run) => state
            .store
            .run_items(&tenant, run)
            .await
            .map_err(|err| store_failed("read arm B's items", &err))?,
        None => Vec::new(),
    };

    let thresholds = CompareThresholds::default();
    let rows = compare_items(&a_items, &b_items, thresholds);

    // MATCHED = present on both sides. Aggregates cover exactly these, and the
    // one-sided rows are excluded from every one of them — which is what the
    // partial banner has to say.
    let matched_keys: std::collections::HashSet<AlignKey> = rows
        .iter()
        .filter(|r| r.verdict != "only_in_a" && r.verdict != "only_in_b")
        .filter_map(|r| {
            r.dataset_item_id
                .as_ref()
                .map_or(Some((false, Uuid::nil(), r.item_ordinal)), |s| {
                    Uuid::parse_str(s).ok().map(|u| (true, u, 0))
                })
        })
        .collect();
    let a_matched: Vec<&EvalItem> = a_items
        .iter()
        .filter(|i| matched_keys.contains(&align_key(i)))
        .collect();
    let b_matched: Vec<&EvalItem> = b_items
        .iter()
        .filter(|i| matched_keys.contains(&align_key(i)))
        .collect();

    let count =
        |v: &str| u32::try_from(rows.iter().filter(|r| r.verdict == v).count()).unwrap_or(u32::MAX);
    let regressed_count = count("regressed");
    let improved_count = count("improved");
    let unchanged_count = count("unchanged");
    let unknown_count = count("unknown");
    let only_in_a = count("only_in_a");
    let only_in_b = count("only_in_b");

    let a_agg = aggregate_arm(arm_a, &a_items, &a_matched);
    let b_agg = aggregate_arm(arm_b, &b_items, &b_matched);

    let summary = format!(
        "{regressed_count} of {} items regressed · {improved_count} improved · \
         {unknown_count} could not be scored",
        e.item_count
    );
    // The partial banner. It fires on the ARM's own item count against the frozen
    // snapshot, not on the matched count, because "arm B stopped after 34 of 50"
    // is the fact the reader needs — the one-sided count is a consequence of it.
    let partial_note =
        (a_agg.items_run < e.item_count || b_agg.items_run < e.item_count).then(|| {
            format!(
                "Arm A ran {} of {} items and arm B ran {}. {} items appear on one side only and \
             are excluded from every aggregate above.",
                a_agg.items_run,
                e.item_count,
                b_agg.items_run,
                only_in_a + only_in_b,
            )
        });

    Ok(Json(CompareResponse {
        experiment_id: e.experiment_id,
        name: e.name,
        dataset_id: e.dataset_id,
        snapshot_id: e.snapshot_id,
        item_count: e.item_count,
        a: a_agg,
        b: b_agg,
        rows,
        regressed_count,
        improved_count,
        unchanged_count,
        unknown_count,
        only_in_a,
        only_in_b,
        thresholds,
        summary,
        partial_note,
    }))
}

/// `GET /v1/evals/{eval_run_id}/items` — per-item detail for one run, cursor-
/// paginated with a cap of 200.
#[tracing::instrument(skip_all, fields(tenant_id = tracing::field::Empty))]
async fn list_run_items(
    State(state): State<ExperimentRoutesState>,
    Path(run_id): Path<String>,
    Query(q): Query<PageQuery>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, ApiError> {
    let tenant = tenant_from_auth(&state, &headers).await?;
    tracing::Span::current().record("tenant_id", tenant.to_string());
    let run_id = parse_id(&run_id)?;
    let limit = q
        .limit
        .unwrap_or(limits::PAGE_DEFAULT)
        .clamp(1, limits::ITEMS_PAGE_MAX);
    // The cursor is the last ordinal seen. `eval_run_items`' ORDER BY makes
    // `item_ordinal` unique within a run, so it is a complete keyset on its own —
    // no timestamp tiebreak needed.
    let after = q.cursor.as_deref().and_then(|c| c.parse::<u32>().ok());
    let rows = state
        .store
        .page_run_items(&tenant, run_id, after, limit + 1)
        .await
        .map_err(|e| store_failed("read the run's items", &e))?;
    let has_more = rows.len() > limit as usize;
    let page: Vec<EvalItem> = rows.into_iter().take(limit as usize).collect();
    let next_cursor = has_more
        .then(|| page.last().map(|i| i.item_ordinal.to_string()))
        .flatten();
    let items: Vec<serde_json::Value> = page
        .iter()
        .map(|i| {
            serde_json::json!({
                "item_ordinal": i.item_ordinal,
                // NIL is rendered as `null`, never as a UUID of zeros — the
                // column's own comment says a reader must test against nil
                // explicitly and must not render it as an id.
                "dataset_item_id": (!i.dataset_item_id.is_nil())
                    .then(|| i.dataset_item_id.to_string()),
                "case_name": i.case_name,
                "status": i.status,
                "output": i.output,
                "output_truncated": i.output_truncated,
                "scores": serde_json::from_str::<serde_json::Value>(&i.scores)
                    .unwrap_or_else(|_| serde_json::json!({})),
                "score": i.score,
                "latency_ms": i.latency_ms,
                "cost_usd": i.cost_usd,
                "error": i.error,
            })
        })
        .collect();
    Ok(Json(serde_json::json!({
        "eval_run_id": run_id,
        "items": items,
        "next_cursor": next_cursor,
    })))
}

// ── The runner ───────────────────────────────────────────────────────────────

/// Runs an experiment's arms, one after another.
///
/// **Not a second executor.** Every arm goes through `PromptEvalEngine::run_arm`,
/// which is the same validate → claim → `running` row → execute path a standalone
/// run takes; only the join point differs. A second execution engine for
/// experiments would be a second definition of "an eval run", and the two would
/// drift on the first behaviour added to either.
struct ExperimentRunner {
    state: ExperimentRoutesState,
    tenant: TenantId,
    prompt_name: String,
    assertions: Vec<Assertion>,
    experiment: Experiment,
    arms: Vec<Arm>,
    budget_usd: Option<f64>,
}

impl ExperimentRunner {
    async fn run(mut self) {
        let mut any_errored = false;
        for idx in 0..self.arms.len() {
            let arm = self.arms[idx].clone();
            let req = EvalRunRequest {
                prompt_version_id: arm.prompt_version_id,
                // One suite per experiment, so every arm's `eval_suite_id`
                // matches and the runs group together without a suites table.
                suite_name: format!("experiment:{}", self.experiment.experiment_id),
                cases: CaseSource::Dataset {
                    dataset_id: self.experiment.dataset_id,
                    // PINNED. Not `None` — resolving "latest" per arm would let a
                    // snapshot frozen mid-experiment change the item set under
                    // arm B, and the comparison would silently be across two
                    // different sets.
                    snapshot_id: Some(self.experiment.snapshot_id),
                },
                assertions: self.assertions.clone(),
                model: (!arm.model.is_empty()).then(|| arm.model.clone()),
            };
            let ctx = RunContext {
                budget_usd: self.budget_usd,
                arm: Some(ArmContext {
                    experiment_id: self.experiment.experiment_id,
                    arm_id: arm.arm_id,
                }),
            };
            // Mark the arm RUNNING the moment its run id exists, before the
            // first provider call. Best-effort: a failed progress write is a
            // WARN, never fatal — the durable record is `eval_runs` plus the
            // terminal write below, and losing a progress marker must not lose an
            // arm that is about to spend money.
            let progress_state = self.state.clone();
            let progress_tenant = self.tenant.clone();
            let progress_arm = arm.clone();
            let experiment_id = self.experiment.experiment_id;
            let announce = move |run_id: Uuid| async move {
                let mut a = progress_arm;
                a.eval_run_id = Some(run_id);
                a.status = ArmStatus::Running;
                if let Err(e) = progress_state
                    .store
                    .update_arm(&progress_tenant, experiment_id, &a)
                    .await
                {
                    tracing::warn!(
                        error = format!("{e:#}"),
                        %experiment_id,
                        arm_id = %a.arm_id,
                        "experiment arm progress write failed — the arm still runs"
                    );
                }
            };
            match self
                .state
                .engine
                .run_arm(self.tenant.clone(), &self.prompt_name, req, ctx, announce)
                .await
            {
                Ok(outcome) => {
                    if outcome.status == crate::prompt_eval::EvalStatus::Errored {
                        any_errored = true;
                    }
                    self.arms[idx].eval_run_id = Some(outcome.eval_run_id);
                    self.arms[idx].status = ArmStatus::from(outcome.status);
                    // The arm's model is only known for certain AFTER the engine
                    // resolved it (an empty `model` on the body means "use the
                    // version's pin"). Recording the resolved value is what makes
                    // the surface able to say WHICH model an arm ran, rather than
                    // which one was asked for.
                    if self.arms[idx].model.is_empty() {
                        if let Some(v) = self
                            .state
                            .engine
                            .router()
                            .version_for_tenant(&self.tenant, arm.prompt_version_id)
                        {
                            self.arms[idx].model = v.model_pin.unwrap_or_default();
                        }
                    }
                }
                Err(e) => {
                    // An arm that could not START is `errored` with NO run id —
                    // `None` still means "never started", which is the truth, and
                    // the experiment as a whole is `errored` rather than
                    // `complete`. Recording it as `pending` would leave the
                    // surface waiting forever.
                    any_errored = true;
                    tracing::error!(
                        error = format!("{e:#}"),
                        experiment_id = %self.experiment.experiment_id,
                        arm_id = %arm.arm_id,
                        "experiment arm failed to start"
                    );
                    self.arms[idx].status = ArmStatus::Errored;
                }
            }
            let arm_now = self.arms[idx].clone();
            if let Err(e) = self
                .state
                .store
                .update_arm(&self.tenant, self.experiment.experiment_id, &arm_now)
                .await
            {
                // The run itself is durable in `eval_runs` + `eval_run_items`;
                // what was lost is the LINK. Loud, and the experiment is errored
                // — a surface that cannot name an arm's run must not present the
                // experiment as complete.
                any_errored = true;
                tracing::error!(
                    error = format!("{e:#}"),
                    experiment_id = %self.experiment.experiment_id,
                    arm_id = %arm_now.arm_id,
                    "experiment arm status write failed"
                );
            }
        }

        let status = if any_errored {
            ExperimentStatus::Errored
        } else {
            ExperimentStatus::Complete
        };
        if let Err(e) = self
            .state
            .store
            .set_experiment_status(&self.tenant, &self.experiment, status)
            .await
        {
            tracing::error!(
                error = format!("{e:#}"),
                experiment_id = %self.experiment.experiment_id,
                "experiment terminal status write failed — the row stays `running`"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(ord: u32, id: Uuid, status: &str, score: Option<f64>, ms: u32) -> EvalItem {
        EvalItem {
            item_ordinal: ord,
            dataset_item_id: id,
            case_name: format!("item:{ord}"),
            status: status.into(),
            output: "out".into(),
            output_truncated: false,
            scores: "{}".into(),
            score,
            latency_ms: ms,
            cost_usd: Some(0.001),
            error: (status == "errored").then(|| "boom".to_string()),
        }
    }

    fn arm(label: &str) -> Arm {
        Arm {
            arm_id: Uuid::new_v4(),
            arm_label: label.into(),
            ordinal: 0,
            eval_run_id: Some(Uuid::new_v4()),
            prompt_version_id: Uuid::new_v4(),
            model: "m".into(),
            status: ArmStatus::Passed,
        }
    }

    // ── Zero vs unknown: the core §3 claim ──────────────────────────────────

    #[test]
    fn an_errored_side_is_unknown_and_has_no_delta() {
        let id = Uuid::new_v4();
        let a = vec![item(0, id, "passed", Some(1.0), 100)];
        let b = vec![item(0, id, "errored", None, 0)];
        let rows = compare_items(&a, &b, CompareThresholds::default());
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].verdict, "unknown");
        assert_eq!(
            rows[0].delta_score, None,
            "an errored item must have NO delta — a null, not a -1.0"
        );
    }

    #[test]
    fn a_measured_zero_is_not_unknown() {
        // THE PAIR THIS SURFACE EXISTS FOR. Same shape as the test above except
        // the score is a measured 0.0 instead of absent, and the verdict differs.
        let id = Uuid::new_v4();
        let a = vec![item(0, id, "passed", Some(1.0), 100)];
        let b = vec![item(0, id, "failed", Some(0.0), 100)];
        let rows = compare_items(&a, &b, CompareThresholds::default());
        assert_eq!(rows[0].verdict, "regressed");
        assert_eq!(rows[0].delta_score, Some(-1.0));
        assert!(
            rows[0].b.as_ref().unwrap().score == Some(0.0),
            "a measured zero must survive as Some(0.0), never as None"
        );
    }

    #[test]
    fn a_pass_to_fail_flip_regresses_even_below_the_score_threshold() {
        // 20 assertions, one flips: Δ = -0.05... but make it SMALLER than the
        // threshold to prove the status flip alone carries it.
        let id = Uuid::new_v4();
        let a = vec![item(0, id, "passed", Some(1.0), 100)];
        let b = vec![item(0, id, "failed", Some(0.99), 100)];
        let rows = compare_items(&a, &b, CompareThresholds::default());
        assert_eq!(rows[0].verdict, "regressed");
    }

    #[test]
    fn a_small_score_move_without_a_status_flip_is_unchanged() {
        let id = Uuid::new_v4();
        let a = vec![item(0, id, "passed", Some(1.0), 100)];
        let b = vec![item(0, id, "passed", Some(0.98), 100)];
        let rows = compare_items(&a, &b, CompareThresholds::default());
        assert_eq!(rows[0].verdict, "unchanged");
        // The delta is still REPORTED — "within margin" is not "no movement".
        // Compared with a tolerance because the value is an f64 subtraction.
        let d = rows[0]
            .delta_score
            .expect("both sides scored ⇒ a delta exists");
        assert!((d - -0.02).abs() < 1e-9, "delta was {d}");
    }

    // ── Ordering: regressions first, or the deliverable fails ───────────────

    #[test]
    fn regressions_sort_first_then_unknown_then_improved_then_unchanged() {
        let ids: Vec<Uuid> = (0..4).map(|_| Uuid::new_v4()).collect();
        let a = vec![
            item(0, ids[0], "passed", Some(1.0), 100), // unchanged
            item(1, ids[1], "passed", Some(1.0), 100), // regressed
            item(2, ids[2], "failed", Some(0.0), 100), // improved
            item(3, ids[3], "passed", Some(1.0), 100), // unknown
        ];
        let b = vec![
            item(0, ids[0], "passed", Some(1.0), 100),
            item(1, ids[1], "failed", Some(0.0), 100),
            item(2, ids[2], "passed", Some(1.0), 100),
            item(3, ids[3], "errored", None, 0),
        ];
        let rows = compare_items(&a, &b, CompareThresholds::default());
        let order: Vec<&str> = rows.iter().map(|r| r.verdict).collect();
        assert_eq!(
            order,
            vec!["regressed", "unknown", "improved", "unchanged"],
            "a run scoring worse on some items must show those items FIRST"
        );
    }

    #[test]
    fn regressions_are_ordered_worst_first() {
        let ids: Vec<Uuid> = (0..2).map(|_| Uuid::new_v4()).collect();
        let a = vec![
            item(0, ids[0], "passed", Some(1.0), 100),
            item(1, ids[1], "passed", Some(1.0), 100),
        ];
        let b = vec![
            item(0, ids[0], "failed", Some(0.8), 100), // Δ -0.2
            item(1, ids[1], "failed", Some(0.0), 100), // Δ -1.0, worse
        ];
        let rows = compare_items(&a, &b, CompareThresholds::default());
        assert_eq!(rows[0].delta_score, Some(-1.0));
    }

    // ── The six counts partition the rows exactly ───────────────────────────

    #[test]
    fn the_six_verdicts_partition_the_rows() {
        let ids: Vec<Uuid> = (0..5).map(|_| Uuid::new_v4()).collect();
        let a = vec![
            item(0, ids[0], "passed", Some(1.0), 100),
            item(1, ids[1], "passed", Some(1.0), 100),
            item(2, ids[2], "passed", Some(1.0), 100), // only in A
        ];
        let b = vec![
            item(0, ids[0], "passed", Some(1.0), 100),
            item(1, ids[1], "errored", None, 0),
            item(3, ids[3], "passed", Some(1.0), 100), // only in B
        ];
        let rows = compare_items(&a, &b, CompareThresholds::default());
        let sum: usize = [
            "regressed",
            "improved",
            "unchanged",
            "unknown",
            "only_in_a",
            "only_in_b",
        ]
        .iter()
        .map(|v| rows.iter().filter(|r| r.verdict == *v).count())
        .sum();
        assert_eq!(
            sum,
            rows.len(),
            "the six counts must add up to the row count"
        );
        assert_eq!(rows.iter().filter(|r| r.verdict == "only_in_a").count(), 1);
        assert_eq!(rows.iter().filter(|r| r.verdict == "only_in_b").count(), 1);
    }

    // ── The dual margin ─────────────────────────────────────────────────────

    #[test]
    fn a_latency_marker_needs_both_margins() {
        let id = Uuid::new_v4();
        // +300ms but only +3% — absolute alone must NOT fire.
        let a = vec![item(0, id, "passed", Some(1.0), 10_000)];
        let b = vec![item(0, id, "passed", Some(1.0), 10_300)];
        let rows = compare_items(&a, &b, CompareThresholds::default());
        assert!(!rows[0].latency_slower, "percent margin not crossed");

        // +90% but only +90ms — relative alone must NOT fire.
        let a = vec![item(0, id, "passed", Some(1.0), 100)];
        let b = vec![item(0, id, "passed", Some(1.0), 190)];
        let rows = compare_items(&a, &b, CompareThresholds::default());
        assert!(!rows[0].latency_slower, "absolute margin not crossed");

        // Both crossed.
        let a = vec![item(0, id, "passed", Some(1.0), 1_000)];
        let b = vec![item(0, id, "passed", Some(1.0), 1_600)];
        let rows = compare_items(&a, &b, CompareThresholds::default());
        assert!(rows[0].latency_slower, "both margins crossed — must fire");
        assert!(!rows[0].latency_faster);
    }

    #[test]
    fn a_zero_denominator_gives_a_null_pct_never_infinity() {
        let id = Uuid::new_v4();
        let a = vec![item(0, id, "passed", Some(1.0), 0)];
        let b = vec![item(0, id, "passed", Some(1.0), 500)];
        let rows = compare_items(&a, &b, CompareThresholds::default());
        assert_eq!(rows[0].delta_latency_ms, Some(500));
        assert_eq!(
            rows[0].delta_latency_pct, None,
            "a 0ms baseline has no percentage — never ∞, never a fake 0%"
        );
        assert!(
            !rows[0].latency_slower,
            "with no percentage the dual margin cannot be satisfied"
        );
    }

    #[test]
    fn an_unpriced_side_has_no_cost_delta() {
        let id = Uuid::new_v4();
        let mut a = vec![item(0, id, "passed", Some(1.0), 100)];
        let mut b = vec![item(0, id, "passed", Some(1.0), 100)];
        a[0].cost_usd = Some(0.01);
        b[0].cost_usd = None;
        let rows = compare_items(&a, &b, CompareThresholds::default());
        assert_eq!(
            rows[0].delta_cost_usd, None,
            "an unpriced side must produce no delta, never $0.00"
        );
    }

    // ── Aggregates ──────────────────────────────────────────────────────────

    #[test]
    fn errors_are_excluded_from_the_pass_rate_denominator() {
        let a = arm("A");
        let items = vec![
            item(0, Uuid::new_v4(), "passed", Some(1.0), 100),
            item(1, Uuid::new_v4(), "failed", Some(0.0), 100),
            item(2, Uuid::new_v4(), "errored", None, 0),
        ];
        let refs: Vec<&EvalItem> = items.iter().collect();
        let agg = aggregate_arm(&a, &items, &refs);
        // 1 of 2, NOT 1 of 3 — an upstream outage must not read as a quality
        // regression.
        assert_eq!(agg.pass_rate, Some(50.0));
        assert_eq!(agg.errored, 1);
    }

    #[test]
    fn no_scored_items_gives_a_null_mean_never_zero() {
        let a = arm("A");
        let items = vec![item(0, Uuid::new_v4(), "errored", None, 0)];
        let refs: Vec<&EvalItem> = items.iter().collect();
        let agg = aggregate_arm(&a, &items, &refs);
        assert_eq!(agg.mean_score, None, "no scored items is `—`, never 0.00");
        assert_eq!(agg.pass_rate, None, "no scored items is `—`, never 0%");
        assert_eq!(
            agg.p95_latency_ms, None,
            "a 60s timeout is not a 60s latency measurement"
        );
    }

    #[test]
    fn a_measured_zero_mean_is_reported_as_zero() {
        let a = arm("A");
        let items = vec![
            item(0, Uuid::new_v4(), "failed", Some(0.0), 100),
            item(1, Uuid::new_v4(), "failed", Some(0.0), 100),
        ];
        let refs: Vec<&EvalItem> = items.iter().collect();
        let agg = aggregate_arm(&a, &items, &refs);
        assert_eq!(agg.mean_score, Some(0.0));
        assert_eq!(agg.pass_rate, Some(0.0));
    }

    #[test]
    fn unpriced_items_are_counted_not_summed_as_zero() {
        let a = arm("A");
        let mut items = vec![
            item(0, Uuid::new_v4(), "passed", Some(1.0), 100),
            item(1, Uuid::new_v4(), "passed", Some(1.0), 100),
        ];
        items[1].cost_usd = None;
        let refs: Vec<&EvalItem> = items.iter().collect();
        let agg = aggregate_arm(&a, &items, &refs);
        assert!((agg.total_cost_usd - 0.001).abs() < 1e-9);
        assert_eq!(agg.unpriced_items, 1, "an unknown cost is its own number");
    }

    #[test]
    fn p95_is_nearest_rank() {
        // 20 values 1..=20: ceil(0.95*20) = 19th smallest = 19.
        assert_eq!(p95((1..=20).collect()), Some(19));
        assert_eq!(p95(vec![5]), Some(5));
        assert_eq!(p95(vec![]), None);
    }

    // ── Statuses ────────────────────────────────────────────────────────────

    #[test]
    fn an_unrecognised_arm_status_is_never_silently_terminal() {
        assert_eq!(ArmStatus::parse("passed"), ArmStatus::Passed);
        assert_eq!(ArmStatus::parse("what"), ArmStatus::Pending);
        assert!(!ArmStatus::Pending.is_terminal());
        assert!(!ArmStatus::Running.is_terminal());
        assert!(ArmStatus::Errored.is_terminal());
    }

    #[test]
    fn the_arm_status_vocabulary_is_a_superset_of_eval_status_by_exactly_pending() {
        // `pending` must NEVER be writable into `eval_runs` — a fifth string
        // there makes the promotion gate return `None`, which blocks promotion
        // silently and permanently. This asserts the mapping is total and that
        // nothing maps INTO pending from an EvalStatus.
        for s in [
            crate::prompt_eval::EvalStatus::Running,
            crate::prompt_eval::EvalStatus::Passed,
            crate::prompt_eval::EvalStatus::Failed,
            crate::prompt_eval::EvalStatus::Errored,
        ] {
            assert_ne!(ArmStatus::from(s), ArmStatus::Pending);
            assert_eq!(ArmStatus::from(s).as_str(), s.as_str());
        }
    }

    #[test]
    fn cursors_round_trip_and_reject_garbage() {
        let id = Uuid::new_v4().to_string();
        let c = encode_cursor(1_700_000_000_123, &id);
        assert_eq!(decode_cursor(&c), Some((1_700_000_000_123, id)));
        assert_eq!(decode_cursor("nope"), None);
        assert_eq!(decode_cursor("123:"), None);
    }

    #[test]
    fn a_nil_dataset_item_id_is_never_rendered_as_an_id() {
        let a = vec![item(0, Uuid::nil(), "passed", Some(1.0), 100)];
        let b = vec![item(0, Uuid::nil(), "passed", Some(1.0), 100)];
        let rows = compare_items(&a, &b, CompareThresholds::default());
        assert_eq!(rows.len(), 1, "nil ids must align on the ordinal instead");
        assert_eq!(
            rows[0].dataset_item_id, None,
            "the all-zero UUID must render as null, never as an id"
        );
    }
}

// ── REAL-CLICKHOUSE ROUND TRIP ───────────────────────────────────────────────
//
// WHY THIS EXISTS, and why it is not optional (founder ruling R97).
//
// Item 8 shipped 49 green tests, a clean gate and a successful deploy — and TWO
// wire-level defects to production in one night. Both were invisible to every one
// of those tests because they all drove a MOCK STORE, and a mock stores a value
// and hands it back: THE BYTES ON THE WIRE ARE THE ENTIRE SUBJECT and no mock
// inspects them.
//
//   B-272  a projection aliases `toString(x) AS x`, and an UNQUALIFIED
//          `WHERE x = toUUID(?)` then compares the aliased String against a
//          UUID. ClickHouse answers Code 386 and EVERY read 502s.
//   B-273  a `String` field against a `FixedString(64)` column. RowBinary emits
//          a varint length prefix for one and none for the other, the stream
//          desynchronises, and the server reports the mismatch on a LATER row.
//
// This module writes and reads EVERY new row type of item 9 — `experiments`,
// `experiment_arms` and `eval_run_items` — through the REAL stores against a REAL
// server, and it is the only thing in the suite that can see either class.
//
// `#[ignore]` + `CLICKHOUSE_TEST_URL`: run via
// `scripts/ci/run-clickhouse-integration.sh`, which starts a throwaway container.
#[cfg(test)]
mod clickhouse_roundtrip {
    use super::*;
    use crate::prompt_eval::EvalRunItemRow;

    fn ch() -> Option<clickhouse::Client> {
        let url = std::env::var("CLICKHOUSE_TEST_URL").ok()?;
        Some(
            clickhouse::Client::default()
                .with_url(url)
                .with_database("tracelane"),
        )
    }

    /// Apply migrations 18 AND 19 for real. Not a hand-written `CREATE TABLE`: a
    /// test that declares its own schema proves the code agrees with the TEST,
    /// which is the tautology B-273 already slipped through once.
    async fn ensure_schema(c: &clickhouse::Client) {
        clickhouse::Client::default()
            .with_url(std::env::var("CLICKHOUSE_TEST_URL").expect("CLICKHOUSE_TEST_URL"))
            .query("CREATE DATABASE IF NOT EXISTS tracelane")
            .execute()
            .await
            .expect("create database");
        for (label, sql) in [
            (
                "18",
                include_str!(
                    "../../../infra/dev/clickhouse/migrations/18_datasets_and_experiments.sql"
                ),
            ),
            (
                "19",
                include_str!(
                    "../../../infra/dev/clickhouse/migrations/19_evl02_experiment_arms.sql"
                ),
            ),
        ] {
            for stmt in crate::clickhouse_query::split_migration_statements(sql) {
                c.query(&stmt)
                    .execute()
                    .await
                    .unwrap_or_else(|e| panic!("migration {label} stmt failed: {e}\n{stmt}"));
            }
        }
    }

    fn experiment(dataset_id: Uuid, snapshot_id: Uuid) -> Experiment {
        Experiment {
            experiment_id: Uuid::new_v4(),
            name: "roundtrip".into(),
            dataset_id,
            snapshot_id,
            status: ExperimentStatus::Running,
            item_count: 3,
            notes: "notes survive".into(),
            created_at_ms: datetime64_millis_now(),
            created_by: "user_test".into(),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn item_row(
        tenant: &TenantId,
        run: Uuid,
        ordinal: u32,
        dataset_item_id: Uuid,
        dataset_id: Option<Uuid>,
        snapshot_id: Option<Uuid>,
        status: &str,
        score: Option<f64>,
        cost: Option<f64>,
    ) -> EvalRunItemRow {
        EvalRunItemRow {
            tenant_id: tenant.to_string(),
            eval_run_id: run,
            item_ordinal: ordinal,
            dataset_item_id,
            dataset_id,
            dataset_snapshot_id: snapshot_id,
            case_name: format!("item:{ordinal}"),
            status: status.into(),
            output: "the model said this".into(),
            output_truncated: 0,
            scores: r#"{"contains(\"ok\")":1.0}"#.into(),
            score,
            latency_ms: 1_234,
            cost_usd: cost,
            error: (status == "errored").then(|| "upstream 500".to_string()),
            started_at: datetime64_millis_now(),
        }
    }

    /// THE ROUND TRIP. Every new row type, written through the real writer and
    /// read back through the real reader.
    ///
    /// A FRESH TENANT UUID PER RUN, so a dirty container and two concurrent runs
    /// cannot make one test read another's rows.
    #[tokio::test]
    #[ignore = "needs CLICKHOUSE_TEST_URL — run scripts/ci/run-clickhouse-integration.sh"]
    async fn an_experiment_its_arms_and_its_items_survive_a_real_round_trip() {
        let Some(c) = ch() else {
            panic!("CLICKHOUSE_TEST_URL not set — this test cannot run, which is not a pass");
        };
        ensure_schema(&c).await;
        let store = ClickHouseExperimentStore::new(c.clone());
        let tenant = TenantId::from_jwt_claim(Uuid::new_v4());
        let dataset_id = Uuid::new_v4();
        let snapshot_id = Uuid::new_v4();

        // ── experiments ─────────────────────────────────────────────────────
        let e = experiment(dataset_id, snapshot_id);
        store
            .create_experiment(&tenant, &e)
            .await
            .expect("create_experiment must not desynchronise the RowBinary stream");
        let got = store
            .get_experiment(&tenant, e.experiment_id)
            .await
            .expect("get_experiment must not fail on a UUID WHERE (B-272)")
            .expect("the experiment written one line ago must be readable");
        assert_eq!(got, e, "the experiment did not survive the round trip");

        // migration 19's two ADDed columns specifically — an `ALTER ADD COLUMN`
        // appends at the END of the table, and the `clickhouse` crate emits the
        // column list from the struct's field NAMES, so this is the assertion
        // that the two agree.
        assert_eq!(
            got.item_count, 3,
            "item_count (migration 19) did not survive"
        );
        assert_eq!(
            got.notes, "notes survive",
            "notes (migration 19) did not survive"
        );

        // ── experiment_arms, including the Nullable(UUID) ───────────────────
        let run_a = Uuid::new_v4();
        let arms = vec![
            Arm {
                arm_id: Uuid::new_v4(),
                arm_label: "A".into(),
                ordinal: 0,
                eval_run_id: Some(run_a),
                prompt_version_id: Uuid::new_v4(),
                model: "claude-haiku-4-5".into(),
                status: ArmStatus::Passed,
            },
            Arm {
                arm_id: Uuid::new_v4(),
                arm_label: String::new(),
                ordinal: 1,
                // NULL — "not started". The value this column exists to hold,
                // and the one an all-zero UUID would have been indistinguishable
                // from.
                eval_run_id: None,
                prompt_version_id: Uuid::new_v4(),
                model: String::new(),
                status: ArmStatus::Pending,
            },
        ];
        store
            .insert_arms(&tenant, e.experiment_id, &arms)
            .await
            .expect("insert_arms must reach ClickHouse");
        let read_arms = store
            .list_arms(&tenant, e.experiment_id)
            .await
            .expect("list_arms must not fail on a UUID WHERE (B-272)");
        assert_eq!(read_arms, arms, "the arms did not survive the round trip");
        assert_eq!(
            read_arms[1].eval_run_id, None,
            "a NULL eval_run_id must read back as None, NEVER as a zero UUID"
        );

        // The `ReplacingMergeTree(updated_at)` update path: rewrite arm B with a
        // run id and a terminal status, then read `FINAL` and see exactly ONE row
        // for it, carrying the NEW values.
        let mut updated = arms[1].clone();
        updated.eval_run_id = Some(Uuid::new_v4());
        updated.status = ArmStatus::Failed;
        updated.model = "claude-haiku-4-5".into();
        store
            .update_arm(&tenant, e.experiment_id, &updated)
            .await
            .expect("update_arm must reach ClickHouse");
        let read_arms = store
            .list_arms(&tenant, e.experiment_id)
            .await
            .expect("list_arms after update");
        assert_eq!(
            read_arms.len(),
            2,
            "FINAL must collapse the rewritten arm, not show it twice"
        );
        assert_eq!(read_arms[1], updated, "the arm rewrite did not take effect");

        // ── eval_run_items, through the REAL eval writer ────────────────────
        //
        // This is the write path `execute_run` uses, so a width mismatch here is
        // the same failure that would hit prod — not a mirror of it.
        let rows = vec![
            item_row(
                &tenant,
                run_a,
                0,
                Uuid::new_v4(),
                Some(dataset_id),
                Some(snapshot_id),
                "passed",
                Some(1.0),
                Some(0.000_25),
            ),
            // THE ZERO-VS-UNKNOWN PAIR, side by side on the wire.
            item_row(
                &tenant,
                run_a,
                1,
                Uuid::new_v4(),
                Some(dataset_id),
                Some(snapshot_id),
                "failed",
                Some(0.0),
                Some(0.0),
            ),
            item_row(
                &tenant,
                run_a,
                2,
                // NIL — an inline case with no frozen item behind it.
                Uuid::nil(),
                None,
                None,
                "errored",
                None,
                None,
            ),
        ];
        crate::prompt_eval::insert_run_items(&c, &rows)
            .await
            .expect("eval_run_items insert must not desynchronise the RowBinary stream");

        let items = store
            .run_items(&tenant, run_a)
            .await
            .expect("run_items must not fail on a UUID WHERE (B-272)");
        assert_eq!(items.len(), 3, "the item rows were not readable back");

        assert_eq!(items[0].score, Some(1.0));
        assert_eq!(items[0].cost_usd, Some(0.000_25));
        assert_eq!(items[0].status, "passed");
        assert!(items[0].error.is_none());
        assert_eq!(items[0].case_name, "item:0");
        assert_eq!(items[0].latency_ms, 1_234);

        // A MEASURED ZERO. `Some(0.0)`, not `None` — the presence flag decides,
        // never the value, and this is the assertion that proves the SQL's
        // `score IS NOT NULL` projection is doing that job.
        assert_eq!(
            items[1].score,
            Some(0.0),
            "a measured zero must survive as Some(0.0) — collapsing it to None is \
             the exact defect this surface exists to prevent"
        );
        assert_eq!(items[1].cost_usd, Some(0.0));

        // UNKNOWN. `None`, from a real `NULL` column — not a zero.
        assert_eq!(items[2].score, None, "a NULL score must read back as None");
        assert_eq!(
            items[2].cost_usd, None,
            "a NULL cost must read back as None"
        );
        assert_eq!(items[2].error.as_deref(), Some("upstream 500"));
        assert!(
            items[2].dataset_item_id.is_nil(),
            "an inline case's dataset_item_id must be the all-zero UUID"
        );

        // And the whole point: the two arms align, and the diff tells the
        // measured zero from the unknown.
        let rows_b = [item_row(
            &tenant,
            run_a,
            0,
            items[0].dataset_item_id,
            Some(dataset_id),
            Some(snapshot_id),
            "failed",
            Some(0.0),
            Some(0.000_25),
        )];
        let b_items: Vec<EvalItem> = rows_b
            .iter()
            .map(|r| EvalItem {
                item_ordinal: r.item_ordinal,
                dataset_item_id: r.dataset_item_id,
                case_name: r.case_name.clone(),
                status: r.status.clone(),
                output: r.output.clone(),
                output_truncated: false,
                scores: r.scores.clone(),
                score: r.score,
                latency_ms: r.latency_ms,
                cost_usd: r.cost_usd,
                error: r.error.clone(),
            })
            .collect();
        let diff = compare_items(&items, &b_items, CompareThresholds::default());
        assert_eq!(diff[0].verdict, "regressed");
        assert_eq!(diff[0].delta_score, Some(-1.0));
    }

    /// TENANT ISOLATION, on the real engine rather than on a mock that was told
    /// to filter. Every read on this surface binds `tenant_id`, and a mock proves
    /// only that the argument was passed.
    #[tokio::test]
    #[ignore = "needs CLICKHOUSE_TEST_URL — run scripts/ci/run-clickhouse-integration.sh"]
    async fn a_second_tenant_cannot_read_the_first_tenants_experiment() {
        let Some(c) = ch() else {
            panic!("CLICKHOUSE_TEST_URL not set — this test cannot run, which is not a pass");
        };
        ensure_schema(&c).await;
        let store = ClickHouseExperimentStore::new(c.clone());
        let a = TenantId::from_jwt_claim(Uuid::new_v4());
        let b = TenantId::from_jwt_claim(Uuid::new_v4());

        let e = experiment(Uuid::new_v4(), Uuid::new_v4());
        store.create_experiment(&a, &e).await.expect("create");
        let arm_row = Arm {
            arm_id: Uuid::new_v4(),
            arm_label: "A".into(),
            ordinal: 0,
            eval_run_id: Some(Uuid::new_v4()),
            prompt_version_id: Uuid::new_v4(),
            model: "m".into(),
            status: ArmStatus::Passed,
        };
        store
            .insert_arms(&a, e.experiment_id, std::slice::from_ref(&arm_row))
            .await
            .expect("insert_arms");
        let run = arm_row.eval_run_id.expect("set above");
        crate::prompt_eval::insert_run_items(
            &c,
            &[item_row(
                &a,
                run,
                0,
                Uuid::new_v4(),
                None,
                None,
                "passed",
                Some(1.0),
                Some(0.01),
            )],
        )
        .await
        .expect("insert items");

        assert!(
            store
                .get_experiment(&b, e.experiment_id)
                .await
                .expect("query must succeed")
                .is_none(),
            "tenant B read tenant A's experiment"
        );
        assert!(
            store
                .list_arms(&b, e.experiment_id)
                .await
                .expect("query must succeed")
                .is_empty(),
            "tenant B read tenant A's arms"
        );
        assert!(
            store
                .run_items(&b, run)
                .await
                .expect("query must succeed")
                .is_empty(),
            "tenant B read tenant A's item rows — the per-item output is a verbatim \
             copy of another workspace's model answers"
        );
        // And tenant A still can, so the assertions above are not passing because
        // the write failed. A refusal test that would pass on an empty table
        // proves nothing.
        assert!(
            store
                .get_experiment(&a, e.experiment_id)
                .await
                .expect("query must succeed")
                .is_some(),
            "tenant A cannot read its own experiment — the isolation assertions above \
             would then be vacuous"
        );
        assert_eq!(store.run_items(&a, run).await.expect("query").len(), 1);
    }
}
