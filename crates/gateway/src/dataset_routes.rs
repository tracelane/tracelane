//! `EVL-04` — datasets: a production trace becomes a permanent test case in one
//! click. The HTTP surface only; the engine that consumes a snapshot is
//! `prompt_eval.rs` and it is already deployed.
//!
//! Mounted only when `CLICKHOUSE_URL` is set, matching `trace_reads::routes` —
//! so this surface cannot exist in a half-configured state and silently return
//! empty lists that read as "you have no datasets".
//!
//! ## THE COPY RULE — the one decision the whole row is built on
//!
//! An item **copies** the span's content; it never references the trace, and it
//! never trusts a client-supplied payload. `POST /v1/datasets/{id}/items` takes
//! `{trace_id, span_id}` and **nothing else** (`deny_unknown_fields`, so a
//! smuggled `input` is a refusal rather than a silently-ignored field). The
//! gateway re-reads the span server-side under the validated tenant claim.
//! Both halves of the reason are written again at the call site, because that is
//! where someone will be tempted to "optimise" it into a foreign key.
//!
//! ## The three refusals, and why they must stay three
//!
//! A trace with no content looks IDENTICAL in the data to a filter that matched
//! nothing — both are zero rows — and the three causes have three different
//! remedies. They are never collapsed:
//!
//! | Code | Fact | Decided from |
//! |---|---|---|
//! | `422 content_capture_disabled` | this workspace records no prompt content | `config::trace_content()` — the AUTHORITATIVE allowlist, never inferred from an empty result |
//! | `422 span_has_no_content` | capture is on, this span predates it | the span row existing but carrying no `gen_ai_input_messages` |
//! | `404` (identical body either way) | unknown trace/span, or another tenant's | the tenant-scoped span lookup returning nothing |
//!
//! A fourth, `422 span_content_unreadable`, exists for a span whose recorded
//! messages do not deserialize. Folding it into `span_has_no_content` would be a
//! lie — the content IS there and something else is wrong.
//!
//! ## `expected_output` is honestly absent, and that is not an error
//!
//! Production captures INPUT ONLY: `crates/gateway/src/server.rs` publishes the
//! span BEFORE the response-side guardrail seam so a BLOCKED request still
//! produces a span (#81), so `gen_ai_output_messages` is populated nowhere. A
//! trace-derived item therefore ALWAYS has `expected_output = NULL`, and the
//! response says so in a machine-readable field
//! (`expected_output_reason: "output_not_captured"`) rather than shipping an
//! empty string, which would be a test case that silently passes nothing and
//! fails nothing.
//!
//! ## Tenant isolation
//!
//! `tenant_id` comes ONLY from `Claims.tenant_id` (the `org_id` → internal-UUID
//! bridge lives in `auth::resolve_tenant_id`). It is never read from a path,
//! query or body. Every SELECT and every INSERT binds it. A dataset id that is
//! unknown, malformed, or belongs to another tenant returns the SAME 404 body —
//! naming which id was missing would confirm that the other one exists.
//!
//! ## Resource caps
//!
//! Every SELECT goes through `clickhouse_query::TenantQuery` at
//! `PlanTier::Builder` — the TIGHTEST tier, deliberately, for the reason
//! `trace_reads.rs` already writes down: these are background/curation queries
//! and must never out-consume the interactive dashboard queries of the same
//! workspace. Dataset routes buy no inference, so the only thing they can spend
//! is ClickHouse time.
//!
//! ## The schema this module is written against
//!
//! ClickHouse migration `18_datasets_and_experiments.sql` (spec `EVL-04` §2.2).
//! **It is applied to prod BEFORE the gateway that reads it deploys.** The
//! columns this file binds, in the order the SELECTs list them:
//!
//! ```sql
//! datasets(tenant_id String, dataset_id UUID, name String,
//!          description String DEFAULT '', deleted UInt8 DEFAULT 0,
//!          created_at DateTime64(3,'UTC'), created_by String,
//!          updated_at DateTime64(3,'UTC'))
//!   ENGINE = ReplacingMergeTree(updated_at) ORDER BY (tenant_id, dataset_id)
//!
//! dataset_items(tenant_id String, dataset_id UUID, item_id UUID, input String,
//!          system String DEFAULT '', expected_output Nullable(String),
//!          metadata String DEFAULT '{}', source_trace_id Nullable(UUID),
//!          source_span_id String DEFAULT '', input_hash FixedString(64),
//!          deleted UInt8 DEFAULT 0, created_at DateTime64(3,'UTC'),
//!          created_by String, updated_at DateTime64(3,'UTC'))
//!   ENGINE = ReplacingMergeTree(updated_at)
//!   ORDER BY (tenant_id, dataset_id, item_id)
//!
//! dataset_snapshots(tenant_id String, dataset_id UUID, snapshot_id UUID,
//!          item_count UInt32, created_at DateTime64(3,'UTC'), created_by String)
//!   ENGINE = MergeTree ORDER BY (tenant_id, dataset_id, snapshot_id)
//!
//! dataset_snapshot_items(tenant_id String, snapshot_id UUID, ordinal UInt32,
//!          item_id UUID, input String, system String DEFAULT '',
//!          expected_output Nullable(String), metadata String DEFAULT '{}',
//!          input_hash FixedString(64), source_trace_id Nullable(UUID),
//!          source_span_id String DEFAULT '')
//!   ENGINE = MergeTree ORDER BY (tenant_id, snapshot_id, ordinal)
//! ```
//!
//! `dataset_snapshot_items` is a plain `MergeTree` on purpose: **immutable by
//! ENGINE, not by convention.** That is the same argument as the copy rule, one
//! level up — `dataset_items` is a `ReplacingMergeTree`, so a snapshot that
//! merely referenced item ids would point at a moving target and nothing would
//! error.

use std::sync::Arc;

use anyhow::{Context as _, Result};
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Path, Query, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::auth::Claims;
use crate::clickhouse_query::{PlanTier, TenantQuery, datetime64_millis_now};
use crate::entitlement_cache::{EntitlementCache, FeatureKey};
use tracelane_shared::{Message, TenantId};

// ── Limits (spec §5) ─────────────────────────────────────────────────────────

/// Hard ceilings. Every one is refused with a typed error naming the limit and
/// the observed value. **Nothing here truncates silently** — a prompt quietly
/// cut short is a test case that tests something else, and nobody would notice
/// until the eval it gates disagreed with production.
pub mod limits {
    /// Items per dataset. Pinned EQUAL to `prompt_eval::limits::MAX_CASES` by
    /// the const assertion below, so a dataset that cannot be run cannot be
    /// created. Raising it means raising both together plus a re-measure of run
    /// wall clock; shipping a 5,000-item dataset whose only consumer refuses at
    /// 201 is the dormant-feature shape this repo already tracks.
    pub const ITEMS_PER_DATASET: usize = 200;
    /// Datasets per tenant.
    pub const DATASETS_PER_TENANT: u64 = 100;
    /// Snapshots per dataset. Snapshots are never auto-deleted — deleting one
    /// un-reproduces every run that cited it — so the cap refuses rather than
    /// evicting.
    pub const SNAPSHOTS_PER_DATASET: u64 = 100;
    /// `input` + `system`, in bytes. The same figure as the capture path's
    /// `max_field_bytes` default, so an item can hold exactly what a span can.
    pub const ITEM_INPUT_BYTES: usize = 65_536;
    /// `expected_output`, in bytes.
    pub const EXPECTED_OUTPUT_BYTES: usize = 65_536;
    /// `metadata` JSON, in bytes.
    pub const METADATA_BYTES: usize = 8_192;
    /// Import file, in bytes. Enforced by an axum body limit on the import
    /// route AND re-checked in the handler, because the layer bounds the
    /// TRANSFER and the handler bounds what we agreed to parse.
    pub const IMPORT_BYTES: usize = 5 * 1024 * 1024;
    /// Default list page size.
    pub const PAGE_DEFAULT: u32 = 50;
    /// Maximum list page size a caller may ask for.
    pub const PAGE_MAX: u32 = 200;
    /// Dataset name. A label, but a displayed one — bounded so a list row
    /// cannot be a megabyte.
    pub const NAME_BYTES: usize = 200;
    /// Dataset description.
    pub const DESCRIPTION_BYTES: usize = 2_000;
    /// Defensive bound on a caller-supplied span id.
    pub const SPAN_ID_BYTES: usize = 128;
}

// A dataset whose item count exceeds what the eval engine will accept is a
// dataset you cannot run — the exact dormant shape §5 pins these two constants
// to prevent. Making it a compile error means the two cannot drift by a commit
// that only touches one of them.
const _: () = assert!(
    limits::ITEMS_PER_DATASET == crate::prompt_eval::limits::MAX_CASES,
    "items-per-dataset must equal prompt_eval::limits::MAX_CASES, or a dataset that \
     cannot be run becomes creatable"
);

/// UUIDv5 namespace for `snapshot_id`. Same convention as
/// `prompt_eval::eval_suite_id_for` and `prompt_router::prompt_id_for`: the id
/// is DERIVED from the content, so re-freezing an unchanged dataset returns the
/// same `snapshot_id` and writes nothing, and two runs that claim the same
/// inputs provably had them.
const SNAPSHOT_NAMESPACE: Uuid = Uuid::from_u128(0x7c31_ab05_4d92_4f68_9e13_20b7_6f4a_c881);

// ── Error shape ──────────────────────────────────────────────────────────────

/// One error shape for every handler on this surface: a typed JSON body with a
/// machine-readable `error` code.
type ApiError = (StatusCode, Json<serde_json::Value>);

/// Build a typed error body.
///
/// This is `prompt_routes::write_err` verbatim, including the double-encoding
/// guard, because that function is private to its module and a second error
/// SHAPE on a sibling surface is what the dashboard's error rendering cannot
/// survive. The guard matters: `auth::role_forbidden_json` and the A13 scope
/// refusal both hand us a fully-formed JSON OBJECT as a string, and wrapping one
/// of those in `{"error": …}` double-encodes it, so `body.error.required_role`
/// arrives escaped inside a string and reads as `undefined`. Observed on prod
/// 2026-08-19 on the prompt surface; the tests there could not see it because
/// `contains()` passes on either shape.
fn api_err(status: StatusCode, msg: impl Into<String>) -> ApiError {
    let msg = msg.into();
    match serde_json::from_str::<serde_json::Value>(&msg) {
        Ok(v) if v.is_object() => (status, Json(v)),
        _ => (status, Json(serde_json::json!({ "error": msg }))),
    }
}

/// A typed refusal that carries structured detail beside the code.
fn coded_err(status: StatusCode, code: &str, message: &str, extra: serde_json::Value) -> ApiError {
    let mut body = serde_json::json!({ "error": code, "message": message });
    if let (Some(obj), Some(more)) = (body.as_object_mut(), extra.as_object()) {
        for (k, v) in more {
            obj.insert(k.clone(), v.clone());
        }
    }
    (status, Json(body))
}

/// The 404 for "no such dataset / trace / span **for this tenant**".
///
/// ONE function, so every caller emits BYTE-IDENTICAL bytes. Naming which id
/// was missing would confirm that the other one exists, which is how a
/// cross-tenant existence oracle gets built one helpful message at a time —
/// the discipline `apps/web/app/api/traces/compare/route.ts` already writes
/// down for the trace surface.
fn not_found() -> ApiError {
    (
        StatusCode::NOT_FOUND,
        Json(serde_json::json!({
            "error": "not_found",
            "message": "No such dataset, trace or span in this workspace.",
        })),
    )
}

// ── Auth seams ───────────────────────────────────────────────────────────────

async fn claims_from_auth(headers: &HeaderMap) -> Result<Claims, ApiError> {
    let h = headers.get("authorization").ok_or_else(|| {
        api_err(
            StatusCode::UNAUTHORIZED,
            "missing Authorization header".to_string(),
        )
    })?;
    let s = h.to_str().map_err(|_| {
        api_err(
            StatusCode::BAD_REQUEST,
            "Authorization must be ASCII".to_string(),
        )
    })?;
    crate::auth::validate_authorization(s)
        .await
        .map_err(|e| api_err(StatusCode::UNAUTHORIZED, format!("auth failed: {e}")))
}

/// A13 scope gate for the READ surfaces.
///
/// A dataset holds a verbatim copy of the workspace's prompt content, so it is
/// exactly the asset `Scope::Read` exists to fence: an `ingest`-scoped SDK key —
/// the credential that ships inside a customer's container image — must not be
/// able to read it back out. This is the same exfiltration shape B-230 closed on
/// `tool_analytics`, `billing/usage` and the audit routes.
fn authorize_read(claims: &Claims) -> Result<(), ApiError> {
    if !claims.allows_scope(crate::auth::scope::Scope::Read) {
        tracing::warn!(sub = %claims.sub, "api key lacks the `read` scope — refusing dataset read");
        return Err(api_err(
            StatusCode::FORBIDDEN,
            serde_json::json!({
                "error": "This API key is not scoped to read recorded data. A dataset holds \
                          a copy of your recorded prompt content; reading it needs the \
                          `read` scope.",
                "type": "insufficient_scope",
                "required_scope": "read",
            })
            .to_string(),
        ));
    }
    Ok(())
}

/// Role + scope gate for the WRITE surfaces.
///
/// **Role** reuses `Claims::can_write_prompts()` — the one gate that already
/// exists for a sibling curation surface: owner/admin JWTs and machine
/// credentials admitted, `member`/`viewer` denied, an unrecognised slug fails
/// CLOSED. A second role vocabulary for a sibling surface is how the vocabulary
/// drifts.
///
/// **Scope** is a separate question and the difference is load-bearing:
/// `can_write_prompts` matches the `role: None` arm for ANY `AuthMethod::ApiKey`
/// *without ever reading `key_scope`*, so on its own it would let a `read`-only
/// or `ingest`-only key create datasets. That exact gap survived one audit on
/// the prompt surface (`prompt_routes::authorize_write` says so at the site), so
/// it is closed here on the first commit rather than found later.
///
/// `Admin` is the right scope for the same reason it is right there: these
/// routes mutate durable workspace state, and `KeyScope::allows` deliberately
/// has no implication hierarchy, so a key that needs two capabilities lists two.
fn authorize_write(claims: &Claims) -> Result<(), ApiError> {
    if !claims.can_write_prompts() {
        return Err(api_err(
            StatusCode::FORBIDDEN,
            crate::auth::role_forbidden_json("owner"),
        ));
    }
    if !claims.allows_scope(crate::auth::scope::Scope::Admin) {
        tracing::warn!(sub = %claims.sub, "api key lacks the `admin` scope — refusing dataset write");
        return Err(api_err(
            StatusCode::FORBIDDEN,
            serde_json::json!({
                "error": "This API key is not scoped to manage datasets. Creating, editing \
                          and freezing datasets changes durable workspace state; it needs \
                          the `admin` scope.",
                "type": "insufficient_scope",
                "required_scope": "admin",
            })
            .to_string(),
        ));
    }
    Ok(())
}

/// The entitlement gate.
///
/// **Absent cache ⇒ REFUSE.** `state.entitlements` is `Some` iff a Postgres
/// control plane exists, so `None` is the unprivileged state
/// (`.claude/rules/tenancy.md`): a no-cache path that GRANTS produces no error,
/// no alert and no complaint, which is exactly how the guardrail rail gate
/// shipped inverted. The refusal is a `503` rather than a `403` because the
/// honest fact is "we could not verify", not "you are not entitled" — the same
/// posture as the audit-export gate and `prompt_routes`.
async fn require_datasets(
    entitlements: &Option<Arc<EntitlementCache>>,
    tenant: &TenantId,
) -> Result<(), ApiError> {
    match entitlements {
        Some(cache) => {
            if cache.check(*tenant.as_uuid(), FeatureKey::Datasets).await {
                Ok(())
            } else {
                Err(coded_err(
                    StatusCode::FORBIDDEN,
                    "entitlement_required",
                    "Datasets turn production traces into a fixed set of test cases. \
                     Your plan does not include them.",
                    serde_json::json!({
                        "feature": "datasets",
                        "upgrade_url": "https://app.tracelane.dev/settings/billing",
                    }),
                ))
            }
        }
        None => {
            tracing::error!("datasets: entitlement cache unavailable (no Postgres) — denying");
            Err(api_err(
                StatusCode::SERVICE_UNAVAILABLE,
                "entitlement verification unavailable".to_string(),
            ))
        }
    }
}

/// Authenticate + authorize a read. Returns the tenant from the validated claim.
async fn tenant_from_auth(
    state: &DatasetRoutesState,
    headers: &HeaderMap,
) -> Result<TenantId, ApiError> {
    let claims = claims_from_auth(headers).await?;
    authorize_read(&claims)?;
    require_datasets(&state.entitlements, &claims.tenant_id).await?;
    Ok(claims.tenant_id)
}

/// Authenticate + authorize a write. Returns `(tenant, actor)` — the actor is
/// the claim `sub`, stamped on every row so provenance is attributable.
async fn actor_from_auth(
    state: &DatasetRoutesState,
    headers: &HeaderMap,
) -> Result<(TenantId, String), ApiError> {
    let claims = claims_from_auth(headers).await?;
    authorize_write(&claims)?;
    require_datasets(&state.entitlements, &claims.tenant_id).await?;
    Ok((claims.tenant_id, claims.sub))
}

// ── Content-capture decision (spec §4) ───────────────────────────────────────

/// Is this workspace recording prompt content?
///
/// **Decided from the allowlist, NEVER inferred from an empty result.** The two
/// are indistinguishable in the data and have different remedies — one is "your
/// filter matched nothing", the other is "no filter you can type will ever
/// match". `server::config::trace_content()` is `None` when the block is absent, which
/// means capture is off for everyone; it is fail-CLOSED by construction and
/// refuses to boot on anything ambiguous.
fn capture_enabled(
    cfg: Option<&crate::server::config::TraceContentConfig>,
    tenant: &TenantId,
) -> bool {
    cfg.is_some_and(|c| c.captures(tenant))
}

/// What a span lookup produced. Four outcomes, four different things to tell the
/// user — see the module docs for why they must not collapse.
///
/// **No `PartialEq`**: `tracelane_shared::Message` deliberately does not implement
/// it, and deriving one here would mean either a bespoke message comparison or a
/// newtype — neither buys anything, because the tests below match on the VARIANT,
/// which is the whole distinction this enum exists to carry.
#[derive(Debug)]
pub(crate) enum SpanVerdict {
    /// No row matched `(tenant, trace, span)`.
    NotFound,
    /// The row exists and carries no recorded input messages.
    NoContent,
    /// The row carries messages that do not deserialize into `Vec<Message>`.
    Unreadable,
    /// `(messages, raw system JSON)`, ready to copy.
    Content(Vec<Message>, String),
}

/// Classify a span read. Pure, so the four outcomes are unit-testable without a
/// ClickHouse.
pub(crate) fn classify_span(row: Option<SpanContentRow>) -> SpanVerdict {
    let Some(row) = row else {
        return SpanVerdict::NotFound;
    };
    // `JSONExtractRaw` returns an EMPTY string for a missing key — not `null`,
    // and not an error. A literal `null` is what a key present-but-null yields.
    // Both mean "this span predates capture", so both land on `NoContent`.
    let raw = row.input_messages.trim();
    if raw.is_empty() || raw == "null" {
        return SpanVerdict::NoContent;
    }
    let Ok(messages) = serde_json::from_str::<Vec<Message>>(raw) else {
        return SpanVerdict::Unreadable;
    };
    if messages.is_empty() {
        return SpanVerdict::NoContent;
    }
    let system = {
        let s = row.system_instructions.trim();
        if s.is_empty() || s == "null" {
            String::new()
        } else {
            s.to_string()
        }
    };
    SpanVerdict::Content(messages, system)
}

/// The dedupe key: sha256 over the canonical serialization of `(messages,
/// system)`.
///
/// Deterministic because `Message`'s field order is fixed by the TYPE, not by a
/// map iteration order. `expected_output` is deliberately NOT in the hash — two
/// items with the same input are the same test case, and adding the second must
/// not overwrite a reference someone already reviewed onto the first.
///
/// # Errors
/// Serialization failure. Fail-CLOSED: without a hash there is no dedupe key,
/// and writing an unkeyed item would let the same case land twice.
pub(crate) fn input_hash(messages: &[Message], system: &str) -> Result<String> {
    let bytes = serde_json::to_vec(&(messages, system))
        .context("serializing (messages, system) for the dedupe hash")?;
    let mut h = Sha256::new();
    h.update(&bytes);
    Ok(hex::encode(h.finalize()))
}

// ── Storage seam ─────────────────────────────────────────────────────────────

/// One row of `datasets`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dataset {
    pub dataset_id: Uuid,
    pub name: String,
    pub description: String,
    pub created_at_ms: i64,
    pub created_by: String,
    pub updated_at_ms: i64,
}

/// One row of `dataset_items`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DatasetItem {
    pub item_id: Uuid,
    /// Display label. `EvalCase.name` is not an `Option`, so the resolver needs
    /// something to put there — but an EMPTY string means UNNAMED and the
    /// surface renders the ordinal. It does not invent a name: a trace-derived
    /// item already carries its provenance in `source_trace_id`, and
    /// manufacturing `trace:<id>` here would put the same fact in two places
    /// where they can disagree.
    pub name: String,
    pub input: String,
    pub system: String,
    pub expected_output: Option<String>,
    pub metadata: String,
    pub source_trace_id: Option<Uuid>,
    pub source_span_id: String,
    pub input_hash: String,
    pub created_at_ms: i64,
    pub created_by: String,
}

/// The §3 counts. Every one is a `count()`/`countIf()` at read time — there is
/// no stored counter anywhere on this surface, because a counter on a MergeTree
/// needs a mutation per write.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ItemStats {
    pub items: u64,
    /// `expected_output IS NOT NULL AND trimBoth(...) != ''`. Whitespace-only
    /// counts as absent — a reference nobody can match is not a reference.
    /// `trimBoth`, not a bare `trim`: ClickHouse's `trim` takes the
    /// `trim([BOTH ...] FROM x)` form and the one-argument spelling is a
    /// different function's signature.
    pub with_reference: u64,
    pub from_traces: u64,
}

/// One row of `dataset_snapshots`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snapshot {
    pub snapshot_id: Uuid,
    pub item_count: u32,
    pub created_at_ms: i64,
    pub created_by: String,
}

/// What one span read returns. Raw JSON text, verbatim — parsing is
/// [`classify_span`]'s job so the four outcomes are decided in one pure place.
#[derive(Debug, Clone, Deserialize, clickhouse::Row)]
pub struct SpanContentRow {
    pub input_messages: String,
    pub system_instructions: String,
}

/// Storage seam. Off the request hot path, so `async_trait` is fine (the ban is
/// on the gateway hot path only). It exists so the refusal policy above can be
/// driven in a unit test without a ClickHouse — a control never observed
/// blocking is not a guard.
///
/// # Errors
/// Every method is fail-CLOSED at the handler: a store error becomes a `502`
/// and nothing is written. These are not fault-tolerance paths — a dataset
/// write that silently no-ops is worse than one that refuses.
#[async_trait::async_trait]
pub trait DatasetStore: Send + Sync {
    async fn create_dataset(&self, tenant: &TenantId, row: &Dataset) -> Result<()>;
    async fn count_datasets(&self, tenant: &TenantId) -> Result<u64>;
    /// `name` is an EXACT filter when present (`EVL-30`); `None` lists the page.
    async fn list_datasets(
        &self,
        tenant: &TenantId,
        cursor: Option<(i64, String)>,
        limit: u32,
        name: Option<&str>,
    ) -> Result<Vec<Dataset>>;
    async fn get_dataset(&self, tenant: &TenantId, dataset_id: Uuid) -> Result<Option<Dataset>>;
    /// Tombstone (`deleted = 1`). Snapshots survive — deleting one would
    /// un-reproduce every run that cited it.
    async fn delete_dataset(&self, tenant: &TenantId, dataset_id: Uuid) -> Result<bool>;

    async fn item_stats(&self, tenant: &TenantId, dataset_id: Uuid) -> Result<ItemStats>;
    async fn list_items(
        &self,
        tenant: &TenantId,
        dataset_id: Uuid,
        cursor: Option<(i64, String)>,
        limit: u32,
    ) -> Result<Vec<DatasetItem>>;
    /// Every live item, in the snapshot's ordinal order. Bounded by
    /// [`limits::ITEMS_PER_DATASET`] by construction.
    async fn all_items(&self, tenant: &TenantId, dataset_id: Uuid) -> Result<Vec<DatasetItem>>;
    async fn find_by_hash(
        &self,
        tenant: &TenantId,
        dataset_id: Uuid,
        hash: &str,
    ) -> Result<Option<Uuid>>;
    async fn insert_items(
        &self,
        tenant: &TenantId,
        dataset_id: Uuid,
        rows: &[DatasetItem],
    ) -> Result<()>;
    /// `expected_output` / `metadata` write-back. `input` is immutable, so the
    /// hash always describes the bytes.
    async fn patch_item(
        &self,
        tenant: &TenantId,
        dataset_id: Uuid,
        item_id: Uuid,
        expected_output: Option<Option<String>>,
        metadata: Option<String>,
    ) -> Result<bool>;
    async fn delete_item(&self, tenant: &TenantId, dataset_id: Uuid, item_id: Uuid)
    -> Result<bool>;

    /// Re-read ONE span's recorded content under the tenant claim.
    async fn span_content(
        &self,
        tenant: &TenantId,
        trace_id: &str,
        span_id: &str,
    ) -> Result<Option<SpanContentRow>>;

    /// EVL-29 — resolve the CONTENT-BEARING span of a trace.
    ///
    /// **A trace-level review carries the OBS-18 `''` span sentinel, and `''` is
    /// not a span id.** `span_content` filters `span_id = ?`, so passing the
    /// sentinel straight through matched nothing and every `trace_error` /
    /// `needs_review` review answered `404 span_not_found` — measured on prod:
    /// 0 of 12,806 spans have an empty `span_id`. The annotation target and the
    /// content source are two different things; this resolves the second.
    ///
    /// Picks the most recent span in the trace that actually carries
    /// `gen_ai_input_messages`, so a trace whose chat span has content resolves
    /// even when it also holds tool or retrieval spans that do not.
    async fn content_span_id(&self, tenant: &TenantId, trace_id: &str) -> Result<Option<String>>;

    /// EVL-29 (R228) — copy this span's content into the snapshot table.
    /// Idempotent: called from the judge at score time AND from the queue list.
    async fn snapshot_content(
        &self,
        tenant: &TenantId,
        trace_id: &str,
        span_id: &str,
        input: &str,
        system: &str,
        input_hash: &str,
    ) -> Result<()>;

    /// EVL-29 (R228) — the snapshot, if one was taken. `None` means never
    /// snapshotted, which is DIFFERENT from "snapshotted and empty".
    async fn read_snapshot(
        &self,
        tenant: &TenantId,
        trace_id: &str,
        span_id: &str,
    ) -> Result<Option<SpanContentRow>>;

    /// EVL-29 (R228) — which of these traces have a snapshot. Bounded by the
    /// caller to one page, the same shape as the Postgres exclusion join.
    async fn snapshotted_trace_ids(
        &self,
        tenant: &TenantId,
        trace_ids: &[String],
    ) -> Result<Vec<String>>;

    async fn count_snapshots(&self, tenant: &TenantId, dataset_id: Uuid) -> Result<u64>;
    async fn snapshot_exists(
        &self,
        tenant: &TenantId,
        dataset_id: Uuid,
        snapshot_id: Uuid,
    ) -> Result<bool>;
    /// Write the frozen copy. Items FIRST, header LAST — see the impl.
    async fn write_snapshot(
        &self,
        tenant: &TenantId,
        dataset_id: Uuid,
        snapshot_id: Uuid,
        actor: &str,
        items: &[DatasetItem],
    ) -> Result<()>;
    async fn list_snapshots(&self, tenant: &TenantId, dataset_id: Uuid) -> Result<Vec<Snapshot>>;
}

// ── ClickHouse implementation ────────────────────────────────────────────────

#[derive(Debug, Serialize, clickhouse::Row)]
struct DatasetWriteRow {
    tenant_id: String,
    #[serde(with = "clickhouse::serde::uuid")]
    dataset_id: Uuid,
    name: String,
    description: String,
    deleted: u8,
    /// `DateTime64(3)` — MILLIS. Always via `datetime64_millis_now`; a
    /// `timestamp_micros()` here lands the row in the year ~48000, silently,
    /// and this repo has shipped that mistake twice already.
    created_at: i64,
    created_by: String,
    updated_at: i64,
}

#[derive(Debug, Deserialize, clickhouse::Row)]
struct DatasetReadRow {
    dataset_id: String,
    name: String,
    description: String,
    created_at: i64,
    created_by: String,
    updated_at: i64,
}

impl DatasetReadRow {
    fn into_dataset(self) -> Option<Dataset> {
        Some(Dataset {
            dataset_id: Uuid::parse_str(&self.dataset_id).ok()?,
            name: self.name,
            description: self.description,
            created_at_ms: self.created_at,
            created_by: self.created_by,
            updated_at_ms: self.updated_at,
        })
    }
}

#[derive(Debug, Serialize, clickhouse::Row)]
struct ItemWriteRow {
    tenant_id: String,
    #[serde(with = "clickhouse::serde::uuid")]
    dataset_id: Uuid,
    #[serde(with = "clickhouse::serde::uuid")]
    item_id: Uuid,
    name: String,
    input: String,
    system: String,
    expected_output: Option<String>,
    metadata: String,
    #[serde(with = "clickhouse::serde::uuid::option")]
    source_trace_id: Option<Uuid>,
    source_span_id: String,
    // FixedString(64) on the wire — see `FixedHex64`. A plain `String` emits a
    // varint length prefix and DESYNCHRONISES the RowBinary stream; the server
    // then reports a byte-count mismatch on a LATER row, which is why this cost
    // an on-node debug in ADR-054 and cost another one here.
    input_hash: crate::prompt_router::FixedHex64,
    deleted: u8,
    created_at: i64,
    created_by: String,
    updated_at: i64,
}

#[derive(Debug, Deserialize, clickhouse::Row)]
struct ItemReadRow {
    item_id: String,
    name: String,
    input: String,
    system: String,
    expected_output: Option<String>,
    metadata: String,
    source_trace_id: String,
    source_span_id: String,
    /// `FixedString(64)` — NOT a `String`. See [`FixedHex64`]'s `Deserialize`:
    /// declaring this a `String` made clickhouse-rs read a length prefix out of
    /// the digest's own bytes and desynchronise the block, which killed EVERY
    /// item read on prod (**B-274**) while the write side was already correct.
    input_hash: crate::prompt_router::FixedHex64,
    created_at: i64,
    created_by: String,
}

impl ItemReadRow {
    fn into_item(self) -> Option<DatasetItem> {
        Some(DatasetItem {
            item_id: Uuid::parse_str(&self.item_id).ok()?,
            name: self.name,
            input: self.input,
            system: self.system,
            expected_output: self.expected_output,
            metadata: self.metadata,
            // A NULL `source_trace_id` renders as an empty string through
            // `toString(…)`; both mean "not from a trace".
            source_trace_id: Uuid::parse_str(self.source_trace_id.trim()).ok(),
            source_span_id: self.source_span_id,
            input_hash: self.input_hash.to_hex_string(),
            created_at_ms: self.created_at,
            created_by: self.created_by,
        })
    }
}

#[derive(Debug, Serialize, clickhouse::Row)]
struct SnapshotHeaderRow {
    tenant_id: String,
    #[serde(with = "clickhouse::serde::uuid")]
    dataset_id: Uuid,
    #[serde(with = "clickhouse::serde::uuid")]
    snapshot_id: Uuid,
    item_count: u32,
    created_at: i64,
    created_by: String,
}

#[derive(Debug, Deserialize, clickhouse::Row)]
struct SnapshotReadRow {
    snapshot_id: String,
    item_count: u32,
    created_at: i64,
    created_by: String,
}

#[derive(Debug, Serialize, clickhouse::Row)]
struct SnapshotItemRow {
    tenant_id: String,
    #[serde(with = "clickhouse::serde::uuid")]
    snapshot_id: Uuid,
    ordinal: u32,
    /// Provenance, kept as a COLUMN rather than as part of the ORDER BY so it
    /// survives the dataset being tombstoned. Omitting it would silently store
    /// the all-zero UUID — a `UUID` column with no DEFAULT takes the type
    /// default, and nothing errors.
    #[serde(with = "clickhouse::serde::uuid")]
    dataset_id: Uuid,
    #[serde(with = "clickhouse::serde::uuid")]
    item_id: Uuid,
    name: String,
    input: String,
    system: String,
    expected_output: Option<String>,
    metadata: String,
    /// `FixedString(64)`, NOT a `String` — B-273's exact shape, which was fixed
    /// on `ItemWriteRow` and MISSED here. A `String` emits a varint length
    /// prefix a FixedString never carries, desynchronising the RowBinary block,
    /// so every snapshot freeze would have failed with a byte-count mismatch
    /// reported against some LATER row (**B-274**).
    input_hash: crate::prompt_router::FixedHex64,
    #[serde(with = "clickhouse::serde::uuid::option")]
    source_trace_id: Option<Uuid>,
    source_span_id: String,
    /// Freeze time — ONE value for the whole snapshot, so every row of one
    /// freeze carries the identical instant.
    created_at: i64,
}

#[derive(Debug, Deserialize, clickhouse::Row)]
struct StatsRow {
    items: u64,
    with_reference: u64,
    from_traces: u64,
}

#[derive(Debug, Deserialize, clickhouse::Row)]
struct CountRow {
    n: u64,
}

#[derive(Debug, Deserialize, clickhouse::Row)]
struct IdRow {
    id: String,
}

/// The ClickHouse-backed store. Every SELECT carries the ADR-031 caps; every
/// statement binds `tenant_id` first.
pub struct ClickHouseDatasetStore {
    ch: clickhouse::Client,
}

impl ClickHouseDatasetStore {
    #[must_use]
    pub fn new(ch: clickhouse::Client) -> Self {
        Self { ch }
    }

    /// Every SELECT on this surface, at the tightest tier. One helper so a new
    /// query cannot forget the caps.
    fn capped(sql: &str) -> String {
        TenantQuery::new(sql, PlanTier::Builder).sql_with_settings()
    }

    /// The item projection, shared by every item read so the column list and
    /// [`ItemReadRow`]'s field order cannot drift apart in one of five copies.
    ///
    /// **`ifNull(toString(source_trace_id), '')` and not a bare `toString`.**
    /// ClickHouse functions PROPAGATE nullability: `toString` over a
    /// `Nullable(UUID)` yields `Nullable(String)`, which does not deserialize
    /// into a plain `String` and would fail at RUNTIME on the first
    /// non-trace-derived (imported) row — a shape no compile check can see.
    /// `''` is the one absent-provenance spelling, read back in
    /// [`ItemReadRow::into_item`].
    const ITEM_COLUMNS: &'static str = "toString(item_id) AS item_id, name, input, system, expected_output, metadata, \
         ifNull(toString(source_trace_id), '') AS source_trace_id, source_span_id, \
         input_hash, created_at, created_by";

    /// One live item by id, or `None`. The read half of the read-modify-write a
    /// `ReplacingMergeTree` tombstone/patch needs.
    async fn read_item(
        &self,
        tenant: &TenantId,
        dataset_id: Uuid,
        item_id: Uuid,
    ) -> Result<Option<DatasetItem>> {
        let sql = Self::capped(&format!(
            "SELECT {cols} FROM dataset_items FINAL \
             WHERE tenant_id = ? AND dataset_items.dataset_id = toUUID(?) AND dataset_items.item_id = toUUID(?) \
               AND deleted = 0 LIMIT 1",
            cols = Self::ITEM_COLUMNS
        ));
        let row = self
            .ch
            .query(&sql)
            .bind(tenant.to_string())
            .bind(dataset_id.to_string())
            .bind(item_id.to_string())
            .fetch_optional::<ItemReadRow>()
            .await
            .context("dataset item SELECT failed")?;
        Ok(row.and_then(ItemReadRow::into_item))
    }

    /// Write one full `dataset_items` row. A `ReplacingMergeTree` version write
    /// is always the WHOLE row — writing a partial one blanks the columns it
    /// omits on the next merge, silently.
    async fn write_item_version(
        &self,
        tenant: &TenantId,
        dataset_id: Uuid,
        item: &DatasetItem,
        deleted: u8,
        updated_at: i64,
    ) -> Result<()> {
        let mut insert = self
            .ch
            .insert("dataset_items")
            .context("clickhouse dataset_items insert init")?;
        insert
            .write(&ItemWriteRow {
                tenant_id: tenant.to_string(),
                dataset_id,
                item_id: item.item_id,
                name: item.name.clone(),
                input: item.input.clone(),
                system: item.system.clone(),
                expected_output: item.expected_output.clone(),
                metadata: item.metadata.clone(),
                source_trace_id: item.source_trace_id,
                source_span_id: item.source_span_id.clone(),
                input_hash: crate::prompt_router::FixedHex64::from_hex_str(&item.input_hash)
                    .context("input_hash must be 64 hex chars")?,
                deleted,
                created_at: item.created_at_ms,
                created_by: item.created_by.clone(),
                updated_at,
            })
            .await
            .context("clickhouse dataset_items insert write")?;
        insert
            .end()
            .await
            .context("clickhouse dataset_items insert end")
    }
}

#[async_trait::async_trait]
impl DatasetStore for ClickHouseDatasetStore {
    async fn create_dataset(&self, tenant: &TenantId, row: &Dataset) -> Result<()> {
        let mut insert = self
            .ch
            .insert("datasets")
            .context("clickhouse datasets insert init")?;
        insert
            .write(&DatasetWriteRow {
                tenant_id: tenant.to_string(),
                dataset_id: row.dataset_id,
                name: row.name.clone(),
                description: row.description.clone(),
                deleted: 0,
                created_at: row.created_at_ms,
                created_by: row.created_by.clone(),
                updated_at: row.updated_at_ms,
            })
            .await
            .context("clickhouse datasets insert write")?;
        insert.end().await.context("clickhouse datasets insert end")
    }

    async fn count_datasets(&self, tenant: &TenantId) -> Result<u64> {
        let sql = Self::capped(
            "SELECT count() AS n FROM datasets FINAL WHERE tenant_id = ? AND deleted = 0",
        );
        let row = self
            .ch
            .query(&sql)
            .bind(tenant.to_string())
            .fetch_one::<CountRow>()
            .await
            .context("dataset count SELECT failed")?;
        Ok(row.n)
    }

    async fn list_datasets(
        &self,
        tenant: &TenantId,
        cursor: Option<(i64, String)>,
        limit: u32,
        name: Option<&str>,
    ) -> Result<Vec<Dataset>> {
        // Built conditionally rather than with a sentinel bind: a `? = 0 OR …`
        // guard reads as clever and hides the branch from anyone auditing the
        // bind order.
        let mut sql = String::from(
            "SELECT toString(dataset_id) AS dataset_id, name, description, \
                    created_at, created_by, updated_at \
             FROM datasets FINAL WHERE tenant_id = ? AND deleted = 0",
        );
        // BOUND, never formatted in. The clause is appended here and the value
        // is bound below in the SAME order — the two must be read together, and
        // that is why the branch is explicit rather than a sentinel.
        if name.is_some() {
            sql.push_str(" AND name = ?");
        }
        if cursor.is_some() {
            sql.push_str(" AND (created_at < ? OR (created_at = ? AND toString(dataset_id) < ?))");
        }
        sql.push_str(" ORDER BY created_at DESC, dataset_id DESC LIMIT ?");

        let mut q = self.ch.query(&sql).bind(tenant.to_string());
        if let Some(n) = name {
            q = q.bind(n);
        }
        if let Some((ts, id)) = &cursor {
            q = q.bind(*ts).bind(*ts).bind(id.clone());
        }
        let rows = q
            .bind(limit)
            .fetch_all::<DatasetReadRow>()
            .await
            .context("dataset list SELECT failed")?;
        Ok(rows
            .into_iter()
            .filter_map(DatasetReadRow::into_dataset)
            .collect())
    }

    async fn get_dataset(&self, tenant: &TenantId, dataset_id: Uuid) -> Result<Option<Dataset>> {
        let sql = Self::capped(
            "SELECT toString(dataset_id) AS dataset_id, name, description, \
                    created_at, created_by, updated_at \
             FROM datasets FINAL \
             WHERE tenant_id = ? AND datasets.dataset_id = toUUID(?) AND deleted = 0",
        );
        let row = self
            .ch
            .query(&sql)
            .bind(tenant.to_string())
            .bind(dataset_id.to_string())
            .fetch_optional::<DatasetReadRow>()
            .await
            .context("dataset get SELECT failed")?;
        Ok(row.and_then(DatasetReadRow::into_dataset))
    }

    async fn delete_dataset(&self, tenant: &TenantId, dataset_id: Uuid) -> Result<bool> {
        // Read-modify-write, because a tombstone on a ReplacingMergeTree is a
        // FULL row with a newer version — writing a partial row would blank the
        // name and description on the next merge.
        let Some(existing) = self.get_dataset(tenant, dataset_id).await? else {
            return Ok(false);
        };
        let mut insert = self
            .ch
            .insert("datasets")
            .context("clickhouse datasets tombstone init")?;
        insert
            .write(&DatasetWriteRow {
                tenant_id: tenant.to_string(),
                dataset_id,
                name: existing.name,
                description: existing.description,
                deleted: 1,
                created_at: existing.created_at_ms,
                created_by: existing.created_by,
                updated_at: datetime64_millis_now(),
            })
            .await
            .context("clickhouse datasets tombstone write")?;
        insert
            .end()
            .await
            .context("clickhouse datasets tombstone end")?;
        Ok(true)
    }

    async fn item_stats(&self, tenant: &TenantId, dataset_id: Uuid) -> Result<ItemStats> {
        let sql = Self::capped(
            "SELECT count() AS items, \
                    countIf(expected_output IS NOT NULL AND trimBoth(expected_output) != '') \
                      AS with_reference, \
                    countIf(source_trace_id IS NOT NULL) AS from_traces \
             FROM dataset_items FINAL \
             WHERE tenant_id = ? AND dataset_items.dataset_id = toUUID(?) AND deleted = 0",
        );
        let row = self
            .ch
            .query(&sql)
            .bind(tenant.to_string())
            .bind(dataset_id.to_string())
            .fetch_one::<StatsRow>()
            .await
            .context("dataset item stats SELECT failed")?;
        Ok(ItemStats {
            items: row.items,
            with_reference: row.with_reference,
            from_traces: row.from_traces,
        })
    }

    async fn list_items(
        &self,
        tenant: &TenantId,
        dataset_id: Uuid,
        cursor: Option<(i64, String)>,
        limit: u32,
    ) -> Result<Vec<DatasetItem>> {
        let mut sql = format!(
            "SELECT {cols} FROM dataset_items FINAL \
             WHERE tenant_id = ? AND dataset_items.dataset_id = toUUID(?) AND deleted = 0",
            cols = Self::ITEM_COLUMNS
        );
        if cursor.is_some() {
            sql.push_str(" AND (created_at > ? OR (created_at = ? AND toString(item_id) > ?))");
        }
        // ASC, matching `all_items` — the list order and the snapshot ordinal
        // order are the SAME order, so what the user froze is what they saw.
        sql.push_str(" ORDER BY created_at ASC, item_id ASC LIMIT ?");

        let mut q = self
            .ch
            .query(&sql)
            .bind(tenant.to_string())
            .bind(dataset_id.to_string());
        if let Some((ts, id)) = &cursor {
            q = q.bind(*ts).bind(*ts).bind(id.clone());
        }
        let rows = q
            .bind(limit)
            .fetch_all::<ItemReadRow>()
            .await
            .context("dataset item list SELECT failed")?;
        Ok(rows
            .into_iter()
            .filter_map(ItemReadRow::into_item)
            .collect())
    }

    async fn all_items(&self, tenant: &TenantId, dataset_id: Uuid) -> Result<Vec<DatasetItem>> {
        let sql = Self::capped(&format!(
            "SELECT {cols} FROM dataset_items FINAL \
             WHERE tenant_id = ? AND dataset_items.dataset_id = toUUID(?) AND deleted = 0 \
             ORDER BY created_at ASC, item_id ASC LIMIT ?",
            cols = Self::ITEM_COLUMNS
        ));
        // ORDER IS DETERMINISTIC, BUT IT IS NOT THE IMPORT FILE'S LINE ORDER.
        // One import stamps every row with the SAME `created_at`, so the
        // tie-break is `item_id` — a random v4. That keeps `snapshot_id`
        // idempotent (the same set always orders the same way, so the same
        // hashes join in the same sequence), which is the property that has to
        // hold; it does NOT mean ordinal 0 was line 1 of the file.
        let rows = self
            .ch
            .query(&sql)
            .bind(tenant.to_string())
            .bind(dataset_id.to_string())
            // The cap is BOUND, not assumed: a dataset that somehow held more
            // than the ceiling must not silently produce a snapshot the eval
            // engine will then refuse at 201.
            .bind(u32::try_from(limits::ITEMS_PER_DATASET).unwrap_or(u32::MAX))
            .fetch_all::<ItemReadRow>()
            .await
            .context("dataset all-items SELECT failed")?;
        Ok(rows
            .into_iter()
            .filter_map(ItemReadRow::into_item)
            .collect())
    }

    async fn find_by_hash(
        &self,
        tenant: &TenantId,
        dataset_id: Uuid,
        hash: &str,
    ) -> Result<Option<Uuid>> {
        let sql = Self::capped(
            "SELECT toString(item_id) AS id FROM dataset_items FINAL \
             WHERE tenant_id = ? AND dataset_items.dataset_id = toUUID(?) AND input_hash = ? AND deleted = 0 \
             LIMIT 1",
        );
        let row = self
            .ch
            .query(&sql)
            .bind(tenant.to_string())
            .bind(dataset_id.to_string())
            .bind(hash.to_string())
            .fetch_optional::<IdRow>()
            .await
            .context("dataset dedupe SELECT failed")?;
        Ok(row.and_then(|r| Uuid::parse_str(&r.id).ok()))
    }

    async fn insert_items(
        &self,
        tenant: &TenantId,
        dataset_id: Uuid,
        rows: &[DatasetItem],
    ) -> Result<()> {
        if rows.is_empty() {
            return Ok(());
        }
        let mut insert = self
            .ch
            .insert("dataset_items")
            .context("clickhouse dataset_items insert init")?;
        for r in rows {
            insert
                .write(&ItemWriteRow {
                    tenant_id: tenant.to_string(),
                    dataset_id,
                    item_id: r.item_id,
                    name: r.name.clone(),
                    input: r.input.clone(),
                    system: r.system.clone(),
                    expected_output: r.expected_output.clone(),
                    metadata: r.metadata.clone(),
                    source_trace_id: r.source_trace_id,
                    source_span_id: r.source_span_id.clone(),
                    input_hash: crate::prompt_router::FixedHex64::from_hex_str(&r.input_hash)
                        .context("input_hash must be 64 hex chars")?,
                    deleted: 0,
                    created_at: r.created_at_ms,
                    created_by: r.created_by.clone(),
                    updated_at: r.created_at_ms,
                })
                .await
                .context("clickhouse dataset_items insert write")?;
        }
        insert
            .end()
            .await
            .context("clickhouse dataset_items insert end")
    }

    async fn patch_item(
        &self,
        tenant: &TenantId,
        dataset_id: Uuid,
        item_id: Uuid,
        expected_output: Option<Option<String>>,
        metadata: Option<String>,
    ) -> Result<bool> {
        let Some(existing) = self.read_item(tenant, dataset_id, item_id).await? else {
            return Ok(false);
        };
        // `input`, `system` and `input_hash` are carried over UNCHANGED. An edit
        // to the input is remove-then-add, so the hash always describes the
        // bytes it names.
        let patched = DatasetItem {
            expected_output: expected_output.unwrap_or(existing.expected_output),
            metadata: metadata.unwrap_or(existing.metadata),
            ..existing
        };
        self.write_item_version(tenant, dataset_id, &patched, 0, datetime64_millis_now())
            .await?;
        Ok(true)
    }

    async fn delete_item(
        &self,
        tenant: &TenantId,
        dataset_id: Uuid,
        item_id: Uuid,
    ) -> Result<bool> {
        let Some(existing) = self.read_item(tenant, dataset_id, item_id).await? else {
            return Ok(false);
        };
        self.write_item_version(tenant, dataset_id, &existing, 1, datetime64_millis_now())
            .await?;
        Ok(true)
    }

    async fn span_content(
        &self,
        tenant: &TenantId,
        trace_id: &str,
        span_id: &str,
    ) -> Result<Option<SpanContentRow>> {
        // `JSONExtractRaw` on the single `attributes` JSON String column — the
        // SAME expression `prompt_eval::cases_from_traces` already uses, so the
        // dataset copy and the eval engine read the identical bytes. `FINAL`
        // because `spans` is a ReplacingMergeTree and a half-merged duplicate
        // must not decide what a permanent test case contains.
        let sql = Self::capped(
            "SELECT JSONExtractRaw(attributes, 'gen_ai_input_messages') AS input_messages, \
                    JSONExtractRaw(attributes, 'gen_ai_system_instructions') \
                      AS system_instructions \
             FROM spans FINAL \
             WHERE tenant_id = ? AND trace_id = ? AND span_id = ? \
             LIMIT 1",
        );
        self.ch
            .query(&sql)
            .bind(tenant.to_string())
            .bind(trace_id.to_string())
            .bind(span_id.to_string())
            .fetch_optional::<SpanContentRow>()
            .await
            .context("span content SELECT failed")
    }

    async fn content_span_id(&self, tenant: &TenantId, trace_id: &str) -> Result<Option<String>> {
        // `FINAL` for the same reason the content read uses it: a half-merged
        // duplicate must not decide which span a permanent test case came from.
        let sql = Self::capped(
            "SELECT span_id FROM spans FINAL \
             WHERE tenant_id = ? AND trace_id = ? \
               AND JSONHas(attributes, 'gen_ai_input_messages') \
             ORDER BY start_time DESC LIMIT 1",
        );
        #[derive(serde::Deserialize, clickhouse::Row)]
        struct R {
            span_id: String,
        }
        Ok(self
            .ch
            .query(&sql)
            .bind(tenant.to_string())
            .bind(trace_id.to_string())
            .fetch_optional::<R>()
            .await
            .context("content span resolve failed")?
            .map(|r| r.span_id))
    }

    async fn snapshot_content(
        &self,
        tenant: &TenantId,
        trace_id: &str,
        span_id: &str,
        input: &str,
        system: &str,
        input_hash: &str,
    ) -> Result<()> {
        #[derive(serde::Serialize, clickhouse::Row)]
        struct SnapRow<'a> {
            tenant_id: &'a str,
            trace_id: &'a str,
            span_id: &'a str,
            input: &'a str,
            system: &'a str,
            // `FixedString(64)`, NOT `String` — and a comment warning about this
            // exact trap sat here while the code did it wrong anyway. Declaring
            // it as a str makes clickhouse-rs emit the varint length prefix a
            // FixedString never carries, desynchronising the RowBinary block:
            // prod answered `Code: 32 ATTEMPT_TO_READ_AFTER_EOF: While executing
            // BinaryRowInputFormat` on every write, and the list path folds that
            // into a warn (fail-OPEN by design), so the queue looked healthy
            // while nothing was ever snapshotted. Fifth instance of the class;
            // `FixedHex64` is the type that exists so it stops recurring.
            input_hash: crate::prompt_router::FixedHex64,
            captured_at: i64,
        }
        let tenant_s = tenant.to_string();
        // Refuse rather than truncate: a hash that is not 64 hex chars cannot be
        // stored in a FixedString(64), and silently padding one would put a
        // WRONG dedupe key on a permanent test case.
        let hash_fixed = crate::prompt_router::FixedHex64::from_hex_str(input_hash)
            .ok_or_else(|| anyhow::anyhow!("input_hash is not 64 hex chars: {input_hash:?}"))?;
        let mut insert = self.ch.insert("trace_content_snapshots")?;
        insert
            .write(&SnapRow {
                tenant_id: &tenant_s,
                trace_id,
                span_id,
                input,
                system,
                input_hash: hash_fixed,
                captured_at: crate::clickhouse_query::datetime64_millis_now(),
            })
            .await?;
        insert.end().await.context("snapshot insert failed")
    }

    async fn read_snapshot(
        &self,
        tenant: &TenantId,
        trace_id: &str,
        span_id: &str,
    ) -> Result<Option<SpanContentRow>> {
        let sql = Self::capped(
            "SELECT input AS input_messages, system AS system_instructions \
             FROM trace_content_snapshots FINAL \
             WHERE tenant_id = ? AND trace_id = ? AND span_id = ? LIMIT 1",
        );
        self.ch
            .query(&sql)
            .bind(tenant.to_string())
            .bind(trace_id.to_string())
            .bind(span_id.to_string())
            .fetch_optional::<SpanContentRow>()
            .await
            .context("snapshot read failed")
    }

    async fn snapshotted_trace_ids(
        &self,
        tenant: &TenantId,
        trace_ids: &[String],
    ) -> Result<Vec<String>> {
        if trace_ids.is_empty() {
            return Ok(Vec::new());
        }
        let sql = Self::capped(
            "SELECT DISTINCT trace_id FROM trace_content_snapshots FINAL \
             WHERE tenant_id = ? AND trace_id IN ?",
        );
        #[derive(serde::Deserialize, clickhouse::Row)]
        struct R {
            trace_id: String,
        }
        let rows = self
            .ch
            .query(&sql)
            .bind(tenant.to_string())
            .bind(trace_ids)
            .fetch_all::<R>()
            .await
            .context("snapshot membership read failed")?;
        Ok(rows.into_iter().map(|r| r.trace_id).collect())
    }

    async fn count_snapshots(&self, tenant: &TenantId, dataset_id: Uuid) -> Result<u64> {
        // Plain MergeTree — no `FINAL`, because a snapshot row is terminal on
        // write and there is nothing to replace.
        //
        // `uniqExact(snapshot_id)`, NOT `count()`. Idempotent re-freeze is a
        // WRITER property (check-then-write), not an engine one: two concurrent
        // freezes of an unchanged dataset can both pass the existence check and
        // write two byte-identical rows. `count()` would then charge the tenant
        // twice against the 100-snapshot cap for one snapshot. Migration 18 says
        // this in its own DDL, and notes that the spec's §3 `count()` is the
        // spec being loose — the query is the thing that has to be right.
        let sql = Self::capped(
            "SELECT uniqExact(snapshot_id) AS n FROM dataset_snapshots \
             WHERE tenant_id = ? AND dataset_snapshots.dataset_id = toUUID(?)",
        );
        let row = self
            .ch
            .query(&sql)
            .bind(tenant.to_string())
            .bind(dataset_id.to_string())
            .fetch_one::<CountRow>()
            .await
            .context("snapshot count SELECT failed")?;
        Ok(row.n)
    }

    async fn snapshot_exists(
        &self,
        tenant: &TenantId,
        dataset_id: Uuid,
        snapshot_id: Uuid,
    ) -> Result<bool> {
        let sql = Self::capped(
            "SELECT count() AS n FROM dataset_snapshots \
             WHERE tenant_id = ? AND dataset_snapshots.dataset_id = toUUID(?) AND dataset_snapshots.snapshot_id = toUUID(?)",
        );
        let row = self
            .ch
            .query(&sql)
            .bind(tenant.to_string())
            .bind(dataset_id.to_string())
            .bind(snapshot_id.to_string())
            .fetch_one::<CountRow>()
            .await
            .context("snapshot exists SELECT failed")?;
        Ok(row.n > 0)
    }

    async fn write_snapshot(
        &self,
        tenant: &TenantId,
        dataset_id: Uuid,
        snapshot_id: Uuid,
        actor: &str,
        items: &[DatasetItem],
    ) -> Result<()> {
        // ITEMS FIRST, HEADER LAST — act, confirm, record. A crash between the
        // two leaves orphan item rows (invisible to every reader, and re-freezing
        // the same content re-derives the same id so they are simply re-used)
        // rather than a header claiming a count of items that were never
        // written. The reverse order turns one failure into a permanently wrong
        // snapshot — the `.claude/rules/logging.md` "never record done before
        // the thing is done" rule, applied to a durable artifact other runs cite.
        // ONE freeze instant for every row of this snapshot, header included.
        // Calling `now()` per row would stamp a range across a slow write and
        // make "when was this frozen" a question with several answers.
        let frozen_at = datetime64_millis_now();
        let mut insert = self
            .ch
            .insert("dataset_snapshot_items")
            .context("clickhouse dataset_snapshot_items insert init")?;
        for (i, it) in items.iter().enumerate() {
            insert
                .write(&SnapshotItemRow {
                    tenant_id: tenant.to_string(),
                    snapshot_id,
                    ordinal: u32::try_from(i).unwrap_or(u32::MAX),
                    dataset_id,
                    item_id: it.item_id,
                    name: it.name.clone(),
                    input: it.input.clone(),
                    system: it.system.clone(),
                    expected_output: it.expected_output.clone(),
                    metadata: it.metadata.clone(),
                    input_hash: crate::prompt_router::FixedHex64::from_hex_str(&it.input_hash)
                        .context("input_hash must be 64 hex chars")?,
                    source_trace_id: it.source_trace_id,
                    source_span_id: it.source_span_id.clone(),
                    created_at: frozen_at,
                })
                .await
                .context("clickhouse dataset_snapshot_items insert write")?;
        }
        insert
            .end()
            .await
            .context("clickhouse dataset_snapshot_items insert end")?;

        let mut header = self
            .ch
            .insert("dataset_snapshots")
            .context("clickhouse dataset_snapshots insert init")?;
        header
            .write(&SnapshotHeaderRow {
                tenant_id: tenant.to_string(),
                dataset_id,
                snapshot_id,
                item_count: u32::try_from(items.len()).unwrap_or(u32::MAX),
                created_at: frozen_at,
                created_by: actor.to_string(),
            })
            .await
            .context("clickhouse dataset_snapshots insert write")?;
        header
            .end()
            .await
            .context("clickhouse dataset_snapshots insert end")
    }

    async fn list_snapshots(&self, tenant: &TenantId, dataset_id: Uuid) -> Result<Vec<Snapshot>> {
        // GROUPed for the same reason `count_snapshots` uses `uniqExact`: two
        // concurrent freezes of one content set can write two identical rows,
        // and rendering the same snapshot twice would read as two frozen sets.
        // `min(created_at)` is the freeze that actually happened first.
        let sql = Self::capped(
            "SELECT toString(snapshot_id) AS snapshot_id, any(item_count) AS item_count, \
                    min(created_at) AS created_at, any(created_by) AS created_by \
             FROM dataset_snapshots \
             WHERE tenant_id = ? AND dataset_snapshots.dataset_id = toUUID(?) \
             GROUP BY snapshot_id \
             ORDER BY created_at DESC LIMIT ?",
        );
        let rows = self
            .ch
            .query(&sql)
            .bind(tenant.to_string())
            .bind(dataset_id.to_string())
            .bind(limits::SNAPSHOTS_PER_DATASET)
            .fetch_all::<SnapshotReadRow>()
            .await
            .context("snapshot list SELECT failed")?;
        Ok(rows
            .into_iter()
            .filter_map(|r| {
                Some(Snapshot {
                    snapshot_id: Uuid::parse_str(&r.snapshot_id).ok()?,
                    item_count: r.item_count,
                    created_at_ms: r.created_at,
                    created_by: r.created_by,
                })
            })
            .collect())
    }
}

// ── Router ───────────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct DatasetRoutesState {
    pub store: Arc<dyn DatasetStore>,
    /// `None` only when Postgres is unset. The gate then REFUSES — `None` is the
    /// unprivileged state (`.claude/rules/tenancy.md`), never a grant.
    pub entitlements: Option<Arc<EntitlementCache>>,
}

/// Mount the dataset routes. The caller mounts this only when `CLICKHOUSE_URL`
/// is set, matching `trace_reads::routes`.
pub fn routes() -> Router<DatasetRoutesState> {
    Router::new()
        .route("/v1/datasets", get(list_datasets).post(create_dataset))
        .route("/v1/datasets/{id}", get(get_dataset).delete(delete_dataset))
        .route("/v1/datasets/{id}/items", get(list_items).post(add_item))
        .route(
            "/v1/datasets/{id}/items/{item_id}",
            axum::routing::patch(patch_item).delete(delete_item),
        )
        .route(
            "/v1/datasets/{id}/snapshots",
            post(create_snapshot).get(list_snapshots),
        )
        .route("/v1/datasets/{id}/export", get(export_dataset))
        .route(
            "/v1/datasets/{id}/import",
            // The one route that accepts a large body. axum's default cap is
            // 2 MiB, which would refuse a legal 5 MiB import with a bare 413 and
            // no code — so the limit is raised HERE, on this route only, rather
            // than globally where it would also widen every other surface.
            post(import_dataset).layer(DefaultBodyLimit::max(limits::IMPORT_BYTES)),
        )
}

// ── DTOs ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
struct DatasetDto {
    dataset_id: Uuid,
    name: String,
    description: String,
    created_at_ms: i64,
    created_by: String,
    /// `None` = the count query FAILED and the UI must render `—`, never `0`.
    /// Zero-vs-unknown, and on an evidence product it is the expensive one.
    items: Option<u64>,
    with_reference: Option<u64>,
    from_traces: Option<u64>,
}

/// Reason code for a NULL reference on a trace-derived item.
const OUTPUT_NOT_CAPTURED: &str = "output_not_captured";

#[derive(Debug, Serialize)]
struct ItemDto {
    item_id: Uuid,
    /// Empty = unnamed. Rendered as the ordinal, never as a fabricated label.
    name: String,
    input: serde_json::Value,
    system: serde_json::Value,
    expected_output: Option<String>,
    /// Present ONLY when `expected_output` is absent AND the item came from a
    /// trace, and it says WHY. Never an empty string standing in for a
    /// reference.
    #[serde(skip_serializing_if = "Option::is_none")]
    expected_output_reason: Option<&'static str>,
    metadata: serde_json::Value,
    source_trace_id: Option<Uuid>,
    source_span_id: String,
    input_hash: String,
    created_at_ms: i64,
    created_by: String,
}

impl From<DatasetItem> for ItemDto {
    fn from(i: DatasetItem) -> Self {
        // An IMPORTED item with no reference is a DIFFERENT fact — the file
        // simply did not carry one — so it must not blame content capture.
        let reason = if i.expected_output.is_none() && i.source_trace_id.is_some() {
            Some(OUTPUT_NOT_CAPTURED)
        } else {
            None
        };
        // Stored as JSON TEXT so ClickHouse holds the exact bytes; re-parsed on
        // the way out so the client gets structure rather than a string it has
        // to parse a second time. A row whose stored JSON does not parse renders
        // as `null`, never as the raw text — the text could be anything, and a
        // client that string-matched it would be reading a format we never
        // promised.
        ItemDto {
            item_id: i.item_id,
            name: i.name,
            input: serde_json::from_str(&i.input).unwrap_or(serde_json::Value::Null),
            system: if i.system.trim().is_empty() {
                serde_json::Value::Null
            } else {
                serde_json::from_str(&i.system).unwrap_or(serde_json::Value::Null)
            },
            expected_output: i.expected_output,
            expected_output_reason: reason,
            metadata: serde_json::from_str(&i.metadata).unwrap_or_else(|_| serde_json::json!({})),
            source_trace_id: i.source_trace_id,
            source_span_id: i.source_span_id,
            input_hash: i.input_hash,
            created_at_ms: i.created_at_ms,
            created_by: i.created_by,
        }
    }
}

#[derive(Debug, Deserialize)]
struct PageQuery {
    #[serde(default)]
    limit: Option<u32>,
    /// Opaque keyset token from a previous `next_cursor`. Same `"{millis}:{id}"`
    /// shape the trace list already uses.
    #[serde(default)]
    cursor: Option<String>,
    /// `EVL-30` — EXACT dataset name, for resolving a name to an id.
    ///
    /// **Why this exists rather than "just page and filter client-side".** The
    /// listing is keyset-paginated at [`limits::PAGE_MAX`] = 200. A CI gate that
    /// resolves `--dataset my-golden-set` by reading one page finds it only if
    /// the dataset happens to be in the newest 200 — and on a workspace where it
    /// is not, the gate reports "no dataset named …" for a dataset that plainly
    /// exists. That is a silent wrong answer produced by a paging boundary, so
    /// the filter belongs in the query rather than in every client.
    ///
    /// **Exact only, no prefix and no wildcard.** The gate needs one name to
    /// mean one dataset; anything looser reintroduces the ambiguity the CLI
    /// already refuses to guess through.
    #[serde(default)]
    name: Option<String>,
}

fn page_limit(q: &PageQuery) -> u32 {
    q.limit
        .unwrap_or(limits::PAGE_DEFAULT)
        .clamp(1, limits::PAGE_MAX)
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

/// Parse a path id.
///
/// A malformed id gets the SAME 404 as an unknown one: it names no dataset in
/// this workspace, and giving it its own code would be one more bit of an
/// existence oracle for no benefit the caller can act on.
fn parse_id(s: &str) -> Result<Uuid, ApiError> {
    Uuid::parse_str(s).map_err(|_| not_found())
}

// ── Handlers: datasets ───────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateDatasetBody {
    name: String,
    #[serde(default)]
    description: Option<String>,
}

/// `POST /v1/datasets`.
#[tracing::instrument(skip_all, fields(tenant_id = tracing::field::Empty))]
async fn create_dataset(
    State(state): State<DatasetRoutesState>,
    headers: HeaderMap,
    Json(body): Json<CreateDatasetBody>,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    let (tenant, actor) = actor_from_auth(&state, &headers).await?;
    tracing::Span::current().record("tenant_id", tenant.to_string());

    let name = body.name.trim().to_string();
    if name.is_empty() || name.len() > limits::NAME_BYTES {
        return Err(coded_err(
            StatusCode::BAD_REQUEST,
            "invalid_name",
            "A dataset needs a name.",
            serde_json::json!({ "max_bytes": limits::NAME_BYTES, "got_bytes": name.len() }),
        ));
    }
    let description = body.description.unwrap_or_default();
    if description.len() > limits::DESCRIPTION_BYTES {
        return Err(coded_err(
            StatusCode::BAD_REQUEST,
            "description_too_large",
            "The description is longer than the limit.",
            serde_json::json!({
                "max_bytes": limits::DESCRIPTION_BYTES,
                "got_bytes": description.len(),
            }),
        ));
    }

    let existing = state
        .store
        .count_datasets(&tenant)
        .await
        .map_err(|e| store_failed("dataset count", &e))?;
    if existing >= limits::DATASETS_PER_TENANT {
        return Err(coded_err(
            StatusCode::CONFLICT,
            "dataset_limit",
            "This workspace is at its dataset limit. Delete one to make room.",
            serde_json::json!({ "limit": limits::DATASETS_PER_TENANT, "current": existing }),
        ));
    }

    let now = datetime64_millis_now();
    let row = Dataset {
        dataset_id: Uuid::new_v4(),
        name,
        description,
        created_at_ms: now,
        created_by: actor,
        updated_at_ms: now,
    };
    state
        .store
        .create_dataset(&tenant, &row)
        .await
        .map_err(|e| store_failed("dataset create", &e))?;
    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({ "dataset_id": row.dataset_id })),
    ))
}

/// `GET /v1/datasets` — cursor-paginated, NEVER an unbounded list.
#[tracing::instrument(skip_all, fields(tenant_id = tracing::field::Empty))]
async fn list_datasets(
    State(state): State<DatasetRoutesState>,
    Query(q): Query<PageQuery>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, ApiError> {
    let tenant = tenant_from_auth(&state, &headers).await?;
    tracing::Span::current().record("tenant_id", tenant.to_string());

    let limit = page_limit(&q);
    let cursor = q.cursor.as_deref().and_then(decode_cursor);
    // A name longer than a name can be matches nothing, so refuse instead of
    // spending a ClickHouse round trip to return an empty list that reads as
    // "no such dataset" rather than "you sent something that is not a name".
    if let Some(n) = q.name.as_deref()
        && n.len() > limits::NAME_BYTES
    {
        return Err(coded_err(
            StatusCode::BAD_REQUEST,
            "name_too_long",
            "That name is longer than a dataset name can be, so it matches nothing. \
             This is refused rather than answered with an empty list, which would read \
             as 'no such dataset'.",
            serde_json::json!({ "max_bytes": limits::NAME_BYTES, "got_bytes": n.len() }),
        ));
    }
    let rows = state
        .store
        .list_datasets(&tenant, cursor, limit, q.name.as_deref())
        .await
        .map_err(|e| store_failed("dataset list", &e))?;

    // A page that ends without saying how many were left is the truncated-result
    // shape. The total is a SEPARATE count() — a page length can never tell you
    // it.
    let total = state.store.count_datasets(&tenant).await.ok();
    let next_cursor = if u32::try_from(rows.len()).unwrap_or(u32::MAX) == limit {
        rows.last()
            .map(|r| encode_cursor(r.created_at_ms, &r.dataset_id.to_string()))
    } else {
        None
    };

    let mut out = Vec::with_capacity(rows.len());
    for r in rows {
        // Per-dataset counts are best-effort: a failed count renders `—`, never
        // `0`. A `0` here would read as "this dataset is empty", which is a
        // different and wrong fact.
        let stats = state.store.item_stats(&tenant, r.dataset_id).await.ok();
        out.push(DatasetDto {
            dataset_id: r.dataset_id,
            name: r.name,
            description: r.description,
            created_at_ms: r.created_at_ms,
            created_by: r.created_by,
            items: stats.map(|s| s.items),
            with_reference: stats.map(|s| s.with_reference),
            from_traces: stats.map(|s| s.from_traces),
        });
    }

    Ok(Json(serde_json::json!({
        "datasets": out,
        "next_cursor": next_cursor,
        "total": total,
    })))
}

/// `GET /v1/datasets/{id}`.
#[tracing::instrument(skip_all, fields(tenant_id = tracing::field::Empty))]
async fn get_dataset(
    State(state): State<DatasetRoutesState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<DatasetDto>, ApiError> {
    let tenant = tenant_from_auth(&state, &headers).await?;
    tracing::Span::current().record("tenant_id", tenant.to_string());
    let dataset_id = parse_id(&id)?;

    let row = state
        .store
        .get_dataset(&tenant, dataset_id)
        .await
        .map_err(|e| store_failed("dataset get", &e))?
        .ok_or_else(not_found)?;
    let stats = state.store.item_stats(&tenant, dataset_id).await.ok();
    Ok(Json(DatasetDto {
        dataset_id: row.dataset_id,
        name: row.name,
        description: row.description,
        created_at_ms: row.created_at_ms,
        created_by: row.created_by,
        items: stats.map(|s| s.items),
        with_reference: stats.map(|s| s.with_reference),
        from_traces: stats.map(|s| s.from_traces),
    }))
}

/// `DELETE /v1/datasets/{id}` — tombstone.
#[tracing::instrument(skip_all, fields(tenant_id = tracing::field::Empty))]
async fn delete_dataset(
    State(state): State<DatasetRoutesState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    let (tenant, _actor) = actor_from_auth(&state, &headers).await?;
    tracing::Span::current().record("tenant_id", tenant.to_string());
    let dataset_id = parse_id(&id)?;

    // Snapshots deliberately SURVIVE the tombstone. Deleting them would
    // un-reproduce every eval run that cited one, which is the property the
    // whole storage design exists to hold.
    let removed = state
        .store
        .delete_dataset(&tenant, dataset_id)
        .await
        .map_err(|e| store_failed("dataset delete", &e))?;
    if removed {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(not_found())
    }
}

// ── Handlers: items ──────────────────────────────────────────────────────────

/// `GET /v1/datasets/{id}/items` — cursor-paginated.
#[tracing::instrument(skip_all, fields(tenant_id = tracing::field::Empty))]
async fn list_items(
    State(state): State<DatasetRoutesState>,
    Path(id): Path<String>,
    Query(q): Query<PageQuery>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, ApiError> {
    let tenant = tenant_from_auth(&state, &headers).await?;
    tracing::Span::current().record("tenant_id", tenant.to_string());
    let dataset_id = parse_id(&id)?;

    // The dataset must be THIS tenant's before anything else is read. The items
    // query is tenant-scoped too, but a foreign id must 404 rather than return
    // an empty list that reads as "this dataset is empty".
    if state
        .store
        .get_dataset(&tenant, dataset_id)
        .await
        .map_err(|e| store_failed("dataset get", &e))?
        .is_none()
    {
        return Err(not_found());
    }

    let limit = page_limit(&q);
    let cursor = q.cursor.as_deref().and_then(decode_cursor);
    let rows = state
        .store
        .list_items(&tenant, dataset_id, cursor, limit)
        .await
        .map_err(|e| store_failed("item list", &e))?;
    let next_cursor = if u32::try_from(rows.len()).unwrap_or(u32::MAX) == limit {
        rows.last()
            .map(|r| encode_cursor(r.created_at_ms, &r.item_id.to_string()))
    } else {
        None
    };
    let stats = state.store.item_stats(&tenant, dataset_id).await.ok();

    Ok(Json(serde_json::json!({
        "items": rows.into_iter().map(ItemDto::from).collect::<Vec<_>>(),
        "next_cursor": next_cursor,
        "total": stats.map(|s| s.items),
        "with_reference": stats.map(|s| s.with_reference),
    })))
}

/// `{trace_id, span_id}` and **nothing else**.
///
/// `deny_unknown_fields` is the structural half of "a client payload is never
/// trusted": a caller that tries to hand us an `input` or an `expected_output`
/// gets a refusal naming the field, instead of having it silently ignored and
/// believing it landed.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AddItemBody {
    trace_id: String,
    #[serde(default)]
    span_id: Option<String>,
}

/// `POST /v1/datasets/{id}/items` — **the one-click conversion**.
#[tracing::instrument(skip_all, fields(tenant_id = tracing::field::Empty))]
async fn add_item(
    State(state): State<DatasetRoutesState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<AddItemBody>,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    // The conversion is a WRITE that also READS recorded span content, so it
    // needs BOTH capabilities. `KeyScope::allows` has no implication hierarchy
    // on purpose — a key that needs two capabilities lists two — so `admin`
    // alone must not be able to copy prompt text it is not scoped to read.
    let claims = claims_from_auth(&headers).await?;
    authorize_write(&claims)?;
    authorize_read(&claims)?;
    require_datasets(&state.entitlements, &claims.tenant_id).await?;
    let (tenant, actor) = (claims.tenant_id, claims.sub);
    tracing::Span::current().record("tenant_id", tenant.to_string());
    let dataset_id = parse_id(&id)?;

    // 1. The dataset must be this tenant's.
    if state
        .store
        .get_dataset(&tenant, dataset_id)
        .await
        .map_err(|e| store_failed("dataset get", &e))?
        .is_none()
    {
        return Err(not_found());
    }

    // 2. Does this workspace record prompt content AT ALL? Decided from the
    //    ALLOWLIST, BEFORE any span is read — an empty result cannot tell this
    //    apart from "nothing matched", and the remedies differ. Reading only
    //    process-global config also means this refusal leaks nothing about which
    //    traces exist.
    if !capture_enabled(crate::server::config::trace_content(), &tenant) {
        return Err(coded_err(
            StatusCode::UNPROCESSABLE_ENTITY,
            "content_capture_disabled",
            "This workspace does not record prompt content, so a trace cannot become a \
             test case. Traces keep model, tokens, cost and latency — not the messages.",
            serde_json::json!({ "setting": "trace_content" }),
        ));
    }

    // 3. The cap, before the span read — cheaper, and "this dataset is full" is
    //    the more actionable fact when both are true.
    let stats = state
        .store
        .item_stats(&tenant, dataset_id)
        .await
        .map_err(|e| store_failed("item stats", &e))?;
    if stats.items >= limits::ITEMS_PER_DATASET as u64 {
        return Err(coded_err(
            StatusCode::CONFLICT,
            "dataset_full",
            "This dataset is full. Remove an item, or start a second dataset.",
            serde_json::json!({ "limit": limits::ITEMS_PER_DATASET, "current": stats.items }),
        ));
    }

    // 4. An item is per-(trace, span), never per-trace. On gateway-proxied
    //    traffic the tree has one node so the two coincide; on SDK-instrumented
    //    traffic they do not, and silently picking "the first span" would copy
    //    the wrong prompt into a permanent test case.
    let Some(span_id) = body
        .span_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    else {
        return Err(coded_err(
            StatusCode::BAD_REQUEST,
            "span_id_required",
            "A dataset item is built from ONE span. Send the span_id of the span you \
             selected — a trace can hold many, and guessing which one would copy the \
             wrong prompt into a permanent test case.",
            serde_json::json!({}),
        ));
    };
    if span_id.len() > limits::SPAN_ID_BYTES {
        return Err(coded_err(
            StatusCode::BAD_REQUEST,
            "invalid_span_id",
            "span_id is longer than any span id we record.",
            serde_json::json!({ "max_bytes": limits::SPAN_ID_BYTES }),
        ));
    }
    // Trace ids are stored as the hyphenated UUID string (ingest writes
    // `Uuid::to_string()`), and a W3C 32-hex trace id parses as a UUID too, so
    // parsing then re-rendering normalises both client spellings onto the one
    // form the column actually holds. An unparseable id names no trace of this
    // tenant, so it takes the same 404 — one body, no oracle.
    let trace_uuid = Uuid::parse_str(body.trace_id.trim()).map_err(|_| {
        tracing::debug!("dataset add: unparseable trace id");
        not_found()
    })?;

    // 5. THE COPY. The span is re-read SERVER-SIDE under the validated tenant
    //    claim and its content is COPIED into the item. It is never referenced,
    //    and the client's payload is never trusted, for two independent reasons:
    //
    //    (a) `spans` is a ReplacingMergeTree. A referenced payload can CHANGE
    //        under a dataset — a later write for the same (tenant, trace, span)
    //        replaces the row the item meant — so a referencing item breaks
    //        reproducibility long before any expiry does, and nothing errors
    //        when it happens.
    //    (b) copying is what makes the 30-day content-column TTL LANDABLE. With
    //        references, the day that TTL ships is the day every dataset built
    //        from production silently empties; with copies it is a retention
    //        change and nothing else.
    let verdict = classify_span(
        state
            .store
            .span_content(&tenant, &trace_uuid.to_string(), span_id)
            .await
            .map_err(|e| store_failed("span content", &e))?,
    );
    let (messages, system) = match verdict {
        // Same body as an unknown dataset: naming which id was missing would
        // confirm the other exists.
        SpanVerdict::NotFound => return Err(not_found()),
        // A DIFFERENT fact from `content_capture_disabled`, with a different
        // remedy — capture is on for this workspace, this span simply predates
        // it. Collapsing the two is the failure this whole surface guards.
        SpanVerdict::NoContent => {
            return Err(coded_err(
                StatusCode::UNPROCESSABLE_ENTITY,
                "span_has_no_content",
                "Content capture is on for this workspace, but this span was recorded \
                 before it was enabled. Newer traces can be converted.",
                serde_json::json!({}),
            ));
        }
        // Neither of the above: the content IS there and something else is
        // wrong. Reporting it as "no content" would send someone to check a
        // setting that is already correct.
        SpanVerdict::Unreadable => {
            tracing::warn!("dataset add: recorded span messages do not deserialize");
            return Err(coded_err(
                StatusCode::UNPROCESSABLE_ENTITY,
                "span_content_unreadable",
                "This span recorded message content in a shape this gateway cannot read, \
                 so it cannot be copied faithfully into a test case.",
                serde_json::json!({}),
            ));
        }
        SpanVerdict::Content(m, s) => (m, s),
    };

    // Re-serialized through `Vec<Message>` rather than stored as the raw span
    // bytes: the item's `input` is then EXACTLY the shape `prompt_eval` will
    // deserialize, so producer and consumer agree by construction.
    let input = serde_json::to_string(&messages).map_err(|e| {
        tracing::error!(error = %e, "dataset add: re-serializing copied messages failed");
        api_err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "could not serialize the copied span content".to_string(),
        )
    })?;
    let size = input.len() + system.len();
    if size > limits::ITEM_INPUT_BYTES {
        return Err(coded_err(
            StatusCode::PAYLOAD_TOO_LARGE,
            "item_too_large",
            "This span's recorded content is larger than one dataset item may hold. It is \
             refused rather than truncated — a truncated prompt is a test case that \
             quietly tests something else.",
            serde_json::json!({ "max_bytes": limits::ITEM_INPUT_BYTES, "got_bytes": size }),
        ));
    }

    let hash = input_hash(&messages, &system).map_err(|e| {
        tracing::error!(error = %format!("{e:#}"), "dataset add: hashing failed");
        api_err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "could not compute the dedupe hash".to_string(),
        )
    })?;
    // A duplicate is NOT an error, and the existing item is NOT overwritten —
    // `expected_output` is deliberately outside the hash, so overwriting would
    // discard a reference someone reviewed.
    if let Some(existing) = state
        .store
        .find_by_hash(&tenant, dataset_id, &hash)
        .await
        .map_err(|e| store_failed("dedupe lookup", &e))?
    {
        return Ok((
            StatusCode::OK,
            Json(serde_json::json!({
                "item_id": existing,
                "deduped": true,
                "expected_output": serde_json::Value::Null,
                "expected_output_reason": OUTPUT_NOT_CAPTURED,
            })),
        ));
    }

    let now = datetime64_millis_now();
    let item = DatasetItem {
        item_id: Uuid::new_v4(),
        // UNNAMED. The provenance lives in `source_trace_id`; manufacturing a
        // `trace:<id>` label here would put the same fact in two columns that
        // can then disagree, and the surface renders the ordinal for an unnamed
        // item.
        name: String::new(),
        input,
        system,
        // ALWAYS NULL on a trace-derived item, and that is expected rather than
        // an error: production captures INPUT ONLY, because the span is
        // published before the response-side guardrail seam so a BLOCKED request
        // still produces a span. An empty string here would be a test case that
        // passes nothing and fails nothing.
        expected_output: None,
        metadata: "{}".to_string(),
        source_trace_id: Some(trace_uuid),
        source_span_id: span_id.to_string(),
        input_hash: hash,
        created_at_ms: now,
        created_by: actor,
    };
    let item_id = item.item_id;
    state
        .store
        .insert_items(&tenant, dataset_id, std::slice::from_ref(&item))
        .await
        .map_err(|e| store_failed("item insert", &e))?;

    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({
            "item_id": item_id,
            "deduped": false,
            "expected_output": serde_json::Value::Null,
            "expected_output_reason": OUTPUT_NOT_CAPTURED,
        })),
    ))
}

/// `expected_output` and `metadata` ONLY.
///
/// `input` is immutable by design — an edit is remove-then-add, so `input_hash`
/// always describes the bytes. `deny_unknown_fields` makes an attempt to PATCH
/// `input` a refusal rather than a silent no-op that leaves the caller believing
/// the case changed.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PatchItemBody {
    /// `Some(None)` clears the reference; absent leaves it alone. Distinguished
    /// deliberately: "set it to nothing" and "do not touch it" are different
    /// intents and a plain `Option` cannot express both.
    #[serde(default, deserialize_with = "double_option")]
    expected_output: Option<Option<String>>,
    #[serde(default)]
    metadata: Option<serde_json::Value>,
}

/// # Errors
/// Propagates the deserializer's error for a non-string, non-null value.
fn double_option<'de, D>(d: D) -> Result<Option<Option<String>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Option::<String>::deserialize(d).map(Some)
}

/// `PATCH /v1/datasets/{id}/items/{item_id}` — the annotation loop's landing
/// zone (spec §2.5). Without it, reference-based scoring on a trace-derived item
/// would be permanently impossible.
#[tracing::instrument(skip_all, fields(tenant_id = tracing::field::Empty))]
async fn patch_item(
    State(state): State<DatasetRoutesState>,
    Path((id, item_id)): Path<(String, String)>,
    headers: HeaderMap,
    Json(body): Json<PatchItemBody>,
) -> Result<StatusCode, ApiError> {
    let (tenant, _actor) = actor_from_auth(&state, &headers).await?;
    tracing::Span::current().record("tenant_id", tenant.to_string());
    let dataset_id = parse_id(&id)?;
    let item_id = parse_id(&item_id)?;

    if let Some(Some(v)) = &body.expected_output
        && v.len() > limits::EXPECTED_OUTPUT_BYTES
    {
        return Err(coded_err(
            StatusCode::PAYLOAD_TOO_LARGE,
            "expected_output_too_large",
            "The reference is larger than one item may hold.",
            serde_json::json!({
                "max_bytes": limits::EXPECTED_OUTPUT_BYTES,
                "got_bytes": v.len(),
            }),
        ));
    }
    let metadata = match &body.metadata {
        None => None,
        Some(v) => {
            if !v.is_object() {
                return Err(coded_err(
                    StatusCode::BAD_REQUEST,
                    "invalid_metadata",
                    "metadata must be a JSON object.",
                    serde_json::json!({}),
                ));
            }
            let s = v.to_string();
            if s.len() > limits::METADATA_BYTES {
                return Err(coded_err(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "metadata_too_large",
                    "metadata is larger than one item may hold.",
                    serde_json::json!({
                        "max_bytes": limits::METADATA_BYTES,
                        "got_bytes": s.len(),
                    }),
                ));
            }
            Some(s)
        }
    };
    if body.expected_output.is_none() && metadata.is_none() {
        return Err(coded_err(
            StatusCode::BAD_REQUEST,
            "nothing_to_patch",
            "Send expected_output, metadata, or both. `input` is immutable — remove the \
             item and add it again to change what the case tests.",
            serde_json::json!({}),
        ));
    }

    let patched = state
        .store
        .patch_item(&tenant, dataset_id, item_id, body.expected_output, metadata)
        .await
        .map_err(|e| store_failed("item patch", &e))?;
    if patched {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(not_found())
    }
}

/// `DELETE /v1/datasets/{id}/items/{item_id}` — tombstone.
#[tracing::instrument(skip_all, fields(tenant_id = tracing::field::Empty))]
async fn delete_item(
    State(state): State<DatasetRoutesState>,
    Path((id, item_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    let (tenant, _actor) = actor_from_auth(&state, &headers).await?;
    tracing::Span::current().record("tenant_id", tenant.to_string());
    let dataset_id = parse_id(&id)?;
    let item_id = parse_id(&item_id)?;

    // Tombstoning a LIVE item never touches a frozen copy — `dataset_snapshot_items`
    // is a plain MergeTree holding its own bytes.
    let removed = state
        .store
        .delete_item(&tenant, dataset_id, item_id)
        .await
        .map_err(|e| store_failed("item delete", &e))?;
    if removed {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(not_found())
    }
}

// ── Handlers: snapshots ──────────────────────────────────────────────────────

/// Derive `snapshot_id` from the CONTENT.
///
/// UUIDv5 over `(tenant, dataset, ordered item hashes)`, the same convention as
/// `prompt_eval::eval_suite_id_for`. Two consequences, both wanted: re-freezing
/// an unchanged dataset returns the SAME id and writes nothing, and two runs
/// that claim the same inputs provably had them.
fn snapshot_id_for(tenant: &TenantId, dataset_id: Uuid, hashes: &[String]) -> Uuid {
    let joined = hashes.join(",");
    Uuid::new_v5(
        &SNAPSHOT_NAMESPACE,
        format!("{tenant}:{dataset_id}:{joined}").as_bytes(),
    )
}

/// `POST /v1/datasets/{id}/snapshots` — freeze.
#[tracing::instrument(skip_all, fields(tenant_id = tracing::field::Empty))]
async fn create_snapshot(
    State(state): State<DatasetRoutesState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    let (tenant, actor) = actor_from_auth(&state, &headers).await?;
    tracing::Span::current().record("tenant_id", tenant.to_string());
    let dataset_id = parse_id(&id)?;

    if state
        .store
        .get_dataset(&tenant, dataset_id)
        .await
        .map_err(|e| store_failed("dataset get", &e))?
        .is_none()
    {
        return Err(not_found());
    }

    let items = state
        .store
        .all_items(&tenant, dataset_id)
        .await
        .map_err(|e| store_failed("snapshot item read", &e))?;
    if items.is_empty() {
        return Err(coded_err(
            StatusCode::CONFLICT,
            "dataset_empty",
            "There is nothing to freeze. Add at least one item first — an empty snapshot \
             would let an experiment claim it ran against a dataset and prove nothing.",
            serde_json::json!({}),
        ));
    }

    let hashes: Vec<String> = items.iter().map(|i| i.input_hash.clone()).collect();
    let snapshot_id = snapshot_id_for(&tenant, dataset_id, &hashes);

    // Re-freezing an UNCHANGED dataset is a no-op that returns the same id. It
    // is not an error and it must not consume one of the snapshot slots.
    if state
        .store
        .snapshot_exists(&tenant, dataset_id, snapshot_id)
        .await
        .map_err(|e| store_failed("snapshot lookup", &e))?
    {
        return Ok((
            StatusCode::OK,
            Json(serde_json::json!({
                "snapshot_id": snapshot_id,
                "item_count": items.len(),
                "created": false,
            })),
        ));
    }

    let existing = state
        .store
        .count_snapshots(&tenant, dataset_id)
        .await
        .map_err(|e| store_failed("snapshot count", &e))?;
    if existing >= limits::SNAPSHOTS_PER_DATASET {
        return Err(coded_err(
            StatusCode::CONFLICT,
            "snapshot_limit",
            "This dataset is at its snapshot limit. Snapshots are never deleted \
             automatically — deleting one would un-reproduce every run that cited it.",
            serde_json::json!({ "limit": limits::SNAPSHOTS_PER_DATASET, "current": existing }),
        ));
    }

    state
        .store
        .write_snapshot(&tenant, dataset_id, snapshot_id, &actor, &items)
        .await
        .map_err(|e| store_failed("snapshot write", &e))?;

    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({
            "snapshot_id": snapshot_id,
            "item_count": items.len(),
            "created": true,
        })),
    ))
}

#[derive(Debug, Serialize)]
struct SnapshotDto {
    snapshot_id: Uuid,
    item_count: u32,
    created_at_ms: i64,
    created_by: String,
}

/// `GET /v1/datasets/{id}/snapshots`.
#[tracing::instrument(skip_all, fields(tenant_id = tracing::field::Empty))]
async fn list_snapshots(
    State(state): State<DatasetRoutesState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, ApiError> {
    let tenant = tenant_from_auth(&state, &headers).await?;
    tracing::Span::current().record("tenant_id", tenant.to_string());
    let dataset_id = parse_id(&id)?;

    if state
        .store
        .get_dataset(&tenant, dataset_id)
        .await
        .map_err(|e| store_failed("dataset get", &e))?
        .is_none()
    {
        return Err(not_found());
    }
    let rows = state
        .store
        .list_snapshots(&tenant, dataset_id)
        .await
        .map_err(|e| store_failed("snapshot list", &e))?;
    let n = rows.len();
    Ok(Json(serde_json::json!({
        "snapshots": rows
            .into_iter()
            .map(|s| SnapshotDto {
                snapshot_id: s.snapshot_id,
                item_count: s.item_count,
                created_at_ms: s.created_at_ms,
                created_by: s.created_by,
            })
            .collect::<Vec<_>>(),
        "total": n,
    })))
}

// ── Handlers: import / export ────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct FormatQuery {
    #[serde(default)]
    format: Option<String>,
}

/// The only format this row ships.
///
/// **CSV is deliberately absent, not forgotten.** A round-trippable CSV must
/// carry `input_json` (the exact bytes) beside `input_text`, and parsing it
/// needs a real RFC-4180 reader — a hand-rolled one silently collapses a
/// multi-turn case into a single user message, which is precisely the failure
/// the spec's round-trip proof exists to catch. Shipping a lossy CSV would be
/// worse than shipping none, so the format is REFUSED BY NAME rather than
/// half-supported.
fn require_jsonl(q: &FormatQuery) -> Result<(), ApiError> {
    match q.format.as_deref().unwrap_or("jsonl") {
        "jsonl" => Ok(()),
        other => Err(coded_err(
            StatusCode::BAD_REQUEST,
            "unsupported_format",
            "Only `jsonl` is supported today. CSV needs a lossless round trip \
             (`input_json` beside `input_text`) and is not shipped until it has one — a \
             lossy CSV would silently flatten a multi-turn case.",
            serde_json::json!({ "requested": other, "supported": ["jsonl"] }),
        )),
    }
}

/// One JSONL line. `deny_unknown_fields` so a mistyped key is a REPORTED
/// rejection with its line number, not a silent drop — a silent skip is
/// indistinguishable from a successful import.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ImportRow {
    #[serde(default)]
    name: Option<String>,
    input: Vec<Message>,
    #[serde(default)]
    system: Option<serde_json::Value>,
    #[serde(default)]
    expected_output: Option<String>,
    #[serde(default)]
    metadata: Option<serde_json::Value>,
}

/// `POST /v1/datasets/{id}/import?format=jsonl`.
#[tracing::instrument(skip_all, fields(tenant_id = tracing::field::Empty))]
async fn import_dataset(
    State(state): State<DatasetRoutesState>,
    Path(id): Path<String>,
    Query(q): Query<FormatQuery>,
    headers: HeaderMap,
    body: String,
) -> Result<Json<serde_json::Value>, ApiError> {
    let (tenant, actor) = actor_from_auth(&state, &headers).await?;
    tracing::Span::current().record("tenant_id", tenant.to_string());
    let dataset_id = parse_id(&id)?;
    require_jsonl(&q)?;

    // Re-checked here as well as in the route layer: the layer bounds the
    // TRANSFER, this bounds what we agreed to parse.
    if body.len() > limits::IMPORT_BYTES {
        return Err(coded_err(
            StatusCode::PAYLOAD_TOO_LARGE,
            "import_too_large",
            "The file is larger than the import limit.",
            serde_json::json!({ "max_bytes": limits::IMPORT_BYTES, "got_bytes": body.len() }),
        ));
    }
    if state
        .store
        .get_dataset(&tenant, dataset_id)
        .await
        .map_err(|e| store_failed("dataset get", &e))?
        .is_none()
    {
        return Err(not_found());
    }

    // PARSE EVERYTHING FIRST, WRITE NOTHING YET. "Imported the first 43 rows and
    // stopped" is the truncated-result shape the caps exist to prevent: the
    // caller cannot tell a partial import from a complete one, and re-running it
    // duplicates whatever did land.
    let mut parsed: Vec<(usize, ImportRow)> = Vec::new();
    let mut rejected: Vec<serde_json::Value> = Vec::new();
    for (i, line) in body.lines().enumerate() {
        let lineno = i + 1;
        if line.trim().is_empty() {
            continue;
        }
        match serde_json::from_str::<ImportRow>(line) {
            Ok(r) if r.input.is_empty() => rejected.push(serde_json::json!({
                "line": lineno,
                "reason": "input is empty — a case with no messages tests nothing",
            })),
            Ok(r) => parsed.push((lineno, r)),
            Err(e) => rejected.push(serde_json::json!({
                "line": lineno,
                "reason": e.to_string(),
            })),
        }
    }

    let existing = state
        .store
        .item_stats(&tenant, dataset_id)
        .await
        .map_err(|e| store_failed("item stats", &e))?;
    let would_be = existing.items + parsed.len() as u64;
    if would_be > limits::ITEMS_PER_DATASET as u64 {
        // The WHOLE file is refused and NOTHING is written. Proving the zero is
        // the point: a partial import leaves a dataset nobody can reason about.
        return Err(coded_err(
            StatusCode::CONFLICT,
            "dataset_full",
            "The whole file was refused and nothing was written — importing part of it \
             would leave a dataset you cannot tell apart from a complete one.",
            serde_json::json!({
                "limit": limits::ITEMS_PER_DATASET,
                "current": existing.items,
                "incoming": parsed.len(),
                "headroom": (limits::ITEMS_PER_DATASET as u64).saturating_sub(existing.items),
            }),
        ));
    }

    let now = datetime64_millis_now();
    let mut to_write: Vec<DatasetItem> = Vec::new();
    let mut seen_hashes: Vec<String> = Vec::new();
    let mut deduped = 0u64;
    for (lineno, r) in parsed {
        let system = r
            .system
            .as_ref()
            .map(std::string::ToString::to_string)
            .unwrap_or_default();
        let Ok(input) = serde_json::to_string(&r.input) else {
            rejected.push(serde_json::json!({
                "line": lineno,
                "reason": "input could not be re-serialized",
            }));
            continue;
        };
        let size = input.len() + system.len();
        if size > limits::ITEM_INPUT_BYTES {
            rejected.push(serde_json::json!({
                "line": lineno,
                "reason": format!(
                    "input + system is {size} bytes; the limit is {}",
                    limits::ITEM_INPUT_BYTES
                ),
            }));
            continue;
        }
        if let Some(eo) = &r.expected_output
            && eo.len() > limits::EXPECTED_OUTPUT_BYTES
        {
            rejected.push(serde_json::json!({
                "line": lineno,
                "reason": format!(
                    "expected_output is {} bytes; the limit is {}",
                    eo.len(),
                    limits::EXPECTED_OUTPUT_BYTES
                ),
            }));
            continue;
        }
        let metadata = match &r.metadata {
            None => "{}".to_string(),
            Some(v) if v.is_object() => v.to_string(),
            Some(_) => {
                rejected.push(serde_json::json!({
                    "line": lineno,
                    "reason": "metadata must be a JSON object",
                }));
                continue;
            }
        };
        if metadata.len() > limits::METADATA_BYTES {
            rejected.push(serde_json::json!({
                "line": lineno,
                "reason": format!(
                    "metadata is {} bytes; the limit is {}",
                    metadata.len(),
                    limits::METADATA_BYTES
                ),
            }));
            continue;
        }
        let Ok(hash) = input_hash(&r.input, &system) else {
            rejected.push(serde_json::json!({
                "line": lineno,
                "reason": "could not hash this row",
            }));
            continue;
        };
        // Dedupe against what is already stored AND against earlier lines of
        // this same file — a file that repeats a case must not land it twice.
        if seen_hashes.contains(&hash)
            || state
                .store
                .find_by_hash(&tenant, dataset_id, &hash)
                .await
                .map_err(|e| store_failed("dedupe lookup", &e))?
                .is_some()
        {
            deduped += 1;
            continue;
        }
        seen_hashes.push(hash.clone());
        // `name` goes to the dedicated column, not into `metadata`. It is a
        // display label the export must return unchanged, and burying it in a
        // free-form JSON blob would make the round trip depend on nobody else
        // ever writing a `metadata.name` key.
        let name = r.name.unwrap_or_default();
        if name.len() > limits::NAME_BYTES {
            rejected.push(serde_json::json!({
                "line": lineno,
                "reason": format!("name is {} bytes; the limit is {}", name.len(),
                                  limits::NAME_BYTES),
            }));
            continue;
        }
        to_write.push(DatasetItem {
            item_id: Uuid::new_v4(),
            name,
            input,
            system,
            expected_output: r.expected_output,
            metadata,
            source_trace_id: None,
            source_span_id: String::new(),
            input_hash: hash,
            created_at_ms: now,
            created_by: actor.clone(),
        });
    }

    let added = to_write.len();
    state
        .store
        .insert_items(&tenant, dataset_id, &to_write)
        .await
        .map_err(|e| store_failed("import insert", &e))?;

    // `rejected: []` is stated explicitly rather than hidden — a caller that has
    // to infer "nothing was rejected" from an absent field will one day infer it
    // from a field we forgot to send.
    Ok(Json(serde_json::json!({
        "added": added,
        "deduped": deduped,
        "rejected_count": rejected.len(),
        "rejected": rejected,
    })))
}

/// `GET /v1/datasets/{id}/export?format=jsonl`.
#[tracing::instrument(skip_all, fields(tenant_id = tracing::field::Empty))]
async fn export_dataset(
    State(state): State<DatasetRoutesState>,
    Path(id): Path<String>,
    Query(q): Query<FormatQuery>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let tenant = tenant_from_auth(&state, &headers).await?;
    tracing::Span::current().record("tenant_id", tenant.to_string());
    let dataset_id = parse_id(&id)?;
    require_jsonl(&q)?;

    if state
        .store
        .get_dataset(&tenant, dataset_id)
        .await
        .map_err(|e| store_failed("dataset get", &e))?
        .is_none()
    {
        return Err(not_found());
    }
    // Not truncatable: the dataset cap sits BELOW any export cap, so there is no
    // second cap to breach. Stated so nobody adds one later.
    let items = state
        .store
        .all_items(&tenant, dataset_id)
        .await
        .map_err(|e| store_failed("export read", &e))?;

    let mut out = String::new();
    for i in items {
        let line = serde_json::json!({
            // Emitted even when empty, so a re-import is byte-for-byte the same
            // shape. An omitted key and an empty one are the same to the
            // importer, but only one of them survives a diff of two exports.
            "name": i.name,
            "input": serde_json::from_str::<serde_json::Value>(&i.input)
                .unwrap_or(serde_json::Value::Null),
            "system": if i.system.trim().is_empty() {
                serde_json::Value::Null
            } else {
                serde_json::from_str(&i.system).unwrap_or(serde_json::Value::Null)
            },
            "expected_output": i.expected_output,
            "metadata": serde_json::from_str::<serde_json::Value>(&i.metadata)
                .unwrap_or_else(|_| serde_json::json!({})),
        });
        out.push_str(&line.to_string());
        out.push('\n');
    }

    Ok((
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/x-ndjson"),
            (
                header::CONTENT_DISPOSITION,
                "attachment; filename=\"dataset.jsonl\"",
            ),
        ],
        out,
    )
        .into_response())
}

// ── Shared failure handling ──────────────────────────────────────────────────

/// A store failure is a `502`, logged with the real cause and answered with a
/// stable code.
///
/// The driver text never reaches the client — it can carry SQL and column names
/// — but the client DOES get a code it can act on, because "something went
/// wrong" is unactionable and is what the Error state exists to avoid.
fn store_failed(what: &str, e: &anyhow::Error) -> ApiError {
    tracing::error!(operation = what, error = %format!("{e:#}"), "dataset store call failed");
    coded_err(
        StatusCode::BAD_GATEWAY,
        "store_unavailable",
        "The dataset store did not answer. Nothing was changed.",
        serde_json::json!({ "operation": what }),
    )
}

// ── Tests ────────────────────────────────────────────────────────────────────

// ── THE ONE TEST THAT SENDS REAL CLICKHOUSE PROTOCOL ─────────────────────────
//
// Founder ruling R97, 2026-08-23. Everything above this line drives a MOCK
// STORE, and that is why **49 green tests, a clean gate and a successful deploy
// shipped two wire-level defects to production in one night**:
//
//   B-272  `toString(dataset_id) AS dataset_id … WHERE dataset_id = toUUID(?)`
//          — the alias shadows the column, so the comparison is String-vs-UUID
//          and ClickHouse answers with Code 386. EVERY read 502'd.
//   B-273  `input_hash` declared `String` against a `FixedString(64)` column —
//          RowBinary emits a varint length prefix, the stream desynchronises,
//          and the server reports the mismatch on a LATER row (Code 33). EVERY
//          write failed.
//
// Neither is reachable through a mock: a mock stores a `String` and hands it
// back. The bytes on the wire are the entire subject, and no amount of
// mock-based coverage inspects them. `docs/reference/TRAPS.md` §33 — an
// all-fixture test has never run the thing it names.
//
// SO THE RULE THIS ENCODES: item 9's experiment writes use the SAME row shapes
// against the SAME tables. Building it on the same blind mock is choosing to
// find this class a third time, on prod, at volume.
//
// WHY IN-CRATE AND NOT `tests/`. `dataset_routes` reaches `crate::auth` in 30
// places, so the `#[path]`-include trick that `postgres_tenant_integration.rs`
// uses cannot pull it in. An out-of-crate test would have to MIRROR
// `ItemWriteRow` — and a mirror of the struct is exactly the thing that was
// wrong. `clickhouse_persister_integration.rs` took that route for migration 03
// and says so in its own header ("raw SQL that mirrors the column shape the Rust
// persisters use"); it therefore could not have caught B-273 either. In-crate,
// this drives the REAL `ClickHouseDatasetStore` with the REAL `ItemWriteRow`.
//
// `#[ignore]` + `CLICKHOUSE_TEST_URL`: run it with
// `scripts/ci/run-clickhouse-integration.sh`, which starts a throwaway container.
#[cfg(test)]
mod clickhouse_roundtrip {
    use super::*;

    fn ch() -> Option<clickhouse::Client> {
        let url = std::env::var("CLICKHOUSE_TEST_URL").ok()?;
        Some(
            clickhouse::Client::default()
                .with_url(url)
                .with_database("tracelane"),
        )
    }

    /// Apply migration 18 for real. Not a hand-written CREATE TABLE: a test that
    /// declares its own schema proves the code agrees with the TEST, which is
    /// the tautology B-273 already slipped through once.
    async fn ensure_schema(c: &clickhouse::Client) {
        clickhouse::Client::default()
            .with_url(std::env::var("CLICKHOUSE_TEST_URL").unwrap())
            .query("CREATE DATABASE IF NOT EXISTS tracelane")
            .execute()
            .await
            .expect("create database");
        let sql = include_str!(
            "../../../infra/dev/clickhouse/migrations/18_datasets_and_experiments.sql"
        );
        for stmt in crate::clickhouse_query::split_migration_statements(sql) {
            c.query(&stmt).execute().await.expect("migration 18 stmt");
        }
    }

    fn item(hash: &str) -> DatasetItem {
        DatasetItem {
            item_id: Uuid::new_v4(),
            name: "case-1".into(),
            input: r#"[{"role":"user","content":"ok"}]"#.into(),
            system: "be brief".into(),
            expected_output: None,
            metadata: "{}".into(),
            source_trace_id: Some(Uuid::new_v4()),
            source_span_id: "span-1".into(),
            input_hash: hash.into(),
            created_at_ms: crate::clickhouse_query::datetime64_millis_now(),
            created_by: "user_test".into(),
        }
    }

    /// **EVL-29 R228 — the content snapshot against a REAL ClickHouse.**
    ///
    /// THE DEFECT THIS EXISTS FOR, found on prod at the first queue listing:
    /// `SnapRow.input_hash` was declared `&str` against a `FixedString(64)`
    /// column, so clickhouse-rs emitted the varint length prefix a FixedString
    /// never carries. Every write answered `Code: 32 ATTEMPT_TO_READ_AFTER_EOF:
    /// While executing BinaryRowInputFormat`, and because the list path folds a
    /// snapshot failure into a `warn!` (fail-OPEN by design — a snapshot failure
    /// must not hide a trace from a reviewer), the queue looked completely
    /// healthy while the table stayed at ZERO rows.
    ///
    /// **FIFTH INSTANCE OF THE CLASS**, and a comment naming this exact trap was
    /// sitting on the offending line while it was wrong. A comment is not a
    /// control; this is.
    #[tokio::test]
    #[ignore = "needs CLICKHOUSE_TEST_URL — run scripts/ci/run-clickhouse-integration.sh"]
    async fn a_content_snapshot_survives_a_real_clickhouse_round_trip() {
        let Some(c) = ch() else {
            panic!("CLICKHOUSE_TEST_URL not set — this test cannot run, which is not a pass");
        };
        ensure_schema(&c).await;
        // Migration 21 applied for real, same reason as 18: a test that declares
        // its own schema proves the code agrees with the TEST.
        let sql = include_str!(
            "../../../infra/dev/clickhouse/migrations/21_evl29_trace_content_snapshots.sql"
        );
        for stmt in crate::clickhouse_query::split_migration_statements(sql) {
            c.query(&stmt).execute().await.expect("migration 21 stmt");
        }

        let store = ClickHouseDatasetStore::new(c.clone());
        let tenant = TenantId::from_jwt_claim(Uuid::new_v4());
        let trace = Uuid::new_v4().to_string();
        let hash = "b".repeat(64);

        store
            .snapshot_content(
                &tenant,
                &trace,
                "span-1",
                r#"[{"role":"user","content":"hi"}]"#,
                "sys",
                &hash,
            )
            .await
            .expect(
                "the snapshot INSERT must succeed — this is the assertion that was red on prod",
            );

        let got = store
            .read_snapshot(&tenant, &trace, "span-1")
            .await
            .expect("read")
            .expect("the row must be there — a silent write failure reads as None");
        assert_eq!(got.input_messages, r#"[{"role":"user","content":"hi"}]"#);
        assert_eq!(got.system_instructions, "sys");

        // Idempotent: the queue list re-snapshots on every page load, so a second
        // write of the same key must collapse rather than duplicate.
        store
            .snapshot_content(
                &tenant,
                &trace,
                "span-1",
                r#"[{"role":"user","content":"hi"}]"#,
                "sys",
                &hash,
            )
            .await
            .expect("re-snapshot");
        let n = store
            .snapshotted_trace_ids(&tenant, std::slice::from_ref(&trace))
            .await
            .expect("membership");
        assert_eq!(
            n,
            vec![trace.clone()],
            "the trace must report as snapshotted exactly once"
        );

        // A hash that is NOT 64 hex chars must be REFUSED, not truncated or
        // padded: a wrong dedupe key on a permanent test case is worse than a
        // failed write.
        assert!(
            store
                .snapshot_content(&tenant, &trace, "span-2", "[]", "", "too-short")
                .await
                .is_err(),
            "a non-64-hex hash must refuse rather than silently store a wrong key"
        );
    }

    /// THE ROUND TRIP. Insert through the real store, read back through the real
    /// store, and assert the two properties that were broken on prod.
    ///
    /// A FRESH TENANT UUID PER RUN, so a dirty container and two concurrent runs
    /// cannot make one test read another's rows — the same reason
    /// `clickhouse_persister_integration.rs` fabricates one.
    #[tokio::test]
    #[ignore = "needs CLICKHOUSE_TEST_URL — run scripts/ci/run-clickhouse-integration.sh"]
    async fn a_dataset_item_survives_a_real_clickhouse_round_trip() {
        let Some(c) = ch() else {
            panic!("CLICKHOUSE_TEST_URL not set — this test cannot run, which is not a pass");
        };
        ensure_schema(&c).await;
        let store = ClickHouseDatasetStore::new(c);
        let tenant = TenantId::from_jwt_claim(Uuid::new_v4());
        let dataset_id = Uuid::new_v4();
        let now = crate::clickhouse_query::datetime64_millis_now();

        store
            .create_dataset(
                &tenant,
                &Dataset {
                    dataset_id,
                    name: "roundtrip".into(),
                    description: String::new(),
                    created_at_ms: now,
                    created_by: "user_test".into(),
                    updated_at_ms: now,
                },
            )
            .await
            .expect("create_dataset must reach ClickHouse");

        // 64 hex chars — a real sha256. B-273 is a WRITE-side failure: with
        // `input_hash: String` this call is where the RowBinary stream
        // desynchronises, so the assertion is that it returns Ok at all.
        let hash = "a".repeat(64);
        let written = item(&hash);
        store
            .insert_items(&tenant, dataset_id, std::slice::from_ref(&written))
            .await
            .expect("insert_items must not desynchronise the RowBinary stream (B-273)");

        // B-272 is a READ-side failure: the projection aliases `toString(item_id)
        // AS item_id`, and an UNQUALIFIED `WHERE dataset_id = toUUID(?)` compares
        // the aliased String against a UUID. This read is the assertion.
        let got = store
            .get_dataset(&tenant, dataset_id)
            .await
            .expect("get_dataset must not fail on a UUID WHERE (B-272)")
            .expect("the dataset written one line ago must be readable");
        assert_eq!(
            got.dataset_id, dataset_id,
            "the UUID WHERE matched the wrong row"
        );
        assert_eq!(got.name, "roundtrip");

        let items = store
            .all_items(&tenant, dataset_id)
            .await
            .expect("all_items must not fail on a UUID WHERE (B-272)");
        assert_eq!(items.len(), 1, "the inserted item was not readable back");
        let read = &items[0];

        // THE FixedString(64) ASSERTION, and it is on the VALUE, not the length
        // alone. A `FixedString(64)` right-pads with NUL bytes, so a short hash
        // reads back as 64 chars of which some are `\0` — a length check alone
        // would pass on a value no dedupe lookup could ever match again.
        assert_eq!(read.input_hash.len(), 64, "input_hash is not 64 bytes");
        assert_eq!(
            read.input_hash, hash,
            "input_hash did not survive the round trip"
        );
        assert!(
            !read.input_hash.contains('\0'),
            "input_hash came back NUL-padded — a short value was written into FixedString(64)"
        );
        assert_eq!(read.item_id, written.item_id, "item_id did not survive");
        assert_eq!(read.input, written.input, "input did not survive");
        assert_eq!(read.system, written.system, "system did not survive");
        assert_eq!(
            read.expected_output, None,
            "expected_output must stay NULL, never coerce to an empty string"
        );

        // The dedupe lookup binds the hash into a FixedString(64) comparison —
        // the other half of B-273, on the read side.
        let found = store
            .find_by_hash(&tenant, dataset_id, &hash)
            .await
            .expect("find_by_hash must reach ClickHouse");
        assert_eq!(
            found,
            Some(written.item_id),
            "the hash written above did not match itself on lookup"
        );
    }

    /// TENANT ISOLATION, on the real engine rather than on a mock that was told
    /// to filter. Every read on this surface binds `tenant_id`, and a mock
    /// proves only that the argument was passed.
    #[tokio::test]
    #[ignore = "needs CLICKHOUSE_TEST_URL — run scripts/ci/run-clickhouse-integration.sh"]
    async fn a_second_tenant_cannot_read_the_first_tenants_dataset() {
        let Some(c) = ch() else {
            panic!("CLICKHOUSE_TEST_URL not set — this test cannot run, which is not a pass");
        };
        ensure_schema(&c).await;
        let store = ClickHouseDatasetStore::new(c);
        let a = TenantId::from_jwt_claim(Uuid::new_v4());
        let b = TenantId::from_jwt_claim(Uuid::new_v4());
        let dataset_id = Uuid::new_v4();
        let now = crate::clickhouse_query::datetime64_millis_now();
        store
            .create_dataset(
                &a,
                &Dataset {
                    dataset_id,
                    name: "tenant-a".into(),
                    description: String::new(),
                    created_at_ms: now,
                    created_by: "user_a".into(),
                    updated_at_ms: now,
                },
            )
            .await
            .expect("create_dataset");
        store
            .insert_items(&a, dataset_id, &[item(&"b".repeat(64))])
            .await
            .expect("insert_items");

        // THE POSITIVE CONTROL MUST USE THE SAME READ PATH AS THE NEGATIVE ONE.
        // Written the lazy way first: this asserted on `get_dataset` while the
        // leak assertions below used `all_items`, so `all_items` returning
        // EMPTY FOR EVERY TENANT would have passed the whole test. That is the
        // probe-that-separates-nothing shape, and it mattered immediately —
        // `all_items` was in fact broken (B-274) and this test still went green.
        assert!(
            store
                .get_dataset(&a, dataset_id)
                .await
                .expect("read a")
                .is_some(),
            "tenant A must see its own dataset — otherwise the isolation assertion below is vacuous"
        );
        assert_eq!(
            store
                .all_items(&a, dataset_id)
                .await
                .expect("items a")
                .len(),
            1,
            "tenant A must read its own item — otherwise the leak assertion below is vacuous"
        );
        assert!(
            store
                .get_dataset(&b, dataset_id)
                .await
                .expect("read b")
                .is_none(),
            "TENANT LEAK: B read A's dataset by id"
        );
        assert!(
            store
                .all_items(&b, dataset_id)
                .await
                .expect("items b")
                .is_empty(),
            "TENANT LEAK: B read A's items by dataset id"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use tracelane_shared::{MessageContent, Role as MsgRole};

    fn tenant() -> TenantId {
        TenantId::from_jwt_claim(Uuid::nil())
    }

    fn other_tenant() -> TenantId {
        TenantId::from_jwt_claim(Uuid::from_u128(9))
    }

    fn msg(text: &str) -> Message {
        Message {
            role: MsgRole::User,
            content: MessageContent::Text(text.into()),
            tool_call_id: None,
            tool_calls: None,
        }
    }

    fn claims(
        role: Option<crate::auth::Role>,
        method: crate::auth::AuthMethod,
        key_scope: crate::auth::scope::KeyScope,
    ) -> Claims {
        Claims {
            tenant_id: tenant(),
            sub: "user-a".to_string(),
            exp: u64::MAX,
            auth_method: method,
            role,
            key_scope,
            budget_usd_monthly: None,
            rate_limit_rpm: None,
        }
    }

    fn scoped(slugs: &[&str]) -> crate::auth::scope::KeyScope {
        let owned: Vec<String> = slugs.iter().map(|s| (*s).to_string()).collect();
        crate::auth::scope::KeyScope::from_column(Some(&owned))
    }

    // ── The refusals must stay DISTINGUISHABLE ───────────────────────────────

    /// The property the whole surface is built to hold. Every code this module
    /// can emit for "there is no content here" is listed, and any two being
    /// equal fails HERE, loudly, rather than being discovered by a user who
    /// tuned a filter that could never work.
    ///
    /// FALSIFIED while writing it: pointing two of these strings at the same
    /// literal — the collapse this guards — makes the assertion fail.
    #[test]
    fn the_no_content_refusals_are_four_distinct_codes() {
        let codes = [
            "content_capture_disabled",
            "span_has_no_content",
            "span_content_unreadable",
            "not_found",
        ];
        for (i, a) in codes.iter().enumerate() {
            for b in codes.iter().skip(i + 1) {
                assert_ne!(
                    a, b,
                    "the refusal codes must stay distinct — collapsing two sends the user \
                     to the wrong remedy"
                );
            }
        }
    }

    /// Capture is decided from the ALLOWLIST, and an absent config is OFF.
    ///
    /// This is the fail-closed direction and the one that matters: no
    /// `trace_content:` block means no tenant captures content, so the
    /// conversion must refuse with `content_capture_disabled` rather than fall
    /// through to a span read that returns nothing and reads as "not found".
    #[test]
    fn absent_trace_content_config_means_capture_is_off() {
        assert!(
            !capture_enabled(None, &tenant()),
            "no config MUST mean no capture — an absent block is the unprivileged state"
        );
    }

    #[test]
    fn classify_span_no_row_is_not_found() {
        assert!(matches!(classify_span(None), SpanVerdict::NotFound));
    }

    /// `JSONExtractRaw` on a missing key returns an EMPTY string, and on a
    /// present-but-null key the literal `null`. Both mean "this span predates
    /// capture" — asserted rather than assumed, because treating `"null"` as
    /// content would produce a case whose input is the four characters `null`.
    #[test]
    fn classify_span_empty_or_null_is_no_content() {
        for raw in ["", "  ", "null"] {
            assert!(
                matches!(
                    classify_span(Some(SpanContentRow {
                        input_messages: raw.into(),
                        system_instructions: String::new(),
                    })),
                    SpanVerdict::NoContent
                ),
                "{raw:?} must classify as NoContent"
            );
        }
    }

    #[test]
    fn classify_span_empty_array_is_no_content_not_content() {
        assert!(
            matches!(
                classify_span(Some(SpanContentRow {
                    input_messages: "[]".into(),
                    system_instructions: String::new(),
                })),
                SpanVerdict::NoContent
            ),
            "zero messages is no content — copying it would build a case that tests nothing"
        );
    }

    #[test]
    fn classify_span_unparseable_is_unreadable_not_no_content() {
        assert!(
            matches!(
                classify_span(Some(SpanContentRow {
                    input_messages: r#"{"not":"a message array"}"#.into(),
                    system_instructions: String::new(),
                })),
                SpanVerdict::Unreadable
            ),
            "content that IS there but unreadable must NOT report as absent — the remedy \
             differs"
        );
    }

    #[test]
    fn classify_span_reads_content_and_system() {
        let raw = serde_json::to_string(&vec![msg("hello")]).expect("serialize");
        match classify_span(Some(SpanContentRow {
            input_messages: raw,
            system_instructions: r#""be terse""#.into(),
        })) {
            SpanVerdict::Content(m, s) => {
                assert_eq!(m.len(), 1);
                assert_eq!(s, r#""be terse""#, "the system field is copied verbatim");
            }
            other => panic!("expected Content, got {other:?}"),
        }
    }

    /// `system` is a DIFFERENT inbound shape from a `role: "system"` message and
    /// most of prod uses the former. Missing it would silently drop the system
    /// instructions from every copied case.
    #[test]
    fn system_absent_is_empty_not_the_string_null() {
        match classify_span(Some(SpanContentRow {
            input_messages: serde_json::to_string(&vec![msg("hi")]).expect("serialize"),
            system_instructions: "null".into(),
        })) {
            SpanVerdict::Content(_, s) => assert_eq!(s, ""),
            other => panic!("expected Content, got {other:?}"),
        }
    }

    // ── The dedupe hash ─────────────────────────────────────────────────────

    #[test]
    fn input_hash_is_stable_across_calls() {
        let m = vec![msg("a"), msg("b")];
        assert_eq!(
            input_hash(&m, "sys").expect("hash"),
            input_hash(&m, "sys").expect("hash")
        );
        assert_eq!(input_hash(&m, "sys").expect("hash").len(), 64, "sha256 hex");
    }

    /// The system field is IN the hash. Two cases with identical messages and
    /// different system instructions are different test cases, and treating them
    /// as duplicates would silently discard one.
    #[test]
    fn input_hash_separates_on_the_system_field() {
        let m = vec![msg("a")];
        assert_ne!(
            input_hash(&m, "sys-a").expect("hash"),
            input_hash(&m, "sys-b").expect("hash")
        );
    }

    #[test]
    fn input_hash_separates_on_message_order() {
        let ab = vec![msg("a"), msg("b")];
        let ba = vec![msg("b"), msg("a")];
        assert_ne!(
            input_hash(&ab, "").expect("hash"),
            input_hash(&ba, "").expect("hash")
        );
    }

    // ── Snapshot identity ───────────────────────────────────────────────────

    #[test]
    fn refreezing_unchanged_content_yields_the_same_snapshot_id() {
        let d = Uuid::from_u128(1);
        let h = vec!["aa".to_string(), "bb".to_string()];
        assert_eq!(
            snapshot_id_for(&tenant(), d, &h),
            snapshot_id_for(&tenant(), d, &h),
            "an unchanged dataset must re-freeze to the SAME id and write nothing"
        );
    }

    #[test]
    fn a_changed_item_set_yields_a_different_snapshot_id() {
        let d = Uuid::from_u128(1);
        assert_ne!(
            snapshot_id_for(&tenant(), d, &["aa".into(), "bb".into()]),
            snapshot_id_for(&tenant(), d, &["aa".into(), "cc".into()]),
        );
    }

    /// ORDER is part of the identity: the same items in a different order are a
    /// different case set for anything order-sensitive, and the ordinal is what
    /// fixes it.
    #[test]
    fn snapshot_id_depends_on_order() {
        let d = Uuid::from_u128(1);
        assert_ne!(
            snapshot_id_for(&tenant(), d, &["aa".into(), "bb".into()]),
            snapshot_id_for(&tenant(), d, &["bb".into(), "aa".into()]),
        );
    }

    /// Two tenants with byte-identical datasets must NOT share a snapshot id —
    /// that would let one tenant's freeze answer the other's existence check.
    #[test]
    fn snapshot_id_is_tenant_scoped() {
        let d = Uuid::from_u128(1);
        let h = vec!["aa".to_string()];
        assert_ne!(
            snapshot_id_for(&tenant(), d, &h),
            snapshot_id_for(&other_tenant(), d, &h),
        );
    }

    // ── Auth gates ──────────────────────────────────────────────────────────

    #[test]
    fn viewer_may_not_write() {
        let c = claims(
            Some(crate::auth::Role::Viewer),
            crate::auth::AuthMethod::JwtBearer,
            crate::auth::scope::KeyScope::LegacyFullSurface,
        );
        assert!(authorize_write(&c).is_err(), "a viewer must NOT write");
    }

    #[test]
    fn member_may_not_write_but_owner_may() {
        let member = claims(
            Some(crate::auth::Role::Member),
            crate::auth::AuthMethod::JwtBearer,
            crate::auth::scope::KeyScope::LegacyFullSurface,
        );
        let owner = claims(
            Some(crate::auth::Role::Owner),
            crate::auth::AuthMethod::JwtBearer,
            crate::auth::scope::KeyScope::LegacyFullSurface,
        );
        assert!(authorize_write(&member).is_err());
        assert!(authorize_write(&owner).is_ok());
    }

    /// A viewer must still be able to SEE datasets — that is the read-only
    /// state, and denying the read too would make the role useless rather than
    /// safe.
    #[test]
    fn viewer_may_read() {
        let c = claims(
            Some(crate::auth::Role::Viewer),
            crate::auth::AuthMethod::JwtBearer,
            crate::auth::scope::KeyScope::LegacyFullSurface,
        );
        assert!(authorize_read(&c).is_ok());
    }

    /// A JWT with an absent or unrecognised role slug fails CLOSED — the PL-9
    /// shape, where WorkOS's default role, a renamed role and an outright typo
    /// all used to land on "grant everything".
    #[test]
    fn unrecognised_role_on_a_jwt_fails_closed() {
        let c = claims(
            None,
            crate::auth::AuthMethod::JwtBearer,
            crate::auth::scope::KeyScope::LegacyFullSurface,
        );
        assert!(authorize_write(&c).is_err());
    }

    /// THE GAP THIS SURFACE CLOSES ON ITS FIRST COMMIT. `can_write_prompts`
    /// admits any API key without ever reading `key_scope`, so without the scope
    /// half a `read`-only key could create datasets. Observed refusing.
    #[test]
    fn a_read_only_api_key_may_not_write() {
        let c = claims(None, crate::auth::AuthMethod::ApiKey, scoped(&["read"]));
        let err = authorize_write(&c).expect_err("a read-scoped key must NOT write");
        assert_eq!(err.0, StatusCode::FORBIDDEN);
        assert_eq!(
            err.1.0.get("required_scope").and_then(|v| v.as_str()),
            Some("admin"),
            "the refusal must name the scope, not collapse into a generic 403"
        );
    }

    #[test]
    fn an_ingest_only_api_key_may_neither_read_nor_write() {
        let c = claims(None, crate::auth::AuthMethod::ApiKey, scoped(&["ingest"]));
        assert!(
            authorize_read(&c).is_err(),
            "an SDK key shipped in a container image must not exfiltrate copied prompts"
        );
        assert!(authorize_write(&c).is_err());
    }

    /// `admin` does NOT imply `read` (`KeyScope::allows` has no hierarchy), so
    /// an admin-only key must not be able to COPY span content it cannot read.
    /// That is why the conversion route asks for both.
    #[test]
    fn an_admin_only_key_may_write_but_not_read() {
        let c = claims(None, crate::auth::AuthMethod::ApiKey, scoped(&["admin"]));
        assert!(authorize_write(&c).is_ok());
        assert!(
            authorize_read(&c).is_err(),
            "admin must not imply read — the conversion asks for both for this reason"
        );
    }

    #[test]
    fn a_legacy_null_scope_key_keeps_the_full_surface() {
        let c = claims(
            None,
            crate::auth::AuthMethod::ApiKey,
            crate::auth::scope::KeyScope::LegacyFullSurface,
        );
        assert!(authorize_read(&c).is_ok());
        assert!(authorize_write(&c).is_ok());
    }

    // ── The entitlement gate fails CLOSED with no cache ──────────────────────

    /// `.claude/rules/tenancy.md`: an absent entitlement cache means "no control
    /// plane", which is the UNPRIVILEGED state. Observed refusing — a no-cache
    /// path that granted would produce no error, no alert and no complaint,
    /// which is exactly how the guardrail rail gate shipped inverted.
    #[tokio::test]
    async fn absent_entitlement_cache_refuses() {
        let err = require_datasets(&None, &tenant())
            .await
            .expect_err("no cache MUST refuse");
        assert_eq!(err.0, StatusCode::SERVICE_UNAVAILABLE);
    }

    // ── Cursor + paging ─────────────────────────────────────────────────────

    #[test]
    fn cursor_round_trips() {
        let c = encode_cursor(1_778_581_394_123, "0192a-id");
        assert_eq!(
            decode_cursor(&c),
            Some((1_778_581_394_123, "0192a-id".into()))
        );
    }

    #[test]
    fn cursor_rejects_malformed() {
        assert_eq!(decode_cursor("nope"), None);
        assert_eq!(decode_cursor("123:"), None);
        assert_eq!(decode_cursor("abc:id"), None);
    }

    /// A page is never unbounded, and a caller asking for a million gets the cap
    /// — the unpaginated `GET /v1/prompts` defect is not inherited.
    #[test]
    fn page_limit_is_clamped_in_both_directions() {
        assert_eq!(
            page_limit(&PageQuery {
                limit: None,
                cursor: None,
                name: None
            }),
            limits::PAGE_DEFAULT
        );
        assert_eq!(
            page_limit(&PageQuery {
                limit: Some(1_000_000),
                cursor: None,
                name: None
            }),
            limits::PAGE_MAX
        );
        assert_eq!(
            page_limit(&PageQuery {
                limit: Some(0),
                cursor: None,
                name: None
            }),
            1
        );
    }

    // ── Body shapes ─────────────────────────────────────────────────────────

    /// The conversion body carries `{trace_id, span_id}` and NOTHING else. A
    /// smuggled payload is refused rather than silently ignored — the client's
    /// content is never what lands in the item.
    #[test]
    fn add_item_body_refuses_a_client_supplied_payload() {
        let ok = r#"{"trace_id":"t","span_id":"s"}"#;
        assert!(serde_json::from_str::<AddItemBody>(ok).is_ok());
        for smuggled in [
            r#"{"trace_id":"t","span_id":"s","input":[{"role":"user","content":"x"}]}"#,
            r#"{"trace_id":"t","span_id":"s","expected_output":"forged"}"#,
            r#"{"trace_id":"t","span_id":"s","tenant_id":"another-tenant"}"#,
        ] {
            assert!(
                serde_json::from_str::<AddItemBody>(smuggled).is_err(),
                "must refuse a client payload: {smuggled}"
            );
        }
    }

    /// `input` is immutable. A PATCH that tries to change it must be a refusal,
    /// not a no-op that leaves the caller believing the case changed.
    #[test]
    fn patch_body_refuses_an_input_edit() {
        assert!(serde_json::from_str::<PatchItemBody>(r#"{"expected_output":"x"}"#).is_ok());
        assert!(serde_json::from_str::<PatchItemBody>(r#"{"metadata":{"a":1}}"#).is_ok());
        assert!(
            serde_json::from_str::<PatchItemBody>(r#"{"input":[]}"#).is_err(),
            "input is immutable — an edit is remove-then-add"
        );
    }

    /// `null` clears the reference; an absent key leaves it alone. A plain
    /// `Option` cannot express both, and conflating them means "clear this"
    /// silently does nothing.
    #[test]
    fn patch_distinguishes_clear_from_leave_alone() {
        let clear: PatchItemBody =
            serde_json::from_str(r#"{"expected_output":null}"#).expect("parse");
        assert_eq!(clear.expected_output, Some(None));
        let untouched: PatchItemBody = serde_json::from_str(r#"{"metadata":{}}"#).expect("parse");
        assert_eq!(untouched.expected_output, None);
    }

    #[test]
    fn import_row_refuses_an_unknown_key() {
        let good = r#"{"input":[{"role":"user","content":"hi"}]}"#;
        assert!(serde_json::from_str::<ImportRow>(good).is_ok());
        let typo = r#"{"input":[{"role":"user","content":"hi"}],"expcted_output":"x"}"#;
        assert!(
            serde_json::from_str::<ImportRow>(typo).is_err(),
            "a mistyped key must be a reported rejection, never a silent drop"
        );
    }

    /// CSV is refused BY NAME rather than half-supported. A lossy CSV would
    /// flatten a multi-turn case into one message and nothing would say so.
    #[test]
    fn csv_is_refused_by_name_not_silently_treated_as_jsonl() {
        assert!(require_jsonl(&FormatQuery { format: None }).is_ok());
        assert!(
            require_jsonl(&FormatQuery {
                format: Some("jsonl".into())
            })
            .is_ok()
        );
        let err = require_jsonl(&FormatQuery {
            format: Some("csv".into()),
        })
        .expect_err("csv must refuse");
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        assert_eq!(
            err.1.0.get("error").and_then(|v| v.as_str()),
            Some("unsupported_format")
        );
    }

    // ── Error shape ─────────────────────────────────────────────────────────

    /// The double-encoding guard. `role_forbidden_json` hands us a JSON OBJECT
    /// as a string; wrapping it would put `required_role` inside an escaped
    /// string where `body.error.required_role` reads as `undefined`. Observed on
    /// prod on the sibling surface, invisible to `contains()`-style assertions.
    #[test]
    fn a_json_object_error_passes_through_unwrapped() {
        let (_, Json(v)) = api_err(
            StatusCode::FORBIDDEN,
            crate::auth::role_forbidden_json("owner"),
        );
        assert_eq!(
            v.get("required_role").and_then(|x| x.as_str()),
            Some("owner"),
            "the machine-readable field must be at the TOP level, not escaped in a string"
        );
    }

    #[test]
    fn a_plain_message_error_is_wrapped() {
        let (_, Json(v)) = api_err(StatusCode::BAD_REQUEST, "plain text".to_string());
        assert_eq!(v.get("error").and_then(|x| x.as_str()), Some("plain text"));
    }

    /// One 404 body for every "not yours" cause. If these ever diverge, a caller
    /// can tell an existing-but-foreign id from a nonexistent one.
    #[test]
    fn the_not_found_body_is_identical_for_every_cause() {
        let a = not_found();
        let b = not_found();
        assert_eq!(a.0, StatusCode::NOT_FOUND);
        assert_eq!(a.1.0, b.1.0);
        assert!(
            !a.1.0.to_string().contains("dataset_id"),
            "the body must not echo which id was missing"
        );
    }

    /// A malformed path id takes the SAME 404 — no separate code, no oracle.
    #[test]
    fn a_malformed_path_id_is_the_same_404() {
        let err = parse_id("not-a-uuid").expect_err("garbage must not resolve");
        assert_eq!(err.0, StatusCode::NOT_FOUND);
        assert_eq!(err.1.0, not_found().1.0);
    }

    #[test]
    fn a_store_failure_never_echoes_the_driver_text() {
        let e = anyhow::anyhow!("SELECT secret FROM dataset_items WHERE tenant_id = 'abc'");
        let (status, Json(v)) = store_failed("item list", &e);
        assert_eq!(status, StatusCode::BAD_GATEWAY);
        let body = v.to_string();
        assert!(
            !body.contains("SELECT"),
            "SQL must not reach the client: {body}"
        );
        assert_eq!(
            v.get("error").and_then(|x| x.as_str()),
            Some("store_unavailable")
        );
    }

    // ── The DTO's honesty about a missing reference ─────────────────────────

    fn trace_item() -> DatasetItem {
        DatasetItem {
            item_id: Uuid::from_u128(7),
            name: String::new(),
            input: serde_json::to_string(&vec![msg("hi")]).expect("serialize"),
            system: String::new(),
            expected_output: None,
            metadata: "{}".into(),
            source_trace_id: Some(Uuid::from_u128(3)),
            source_span_id: "span-1".into(),
            input_hash: "f".repeat(64),
            created_at_ms: 1,
            created_by: "user-a".into(),
        }
    }

    /// A trace-derived item ALWAYS has a NULL reference, and the DTO says WHY.
    /// An empty string here would be a test case that passes nothing and fails
    /// nothing, which is worse than no case at all.
    #[test]
    fn a_trace_derived_item_reports_why_its_reference_is_absent() {
        let dto = ItemDto::from(trace_item());
        assert!(dto.expected_output.is_none());
        assert_eq!(dto.expected_output_reason, Some(OUTPUT_NOT_CAPTURED));
        let json = serde_json::to_value(&dto).expect("serialize");
        assert!(json.get("expected_output").expect("field").is_null());
        assert_ne!(
            json.get("expected_output").expect("field"),
            &serde_json::json!(""),
            "never an empty string standing in for a reference"
        );
    }

    /// A trace-derived item is UNNAMED. Manufacturing `trace:<id>` here would
    /// duplicate what `source_trace_id` already says, in a column that can then
    /// disagree with it.
    #[test]
    fn a_trace_derived_item_is_unnamed_rather_than_labelled_from_its_trace() {
        let dto = ItemDto::from(trace_item());
        assert_eq!(
            dto.name, "",
            "empty means unnamed; the surface renders the ordinal"
        );
        assert!(
            dto.source_trace_id.is_some(),
            "provenance lives here instead"
        );
    }

    /// An IMPORTED item with no reference is a different fact — the file simply
    /// did not carry one — so it must not claim `output_not_captured`.
    #[test]
    fn an_imported_item_without_a_reference_does_not_blame_capture() {
        let mut i = trace_item();
        i.source_trace_id = None;
        i.source_span_id = String::new();
        assert_eq!(ItemDto::from(i).expected_output_reason, None);
    }

    #[test]
    fn an_item_with_a_reference_carries_no_reason() {
        let mut i = trace_item();
        i.expected_output = Some("TRANSFER".into());
        let dto = ItemDto::from(i);
        assert_eq!(dto.expected_output, Some("TRANSFER".into()));
        assert_eq!(dto.expected_output_reason, None);
    }

    /// Stored JSON that does not parse renders as `null`, never as raw text — a
    /// client that string-matched the text would be reading a format we never
    /// promised.
    #[test]
    fn unparseable_stored_json_renders_as_null_not_as_raw_text() {
        let mut i = trace_item();
        i.input = "{not json".into();
        assert!(ItemDto::from(i).input.is_null());
    }

    // ── The store seam carries the tenant on EVERY call ─────────────────────

    #[derive(Default)]
    struct MockStore {
        seen_tenant: Mutex<Vec<String>>,
        items: Mutex<Vec<(Uuid, DatasetItem)>>,
        datasets: Mutex<Vec<Dataset>>,
    }

    impl MockStore {
        fn note(&self, t: &TenantId) {
            self.seen_tenant
                .lock()
                .expect("seen_tenant poisoned")
                .push(t.to_string());
        }
    }

    #[async_trait::async_trait]
    impl DatasetStore for MockStore {
        async fn create_dataset(&self, t: &TenantId, row: &Dataset) -> Result<()> {
            self.note(t);
            self.datasets.lock().expect("poisoned").push(row.clone());
            Ok(())
        }
        async fn count_datasets(&self, t: &TenantId) -> Result<u64> {
            self.note(t);
            Ok(self.datasets.lock().expect("poisoned").len() as u64)
        }
        async fn list_datasets(
            &self,
            t: &TenantId,
            _c: Option<(i64, String)>,
            _l: u32,
            name: Option<&str>,
        ) -> Result<Vec<Dataset>> {
            self.note(t);
            let all = self.datasets.lock().expect("poisoned").clone();
            // The mock honours the filter so a handler test can observe it
            // actually narrowing. A mock that ignored `name` would let a
            // handler that never forwards it pass.
            Ok(match name {
                Some(n) => all.into_iter().filter(|d| d.name == n).collect(),
                None => all,
            })
        }
        async fn get_dataset(&self, t: &TenantId, id: Uuid) -> Result<Option<Dataset>> {
            self.note(t);
            Ok(self
                .datasets
                .lock()
                .expect("poisoned")
                .iter()
                .find(|d| d.dataset_id == id)
                .cloned())
        }
        async fn delete_dataset(&self, t: &TenantId, id: Uuid) -> Result<bool> {
            self.note(t);
            let mut d = self.datasets.lock().expect("poisoned");
            let before = d.len();
            d.retain(|x| x.dataset_id != id);
            Ok(before != d.len())
        }
        async fn item_stats(&self, t: &TenantId, id: Uuid) -> Result<ItemStats> {
            self.note(t);
            let items = self.items.lock().expect("poisoned");
            let mine: Vec<_> = items.iter().filter(|(d, _)| *d == id).collect();
            Ok(ItemStats {
                items: mine.len() as u64,
                with_reference: mine
                    .iter()
                    .filter(|(_, i)| {
                        i.expected_output
                            .as_deref()
                            .is_some_and(|s| !s.trim().is_empty())
                    })
                    .count() as u64,
                from_traces: mine
                    .iter()
                    .filter(|(_, i)| i.source_trace_id.is_some())
                    .count() as u64,
            })
        }
        async fn list_items(
            &self,
            t: &TenantId,
            id: Uuid,
            _c: Option<(i64, String)>,
            _l: u32,
        ) -> Result<Vec<DatasetItem>> {
            self.all_items(t, id).await
        }
        async fn all_items(&self, t: &TenantId, id: Uuid) -> Result<Vec<DatasetItem>> {
            self.note(t);
            Ok(self
                .items
                .lock()
                .expect("poisoned")
                .iter()
                .filter(|(d, _)| *d == id)
                .map(|(_, i)| i.clone())
                .collect())
        }
        async fn find_by_hash(&self, t: &TenantId, id: Uuid, hash: &str) -> Result<Option<Uuid>> {
            self.note(t);
            Ok(self
                .items
                .lock()
                .expect("poisoned")
                .iter()
                .find(|(d, i)| *d == id && i.input_hash == hash)
                .map(|(_, i)| i.item_id))
        }
        async fn insert_items(&self, t: &TenantId, id: Uuid, rows: &[DatasetItem]) -> Result<()> {
            self.note(t);
            let mut items = self.items.lock().expect("poisoned");
            for r in rows {
                items.push((id, r.clone()));
            }
            Ok(())
        }
        async fn patch_item(
            &self,
            t: &TenantId,
            id: Uuid,
            item_id: Uuid,
            expected_output: Option<Option<String>>,
            metadata: Option<String>,
        ) -> Result<bool> {
            self.note(t);
            let mut items = self.items.lock().expect("poisoned");
            let Some((_, i)) = items
                .iter_mut()
                .find(|(d, i)| *d == id && i.item_id == item_id)
            else {
                return Ok(false);
            };
            if let Some(eo) = expected_output {
                i.expected_output = eo;
            }
            if let Some(m) = metadata {
                i.metadata = m;
            }
            Ok(true)
        }
        async fn delete_item(&self, t: &TenantId, id: Uuid, item_id: Uuid) -> Result<bool> {
            self.note(t);
            let mut items = self.items.lock().expect("poisoned");
            let before = items.len();
            items.retain(|(d, i)| !(*d == id && i.item_id == item_id));
            Ok(before != items.len())
        }
        async fn span_content(
            &self,
            t: &TenantId,
            _trace: &str,
            _span: &str,
        ) -> Result<Option<SpanContentRow>> {
            self.note(t);
            Ok(None)
        }
        // EVL-29 R228. Minimal, matching this mock's own `span_content`, which
        // also returns `Ok(None)`: MockStore exists to assert that every store
        // call carries the tenant, not to simulate ClickHouse. The real
        // behaviour of these four is covered against a live database by
        // `scripts/ci/run-clickhouse-integration.sh`, which is the only place
        // that can prove a RowBinary column mapping.
        async fn content_span_id(&self, t: &TenantId, _trace: &str) -> Result<Option<String>> {
            self.note(t);
            Ok(None)
        }
        async fn snapshot_content(
            &self,
            t: &TenantId,
            _trace: &str,
            _span: &str,
            _input: &str,
            _system: &str,
            _hash: &str,
        ) -> Result<()> {
            self.note(t);
            Ok(())
        }
        async fn read_snapshot(
            &self,
            t: &TenantId,
            _trace: &str,
            _span: &str,
        ) -> Result<Option<SpanContentRow>> {
            self.note(t);
            Ok(None)
        }
        async fn snapshotted_trace_ids(
            &self,
            t: &TenantId,
            _trace_ids: &[String],
        ) -> Result<Vec<String>> {
            self.note(t);
            Ok(Vec::new())
        }
        async fn count_snapshots(&self, t: &TenantId, _id: Uuid) -> Result<u64> {
            self.note(t);
            Ok(0)
        }
        async fn snapshot_exists(&self, t: &TenantId, _id: Uuid, _s: Uuid) -> Result<bool> {
            self.note(t);
            Ok(false)
        }
        async fn write_snapshot(
            &self,
            t: &TenantId,
            _id: Uuid,
            _s: Uuid,
            _actor: &str,
            _items: &[DatasetItem],
        ) -> Result<()> {
            self.note(t);
            Ok(())
        }
        async fn list_snapshots(&self, t: &TenantId, _id: Uuid) -> Result<Vec<Snapshot>> {
            self.note(t);
            Ok(Vec::new())
        }
    }

    /// Every store call carries the tenant from the validated claim. The seam is
    /// the only place a tenant id can enter a query, so this is the structural
    /// half of isolation; the SQL half is the `WHERE tenant_id = ?` bind in
    /// every statement above.
    /// `EVL-30` / R249 — the exact-name filter must NARROW, and must not be a
    /// way around the tenant filter.
    ///
    /// **Why this exists at all:** the listing is keyset-paginated at
    /// `PAGE_MAX = 200`, so a CLI resolving `--dataset <name>` by reading one
    /// page finds it only if it is in the newest 200. On a workspace where it
    /// is not, the gate says "no dataset named …" about a dataset that plainly
    /// exists — a wrong answer manufactured by a paging boundary.
    ///
    /// The assertion is that the filter SELECTS, not merely that the call
    /// succeeds: `None` returns both rows and `Some("beta")` returns exactly
    /// one. A filter that silently did nothing would pass a call-succeeded test.
    #[tokio::test]
    async fn dataset_name_filter_narrows_and_stays_tenant_scoped() {
        let s = MockStore::default();
        let t = tenant();
        for (n, name) in [(11u128, "alpha"), (12u128, "beta")] {
            s.create_dataset(
                &t,
                &Dataset {
                    dataset_id: Uuid::from_u128(n),
                    name: name.into(),
                    description: String::new(),
                    created_at_ms: 1,
                    created_by: "u".into(),
                    updated_at_ms: 1,
                },
            )
            .await
            .expect("create");
        }

        let all = s.list_datasets(&t, None, 10, None).await.expect("list all");
        assert_eq!(all.len(), 2, "unfiltered listing should return both");

        let one = s
            .list_datasets(&t, None, 10, Some("beta"))
            .await
            .expect("list filtered");
        assert_eq!(
            one.len(),
            1,
            "the name filter must NARROW, not pass through"
        );
        assert_eq!(one[0].name, "beta");

        // A name nobody has is an empty list, never an error and never a match.
        let none = s
            .list_datasets(&t, None, 10, Some("gamma"))
            .await
            .expect("list missing");
        assert!(none.is_empty(), "an unknown name must match nothing");

        // The tenant is still the outer filter: every call above recorded the
        // tenant it was asked for, and the filter never replaced it.
        let seen = s.seen_tenant.lock().expect("poisoned").clone();
        assert!(
            seen.iter().all(|x| x == &t.to_string()) && !seen.is_empty(),
            "every call must carry the caller's tenant; the name filter is an \
             ADDITIONAL narrowing, never a replacement for it"
        );
    }

    #[tokio::test]
    async fn every_store_call_is_tenant_scoped() {
        let s = MockStore::default();
        let t = tenant();
        let d = Uuid::from_u128(5);
        s.create_dataset(
            &t,
            &Dataset {
                dataset_id: d,
                name: "x".into(),
                description: String::new(),
                created_at_ms: 1,
                created_by: "u".into(),
                updated_at_ms: 1,
            },
        )
        .await
        .expect("create");
        s.count_datasets(&t).await.expect("count");
        s.list_datasets(&t, None, 10, None).await.expect("list");
        s.get_dataset(&t, d).await.expect("get");
        s.item_stats(&t, d).await.expect("stats");
        s.list_items(&t, d, None, 10).await.expect("items");
        s.find_by_hash(&t, d, "h").await.expect("hash");
        s.span_content(&t, "tr", "sp").await.expect("span");
        s.count_snapshots(&t, d).await.expect("snap count");
        s.snapshot_exists(&t, d, Uuid::nil())
            .await
            .expect("snap ex");
        s.list_snapshots(&t, d).await.expect("snap list");

        let seen = s.seen_tenant.lock().expect("poisoned");
        assert!(seen.len() >= 11, "every call must record a tenant");
        assert!(
            seen.iter().all(|x| *x == t.to_string()),
            "no store call may run without the claim's tenant"
        );
    }

    /// A duplicate is found by hash and the FIRST item wins. Overwriting would
    /// discard a reference someone reviewed, which is why `expected_output` sits
    /// outside the hash.
    #[tokio::test]
    async fn the_same_content_dedupes_to_one_item() {
        let s = MockStore::default();
        let t = tenant();
        let d = Uuid::from_u128(5);
        let mut a = trace_item();
        a.expected_output = Some("reviewed".into());
        s.insert_items(&t, d, std::slice::from_ref(&a))
            .await
            .expect("insert");
        let hit = s.find_by_hash(&t, d, &a.input_hash).await.expect("lookup");
        assert_eq!(hit, Some(a.item_id), "the same input must be recognised");
        assert_eq!(
            s.item_stats(&t, d).await.expect("stats").items,
            1,
            "one row, not two"
        );
    }

    /// The §3 counts are MEASURED. `0 of N` is a measured fact rather than a
    /// blank — it is the number that explains why exact-match scoring is
    /// unavailable, and whitespace-only counts as absent.
    #[tokio::test]
    async fn scorable_with_a_reference_is_counted_not_assumed() {
        let s = MockStore::default();
        let t = tenant();
        let d = Uuid::from_u128(5);
        let mut with_ws = trace_item();
        with_ws.item_id = Uuid::from_u128(8);
        with_ws.expected_output = Some("   ".into());
        s.insert_items(&t, d, &[trace_item(), with_ws])
            .await
            .expect("insert");
        let stats = s.item_stats(&t, d).await.expect("stats");
        assert_eq!(stats.items, 2);
        assert_eq!(stats.with_reference, 0, "0 of 2, measured");
        assert_eq!(stats.from_traces, 2);
    }

    /// The PATCH landing zone flips `0 of N` to `1 of N` — the write-back item
    /// 12's annotation loop needs, proven end-to-end through the seam.
    #[tokio::test]
    async fn patching_a_reference_moves_the_scorable_count() {
        let s = MockStore::default();
        let t = tenant();
        let d = Uuid::from_u128(5);
        let item = trace_item();
        s.insert_items(&t, d, std::slice::from_ref(&item))
            .await
            .expect("insert");
        assert_eq!(s.item_stats(&t, d).await.expect("stats").with_reference, 0);
        assert!(
            s.patch_item(&t, d, item.item_id, Some(Some("TRANSFER".into())), None)
                .await
                .expect("patch")
        );
        assert_eq!(s.item_stats(&t, d).await.expect("stats").with_reference, 1);
    }

    /// Patching an item that is not this tenant's / not in this dataset reports
    /// `false`, which the handler turns into the shared 404 — never a silent
    /// success.
    #[tokio::test]
    async fn patching_an_unknown_item_reports_not_found() {
        let s = MockStore::default();
        assert!(
            !s.patch_item(
                &tenant(),
                Uuid::from_u128(5),
                Uuid::from_u128(999),
                Some(Some("x".into())),
                None
            )
            .await
            .expect("patch")
        );
    }
}
