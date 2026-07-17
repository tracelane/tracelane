//! Customer-facing audit-log export endpoint.
//!
//! GET /v1/audit/export?since=<iso8601>&until=<iso8601>&limit=<u32>
//!
//! Streams NDJSON rows from `tracelane.audit_log` filtered by the
//! requesting tenant + time range. Each line is a JSON object with the
//! exact field set the three reference verifiers (Rust / Python / TS)
//! consume — `format, tenant_id, seq, event_time, event_type, actor,
//! payload, prev_hash, row_hash, rekor_entry_id`. Customers run
//! `tlane verify` over the downloaded NDJSON to prove their own audit
//! chain is intact.
//!
//!
//! `payload` is emitted as the **verbatim stored canonical JSON string**
//! (the exact `row_hash` preimage the writer hashed at append time —
//! `audit.rs` stores `canonical_payload(...)` in the `payload` column,
//! `audit_format::row_hash_v2` hashes that same string). We do **not**
//! re-parse it into a JSON object here: re-deriving the canonical form on
//! (JS `JSON.parse`/`stringify` is lossy — `1.0→1`, `>2^53` loses
//! precision, `1e2→100`, `0.50→0.5`). Every verifier now SHA-256s the
//! stored bytes directly; parity is true by construction.
//!
//! Each row carries an explicit `format: "v2.1"` marker (never
//! type-sniffing). Legacy `v2` exports (payload as a nested object, no
//! marker) still verify under the verifiers' read-only re-canonicalize
//! path — the documented lossy limitation of the old format.
//!
//! Auth: `Authorization: Bearer <jwt|tlane_apikey>` (same as everywhere).
//! Tenant id NEVER from request body or query — only from a verified
//! claim (CLAUDE.md invariant).
//!
//!
//! The tamper-evident export is a **paid** capability — the $999/mo Audit
//! SKU (`FeatureKey::AuditAddon`). After the tenant is resolved from the
//! validated claim (the org_id→tenant seam lives in `auth`), the handler
//! checks `entitlement_cache.check(tenant, AuditAddon)` (plan defaults
//! overlaid by workspace overrides, deny-overrides-grant — never a
//! tier-string compare). An unentitled key gets a typed `403
//! entitlement_required` with an upgrade pointer and **zero ledger bytes**
//! — the check runs BEFORE any ClickHouse read. Fail **closed**: if the
//! entitlement cache is absent (no Postgres), the export is refused (503).
//!
//! Limits:
//!   - default limit 1000 rows
//!   - hard cap 50_000 rows per call (caller paginates via `since`
//!     advancing past the last seq's event_time)
//!   - request fails fast if since > until
//!
//! Production wiring is gated on CLICKHOUSE_URL: without it the route
//! returns 503. Tests use a `MockExportReader` that yields fixed rows.

use anyhow::{Context as _, Result};
use axum::{
    Json, Router,
    body::Body,
    extract::{Query, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::get,
};
use chrono::{DateTime, Utc};
use clickhouse::Client as ClickhouseClient;
use futures::stream::{self, StreamExt as _};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracelane_shared::TenantId;

const DEFAULT_LIMIT: u32 = 1000;
const MAX_LIMIT: u32 = 50_000;

/// Export wire-format marker (ADR-050). `v2.1` = `payload` is the verbatim
/// stored canonical JSON string; verifiers hash it byte-for-byte, never
/// re-derive. Bumped from the implicit `v2` (payload as a nested object).
pub const EXPORT_FORMAT: &str = "v2.1";

/// One exported row — wire-compatible with `verifier_rust::AuditRow`.
///
/// `payload` is the **verbatim canonical JSON string** stored in the
/// `payload` column (the `row_hash` preimage), NOT a re-parsed object —
/// see the module docs and ADR-050. `format` self-describes each row so
/// verifiers branch explicitly instead of type-sniffing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportRow {
    /// Wire-format marker; always [`EXPORT_FORMAT`] (`"v2.1"`) for new exports.
    pub format: String,
    pub tenant_id: String,
    pub seq: u64,
    pub event_time: String,
    pub event_type: String,
    pub actor: String,
    /// Verbatim canonical JSON string (the exact `row_hash` preimage).
    pub payload: String,
    pub prev_hash: String,
    pub row_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rekor_entry_id: Option<String>,
}

/// One exported ANCHOR record (ADR-062 Amendment 1) — the per-batch offline
/// bundle the three verifiers check. Discriminated from row records by
/// `"type":"anchor"` (row records carry no `type`). The verifier reconstructs the
/// `anchor_commitment` from these fields to check the bound Ed25519 attestation,
/// then (when `rekor` is present) verifies the ECDSA entry sig + RFC6962 inclusion
/// proof + C2SP checkpoint against the pinned log key.
#[derive(Debug, Clone, Serialize)]
pub struct AnchorExportRecord {
    #[serde(rename = "type")]
    pub kind: &'static str,
    pub tenant_id: String,
    pub batch_start_seq: u64,
    pub batch_end_seq: u64,
    pub merkle_root: String,
    /// `anchored` | `unanchored` — must match the byte the Ed25519 sig committed to.
    pub anchor_state: String,
    pub ed25519: Ed25519Block,
    /// Present iff `anchor_state == "anchored"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rekor: Option<RekorBlock>,
}

/// The tenant's local attestation. `pubkey` is REFERENCE ONLY — the verifier uses
/// the trusted `--tenant-pubkey` and fails closed on mismatch (ADR-062 C2).
#[derive(Debug, Clone, Serialize)]
pub struct Ed25519Block {
    pub signature: String,
    pub pubkey: String,
}

/// The public-transparency-log bundle (Rekor v2 has no online lookup).
#[derive(Debug, Clone, Serialize)]
pub struct RekorBlock {
    pub log_url: String,
    pub log_index: String,
    pub canonicalized_body: String,
    pub inclusion_proof: serde_json::Value,
    pub checkpoint: CheckpointBlock,
}

#[derive(Debug, Clone, Serialize)]
pub struct CheckpointBlock {
    pub envelope: String,
}

/// Aggregate summary of the ledger for a window — computed in ClickHouse so the
/// total + per-day + per-type breakdown are truthful for a LARGE ledger (never
/// capped at the export row limit). Powers the "About this ledger" panel's
/// temporal breakdown.
#[derive(Debug, Clone, Serialize, Default)]
pub struct AuditSummary {
    /// Total events in the window (the real count, not the loaded-row count).
    pub total: u64,
    /// Earliest / latest event_time in the window (ISO-8601), `None` when empty.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_event: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_event: Option<String>,
    /// Event count per calendar day (ascending) — the temporal distribution.
    pub by_day: Vec<DayCount>,
    /// Event count per event_type (descending) — which audit events are stored.
    pub by_type: Vec<TypeCount>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DayCount {
    /// `YYYY-MM-DD` (UTC).
    pub day: String,
    pub count: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct TypeCount {
    pub event_type: String,
    pub count: u64,
}

/// Read-side hook for the audit_log table. Production swaps in
/// `ClickHouseExportReader`; tests use `MockExportReader`.
#[async_trait::async_trait]
pub trait AuditExportReader: Send + Sync {
    /// Return up to `limit` rows ordered by `seq` ascending. The handler
    /// streams these to the wire as NDJSON.
    async fn read_range(
        &self,
        tenant_id: &TenantId,
        since: DateTime<Utc>,
        until: DateTime<Utc>,
        limit: u32,
    ) -> Result<Vec<ExportRow>>;

    /// Return the per-batch anchor bundles (ADR-062) for the window. Default:
    /// none — dev/mock readers without an `audit_anchor_records` table export
    /// chain rows only (the hash chain still verifies; anchors are absent).
    async fn read_anchor_records(
        &self,
        _tenant_id: &TenantId,
        _since: DateTime<Utc>,
        _until: DateTime<Utc>,
        _limit: u32,
    ) -> Result<Vec<AnchorExportRecord>> {
        Ok(Vec::new())
    }

    /// Aggregate the window into totals + per-day + per-type counts. Default: an
    /// empty summary (dev/mock readers report no aggregate). The ClickHouse impl
    /// GROUP BYs so the counts are exact for any ledger size.
    async fn summarize(
        &self,
        _tenant_id: &TenantId,
        _since: DateTime<Utc>,
        _until: DateTime<Utc>,
    ) -> Result<AuditSummary> {
        Ok(AuditSummary::default())
    }
}

/// ClickHouse-backed reader. Issues a single `SELECT ... ORDER BY seq
/// LIMIT ?` against `tracelane.audit_log`.
pub struct ClickHouseExportReader {
    client: ClickhouseClient,
}

impl ClickHouseExportReader {
    pub fn new(client: ClickhouseClient) -> Self {
        Self { client }
    }
}

// `clickhouse::Row` (RowBinary), so `seq` / the batch seqs come back as REAL u64
// integers and serde emits them to the verifier NDJSON as JSON NUMBERS. A
// ClickHouse `FORMAT JSONEachRow` read instead quotes UInt64 as STRINGS by
// default, and the verifier's `seq + 1` then does string concatenation ("0"+1 →
// "01") → a false `seq_out_of_order` RED (and, if a hash encoding ever changed,
// potentially a false GREEN — the same "serialization lies about integrity"
// pin `SETTINGS output_format_json_quote_64bit_integers = 0` explicitly.
#[derive(Debug, Deserialize, clickhouse::Row)]
struct AuditLogRow {
    tenant_id: String,
    seq: u64,
    event_time: i64, // microseconds since Unix epoch
    event_type: String,
    actor: String,
    payload: String,
    prev_hash: String,
    row_hash: String,
    rekor_entry_id: Option<String>,
}

/// Deserialization shape for `audit_anchor_records` (ADR-062). `inclusion_proof`
/// is a JSON string in ClickHouse; it is re-parsed to a `Value` for the export.
#[derive(Debug, Deserialize, clickhouse::Row)]
struct AuditAnchorRow {
    tenant_id: String,
    batch_start_seq: u64,
    batch_end_seq: u64,
    merkle_root: String,
    anchor_state: String,
    ed25519_sig: String,
    ed25519_pubkey: String,
    rekor_log_url: String,
    rekor_log_index: String,
    canonicalized_body: String,
    inclusion_proof: String,
    checkpoint_envelope: String,
}

#[async_trait::async_trait]
impl AuditExportReader for ClickHouseExportReader {
    async fn read_range(
        &self,
        tenant_id: &TenantId,
        since: DateTime<Utc>,
        until: DateTime<Utc>,
        limit: u32,
    ) -> Result<Vec<ExportRow>> {
        let since_us = since.timestamp_micros();
        let until_us = until.timestamp_micros();
        let limit = limit.clamp(1, MAX_LIMIT);

        // ADR-031 V1.1 sweep: audit-log export is bounded per-tenant +
        // time-windowed; per-tier resource caps would be additive. The
        // V1.1 sweep routes through TenantQuery so the export command
        // inherits the tier-derived 10s/30s/60s/300s execution caps.
        // Exempted in `scripts/ci/no-raw-ch-query.sh`.
        let rows = self
            .client
            .query(
                // The output alias MUST differ from the column name: aliasing
                // `toUnixTimestamp64Micro(event_time) AS event_time` makes the
                // WHERE's `toUnixTimestamp64Micro(event_time)` resolve `event_time`
                // to the Int64 alias → `toUnixTimestamp64Micro(Int64)` → Code 43
                // ILLEGAL_TYPE_OF_ARGUMENT (the same alias-collision class as
                // mv_trace_summaries). `event_time_us` keeps the WHERE on the
                // DateTime64 column. Row deserialization is positional, so the
                // alias name does not affect `AuditLogRow`.
                // ADR-065 GATE 1: `FINAL` collapses a crash-retry duplicate at
                // the same (tenant_id, seq) to its ReplacingMergeTree version
                // winner (latest event_time) on an UN-MERGED table, so the
                // orphan is never exported and the verifier's strict
                // consecutive-seq walk stays clean. The race window is BEFORE
                // the background merge — FINAL, not a reliance on merge timing.
                "SELECT tenant_id, seq, toUnixTimestamp64Micro(event_time) AS event_time_us, \
                        event_type, actor, payload, prev_hash, row_hash, rekor_entry_id \
                 FROM audit_log FINAL \
                 WHERE tenant_id = ? \
                   AND toUnixTimestamp64Micro(event_time) >= ? \
                   AND toUnixTimestamp64Micro(event_time) <= ? \
                 ORDER BY seq ASC \
                 LIMIT ?",
            )
            .bind(tenant_id.to_string())
            .bind(since_us)
            .bind(until_us)
            .bind(limit)
            .fetch_all::<AuditLogRow>()
            .await
            .context("audit_log SELECT failed")?;

        let mut out = Vec::with_capacity(rows.len());
        for r in rows {
            // ADR-050 (v2.1): the `payload` column IS the verbatim canonical
            // JSON string the writer hashed (`row_hash` preimage). Emit it
            // AS-IS — do NOT re-parse into a Value and re-serialize. Re-deriving
            // Every v2 row ever written stored this canonical form, so stamping
            // `v2.1` on all rows is correct — no pre-ADR-050 row is misrepresented.
            out.push(ExportRow {
                format: EXPORT_FORMAT.to_string(),
                tenant_id: r.tenant_id,
                seq: r.seq,
                event_time: micros_to_iso8601(r.event_time),
                event_type: r.event_type,
                actor: r.actor,
                payload: r.payload,
                prev_hash: r.prev_hash,
                row_hash: r.row_hash,
                rekor_entry_id: r.rekor_entry_id,
            });
        }
        Ok(out)
    }

    async fn read_anchor_records(
        &self,
        tenant_id: &TenantId,
        since: DateTime<Utc>,
        until: DateTime<Utc>,
        limit: u32,
    ) -> Result<Vec<AnchorExportRecord>> {
        let since_us = since.timestamp_micros();
        let until_us = until.timestamp_micros();
        let limit = limit.clamp(1, MAX_LIMIT);

        // Bounded per-tenant + time-windowed (mirrors read_range). tenant_id
        // filter present per the CLAUDE.md hard rule. Exempted in no-raw-ch-query.sh.
        let rows = self
            .client
            .query(
                "SELECT tenant_id, batch_start_seq, batch_end_seq, merkle_root, anchor_state, \
                        ed25519_sig, ed25519_pubkey, rekor_log_url, rekor_log_index, \
                        canonicalized_body, inclusion_proof, checkpoint_envelope \
                 FROM audit_anchor_records \
                 WHERE tenant_id = ? \
                   AND toUnixTimestamp64Micro(anchored_at) >= ? \
                   AND toUnixTimestamp64Micro(anchored_at) <= ? \
                 ORDER BY batch_start_seq ASC \
                 LIMIT ?",
            )
            .bind(tenant_id.to_string())
            .bind(since_us)
            .bind(until_us)
            .bind(limit)
            .fetch_all::<AuditAnchorRow>()
            .await
            .context("audit_anchor_records SELECT failed")?;

        let mut out = Vec::with_capacity(rows.len());
        for r in rows {
            let rekor = if r.anchor_state == "anchored" && !r.rekor_log_index.is_empty() {
                Some(RekorBlock {
                    log_url: r.rekor_log_url,
                    log_index: r.rekor_log_index,
                    canonicalized_body: r.canonicalized_body,
                    // Stored as a JSON string; re-parse for the export. A corrupt
                    // blob degrades to Null (the verifier then fails the anchor,
                    // never silently passes).
                    inclusion_proof: serde_json::from_str(&r.inclusion_proof)
                        .unwrap_or(serde_json::Value::Null),
                    checkpoint: CheckpointBlock {
                        envelope: r.checkpoint_envelope,
                    },
                })
            } else {
                None
            };
            out.push(AnchorExportRecord {
                kind: "anchor",
                tenant_id: r.tenant_id,
                batch_start_seq: r.batch_start_seq,
                batch_end_seq: r.batch_end_seq,
                merkle_root: r.merkle_root,
                anchor_state: r.anchor_state,
                ed25519: Ed25519Block {
                    signature: r.ed25519_sig,
                    pubkey: r.ed25519_pubkey,
                },
                rekor,
            });
        }
        Ok(out)
    }

    async fn summarize(
        &self,
        tenant_id: &TenantId,
        since: DateTime<Utc>,
        until: DateTime<Utc>,
    ) -> Result<AuditSummary> {
        let since_us = since.timestamp_micros();
        let until_us = until.timestamp_micros();

        // Totals + span. tenant_id filter present (CLAUDE.md hard rule); the whole
        // file is allow-listed in no-raw-ch-query.sh. `event_time_us` alias avoids
        // the same alias-collision class documented in read_range.
        #[derive(Deserialize, clickhouse::Row)]
        struct Totals {
            total: u64,
            first_us: i64,
            last_us: i64,
        }
        let totals = self
            .client
            .query(
                // FINAL so a crash-retry duplicate (ADR-065) is counted once —
                // the total tracks distinct (tenant_id, seq) rows, not orphans.
                "SELECT count() AS total, \
                        toUnixTimestamp64Micro(min(event_time)) AS first_us, \
                        toUnixTimestamp64Micro(max(event_time)) AS last_us \
                 FROM audit_log FINAL \
                 WHERE tenant_id = ? \
                   AND toUnixTimestamp64Micro(event_time) >= ? \
                   AND toUnixTimestamp64Micro(event_time) <= ?",
            )
            .bind(tenant_id.to_string())
            .bind(since_us)
            .bind(until_us)
            .fetch_one::<Totals>()
            .await
            .context("audit_log summary totals failed")?;

        // Per-day counts (bounded to 400 days for the histogram payload).
        #[derive(Deserialize, clickhouse::Row)]
        struct DayRow {
            day: String,
            c: u64,
        }
        let day_rows = self
            .client
            .query(
                "SELECT toString(toDate(event_time)) AS day, count() AS c \
                 FROM audit_log FINAL \
                 WHERE tenant_id = ? \
                   AND toUnixTimestamp64Micro(event_time) >= ? \
                   AND toUnixTimestamp64Micro(event_time) <= ? \
                 GROUP BY day ORDER BY day ASC LIMIT 400",
            )
            .bind(tenant_id.to_string())
            .bind(since_us)
            .bind(until_us)
            .fetch_all::<DayRow>()
            .await
            .context("audit_log summary by_day failed")?;

        // Per-type counts.
        #[derive(Deserialize, clickhouse::Row)]
        struct TypeRow {
            event_type: String,
            c: u64,
        }
        let type_rows = self
            .client
            .query(
                "SELECT event_type, count() AS c \
                 FROM audit_log FINAL \
                 WHERE tenant_id = ? \
                   AND toUnixTimestamp64Micro(event_time) >= ? \
                   AND toUnixTimestamp64Micro(event_time) <= ? \
                 GROUP BY event_type ORDER BY c DESC LIMIT 50",
            )
            .bind(tenant_id.to_string())
            .bind(since_us)
            .bind(until_us)
            .fetch_all::<TypeRow>()
            .await
            .context("audit_log summary by_type failed")?;

        let (first_event, last_event) = if totals.total == 0 {
            (None, None)
        } else {
            (
                Some(micros_to_iso8601(totals.first_us)),
                Some(micros_to_iso8601(totals.last_us)),
            )
        };
        Ok(AuditSummary {
            total: totals.total,
            first_event,
            last_event,
            by_day: day_rows
                .into_iter()
                .map(|r| DayCount {
                    day: r.day,
                    count: r.c,
                })
                .collect(),
            by_type: type_rows
                .into_iter()
                .map(|r| TypeCount {
                    event_type: r.event_type,
                    count: r.c,
                })
                .collect(),
        })
    }
}

fn micros_to_iso8601(micros: i64) -> String {
    let secs = micros.div_euclid(1_000_000);
    let nanos = (micros.rem_euclid(1_000_000) as u32) * 1_000;
    DateTime::<Utc>::from_timestamp(secs, nanos)
        // Force SecondsFormat::Micros so the round-trip via
        // parse_from_rfc3339 -> timestamp_micros recovers the exact
        // input value. chrono's default to_rfc3339() uses AutoSi
        // which can pick fewer than 6 decimal places when the
        // sub-second component is a clean ms multiple, breaking
        // exact-microsecond round-trip.
        .map(|dt| dt.to_rfc3339_opts(chrono::SecondsFormat::Micros, true))
        .unwrap_or_else(|| String::from("1970-01-01T00:00:00.000000Z"))
}

/// Handler state. Held in `AppState`-style separately so the audit
/// route doesn't need the full gateway state.
#[derive(Clone)]
pub struct ExportState {
    pub reader: Arc<dyn AuditExportReader>,
    /// only when Postgres is unset (no entitlement source), in which case
    /// the gate FAILS CLOSED — we won't serve the paid export we can't
    /// verify. In production the cache is always present alongside the
    /// export route.
    pub entitlements: Option<Arc<crate::entitlement_cache::EntitlementCache>>,
}

#[derive(Debug, Deserialize)]
pub struct ExportQuery {
    /// ISO-8601 lower bound (inclusive). Defaults to epoch if absent.
    #[serde(default)]
    since: Option<String>,
    /// ISO-8601 upper bound (inclusive). Defaults to now if absent.
    #[serde(default)]
    until: Option<String>,
    /// Row cap. Default 1000, max 50_000.
    #[serde(default)]
    limit: Option<u32>,
}

/// Plug the export routes into a Router. Mounted only when CLICKHOUSE_URL
/// is set in production.
pub fn routes() -> Router<ExportState> {
    Router::new()
        .route("/v1/audit/export", get(handler))
        .route("/v1/audit/summary", get(summary_handler))
}

/// GET /v1/audit/summary — the aggregate breakdown (total + per-day + per-type)
/// for the window. Same auth + Audit-SKU gate as the export; the aggregation is a
/// ClickHouse GROUP BY, so the counts are exact for a large ledger (the export's
/// row cap does not apply). Returns JSON.
async fn summary_handler(
    State(state): State<ExportState>,
    Query(q): Query<ExportQuery>,
    headers: HeaderMap,
) -> Response {
    // 1. Auth (mirrors the export handler).
    let auth = match headers.get("authorization").and_then(|v| v.to_str().ok()) {
        Some(s) => s.to_owned(),
        None => return error_response(StatusCode::UNAUTHORIZED, "missing Authorization header"),
    };
    let claims = match crate::auth::validate_authorization(&auth).await {
        Ok(c) => c,
        Err(err) => {
            tracing::warn!(error = %err, "audit summary auth failed");
            return error_response(StatusCode::UNAUTHORIZED, "invalid credentials");
        }
    };

    // 2. Audit-SKU entitlement gate — fail closed (identical to export).
    match state.entitlements {
        Some(ref cache) => {
            if !cache
                .check(
                    *claims.tenant_id.as_uuid(),
                    crate::entitlement_cache::FeatureKey::AuditAddon,
                )
                .await
            {
                return entitlement_required_response();
            }
        }
        None => {
            return error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "entitlement verification unavailable",
            );
        }
    }

    // 3. Window (same defaults as export).
    let until = parse_iso(&q.until).unwrap_or_else(Utc::now);
    let since = parse_iso(&q.since).unwrap_or_else(|| Utc::now() - chrono::Duration::days(30));
    if since > until {
        return error_response(StatusCode::BAD_REQUEST, "since > until");
    }

    // 4. Aggregate.
    match state
        .reader
        .summarize(&claims.tenant_id, since, until)
        .await
    {
        Ok(summary) => (StatusCode::OK, Json(summary)).into_response(),
        Err(err) => {
            tracing::error!(error = %err, "audit summary failed");
            error_response(StatusCode::INTERNAL_SERVER_ERROR, "summary failed")
        }
    }
}

/// Axum handler. Streams NDJSON.
async fn handler(
    State(state): State<ExportState>,
    Query(q): Query<ExportQuery>,
    headers: HeaderMap,
) -> Response {
    // 1. Auth — Authorization: Bearer <jwt|tlane_*>
    let auth = match headers.get("authorization").and_then(|v| v.to_str().ok()) {
        Some(s) => s.to_owned(),
        None => return error_response(StatusCode::UNAUTHORIZED, "missing Authorization header"),
    };
    let claims = match crate::auth::validate_authorization(&auth).await {
        Ok(c) => c,
        Err(err) => {
            tracing::warn!(error = %err, "audit export auth failed");
            return error_response(StatusCode::UNAUTHORIZED, "invalid credentials");
        }
    };

    //    already resolved from the validated claim (the org_id→tenant seam is in
    //    `auth`), so the entitlement query only ever sees the internal tenant
    //    UUID — never a raw org_id. This runs BEFORE any ClickHouse read, so an
    //    unentitled key gets zero ledger bytes.
    match state.entitlements {
        Some(ref cache) => {
            if !cache
                .check(
                    *claims.tenant_id.as_uuid(),
                    crate::entitlement_cache::FeatureKey::AuditAddon,
                )
                .await
            {
                tracing::info!(
                    tenant_id = %claims.tenant_id,
                    "audit export denied — tenant lacks the Audit SKU entitlement"
                );
                return entitlement_required_response();
            }
        }
        None => {
            // Fail closed: no entitlement source → refuse the paid export rather
            // than serve a grant we cannot verify.
            tracing::error!("audit export: entitlement cache unavailable (no Postgres) — denying");
            return error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "entitlement verification unavailable",
            );
        }
    }

    // 3. Parse + validate query window.
    let until = parse_iso(&q.until).unwrap_or_else(Utc::now);
    let since = parse_iso(&q.since).unwrap_or_else(|| Utc::now() - chrono::Duration::days(30));
    if since > until {
        return error_response(StatusCode::BAD_REQUEST, "since > until");
    }
    let limit = q
        .limit
        .map(|l| l.clamp(1, MAX_LIMIT))
        .unwrap_or(DEFAULT_LIMIT);

    // 4. Fetch.
    let rows = match state
        .reader
        .read_range(&claims.tenant_id, since, until, limit)
        .await
    {
        Ok(r) => r,
        Err(err) => {
            tracing::error!(error = %err, "audit_log read_range failed");
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "export failed");
        }
    };

    // 4b. Fetch the per-batch anchor bundles (ADR-062). Best-effort: a failure
    //     here must NOT drop the chain export (the hash chain verifies without
    //     anchors), so log and continue with rows only.
    let anchors = match state
        .reader
        .read_anchor_records(&claims.tenant_id, since, until, limit)
        .await
    {
        Ok(a) => a,
        Err(err) => {
            tracing::warn!(
                error = %err,
                "audit_anchor_records read failed — exporting chain rows only"
            );
            Vec::new()
        }
    };

    // 5. Stream NDJSON: chain rows, then anchor records. One record per line.
    let row_lines = rows.into_iter().map(|row| serde_json::to_string(&row));
    let anchor_lines = anchors.into_iter().map(|a| serde_json::to_string(&a));
    let lines = row_lines.chain(anchor_lines).map(|res| match res {
        Ok(json) => Ok::<_, std::convert::Infallible>(format!("{json}\n").into_bytes()),
        Err(_) => Ok(Vec::new()), // drop a malformed record, keep streaming
    });
    let body = Body::from_stream(stream::iter(lines).map(|r| r.map(bytes::Bytes::from)));

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/x-ndjson")
        .header(
            header::CONTENT_DISPOSITION,
            format!(
                "attachment; filename=\"tracelane-audit-{}.ndjson\"",
                claims.tenant_id
            ),
        )
        .body(body)
        .unwrap_or_else(|_| {
            error_response(StatusCode::INTERNAL_SERVER_ERROR, "response build failed")
        })
}

fn parse_iso(s: &Option<String>) -> Option<DateTime<Utc>> {
    s.as_ref()
        .and_then(|t| DateTime::parse_from_rfc3339(t).ok())
        .map(|dt| dt.with_timezone(&Utc))
}

fn error_response(status: StatusCode, msg: &str) -> Response {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(format!(r#"{{"error":"{msg}"}}"#)))
        .unwrap_or_else(|_| Response::new(Body::empty()))
}

/// error schema (`server.rs::notify_quota_exceeded`): a machine-readable `error`
/// code + human `message` + an `upgrade_url` pointer — never an opaque error.
/// `serde_json` handles escaping (no `format!` string injection).
fn entitlement_required_response() -> Response {
    (
        StatusCode::FORBIDDEN,
        Json(serde_json::json!({
            "error": "entitlement_required",
            "feature": "audit_ledger",
            "message": "The tamper-evident audit ledger export requires the Audit add-on.",
            "upgrade_url": "https://app.tracelane.dev/settings/billing",
        })),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    pub struct MockExportReader {
        pub rows: Vec<ExportRow>,
    }

    #[async_trait::async_trait]
    impl AuditExportReader for MockExportReader {
        async fn read_range(
            &self,
            _tenant_id: &TenantId,
            _since: DateTime<Utc>,
            _until: DateTime<Utc>,
            _limit: u32,
        ) -> Result<Vec<ExportRow>> {
            Ok(self.rows.clone())
        }
    }

    fn fixture_row(seq: u64) -> ExportRow {
        ExportRow {
            format: EXPORT_FORMAT.into(),
            tenant_id: "00000000-0000-0000-0000-000000000001".into(),
            seq,
            event_time: "2026-05-09T10:00:00Z".into(),
            event_type: "chat.completions.request".into(),
            actor: "test-user".into(),
            // Verbatim canonical string (the shape the payload column stores),
            // NOT a nested object — v2.1 (ADR-050).
            payload: r#"{"model":"claude-sonnet-4-6"}"#.into(),
            prev_hash: format!("{seq}-prev"),
            row_hash: format!("{seq}-hash"),
            rekor_entry_id: None,
        }
    }

    #[test]
    fn micros_to_iso8601_round_trips_via_rfc3339() {
        // The contract is exact-microsecond round-trip — we don't care
        // what calendar date the value decodes to as long as
        // parse_from_rfc3339(format(x)) recovers x. (Earlier version of
        // this test asserted a hand-computed date prefix that was
        // wrong; the prefix check has been dropped.)
        for micros in [
            1_778_581_394_123_456_i64,
            0_i64,
            1_000_000_i64,
            999_999_i64,
            1_700_000_000_999_999_i64,
        ] {
            let s = micros_to_iso8601(micros);
            let dt = DateTime::parse_from_rfc3339(&s)
                .unwrap_or_else(|_| panic!("could not parse {s} for input {micros}"));
            assert_eq!(
                dt.timestamp_micros(),
                micros,
                "round-trip failed for {micros}: emitted {s}",
            );
        }
    }

    #[test]
    fn export_row_serializes_with_required_fields() {
        let r = fixture_row(42);
        let s = serde_json::to_string(&r).unwrap();
        assert!(s.contains(r#""seq":42"#));
        assert!(s.contains(r#""row_hash":"42-hash""#));
        assert!(s.contains(r#""prev_hash":"42-prev""#));
        // v2.1 wire format: explicit marker + payload emitted as a JSON
        // STRING (`"payload":"{...`), never a nested object (`"payload":{`).
        assert!(s.contains(r#""format":"v2.1""#));
        assert!(
            s.contains(r#""payload":"{"#),
            "payload must be a verbatim string, got: {s}"
        );
        assert!(
            !s.contains(r#""payload":{"#),
            "payload must NOT be a nested object"
        );
    }

    #[test]
    fn export_row_skips_rekor_when_none() {
        let r = fixture_row(1);
        let s = serde_json::to_string(&r).unwrap();
        // skip_serializing_if = Option::is_none
        assert!(!s.contains("rekor_entry_id"));
    }

    #[test]
    fn export_row_includes_rekor_when_some() {
        let mut r = fixture_row(1);
        r.rekor_entry_id = Some("uuid-12345".into());
        let s = serde_json::to_string(&r).unwrap();
        assert!(s.contains(r#""rekor_entry_id":"uuid-12345""#));
    }

    // ---- ADR-062 anchor export records ---------------------------------

    #[test]
    fn anchor_record_serializes_with_type_discriminator() {
        let a = AnchorExportRecord {
            kind: "anchor",
            tenant_id: "t".into(),
            batch_start_seq: 0,
            batch_end_seq: 99,
            merkle_root: "abc".into(),
            anchor_state: "anchored".into(),
            ed25519: Ed25519Block {
                signature: "sig".into(),
                pubkey: "pk".into(),
            },
            rekor: Some(RekorBlock {
                log_url: "https://log2025-1.rekor.sigstore.dev".into(),
                log_index: "42".into(),
                canonicalized_body: "body".into(),
                inclusion_proof: serde_json::json!({"tree_size":"43"}),
                checkpoint: CheckpointBlock {
                    envelope: "cp".into(),
                },
            }),
        };
        let s = serde_json::to_string(&a).unwrap();
        // The verifier keys off the `type` discriminator (row records have none).
        assert!(s.contains(r#""type":"anchor""#), "{s}");
        assert!(s.contains(r#""anchor_state":"anchored""#));
        assert!(s.contains(r#""log_index":"42""#));
        assert!(s.contains(r#""envelope":"cp""#));
        assert!(s.contains(r#""tree_size":"43""#));
    }

    #[test]
    fn anchor_record_omits_rekor_when_unanchored() {
        let a = AnchorExportRecord {
            kind: "anchor",
            tenant_id: "t".into(),
            batch_start_seq: 0,
            batch_end_seq: 9,
            merkle_root: "abc".into(),
            anchor_state: "unanchored".into(),
            ed25519: Ed25519Block {
                signature: "sig".into(),
                pubkey: "pk".into(),
            },
            rekor: None,
        };
        let s = serde_json::to_string(&a).unwrap();
        assert!(
            !s.contains("rekor"),
            "an unanchored record must omit the rekor block: {s}"
        );
        assert!(s.contains(r#""anchor_state":"unanchored""#));
    }

    #[test]
    fn parse_iso_accepts_valid_rfc3339() {
        let s = Some("2026-05-09T10:00:00Z".to_string());
        let dt = parse_iso(&s).unwrap();
        assert_eq!(dt.to_rfc3339(), "2026-05-09T10:00:00+00:00");
    }

    #[test]
    fn parse_iso_returns_none_on_garbage() {
        let s = Some("not a date".to_string());
        assert!(parse_iso(&s).is_none());
    }

    #[tokio::test]
    async fn mock_reader_returns_seeded_rows() {
        let reader = MockExportReader {
            rows: vec![fixture_row(0), fixture_row(1), fixture_row(2)],
        };
        let tid = TenantId::from_jwt_claim(uuid::Uuid::nil());
        let out = reader
            .read_range(&tid, Utc::now(), Utc::now(), 100)
            .await
            .unwrap();
        assert_eq!(out.len(), 3);
        assert_eq!(out[0].seq, 0);
        assert_eq!(out[2].seq, 2);
    }

    #[tokio::test]
    async fn mock_reader_summarize_defaults_empty() {
        // The mock uses the trait default — an empty summary (no aggregate).
        let reader = MockExportReader {
            rows: vec![fixture_row(0)],
        };
        let tid = TenantId::from_jwt_claim(uuid::Uuid::nil());
        let s = reader
            .summarize(&tid, Utc::now(), Utc::now())
            .await
            .unwrap();
        assert_eq!(s.total, 0);
        assert!(s.first_event.is_none());
        assert!(s.by_day.is_empty());
        assert!(s.by_type.is_empty());
    }

    /// Pin the JSON contract the web "About this ledger" panel reads — the exact
    /// keys + the per-day temporal breakdown (a large ledger: 50 → 200 → 300000).
    #[test]
    fn audit_summary_serializes_to_the_web_contract() {
        let s = AuditSummary {
            total: 300_250,
            first_event: Some("2026-07-11T00:00:00.000000Z".into()),
            last_event: Some("2026-07-13T00:00:00.000000Z".into()),
            by_day: vec![
                DayCount {
                    day: "2026-07-11".into(),
                    count: 50,
                },
                DayCount {
                    day: "2026-07-12".into(),
                    count: 200,
                },
                DayCount {
                    day: "2026-07-13".into(),
                    count: 300_000,
                },
            ],
            by_type: vec![TypeCount {
                event_type: "chat.completions.request".into(),
                count: 300_250,
            }],
        };
        let v = serde_json::to_value(&s).unwrap();
        assert_eq!(v["total"], 300_250);
        assert_eq!(v["by_day"][2]["day"], "2026-07-13");
        assert_eq!(v["by_day"][2]["count"], 300_000);
        assert_eq!(v["by_type"][0]["event_type"], "chat.completions.request");
        // An empty summary omits first/last (skip_serializing_if) — the web treats
        // an absent span as "no events", never a fake epoch date.
        let empty = serde_json::to_value(AuditSummary::default()).unwrap();
        assert!(empty.get("first_event").is_none());
        assert_eq!(empty["total"], 0);
    }

    /// The gateway WRITER's canonicalization must produce byte-for-byte the
    /// exact preimage the three reference verifiers (and the shared
    /// `evals/audit-ledger/boundary-numbers.v2_1.ndjson` vector) expect. If
    /// class. Pins the canonical bytes, genesis seed, and row_hash over the
    /// JS-unsafe number class (`1.0`, `>2^53`, `1e2`, `0.50`).
    #[test]
    fn v2_1_writer_canonicalization_matches_conformance_vector() {
        use crate::audit_format;
        let tenant = TenantId::from_jwt_claim(
            uuid::Uuid::parse_str("00000000-0000-0000-0000-000000000009").unwrap(),
        );
        let payload = serde_json::json!({
            "temperature": 1.0,
            "top_p": 0.50,
            "big_int": 9_007_199_254_740_993_u64, // > 2^53
            "exp": 1e2,
        });
        // The exact bytes the verifiers + the shared vector encode (no drift).
        let canonical =
            audit_format::canonical_payload(&tracelane_policy::pii::redact_json(&payload));
        assert_eq!(
            canonical,
            r#"{"big_int":9007199254740993,"exp":100.0,"temperature":1.0,"top_p":0.5}"#
        );
        let g = audit_format::genesis_prev_hash(&tenant);
        assert_eq!(
            audit_format::hex_encode(&g),
            "48151affc57484ee3bf4d013132e354cab5deb6134599089144f1228da5d7fa5"
        );
        let h0 = audit_format::row_hash_v2(
            &g,
            &tenant,
            0,
            "chat.completions.request",
            "user1",
            &canonical,
        );
        assert_eq!(
            audit_format::hex_encode(&h0),
            "965997278c41ad63099b1179ff5a15031a412041f01cbc4f377cc8b7a852ae15"
        );
    }

    /// End-state proof (offline #2b, real writer + real exporter code): the
    /// exported `payload` is the stored canonical string VERBATIM, it re-hashes
    /// to the stored `row_hash` (so the chain verifies), and a one-digit tamper
    #[test]
    fn v2_1_exported_payload_is_the_verbatim_row_hash_preimage() {
        use crate::audit_format;
        let tenant = TenantId::from_jwt_claim(
            uuid::Uuid::parse_str("00000000-0000-0000-0000-000000000009").unwrap(),
        );
        let payload = serde_json::json!({"temperature": 1.0, "big_int": 9_007_199_254_740_993_u64});
        // The writer canonicalizes ONCE and stores this exact string.
        let canonical = audit_format::canonical_payload(&payload);
        let g = audit_format::genesis_prev_hash(&tenant);
        let h = audit_format::row_hash_v2(&g, &tenant, 0, "request", "u1", &canonical);

        // The exporter maps the stored CH row (payload column = canonical
        // string) to the v2.1 wire row, payload VERBATIM.
        let export = ExportRow {
            format: EXPORT_FORMAT.to_string(),
            tenant_id: tenant.to_string(),
            seq: 0,
            event_time: "2026-05-14T00:00:00.000000Z".into(),
            event_type: "request".into(),
            actor: "u1".into(),
            payload: canonical.clone(),
            prev_hash: audit_format::hex_encode(&g),
            row_hash: audit_format::hex_encode(&h),
            rekor_entry_id: None,
        };
        let line = serde_json::to_string(&export).unwrap();

        // Re-parse as a verifier would: `payload` is a STRING, byte-identical
        // to the stored canonical, and it re-hashes to the stored row_hash.
        let reparsed: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(reparsed["format"], "v2.1");
        let payload_on_wire = reparsed["payload"]
            .as_str()
            .expect("v2.1 payload must be a JSON string, not an object");
        assert_eq!(
            payload_on_wire, canonical,
            "exported payload must be verbatim (no read-path re-derive)"
        );
        let rehash = audit_format::row_hash_v2(&g, &tenant, 0, "request", "u1", payload_on_wire);
        assert_eq!(
            rehash, h,
            "the exported payload IS the row_hash preimage → the chain verifies"
        );

        // A one-digit payload tamper MUST break the hash (tamper-evidence).
        let tampered = payload_on_wire.replace("9007199254740993", "9007199254740992");
        let rehash_tampered = audit_format::row_hash_v2(&g, &tenant, 0, "request", "u1", &tampered);
        assert_ne!(
            rehash_tampered, h,
            "a payload tamper must break the row_hash"
        );
    }

    // ---- ADR-065 GATE 1 — export dedups the crash-retry orphan on an
    //      UN-MERGED ReplacingMergeTree table (the race window is BEFORE the
    //      background merge). Needs a live ClickHouse:
    //        CLICKHOUSE_TEST_URL=http://localhost:8123 cargo test -p gateway \
    //          --bin gateway audit_export::tests::gate1 -- --ignored --nocapture

    /// Insert two rows at the SAME `(tenant_id, seq)` with different `row_hash`
    /// and different `event_time` (later = the version winner), do NOT
    /// `OPTIMIZE`, then read via the production export path
    /// (`ClickHouseExportReader::read_range`, which uses `FINAL`) and assert only
    /// the version winner is returned — the orphan is invisible pre-merge.
    #[tokio::test]
    #[ignore]
    async fn gate1_export_dedups_orphan_on_unmerged_table() {
        let Some(url) = std::env::var("CLICKHOUSE_TEST_URL").ok() else {
            eprintln!("skip gate1: CLICKHOUSE_TEST_URL unset");
            return;
        };
        let ch = ClickhouseClient::default()
            .with_url(&url)
            .with_database("tracelane");
        ch.query("CREATE DATABASE IF NOT EXISTS tracelane")
            .execute()
            .await
            .unwrap();
        for stmt in [
            "DROP TABLE IF EXISTS tracelane.audit_log_pre_rmt",
            "DROP TABLE IF EXISTS tracelane.audit_log_rmt",
            "DROP TABLE IF EXISTS tracelane.audit_log",
            "CREATE TABLE tracelane.audit_log \
             (tenant_id String, seq UInt64, event_time DateTime64(6,'UTC'), \
              event_type String, actor String, payload String DEFAULT '{}', \
              prev_hash String DEFAULT '', row_hash String, \
              rekor_entry_id Nullable(String), signature String DEFAULT '', \
              signing_pubkey String DEFAULT '') \
             ENGINE = ReplacingMergeTree(event_time) \
             PARTITION BY toYYYYMM(event_time) ORDER BY (tenant_id, seq) \
             SETTINGS index_granularity = 8192",
        ] {
            ch.query(stmt).execute().await.unwrap();
        }

        let tenant = TenantId::from_jwt_claim(uuid::Uuid::new_v4());

        #[derive(serde::Serialize, clickhouse::Row)]
        struct InsertRow {
            tenant_id: String,
            seq: u64,
            event_time: i64,
            event_type: String,
            actor: String,
            payload: String,
            prev_hash: String,
            row_hash: String,
            rekor_entry_id: Option<String>,
            signature: String,
            signing_pubkey: String,
        }
        let base_us = Utc::now().timestamp_micros();
        let mk = |row_hash: &str, event_time: i64| InsertRow {
            tenant_id: tenant.to_string(),
            seq: 0,
            event_time,
            event_type: "chat.completions.request".into(),
            actor: "u".into(),
            payload: "{}".into(),
            prev_hash: String::new(),
            row_hash: row_hash.into(),
            rekor_entry_id: None,
            signature: String::new(),
            signing_pubkey: String::new(),
        };
        // Insert the ORPHAN first (earlier event_time), the CANONICAL second
        // (later event_time = the version winner). Two separate inserts so they
        // land in different parts and are NOT merged.
        let orphan = "a".repeat(64);
        let canonical = "b".repeat(64);
        {
            let mut ins = ch.insert("audit_log").unwrap();
            ins.write(&mk(&orphan, base_us)).await.unwrap();
            ins.end().await.unwrap();
        }
        {
            let mut ins = ch.insert("audit_log").unwrap();
            ins.write(&mk(&canonical, base_us + 1)).await.unwrap();
            ins.end().await.unwrap();
        }

        // Sanity: on the RAW table both rows exist (we did NOT OPTIMIZE).
        let raw: u64 = ch
            .query("SELECT count() FROM audit_log WHERE tenant_id = ?")
            .bind(tenant.to_string())
            .fetch_one()
            .await
            .unwrap();
        assert_eq!(
            raw, 2,
            "pre-condition: both rows present on the un-merged table"
        );

        // The production export path must return only the version winner.
        let reader = super::ClickHouseExportReader::new(ch.clone());
        let since = DateTime::<Utc>::from_timestamp(0, 0).unwrap();
        let until = Utc::now() + chrono::Duration::days(1);
        let rows = reader.read_range(&tenant, since, until, 100).await.unwrap();
        assert_eq!(
            rows.len(),
            1,
            "export must dedup the orphan on an UN-MERGED table (FINAL)"
        );
        assert_eq!(
            rows[0].row_hash, canonical,
            "the version winner (latest event_time) must be the one exported"
        );
    }

    //
    // Drives the REAL handler (auth → entitlement gate → response) via the
    // `tlane_` dev-stub auth path (debug-only: active when there is no global
    // Postgres pool + WORKOS_CLIENT_ID is unset). These prove the observable
    // end-state, not that middleware exists.
    #[cfg(debug_assertions)]
    mod entitlement_gate {
        use super::super::{ExportQuery, ExportState, handler};
        use super::{MockExportReader, fixture_row};
        use crate::entitlement_cache::{EntitlementCache, ResolvedEntitlements};
        use axum::extract::{Query, State};
        use axum::http::{HeaderMap, StatusCode};
        use std::pin::Pin;
        use std::sync::Arc;

        // Env is process-global; serialize these tests + the dev-stub env twiddle.
        static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

        fn rt() -> tokio::runtime::Runtime {
            tokio::runtime::Runtime::new().unwrap()
        }

        /// Enables the debug `tlane_` dev-stub auth path (no WorkOS, dev-auth on)
        /// and restores the prior env on drop so it can't leak across tests.
        struct DevAuthEnv {
            client: Option<String>,
            dev: Option<String>,
        }
        impl DevAuthEnv {
            fn enable() -> Self {
                let client = std::env::var("WORKOS_CLIENT_ID").ok();
                let dev = std::env::var("TRACELANE_DEV_AUTH").ok();
                unsafe {
                    std::env::remove_var("WORKOS_CLIENT_ID");
                    std::env::remove_var("TRACELANE_DEV_AUTH");
                }
                Self { client, dev }
            }
        }
        impl Drop for DevAuthEnv {
            fn drop(&mut self) {
                unsafe {
                    match &self.client {
                        Some(v) => std::env::set_var("WORKOS_CLIENT_ID", v),
                        None => std::env::remove_var("WORKOS_CLIENT_ID"),
                    }
                    match &self.dev {
                        Some(v) => std::env::set_var("TRACELANE_DEV_AUTH", v),
                        None => std::env::remove_var("TRACELANE_DEV_AUTH"),
                    }
                }
            }
        }

        /// A cache that resolves EVERY tenant to a fixed `f_audit_addon` grant.
        fn fixed_entitlement(f_audit_addon: bool) -> Arc<EntitlementCache> {
            Arc::new(EntitlementCache::new(Arc::new(
                move |_tenant: uuid::Uuid| {
                    Box::pin(async move {
                        Ok(ResolvedEntitlements {
                            f_audit_addon,
                            ..ResolvedEntitlements::deny_all()
                        })
                    })
                        as Pin<
                            Box<
                                dyn std::future::Future<
                                        Output = anyhow::Result<ResolvedEntitlements>,
                                    > + Send,
                            >,
                        >
                },
            )))
        }

        /// Drive the handler with an authenticated `tlane_` key. Returns
        /// `(status, body_text)`.
        async fn call_export(entitlements: Option<Arc<EntitlementCache>>) -> (StatusCode, String) {
            let state = ExportState {
                reader: Arc::new(MockExportReader {
                    rows: vec![fixture_row(0), fixture_row(1)],
                }),
                entitlements,
            };
            let query = ExportQuery {
                since: None,
                until: None,
                limit: None,
            };
            let mut headers = HeaderMap::new();
            headers.insert(
                "authorization",
                "Bearer tlane_b073gateconftestkey0123456789"
                    .parse()
                    .unwrap(),
            );
            let resp = handler(State(state), Query(query), headers).await;
            let status = resp.status();
            let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
                .await
                .unwrap();
            (status, String::from_utf8_lossy(&bytes).into_owned())
        }

        // WITHOUT the Audit SKU must get 403 + ZERO ledger bytes, not the export.
        #[test]
        fn tlane_key_without_audit_entitlement_gets_403_and_zero_ledger_bytes() {
            let _g = ENV_LOCK.lock().expect("env lock");
            let _env = DevAuthEnv::enable();
            rt().block_on(async {
                let (status, body) = call_export(Some(fixed_entitlement(false))).await;
                assert_eq!(status, StatusCode::FORBIDDEN, "body: {body}");
                // Typed error code + upgrade pointer — not opaque.
                assert!(body.contains("entitlement_required"), "body: {body}");
                assert!(body.contains("upgrade_url"), "body: {body}");
                // ZERO ledger bytes: no row payload or row_hash leaked.
                assert!(
                    !body.contains("claude-sonnet-4-6"),
                    "paywall leaked ledger payload: {body}"
                );
                assert!(
                    !body.contains("row_hash"),
                    "paywall leaked ledger row_hash: {body}"
                );
            });
        }

        // A key WITH the Audit SKU gets the export bytes.
        #[test]
        fn tlane_key_with_audit_entitlement_gets_the_export() {
            let _g = ENV_LOCK.lock().expect("env lock");
            let _env = DevAuthEnv::enable();
            rt().block_on(async {
                let (status, body) = call_export(Some(fixed_entitlement(true))).await;
                assert_eq!(status, StatusCode::OK, "body: {body}");
                assert!(
                    body.contains("claude-sonnet-4-6"),
                    "entitled export missing ledger payload: {body}"
                );
                assert!(
                    body.contains(r#""format":"v2.1""#),
                    "entitled export missing v2.1 rows: {body}"
                );
            });
        }

        // Fail closed: no entitlement source (no Postgres) → refuse, zero bytes.
        #[test]
        fn missing_entitlement_cache_fails_closed_503_zero_bytes() {
            let _g = ENV_LOCK.lock().expect("env lock");
            let _env = DevAuthEnv::enable();
            rt().block_on(async {
                let (status, body) = call_export(None).await;
                assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "body: {body}");
                assert!(
                    !body.contains("claude-sonnet-4-6"),
                    "fail-closed leaked ledger payload: {body}"
                );
            });
        }
    }
}
