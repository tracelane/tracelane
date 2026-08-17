//! Free-tier audit self-verify endpoint (ADR-066).
//!
//! `GET /v1/audit/self-verify?limit=<u32>`
//!
//! The FREE "see + verify your own chain" surface. It reads the caller's OWN
//! recent audit chain (within their tier's retention window), runs the SAME
//! reference verifier the OSS CLI ships (`tracelane-audit-verifier`) over the
//! exact NDJSON the export would produce, and returns a truthful verdict plus the
//! chain bytes so the browser can render + independently re-verify.
//!
//! This is deliberately distinct from the paid `/v1/audit/export` (the $999
//! Article-12 evidence pack, `FeatureKey::AuditAddon`): self-verify is
//! default-granted on every plan (`FeatureKey::AuditSelfVerify`), scope-floored to
//! the caller's own chain within their retention window, and never produces the
//! formatted, downloadable compliance deliverable. See ADR-066 for the split.
//!
//! ## Tenant isolation (the #1 recurring bug class — 3 prod incidents)
//!
//! The tenant is resolved ONLY from the validated `Authorization` claim
//! (`Claims::tenant_id`, an internal UUID produced by the org_id→tenant bridge in
//! `auth`). The request query has NO `tenant_id` / `since` / `until` fields — the
//! window is derived from the tier's `retention_days`, never from the request. A
//! raw org_id or a body/param tenant_id therefore CANNOT reach the ClickHouse
//! read: every read binds `claims.tenant_id` and the reader's SQL is
//! `WHERE tenant_id = ? ... FINAL`. Enforced structurally + by
//! `scripts/ci/check-tenant-id-provenance.sh`.
//!
//! ## Single verification implementation (constraint 2)
//!
//! We do NOT reimplement verification. The chain is serialized to the identical
//! NDJSON the export streams, then handed to `verify_ledger_reader` — the exact
//! entry point `tlane verify` uses. The server runs the chain-integrity option
//! set (`VerifyOptions::offline()` — no pinned tenant key), so a customer running
//! the OSS verifier over the same bytes with the same options reproduces this
//! verdict byte-for-byte.
//!
//! ## Honest RED / anchor coverage (constraint 3 + ADR-062)
//!
//! The verdict surfaces `hash_chain_valid` (+ the first failing seq/kind),
//! `signatures_valid`, `rekor_anchors_seen/resolved`, `anchors_included`, and
//! `strip_detected` truthfully — a tampered chain returns RED. Anchoring is
//! per-batch and best-effort: an unanchored chain still verifies its hash chain
//! (green), and `rekor_anchors_resolved` / `anchors_included` report the REAL
//! coverage, so the response never implies universal anchoring.

use axum::{
    Json, Router,
    body::Body,
    extract::{Query, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::get,
};
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use std::io::Cursor;
use tracelane_audit_verifier::{VerifyOptions, verify_ledger_reader};

use crate::audit_export::{AnchorExportRecord, EXPORT_FORMAT, ExportRow, ExportState};

/// Keep only anchor records whose EVERY covered seq (`batch_start_seq..=batch_end_seq`)
/// is present in `rows`. The self-verify view is capped at the most-recent `limit`
/// rows, so an anchor committing to OLDER rows outside that window makes the shared
/// verifier report `anchor_rows_missing` — a coverage artifact of the capped view,
/// NOT tampering (the hash chain still verifies GREEN). Filtering keeps CLAIM 2
/// honest: it green-verifies the anchors fully covered here and stays silent on the
/// rest (ADR-062 partial-coverage guard); `tlane verify` over the full exported
/// ledger still checks every anchor. A malformed range (`end < start`) or one with a
/// gap in its covered rows is dropped (can't be fully checked from this bundle).
fn anchors_fully_covered(
    rows: &[ExportRow],
    anchors: Vec<AnchorExportRecord>,
) -> Vec<AnchorExportRecord> {
    // INVARIANT: the self-verify handler is SINGLE-TENANT (rows come from one
    // `tenant` claim — see `handler`), so a bare seq set is safe. If this filter is
    // ever reused on a multi-tenant export, key on `(tenant_id, seq)` before the
    // `loaded.contains` check — an anchor with a spoofed tenant_id must not borrow
    // coverage from another tenant's identical seqs. (Even then the per-tenant
    // lookup in `verify_anchors_offline` catches it as `anchor_rows_missing`, but
    // fail at the filter, not defence-in-depth downstream.)
    let loaded: std::collections::HashSet<u64> = rows.iter().map(|r| r.seq).collect();
    anchors
        .into_iter()
        .filter(|a| {
            a.batch_end_seq >= a.batch_start_seq
                && (a.batch_start_seq..=a.batch_end_seq).all(|s| loaded.contains(&s))
        })
        .collect()
}

/// The single truthful GREEN/RED decision for a self-verify response, pulled out
/// as a pure fn so the exact green condition is testable without a live reader.
///
/// GREEN requires ALL of: an intact hash chain, no signature failure, no strip, a
/// trust root (ADR-070 — genesis present OR a public Rekor anchor inside a
/// retention-windowed view), AND a non-truncated response. `truncated` is true when
/// the verifier saw 0 rows while the ledger holds some in this window (a stripped or
/// broken response) — verifying nothing is never a GREEN pass.
///
/// R53 — THREE values: `green`, `red`, `indeterminate`. Positive evidence of a problem
/// is RED; a window that cannot be rooted is INDETERMINATE (never green, never an
/// accusation). See `self_verify_verdict`.
fn self_verify_verdict(
    hash_chain_valid: bool,
    signatures_valid: bool,
    strip_detected: bool,
    trust_established: bool,
    truncated: bool,
) -> &'static str {
    // R53 — THREE verdicts, because two were a lie in one direction.
    //
    // RED is reserved for POSITIVE EVIDENCE that something is wrong: a recomputed hash
    // that does not match, a signature that does not verify, a proof that is missing, or
    // a response that was cut. Those are unconditional — no window excuses them.
    if !hash_chain_valid || !signatures_valid || strip_detected || truncated {
        return "red";
    }
    // Everything checkable PASSED and the only thing missing is a trust root for this
    // window — because `anchors_fully_covered` removed every anchor whose covered seqs
    // fall outside it. Measured on prod 2026-08-15: at `?limit=10` all 161 of
    // a4037bef's anchors were dropped and this returned RED for a fully intact ledger.
    //
    // That is CLAUDE.md §14 read in reverse. The rule says "I cannot see" is never
    // "nothing is wrong"; its converse binds just as hard — "I cannot see" is never
    // "something IS wrong" either. Telling a customer their tamper-evident ledger failed
    // verification, when all we did was look at too narrow a slice of it, is worse than
    // any false green: a customer acting on it escalates, to us or to their auditor.
    //
    // NOT A ROLLBACK OF ADR-070. That ADR's property was "an unrooted window is never
    // GREEN", and `indeterminate` is not green. This RECLASSIFIES the same state; it
    // does not re-admit it to the pass bucket.
    if !trust_established {
        return "indeterminate";
    }
    "green"
}

/// Default chain-row cap when the caller does not pass `?limit=`.
const DEFAULT_LIMIT: u32 = 1000;
/// Hard row cap per call (mirrors the export). The free surface is bounded.
const MAX_LIMIT: u32 = 50_000;
/// Retention-window floor used when the resolved `retention_days` is missing or
/// non-positive (the free-tier floor — ADR-020 `free_v1`).
const RETENTION_FLOOR_DAYS: i64 = 7;

/// Query params — `limit` ONLY. There is intentionally NO `tenant_id`, `since`,
/// or `until` field: the tenant comes from the validated claim and the window
/// from entitlements, so a request-supplied tenant/window cannot influence the
/// read. Unknown params (e.g. an injected `?tenant_id=`) are ignored by serde,
/// never used for tenancy.
#[derive(Debug, Deserialize)]
pub struct SelfVerifyQuery {
    #[serde(default)]
    limit: Option<u32>,
}

/// The verification window actually used (derived, not request-supplied).
#[derive(Debug, Clone, Serialize)]
pub struct SelfVerifyWindow {
    /// ISO-8601 lower bound = `until - retention_days`.
    pub since: String,
    /// ISO-8601 upper bound = now.
    pub until: String,
    /// The tier's trace-retention window used to bound the read.
    pub retention_days: i32,
}

/// The first detected chain break, surfaced so a RED verdict is actionable
/// (constraint 3). `None` on a GREEN chain.
#[derive(Debug, Clone, Serialize)]
pub struct SelfVerifyFailure {
    /// The failing row's `seq`, when the failure is row-scoped.
    pub seq: Option<u64>,
    /// Machine-readable failure kind (e.g. `row_hash_mismatch`, `anchor_stripped`).
    pub kind: String,
    pub detail: String,
}

/// The self-verify verdict returned to the caller. Mirrors the verifier's
/// `VerifyReport` fields verbatim (never a swallowed always-green boolean).
#[derive(Debug, Clone, Serialize)]
pub struct SelfVerifyResponse {
    pub tenant_id: String,
    /// Always `"v2.1"` (the export wire format).
    pub format: &'static str,
    pub window: SelfVerifyWindow,
    /// Chain rows the server verified (== the verifier's `rows_seen`). Capped at
    /// the render limit — NOT the ledger size; see `total_in_window`.
    pub rows_verified: u64,
    /// EXACT uncapped count of chain rows in the window (a cheap `count()`), so the
    /// UI can say "Showing {rows_verified} of {total_in_window}" honestly instead
    /// of letting the loaded cap read as the whole ledger. Always ≥ `rows_verified`.
    pub total_in_window: u64,
    /// `"green"` iff `hash_chain_valid && signatures_valid && !strip_detected &&
    /// trust_established` (ADR-070 trust root) AND the response was not truncated
    /// (0 rows verified out of a non-empty ledger). A genesis-rooted unanchored
    /// chain is still GREEN (ADR-062 "unanchored-still-verifies"); a windowed view
    /// with no public anchor, or a truncated one, is RED. See `self_verify_verdict`.
    /// `green` | `red` | `indeterminate` (R53). A consumer that treats anything other
    /// than `green` as an alarm keeps working, but SHOULD distinguish the third value:
    /// `indeterminate` means verification could not be completed over this window, not
    /// that the ledger is bad.
    pub verdict: &'static str,
    pub hash_chain_valid: bool,
    pub signatures_valid: bool,
    /// Anchor batches seen / cryptographically resolved / with a full public
    /// inclusion proof — reported truthfully so we never imply universal
    /// anchoring (ADR-062 per-batch, partial-coverage guards).
    pub rekor_anchors_seen: u64,
    pub rekor_anchors_resolved: u64,
    pub anchors_included: u64,
    /// A batch committed to "anchored" but its bundle is absent (strip/downgrade).
    pub strip_detected: bool,
    /// ADR-070 — the seq the verified scope STARTS at. `0` = full genesis→tip;
    /// `> 0` = a retention-WINDOWED verify rooted at a public Rekor anchor (rows
    /// below it are present-but-unverified). The UI renders the honest scope.
    pub verified_from_seq: u64,
    /// ADR-070 — `false` for a windowed view with no public anchor to root it
    /// (RED, never green). The `verdict` already reflects this.
    pub trust_established: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_failure: Option<SelfVerifyFailure>,
    /// The exact NDJSON the server verified (own chain, retention window). The
    /// browser renders it and re-runs the OSS verifier to reproduce the verdict.
    pub chain_ndjson: String,
}

/// Mount the self-verify route. Shares [`ExportState`] with the export module
/// (same tenant-isolated reader + entitlement cache) but is a DISTINCT route and
/// gate — it never touches `/v1/audit/export`.
pub fn routes() -> Router<ExportState> {
    Router::new().route("/v1/audit/self-verify", get(handler))
}

async fn handler(
    State(state): State<ExportState>,
    Query(q): Query<SelfVerifyQuery>,
    headers: HeaderMap,
) -> Response {
    // 1. Auth — Authorization: Bearer <jwt|tlane_*>. The tenant is resolved from
    //    the validated claim (org_id→tenant bridge in `auth`); the query/body/
    //    headers never feed tenancy.
    let auth = match headers.get("authorization").and_then(|v| v.to_str().ok()) {
        Some(s) => s.to_owned(),
        None => return error_response(StatusCode::UNAUTHORIZED, "missing Authorization header"),
    };
    let claims = match crate::auth::validate_authorization(&auth).await {
        Ok(c) => c,
        Err(err) => {
            tracing::warn!(error = %err, "audit self-verify auth failed");
            return error_response(StatusCode::UNAUTHORIZED, "invalid credentials");
        }
    };

    // A13 scope gate — B-230. An entitlement gate is NOT a scope gate. Until
    // 2026-08-13 the audit ledger was reachable by any authenticated key, so an
    // `ingest`-scoped SDK key (default-on since GWY-41, and the credential most
    // likely to sit in a container image) could read it. `read` is the scope
    // `crates/shared/src/api_scope.rs:47-49` defines for precisely the
    // hand-a-key-to-an-auditor case this surface exists to serve.
    if !claims.allows_scope(crate::auth::scope::Scope::Read) {
        tracing::warn!(sub = %claims.sub, "api key lacks the `read` scope — refusing audit read");
        return error_response(
            StatusCode::FORBIDDEN,
            "this API key is not scoped to read recorded data — it needs the `read` scope",
        );
    }
    let tenant = claims.tenant_id;

    // 2. Entitlement — resolve the full set (we need `retention_days`) and require
    //    the default-TRUE `f_audit_selfverify` grant. Fail CLOSED when there is no
    //    entitlement source (prod always has one alongside this route); a
    //    per-workspace FALSE override (deny-overrides-grant) yields 403.
    let resolved = match state.entitlements {
        Some(ref cache) => cache.resolved(*tenant.as_uuid()).await,
        None => {
            tracing::error!(
                "audit self-verify: entitlement cache unavailable (no Postgres) — denying"
            );
            return error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "entitlement verification unavailable",
            );
        }
    };
    if !resolved.f_audit_selfverify {
        tracing::info!(
            tenant_id = %tenant,
            "audit self-verify denied — f_audit_selfverify disabled for this workspace"
        );
        return self_verify_disabled_response();
    }

    // 3. Window — the caller's OWN chain within their tier's retention window.
    //    Derived from entitlements, NEVER from the request (scope floor).
    let days = if resolved.retention_days > 0 {
        resolved.retention_days as i64
    } else {
        RETENTION_FLOOR_DAYS
    };
    let until = Utc::now();
    let since = until - Duration::days(days);
    let limit = q
        .limit
        .map(|l| l.clamp(1, MAX_LIMIT))
        .unwrap_or(DEFAULT_LIMIT);

    // 4. Read the caller's OWN chain rows + anchor records. The reader binds
    //    `tenant` (= the validated claim) into `WHERE tenant_id = ? ... FINAL`.
    let rows = match state.reader.read_range(&tenant, since, until, limit).await {
        Ok(r) => r,
        Err(err) => {
            tracing::error!(error = %err, "audit self-verify read_range failed");
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "self-verify read failed");
        }
    };
    // Anchor records are best-effort: their absence must not drop the chain
    // verification (an unanchored chain still verifies — ADR-062).
    let anchors = match state
        .reader
        .read_anchor_records(&tenant, since, until, limit)
        .await
    {
        Ok(a) => a,
        Err(err) => {
            tracing::warn!(
                error = %err,
                "audit self-verify anchor read failed — verifying chain rows only"
            );
            Vec::new()
        }
    };

    // Emit ONLY anchors fully covered by the loaded rows: the capped self-verify
    // window must not hand the verifier an anchor whose OLDER covered rows weren't
    // loaded, or it reports `anchor_rows_missing` on an otherwise-intact chain
    // (a coverage false-alarm, not tampering). See `anchors_fully_covered`.
    let anchors = anchors_fully_covered(&rows, anchors);

    // 5. Serialize to the IDENTICAL NDJSON the export streams: chain rows first,
    //    then anchor records, one record per line. A record that fails to
    //    serialize is skipped (mirrors the export streaming) — never a partial
    //    line that would corrupt the verifier's view.
    let mut ndjson = String::new();
    for row in &rows {
        if let Ok(line) = serde_json::to_string(row) {
            ndjson.push_str(&line);
            ndjson.push('\n');
        }
    }
    for a in &anchors {
        if let Ok(line) = serde_json::to_string(a) {
            ndjson.push_str(&line);
            ndjson.push('\n');
        }
    }

    // 6. Pin the tenant's OWN trusted Ed25519 pubkey — the ADR-062 C2 trust root,
    //    the identical key `GET /v1/audit/pubkey` serves as the out-of-band channel
    //    (the gateway is the trust root for its own tenant; the dashboard uses the
    //    same server-side lookup). Pinning it lets the SHARED verifier RESOLVE the
    //    Rekor inclusion proofs on anchored batches (constraint 6 — four-guard
    //    honesty: per-batch, best-effort, partial coverage, unanchored-still-GREEN),
    //    not just the hash chain. A tenant with no audit key (never anchored) gets
    //    a key-less verify and the chain still verifies GREEN. The verdict stays
    //    reproducible: a customer running `tlane verify --tenant-pubkey <their key
    //    from /v1/audit/pubkey>` computes the identical result.
    let tenant_pubkey: Option<[u8; 32]> = async {
        let pool = crate::db::global_pool()?;
        let client = pool.get().await.ok()?;
        let row = client
            .query_opt(
                "SELECT public_key_b64 FROM tenant_audit_keys WHERE tenant_id = $1",
                &[tenant.as_uuid()],
            )
            .await
            .ok()??;
        let b64: String = row.get(0);
        use base64::Engine as _;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(b64.trim())
            .ok()?;
        <[u8; 32]>::try_from(bytes.as_slice()).ok()
    }
    .await;
    let opts = match tenant_pubkey {
        Some(pk) => VerifyOptions::offline().with_tenant_pubkey(pk),
        None => VerifyOptions::offline(),
    };
    let report = match verify_ledger_reader(Cursor::new(ndjson.as_bytes()), "self-verify", &opts) {
        Ok(r) => r,
        Err(err) => {
            // Unreachable for an in-memory Cursor (never errors); fail CLOSED
            // rather than imply a passing verdict on an I/O fault.
            tracing::error!(error = %err, "audit self-verify: verifier I/O error");
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "verification failed");
        }
    };

    // EXACT uncapped count of chain rows in the window, so the UI shows an HONEST
    // total ("Showing N of {total}") instead of letting the loaded cap read as the
    // whole ledger. Falls back to the loaded count if the count query fails (never
    // implies a total smaller than what was loaded). Computed BEFORE the verdict —
    // it also detects a TRUNCATED response (0 rows verified out of a non-empty
    // ledger is an integrity failure, not an empty pass).
    let total_in_window = state
        .reader
        .count_in_range(&tenant, since, until)
        .await
        .unwrap_or(report.rows_seen)
        .max(report.rows_seen);

    // 7. Build the truthful verdict (ADR-070 trust root + truncation guard — see
    //    `self_verify_verdict`). A genesis-rooted unanchored view is still GREEN; a
    //    windowed view with no anchor, or a response that verified 0 of N rows, RED.
    let truncated = report.rows_seen == 0 && total_in_window > 0;
    let verdict = self_verify_verdict(
        report.hash_chain_valid,
        report.signatures_valid,
        report.strip_detected,
        report.trust_established,
        truncated,
    );
    let first_failure = report
        .errors
        .first()
        .map(|e| SelfVerifyFailure {
            seq: e.seq,
            kind: e.kind.clone(),
            detail: e.detail.clone(),
        })
        .or_else(|| {
            // The verifier saw no rows, so it emitted no error — synthesize the
            // truncation reason so the UI shows WHY it is RED, not a blank card.
            truncated.then(|| SelfVerifyFailure {
                seq: None,
                kind: "truncated_ledger".into(),
                detail: format!(
                    "loaded 0 rows but the ledger holds {total_in_window} in this window — response truncated"
                ),
            })
        });

    let body = SelfVerifyResponse {
        tenant_id: tenant.to_string(),
        format: EXPORT_FORMAT,
        window: SelfVerifyWindow {
            since: since.to_rfc3339_opts(chrono::SecondsFormat::Micros, true),
            until: until.to_rfc3339_opts(chrono::SecondsFormat::Micros, true),
            retention_days: days as i32,
        },
        rows_verified: report.rows_seen,
        total_in_window,
        verdict,
        hash_chain_valid: report.hash_chain_valid,
        signatures_valid: report.signatures_valid,
        rekor_anchors_seen: report.rekor_anchors_seen,
        rekor_anchors_resolved: report.rekor_anchors_resolved,
        anchors_included: report.anchors_included,
        strip_detected: report.strip_detected,
        verified_from_seq: report.verified_from_seq,
        trust_established: report.trust_established,
        first_failure,
        chain_ndjson: ndjson,
    };
    (StatusCode::OK, Json(body)).into_response()
}

fn error_response(status: StatusCode, msg: &str) -> Response {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::json!({ "error": msg }).to_string()))
        .unwrap_or_else(|_| Response::new(Body::empty()))
}

/// Typed `403` when a workspace has `f_audit_selfverify = FALSE` (a
/// deny-overrides-grant override of the default-TRUE grant). Not an upsell — the
/// feature is free; it has simply been switched off for this workspace.
fn self_verify_disabled_response() -> Response {
    (
        StatusCode::FORBIDDEN,
        Json(serde_json::json!({
            "error": "feature_disabled",
            "feature": "audit_self_verify",
            "message": "Audit self-verify is disabled for this workspace.",
        })),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit_export::{AuditExportReader, ExportRow};
    use crate::entitlement_cache::{EntitlementCache, ResolvedEntitlements};
    use anyhow::Result;
    use axum::extract::{Query, State};
    use axum::http::{HeaderMap, StatusCode};
    use chrono::{DateTime, Utc};
    use std::collections::HashMap;
    use std::pin::Pin;
    use std::sync::Arc;
    use tracelane_shared::TenantId;

    const TENANT_A: &str = "00000000-0000-0000-0000-000000000001"; // == DEV_TENANT_UUID
    const TENANT_B: &str = "22222222-2222-2222-2222-222222222222";

    // Env is process-global; serialize the dev-stub env twiddle across tests.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn rt() -> tokio::runtime::Runtime {
        tokio::runtime::Runtime::new().unwrap()
    }

    /// Enables the debug `tlane_` dev-stub auth path (no WorkOS, dev-auth on) and
    /// restores the prior env on drop so it cannot leak across tests.
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

    /// A reader that enforces `WHERE tenant_id = ?` in memory: it returns ONLY the
    /// rows seeded for the tenant it is called with. Mirrors the ClickHouse
    /// reader's tenant-scoping so the handler's isolation is testable without a DB.
    struct TenantScopedMockReader {
        rows_by_tenant: HashMap<String, Vec<ExportRow>>,
    }

    #[async_trait::async_trait]
    impl AuditExportReader for TenantScopedMockReader {
        async fn read_range(
            &self,
            tenant_id: &TenantId,
            _since: DateTime<Utc>,
            _until: DateTime<Utc>,
            _limit: u32,
        ) -> Result<Vec<ExportRow>> {
            // The ONLY thing that selects rows is the passed tenant_id (the
            // validated claim). There is no other seam.
            Ok(self
                .rows_by_tenant
                .get(&tenant_id.to_string())
                .cloned()
                .unwrap_or_default())
        }
    }

    /// Build a REAL, hash-valid v2.1 chain of `n` rows for `tenant`. Each row's
    /// `row_hash` is the genuine `audit_format` preimage, so the verifier reports
    /// GREEN. The last row's `row_hash` is returned for a targeted tamper.
    fn healthy_chain(tenant: &TenantId, n: u64, payload_tag: &str) -> Vec<ExportRow> {
        use crate::audit_format;
        let mut prev = audit_format::genesis_prev_hash(tenant);
        let mut out = Vec::with_capacity(n as usize);
        for seq in 0..n {
            let payload = serde_json::json!({ "tag": payload_tag, "seq": seq });
            let canonical = audit_format::canonical_payload(&payload);
            let event_type = "chat.completions.request";
            let actor = "u1";
            let h = audit_format::row_hash_v2(&prev, tenant, seq, event_type, actor, &canonical);
            out.push(ExportRow {
                format: EXPORT_FORMAT.to_string(),
                tenant_id: tenant.to_string(),
                seq,
                event_time: "2026-07-14T00:00:00.000000Z".to_string(),
                event_type: event_type.to_string(),
                actor: actor.to_string(),
                payload: canonical,
                prev_hash: audit_format::hex_encode(&prev),
                row_hash: audit_format::hex_encode(&h),
                rekor_entry_id: None,
            });
            prev = h;
        }
        out
    }

    /// Entitlement cache that resolves EVERY tenant to a fixed `f_audit_selfverify`
    /// grant + a fixed `retention_days`.
    fn fixed_entitlement(selfverify: bool, retention_days: i32) -> Arc<EntitlementCache> {
        Arc::new(EntitlementCache::new(Arc::new(
            move |_tenant: uuid::Uuid| {
                Box::pin(async move {
                    Ok(ResolvedEntitlements {
                        f_audit_selfverify: selfverify,
                        retention_days,
                        ..ResolvedEntitlements::deny_all()
                    })
                })
                    as Pin<
                        Box<
                            dyn std::future::Future<Output = anyhow::Result<ResolvedEntitlements>>
                                + Send,
                        >,
                    >
            },
        )))
    }

    fn dev_key_headers() -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            "authorization",
            "Bearer tlane_selfverifyconftestkey0123456789"
                .parse()
                .unwrap(),
        );
        headers
    }

    /// Drive the real handler and return the parsed response body + status.
    async fn call(
        reader: Arc<dyn AuditExportReader>,
        entitlements: Option<Arc<EntitlementCache>>,
        headers: HeaderMap,
        limit: Option<u32>,
    ) -> (StatusCode, serde_json::Value) {
        let state = ExportState {
            reader,
            entitlements,
        };
        let resp = handler(State(state), Query(SelfVerifyQuery { limit }), headers).await;
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), 8 << 20)
            .await
            .unwrap();
        let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::String(
            String::from_utf8_lossy(&bytes).into_owned(),
        ));
        (status, json)
    }

    // ---- Constraint 1: TENANT ISOLATION (written first) ------------------
    //
    // Tenant A's token must return ZERO of tenant B's rows EVEN WHEN B's
    // tenant_id is injected into every mutable field (query param, header, and a
    // JSON-ish body). The handler resolves the tenant ONLY from the validated
    // claim (= A = DEV_TENANT_UUID), so B's rows are unreachable.
    #[test]
    fn isolation_tenant_a_never_sees_tenant_b_rows_despite_injection() {
        let _g = ENV_LOCK.lock().expect("env lock");
        let _env = DevAuthEnv::enable();
        rt().block_on(async {
            let a = TenantId::from_jwt_claim(uuid::Uuid::parse_str(TENANT_A).unwrap());
            let b = TenantId::from_jwt_claim(uuid::Uuid::parse_str(TENANT_B).unwrap());
            let a_rows = healthy_chain(&a, 3, "TENANT_A_SECRET");
            let b_rows = healthy_chain(&b, 5, "TENANT_B_SECRET");
            let mut map = HashMap::new();
            map.insert(a.to_string(), a_rows);
            map.insert(b.to_string(), b_rows);
            let reader = Arc::new(TenantScopedMockReader {
                rows_by_tenant: map,
            });

            // Inject tenant B into every mutable request field.
            let mut headers = dev_key_headers();
            headers.insert("x-tenant-id", TENANT_B.parse().unwrap());
            headers.insert("x-tracelane-tenant", TENANT_B.parse().unwrap());
            headers.insert("content-type", "application/json".parse().unwrap());

            // The query also carries an injected tenant_id. Build it through the
            // REAL axum extractor from a URI so we prove axum ignores the unknown
            // `tenant_id` param (never a tenancy seam).
            let state = ExportState {
                reader,
                entitlements: Some(fixed_entitlement(true, 7)),
            };
            let uri: axum::http::Uri =
                format!("/v1/audit/self-verify?tenant_id={TENANT_B}&limit=100")
                    .parse()
                    .unwrap();
            let q = Query::<SelfVerifyQuery>::try_from_uri(&uri).unwrap();
            let resp = handler(State(state), q, headers).await;
            assert_eq!(resp.status(), StatusCode::OK);
            let bytes = axum::body::to_bytes(resp.into_body(), 8 << 20)
                .await
                .unwrap();
            let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

            // Verdict is scoped to A.
            assert_eq!(json["tenant_id"], TENANT_A);
            assert_eq!(
                json["rows_verified"], 3,
                "must return A's 3 rows, not B's 5"
            );
            let chain = json["chain_ndjson"].as_str().unwrap();
            assert!(
                chain.contains("TENANT_A_SECRET"),
                "A's own chain must be present"
            );
            assert!(
                !chain.contains("TENANT_B_SECRET"),
                "TENANT ISOLATION BREACH: tenant B's rows leaked into A's self-verify"
            );
            assert!(
                !chain.contains(TENANT_B),
                "tenant B's id must never appear in A's verified chain"
            );
        });
    }

    // ---- Constraint 2: SHARED-VERIFIER byte-for-byte equality ------------
    //
    // The server verdict MUST equal what the customer computes offline with the
    // OSS verifier over the IDENTICAL payload. We take the response's chain
    // bytes, run the file-based `verify_ledger` (the OSS CLI path) over them, and
    // byte-compare the serialized verdict cores.
    #[test]
    fn server_verdict_equals_offline_oss_verifier_byte_for_byte() {
        #[derive(serde::Serialize)]
        struct VerdictCore {
            rows: u64,
            hash_chain_valid: bool,
            signatures_valid: bool,
            rekor_anchors_seen: u64,
            rekor_anchors_resolved: u64,
            anchors_included: u64,
            strip_detected: bool,
        }

        let _g = ENV_LOCK.lock().expect("env lock");
        let _env = DevAuthEnv::enable();
        rt().block_on(async {
            let a = TenantId::from_jwt_claim(uuid::Uuid::parse_str(TENANT_A).unwrap());
            let mut map = HashMap::new();
            map.insert(a.to_string(), healthy_chain(&a, 4, "conformance"));
            let reader = Arc::new(TenantScopedMockReader {
                rows_by_tenant: map,
            });

            let (status, json) = call(
                reader,
                Some(fixed_entitlement(true, 7)),
                dev_key_headers(),
                None,
            )
            .await;
            assert_eq!(status, StatusCode::OK, "body: {json}");

            // Server-reported verdict core.
            let server = VerdictCore {
                rows: json["rows_verified"].as_u64().unwrap(),
                hash_chain_valid: json["hash_chain_valid"].as_bool().unwrap(),
                signatures_valid: json["signatures_valid"].as_bool().unwrap(),
                rekor_anchors_seen: json["rekor_anchors_seen"].as_u64().unwrap(),
                rekor_anchors_resolved: json["rekor_anchors_resolved"].as_u64().unwrap(),
                anchors_included: json["anchors_included"].as_u64().unwrap(),
                strip_detected: json["strip_detected"].as_bool().unwrap(),
            };

            // Offline OSS path: run the SAME reference verifier over the SAME
            // chain bytes. `verify_ledger_reader` IS the single implementation the
            // file-based `verify_ledger` (`tlane verify`) delegates to — the
            // verifier-level `reader_and_file_entries_agree_byte_for_byte` test
            // pins reader==file, so this chains to the OSS CLI path exactly.
            let chain = json["chain_ndjson"].as_str().unwrap();
            let offline = verify_ledger_reader(
                Cursor::new(chain.as_bytes()),
                "offline",
                &VerifyOptions::offline(),
            )
            .unwrap();
            let offline_core = VerdictCore {
                rows: offline.rows_seen,
                hash_chain_valid: offline.hash_chain_valid,
                signatures_valid: offline.signatures_valid,
                rekor_anchors_seen: offline.rekor_anchors_seen,
                rekor_anchors_resolved: offline.rekor_anchors_resolved,
                anchors_included: offline.anchors_included,
                strip_detected: offline.strip_detected,
            };

            assert_eq!(
                serde_json::to_string(&server).unwrap(),
                serde_json::to_string(&offline_core).unwrap(),
                "server self-verify verdict diverged from the offline OSS verifier"
            );
            // And it must be GREEN for a healthy chain.
            assert_eq!(json["verdict"], "green");
        });
    }

    // ---- Constraint 3: honest GREEN and RED -----------------------------

    #[test]
    fn self_verify_verdict_green_only_when_all_hold() {
        // GREEN requires the full conjunction; flipping ANY input to the bad value
        // must yield RED. Negative cases first (.claude/rules/testing.md).
        assert_eq!(
            self_verify_verdict(false, true, false, true, false),
            "red",
            "broken hash chain"
        );
        assert_eq!(
            self_verify_verdict(true, false, false, true, false),
            "red",
            "signature failure"
        );
        assert_eq!(
            self_verify_verdict(true, true, true, true, false),
            "red",
            "strip detected"
        );
        // R53 — THE RECLASSIFICATION, asserted rather than described. This case used
        // to be "red" and is now "indeterminate". Everything checkable passed; the only
        // absent thing is a trust root for this window.
        assert_eq!(
            self_verify_verdict(true, true, false, false, false),
            "indeterminate",
            "unrooted window: cannot verify is NOT verification failed"
        );
        // ADR-070's property SURVIVES — it said an unrooted window is never GREEN, and
        // it still is not. Reclassified, not reversed; assert the half that binds.
        assert_ne!(
            self_verify_verdict(true, true, false, false, false),
            "green",
            "an unrooted window must never be green (ADR-070)"
        );
        // And a REAL problem inside an unrooted window is still RED — positive evidence
        // outranks the window every time, so `indeterminate` can never mask a defect.
        assert_eq!(
            self_verify_verdict(false, true, false, false, false),
            "red",
            "broken chain in an unrooted window is RED, not indeterminate"
        );
        assert_eq!(
            self_verify_verdict(true, true, true, false, false),
            "red",
            "strip in an unrooted window is RED, not indeterminate"
        );
        assert_eq!(
            self_verify_verdict(true, true, false, true, true),
            "red",
            "truncated: 0 rows verified out of a non-empty ledger"
        );
        assert_eq!(
            self_verify_verdict(true, true, false, true, false),
            "green",
            "all invariants hold"
        );
    }

    #[test]
    fn healthy_chain_is_green() {
        let _g = ENV_LOCK.lock().expect("env lock");
        let _env = DevAuthEnv::enable();
        rt().block_on(async {
            let a = TenantId::from_jwt_claim(uuid::Uuid::parse_str(TENANT_A).unwrap());
            let mut map = HashMap::new();
            map.insert(a.to_string(), healthy_chain(&a, 3, "ok"));
            let reader = Arc::new(TenantScopedMockReader {
                rows_by_tenant: map,
            });
            let (status, json) = call(
                reader,
                Some(fixed_entitlement(true, 7)),
                dev_key_headers(),
                None,
            )
            .await;
            assert_eq!(status, StatusCode::OK, "body: {json}");
            assert_eq!(json["verdict"], "green");
            assert_eq!(json["hash_chain_valid"], true);
            assert!(json["first_failure"].is_null());
        });
    }

    #[test]
    fn tampered_chain_is_red_with_failing_seq() {
        let _g = ENV_LOCK.lock().expect("env lock");
        let _env = DevAuthEnv::enable();
        rt().block_on(async {
            let a = TenantId::from_jwt_claim(uuid::Uuid::parse_str(TENANT_A).unwrap());
            let mut rows = healthy_chain(&a, 3, "ok");
            // Tamper the middle row's payload while keeping its (now-stale)
            // row_hash → the verifier must recompute a mismatch at seq 1.
            rows[1].payload = r#"{"tag":"TAMPERED","seq":1}"#.to_string();
            let mut map = HashMap::new();
            map.insert(a.to_string(), rows);
            let reader = Arc::new(TenantScopedMockReader {
                rows_by_tenant: map,
            });
            let (status, json) = call(
                reader,
                Some(fixed_entitlement(true, 7)),
                dev_key_headers(),
                None,
            )
            .await;
            assert_eq!(status, StatusCode::OK, "body: {json}");
            assert_eq!(json["verdict"], "red");
            assert_eq!(json["hash_chain_valid"], false);
            assert_eq!(json["first_failure"]["kind"], "row_hash_mismatch");
            assert_eq!(json["first_failure"]["seq"], 1);
        });
    }

    // ---- Gate + fail-closed behaviour ------------------------------------

    #[test]
    fn workspace_with_selfverify_disabled_gets_403() {
        let _g = ENV_LOCK.lock().expect("env lock");
        let _env = DevAuthEnv::enable();
        rt().block_on(async {
            let a = TenantId::from_jwt_claim(uuid::Uuid::parse_str(TENANT_A).unwrap());
            let mut map = HashMap::new();
            map.insert(a.to_string(), healthy_chain(&a, 2, "ok"));
            let reader = Arc::new(TenantScopedMockReader {
                rows_by_tenant: map,
            });
            let (status, json) = call(
                reader,
                Some(fixed_entitlement(false, 7)), // override OFF
                dev_key_headers(),
                None,
            )
            .await;
            assert_eq!(status, StatusCode::FORBIDDEN, "body: {json}");
            assert_eq!(json["feature"], "audit_self_verify");
            // Zero ledger bytes leaked on the deny path.
            assert!(json.get("chain_ndjson").is_none());
        });
    }

    #[test]
    fn missing_entitlement_cache_fails_closed_503() {
        let _g = ENV_LOCK.lock().expect("env lock");
        let _env = DevAuthEnv::enable();
        rt().block_on(async {
            let a = TenantId::from_jwt_claim(uuid::Uuid::parse_str(TENANT_A).unwrap());
            let mut map = HashMap::new();
            map.insert(a.to_string(), healthy_chain(&a, 2, "ok"));
            let reader = Arc::new(TenantScopedMockReader {
                rows_by_tenant: map,
            });
            let (status, _json) = call(reader, None, dev_key_headers(), None).await;
            assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        });
    }

    #[test]
    fn missing_auth_header_is_401() {
        let _g = ENV_LOCK.lock().expect("env lock");
        let _env = DevAuthEnv::enable();
        rt().block_on(async {
            let a = TenantId::from_jwt_claim(uuid::Uuid::parse_str(TENANT_A).unwrap());
            let mut map = HashMap::new();
            map.insert(a.to_string(), healthy_chain(&a, 1, "ok"));
            let reader = Arc::new(TenantScopedMockReader {
                rows_by_tenant: map,
            });
            let (status, _json) = call(
                reader,
                Some(fixed_entitlement(true, 7)),
                HeaderMap::new(),
                None,
            )
            .await;
            assert_eq!(status, StatusCode::UNAUTHORIZED);
        });
    }

    /// The anchor-aware path: an unanchored chain still verifies GREEN, and the
    /// response reports zero resolved anchors (never implies universal anchoring).
    #[test]
    fn unanchored_chain_is_green_with_zero_resolved_anchors() {
        let _g = ENV_LOCK.lock().expect("env lock");
        let _env = DevAuthEnv::enable();
        rt().block_on(async {
            let a = TenantId::from_jwt_claim(uuid::Uuid::parse_str(TENANT_A).unwrap());
            let mut map = HashMap::new();
            map.insert(a.to_string(), healthy_chain(&a, 4, "ok"));
            let reader = Arc::new(TenantScopedMockReader {
                rows_by_tenant: map,
            });
            let (status, json) = call(
                reader,
                Some(fixed_entitlement(true, 7)),
                dev_key_headers(),
                None,
            )
            .await;
            assert_eq!(status, StatusCode::OK, "body: {json}");
            assert_eq!(json["verdict"], "green");
            assert_eq!(json["rekor_anchors_resolved"], 0);
            assert_eq!(json["anchors_included"], 0);
            assert_eq!(json["strip_detected"], false);
        });
    }

    // ---- anchors_fully_covered: the coverage-window filter that kills the
    // `anchor_rows_missing` false alarm on a capped self-verify view ----------

    fn export_rows_with_seqs(seqs: &[u64]) -> Vec<ExportRow> {
        seqs.iter()
            .map(|&seq| ExportRow {
                format: EXPORT_FORMAT.to_string(),
                tenant_id: TENANT_A.to_string(),
                seq,
                event_time: String::new(),
                event_type: String::new(),
                actor: String::new(),
                payload: String::new(),
                prev_hash: String::new(),
                row_hash: String::new(),
                rekor_entry_id: None,
            })
            .collect()
    }

    fn anchor_rec(start: u64, end: u64) -> AnchorExportRecord {
        AnchorExportRecord {
            kind: "anchor",
            tenant_id: TENANT_A.to_string(),
            batch_start_seq: start,
            batch_end_seq: end,
            merkle_root: "00".repeat(32),
            anchor_state: "unanchored".to_string(),
            ed25519: crate::audit_export::Ed25519Block {
                signature: String::new(),
                pubkey: String::new(),
            },
            rekor: None,
        }
    }

    #[test]
    fn anchors_outside_loaded_window_are_dropped_covered_kept() {
        // Loaded slice = the most-recent rows 100..=199 (the capped view).
        let rows = export_rows_with_seqs(&(100..=199).collect::<Vec<_>>());
        let anchors = vec![
            anchor_rec(0, 99),    // older batch — rows not loaded → DROP
            anchor_rec(100, 149), // fully covered → KEEP
            anchor_rec(150, 250), // straddles the top edge (200..=250 absent) → DROP
            anchor_rec(150, 199), // fully covered → KEEP
            anchor_rec(300, 100), // malformed (end < start) → DROP
        ];
        let kept = anchors_fully_covered(&rows, anchors);
        assert_eq!(kept.len(), 2, "only the two fully-covered anchors survive");
        assert!(
            kept.iter()
                .all(|a| a.batch_start_seq >= 100 && a.batch_end_seq <= 199)
        );
    }

    #[test]
    fn anchor_spanning_a_gap_in_loaded_rows_is_dropped() {
        // Rows 100..=199 EXCEPT 150 (e.g. a repaired dup left a gap). An anchor
        // covering 140..=160 spans the hole → not fully covered → DROP; a batch
        // wholly below the gap is KEPT.
        let seqs: Vec<u64> = (100..=199).filter(|&s| s != 150).collect();
        let rows = export_rows_with_seqs(&seqs);
        let kept = anchors_fully_covered(&rows, vec![anchor_rec(140, 160), anchor_rec(100, 149)]);
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].batch_start_seq, 100);
        assert_eq!(kept[0].batch_end_seq, 149);
    }

    #[test]
    fn empty_rows_or_no_anchors_are_handled() {
        assert!(anchors_fully_covered(&[], vec![]).is_empty());
        // An anchor over an empty loaded set is never covered → dropped.
        assert!(anchors_fully_covered(&[], vec![anchor_rec(0, 0)]).is_empty());
    }
}
