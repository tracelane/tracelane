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

use crate::audit_export::{EXPORT_FORMAT, ExportState};

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
    /// Chain rows the server verified (== the verifier's `rows_seen`).
    pub rows_verified: u64,
    /// `"green"` iff `hash_chain_valid && signatures_valid && !strip_detected`.
    /// An unanchored chain is still GREEN (hash-chain integrity), matching the
    /// ADR-062 "unanchored-still-verifies" guard.
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

    // 7. Build the truthful verdict. GREEN requires an intact hash chain, no
    //    signature failure, and no strip — unanchored is still GREEN.
    let verdict = if report.hash_chain_valid && report.signatures_valid && !report.strip_detected {
        "green"
    } else {
        "red"
    };
    let first_failure = report.errors.first().map(|e| SelfVerifyFailure {
        seq: e.seq,
        kind: e.kind.clone(),
        detail: e.detail.clone(),
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
        verdict,
        hash_chain_valid: report.hash_chain_valid,
        signatures_valid: report.signatures_valid,
        rekor_anchors_seen: report.rekor_anchors_seen,
        rekor_anchors_resolved: report.rekor_anchors_resolved,
        anchors_included: report.anchors_included,
        strip_detected: report.strip_detected,
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
}
