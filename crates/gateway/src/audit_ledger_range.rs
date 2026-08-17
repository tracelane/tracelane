//! `GET /v1/audit/ledger-range` — the tenant's audit-ledger sequence range.
//!
//! WHY THIS ROUTE EXISTS (R56, ADR-074 §7). §7 asks for a `▸ 15700–15799` chip
//! "wherever a trace appears", at PER-TENANT scope. Nothing could serve it:
//!
//! * `/v1/traces/{id}/chain` returns a single PER-TRACE seq, and `/v1/traces`
//!   carries no ledger field — so a per-row chip meant one gateway call per row,
//!   which is the fan-out that cost 6s on `/dashboard`.
//! * `/v1/audit/summary` has the right shape but aggregates `min/max(event_time)`,
//!   not `seq`, and is gated on the PAID Audit add-on — B-249 measured **two**
//!   `workspace_entitlements` rows fleet-wide, so the chip would be blank for
//!   almost every workspace.
//! * `/v1/audit/self-verify` is free-tier and its NDJSON carries per-row `seq`, but
//!   `read_range` is `ORDER BY seq ASC LIMIT ?` — it loads the OLDEST rows, so a
//!   range derived from it UNDERSTATES and silently freezes as the ledger grows.
//!
//! So the chip stayed unplaced rather than render a confident number the data does
//! not support. This is the field that makes it truthful.
//!
//! THE QUERY IS CHEAP, WHICH IS WHY THIS IS A ROUTE AND NOT A BATCH JOB.
//! `audit_log` is `ENGINE = ReplacingMergeTree(event_time) ORDER BY (tenant_id, seq)`
//! with **no TTL**, so `min(seq)` / `max(seq)` for one tenant is served straight off
//! the sort key, and the answer is genuinely the LIFETIME range rather than a window.
//!
//! GATE: free-tier, mirroring self-verify exactly — `Scope::Read` (an entitlement
//! gate is not a scope gate, B-230) plus the default-granted `f_audit_selfverify`.
//! It reveals strictly less than self-verify already does: two integers and a count,
//! no row contents. Fails CLOSED with no entitlement source.
//!
//! HONESTY: an empty ledger returns `from: null, to: null, total: 0` — never `0–0`,
//! which would read as "one row at seq 0". The UI renders nothing for a null range.

use axum::{
    Router,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::Response,
    routing::get,
};
use serde::Serialize;

use crate::audit_export::{ExportState, error_response};

/// The tenant's lifetime ledger sequence range.
#[derive(Debug, Clone, Serialize, Default)]
pub struct LedgerRange {
    pub tenant_id: String,
    /// Lowest `seq` in the tenant's chain, or `null` when the ledger is empty.
    /// NEVER `0` as a stand-in for absent — seq 0 is a real genesis row
    /// (`audit_chain_state` assigns from a `last_seq = -1` sentinel).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from: Option<u64>,
    /// Highest `seq` — the current chain head. `null` on an empty ledger.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to: Option<u64>,
    /// Exact row count. `0` here means measured-and-empty, which is why `from`/`to`
    /// are absent rather than zero.
    pub total: u64,
}

pub fn routes() -> Router<ExportState> {
    Router::new().route("/v1/audit/ledger-range", get(handler))
}

async fn handler(State(state): State<ExportState>, headers: HeaderMap) -> Response {
    // 1. Auth — the tenant comes from the validated claim, never the request.
    let auth = match headers.get("authorization").and_then(|v| v.to_str().ok()) {
        Some(s) => s.to_owned(),
        None => return error_response(StatusCode::UNAUTHORIZED, "missing Authorization header"),
    };
    let claims = match crate::auth::validate_authorization(&auth).await {
        Ok(c) => c,
        Err(err) => {
            tracing::warn!(error = %err, "audit ledger-range auth failed");
            return error_response(StatusCode::UNAUTHORIZED, "invalid credentials");
        }
    };

    // 2. Scope — B-230: an entitlement gate is NOT a scope gate. An `ingest`-scoped
    //    SDK key must not read the ledger, even a two-integer summary of it.
    if !claims.allows_scope(crate::auth::scope::Scope::Read) {
        return error_response(
            StatusCode::FORBIDDEN,
            "this API key is not scoped to read recorded data — it needs the `read` scope",
        );
    }
    let tenant = claims.tenant_id;

    // 3. Entitlement — the same default-granted free-tier flag self-verify uses.
    //    FAILS CLOSED without an entitlement source.
    let resolved = match state.entitlements {
        Some(ref cache) => cache.resolved(*tenant.as_uuid()).await,
        None => {
            tracing::error!("audit ledger-range: entitlement cache unavailable — denying");
            return error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "entitlement verification unavailable",
            );
        }
    };
    if !resolved.f_audit_selfverify {
        return error_response(
            StatusCode::FORBIDDEN,
            "audit ledger access is disabled for this workspace",
        );
    }

    // 4. The range itself.
    match state.reader.ledger_range(&tenant).await {
        Ok((from, to, total)) => {
            let body = LedgerRange {
                tenant_id: tenant.to_string(),
                from,
                to,
                total,
            };
            match serde_json::to_string(&body) {
                Ok(json) => Response::builder()
                    .status(StatusCode::OK)
                    .header("content-type", "application/json")
                    .body(json.into())
                    .unwrap_or_else(|_| {
                        error_response(StatusCode::INTERNAL_SERVER_ERROR, "response build failed")
                    }),
                Err(_) => error_response(StatusCode::INTERNAL_SERVER_ERROR, "serialization failed"),
            }
        }
        Err(err) => {
            tracing::error!(error = %err, tenant_id = %tenant, "ledger-range query failed");
            // A read failure is NOT an empty ledger. Returning 0/null here would tell
            // the workspace it has no ledger, which is the collapsed-state defect
            // B-249 already cost us — two distinct states rendering as one, and the
            // one rendered being false.
            error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "ledger range unavailable — the audit store could not be read",
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_ledger_omits_the_range_rather_than_sending_zero() {
        // `0–0` would read as "one row at seq 0", and seq 0 is a REAL genesis row —
        // `audit_chain_state` assigns from a `last_seq = -1` sentinel. Absent is the
        // only honest encoding of "no rows".
        let body = LedgerRange {
            tenant_id: "t".into(),
            from: None,
            to: None,
            total: 0,
        };
        let v = serde_json::to_value(&body).unwrap();
        assert!(v.get("from").is_none(), "empty ledger must omit `from`");
        assert!(v.get("to").is_none(), "empty ledger must omit `to`");
        assert_eq!(v["total"], 0);
    }

    #[test]
    fn a_real_range_serializes_both_bounds() {
        let body = LedgerRange {
            tenant_id: "t".into(),
            from: Some(15_700),
            to: Some(15_799),
            total: 100,
        };
        let v = serde_json::to_value(&body).unwrap();
        assert_eq!(v["from"], 15_700);
        assert_eq!(v["to"], 15_799);
        assert_eq!(v["total"], 100);
    }

    #[test]
    fn seq_zero_is_a_real_row_and_must_survive_serialization() {
        // The regression this guards: treating 0 as "absent" (a `skip_serializing_if`
        // on the value rather than on the Option) would erase a genuine genesis row.
        let body = LedgerRange {
            tenant_id: "t".into(),
            from: Some(0),
            to: Some(0),
            total: 1,
        };
        let v = serde_json::to_value(&body).unwrap();
        assert_eq!(v["from"], 0, "seq 0 is a real genesis row, not absent");
        assert_eq!(v["to"], 0);
    }
}
