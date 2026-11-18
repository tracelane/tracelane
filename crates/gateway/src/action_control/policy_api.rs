//! HTTP authoring for protected-tool policies (ACT-12): a thin route over `activate_tx`.
//! Every refusal is `(status, code)` from the closed vocabulary in the spec; unknown -> 503.
use super::{policy::*, policy_store};
use crate::{
    auth::Claims,
    control_plane::ControlActor,
    db::control_audit::{self, Change},
    server::AppState,
};
use axum::http::HeaderMap;
use serde_json::{Value, json};
use uuid::Uuid;

pub type Refusal = (u16, &'static str);
const UNAVAILABLE: Refusal = (503, "evidence_unavailable");
const BAD_REQUEST: Refusal = (400, "invalid_policy_request");
const NOT_FOUND: Refusal = (404, "policy_not_found");

fn unavailable<E>(_: E) -> Refusal {
    UNAVAILABLE
}
/// Closed map of `activate_tx` failures; anything unlisted fails CLOSED as 503.
fn refusal(e: &anyhow::Error) -> Refusal {
    match e.to_string().as_str() {
        "contract_invalid" => (422, "contract_invalid"),
        "approval_policy_invalid" => (422, "policy_invalid"),
        "policy_version_must_increase" => (409, "policy_version_must_increase"),
        "unauthorized" => (403, "forbidden"),
        _ => {
            // A reused policy_id (unique key) is the caller's conflict, not an outage.
            let unique = e.chain().any(|c| {
                c.downcast_ref::<tokio_postgres::Error>()
                    .and_then(tokio_postgres::Error::code)
                    == Some(&tokio_postgres::error::SqlState::UNIQUE_VIOLATION)
            });
            if unique {
                (409, "policy_conflict")
            } else {
                UNAVAILABLE
            }
        }
    }
}

/// # Errors
/// Fail-CLOSED: the flag, the human session, server ownership and every `activate_tx`
/// check refuse before a commit; the transaction is dropped (rolled back) on any error.
/// Only the derived ledger copy fails OPEN (recovered from the canonical rows).
#[tracing::instrument(skip_all, fields(tenant_id=%claims.tenant_id))]
pub async fn publish(
    state: &AppState,
    claims: &Claims,
    actor: &ControlActor,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<Value, Refusal> {
    let pool = state.pg.as_ref().ok_or(UNAVAILABLE)?;
    let cache = state.entitlements.as_ref().ok_or(UNAVAILABLE)?;
    let tenant = claims.tenant_id.as_uuid();
    let resolved = cache.resolved(*tenant).await;
    if !crate::action_control::enabled(Some(&resolved)) {
        return Err((409, "action_control_disabled"));
    }
    let limits = &crate::mcp_policy::settings().map_err(unavailable)?.limits;
    if body.len() > limits.max_request_bytes {
        return Err(BAD_REQUEST);
    }
    // Strict parse: a duplicated key anywhere is refused rather than last-one-wins.
    let doc = crate::strict_json::from_slice(body).map_err(|_| BAD_REQUEST)?;
    let (Some(c), Some(p)) = (doc.get("contract"), doc.get("policy")) else {
        return Err(BAD_REQUEST);
    };
    if doc.as_object().is_none_or(|o| o.len() != 2) {
        return Err(BAD_REQUEST);
    }
    let (c_raw, p_raw) = (c.to_string(), p.to_string());
    let contract = parse_contract(&c_raw).map_err(|_| (422, "contract_invalid"))?;
    let policy = parse_policy(&p_raw, &contract).map_err(|_| (422, "policy_invalid"))?;
    // Claims prove the role; only re-verifying the header proves a human session.
    let Some(auth) = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
    else {
        return Err((403, "forbidden"));
    };
    match crate::auth::verified_session(auth).await {
        Ok(Some(_)) => {}
        Ok(None) => return Err((403, "forbidden")),
        Err(_) => return Err(UNAVAILABLE),
    }
    let timeout = std::time::Duration::from_secs(limits.call_timeout_secs);
    // Fail-CLOSED: expiry drops the transaction (rollback) and answers 503.
    let (out, rows) = tokio::time::timeout(
        timeout,
        commit_policy(
            pool,
            claims,
            actor,
            &resolved,
            timeout,
            (&c_raw, &p_raw),
            (&contract, &policy),
        ),
    )
    .await
    .map_err(unavailable)??;
    super::execution::after_commit(Some(&state.audit_chain), claims, vec![rows], timeout);
    Ok(out)
}

type Parsed<'a> = (&'a str, &'a str);
async fn commit_policy(
    pool: &deadpool_postgres::Pool,
    claims: &Claims,
    actor: &ControlActor,
    resolved: &crate::entitlement_cache::ResolvedEntitlements,
    timeout: std::time::Duration,
    (c_raw, p_raw): Parsed<'_>,
    (contract, policy): (&Contract, &Policy),
) -> Result<(Value, crate::db::audit_chain_state::AtomicBatchAppend), Refusal> {
    let tenant = claims.tenant_id.as_uuid();
    let mut db = pool.get().await.map_err(unavailable)?;
    let tx = db.transaction().await.map_err(unavailable)?;
    super::execution::deadline_tx(&tx, timeout)
        .await
        .map_err(unavailable)?;
    let owned = tx
        .query_opt(
            "SELECT 1 FROM mcp_servers WHERE tenant_id=$1 AND id=$2 AND archived_at IS NULL FOR SHARE",
            &[tenant, &contract.server_id],
        )
        .await
        .map_err(unavailable)?;
    if owned.is_none() {
        return Err((404, "mcp_server_not_found"));
    }
    let prior = tx
        .query_opt(
            "SELECT policy_id,version FROM action_policy_active WHERE tenant_id=$1 AND tool_ref=$2",
            &[tenant, &contract.tool_ref],
        )
        .await
        .map_err(unavailable)?
        .map(|r| json!({"policy_id":r.get::<_, Uuid>(0),"policy_version":r.get::<_, i32>(1)}));
    let rows = policy_store::activate_tx(&tx, claims, Some(resolved), c_raw, p_raw)
        .await
        .map_err(|e| refusal(&e))?;
    let stored = tx
        .query_one(
            "SELECT p.policy_hash,c.contract_hash FROM action_policies p JOIN action_tool_contracts c ON c.tenant_id=p.tenant_id AND c.tool_ref=p.tool_ref AND c.version=p.contract_version WHERE p.tenant_id=$1 AND p.tool_ref=$2 AND p.policy_id=$3 AND p.version=$4",
            &[tenant, &contract.tool_ref, &policy.policy_id, &i32::try_from(policy.version).map_err(unavailable)?],
        )
        .await
        .map_err(unavailable)?;
    let mut out = json!({"tool_ref":contract.tool_ref,"policy_id":policy.policy_id,"policy_version":policy.version,
        "policy_hash":stored.get::<_, String>(0),"contract_hash":stored.get::<_, String>(1)});
    if policy.require_principal {
        let has_issuer = tx
            .query_opt(
                "SELECT 1 FROM tenant_principal_issuers WHERE tenant_id=$1 LIMIT 1",
                &[tenant],
            )
            .await
            .map_err(unavailable)?
            .is_some();
        if !has_issuer {
            out["warnings"] = json!(["principal_issuer_missing"]);
        }
    }
    control_audit::record(
        &tx,
        &actor.tenant_id,
        &actor.audit,
        Change {
            action: "action_policy.activate",
            target_type: "action_policy",
            target_id: contract.tool_ref.to_string(),
            before: prior,
            after: Some(out.clone()),
        },
    )
    .await
    .map_err(unavailable)?;
    tx.commit().await.map_err(unavailable)?;
    Ok((out, rows))
}

const ACTIVE_FROM: &str = " FROM action_policy_active a JOIN action_policies p ON p.tenant_id=a.tenant_id AND p.tool_ref=a.tool_ref AND p.policy_id=a.policy_id AND p.version=a.version JOIN action_tool_contracts c ON c.tenant_id=p.tenant_id AND c.tool_ref=p.tool_ref AND c.version=p.contract_version WHERE a.tenant_id=$1";
const ACTIVE_KEYS: &str = "'tool_ref',c.tool_ref,'server_id',c.server_id,'tool_name',c.tool_name,'contract_version',c.version,'policy_id',p.policy_id,'policy_version',p.version,'policy_hash',p.policy_hash,'contract_hash',c.contract_hash,'publisher_sub',p.publisher_sub";

/// `GET /v1/action-policies` (no `tool_ref`) or `/{tool_ref}`. Every query is keyed by the
/// tenant of the validated claims.
#[tracing::instrument(skip_all, fields(tenant_id=%actor.tenant_id))]
pub async fn read(
    state: &AppState,
    actor: &ControlActor,
    tool_ref: Option<&str>,
) -> Result<Value, Refusal> {
    let pool = state.pg.as_ref().ok_or(UNAVAILABLE)?;
    let db = pool.get().await.map_err(unavailable)?;
    let tenant = actor.tenant_id.as_uuid();
    let Some(raw) = tool_ref else {
        let sql =
            format!("SELECT jsonb_build_object({ACTIVE_KEYS}){ACTIVE_FROM} ORDER BY c.tool_name");
        let rows = db.query(&sql, &[tenant]).await.map_err(unavailable)?;
        return Ok(
            json!({"policies":rows.iter().map(|r| r.get::<_, Value>(0)).collect::<Vec<_>>()}),
        );
    };
    let tool: Uuid = raw.parse().map_err(|_| NOT_FOUND)?;
    let sql = format!(
        "SELECT jsonb_build_object({ACTIVE_KEYS},'contract_jcs',c.body_jcs,'policy_jcs',p.body_jcs){ACTIVE_FROM} AND a.tool_ref=$2"
    );
    let mut detail: Value = db
        .query_opt(&sql, &[tenant, &tool])
        .await
        .map_err(unavailable)?
        .ok_or(NOT_FOUND)?
        .get(0);
    let cap = crate::mcp_policy::settings()
        .map_err(unavailable)?
        .approvals
        .list_page_size;
    let rows = db
        .query(
            "SELECT jsonb_build_object('policy_id',policy_id,'version',version,'policy_hash',policy_hash,'publisher_sub',publisher_sub) FROM action_policies WHERE tenant_id=$1 AND tool_ref=$2 ORDER BY version DESC LIMIT $3",
            &[tenant, &tool, &i64::try_from(cap + 1).map_err(unavailable)?],
        )
        .await
        .map_err(unavailable)?;
    detail["history_truncated"] = json!(rows.len() > cap);
    detail["history"] = Value::Array(
        rows.iter()
            .take(cap)
            .map(|r| r.get::<_, Value>(0))
            .collect(),
    );
    Ok(detail)
}
