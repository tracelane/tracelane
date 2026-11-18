//! Authenticated MCP control plane: every write and its audit row share a transaction.
use crate::{
    auth::Claims,
    control_plane::ControlActor,
    db::control_audit::{self, Change},
    server::AppState,
};
use axum::{
    Json, Router,
    body::Bytes,
    extract::{MatchedPath, OriginalUri, Path, State},
    http::{HeaderMap, Method, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
};
use serde_json::{Value, json};
use std::collections::HashMap;
use uuid::Uuid;
#[derive(Debug)]
struct Fault(u16, &'static str);
type Result<T> = std::result::Result<T, Fault>;
impl From<tokio_postgres::Error> for Fault {
    fn from(_: tokio_postgres::Error) -> Self {
        Self(503, "mcp_store_unavailable")
    }
}
impl From<deadpool_postgres::PoolError> for Fault {
    fn from(_: deadpool_postgres::PoolError) -> Self {
        Self(503, "mcp_store_unavailable")
    }
}
impl From<anyhow::Error> for Fault {
    fn from(_: anyhow::Error) -> Self {
        Self(503, "mcp_store_unavailable")
    }
}
fn invalid() -> Fault {
    Fault(400, "invalid_field")
}
fn text<'a>(v: &'a Value, k: &str) -> Result<&'a str> {
    v.get(k).and_then(Value::as_str).ok_or_else(invalid)
}
fn id(v: &str) -> Result<Uuid> {
    Uuid::parse_str(v).map_err(|_| invalid())
}
fn optional_id(v: &Value, k: &str) -> Result<Option<Uuid>> {
    match v.get(k) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => id(s).map(Some),
        _ => Err(invalid()),
    }
}
fn fields(v: &Value, allowed: &[&str]) -> Result<()> {
    if v.as_object()
        .is_some_and(|o| o.keys().all(|k| allowed.contains(&k.as_str())))
    {
        Ok(())
    } else {
        Err(invalid())
    }
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/v1/mcp-servers", get(control).post(control))
        .route(
            "/v1/mcp-servers/{id}",
            get(control).patch(control).delete(control),
        )
        .route("/v1/mcp-servers/{id}/test", axum::routing::post(control))
        .route(
            "/v1/mcp-servers/{id}/receipt-key",
            axum::routing::put(control),
        )
        .route("/v1/mcp-policy", get(control).put(control))
        .route("/v1/mcp-policy/preview", get(control))
        .route("/v1/mcp-tool-rules", get(control).post(control))
        .route("/v1/mcp-tool-rules/{id}", axum::routing::delete(control))
        .route("/v1/mcp-tools", get(control))
        .route("/v1/action-authority", get(control))
        .route("/v1/mcp-tools/approve", axum::routing::post(control))
        .route(
            "/v1/mcp-tools/{server_id}/{tool_name}",
            axum::routing::delete(control),
        )
        .route(
            "/v1/principal-issuers",
            axum::routing::post(control).delete(control),
        )
        .route("/v1/action-policies", get(control).post(control))
        .route("/v1/action-policies/{tool_ref}", get(control))
        .route("/v1/actions", get(control))
        .route("/v1/actions/{action_id}", get(control))
        .route("/v1/approvals", get(control))
        .route("/v1/approvals/settings", get(control).put(control))
        .route("/v1/approval-rules", get(control).post(control))
        .route("/v1/approval-rules/{id}", axum::routing::delete(control))
        .route("/v1/approvals/{id}", get(control))
        .route("/v1/approvals/{id}/approve", axum::routing::post(control))
        .route("/v1/approvals/{id}/deny", axum::routing::post(control))
        .with_state(state)
}
async fn control(
    State(state): State<AppState>,
    Path(params): Path<HashMap<String, String>>,
    OriginalUri(uri): OriginalUri,
    matched: MatchedPath,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let claims = match crate::auth::validate_authorization(
        headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default(),
    )
    .await
    {
        Ok(c) => c,
        Err(_) => return crate::mcp_proxy::error(StatusCode::UNAUTHORIZED, "unauthorized"),
    };
    let path = uri.path();
    // Only the requesting key can poll, and its response contains status fields only.
    if method == Method::GET
        && matched.as_str() == "/v1/approvals/{id}"
        && claims.api_key_id().is_some()
    {
        if let Err(seconds) = crate::admission::charge_rate_limit(&state, &claims).await {
            let mut response =
                crate::mcp_proxy::error(StatusCode::TOO_MANY_REQUESTS, "rate_limited");
            crate::admission::insert_retry_after(&mut response, seconds);
            return response;
        }
        return respond(
            poll(
                &state,
                &claims,
                params.get("id").map(String::as_str).unwrap_or_default(),
            )
            .await,
        );
    }
    use crate::auth::capability::{CONTROL_ROUTES, Method as RegisteredMethod};
    let registered_method = match method {
        Method::GET => RegisteredMethod::Get,
        Method::POST => RegisteredMethod::Post,
        Method::PUT => RegisteredMethod::Put,
        Method::PATCH => RegisteredMethod::Patch,
        Method::DELETE => RegisteredMethod::Delete,
        _ => return crate::mcp_proxy::error(StatusCode::FORBIDDEN, "role_forbidden"),
    };
    let Some(cap) = CONTROL_ROUTES
        .iter()
        .find(|r| r.method == registered_method && r.path == matched.as_str())
        .map(|r| r.cap)
    else {
        return crate::mcp_proxy::error(StatusCode::FORBIDDEN, "role_forbidden");
    };
    let actor = match crate::control_plane::require_control(&claims, cap, &headers).await {
        Ok(a) => a,
        Err(e) => {
            if e.status == StatusCode::FORBIDDEN
                && !claims.can(cap)
                && method == Method::POST
                && matches!(
                    matched.as_str(),
                    "/v1/approvals/{id}/approve" | "/v1/approvals/{id}/deny"
                )
                && state.pg.is_some()
                && let Some(id) = params.get("id").and_then(|s| Uuid::parse_str(s).ok())
            {
                // Explicit cached OFF preserves the original control denial even if
                // Postgres is unavailable. Unknown/invalidated flags still fail CLOSED.
                if state
                    .entitlements
                    .as_ref()
                    .and_then(|cache| cache.cached_resolved(*claims.tenant_id.as_uuid()))
                    .is_some_and(|r| !crate::action_control::enabled(Some(&r)))
                {
                    return e.into_response();
                }
                // Share the existing refusal budget per (tenant, principal), before
                // any fallback SQL. Exhaustion preserves the original refusal.
                if !crate::control_plane::refusal_logged(&claims) {
                    return e.into_response();
                }
                let timeout = match crate::mcp_policy::settings() {
                    Ok(l) => std::time::Duration::from_secs(l.limits.call_timeout_secs),
                    Err(_) => {
                        return crate::mcp_proxy::error(
                            StatusCode::SERVICE_UNAVAILABLE,
                            "approval_unavailable",
                        );
                    }
                };
                // A denied control gate must never run the granting decision path.
                let recorded = tokio::time::timeout(
                    timeout,
                    protected_decision(&state, &claims, &headers, id, None, "", None),
                )
                .await;
                // A resolved-OFF flag is the legacy path: keep the original refusal (no 503
                // that would reveal the id is a protected approval).
                if !matches!(
                    recorded,
                    Ok(Ok(_))
                        | Ok(Err(Fault(403, _)))
                        | Ok(Err(Fault(503, "action_control_disabled")))
                ) {
                    return crate::mcp_proxy::error(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "approval_unavailable",
                    );
                }
            }
            return e.into_response();
        }
    };
    if path == "/v1/principal-issuers" {
        return respond(
            crate::action_control::principal_api::change(
                &state,
                &claims,
                &actor,
                &headers,
                &body,
                method == Method::DELETE,
            )
            .await
            .map_err(|(status, code)| Fault(status, code)),
        );
    }
    if path.starts_with("/v1/action-policies") {
        // Own body cap and error vocabulary (spec ACT-12 §2); no generic body parse.
        let result = if method == Method::POST {
            crate::action_control::policy_api::publish(&state, &claims, &actor, &headers, &body)
                .await
        } else {
            crate::action_control::policy_api::read(
                &state,
                &actor,
                params.get("tool_ref").map(String::as_str),
            )
            .await
        };
        return match result {
            Ok(v) if method == Method::POST => (StatusCode::CREATED, Json(v)).into_response(),
            r => respond(r.map_err(|(status, code)| Fault(status, code))),
        };
    }
    if matched.as_str() == "/v1/mcp-servers/{id}/receipt-key" {
        // Own strict body parse and error vocabulary (spec ACT-17 §2).
        let server = params.get("id").map(String::as_str).unwrap_or_default();
        // Each call takes the tenant lock every protected reservation takes and appends an
        // undeletable ledger row, so it is charged like any other request.
        if let Err(seconds) = crate::admission::charge_rate_limit(&state, &claims).await {
            let mut response =
                crate::mcp_proxy::error(StatusCode::TOO_MANY_REQUESTS, "rate_limited");
            crate::admission::insert_retry_after(&mut response, seconds);
            return response;
        }
        let result =
            crate::action_control::receipt_keys::register(&state, &claims, &actor, server, &body)
                .await;
        return respond(result.map_err(|(status, code)| Fault(status, code)));
    }
    let result = async {
        let limits = crate::mcp_policy::settings()?;
        if body.len() > limits.limits.max_request_bytes {
            return Err(Fault(413, "mcp_request_too_large"));
        }
        let mut value = if body.is_empty() {
            json!({})
        } else {
            serde_json::from_slice(&body).map_err(|_| invalid())?
        };
        let query: HashMap<String, String> =
            reqwest::Url::parse(&format!("https://gateway.invalid{uri}"))
                .map_err(|_| invalid())?
                .query_pairs()
                .into_owned()
                .collect();
        if method == Method::GET && path.starts_with("/v1/actions") {
            return crate::action_control::timeline::read(
                &state,
                &actor,
                params.get("action_id").map(String::as_str),
                &query,
            )
            .await
            .map_err(|(status, code)| Fault(status, code));
        }
        if method == Method::GET {
            return read(&state, &actor, path, &params, &query).await;
        }
        let result = write(
            &state, &actor, &claims, &headers, path, &method, &params, &mut value,
        )
        .await?;
        if path.starts_with("/v1/mcp-servers/") && matches!(method, Method::PATCH | Method::DELETE)
        {
            crate::mcp_transport::evict_tenant(*actor.tenant_id.as_uuid());
        }
        if !path.starts_with("/v1/approvals/") || path == "/v1/approvals/settings" {
            crate::mcp_inspection::evict(*actor.tenant_id.as_uuid());
            if let Some(cache) = &state.entitlements {
                cache.invalidate(*actor.tenant_id.as_uuid()).await;
            }
        }
        Ok(result)
    }
    .await;
    respond(result)
}
fn respond(r: Result<Value>) -> Response {
    match r {
        Ok(v) => Json(v).into_response(),
        Err(Fault(status, code)) => {
            let status = StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            if let Some(field) = code.strip_prefix("invalid_field:") {
                (status, Json(json!({"error":"invalid_field","field":field}))).into_response()
            } else {
                crate::mcp_proxy::error(status, code)
            }
        }
    }
}
async fn poll(state: &AppState, claims: &Claims, raw: &str) -> Result<Value> {
    let pool = state.pg.as_ref().ok_or(Fault(503, "no_control_plane"))?;
    let client = pool.get().await?;
    let r=client.query_opt("SELECT id,CASE WHEN status='pending' AND expires_at<=now() THEN 'expired' WHEN status='approved' AND grant_expires_at<=now() THEN 'expired' ELSE status END,expires_at,grant_expires_at FROM approvals WHERE tenant_id=$1 AND id=$2 AND requester_sub=$3",&[claims.tenant_id.as_uuid(),&id(raw)?,&claims.sub]).await?.ok_or(Fault(404,"approval_not_found"))?;
    Ok(
        json!({"id":r.get::<_,Uuid>(0),"status":r.get::<_,String>(1),"expires_at":r.get::<_,chrono::DateTime<chrono::Utc>>(2),"grant_expires_at":r.get::<_,Option<chrono::DateTime<chrono::Utc>>>(3)}),
    )
}
async fn read(
    state: &AppState,
    actor: &ControlActor,
    path: &str,
    p: &HashMap<String, String>,
    q: &HashMap<String, String>,
) -> Result<Value> {
    if path == "/v1/action-authority" {
        let as_of = q
            .get("as_of")
            .map(|s| chrono::DateTime::parse_from_rfc3339(s))
            .transpose()
            .map_err(|_| Fault(400, "as_of_invalid"))?
            .map(|d| d.with_timezone(&chrono::Utc));
        // Absent entitlement cache = OFF (tenancy.md); any failure is one fail-closed 503.
        let on = match &state.entitlements {
            Some(c) => {
                let t = *actor.tenant_id.as_uuid();
                let resolved = c.resolved(t).await;
                // The outage fallback is a fresh snapshot that is never the cached one: do not
                // present it as a confident "action control off".
                if !c.is_current(t, &resolved) {
                    return Err(Fault(503, "register_unavailable"));
                }
                crate::action_control::enabled(Some(&resolved))
            }
            None => false,
        };
        let pool = state
            .pg
            .as_ref()
            .ok_or(Fault(503, "register_unavailable"))?;
        return crate::action_control::authority::register(pool, &actor.tenant_id, on, as_of)
            .await
            .map_err(|e| {
                if let Some(r) = e.downcast_ref::<crate::action_control::authority::AsOfRejected>()
                {
                    return Fault(400, r.0);
                }
                tracing::warn!(error = %e, "action authority register unavailable");
                Fault(503, "register_unavailable")
            });
    }
    let pool = state.pg.as_ref().ok_or(Fault(503, "no_control_plane"))?;
    let client = pool.get().await?;
    let tenant = actor.tenant_id.as_uuid();
    let l = crate::mcp_policy::settings()?;
    match path {
        "/v1/mcp-servers" => {
            let rows=client.query("SELECT to_jsonb(s)-'credential_ct'-'tenant_id' FROM mcp_servers s WHERE tenant_id=$1 AND archived_at IS NULL ORDER BY name",&[tenant]).await?;
            Ok(
                json!({"servers":rows.iter().map(|r|r.get::<_,Value>(0)).collect::<Vec<_>>(),"limits":l.limits}),
            )
        }
        "/v1/mcp-policy" => {
            let snapshot = crate::mcp_store::load(&client, tenant).await?;
            let keys=client.query("SELECT id,name FROM api_keys WHERE tenant_id=$1 AND revoked_at IS NULL ORDER BY name",&[tenant]).await?.iter().map(|r|json!({"id":r.get::<_,Uuid>(0),"name":r.get::<_,String>(1)})).collect::<Vec<_>>();
            Ok(
                json!({"policy":snapshot.policy,"rules":snapshot.rules,"model_rules":snapshot.model_rules,"keys":keys,"limits":l.policy}),
            )
        }
        "/v1/mcp-tool-rules" => {
            let rows=client.query("SELECT to_jsonb(r)-'tenant_id' FROM mcp_tool_rules r WHERE tenant_id=$1 ORDER BY created_at,id",&[tenant]).await?;
            Ok(json!({"rules":rows.iter().map(|r|r.get::<_,Value>(0)).collect::<Vec<_>>()}))
        }
        "/v1/approval-rules" => {
            let rows=client.query("SELECT to_jsonb(r)-'tenant_id' FROM approval_rules r WHERE tenant_id=$1 ORDER BY created_at,id",&[tenant]).await?;
            let keys=client.query("SELECT id,name FROM api_keys WHERE tenant_id=$1 AND revoked_at IS NULL ORDER BY name",&[tenant]).await?.iter().map(|r|json!({"id":r.get::<_,Uuid>(0),"name":r.get::<_,String>(1)})).collect::<Vec<_>>();
            Ok(
                json!({"rules":rows.iter().map(|r|r.get::<_,Value>(0)).collect::<Vec<_>>(),"keys":keys,"limits":{"tool_glob_max_chars":l.policy.tool_glob_max_chars,"max_ttl_secs":l.approvals.max_ttl_secs}}),
            )
        }
        "/v1/mcp-tools" => {
            let server = q.get("server").map(|s| id(s)).transpose()?;
            let rows=client.query("SELECT to_jsonb(d)-'tenant_id' || jsonb_build_object('server_name',s.name) FROM mcp_tool_defs d JOIN mcp_servers s ON s.tenant_id=d.tenant_id AND s.id=d.server_id WHERE d.tenant_id=$1 AND ($2::uuid IS NULL OR d.server_id=$2) AND s.archived_at IS NULL ORDER BY s.name,d.tool_name,d.last_seen DESC",&[tenant,&server]).await?;
            Ok(json!({"tools":rows.iter().map(|r|r.get::<_,Value>(0)).collect::<Vec<_>>()}))
        }
        "/v1/approvals/settings" => {
            let snapshot = crate::mcp_store::load(&client, tenant).await?;
            Ok(json!({"settings":snapshot.approval_settings,"limits":l.approvals}))
        }
        "/v1/approvals" => {
            let status = q.get("status").map_or("pending", String::as_str);
            if !["pending", "approved", "denied", "expired", "consumed"].contains(&status) {
                return Err(invalid());
            }
            let limit = q
                .get("limit")
                .map(|s| s.parse::<usize>().map_err(|_| invalid()))
                .transpose()?
                .unwrap_or(l.approvals.list_page_size)
                .min(l.approvals.max_list_page_size) as i64;
            let cursor = q
                .get("cursor")
                .map(|s| {
                    let (date, key) = s.split_once('|').ok_or_else(invalid)?;
                    Ok::<_, Fault>((
                        chrono::DateTime::parse_from_rfc3339(date)
                            .map(|d| d.with_timezone(&chrono::Utc))
                            .map_err(|_| invalid())?,
                        id(key)?,
                    ))
                })
                .transpose()?;
            let cursor_time = cursor.as_ref().map(|c| c.0);
            let cursor_id = cursor.as_ref().map(|c| c.1);
            let rows=client.query("SELECT to_jsonb(a)-'args_fp'-'tenant_id' || jsonb_build_object('server_name',s.name,'key_name',k.name,'age_secs',extract(epoch from now()-a.created_at)::bigint) FROM approvals a LEFT JOIN mcp_servers s ON s.tenant_id=a.tenant_id AND s.id=a.server_id LEFT JOIN api_keys k ON k.tenant_id=a.tenant_id AND k.id=a.key_id WHERE a.tenant_id=$1 AND a.status=$2 AND ($3::timestamptz IS NULL OR (a.created_at,a.id)<($3,$4::uuid)) ORDER BY a.created_at DESC,a.id DESC LIMIT $5",&[tenant,&status,&cursor_time,&cursor_id,&limit]).await?;
            let items: Vec<Value> = rows.iter().map(|r| r.get(0)).collect();
            let next = if items.len() == limit as usize {
                items.last().and_then(|r| {
                    Some(format!(
                        "{}|{}",
                        r["created_at"].as_str()?,
                        r["id"].as_str()?
                    ))
                })
            } else {
                None
            };
            let count:i64=client.query_one("SELECT count(*) FROM approvals WHERE tenant_id=$1 AND status='pending' AND expires_at>now()",&[tenant]).await?.get(0);
            Ok(
                json!({"approvals":items,"pending":count,"held_now":crate::approvals::held_now(*tenant),"next_cursor":next}),
            )
        }
        "/v1/mcp-policy/preview" => preview(state, actor, q).await,
        _ if path.starts_with("/v1/mcp-servers/") => {
            let row=client.query_opt("SELECT to_jsonb(s)-'credential_ct'-'tenant_id' FROM mcp_servers s WHERE tenant_id=$1 AND id=$2 AND archived_at IS NULL",&[tenant,&id(p.get("id").ok_or_else(invalid)?)?]).await?.ok_or(Fault(404,"mcp_server_not_found"))?;
            Ok(row.get(0))
        }
        _ if path.starts_with("/v1/approvals/") => {
            let row=client.query_opt("SELECT to_jsonb(a)-'args_fp'-'tenant_id' FROM approvals a WHERE tenant_id=$1 AND id=$2",&[tenant,&id(p.get("id").ok_or_else(invalid)?)?]).await?.ok_or(Fault(404,"approval_not_found"))?;
            Ok(row.get(0))
        }
        _ => Err(Fault(404, "not_found")),
    }
}
async fn record(
    tx: &tokio_postgres::Transaction<'_>,
    actor: &ControlActor,
    action: &str,
    target: &str,
    before: Option<Value>,
    after: Option<Value>,
) -> Result<()> {
    control_audit::record(
        tx,
        &actor.tenant_id,
        &actor.audit,
        Change {
            action,
            target_type: "mcp",
            target_id: target.into(),
            before,
            after,
        },
    )
    .await?;
    Ok(())
}
#[allow(clippy::too_many_arguments)] // Retain authenticated Claims and the header for verified session provenance.
async fn write(
    state: &AppState,
    actor: &ControlActor,
    claims: &Claims,
    headers: &HeaderMap,
    path: &str,
    method: &Method,
    p: &HashMap<String, String>,
    v: &mut Value,
) -> Result<Value> {
    let pool = state.pg.as_ref().ok_or(Fault(503, "no_control_plane"))?;
    let l = crate::mcp_policy::settings()?;
    if path.starts_with("/v1/mcp-servers") {
        return server_write(state, actor, path, method, p, v).await;
    }
    if path.starts_with("/v1/approvals/") && (path.ends_with("/approve") || path.ends_with("/deny"))
    {
        fields(v, &["note", "descriptor_digest"])?;
        let note = match v.get("note") {
            None | Some(Value::Null) => "",
            Some(Value::String(s)) => s,
            _ => return Err(invalid()),
        };
        let echo = match v.get("descriptor_digest") {
            None | Some(Value::Null) => None,
            Some(Value::String(s)) => Some(s.as_str()),
            _ => return Err(invalid()),
        };
        if note.chars().count() > l.approvals.note_max_chars {
            return Err(invalid());
        }
        let approval = id(p.get("id").ok_or_else(invalid)?)?;
        let timeout = std::time::Duration::from_secs(l.limits.call_timeout_secs);
        if let Some(result) = tokio::time::timeout(
            timeout,
            protected_decision(
                state,
                claims,
                headers,
                approval,
                Some(path.ends_with("/approve")),
                note,
                echo,
            ),
        )
        .await
        .map_err(|_| Fault(503, "approval_unavailable"))??
        {
            return Ok(result);
        }
    }
    let mut client = pool.get().await?;
    let tx = client.transaction().await?;
    let tenant = actor.tenant_id.as_uuid();
    tx.query_one("SELECT id FROM tenants WHERE id=$1 FOR UPDATE", &[tenant])
        .await?;
    let mut wake = None;
    let result = match path {
        "/v1/mcp-policy" => {
            let policy: crate::mcp_policy::Policy =
                serde_json::from_value(v.clone()).map_err(|_| invalid())?;
            if policy.default_action == crate::mcp_policy::Action::RequireApproval {
                return Err(invalid());
            }
            let before = tx
                .query_opt(
                    "SELECT to_jsonb(p)-'tenant_id' FROM mcp_policy p WHERE tenant_id=$1",
                    &[tenant],
                )
                .await?
                .map(|r| r.get(0));
            tx.execute("INSERT INTO mcp_policy(tenant_id,rules_mode,pins_mode,injection_mode,default_action,updated_by) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(tenant_id) DO UPDATE SET rules_mode=$2,pins_mode=$3,injection_mode=$4,default_action=$5,updated_by=$6,updated_at=now()",&[tenant,&text(v,"rules_mode")?,&text(v,"pins_mode")?,&text(v,"injection_mode")?,&text(v,"default_action")?,&actor.audit.sub]).await?;
            record(
                &tx,
                actor,
                "mcp_policy.update",
                &tenant.to_string(),
                before,
                Some(v.clone()),
            )
            .await?;
            v.clone()
        }
        "/v1/mcp-tool-rules" | "/v1/approval-rules" => {
            let model = path == "/v1/approval-rules";
            fields(
                v,
                if model {
                    &["model_glob", "key_id", "ttl_secs"]
                } else {
                    &["server_id", "key_id", "tool_glob", "action", "reason"]
                },
            )?;
            let glob = text(v, if model { "model_glob" } else { "tool_glob" })?;
            if !crate::mcp_policy::valid_glob(glob) {
                return Err(Fault(
                    400,
                    if model {
                        "invalid_field:model_glob"
                    } else {
                        "invalid_field:tool_glob"
                    },
                ));
            }
            let key = optional_id(v, "key_id")?;
            let server = optional_id(v, "server_id")?;
            if let Some(key) = key
                && tx.query_opt("SELECT id FROM api_keys WHERE tenant_id=$1 AND id=$2 AND revoked_at IS NULL",&[tenant,&key]).await?.is_none(){return Err(Fault(404,"key_not_found"))}
            if let Some(server) = server
                && tx.query_opt("SELECT id FROM mcp_servers WHERE tenant_id=$1 AND id=$2 AND archived_at IS NULL",&[tenant,&server]).await?.is_none(){return Err(Fault(404,"mcp_server_not_found"))}
            let count: i64 = tx
                .query_one(
                    if model {
                        "SELECT count(*) FROM approval_rules WHERE tenant_id=$1"
                    } else {
                        "SELECT count(*) FROM mcp_tool_rules WHERE tenant_id=$1"
                    },
                    &[tenant],
                )
                .await?
                .get(0);
            if count >= l.policy.max_rules_per_workspace as i64 {
                return Err(Fault(409, "mcp_rule_limit"));
            }
            let rule = Uuid::new_v4();
            if model {
                let ttl = v
                    .get("ttl_secs")
                    .filter(|v| !v.is_null())
                    .map(|v| {
                        v.as_i64()
                            .filter(|n| *n > 0 && *n <= i64::from(l.approvals.max_ttl_secs))
                            .map(|n| n as i32)
                            .ok_or_else(invalid)
                    })
                    .transpose()?;
                tx.execute("INSERT INTO approval_rules(id,tenant_id,model_glob,key_id,ttl_secs,created_by) VALUES($1,$2,$3,$4,$5,$6)",&[&rule,tenant,&glob,&key,&ttl,&actor.audit.sub]).await?;
            } else {
                let action = text(v, "action")?;
                if !["allow", "deny", "require_approval"].contains(&action) {
                    return Err(invalid());
                }
                let reason = v.get("reason").and_then(Value::as_str).unwrap_or_default();
                if reason.chars().count() > l.policy.reason_max_chars {
                    return Err(invalid());
                }
                tx.execute("INSERT INTO mcp_tool_rules(id,tenant_id,server_id,key_id,tool_glob,action,reason,created_by) VALUES($1,$2,$3,$4,$5,$6,$7,$8)",&[&rule,tenant,&server,&key,&glob,&action,&reason,&actor.audit.sub]).await?;
            }
            record(
                &tx,
                actor,
                if model {
                    "approval_rule.create"
                } else {
                    "mcp_tool_rule.create"
                },
                &rule.to_string(),
                None,
                Some(v.clone()),
            )
            .await?;
            json!({"id":rule})
        }
        "/v1/approvals/settings" => {
            fields(v, &["require_second_approver", "default_ttl_secs"])?;
            let settings: crate::mcp_store::ApprovalSettings =
                serde_json::from_value(v.clone()).map_err(|_| invalid())?;
            if settings.default_ttl_secs <= 0
                || settings.default_ttl_secs > l.approvals.max_ttl_secs
            {
                return Err(invalid());
            }
            let before = tx
                .query_opt(
                    "SELECT to_jsonb(s)-'tenant_id' FROM approval_settings s WHERE tenant_id=$1",
                    &[tenant],
                )
                .await?
                .map(|r| r.get(0));
            tx.execute("INSERT INTO approval_settings(tenant_id,require_second_approver,default_ttl_secs,updated_by) VALUES($1,$2,$3,$4) ON CONFLICT(tenant_id) DO UPDATE SET require_second_approver=$2,default_ttl_secs=$3,updated_by=$4,updated_at=now()",&[tenant,&settings.require_second_approver,&settings.default_ttl_secs,&actor.audit.sub]).await?;
            record(
                &tx,
                actor,
                "approval.settings.update",
                &tenant.to_string(),
                before,
                Some(v.clone()),
            )
            .await?;
            v.clone()
        }
        "/v1/mcp-tools/approve" => {
            fields(v, &["server_id", "tool_name", "def_hash"])?;
            let server = id(text(v, "server_id")?)?;
            let name = text(v, "tool_name")?;
            let hash = text(v, "def_hash")?;
            let row=tx.query_opt("SELECT def_hash FROM mcp_tool_defs WHERE tenant_id=$1 AND server_id=$2 AND tool_name=$3 AND def_hash=$4 FOR UPDATE",&[tenant,&server,&name,&hash]).await?.ok_or(Fault(404,"tool_observation_not_found"))?;
            let stored: String = row.get(0);
            let before=tx.query_opt("SELECT to_jsonb(d)-'tenant_id' FROM mcp_tool_defs d WHERE tenant_id=$1 AND server_id=$2 AND tool_name=$3 AND status='approved'",&[tenant,&server,&name]).await?.map(|r|r.get::<_,Value>(0));
            tx.execute("UPDATE mcp_tool_defs SET status='observed',approved_by=NULL,approved_at=NULL WHERE tenant_id=$1 AND server_id=$2 AND tool_name=$3 AND status='approved'",&[tenant,&server,&name]).await?;
            tx.execute("UPDATE mcp_tool_defs SET status='approved',approved_by=$5,approved_at=now() WHERE tenant_id=$1 AND server_id=$2 AND tool_name=$3 AND def_hash=$4",&[tenant,&server,&name,&stored,&actor.audit.sub]).await?;
            record(
                &tx,
                actor,
                "mcp_tool.approve",
                name,
                before,
                Some(json!({"server_id":server,"tool_name":name,"def_hash":stored})),
            )
            .await?;
            json!({"approved":true})
        }
        _ if path.starts_with("/v1/approvals/") => {
            fields(v, &["note"])?;
            let note = v.get("note").and_then(Value::as_str).unwrap_or_default();
            if note.chars().count() > l.approvals.note_max_chars {
                return Err(invalid());
            }
            let approval = id(p.get("id").ok_or_else(invalid)?)?;
            let approve = path.ends_with("/approve");
            let r=tx.query_opt("SELECT status,expires_at,requester_creator FROM approvals WHERE action_id IS NULL AND tenant_id=$1 AND id=$2 FOR UPDATE",&[tenant,&approval]).await?.ok_or(Fault(404,"approval_not_found"))?;
            if r.get::<_, chrono::DateTime<chrono::Utc>>(1) <= chrono::Utc::now() {
                return Err(Fault(409, "approval_expired"));
            }
            if r.get::<_, String>(0) != "pending" {
                return Err(Fault(409, "approval_not_pending"));
            }
            let second = tx
                .query_opt(
                    "SELECT require_second_approver FROM approval_settings WHERE tenant_id=$1",
                    &[tenant],
                )
                .await?
                .is_some_and(|r| r.get(0));
            if second
                && r.get::<_, Option<String>>(2)
                    .is_none_or(|s| s == actor.audit.sub)
            {
                return Err(Fault(403, "self_approval_forbidden"));
            }
            let status = if approve { "approved" } else { "denied" };
            let n=tx.execute("UPDATE approvals SET status=$3,decided_by=$4,decided_at=clock_timestamp(),decision_note=$5,grant_expires_at=CASE WHEN $3='approved' THEN clock_timestamp()+make_interval(secs=>$6::double precision) ELSE NULL END WHERE action_id IS NULL AND tenant_id=$1 AND id=$2 AND status='pending' AND expires_at>clock_timestamp()",&[tenant,&approval,&status,&actor.audit.sub,&note,&f64::from(l.approvals.grant_ttl_secs)]).await?;
            if n != 1 {
                return Err(Fault(409, "approval_not_pending"));
            }
            record(
                &tx,
                actor,
                if approve {
                    "approval.approve"
                } else {
                    "approval.deny"
                },
                &approval.to_string(),
                Some(json!({"status":"pending"})),
                Some(json!({"status":status})),
            )
            .await?;
            wake = Some(approval);
            json!({"id":approval,"status":status})
        }
        _ if path.starts_with("/v1/mcp-tools/") => {
            let server = id(p.get("server_id").ok_or_else(invalid)?)?;
            let tool = p.get("tool_name").ok_or_else(invalid)?;
            let before=tx.query_opt("SELECT to_jsonb(d)-'tenant_id' FROM mcp_tool_defs d WHERE tenant_id=$1 AND server_id=$2 AND tool_name=$3 AND status='approved'",&[tenant,&server,&tool]).await?.map(|r|r.get::<_,Value>(0));
            let n=tx.execute("UPDATE mcp_tool_defs SET status='observed',approved_by=NULL,approved_at=NULL WHERE tenant_id=$1 AND server_id=$2 AND tool_name=$3 AND status='approved'",&[tenant,&server,&tool]).await?;
            if n == 0 {
                return Err(Fault(404, "tool_pin_not_found"));
            }
            record(
                &tx,
                actor,
                "mcp_tool.unpin",
                tool,
                before,
                Some(json!({"status":"observed"})),
            )
            .await?;
            json!({"removed":true})
        }
        _ if path.starts_with("/v1/mcp-tool-rules/") || path.starts_with("/v1/approval-rules/") => {
            let rule = id(p.get("id").ok_or_else(invalid)?)?;
            let model = path.starts_with("/v1/approval-rules/");
            let row=tx.query_opt(if model{"DELETE FROM approval_rules WHERE tenant_id=$1 AND id=$2 RETURNING to_jsonb(approval_rules)-'tenant_id'"}else{"DELETE FROM mcp_tool_rules WHERE tenant_id=$1 AND id=$2 RETURNING to_jsonb(mcp_tool_rules)-'tenant_id'"},&[tenant,&rule]).await?.ok_or(Fault(404,"rule_not_found"))?;
            record(
                &tx,
                actor,
                if model {
                    "approval_rule.delete"
                } else {
                    "mcp_tool_rule.delete"
                },
                &rule.to_string(),
                Some(row.get(0)),
                None,
            )
            .await?;
            json!({"removed":true})
        }
        _ => return Err(Fault(404, "not_found")),
    };
    tx.commit().await?;
    if let Some(id) = wake {
        crate::approvals::wake(id);
    }
    Ok(result)
}
async fn server_write(
    state: &AppState,
    actor: &ControlActor,
    path: &str,
    method: &Method,
    p: &HashMap<String, String>,
    v: &mut Value,
) -> Result<Value> {
    use secrecy::{ExposeSecret, SecretString};
    let pool = state.pg.as_ref().ok_or(Fault(503, "no_control_plane"))?;
    let mut client = pool.get().await?;
    let tenant = actor.tenant_id.as_uuid();
    let target = if let Some(raw) = p.get("id") {
        id(raw)?
    } else {
        Uuid::new_v4()
    };
    let previous = if p.contains_key("id") {
        Some(client.query_opt("SELECT to_jsonb(s)-'tenant_id' FROM mcp_servers s WHERE tenant_id=$1 AND id=$2 AND archived_at IS NULL",&[tenant,&target]).await?.ok_or(Fault(404,"mcp_server_not_found"))?.get::<_,Value>(0))
    } else {
        None
    };
    #[cfg(all(test, debug_assertions))]
    crate::mcp_security_tests::after_server_read(target).await;
    if path.ends_with("/test") {
        let snapshot = crate::mcp_store::load(&client, tenant).await?;
        let server = snapshot
            .servers
            .iter()
            .find(|s| s.id == target)
            .ok_or(Fault(404, "mcp_server_not_found"))?;
        if server.auth_mode == "passthrough" {
            return Err(Fault(400, "client_credential_required"));
        }
        let secret =
            crate::mcp_proxy::credential(&snapshot, server, &actor.tenant_id, &HeaderMap::new())
                .await
                .map_err(|c| Fault(503, c))?;
        let reply = crate::mcp_proxy::discover(server, secret.as_ref())
            .await
            .map_err(|c| Fault(502, c))?;
        let tools = reply["result"]["tools"]
            .as_array()
            .ok_or(Fault(502, "invalid_mcp_response"))?;
        return Ok(
            json!({"tools":tools.len(),"tool_names":tools.iter().filter_map(|t|t["name"].as_str()).collect::<Vec<_>>()}),
        );
    }
    if method == Method::DELETE {
        let tx = client.transaction().await?;
        let n=tx.execute("UPDATE mcp_servers SET archived_at=now(),enabled=false,credential_ct=NULL,auth_mode='none',credential_last4=NULL WHERE tenant_id=$1 AND id=$2 AND archived_at IS NULL",&[tenant,&target]).await?;
        if n != 1 {
            return Err(Fault(404, "mcp_server_not_found"));
        }
        record(
            &tx,
            actor,
            "mcp_server.archive",
            &target.to_string(),
            Some(json!({"enabled":previous.as_ref().and_then(|p|p.get("enabled"))})),
            Some(json!({"archived":true})),
        )
        .await?;
        tx.commit().await?;
        return Ok(json!({"archived":true}));
    }
    fields(
        v,
        &[
            "slug",
            "name",
            "url",
            "transport",
            "auth_mode",
            "credential_kind",
            "credential_header",
            "credential",
            "enabled",
        ],
    )?;
    let secret = match v.as_object_mut().and_then(|o| o.remove("credential")) {
        Some(Value::String(s)) if !s.is_empty() => Some(SecretString::from(s)),
        None | Some(Value::Null) => None,
        _ => return Err(invalid()),
    };
    let mut merged=previous.clone().unwrap_or_else(||json!({"transport":"streamable_http","auth_mode":"none","credential_kind":"bearer","enabled":true}));
    if let (Some(to), Some(from)) = (merged.as_object_mut(), v.as_object()) {
        for (k, val) in from {
            to.insert(k.clone(), val.clone());
        }
    }
    let slug = text(&merged, "slug")?;
    if slug.is_empty()
        || slug.len() > crate::mcp_policy::settings()?.limits.max_slug_chars
        || !slug
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
    {
        return Err(invalid());
    }
    let name = text(&merged, "name")?;
    let url = text(&merged, "url")?;
    let transport = text(&merged, "transport")?;
    let auth_mode = text(&merged, "auth_mode")?;
    let kind = text(&merged, "credential_kind")?;
    let l = crate::mcp_policy::settings()?;
    if name.trim().is_empty()
        || name.chars().count() > l.limits.max_name_chars
        || url.len() > l.limits.max_url_bytes
        || !["streamable_http", "legacy_sse"].contains(&transport)
        || !["none", "gateway_held", "passthrough"].contains(&auth_mode)
        || !["bearer", "header"].contains(&kind)
    {
        return Err(invalid());
    }
    crate::mcp_proxy::safe_client(url)
        .await
        .map_err(|_| Fault(400, "ssrf_blocked"))?;
    let header = merged
        .get("credential_header")
        .and_then(Value::as_str)
        .map(str::to_ascii_lowercase);
    if kind == "header"
        && !header.as_deref().is_some_and(|h| {
            h.starts_with("x-")
                && !h.starts_with("x-tracelane-")
                && !h.starts_with("x-forwarded-")
                && axum::http::HeaderName::from_bytes(h.as_bytes()).is_ok()
        })
    {
        return Err(invalid());
    }
    let enabled = merged
        .get("enabled")
        .and_then(Value::as_bool)
        .ok_or_else(invalid)?;
    let vault = crate::kms::KeyVault::global()
        .map_err(|_| Fault(503, "upstream_credential_unavailable"))?;
    let revision = vault.revision(&actor.tenant_id);
    let (ct, last4) = if auth_mode == "gateway_held" {
        if let Some(secret) = secret {
            let master =
                crate::byok::master_key().ok_or(Fault(503, "upstream_credential_unavailable"))?;
            let config = crate::kms::vault::load(&**client, &actor.tenant_id, master)
                .await
                .map_err(|_| Fault(503, "upstream_credential_unavailable"))?;
            let ct = vault
                .seal(
                    config.as_ref(),
                    &actor.tenant_id,
                    &format!("mcp-server-credential:{target}"),
                    &secret,
                    master,
                )
                .await
                .map_err(|_| Fault(503, "upstream_credential_unavailable"))?;
            let last4 = secret
                .expose_secret()
                .chars()
                .rev()
                .take(4)
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect::<String>();
            (Some(ct), Some(last4))
        } else {
            (
                Some(text(&merged, "credential_ct")?.to_owned()),
                merged
                    .get("credential_last4")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
            )
        }
    } else {
        (None, None)
    };
    let _fence = vault
        .lock(&actor.tenant_id)
        .await
        .map_err(|_| Fault(503, "upstream_credential_unavailable"))?;
    vault
        .check_revision(&actor.tenant_id, revision)
        .map_err(|_| Fault(409, "credential_configuration_changed"))?;
    let tx = client.transaction().await?;
    tx.query_one("SELECT id FROM tenants WHERE id=$1 FOR UPDATE", &[tenant])
        .await?;
    if let Some(previous) = &previous {
        let current=tx.query_opt("SELECT to_jsonb(s)-'tenant_id' FROM mcp_servers s WHERE tenant_id=$1 AND id=$2 AND archived_at IS NULL FOR UPDATE",&[tenant,&target]).await?.ok_or(Fault(409,"mcp_server_changed"))?;
        if current.get::<_, Value>(0) != *previous {
            return Err(Fault(409, "mcp_server_changed"));
        }
    }
    if previous.is_none() {
        let count: i64 = tx
            .query_one(
                "SELECT count(*) FROM mcp_servers WHERE tenant_id=$1 AND archived_at IS NULL",
                &[tenant],
            )
            .await?
            .get(0);
        if count >= l.limits.max_servers_per_workspace as i64 {
            return Err(Fault(409, "mcp_server_limit"));
        }
    }
    tx.execute("INSERT INTO mcp_servers(id,tenant_id,slug,name,url,transport,auth_mode,credential_kind,credential_header,credential_ct,credential_last4,enabled) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) ON CONFLICT(id) DO UPDATE SET slug=$3,name=$4,url=$5,transport=$6,auth_mode=$7,credential_kind=$8,credential_header=$9,credential_ct=$10,credential_last4=$11,enabled=$12,updated_at=now() WHERE mcp_servers.tenant_id=$2 AND mcp_servers.archived_at IS NULL",&[&target,tenant,&slug,&name,&url,&transport,&auth_mode,&kind,&header,&ct,&last4,&enabled]).await?;
    let public = json!({"id":target,"slug":slug,"name":name,"url":url,"transport":transport,"auth_mode":auth_mode,"credential_kind":kind,"credential_header":header,"credential_last4":last4,"enabled":enabled});
    let before = previous.map(|mut p| {
        if let Some(o) = p.as_object_mut() {
            o.remove("credential_ct");
        }
        p
    });
    record(
        &tx,
        actor,
        if before.is_some() {
            "mcp_server.update"
        } else {
            "mcp_server.create"
        },
        &target.to_string(),
        before,
        Some(public.clone()),
    )
    .await?;
    tx.commit().await?;
    Ok(public)
}

async fn preview(
    state: &AppState,
    actor: &ControlActor,
    q: &HashMap<String, String>,
) -> Result<Value> {
    let limits = &crate::mcp_policy::settings()?.policy;
    let now = chrono::Utc::now();
    let since = q
        .get("since")
        .map(|s| {
            chrono::DateTime::parse_from_rfc3339(s)
                .map(|d| d.with_timezone(&chrono::Utc))
                .map_err(|_| invalid())
        })
        .transpose()?
        .unwrap_or(now - chrono::Duration::hours(limits.preview_window_hours));
    if since > now || since < now - chrono::Duration::hours(limits.preview_max_window_hours) {
        return Err(invalid());
    }
    let unavailable = || json!({"since":since,"would_block":null,"stats_unavailable":true});
    let Some(url) = &state.quota_ch_url else {
        return Ok(unavailable());
    };
    let tier =
        crate::clickhouse_query::tier_for_tenant(state.entitlements.as_ref(), &actor.tenant_id)
            .await;
    let sql=crate::clickhouse_query::TenantQuery::new("SELECT toUInt64(countIf(JSONExtractBool(attributes,'tracelane.mcp.would_block'))) AS would_block FROM spans FINAL WHERE tenant_id=? AND start_time>=fromUnixTimestamp64Milli(?)",tier).with_log_comment(format!("tenant_id={}",actor.tenant_id)).sql_with_settings();
    #[derive(serde::Deserialize, clickhouse::Row)]
    struct Counts {
        would_block: u64,
    }
    let row = crate::clickhouse_query::ch_client(url)
        .query(&sql)
        .bind(actor.tenant_id.to_string())
        .bind(since.timestamp_millis())
        .fetch_one::<Counts>()
        .await;
    Ok(match row {
        Ok(row) => json!({"since":since,"would_block":row.would_block,"stats_unavailable":false}),
        Err(_) => unavailable(),
    })
}

#[cfg(all(test, debug_assertions))]
#[path = "mcp_routes_fix_tests.rs"]
mod fix_tests;

// Keep validated Claims: ControlActor's display labels are not authorization facts.
/// # Errors
/// Fail-CLOSED: no control plane, an unresolved flag or an unverifiable session is a
/// 503; a refused human is the decision's own 403. No pooled connection is held
/// across the entitlement resolve or the session (JWKS) check.
async fn protected_decision(
    state: &AppState,
    claims: &Claims,
    headers: &HeaderMap,
    id: Uuid,
    decision: Option<bool>,
    note: &str,
    echo: Option<&str>,
) -> Result<Option<Value>> {
    // A digest we cannot honour (flag off, or not a protected row) is refused, never ignored.
    let unsupported = echo.map_or(Ok(None), |_| Err(Fault(400, "descriptor_unsupported")));
    // Explicit cached OFF preserves legacy approve/deny without a bound-row probe.
    if state
        .entitlements
        .as_ref()
        .and_then(|cache| cache.cached_resolved(*claims.tenant_id.as_uuid()))
        .is_some_and(|r| !crate::action_control::enabled(Some(&r)))
    {
        return unsupported;
    }
    let pool = state.pg.as_ref().ok_or(Fault(503, "no_control_plane"))?;
    let protected_row = pool
        .get()
        .await?
        .query_opt(
            "SELECT 1 FROM approvals WHERE tenant_id=$1 AND id=$2 AND action_id IS NOT NULL",
            &[claims.tenant_id.as_uuid(), &id],
        )
        .await?
        .is_some();
    if !protected_row {
        return unsupported;
    }
    let resolved = match &state.entitlements {
        Some(cache) => cache.resolved(*claims.tenant_id.as_uuid()).await,
        None => return Err(Fault(503, "approval_unavailable")),
    };
    if !crate::action_control::enabled(Some(&resolved)) {
        return Err(Fault(503, "action_control_disabled"));
    }
    let session = if decision.is_some() {
        // Claims proves role, but only re-verifying this header proves a session.
        crate::auth::verified_session(
            headers
                .get(axum::http::header::AUTHORIZATION)
                .and_then(|h| h.to_str().ok())
                .unwrap_or_default(),
        )
        .await
        .map_err(|_| Fault(503, "approval_unavailable"))?
    } else {
        None
    };
    let mut db = pool.get().await?;
    let tx = db.transaction().await?;
    crate::action_control::execution::deadline_tx(
        &tx,
        std::time::Duration::from_secs(crate::mcp_policy::settings()?.limits.call_timeout_secs),
    )
    .await?;
    let (code, rows) = if let Some(approve) = decision {
        crate::approvals::protected::decide_echo_tx(
            &tx,
            claims,
            Some(&resolved),
            id,
            approve,
            note,
            session.as_ref().map(|(sid, _)| sid.as_str()),
            echo,
        )
        .await?
    } else {
        (
            Some("unauthorized"),
            crate::approvals::protected::reject_attempt_tx(&tx, claims, Some(&resolved), id)
                .await?,
        )
    };
    tx.commit().await?;
    crate::action_control::execution::after_commit(
        Some(&state.audit_chain),
        claims,
        vec![rows],
        std::time::Duration::from_secs(crate::mcp_policy::settings()?.limits.call_timeout_secs),
    );
    if let Some(code) = code {
        return Err(Fault(
            if matches!(code, "unauthorized" | "separation_required") {
                403
            } else {
                409
            },
            code,
        ));
    }
    Ok(Some(
        json!({"id":id,"status":if decision == Some(true) {"approved"}else{"denied"}}),
    ))
}
