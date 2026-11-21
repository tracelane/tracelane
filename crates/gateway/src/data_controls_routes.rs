//! Workspace retention controls. Tenant and capability come from validated claims.
use crate::{
    auth::{Claims, capability::Capability},
    server::AppState,
};
use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, put},
};
use serde::Deserialize;
use serde_json::{Value, json};

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/v1/data-controls", get(read))
        .route("/v1/data-controls/retention", put(write))
        .with_state(state)
}
fn error(status: StatusCode, code: &str) -> Response {
    (
        status,
        Json(json!({"error":code,"message":code.replace('_', " ")})),
    )
        .into_response()
}
async fn claims(headers: &HeaderMap) -> Result<Claims, Response> {
    crate::auth::validate_authorization(
        headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default(),
    )
    .await
    .map_err(|_| error(StatusCode::UNAUTHORIZED, "unauthorized"))
}
const READ_SQL: &str = concat!(
    "SELECT dc.retention_days, COALESCE(we.queryable_days, pa.queryable_days)::int AS plan_days, COALESCE(we.f_audit_addon, pe.f_audit_addon, false) AS audit_addon FROM tenants t JOIN plan_entitlements pe ON pe.plan_lookup_key=t.plan::text || '_v1' LEFT JOIN workspace_entitlements we ON we.tenant_id=t.id ",
    crate::entitlement_cache::allowance_pin_join!(
        "COALESCE(we.plan_lookup_key, pe.plan_lookup_key)",
        "clock_timestamp()"
    ),
    " LEFT JOIN workspace_data_controls dc ON dc.tenant_id=t.id WHERE t.id=$1 AND t.archived_at IS NULL"
);

/// The workspace's STORED retention choice (`None` = the plan default), through the same
/// statement `GET /v1/data-controls` runs. A workspace with no plan row has no readable
/// retention at all — an error here, as the route answers `retention_unavailable`.
///
/// # Errors
/// A statement failure, or no plan row for the tenant. Fail-CLOSED.
pub(crate) async fn stored_retention_days(
    client: &(impl tokio_postgres::GenericClient + Sync),
    tenant: &uuid::Uuid,
) -> anyhow::Result<Option<i32>> {
    let row = client
        .query_opt(READ_SQL, &[tenant])
        .await?
        .ok_or_else(|| anyhow::anyhow!("retention_unavailable: no plan row for the workspace"))?;
    Ok(row.get::<_, Option<i32>>("retention_days"))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RetentionBody {
    #[serde(deserialize_with = "required_days")]
    days: Option<i32>,
    confirm: Option<String>,
}
fn required_days<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<i32>, D::Error> {
    Option::deserialize(d)
}
fn validate(
    body: &RetentionBody,
    current: i32,
    plan: i32,
    min: i32,
    max: i32,
) -> Result<i32, &'static str> {
    let days = body.days.unwrap_or(plan);
    if plan <= 0 {
        return Err("retention_unavailable");
    }
    if days < min {
        return Err("retention_below_floor");
    }
    if days > plan || days > max {
        return Err("retention_above_plan");
    }
    if days < current
        && body.confirm.as_deref() != Some(format!("delete data older than {days} days").as_str())
    {
        return Err("confirmation_required");
    }
    Ok(days)
}
async fn view(state: &AppState, claims: &Claims) -> Result<Value, Response> {
    let unavailable = || error(StatusCode::SERVICE_UNAVAILABLE, "retention_unavailable");
    let policy = state
        .rate_card
        .load()
        .policy
        .data_controls
        .ok_or_else(unavailable)?;
    let pool = state.pg.as_ref().ok_or_else(unavailable)?;
    let client = pool.get().await.map_err(|_| unavailable())?;
    let row = client
        .query_opt(READ_SQL, &[claims.tenant_id.as_uuid()])
        .await
        .map_err(|_| unavailable())?
        .ok_or_else(unavailable)?;
    let plan: i32 = row
        .get::<_, Option<i32>>("plan_days")
        .filter(|n| *n > 0)
        .ok_or_else(unavailable)?;
    let stored: Option<i32> = row.get("retention_days");
    let min = if row.get::<_, bool>("audit_addon") {
        policy.audit_addon_min_days
    } else {
        policy.retention_days_min
    };
    if min > plan {
        return Err(unavailable());
    }
    let keys = client.query("SELECT id::text, name, key_prefix, capture FROM api_keys WHERE tenant_id=$1 AND (revoked_at IS NULL OR revoked_at > now()) AND (expires_at IS NULL OR expires_at > now()) ORDER BY created_at", &[claims.tenant_id.as_uuid()]).await.map_err(|_| unavailable())?;
    let keys: Vec<Value> = keys.iter().map(|r| json!({"id":r.get::<_,String>(0),"name":r.get::<_,String>(1),"prefix":r.get::<_,String>(2),"capture":r.get::<_,Option<Value>>(3)})).collect();
    let capture = crate::server::config::content_capture_for(
        state.entitlements.as_deref(),
        &claims.tenant_id,
    )
    .await;
    let mode = if state.quota_ch_url.is_some() {
        crate::retention_sweep::SweepMode::from_env()
    } else {
        crate::retention_sweep::SweepMode::Off
    };
    let mode_name = match mode {
        crate::retention_sweep::SweepMode::Off => "off",
        crate::retention_sweep::SweepMode::DryRun => "dryrun",
        crate::retention_sweep::SweepMode::Enforce => "enforce",
    };
    Ok(
        json!({"retention":{"days":stored,"effective_days":stored.unwrap_or(plan).min(plan).max(min.min(plan)),"plan_days":plan,"min_days":min,"max_days":plan.min(policy.retention_days_max)},
        "capture":{"input":capture.input,"output":capture.output},"keys":keys,
        "key_overrides_count":keys.iter().filter(|k| !k["capture"].is_null()).count(),
        "sweep":{"mode":mode_name,"enforced":mode == crate::retention_sweep::SweepMode::Enforce,"next_sweep_at": if mode == crate::retention_sweep::SweepMode::Off {None} else {Some((chrono::Utc::now()+chrono::Duration::seconds(crate::retention_sweep::secs_until_next_retention_slot(chrono::Utc::now()) as i64)).to_rfc3339())}},
        "routes":crate::zdr::bindings(),"can_edit":claims.can(Capability::EditPolicies)}),
    )
}
async fn read(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let claims = match claims(&headers).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    if let Err(e) =
        crate::control_plane::require_control(&claims, Capability::ViewSettings, &headers).await
    {
        return e.into_response();
    }
    match view(&state, &claims).await {
        Ok(v) => Json(v).into_response(),
        Err(r) => r,
    }
}
async fn save_retention(
    pool: &crate::db::DbPool,
    claims: &Claims,
    control: &crate::control_plane::ControlActor,
    body: &RetentionBody,
    policy: crate::db::data_controls::Policy,
) -> anyhow::Result<bool> {
    let mut client = pool.get().await?;
    let tx = client.transaction().await?;
    let changed = save_retention_in_tx(&tx, claims, control, body, policy).await?;
    if changed {
        tx.commit().await?;
    }
    Ok(changed)
}

/// Retain the retention-sweep lock and plan validation inside the caller's transaction.
#[tracing::instrument(skip_all, fields(tenant_id = %claims.tenant_id))]
pub(crate) async fn save_retention_in_tx(
    tx: &deadpool_postgres::Transaction<'_>,
    claims: &Claims,
    control: &crate::control_plane::ControlActor,
    body: &RetentionBody,
    policy: crate::db::data_controls::Policy,
) -> anyhow::Result<bool> {
    crate::db::controls::lock_config(tx, &claims.tenant_id).await?;
    let key = crate::retention_sweep::retention_lock_key(tx, &claims.tenant_id.to_string()).await?;
    let acquired: bool = tx
        .query_one("SELECT pg_try_advisory_xact_lock($1)", &[&key])
        .await?
        .get(0);
    if !acquired {
        anyhow::bail!("retention_unavailable");
    }
    tx.query_one(
        "SELECT id FROM tenants WHERE id=$1 AND archived_at IS NULL",
        &[claims.tenant_id.as_uuid()],
    )
    .await?;
    let row = tx
        .query_one(READ_SQL, &[claims.tenant_id.as_uuid()])
        .await?;
    let plan: i32 = row
        .get::<_, Option<i32>>("plan_days")
        .ok_or_else(|| anyhow::anyhow!("retention_unavailable"))?;
    let previous: Option<i32> = row.get("retention_days");
    let min = if row.get::<_, bool>("audit_addon") {
        policy.audit_addon_min_days
    } else {
        policy.retention_days_min
    };
    validate(
        body,
        previous.unwrap_or(plan).min(plan).max(min.min(plan)),
        plan,
        min,
        policy.retention_days_max,
    )
    .map_err(|code| anyhow::anyhow!(code))?;
    if previous == body.days {
        return Ok(false);
    };
    tx.execute("INSERT INTO workspace_data_controls (tenant_id,retention_days,updated_by) VALUES ($1,$2,$3) ON CONFLICT (tenant_id) DO UPDATE SET retention_days=EXCLUDED.retention_days,updated_by=EXCLUDED.updated_by,updated_at=clock_timestamp()", &[claims.tenant_id.as_uuid(),&body.days,&claims.sub]).await?;
    crate::db::control_audit::record(
        tx,
        &claims.tenant_id,
        &control.audit,
        crate::db::control_audit::Change {
            action: "workspace.retention.set",
            target_type: "workspace",
            target_id: claims.tenant_id.to_string(),
            before: Some(json!({"days":previous})),
            after: Some(json!({"days":body.days})),
        },
    )
    .await?;
    Ok(true)
}
async fn write(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Result<Json<RetentionBody>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let claims = match claims(&headers).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let control =
        match crate::control_plane::require_control(&claims, Capability::EditPolicies, &headers)
            .await
        {
            Ok(c) => c,
            Err(d) => return d.into_response(),
        };
    let Ok(Json(body)) = body else {
        return error(StatusCode::BAD_REQUEST, "invalid_field");
    };
    let Some(policy) = state.rate_card.load().policy.data_controls else {
        return error(StatusCode::SERVICE_UNAVAILABLE, "retention_unavailable");
    };
    let Some(pool) = state.pg.as_ref() else {
        return error(StatusCode::SERVICE_UNAVAILABLE, "no_control_plane");
    };
    let result = save_retention(pool, &claims, &control, &body, policy).await;
    match result {
        Err(e) => {
            let code = e.to_string();
            match code.as_str() {
                "retention_below_floor" | "retention_above_plan" | "confirmation_required" => {
                    error(StatusCode::BAD_REQUEST, &code)
                }
                _ => error(StatusCode::SERVICE_UNAVAILABLE, "retention_unavailable"),
            }
        }
        Ok(changed) => {
            if let Some(cache) = state.entitlements.as_ref() {
                cache.invalidate(*claims.tenant_id.as_uuid()).await;
            }
            match view(&state, &claims).await {
                Err(r) => r,
                Ok(mut v) => {
                    v["changed"] = json!(changed);
                    v["rows_past_window"] = crate::retention_sweep::estimate(
                        &state,
                        &claims.tenant_id,
                        v["retention"]["effective_days"].as_i64().unwrap_or(0) as i32,
                        policy.estimate_row_cap,
                    )
                    .await;
                    Json(v).into_response()
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    #[ignore = "throwaway Postgres; POSTGRES_TEST_URL"]
    async fn og38_retention_is_tenant_isolated_and_audited() {
        let config: tokio_postgres::Config =
            std::env::var("POSTGRES_TEST_URL").unwrap().parse().unwrap();
        let pool = deadpool_postgres::Pool::builder(deadpool_postgres::Manager::new(
            config,
            tokio_postgres::NoTls,
        ))
        .max_size(1)
        .build()
        .unwrap();
        let a = uuid::Uuid::from_u128(38);
        let b = uuid::Uuid::from_u128(39);
        {
            let pg = pool.get().await.unwrap();
            pg.batch_execute("CREATE TEMP TABLE tenants(id uuid PRIMARY KEY,plan text,plan_version text,price_protected_until timestamptz,archived_at timestamptz);
                CREATE TEMP TABLE api_keys(id uuid PRIMARY KEY,tenant_id uuid);
                CREATE TEMP TABLE workspace_entitlements(tenant_id uuid,queryable_days int,plan_lookup_key text,f_audit_addon boolean);
                CREATE TEMP TABLE plan_entitlements(plan_lookup_key text,f_audit_addon boolean);
                CREATE TEMP TABLE plan_allowances(plan_lookup_key text,plan_version text,is_current boolean,queryable_days int);
                CREATE TEMP TABLE admin_audit_log(id bigserial,actor_user_id text,actor_workspace_id uuid,action text,target_type text,target_id text,before_json jsonb,after_json jsonb,ip_addr inet,user_agent text,request_id text,actor_role text,actor_auth_method text);
                INSERT INTO plan_entitlements VALUES('team_v1',false);
                INSERT INTO plan_allowances VALUES('team_v1','v3',true,730);").await.unwrap();
            // The actual migration must work before the first updated gateway boots.
            // Its persistent table is redirected to this session's temporary schema.
            pg.batch_execute(
                &include_str!("../../../apps/web/db/migrations/0078_og38_data_controls.sql")
                    .replace(
                        "CREATE TABLE IF NOT EXISTS workspace_data_controls",
                        "CREATE TEMP TABLE IF NOT EXISTS workspace_data_controls",
                    ),
            )
            .await
            .unwrap();
            pg.execute(
                "INSERT INTO tenants(id,plan) VALUES($1,'team'),($2,'team')",
                &[&a, &b],
            )
            .await
            .unwrap();
            pg.execute("INSERT INTO workspace_data_controls(tenant_id,retention_days,updated_by) VALUES($1,180,'b')", &[&b]).await.unwrap();
        }
        let mut claims = crate::auth::dev_stub_claims(crate::auth::AuthMethod::JwtBearer);
        claims.tenant_id = tracelane_shared::TenantId::from_jwt_claim(a);
        let control = crate::control_plane::ControlActor::for_test(claims.tenant_id.clone());
        let policy = crate::db::data_controls::Policy::embedded().unwrap();
        let reduction = body(Some(90), Some("delete data older than 90 days"));
        assert!(
            save_retention(&pool, &claims, &control, &reduction, policy)
                .await
                .unwrap()
        );
        assert!(
            !save_retention(&pool, &claims, &control, &reduction, policy)
                .await
                .unwrap()
        );
        {
            let pg = pool.get().await.unwrap();
            assert_eq!(
                pg.query_one(READ_SQL, &[&a])
                    .await
                    .unwrap()
                    .get::<_, Option<i32>>("retention_days"),
                Some(90)
            );
            assert_eq!(
                pg.query_one(READ_SQL, &[&b])
                    .await
                    .unwrap()
                    .get::<_, Option<i32>>("retention_days"),
                Some(180)
            );
            assert_eq!(
                pg.query_one(
                    "SELECT count(*) FROM admin_audit_log WHERE actor_workspace_id=$1",
                    &[&a]
                )
                .await
                .unwrap()
                .get::<_, i64>(0),
                1
            );
            pg.batch_execute("ALTER TABLE admin_audit_log ADD CONSTRAINT reject_test_audit CHECK(false) NOT VALID").await.unwrap();
        }
        assert!(
            save_retention(&pool, &claims, &control, &body(Some(100), None), policy)
                .await
                .is_err()
        );
        assert_eq!(
            pool.get()
                .await
                .unwrap()
                .query_one(READ_SQL, &[&a])
                .await
                .unwrap()
                .get::<_, Option<i32>>("retention_days"),
            Some(90),
            "audit failure rolls back retention"
        );
    }

    fn body(days: Option<i32>, confirm: Option<&str>) -> RetentionBody {
        RetentionBody {
            days,
            confirm: confirm.map(str::to_owned),
        }
    }
    #[test]
    fn og38_null_retention_uses_plan() {
        assert_eq!(validate(&body(None, None), 90, 730, 7, 3650), Ok(730));
    }
    #[test]
    fn og38_confirmed_reduction_accepted() {
        assert_eq!(
            validate(
                &body(Some(90), Some("delete data older than 90 days")),
                730,
                730,
                7,
                3650
            ),
            Ok(90)
        );
    }
    #[test]
    fn og38_retention_noop_is_idempotent() {
        assert_eq!(validate(&body(Some(90), None), 90, 730, 7, 3650), Ok(90));
    }
    #[test]
    fn og38_retention_increase_accepted() {
        assert_eq!(validate(&body(Some(100), None), 90, 730, 7, 3650), Ok(100));
    }
    #[test]
    fn og38_floor_is_inclusive() {
        assert_eq!(
            validate(
                &body(Some(7), Some("delete data older than 7 days")),
                30,
                30,
                7,
                3650
            ),
            Ok(7)
        );
    }
    #[test]
    fn og38_plan_ceiling_is_inclusive() {
        assert_eq!(validate(&body(Some(730), None), 90, 730, 7, 3650), Ok(730));
    }
    #[test]
    fn og38_owner_can_edit_retention() {
        let mut c = crate::auth::dev_stub_claims(crate::auth::AuthMethod::JwtBearer);
        c.role = Some(crate::auth::Role::Owner);
        assert!(c.can(Capability::EditPolicies));
    }
    #[test]
    fn og38_retention_requires_confirmation() {
        assert_eq!(
            validate(&body(Some(90), None), 730, 730, 7, 3650),
            Err("confirmation_required")
        );
    }
    #[test]
    fn og38_retention_confirmation_binds_days() {
        assert_eq!(
            validate(
                &body(Some(90), Some("delete data older than 91 days")),
                730,
                730,
                7,
                3650
            ),
            Err("confirmation_required")
        );
    }
    #[test]
    fn og38_retention_rejects_below_floor() {
        assert_eq!(
            validate(&body(Some(6), None), 730, 730, 7, 3650),
            Err("retention_below_floor")
        );
    }
    #[test]
    fn og38_retention_rejects_above_plan() {
        assert_eq!(
            validate(&body(Some(31), None), 30, 30, 7, 3650),
            Err("retention_above_plan")
        );
    }
    #[test]
    fn og38_retention_refuses_unknown_plan() {
        assert_eq!(
            validate(&body(Some(7), None), 0, 0, 7, 3650),
            Err("retention_unavailable")
        );
    }
    #[test]
    fn og38_retention_enforces_audit_floor() {
        assert_eq!(
            validate(&body(Some(90), None), 730, 730, 180, 3650),
            Err("retention_below_floor")
        );
    }
    #[test]
    fn og38_retention_body_rejects_missing_days() {
        assert!(serde_json::from_str::<RetentionBody>("{}").is_err());
    }
    #[test]
    fn og38_retention_body_rejects_tenant() {
        assert!(
            serde_json::from_str::<RetentionBody>(r#"{"days":90,"tenant_id":"foreign"}"#).is_err()
        );
    }
    #[test]
    fn og38_retention_denies_nonowner() {
        for role in [
            None,
            Some(crate::auth::Role::Member),
            Some(crate::auth::Role::Viewer),
        ] {
            let mut c = crate::auth::dev_stub_claims(crate::auth::AuthMethod::JwtBearer);
            c.role = role;
            assert!(!c.can(Capability::EditPolicies));
        }
        assert!(
            !crate::auth::dev_stub_claims(crate::auth::AuthMethod::ApiKey)
                .can(Capability::EditPolicies)
        );
    }
}

#[cfg(all(test, debug_assertions))]
#[path = "data_controls_fix_tests.rs"]
mod fix_tests;
