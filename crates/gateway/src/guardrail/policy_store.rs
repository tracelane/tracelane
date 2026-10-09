//! Tenant-scoped policy storage; writes and their audit row commit together.
use super::policy::Policies;
use anyhow::Result;
use serde_json::Value;
use tracelane_shared::TenantId;
use uuid::Uuid;

pub const SCHEMA_COLUMNS: &[(&str, &str)] = &[
    ("guardrail_policies", "tenant_id"),
    ("guardrail_policies", "scope"),
    ("guardrail_policies", "scope_id"),
    ("guardrail_policies", "policy"),
    ("guardrail_policies", "updated_at"),
    ("guardrail_policies", "updated_by"),
];

/// Called only during the entitlement snapshot refresh. Fail-CLOSED to the cache's
/// last-known snapshot when any query fails.
pub async fn load(client: &tokio_postgres::Client, tenant: &Uuid) -> Result<Policies> {
    let mut policies = Policies::default();
    for row in client
        .query(
            "SELECT scope, scope_id, policy, updated_at FROM guardrail_policies WHERE tenant_id = $1 ORDER BY scope, scope_id",
            &[tenant],
        )
        .await?
    {
        let scope: String = row.get(0);
        let id: Uuid = row.get(1);
        let value: Value = row.get(2);
        let updated: chrono::DateTime<chrono::Utc> = row.get(3);
        use std::fmt::Write as _;
        let _ = write!(policies.revision, "{scope}:{id}:{updated};");
        match scope.as_str() {
            "workspace" => policies.workspace = Some(value),
            "key" => {
                policies.keys.insert(id, value);
            }
            "project" => {
                policies.projects.insert(id, value);
            }
            _ => anyhow::bail!("unknown stored guardrail scope"),
        }
    }
    // Resolve membership in the same tenant; a project ID alone is never authority.
    for row in client
        .query(
            "SELECT id, project_id FROM api_keys WHERE tenant_id = $1 AND project_id IS NOT NULL",
            &[tenant],
        )
        .await?
    {
        policies.key_projects.insert(row.get(0), row.get(1));
    }
    policies.hooks = super::hooks_api::load(client, tenant, &mut policies.revision).await?;
    Ok(policies)
}

/// Ownership is checked under row lock in the write transaction. A foreign scope is
/// indistinguishable from an unknown scope. Fail-CLOSED on query failure.
pub async fn owns(
    client: &impl tokio_postgres::GenericClient,
    tenant: &Uuid,
    scope: &str,
    id: &Uuid,
) -> Result<bool> {
    let sql = match scope {
        "workspace" => return Ok(tenant == id),
        "key" => "SELECT id FROM api_keys WHERE tenant_id = $1 AND id = $2 FOR SHARE",
        "project" => "SELECT id FROM projects WHERE tenant_id = $1 AND id = $2 FOR SHARE",
        _ => return Ok(false),
    };
    Ok(client.query_opt(sql, &[tenant, id]).await?.is_some())
}

/// Fail-CLOSED: no write survives a missing audit row.
pub async fn write(
    pool: &crate::db::DbPool,
    tenant: &TenantId,
    scope: &str,
    id: Uuid,
    value: &Value,
    actor: &crate::db::control_audit::Actor,
) -> Result<bool> {
    let mut client = pool.get().await?;
    let tx = client.transaction().await?;
    // Serialize same-tenant creates too (SELECT FOR UPDATE on a missing policy cannot).
    tx.query_one(
        "SELECT id FROM tenants WHERE id = $1 FOR UPDATE",
        &[tenant.as_uuid()],
    )
    .await?;
    if !owns(&*tx, tenant.as_uuid(), scope, &id).await? {
        return Ok(false);
    }
    let before: Option<Value> = tx.query_opt("SELECT policy FROM guardrail_policies WHERE tenant_id = $1 AND scope = $2 AND scope_id = $3", &[tenant.as_uuid(), &scope, &id]).await?.map(|r| r.get(0));
    if value.is_null() {
        tx.execute(
            "DELETE FROM guardrail_policies WHERE tenant_id = $1 AND scope = $2 AND scope_id = $3",
            &[tenant.as_uuid(), &scope, &id],
        )
        .await?;
    } else {
        tx.execute("INSERT INTO guardrail_policies (tenant_id, scope, scope_id, policy, updated_by) VALUES ($1, $2, $3, $4, $5) ON CONFLICT (tenant_id, scope, scope_id) DO UPDATE SET policy = EXCLUDED.policy, updated_by = EXCLUDED.updated_by, updated_at = clock_timestamp()", &[tenant.as_uuid(), &scope, &id, value, &actor.sub]).await?;
    }
    crate::db::control_audit::record(
        &tx,
        tenant,
        actor,
        crate::db::control_audit::Change {
            action: "guardrail.policy.set",
            target_type: "guardrail_policy",
            target_id: format!("{scope}:{id}"),
            before,
            after: Some(value.clone()),
        },
    )
    .await?;
    tx.commit().await?;
    Ok(true)
}

#[cfg(test)]
mod pg_tests {
    use super::*;
    use serde_json::json;
    #[tokio::test]
    #[ignore = "requires an operator-run migrated Postgres test database"]
    async fn og30_pg_policy_roundtrip_is_tenant_scoped_and_audit_failure_rolls_back() {
        let pool = crate::entitlement_cache::b409_fixture::fresh_migrated_pool().await;
        let client = pool.get().await.unwrap();
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        for id in [a, b] {
            client
                .execute(
                    "INSERT INTO tenants (id, workos_org_id, name) VALUES ($1, $2, 'policy test')",
                    &[&id, &format!("org_policy_{id}")],
                )
                .await
                .unwrap();
        }
        let ta = TenantId::from_jwt_claim(a);
        let tb = TenantId::from_jwt_claim(b);
        let actor = crate::db::control_audit::Actor {
            sub: "unit-test-admin".into(),
            role: "admin",
            auth_method: "workos_session",
            request_id: Uuid::new_v4().to_string(),
            ip: None,
            user_agent: None,
        };
        let before = json!({"rails":{"R8_injection":{"mode":"observe"}}});
        assert!(
            write(&pool, &ta, "workspace", a, &before, &actor)
                .await
                .unwrap()
        );
        assert_eq!(
            load(&client, &a).await.unwrap().workspace,
            Some(before.clone())
        );
        assert!(load(&client, &b).await.unwrap().workspace.is_none());
        assert!(
            !write(&pool, &tb, "workspace", a, &Value::Null, &actor)
                .await
                .unwrap()
        );
        let count: i64 = client.query_one("SELECT count(*) FROM admin_audit_log WHERE actor_workspace_id = $1 AND action = 'guardrail.policy.set'", &[&a]).await.unwrap().get(0);
        assert_eq!(count, 1);
        client.batch_execute("ALTER TABLE admin_audit_log ADD CONSTRAINT og30_refuse CHECK (action <> 'guardrail.policy.set') NOT VALID").await.unwrap();
        assert!(
            write(&pool, &ta, "workspace", a, &Value::Null, &actor)
                .await
                .is_err()
        );
        assert_eq!(load(&client, &a).await.unwrap().workspace, Some(before));
    }
}
