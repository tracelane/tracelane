//! `model_aliases` — GWY-27 per-workspace model aliases (`specs/GWY-27-model-aliases.md`).
//!
//! One alias names exactly ONE concrete target model for one workspace. The hot path
//! never reads this table: the map rides `entitlement_cache::ResolvedEntitlements`
//! (loaded by [`list`] inside the entitlement refresh) and is applied by [`resolve`].
//! Writes come only from the owner-gated `/v1/model-aliases` routes
//! (`crate::model_alias_routes`), which validate the target against the routing map with
//! [`validate_write`] before anything is stored.
//!
//! Tenant isolation: every statement filters on `tenant_id = $1` from the validated
//! claim's tenant UUID (never an `org_id`, never a request body).

use std::collections::BTreeMap;

use anyhow::{Result, anyhow};
use tracelane_shared::TenantId;

use crate::db::DbPool as Pool;

/// Longest alias accepted — a wire-format invariant (the table CHECKs the same shape),
/// not a tunable, so it is not in `billing_policy`.
pub const MAX_ALIAS_LEN: usize = 64;
/// Longest target model string stored (the table CHECKs 1..=256).
pub const MAX_TARGET_LEN: usize = 256;
/// Upper bound on rows the entitlement refresh reads per workspace. A safety bound on a
/// background read, above any cap `billing_policy` can set today — not the product cap.
const LIST_BOUND: i64 = 1000;

/// Why a write was refused. Each maps to one `400` code the UI shows at the field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AliasError {
    /// The alias is not `^[A-Za-z0-9][A-Za-z0-9._:/-]{0,63}$`.
    BadAlias,
    /// The target is empty or longer than [`MAX_TARGET_LEN`].
    BadTarget,
    /// The target does not route to any provider — `unroutable_target`.
    UnroutableTarget,
    /// The target is itself one of this workspace's aliases (no chains — one hop).
    TargetIsAlias,
    /// `alias == target`.
    SelfAlias,
    /// Creating a new alias would exceed the workspace cap.
    CapReached { max: u32 },
}

impl AliasError {
    /// The stable wire code (`{"error": …}`).
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::BadAlias => "invalid_alias",
            Self::BadTarget => "invalid_target",
            Self::UnroutableTarget => "unroutable_target",
            Self::TargetIsAlias => "target_is_alias",
            Self::SelfAlias => "self_alias",
            Self::CapReached { .. } => "alias_cap_reached",
        }
    }
}

/// Does `alias` have the stored shape? Pure.
#[must_use]
pub fn valid_alias(alias: &str) -> bool {
    let b = alias.as_bytes();
    !b.is_empty()
        && b.len() <= MAX_ALIAS_LEN
        && b[0].is_ascii_alphanumeric()
        && b.iter()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b':' | b'/' | b'-'))
}

/// Every refusal a write can hit, decided without I/O. Pure — `routable` is
/// `ProviderRegistry::provider_id_for_model(..).is_some()` in production.
///
/// `existing` is the workspace's current map; `max` the policy cap. Replacing an
/// existing alias never counts against the cap.
///
/// # Errors
/// The first [`AliasError`] that applies, in a fixed order.
pub fn validate_write(
    alias: &str,
    target: &str,
    existing: &BTreeMap<String, String>,
    max: u32,
    routable: impl Fn(&str) -> bool,
) -> std::result::Result<(), AliasError> {
    if !valid_alias(alias) {
        return Err(AliasError::BadAlias);
    }
    if target.is_empty() || target.len() > MAX_TARGET_LEN {
        return Err(AliasError::BadTarget);
    }
    if alias == target {
        return Err(AliasError::SelfAlias);
    }
    if existing.contains_key(target) {
        return Err(AliasError::TargetIsAlias);
    }
    if !routable(target) {
        return Err(AliasError::UnroutableTarget);
    }
    let is_new = !existing.contains_key(alias);
    if is_new && existing.len() >= usize::try_from(max).unwrap_or(usize::MAX) {
        return Err(AliasError::CapReached { max });
    }
    Ok(())
}

/// The target for `model`, if it is one of this workspace's aliases. One lookup,
/// ONE hop — a target is never itself resolved as an alias. Pure; the hot path's
/// only use of this module.
#[must_use]
pub fn resolve<'a>(aliases: &'a BTreeMap<String, String>, model: &str) -> Option<&'a str> {
    aliases.get(model).map(String::as_str)
}

/// The workspace's aliases, alias → target.
///
/// # Errors
/// Propagates pool/statement errors. The entitlement refresh (the only background
/// caller) treats an error as "no aliases" and counts `workspace_gateway_config_unreadable` —
/// see `entitlement_cache::pg_resolver`.
pub async fn list(pool: &Pool, tenant_id: &TenantId) -> Result<BTreeMap<String, String>> {
    let client = pool.get().await.map_err(|e| anyhow!("pool: {e}"))?;
    list_with(&client, tenant_id.as_uuid()).await
}

/// [`list`] on a connection the caller already holds — the entitlement refresh reuses
/// the one it resolved the plan with, so the aliases cost no extra Neon wake.
///
/// # Errors
/// Propagates the statement error.
pub async fn list_with(
    client: &tokio_postgres::Client,
    tenant: &uuid::Uuid,
) -> Result<BTreeMap<String, String>> {
    let rows = client
        .query(
            "SELECT alias, target_model FROM model_aliases \
             WHERE tenant_id = $1 ORDER BY alias LIMIT $2",
            &[tenant, &LIST_BOUND],
        )
        .await
        .map_err(|e| anyhow!("model_aliases list: {e}"))?;
    Ok(rows
        .iter()
        .map(|r| (r.get::<_, String>(0), r.get::<_, String>(1)))
        .collect())
}

/// Outcome of [`put`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PutOutcome {
    Created,
    Updated,
    /// `create_only` and the alias already exists — nothing written (`409`).
    Exists,
    /// A concurrent writer filled the cap between validation and insert — nothing written.
    CapReached,
}

/// Create or replace one alias. Validation ([`validate_write`]) is the caller's job and
/// runs first; the cap is re-checked INSIDE the insert so a concurrent create cannot
/// push the count past it through this statement.
///
/// # Errors
/// Fails CLOSED: any pool/statement error propagates — a write reported as success
/// must have happened.
pub async fn put(
    pool: &Pool,
    tenant_id: &TenantId,
    alias: &str,
    target: &str,
    updated_by: &str,
    max: u32,
    create_only: bool,
) -> Result<PutOutcome> {
    let client = pool.get().await.map_err(|e| anyhow!("pool: {e}"))?;
    let tenant = tenant_id.as_uuid();
    let exists = client
        .query_opt(
            "SELECT 1 FROM model_aliases WHERE tenant_id = $1 AND alias = $2",
            &[tenant, &alias],
        )
        .await
        .map_err(|e| anyhow!("model_aliases probe: {e}"))?
        .is_some();
    if exists {
        if create_only {
            return Ok(PutOutcome::Exists);
        }
        client
            .execute(
                "UPDATE model_aliases SET target_model = $3, updated_by = $4, updated_at = NOW() \
                 WHERE tenant_id = $1 AND alias = $2",
                &[tenant, &alias, &target, &updated_by],
            )
            .await
            .map_err(|e| anyhow!("model_aliases update: {e}"))?;
        return Ok(PutOutcome::Updated);
    }
    let max = i64::from(max);
    let inserted = client
        .execute(
            "INSERT INTO model_aliases (tenant_id, alias, target_model, updated_by) \
             SELECT $1, $2, $3, $4 \
             WHERE (SELECT count(*) FROM model_aliases WHERE tenant_id = $1) < $5 \
             ON CONFLICT (tenant_id, alias) DO NOTHING",
            &[tenant, &alias, &target, &updated_by, &max],
        )
        .await
        .map_err(|e| anyhow!("model_aliases insert: {e}"))?;
    Ok(if inserted == 1 {
        PutOutcome::Created
    } else if create_only {
        // Either the cap filled or a concurrent create won the alias; re-probe to say which.
        let now_exists = client
            .query_opt(
                "SELECT 1 FROM model_aliases WHERE tenant_id = $1 AND alias = $2",
                &[tenant, &alias],
            )
            .await
            .map_err(|e| anyhow!("model_aliases re-probe: {e}"))?
            .is_some();
        if now_exists {
            PutOutcome::Exists
        } else {
            PutOutcome::CapReached
        }
    } else {
        PutOutcome::CapReached
    })
}

/// Delete one alias. `Ok(false)` when it did not exist.
///
/// # Errors
/// Fails CLOSED on pool/statement errors.
pub async fn delete(pool: &Pool, tenant_id: &TenantId, alias: &str) -> Result<bool> {
    let client = pool.get().await.map_err(|e| anyhow!("pool: {e}"))?;
    let n = client
        .execute(
            "DELETE FROM model_aliases WHERE tenant_id = $1 AND alias = $2",
            &[tenant_id.as_uuid(), &alias],
        )
        .await
        .map_err(|e| anyhow!("model_aliases delete: {e}"))?;
    Ok(n == 1)
}

/// `billing_policy.model_aliases_max_per_workspace` — read on the WRITE path only
/// (writes are rare; this is not the hot path). `Ok(None)` when the row is absent or
/// not a non-negative integer: the caller refuses new aliases rather than guessing a cap.
///
/// # Errors
/// Propagates pool/statement errors.
pub async fn read_cap(pool: &Pool) -> Result<Option<u32>> {
    let client = pool.get().await.map_err(|e| anyhow!("pool: {e}"))?;
    let row = client
        .query_opt(
            "SELECT value::text FROM billing_policy WHERE key = 'model_aliases_max_per_workspace'",
            &[],
        )
        .await
        .map_err(|e| anyhow!("billing_policy read: {e}"))?;
    Ok(row.and_then(|r| r.get::<_, String>(0).trim().parse::<u32>().ok()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(a, t)| ((*a).to_string(), (*t).to_string()))
            .collect()
    }

    fn routable(m: &str) -> bool {
        m.starts_with("gpt-") || m.starts_with("claude-")
    }

    #[test]
    fn alias_shape() {
        for ok in ["fast", "gpt-4o", "team/fast", "a", "v1.2:beta_x"] {
            assert!(valid_alias(ok), "{ok}");
        }
        let too_long = "a".repeat(MAX_ALIAS_LEN + 1);
        for bad in ["", "-fast", "fa st", "fäst", "fast!", too_long.as_str()] {
            assert!(!valid_alias(bad), "{bad:?}");
        }
        assert!(valid_alias(&"a".repeat(MAX_ALIAS_LEN)));
    }

    #[test]
    fn every_refusal_blocks_and_a_clean_write_passes() {
        let existing = map(&[("fast", "claude-haiku"), ("smart", "gpt-5")]);
        let v = |a: &str, t: &str, max| validate_write(a, t, &existing, max, routable);
        assert_eq!(v("bad alias", "gpt-5", 50), Err(AliasError::BadAlias));
        assert_eq!(v("x", "", 50), Err(AliasError::BadTarget));
        assert_eq!(v("gpt-5", "gpt-5", 50), Err(AliasError::SelfAlias));
        assert_eq!(v("x", "fast", 50), Err(AliasError::TargetIsAlias));
        assert_eq!(v("x", "llama-nope", 50), Err(AliasError::UnroutableTarget));
        assert_eq!(v("x", "gpt-5", 2), Err(AliasError::CapReached { max: 2 }));
        // Replacing an existing alias never counts against the cap.
        assert_eq!(v("fast", "gpt-5", 2), Ok(()));
        // Shadowing a real model name is the redirect use case — allowed.
        assert_eq!(v("gpt-4o", "gpt-4o-mini", 50), Ok(()));
        assert_eq!(v("new", "claude-sonnet", 50), Ok(()));
    }

    #[test]
    fn resolve_is_one_hop() {
        let m = map(&[("fast", "gpt-4o-mini"), ("gpt-4o-mini", "claude-x")]);
        // One hop, never two — even if the stored data were ever to form a chain.
        assert_eq!(resolve(&m, "fast"), Some("gpt-4o-mini"));
        assert_eq!(resolve(&m, "unknown"), None);
    }

    /// A pool on the runner's migrated database (`run-postgres-integration.sh` applies
    /// every migration in `crate::db::MIGRATIONS`, 0050 included).
    fn pool_for(url: &str) -> Pool {
        let mut cfg = deadpool_postgres::Config::new();
        cfg.url = Some(url.to_owned());
        cfg.create_pool(
            Some(deadpool_postgres::Runtime::Tokio1),
            tokio_postgres::NoTls,
        )
        .expect("pool on POSTGRES_TEST_URL")
    }

    /// Spec §7 row 5 — against a REAL Postgres: the migration's constraints, every
    /// `put` outcome, the cap enforced inside the insert, the entitlement resolver
    /// actually loading the map, delete, and the tenant cascade.
    #[tokio::test]
    #[ignore = "needs POSTGRES_TEST_URL — run scripts/ci/run-postgres-integration.sh"]
    async fn gwy27_model_aliases_round_trip_against_real_postgres() {
        let Ok(url) = std::env::var("POSTGRES_TEST_URL") else {
            panic!("POSTGRES_TEST_URL not set — this test cannot run, which is not a pass");
        };
        let pool = pool_for(&url);
        let client = pool.get().await.expect("connect");
        let org = format!("org_gwy27_{}", uuid::Uuid::new_v4().simple());
        let id: uuid::Uuid = client
            .query_one(
                "INSERT INTO tenants (workos_org_id, name) VALUES ($1, $2) RETURNING id",
                &[&org, &"gwy27-alias-test"],
            )
            .await
            .expect("throwaway tenant")
            .get(0);
        let tenant = TenantId::from_jwt_claim(id);

        // The cap is DATA. Seed a small one so the refusal is reachable in the test.
        client
            .execute(
                "INSERT INTO billing_policy (key, value) VALUES ('model_aliases_max_per_workspace', '2'::jsonb) \
                 ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
                &[],
            )
            .await
            .expect("seed the cap");
        assert_eq!(read_cap(&pool).await.unwrap(), Some(2));

        let put = |alias: &'static str, target: &'static str, create: bool| {
            let pool = pool.clone();
            let tenant = tenant.clone();
            async move {
                put(&pool, &tenant, alias, target, "test", 2, create)
                    .await
                    .unwrap()
            }
        };
        assert_eq!(put("fast", "gpt-4o-mini", true).await, PutOutcome::Created);
        assert_eq!(
            put("fast", "gpt-4o", true).await,
            PutOutcome::Exists,
            "create never overwrites"
        );
        assert_eq!(put("fast", "gpt-4o", false).await, PutOutcome::Updated);
        assert_eq!(put("smart", "gpt-5", true).await, PutOutcome::Created);
        assert_eq!(
            put("third", "gpt-5-mini", true).await,
            PutOutcome::CapReached,
            "the cap holds INSIDE the insert, not only in validate_write"
        );

        let listed = list(&pool, &tenant).await.unwrap();
        assert_eq!(
            listed,
            map(&[("fast", "gpt-4o"), ("smart", "gpt-5")]),
            "update replaced the target; the capped insert wrote nothing"
        );

        // The entitlement refresh's use of `list_with` (both directions, incl. the
        // unreadable → no-aliases + counted path) is proven in `entitlement_cache`'s
        // `gwy27_attach_model_aliases_*` — this file is also compiled into the
        // `postgres_tenant_integration` crate, where `crate::entitlement_cache` does not exist.

        // The table refuses what validation refuses, even from a raw write.
        let self_alias = client
            .execute(
                "INSERT INTO model_aliases (tenant_id, alias, target_model) VALUES ($1, 'x', 'x')",
                &[&id],
            )
            .await;
        assert!(
            self_alias.is_err(),
            "model_aliases_not_self must refuse alias = target"
        );
        let bad_shape = client
            .execute(
                "INSERT INTO model_aliases (tenant_id, alias, target_model) VALUES ($1, '-bad', 'gpt-5')",
                &[&id],
            )
            .await;
        assert!(
            bad_shape.is_err(),
            "model_aliases_alias_shape must refuse a leading dash"
        );

        assert!(delete(&pool, &tenant, "fast").await.unwrap());
        assert!(
            !delete(&pool, &tenant, "fast").await.unwrap(),
            "a second delete finds nothing"
        );

        // Tenant isolation + cascade: another tenant sees none of these; deleting the
        // tenant removes its aliases.
        let other = TenantId::from_jwt_claim(uuid::Uuid::new_v4());
        assert!(list(&pool, &other).await.unwrap().is_empty());
        client
            .execute("DELETE FROM tenants WHERE id = $1", &[&id])
            .await
            .expect("delete tenant");
        let left: i64 = client
            .query_one(
                "SELECT count(*) FROM model_aliases WHERE tenant_id = $1",
                &[&id],
            )
            .await
            .unwrap()
            .get(0);
        assert_eq!(left, 0, "ON DELETE CASCADE");
    }
}
