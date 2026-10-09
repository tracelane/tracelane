//! `workspace_cache_settings` + `cache_epochs` + `api_keys.cache` — OG-51
//! (`specs/OG-51-cache-controls.md`), migration 0075.
//!
//! The hot path never queries these: the entitlement refresh loads them onto
//! `ResolvedEntitlements::cache` ([`read_with`], on the resolve's own connection) and the
//! write routes (`crate::cache_routes`) invalidate the tenant's entry after every commit.
//!
//! **Invalidation is a generation counter, not a delete.** The gateway's ClickHouse user
//! holds no delete grant, so [`bump_epoch`] increments a per-scope `epoch` that the cache
//! folds into both of its hashes; the old entries become unreachable and age out by TTL,
//! capacity and the retention sweeper.
//!
//! Every write records ONE control change (`record_control_change`, the OG-35 row) in the
//! SAME transaction — fail-CLOSED: an unrecorded cache change is rolled back.
//!
//! Tenant isolation: every statement filters `tenant_id = $1`, the validated claim's tenant
//! UUID — never a path or body field.
//!
//! Self-contained on purpose: `tests/postgres_tenant_integration.rs` mounts `src/db/mod.rs`
//! by `#[path]`, so nothing here reaches a gateway module outside `db`.

use std::collections::BTreeMap;

use anyhow::{Context, Result, anyhow};
use chrono::{DateTime, Utc};
use serde_json::{Value, json};
use tracelane_shared::TenantId;
use uuid::Uuid;

use crate::db::DbPool as Pool;

/// The columns the entitlement resolve reads — named by the boot schema check, so a
/// gateway never boots against a Neon without migration 0075.
pub const CACHE_SCHEMA_COLUMNS: &[(&str, &str)] = &[
    ("workspace_cache_settings", "tenant_id"),
    ("workspace_cache_settings", "mode"),
    ("workspace_cache_settings", "ttl_hours"),
    ("workspace_cache_settings", "namespace_by"),
    ("workspace_cache_settings", "semantic"),
    ("cache_epochs", "tenant_id"),
    ("cache_epochs", "scope"),
    ("cache_epochs", "epoch"),
    ("api_keys", "cache"),
];

/// What the workspace chose for the response cache.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Mode {
    /// Serve per the operator block AND the workspace's content capture (the default).
    #[default]
    Inherit,
    /// The workspace explicitly enables the cache (needs the plan's `f_cache_control`).
    On,
    /// Never serve from or store into the cache.
    Off,
}

impl Mode {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Inherit => "inherit",
            Self::On => "on",
            Self::Off => "off",
        }
    }

    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "inherit" => Some(Self::Inherit),
            "on" => Some(Self::On),
            "off" => Some(Self::Off),
            _ => None,
        }
    }
}

/// What a cache entry is private to. Ordered by NARROWNESS: a later variant is narrower,
/// and a key may only move to a narrower one than the workspace chose.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
pub enum NamespaceBy {
    /// One cache per workspace, shared by every key, project and end user (today).
    #[default]
    Workspace,
    /// Private to the key's project.
    Project,
    /// Private to the request's end user (`user` / `x-tracelane-end-user`).
    EndUser,
    /// Private to the API key. The narrowest.
    Key,
}

impl NamespaceBy {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Workspace => "workspace",
            Self::Project => "project",
            Self::EndUser => "end_user",
            Self::Key => "key",
        }
    }

    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "workspace" => Some(Self::Workspace),
            "project" => Some(Self::Project),
            "end_user" => Some(Self::EndUser),
            "key" => Some(Self::Key),
            _ => None,
        }
    }
}

/// The workspace's stored cache settings. `Default` = nothing set (no row) = today.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Settings {
    pub mode: Mode,
    /// `None` = the operator / plan TTL.
    pub ttl_hours: Option<u32>,
    pub namespace_by: NamespaceBy,
    /// `false` = the semantic (embedding) tier is off for this workspace.
    pub semantic: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            mode: Mode::Inherit,
            ttl_hours: None,
            namespace_by: NamespaceBy::Workspace,
            semantic: true,
        }
    }
}

impl Settings {
    #[must_use]
    pub fn to_json(self) -> Value {
        json!({
            "mode": self.mode.as_str(),
            "ttl_hours": self.ttl_hours,
            "namespace_by": self.namespace_by.as_str(),
            "semantic": self.semantic,
        })
    }
}

/// One key's own narrowing (`api_keys.cache`). It can only narrow.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct KeyCache {
    /// `{"mode":"off"}`: no request on this key is served from or stored in the cache.
    pub off: bool,
    /// A namespace at least as narrow as the workspace's.
    pub namespace_by: Option<NamespaceBy>,
}

impl KeyCache {
    /// Parse a stored `api_keys.cache` document. **Fail-CLOSED**: a document that does not
    /// parse (an unknown field, a wrong type, an unknown mode) turns the cache OFF for the
    /// key — the narrowing direction — rather than being ignored.
    #[must_use]
    pub fn from_stored(v: &Value) -> Self {
        match Self::parse_strict(v) {
            Ok(k) => k,
            Err(_) => Self {
                off: true,
                namespace_by: None,
            },
        }
    }

    /// The strict parse the write route also uses: `{mode?: "off", namespace_by?}` only.
    ///
    /// # Errors
    /// The field and a message, for a `400 invalid_field`.
    pub fn parse_strict(v: &Value) -> std::result::Result<Self, (String, String)> {
        let Some(o) = v.as_object() else {
            return Err(("cache".into(), "cache must be a JSON object".into()));
        };
        let mut out = Self::default();
        for (k, val) in o {
            match k.as_str() {
                "mode" => match val.as_str() {
                    Some("off") => out.off = true,
                    _ => {
                        return Err((
                            "cache.mode".into(),
                            "a key can only switch the cache OFF (\"off\"); it never turns it on"
                                .into(),
                        ));
                    }
                },
                "namespace_by" => match val.as_str().and_then(NamespaceBy::parse) {
                    Some(n) => out.namespace_by = Some(n),
                    None => {
                        return Err((
                            "cache.namespace_by".into(),
                            "namespace_by must be workspace, project, end_user or key".into(),
                        ));
                    }
                },
                other => {
                    return Err((
                        format!("cache.{other}"),
                        "unknown field (allowed: mode, namespace_by)".into(),
                    ));
                }
            }
        }
        if !out.off && out.namespace_by.is_none() {
            return Err((
                "cache".into(),
                "an empty cache document sets nothing — send null to clear it".into(),
            ));
        }
        Ok(out)
    }

    #[must_use]
    pub fn to_json(self) -> Value {
        let mut o = serde_json::Map::new();
        if self.off {
            o.insert("mode".into(), json!("off"));
        }
        if let Some(n) = self.namespace_by {
            o.insert("namespace_by".into(), json!(n.as_str()));
        }
        Value::Object(o)
    }
}

/// Everything the hot path needs about a workspace's cache, loaded in the entitlement
/// refresh. `Default` = no settings, no epochs, no key overrides = today's behaviour.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Loaded {
    pub settings: Settings,
    /// Whether the workspace has a row at all (`updated_at` is `None` when it never set one).
    pub updated_at: Option<DateTime<Utc>>,
    /// `scope` → epoch (only non-zero rows matter, zero is stored for audit).
    pub epochs: BTreeMap<String, i64>,
    /// The workspace's keys that carry their own narrowing.
    pub keys: BTreeMap<Uuid, KeyCache>,
}

impl Loaded {
    /// The epoch of `scope`, `0` when none was ever bumped.
    #[must_use]
    pub fn epoch(&self, scope: &str) -> i64 {
        self.epochs.get(scope).copied().unwrap_or(0)
    }

    /// The non-zero epochs that apply to a request, in a FIXED order (workspace, project,
    /// key, model) — the order they are folded into the hashes.
    #[must_use]
    pub fn applicable_epochs(
        &self,
        project: Option<Uuid>,
        key: Option<Uuid>,
        model: &str,
    ) -> Vec<(String, i64)> {
        let mut scopes = vec!["workspace".to_owned()];
        if let Some(p) = project {
            scopes.push(format!("project:{p}"));
        }
        if let Some(k) = key {
            scopes.push(format!("key:{k}"));
        }
        scopes.push(format!("model:{model}"));
        scopes
            .into_iter()
            .filter_map(|s| {
                let e = self.epoch(&s);
                (e != 0).then_some((s, e))
            })
            .collect()
    }
}

/// Read a workspace's cache state on a connection the caller holds (the entitlement
/// refresh). A missing row is the default.
///
/// # Errors
/// Propagates a statement error. The entitlement refresh turns it into the PRIVACY default
/// (cache off for the workspace) and counts the degradation — never "on".
pub async fn read_with(client: &tokio_postgres::Client, tenant: &Uuid) -> Result<Loaded> {
    let mut out = Loaded::default();
    if let Some(r) = client
        .query_opt(
            "SELECT mode, ttl_hours, namespace_by, semantic, updated_at \
             FROM workspace_cache_settings WHERE tenant_id = $1",
            &[tenant],
        )
        .await
        .map_err(|e| anyhow!("workspace_cache_settings read: {e}"))?
    {
        let mode: String = r.get(0);
        let ttl: Option<i32> = r.get(1);
        let ns: String = r.get(2);
        out.settings = Settings {
            // A value the CHECK constraint forbids cannot exist; if one somehow does, the
            // privacy-safe reading is OFF.
            mode: Mode::parse(&mode).unwrap_or(Mode::Off),
            ttl_hours: ttl.and_then(|t| u32::try_from(t).ok()).filter(|t| *t > 0),
            namespace_by: NamespaceBy::parse(&ns).unwrap_or(NamespaceBy::Key),
            semantic: r.get(3),
        };
        out.updated_at = Some(r.get(4));
    }
    for r in client
        .query(
            "SELECT scope, epoch FROM cache_epochs WHERE tenant_id = $1",
            &[tenant],
        )
        .await
        .map_err(|e| anyhow!("cache_epochs read: {e}"))?
    {
        out.epochs.insert(r.get(0), r.get(1));
    }
    for r in client
        .query(
            "SELECT id, cache FROM api_keys WHERE tenant_id = $1 AND cache IS NOT NULL",
            &[tenant],
        )
        .await
        .map_err(|e| anyhow!("api_keys.cache read: {e}"))?
    {
        let v: Value = r.get(1);
        out.keys.insert(r.get(0), KeyCache::from_stored(&v));
    }
    Ok(out)
}

/// What a settings write did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SetOutcome {
    pub previous: Settings,
    pub current: Settings,
    /// `false` when the request matched the stored value: nothing written, nothing recorded.
    pub changed: bool,
}

/// Replace the workspace's cache settings and record the change — atomically.
///
/// One transaction: materialise the row (so the lock has something to lock on a first
/// write), `SELECT … FOR UPDATE`, compare, update, record, commit. A no-op write rolls back
/// without recording.
///
/// # Errors
/// Fail-CLOSED: any failure (including the audit insert) rolls the change back.
#[tracing::instrument(skip(pool, new, actor), fields(tenant_id = %tenant))]
pub async fn set_settings(
    pool: &Pool,
    tenant: &TenantId,
    new: &Settings,
    actor: &str,
) -> Result<SetOutcome> {
    let mut client = pool.get().await.map_err(|e| anyhow!("pool: {e}"))?;
    let tx = client.transaction().await?;
    let t = tenant.as_uuid();
    tx.execute(
        "INSERT INTO workspace_cache_settings (tenant_id) VALUES ($1) \
         ON CONFLICT (tenant_id) DO NOTHING",
        &[t],
    )
    .await
    .context("INSERT workspace_cache_settings failed")?;
    let row = tx
        .query_one(
            "SELECT mode, ttl_hours, namespace_by, semantic FROM workspace_cache_settings \
             WHERE tenant_id = $1 FOR UPDATE",
            &[t],
        )
        .await
        .context("SELECT workspace_cache_settings FOR UPDATE failed")?;
    let mode: String = row.get(0);
    let ttl: Option<i32> = row.get(1);
    let ns: String = row.get(2);
    let previous = Settings {
        mode: Mode::parse(&mode).unwrap_or(Mode::Off),
        ttl_hours: ttl.and_then(|t| u32::try_from(t).ok()),
        namespace_by: NamespaceBy::parse(&ns).unwrap_or(NamespaceBy::Key),
        semantic: row.get(3),
    };
    if previous == *new {
        // Nothing to write or record. (The materialised default row stays: it is the default.)
        tx.commit()
            .await
            .context("workspace_cache_settings no-op commit failed")?;
        return Ok(SetOutcome {
            previous,
            current: previous,
            changed: false,
        });
    }
    let ttl_i32 = new.ttl_hours.map(|t| i32::try_from(t).unwrap_or(i32::MAX));
    tx.execute(
        "UPDATE workspace_cache_settings SET mode = $2, ttl_hours = $3, namespace_by = $4, \
         semantic = $5, updated_at = now(), updated_by = $6 WHERE tenant_id = $1",
        &[
            t,
            &new.mode.as_str(),
            &ttl_i32,
            &new.namespace_by.as_str(),
            &new.semantic,
            &actor,
        ],
    )
    .await
    .context("UPDATE workspace_cache_settings failed")?;
    crate::db::controls::record_control_change(
        &tx,
        &crate::db::controls::ControlChange {
            tenant: *t,
            actor,
            action: "cache.settings.set",
            target_type: "workspace",
            target_id: t.to_string(),
            before: Some(previous.to_json()),
            after: Some(new.to_json()),
        },
    )
    .await?;
    tx.commit()
        .await
        .context("workspace_cache_settings commit failed")?;
    Ok(SetOutcome {
        previous,
        current: *new,
        changed: true,
    })
}

/// What a bump did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BumpOutcome {
    /// The scope's new epoch.
    Bumped { epoch: i64 },
    /// A NEW scope row was refused: the workspace already has `max` of them.
    LimitReached { max: usize },
}

/// Bump one scope's generation counter (creating it at 1) and record the change. A
/// per-tenant advisory lock serialises two bumps so neither can pass the row cap on a
/// stale count.
///
/// # Errors
/// Fail-CLOSED: any failure rolls back.
#[tracing::instrument(skip(pool, actor), fields(tenant_id = %tenant))]
pub async fn bump_epoch(
    pool: &Pool,
    tenant: &TenantId,
    scope: &str,
    max_rows: usize,
    actor: &str,
) -> Result<BumpOutcome> {
    let mut client = pool.get().await.map_err(|e| anyhow!("pool: {e}"))?;
    let tx = client.transaction().await?;
    let t = tenant.as_uuid();
    tx.execute(
        "SELECT pg_advisory_xact_lock(hashtext('cache_epochs:' || $1::uuid::text))",
        &[t],
    )
    .await
    .context("cache_epochs lock failed")?;
    let existing: Option<i64> = tx
        .query_opt(
            "SELECT epoch FROM cache_epochs WHERE tenant_id = $1 AND scope = $2",
            &[t, &scope],
        )
        .await
        .context("SELECT cache_epochs failed")?
        .map(|r| r.get(0));
    if existing.is_none() {
        let n: i64 = tx
            .query_one(
                "SELECT count(*) FROM cache_epochs WHERE tenant_id = $1",
                &[t],
            )
            .await
            .context("count cache_epochs failed")?
            .get(0);
        if usize::try_from(n).unwrap_or(usize::MAX) >= max_rows {
            return Ok(BumpOutcome::LimitReached { max: max_rows });
        }
    }
    let row = tx
        .query_one(
            "INSERT INTO cache_epochs (tenant_id, scope, epoch) VALUES ($1, $2, 1) \
             ON CONFLICT (tenant_id, scope) DO UPDATE \
               SET epoch = cache_epochs.epoch + 1, updated_at = now() \
             RETURNING epoch",
            &[t, &scope],
        )
        .await
        .context("bump cache_epochs failed")?;
    let epoch: i64 = row.get(0);
    crate::db::controls::record_control_change(
        &tx,
        &crate::db::controls::ControlChange {
            tenant: *t,
            actor,
            action: "cache.invalidate",
            target_type: "cache_scope",
            target_id: scope.to_owned(),
            before: Some(json!({ "scope": scope, "epoch": existing.unwrap_or(0) })),
            after: Some(json!({ "scope": scope, "epoch": epoch })),
        },
    )
    .await?;
    tx.commit().await.context("cache_epochs commit failed")?;
    Ok(BumpOutcome::Bumped { epoch })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn og51_a_key_document_can_only_narrow_and_a_bad_stored_one_fails_to_off() {
        let off = KeyCache::parse_strict(&json!({"mode":"off"})).unwrap();
        assert!(off.off);
        let ns = KeyCache::parse_strict(&json!({"namespace_by":"key"})).unwrap();
        assert_eq!(ns.namespace_by, Some(NamespaceBy::Key));
        // A key never turns the cache on, whatever it says.
        for bad in [
            json!({"mode":"on"}),
            json!({"mode":"inherit"}),
            json!({"namespace_by":"galaxy"}),
            json!({"ttl_hours":1}),
            json!({}),
            json!("off"),
        ] {
            assert!(KeyCache::parse_strict(&bad).is_err(), "{bad}");
            // Stored garbage is read as OFF — the narrowing direction, never "ignored".
            assert!(KeyCache::from_stored(&bad).off, "{bad}");
        }
    }

    #[test]
    fn og51_namespace_narrowness_is_ordered_workspace_to_key() {
        assert!(NamespaceBy::Workspace < NamespaceBy::Project);
        assert!(NamespaceBy::Project < NamespaceBy::EndUser);
        assert!(NamespaceBy::EndUser < NamespaceBy::Key);
        for n in [
            NamespaceBy::Workspace,
            NamespaceBy::Project,
            NamespaceBy::EndUser,
            NamespaceBy::Key,
        ] {
            assert_eq!(NamespaceBy::parse(n.as_str()), Some(n));
        }
    }

    #[test]
    fn og51_applicable_epochs_are_the_non_zero_ones_in_a_fixed_order() {
        let (p, k) = (Uuid::new_v4(), Uuid::new_v4());
        let mut l = Loaded::default();
        assert!(l.applicable_epochs(Some(p), Some(k), "gpt-4o").is_empty());
        l.epochs.insert("model:gpt-4o".into(), 2);
        l.epochs.insert("workspace".into(), 1);
        l.epochs.insert(format!("key:{k}"), 3);
        l.epochs.insert(format!("project:{}", Uuid::new_v4()), 9); // someone else's project
        assert_eq!(
            l.applicable_epochs(Some(p), Some(k), "gpt-4o"),
            vec![
                ("workspace".to_owned(), 1),
                (format!("key:{k}"), 3),
                ("model:gpt-4o".to_owned(), 2)
            ]
        );
        assert_eq!(
            l.applicable_epochs(None, None, "claude").len(),
            1,
            "only the workspace epoch applies to a request with no key, project or bumped model"
        );
    }
}
