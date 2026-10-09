//! `OG-35` / `AUD-16` — every control change, recorded with before and after
//! (`specs/OG-35-control-change-audit.md`).
//!
//! **The store is `admin_audit_log` (ADR-031), not a new table.** ADR-031 already
//! decided that every mutating admin endpoint writes one row there "inside its
//! transaction", and the key rotate / edit / revoke paths already did
//! (`db/api_keys.rs`). OG-35 finishes that decision instead of starting a second
//! trail: migration 0058 adds `request_id`, `actor_role` and `actor_auth_method`,
//! and makes the table APPEND-ONLY (a trigger refuses every UPDATE, every TRUNCATE,
//! and every DELETE except of a tenant `tenant-purge.sh` has already tombstoned in
//! `purged_tenants`).
//!
//! **Fail-CLOSED, by construction.** [`record`] takes the change's own
//! transaction: a row that cannot be written rolls the change back, and the
//! caller answers an error. There is no "record after" shape here, because an
//! unrecorded control change is exactly what this exists to prevent.
//!
//! **Secrets never land in the trail.** [`redact`] runs on `before` and `after`
//! inside [`record`] — every caller gets it, none can forget it: a field whose NAME
//! is credential-shaped is replaced whole, and every string VALUE goes through the
//! log scrubber (`tracelane_shared::redact::scrub`: `tlane_…`, `sk-…`, JWTs, PEM
//! private keys, …). Callers should still never put key material in a change; this
//! is the second line, not the first.
//!
//! **Self-contained on purpose:** `crates/gateway/tests/postgres_tenant_integration.rs`
//! mounts `src/db/mod.rs` by `#[path]`, so nothing here may reach a gateway module
//! outside `db`. The actor is therefore plain data the route layer fills in
//! (`control_plane::require_control`).

use anyhow::{Context as _, Result};
use chrono::{DateTime, Utc};
use deadpool_postgres::Pool;
use serde::Serialize;
use serde_json::Value;
use std::net::IpAddr;
use tracelane_shared::TenantId;

/// Who made a control change, as the route layer authenticated them.
#[derive(Debug, Clone)]
pub struct Actor {
    /// WorkOS user id, `apikey:<uuid>`, or `self-host` — the `Claims::sub`.
    pub sub: String,
    /// `admin` / `developer` / `viewer` / `billing` / `unrecognised`, or a
    /// principal label (`api_key`, `self_host_operator`) — `Claims::role_label`.
    pub role: &'static str,
    /// `workos_session` / `api_key` / `self_host_master_key` / … —
    /// `Claims::auth_method_label`.
    pub auth_method: &'static str,
    /// Minted by the gateway per control request (never taken from the caller).
    pub request_id: String,
    /// The caller's address as the gateway proved it (OG-36 derivation), if any.
    pub ip: Option<IpAddr>,
    /// `User-Agent`, truncated to [`USER_AGENT_MAX`] bytes.
    pub user_agent: Option<String>,
}

/// Longest `User-Agent` kept on a row. A header the caller controls must not be
/// able to grow the audit trail without bound.
pub const USER_AGENT_MAX: usize = 256;

impl Actor {
    /// A fixed actor for tests and maintenance paths that are not an HTTP request.
    #[must_use]
    pub fn system(sub: &str) -> Self {
        Self {
            sub: sub.to_owned(),
            role: "system",
            auth_method: "system",
            request_id: uuid::Uuid::new_v4().to_string(),
            ip: None,
            user_agent: None,
        }
    }
}

/// Anything a store can record as the actor: a full [`Actor`] (the HTTP path, from
/// `control_plane::require_control`), or a bare `sub` string (tests and
/// maintenance paths, recorded as [`Actor::system`]). Lets the key stores take the
/// full actor without rewriting every real-Postgres test that passes a name.
pub trait AsActor {
    fn as_actor(&self) -> std::borrow::Cow<'_, Actor>;
}

impl AsActor for Actor {
    fn as_actor(&self) -> std::borrow::Cow<'_, Actor> {
        std::borrow::Cow::Borrowed(self)
    }
}

impl AsActor for str {
    fn as_actor(&self) -> std::borrow::Cow<'_, Actor> {
        std::borrow::Cow::Owned(Actor::system(self))
    }
}

tokio::task_local! {
    /// The full request actor, for stores reached through a seam whose signature
    /// carries only the `sub` (the `KeyMinter` trait in `key_routes.rs`, which
    /// mocks and concurrent branches implement — widening it would break them all).
    static CURRENT: Actor;
}

/// Run `fut` with `actor` as the request actor ([`current`]).
pub async fn scoped<F: std::future::Future>(actor: Actor, fut: F) -> F::Output {
    CURRENT.scope(actor, fut).await
}

/// The request actor set by [`scoped`], if any. A store that finds none still
/// RECORDS — as [`Actor::system`] of the `sub` it was given — so a missing scope
/// costs the row its request id and role, never the row itself.
#[must_use]
pub fn current() -> Option<Actor> {
    CURRENT.try_with(Clone::clone).ok()
}

/// One control change: what was done to what, and the state on either side.
#[derive(Debug, Clone)]
pub struct Change<'a> {
    /// `<target>.<verb>` (ADR-031 convention), e.g. `model_alias.put`.
    pub action: &'a str,
    pub target_type: &'a str,
    pub target_id: String,
    /// The state before the change; `None` for a create.
    pub before: Option<Value>,
    /// The state after the change; `None` for a delete.
    pub after: Option<Value>,
}

/// Field names whose VALUE is a credential, compared case-insensitively with
/// `_` / `-` removed. Matching is on the whole name, so `keyPrefix` and `key_id`
/// stay legible while `key`, `rawKey` and `api_key` do not.
const SECRET_FIELDS: &[&str] = &[
    "key",
    "rawkey",
    "apikey",
    "secret",
    "clientsecret",
    "webhooksecret",
    "signingsecret",
    "token",
    "accesstoken",
    "refreshtoken",
    "bearer",
    "authorization",
    "password",
    "passphrase",
    "plaintext",
    "ciphertext",
    "ciphertextb64",
    "lookuphash",
    "argon2idphc",
    "privatekey",
    "signingkey",
    "credential",
    "credentials",
    "masterkey",
];

/// What a redacted value is replaced with.
pub const REDACTED: &str = "[REDACTED]";

fn is_secret_field(name: &str) -> bool {
    let norm: String = name
        .chars()
        .filter(|c| *c != '_' && *c != '-')
        .flat_map(char::to_lowercase)
        .collect();
    SECRET_FIELDS.contains(&norm.as_str())
}

/// Remove credentials from a before/after value (module doc). Pure.
#[must_use]
pub fn redact(v: Value) -> Value {
    match v {
        Value::Object(map) => Value::Object(
            map.into_iter()
                .map(|(k, v)| {
                    let v = if is_secret_field(&k) && !v.is_null() {
                        Value::String(REDACTED.to_owned())
                    } else {
                        redact(v)
                    };
                    (k, v)
                })
                .collect(),
        ),
        Value::Array(items) => Value::Array(items.into_iter().map(redact).collect()),
        Value::String(s) => {
            let scrubbed = tracelane_shared::redact::scrub(s.as_bytes());
            if scrubbed == s.as_bytes() {
                Value::String(s)
            } else {
                Value::String(String::from_utf8_lossy(&scrubbed).into_owned())
            }
        }
        other => other,
    }
}

/// The columns [`record`] writes that migration 0058 adds — read by
/// `scripts/ci/check-deploy-schema.py`, which REFUSES a deploy to a target that lacks
/// them (every control change would 503). Its only other reader is the test below
/// that pins it to the INSERT, hence no runtime reader.
#[cfg_attr(not(test), allow(dead_code))]
pub const CONTROL_AUDIT_SCHEMA_COLUMNS: &[(&str, &str)] = &[
    ("tenant_kms_configs", "tenant_id"),
    ("tenant_kms_configs", "backend"),
    ("tenant_kms_configs", "key_ref"),
    ("tenant_kms_configs", "params"),
    ("tenant_kms_configs", "secret_enc"),
    ("tenant_kms_configs", "status"),
    ("tenant_kms_configs", "updated_at"),
    ("tenant_kms_configs", "updated_by"),
    ("tenant_data_keys", "id"),
    ("tenant_data_keys", "tenant_id"),
    ("tenant_data_keys", "wrapped_dek"),
    ("tenant_data_keys", "key_ref"),
    ("tenant_data_keys", "retired_at"),
    ("admin_audit_log", "request_id"),
    ("admin_audit_log", "actor_role"),
    ("admin_audit_log", "actor_auth_method"),
    ("tenant_admin_security", "admin_ip_allowlist"),
    ("tenant_admin_security", "sso_required"),
];

/// Write one control-change row INSIDE the change's transaction.
///
/// # Errors
/// Fail-CLOSED: any insert failure is returned, and the caller must let it roll
/// the change back (drop the transaction) and answer an error. That is the point.
pub async fn record(
    tx: &tokio_postgres::Transaction<'_>,
    tenant: &TenantId,
    actor: &Actor,
    change: Change<'_>,
) -> Result<i64> {
    let before = change.before.map(redact);
    let after = change.after.map(redact);
    let ua: Option<String> = actor
        .user_agent
        .as_deref()
        .map(|u| truncate_utf8(u, USER_AGENT_MAX).to_owned());
    let row = tx
        .query_one(
            "INSERT INTO admin_audit_log
                 (actor_user_id, actor_workspace_id, action, target_type, target_id,
                  before_json, after_json, ip_addr, user_agent, request_id,
                  actor_role, actor_auth_method)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
             RETURNING id",
            &[
                &actor.sub,
                tenant.as_uuid(),
                &change.action,
                &change.target_type,
                &change.target_id,
                &before,
                &after,
                &actor.ip,
                &ua,
                &actor.request_id,
                &actor.role,
                &actor.auth_method,
            ],
        )
        .await
        .with_context(|| format!("admin_audit_log {} insert failed", change.action))?;
    Ok(row.get(0))
}

/// Record a change performed OUTSIDE this database transaction's reach — the
/// dashboard's WorkOS team calls and its own CMK / workspace writes
/// (`POST /v1/audit/control-changes`). The dashboard calls this BEFORE it acts and
/// refuses to act when it fails, so the record still precedes the change.
///
/// # Errors
/// Fail-CLOSED: pool, transaction or insert failure.
pub async fn record_standalone(
    pool: &Pool,
    tenant: &TenantId,
    actor: &Actor,
    change: Change<'_>,
) -> Result<i64> {
    let mut client = pool.get().await.context("pool checkout")?;
    let tx = client.transaction().await?;
    let id = record(&tx, tenant, actor, change).await?;
    tx.commit().await?;
    Ok(id)
}

fn truncate_utf8(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// One row of the trail as `GET /v1/audit/control-changes` returns it.
#[derive(Debug, Clone, Serialize)]
pub struct AuditRow {
    pub id: i64,
    pub occurred_at: DateTime<Utc>,
    pub actor: String,
    pub actor_role: Option<String>,
    pub actor_auth_method: Option<String>,
    pub action: String,
    pub target_type: String,
    pub target_id: String,
    pub before: Option<Value>,
    pub after: Option<Value>,
    pub ip: Option<String>,
    pub user_agent: Option<String>,
    pub request_id: Option<String>,
}

/// Filters for [`list`]. Every filter is exact-match; nothing is interpolated.
#[derive(Debug, Clone, Default)]
pub struct ListQuery {
    pub since: Option<DateTime<Utc>>,
    pub until: Option<DateTime<Utc>>,
    pub action: Option<String>,
    pub target_type: Option<String>,
    /// Cursor: only rows with `id` below this (the previous page's last id).
    pub before_id: Option<i64>,
    pub limit: i64,
}

/// A tenant's trail, newest first. Tenant-scoped by `actor_workspace_id`; rows a
/// cross-workspace operator wrote with a NULL workspace are never returned.
///
/// # Errors
/// Pool checkout or query failure (the route answers 503).
pub async fn list(pool: &Pool, tenant: &TenantId, q: &ListQuery) -> Result<Vec<AuditRow>> {
    let client = pool.get().await.context("pool checkout")?;
    let rows = client
        .query(
            "SELECT id, occurred_at, actor_user_id, actor_role, actor_auth_method, action,
                    target_type, target_id, before_json, after_json, host(ip_addr), user_agent,
                    request_id
               FROM admin_audit_log
              WHERE actor_workspace_id = $1
                AND ($2::timestamptz IS NULL OR occurred_at >= $2)
                AND ($3::timestamptz IS NULL OR occurred_at <  $3)
                AND ($4::text IS NULL OR action = $4)
                AND ($5::text IS NULL OR target_type = $5)
                AND ($6::bigint IS NULL OR id < $6)
              ORDER BY id DESC
              LIMIT $7",
            &[
                tenant.as_uuid(),
                &q.since,
                &q.until,
                &q.action,
                &q.target_type,
                &q.before_id,
                &q.limit,
            ],
        )
        .await
        .context("admin_audit_log list failed")?;
    Ok(rows
        .iter()
        .map(|r| AuditRow {
            id: r.get(0),
            occurred_at: r.get(1),
            actor: r.get(2),
            actor_role: r.get(3),
            actor_auth_method: r.get(4),
            action: r.get(5),
            target_type: r.get(6),
            target_id: r.get(7),
            before: r.get(8),
            after: r.get(9),
            ip: r.get(10),
            user_agent: r.get(11),
            request_id: r.get(12),
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn credential_shaped_fields_are_replaced_whole() {
        let v = redact(json!({
            "name": "ci",
            "keyPrefix": "tlane_ab",
            "rawKey": "anything at all",
            "api_key": "x",
            "Authorization": "Basic Zm9vOmJhcg==",
            "nested": {"client-secret": "s", "token": "t", "id": "k1"},
            "list": [{"password": "p"}],
            "plaintext": null
        }));
        assert_eq!(v["name"], "ci");
        assert_eq!(
            v["keyPrefix"], "tlane_ab",
            "a display prefix is not a secret"
        );
        for path in [
            &v["rawKey"],
            &v["api_key"],
            &v["Authorization"],
            &v["nested"]["client-secret"],
            &v["nested"]["token"],
            &v["list"][0]["password"],
        ] {
            assert_eq!(path, REDACTED);
        }
        assert_eq!(v["nested"]["id"], "k1");
        assert!(v["plaintext"].is_null(), "an absent value stays absent");
    }

    #[test]
    fn credential_shaped_values_are_scrubbed_under_any_field_name() {
        let tlane = format!("tlane_{}", "A".repeat(40));
        let v = redact(json!({
            "note": format!("rotated to {tlane} today"),
            "provider": "sk-proj-abcdefghijklmnopqrstuvwxyz0123",
            "jwt": "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1In0.c2lnbmF0dXJl"
        }));
        let s = v.to_string();
        assert!(!s.contains(&tlane), "a tlane_ key survived: {s}");
        assert!(!s.contains("abcdefghijklmnopqrstuvwxyz0123"), "{s}");
        assert!(!s.contains("eyJzdWIiOiJ1In0"), "{s}");
    }

    /// The deploy-schema list names every 0058 column the INSERT writes — so the
    /// deploy refusal and the writer cannot drift apart.
    #[test]
    fn the_deploy_schema_list_matches_what_record_writes() {
        let src = include_str!("control_audit.rs");
        let insert = &src[src.find("INSERT INTO admin_audit_log").unwrap()..];
        let insert = &insert[..insert.find("VALUES").unwrap()];
        for (table, col) in CONTROL_AUDIT_SCHEMA_COLUMNS {
            if *table == "admin_audit_log" {
                assert!(insert.contains(col), "record() does not write {col}");
            }
        }
        for col in ["request_id", "actor_role", "actor_auth_method"] {
            assert!(
                CONTROL_AUDIT_SCHEMA_COLUMNS.contains(&("admin_audit_log", col)),
                "{col} is written but not required of the deploy target"
            );
        }
    }

    #[test]
    fn user_agent_truncation_respects_char_boundaries() {
        let s = "é".repeat(200);
        let t = truncate_utf8(&s, USER_AGENT_MAX);
        assert!(t.len() <= USER_AGENT_MAX);
        assert!(s.starts_with(t));
    }
}
