//! Admin-action audit log helper (ADR-031).
//!
//! Inserts one row into `admin_audit_log` (Postgres) per mutating
//! admin action. The helper is intentionally low-ceremony — every
//! field is `Option`-able where the prompt allows; callers fill in
//! whatever they have. Failure to record is logged at `tracing::error!`
//! and returned to the caller as `Result::Err` so the caller can
//! decide whether to fail the request or proceed (default: proceed —
//! we'd rather lose one audit row than 500 the user).
//!
//! ## V1 scope
//!
//! V1 ships the helper + three demo call sites:
//!   * `apps/web/app/api/settings/api-keys` POST (create) + DELETE (revoke)
//!   * `apps/web/app/api/prompts/[name]/promote` POST
//!
//! The TS-side mirror is `apps/web/lib/admin-audit.ts`. The remaining
//! ~12 admin endpoints get a V1.1 sweep — tracked in CHANGELOG +
//! ADR-031 §V1 wiring scope.

// No production caller today (B-390, 2026-09-12) — see the note above
// `record_admin_action` below for the full picture. This struct + its
// builder methods are exercised by a test; gated accordingly rather than
// deleted, since AUD-16 tracks this as a real, deferred (not abandoned)
// wiring gap.
#[cfg(test)]
use serde_json::Value as JsonValue;
#[cfg(test)]
use uuid::Uuid;

/// A pending audit entry. Construct with the helpers and submit via
/// `record_admin_action` (deleted 2026-09-12, B-390 — see its former
/// location's supersession note below).
///
/// `actor_user_id` is the WorkOS user id string (opaque, e.g.
/// `user_01HXYZ...`). The schema column is `TEXT` because Tracelane
/// does not maintain a local `users` table — WorkOS is the identity
/// system of record.
#[derive(Debug, Clone)]
#[cfg(test)]
pub struct AdminAuditEntry {
    pub actor_user_id: String,
    pub actor_workspace_id: Option<Uuid>,
    /// Enum-like action string. Convention: `<target>.<verb>`, e.g.
    /// `api_key.create`, `api_key.revoke`, `prompt.promote`,
    /// `billing.subscription.cancel`, `member.invite`,
    /// `byok.provider_key.create`.
    pub action: String,
    /// Schema-bearing category. Examples: `api_key`, `prompt`,
    /// `subscription`, `provider_key`, `member`.
    pub target_type: String,
    /// External or internal id of the mutated row.
    pub target_id: String,
    pub before_json: Option<JsonValue>,
    pub after_json: Option<JsonValue>,
    /// `x-forwarded-for` head (first hop) or socket peer string. We
    /// store as `TEXT` in the application layer and let Postgres'
    /// `INET` cast accept or reject — invalid values are dropped to
    /// NULL by the helper rather than failing the audit insert.
    pub ip_addr: Option<String>,
    pub user_agent: Option<String>,
}

#[cfg(test)]
impl AdminAuditEntry {
    /// Construct a minimal entry for a `<target>.<verb>` action; fill in
    /// before/after with the chaining setters.
    pub fn new(
        actor_user_id: impl Into<String>,
        action: impl Into<String>,
        target_type: impl Into<String>,
        target_id: impl Into<String>,
    ) -> Self {
        Self {
            actor_user_id: actor_user_id.into(),
            actor_workspace_id: None,
            action: action.into(),
            target_type: target_type.into(),
            target_id: target_id.into(),
            before_json: None,
            after_json: None,
            ip_addr: None,
            user_agent: None,
        }
    }

    pub fn workspace(mut self, ws: Uuid) -> Self {
        self.actor_workspace_id = Some(ws);
        self
    }
    // `before(mut self, before: JsonValue)` (the `before_json` counterpart of
    // `after` below) was deleted 2026-09-12 (B-390) — zero callers anywhere,
    // including this file's own test, unlike `after`. The `before_json`
    // field itself is untouched (`pub`, directly settable) — this only
    // removed the unused chaining-setter sugar for it. Restorable from git
    // history at `ba4627ccd53d35054629832edc11db7288acbceb`.
    pub fn after(mut self, after: JsonValue) -> Self {
        self.after_json = Some(after);
        self
    }
    // clippy::wrong_self_convention false positive: `from_request` is the
    // builder verb for "populate from the inbound request" — it is not a
    // type-conversion constructor. Renaming would be cosmetic and would
    // ripple through call sites for no behavioral gain.
    #[allow(clippy::wrong_self_convention)]
    pub fn from_request(mut self, ip: Option<String>, ua: Option<String>) -> Self {
        self.ip_addr = ip;
        self.user_agent = ua;
        self
    }
}

// `record_admin_action` (the Postgres INSERT writer this builder fed) was
// deleted 2026-09-12 (B-390) — zero callers anywhere in the tree, including
// tests (it needs a live `deadpool_postgres::Pool`, so no unit test ever
// exercised it). AUD-16 already documents this honestly as a "V1.1 sweep"
// gap with the web-side TS mirror (`apps/web/lib/admin-audit.ts`) doing the
// real writing today for the 7 wired endpoints; this Rust-side function had
// none. Restorable from git history at
// `ba4627ccd53d35054629832edc11db7288acbceb` (the last commit that carried
// it) when a gateway-side admin route needs to write this table directly.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entry_builder_threads_optional_fields() {
        let actor = "user_01HXYZ_test";
        let ws = Uuid::new_v4();
        let e = AdminAuditEntry::new(actor, "api_key.create", "api_key", "key_123")
            .workspace(ws)
            .after(serde_json::json!({"name": "ci-token"}))
            .from_request(Some("203.0.113.5".into()), Some("Mozilla/5.0".into()));

        assert_eq!(e.actor_user_id, actor);
        assert_eq!(e.actor_workspace_id, Some(ws));
        assert_eq!(e.action, "api_key.create");
        assert_eq!(e.target_type, "api_key");
        assert_eq!(e.target_id, "key_123");
        assert!(e.before_json.is_none());
        assert!(e.after_json.is_some());
        assert_eq!(e.ip_addr.as_deref(), Some("203.0.113.5"));
        assert_eq!(e.user_agent.as_deref(), Some("Mozilla/5.0"));
    }

    #[test]
    fn action_string_convention_is_target_dot_verb() {
        // Documenting the convention via tests so a future contributor
        // sees the shape we expect when grepping action labels for
        // dashboards.
        for valid in [
            "api_key.create",
            "api_key.revoke",
            "prompt.promote",
            "billing.subscription.cancel",
            "member.invite",
            "byok.provider_key.create",
        ] {
            assert!(
                valid.contains('.'),
                "action `{valid}` should follow <target>.<verb>"
            );
        }
    }
}
