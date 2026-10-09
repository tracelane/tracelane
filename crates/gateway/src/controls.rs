//! `OG-25` — the workspace's own controls (pause, blocks, the workspace policy layer of
//! `OG-21`/`OG-22`), as the hot path sees them, plus the reference-table bounds every
//! ONE GATEWAY wave C/D control reads. Specs: `specs/OG-25-emergency-controls.md`,
//! `specs/OG-21-tpm-rpm-limits.md`, `specs/OG-22-budgets-every-level.md`,
//! `specs/OG-24-spend-alerts.md`.
//!
//! **How the controls reach a request.** `workspace_controls` is read by
//! `entitlement_cache::attach_workspace_controls` on the resolve's own connection and
//! carried on [`crate::entitlement_cache::ResolvedEntitlements::controls`] — a warm
//! read per request, never a Postgres round trip. Every write route invalidates the
//! tenant's cache entry after its commit (immediate on this gateway; one gateway per
//! control plane, B-386). A failed read fails the whole resolve, so the cache keeps
//! serving the LAST-KNOWN controls.
//!
//! **No control plane** (no entitlement cache) ⇒ no controls: nothing can have been
//! configured, so nothing is paused or blocked. These are RESTRICTIONS an owner adds,
//! not grants, so `.claude/rules/tenancy.md`'s "absent ⇒ unprivileged" is already the
//! answer: the caller keeps exactly the free/OSS defaults it had.

use std::sync::OnceLock;

use serde_json::Value;
use tracelane_shared::key_policy::{Denial, Fact, KeyPolicy, LayerPolicy, Origin, deny_matches};

// ── Reference table ──────────────────────────────────────────────────────────

/// The `gateway_controls` block of `crates/gateway/translation_policy.v1.json`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ControlsConfig {
    pub default_output_reserve_tokens: u64,
    pub limit_max_end_users_per_tenant: usize,
    pub limit_idle_evict_secs: u64,
    pub reservation_ttl_secs: u64,
    pub max_pending_reservations: usize,
    pub budget_max_end_users_per_tenant: usize,
    pub budget_seed_retry_backoff_ms: u64,
    pub alert_queue_capacity: usize,
    pub alert_max_attempts: u32,
    pub alert_backoff_base_secs: u64,
    pub alert_poll_interval_secs: u64,
    pub alert_webhook_replay_window_secs: u64,
    pub max_alert_channels_per_tenant: usize,
    pub max_block_entries: usize,
    pub max_pause_reason_chars: usize,
    /// rev5 L6.
    pub end_user_ids_per_key_per_window: usize,
    pub end_user_ids_window_secs: u64,
}

/// Used ONLY when the shipped block does not parse (`the_shipped_block_parses` makes
/// that unreachable in a tested build): the documented values, never "unbounded".
const FALLBACK: ControlsConfig = ControlsConfig {
    default_output_reserve_tokens: 1024,
    limit_max_end_users_per_tenant: 50_000,
    limit_idle_evict_secs: 120,
    reservation_ttl_secs: 600,
    max_pending_reservations: 100_000,
    budget_max_end_users_per_tenant: 50_000,
    budget_seed_retry_backoff_ms: 5_000,
    alert_queue_capacity: 10_000,
    alert_max_attempts: 8,
    alert_backoff_base_secs: 30,
    alert_poll_interval_secs: 10,
    alert_webhook_replay_window_secs: 300,
    max_alert_channels_per_tenant: 20,
    max_block_entries: 256,
    max_pause_reason_chars: 500,
    end_user_ids_per_key_per_window: 1000,
    end_user_ids_window_secs: 3600,
};

fn parse_table(raw: &str) -> Option<ControlsConfig> {
    let v: Value = serde_json::from_str(raw).ok()?;
    let v = v.get("gateway_controls")?;
    let n = |k: &str| v.get(k).and_then(Value::as_u64).filter(|n| *n >= 1);
    let u = |k: &str| n(k).and_then(|n| usize::try_from(n).ok());
    Some(ControlsConfig {
        default_output_reserve_tokens: n("default_output_reserve_tokens")?,
        limit_max_end_users_per_tenant: u("limit_max_end_users_per_tenant")?,
        limit_idle_evict_secs: n("limit_idle_evict_secs")?,
        reservation_ttl_secs: n("reservation_ttl_secs")?,
        max_pending_reservations: u("max_pending_reservations")?,
        budget_max_end_users_per_tenant: u("budget_max_end_users_per_tenant")?,
        budget_seed_retry_backoff_ms: n("budget_seed_retry_backoff_ms")?,
        alert_queue_capacity: u("alert_queue_capacity")?,
        alert_max_attempts: u32::try_from(n("alert_max_attempts")?).ok()?,
        alert_backoff_base_secs: n("alert_backoff_base_secs")?,
        alert_poll_interval_secs: n("alert_poll_interval_secs")?,
        alert_webhook_replay_window_secs: n("alert_webhook_replay_window_secs")?,
        max_alert_channels_per_tenant: u("max_alert_channels_per_tenant")?,
        max_block_entries: u("max_block_entries")?,
        max_pause_reason_chars: u("max_pause_reason_chars")?,
        end_user_ids_per_key_per_window: u("end_user_ids_per_key_per_window")?,
        end_user_ids_window_secs: n("end_user_ids_window_secs")?,
    })
}

/// The bounds, parsed once.
pub(crate) fn config() -> ControlsConfig {
    static C: OnceLock<ControlsConfig> = OnceLock::new();
    *C.get_or_init(|| {
        parse_table(include_str!("../translation_policy.v1.json")).unwrap_or_else(|| {
            tracing::warn!(
                "translation_policy.v1.json gateway_controls block did not parse — using the documented defaults"
            );
            FALLBACK
        })
    })
}

// ── What the hot path carries ────────────────────────────────────────────────

/// A workspace pause.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pause {
    pub at: chrono::DateTime<chrono::Utc>,
    pub by: Option<String>,
    pub reason: Option<String>,
}

/// One workspace's controls. `Default` = nothing set (no row).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct WorkspaceControls {
    /// The workspace layer of `OG-21`/`OG-22` (`limits`, `budget`, `end_user_budget`).
    /// `Some(Invalid)` = a stored document that does not parse, or that carries a rule
    /// a workspace may not: every request in the workspace is refused `policy_invalid`.
    pub policy: Option<LayerPolicy>,
    pub paused: Option<Pause>,
    /// Lower-cased `OG-20` model globs.
    pub blocked_models: Vec<String>,
    /// Lower-cased provider ids.
    pub blocked_providers: Vec<String>,
    /// Exact end-user ids (`OBS-20`).
    pub blocked_end_users: Vec<String>,
}

impl WorkspaceControls {
    /// Build from the `workspace_controls` row's columns (the READ path: no write bounds).
    #[must_use]
    pub fn from_row(
        policy: Option<&Value>,
        paused: Option<Pause>,
        blocked_models: Vec<String>,
        blocked_providers: Vec<String>,
        blocked_end_users: Vec<String>,
    ) -> Self {
        let policy = policy.filter(|v| !v.is_null()).map(|doc| {
            match KeyPolicy::parse(doc, None)
                .ok()
                .filter(|p| p.workspace_only().is_ok())
            {
                Some(p) => LayerPolicy::Valid(Box::new(p)),
                None => LayerPolicy::Invalid,
            }
        });
        Self {
            policy,
            paused,
            blocked_models: blocked_models
                .into_iter()
                .map(|m| m.to_ascii_lowercase())
                .collect(),
            blocked_providers: blocked_providers
                .into_iter()
                .map(|m| m.to_ascii_lowercase())
                .collect(),
            blocked_end_users,
        }
    }

    /// The workspace layer's document, when it parsed.
    #[must_use]
    pub fn policy(&self) -> Option<&KeyPolicy> {
        match &self.policy {
            Some(LayerPolicy::Valid(p)) => Some(p),
            _ => None,
        }
    }

    /// Anything the admission `Controls` step must look at?
    #[must_use]
    pub fn restricts(&self) -> bool {
        self.paused.is_some()
            || matches!(self.policy, Some(LayerPolicy::Invalid))
            || !self.blocked_models.is_empty()
            || !self.blocked_providers.is_empty()
            || !self.blocked_end_users.is_empty()
    }
}

// ── The admission step ───────────────────────────────────────────────────────

/// Why the `Controls` step refused.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum ControlRefusal {
    /// `423 workspace_paused`.
    Paused {
        since: chrono::DateTime<chrono::Utc>,
    },
    /// `403 model_blocked` / `provider_blocked` / `end_user_blocked` /
    /// `block_unenforceable`, or `403 policy_invalid` for a broken workspace policy.
    Blocked(Denial),
}

/// The pause message every wire renders.
pub(crate) fn paused_message(since: chrono::DateTime<chrono::Utc>) -> String {
    format!(
        "this workspace's gateway traffic was paused by an owner at {} — an owner can resume it \
         with POST /v1/controls/resume",
        since.to_rfc3339()
    )
}

fn blocked(code: &'static str, rule: &'static str, message: String) -> Denial {
    Denial::new(403, code, rule, Origin::Workspace, None, message)
}

/// Is the workspace paused? (Checked first, and by `pre_body_gate` before a body is read.)
pub(crate) fn check_paused(c: &WorkspaceControls) -> Result<(), ControlRefusal> {
    match &c.paused {
        Some(p) => Err(ControlRefusal::Paused { since: p.at }),
        None => Ok(()),
    }
}

/// One request against the pause, the block lists and the workspace policy's validity.
/// `resolve(model, workspace_alias)` is admission's `policy_resolve` (every name the
/// request dispatches under, and its provider) — an alias cannot launder a blocked model.
///
/// # Errors
/// The first control that refuses. Fail-CLOSED: a route that cannot name its model
/// while a model block exists is refused `block_unenforceable`.
pub(crate) fn check_request(
    c: &WorkspaceControls,
    request: &tracelane_shared::key_policy::PolicyRequest,
    end_user: Option<&str>,
    resolve: &dyn Fn(&str, bool) -> tracelane_shared::key_policy::Resolved,
) -> Result<(), ControlRefusal> {
    check_paused(c)?;
    if matches!(c.policy, Some(LayerPolicy::Invalid)) {
        return Err(ControlRefusal::Blocked(blocked(
            "policy_invalid",
            "policy",
            "this workspace's policy could not be read, so every request is refused — an owner \
             must correct or clear it (PUT /v1/controls/policy)"
                .to_owned(),
        )));
    }
    if let Some(u) = end_user
        && c.blocked_end_users.iter().any(|b| b == u)
    {
        return Err(ControlRefusal::Blocked(blocked(
            "end_user_blocked",
            "end_users",
            "this end user is blocked in this workspace by an owner".to_owned(),
        )));
    }
    if c.blocked_models.is_empty() && c.blocked_providers.is_empty() {
        return Ok(());
    }
    for s in &request.subjects {
        let at = |m: String| match s.line {
            Some(n) => format!("{m} (line {n} of the batch file)"),
            None => m,
        };
        let resolved = match &s.model {
            Fact::Known(m) => Some(resolve(m, s.workspace_alias)),
            _ => None,
        };
        if !c.blocked_models.is_empty() {
            match (&s.model, &resolved) {
                (Fact::Known(m), Some(r)) => {
                    if r.names
                        .iter()
                        .chain(r.allow_names.iter())
                        .any(|n| deny_matches(&c.blocked_models, n))
                    {
                        let shown: String = m.chars().take(128).collect();
                        let mut d = blocked(
                            "model_blocked",
                            "models",
                            at(format!(
                                "the model `{shown}` is blocked in this workspace by an owner"
                            )),
                        );
                        d.line = s.line;
                        return Err(ControlRefusal::Blocked(d));
                    }
                }
                (Fact::NotApplicable, _) => {}
                _ => {
                    let mut d = blocked(
                        "block_unenforceable",
                        "models",
                        at(
                            "models are blocked in this workspace and this endpoint cannot name \
                            the model it would call, so the request is refused"
                                .to_owned(),
                        ),
                    );
                    d.line = s.line;
                    return Err(ControlRefusal::Blocked(d));
                }
            }
        }
        if !c.blocked_providers.is_empty() {
            let provider = s
                .provider
                .clone()
                .or_else(|| resolved.as_ref().and_then(|r| r.provider.clone()))
                .map(|p| p.to_ascii_lowercase());
            let refused = match &provider {
                Some(p) => c.blocked_providers.contains(p),
                // Unroutable or unknown: it cannot be shown NOT to be a blocked provider.
                None => !matches!(s.model, Fact::NotApplicable),
            };
            if refused {
                let mut d = blocked(
                    "provider_blocked",
                    "providers",
                    at(format!(
                        "the provider `{}` is blocked in this workspace by an owner",
                        provider.as_deref().unwrap_or("(unknown)")
                    )),
                );
                d.line = s.line;
                return Err(ControlRefusal::Blocked(d));
            }
        }
    }
    Ok(())
}

/// After admission (ZDR re-route, cross-provider failover): may the request MOVE to
/// `model` on `provider`? `false` when either is blocked, when the workspace policy's model
/// / provider rules refuse it (rev5 M6), or when that policy did not parse.
#[must_use]
pub(crate) fn allows_dispatch(c: &WorkspaceControls, model: &str, provider: &str) -> bool {
    let lower = provider.to_ascii_lowercase();
    !c.blocked_providers.contains(&lower)
        && !deny_matches(&c.blocked_models, model)
        && !matches!(c.policy, Some(LayerPolicy::Invalid))
        && c.policy()
            .is_none_or(|p| p.allows_dispatch(model, provider))
}

/// rev6: why a COMPANION call (Anthropic `count_tokens`, Gemini `countTokens`) is refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CompanionRefusal {
    pub status: u16,
    pub code: &'static str,
    pub message: String,
}

/// rev6 — the controls a companion call runs before it forwards the caller's prompt to
/// `provider` for `model` with the tenant's key: the `OG-25` pause and blocks, the
/// workspace policy (an unparseable one refuses, its model / provider rules bind — rev5
/// M6) and the key's `OG-20` model / provider rules. Not limits and not budgets: a token
/// count generates nothing and costs nothing. `controls` is `None` with no control plane
/// (nothing can have been set). Fail-CLOSED: an invalid key layer refuses
/// (`Governance::allows_dispatch`).
pub(crate) fn companion_refusal(
    claims: &crate::auth::Claims,
    controls: Option<&WorkspaceControls>,
    model: &str,
    provider: &str,
) -> Option<CompanionRefusal> {
    let refuse = |status: u16, code: &'static str, message: String| {
        Some(CompanionRefusal {
            status,
            code,
            message,
        })
    };
    let shown: String = model.chars().take(128).collect();
    if let Some(c) = controls {
        if let Some(p) = &c.paused {
            return refuse(423, "workspace_paused", paused_message(p.at));
        }
        if matches!(c.policy, Some(LayerPolicy::Invalid)) {
            return refuse(
                403,
                "policy_invalid",
                "this workspace's policy could not be read, so every request is refused — an \
                 owner must correct or clear it (PUT /v1/controls/policy)"
                    .to_owned(),
            );
        }
        if c.blocked_providers.contains(&provider.to_ascii_lowercase()) {
            return refuse(
                403,
                "provider_blocked",
                format!("the provider `{provider}` is blocked in this workspace by an owner"),
            );
        }
        if deny_matches(&c.blocked_models, model) {
            return refuse(
                403,
                "model_blocked",
                format!("the model `{shown}` is blocked in this workspace by an owner"),
            );
        }
        if c.policy()
            .is_some_and(|p| !p.allows_dispatch(model, provider))
        {
            return refuse(
                403,
                "policy_model_denied",
                format!("the workspace policy does not allow the model `{shown}` on `{provider}`"),
            );
        }
    }
    if claims
        .governance
        .as_deref()
        .is_some_and(|g| !g.allows_dispatch(model, provider))
    {
        return refuse(
            403,
            "policy_model_denied",
            format!("this API key's policy does not allow the model `{shown}` on `{provider}`"),
        );
    }
    None
}

// ── The control-change record ────────────────────────────────────────────────
//
// The `OG-35` hook is `crate::db::controls::record_control_change` — in `db/` so it
// runs inside each write's own transaction.

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use tracelane_shared::key_policy::{PolicyRequest, Resolved, Subject};

    fn req(model: &str) -> PolicyRequest {
        PolicyRequest {
            subjects: vec![Subject {
                line: None,
                model: Fact::Known(model.into()),
                workspace_alias: true,
                provider: None,
                input_tokens: Fact::Known(1),
                output_cap: Fact::Known(Some(1)),
            }],
            body_bytes: Fact::Known(1),
        }
    }

    /// `fast` is a workspace alias for `gpt-4o`; everything routes to openai except
    /// `claude*`.
    fn resolve(m: &str, ws: bool) -> Resolved {
        let target = if ws && m == "fast" { "gpt-4o" } else { m };
        let mut names = vec![m.to_owned()];
        if target != m {
            names.push(target.to_owned());
        }
        Resolved {
            names,
            allow_names: vec![target.to_owned()],
            provider: Some(if target.starts_with("claude") {
                "anthropic".into()
            } else {
                "openai".into()
            }),
        }
    }

    fn code(r: Result<(), ControlRefusal>) -> Option<&'static str> {
        match r {
            Ok(()) => None,
            Err(ControlRefusal::Paused { .. }) => Some("workspace_paused"),
            Err(ControlRefusal::Blocked(d)) => Some(d.code),
        }
    }

    #[test]
    fn the_shipped_block_parses() {
        let c = parse_table(include_str!("../translation_policy.v1.json")).expect("parses");
        assert_eq!(c, config());
        assert!(parse_table(r#"{"gateway_controls":{"max_block_entries":0}}"#).is_none());
    }

    #[test]
    fn og25_nothing_set_restricts_nothing() {
        let c = WorkspaceControls::default();
        assert!(!c.restricts());
        assert_eq!(
            code(check_request(&c, &req("gpt-4o"), Some("u1"), &resolve)),
            None
        );
    }

    #[test]
    fn og25_a_pause_refuses_everything_first() {
        let c = WorkspaceControls {
            paused: Some(Pause {
                at: chrono::Utc::now(),
                by: None,
                reason: None,
            }),
            ..Default::default()
        };
        assert_eq!(
            code(check_request(&c, &req("gpt-4o"), None, &resolve)),
            Some("workspace_paused")
        );
    }

    #[test]
    fn og25_blocked_model_provider_and_end_user_refuse_and_an_alias_cannot_launder() {
        let c = WorkspaceControls::from_row(None, None, vec!["GPT-4o*".into()], vec![], vec![]);
        assert_eq!(
            code(check_request(&c, &req("gpt-4o-mini"), None, &resolve)),
            Some("model_blocked")
        );
        assert_eq!(
            code(check_request(&c, &req("fast"), None, &resolve)),
            Some("model_blocked"),
            "the workspace alias `fast` targets gpt-4o"
        );
        assert_eq!(
            code(check_request(&c, &req("claude-x"), None, &resolve)),
            None
        );

        let c = WorkspaceControls::from_row(None, None, vec![], vec!["Anthropic".into()], vec![]);
        assert_eq!(
            code(check_request(&c, &req("claude-x"), None, &resolve)),
            Some("provider_blocked")
        );
        assert_eq!(
            code(check_request(&c, &req("gpt-4o"), None, &resolve)),
            None
        );
        assert!(!allows_dispatch(&c, "claude-x", "anthropic"));
        assert!(allows_dispatch(&c, "gpt-4o", "openai"));

        let c = WorkspaceControls::from_row(None, None, vec![], vec![], vec!["bad-user".into()]);
        assert_eq!(
            code(check_request(
                &c,
                &req("gpt-4o"),
                Some("bad-user"),
                &resolve
            )),
            Some("end_user_blocked")
        );
        assert_eq!(
            code(check_request(
                &c,
                &req("gpt-4o"),
                Some("good-user"),
                &resolve
            )),
            None
        );
        assert_eq!(
            code(check_request(&c, &req("gpt-4o"), None, &resolve)),
            None
        );
    }

    #[test]
    fn og25_a_route_that_cannot_name_its_model_is_refused_under_a_model_block() {
        let c = WorkspaceControls::from_row(None, None, vec!["x".into()], vec![], vec![]);
        let opaque = PolicyRequest {
            subjects: vec![Subject::unknown()],
            body_bytes: Fact::Unknown,
        };
        assert_eq!(
            code(check_request(&c, &opaque, None, &resolve)),
            Some("block_unenforceable")
        );
    }

    #[test]
    fn og25_a_workspace_policy_with_a_key_rule_is_invalid_and_refuses_everything() {
        let c = WorkspaceControls::from_row(
            Some(&json!({"max_output_tokens": 5})),
            None,
            vec![],
            vec![],
            vec![],
        );
        assert!(c.restricts());
        assert_eq!(
            code(check_request(&c, &req("gpt-4o"), None, &resolve)),
            Some("policy_invalid")
        );
        let ok = WorkspaceControls::from_row(
            Some(&json!({"limits": {"rpm": 5}})),
            None,
            vec![],
            vec![],
            vec![],
        );
        assert!(ok.policy().is_some());
        assert_eq!(
            code(check_request(&ok, &req("gpt-4o"), None, &resolve)),
            None
        );
    }
}
