//! Tenant/server scoped MCP policy. A failed cached-policy read never grants access.
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    #[default]
    Observe,
    Enforce,
}
#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    #[default]
    Allow,
    RequireApproval,
    Deny,
}
#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub rules_mode: Mode,
    pub pins_mode: Mode,
    pub injection_mode: Mode,
    pub default_action: Action,
}
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub id: Uuid,
    pub server_id: Option<Uuid>,
    pub key_id: Option<Uuid>,
    pub tool_glob: String,
    pub action: Action,
    pub reason: String,
}

pub fn evaluate(
    policy: &Policy,
    rules: &[Rule],
    server: Uuid,
    key: Option<Uuid>,
    tool: &str,
) -> Action {
    rules
        .iter()
        .filter(|r| {
            r.server_id.is_none_or(|id| id == server)
                && r.key_id.is_none_or(|id| Some(id) == key)
                && tracelane_shared::key_policy::glob_match(&r.tool_glob, tool)
        })
        .map(|r| r.action)
        .max()
        .unwrap_or(policy.default_action)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn rule(glob: &str, action: Action) -> Rule {
        Rule {
            id: Uuid::from_u128(1),
            server_id: None,
            key_id: None,
            tool_glob: glob.into(),
            action,
            reason: String::new(),
        }
    }
    #[test]
    fn mcp_rule_precedence_matrix() {
        for rules in [
            vec![rule("*", Action::Allow), rule("delete_*", Action::Deny)],
            vec![
                rule("delete_*", Action::Deny),
                rule("*", Action::RequireApproval),
            ],
        ] {
            assert_eq!(
                evaluate(&Policy::default(), &rules, Uuid::nil(), None, "DELETE_repo"),
                Action::Deny
            );
        }
        assert_eq!(
            evaluate(
                &Policy::default(),
                &[rule("*", Action::RequireApproval)],
                Uuid::nil(),
                None,
                "create_pr"
            ),
            Action::RequireApproval
        );
    }
    #[test]
    fn mcp_global_server_rule_matches() {
        assert_eq!(
            evaluate(
                &Policy::default(),
                &[rule("get*", Action::Deny)],
                Uuid::from_u128(3),
                None,
                "get"
            ),
            Action::Deny
        );
    }
    #[test]
    fn mcp_key_specific_rule_matches() {
        let mut r = rule("*", Action::Deny);
        r.key_id = Some(Uuid::from_u128(4));
        assert_eq!(
            evaluate(
                &Policy::default(),
                &[r],
                Uuid::nil(),
                Some(Uuid::from_u128(4)),
                "search"
            ),
            Action::Deny
        );
    }
    #[test]
    fn mcp_wrong_key_rule_does_not_match() {
        let mut r = rule("*", Action::Deny);
        r.key_id = Some(Uuid::from_u128(4));
        assert_eq!(
            evaluate(
                &Policy::default(),
                &[r],
                Uuid::nil(),
                Some(Uuid::from_u128(5)),
                "search"
            ),
            Action::Allow
        );
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Settings {
    pub principal: PrincipalLimits,
    pub limits: Limits,
    pub proxied_methods: Vec<String>,
    pub allow_passthrough_auth: bool,
    pub policy: PolicyLimits,
    pub approvals: ApprovalLimits,
    pub chat: ChatLimits,
    pub spans: SpanLimits,
}
/// ACT-23: caps on a signed chat interaction (`specs/ACT-23-approve-from-slack-and-teams.md` §5).
/// Security parameters, not workspace settings.
#[derive(Debug, Deserialize, Serialize)]
pub struct ChatLimits {
    /// A signed request whose timestamp is further than this from our clock (either way) is
    /// refused. 300 = the 5 minutes in Slack's published verification example; capped at 600.
    pub replay_window_secs: i64,
    /// Larger bodies are refused before any HMAC is computed. Our message is under 4 KB; capped at 65536.
    pub max_interaction_bytes: usize,
}
/// Reviewed ACT-16 caps; invalid seed data fails CLOSED in settings().
#[derive(Debug, Deserialize, Serialize)]
pub struct PrincipalLimits {
    pub clock_skew_secs: i64,
    pub max_lifetime_secs: i64,
    pub jwks_ttl_secs: u64,
    pub max_issuers: usize,
    pub max_roles: usize,
    pub max_claim_chars: usize,
    pub max_token_bytes: usize,
    pub max_jwks_bytes: usize,
    pub cache_entries: u64,
}
#[derive(Debug, Deserialize, Serialize)]
pub struct SpanLimits {
    pub methods: Vec<String>,
    pub max_verdicts: usize,
    pub max_content_bytes: usize,
    pub usage: McpUsageLimits,
}
#[derive(Debug, Deserialize, Serialize)]
pub struct McpUsageLimits {
    pub window_default_hours: u32,
    pub window_max_days: u32,
    pub min_samples_for_p95: u32,
    pub latency_excluded_methods: Vec<String>,
    pub max_groups: u32,
}
#[derive(Debug, Deserialize, Serialize)]
pub struct Limits {
    pub max_servers_per_workspace: usize,
    pub max_request_bytes: usize,
    pub max_response_bytes: usize,
    pub call_timeout_secs: u64,
    pub max_event_bytes: usize,
    pub max_legacy_sessions_per_workspace: usize,
    pub max_pending_calls_per_session: usize,
    pub max_tool_list_pages: usize,
    pub max_header_bytes: usize,
    pub max_name_chars: usize,
    pub max_slug_chars: usize,
    pub legacy_session_secs: u64,
    pub legacy_event_buffer: usize,
    pub max_legacy_sessions_total: usize,
    pub max_url_bytes: usize,
}
#[derive(Debug, Deserialize, Serialize)]
pub struct PolicyLimits {
    pub max_rules_per_workspace: usize,
    pub tool_glob_max_chars: usize,
    pub reason_max_chars: usize,
    pub observer_max_tracked: usize,
    pub observer_max_name_len: usize,
    pub observer_flush_secs: u64,
    pub pin_cache_ttl_secs: u64,
    pub verify_timeout_ms: u64,
    pub preview_window_hours: i64,
    pub preview_max_window_hours: i64,
}
#[derive(Debug, Deserialize, Serialize)]
pub struct ApprovalLimits {
    pub hold_secs: u64,
    pub model_hold_secs: u64,
    pub default_ttl_secs: i32,
    pub max_ttl_secs: i32,
    pub grant_ttl_secs: i32,
    pub max_pending_per_workspace: usize,
    pub approval_notice_window_secs: i64,
    pub max_held_per_workspace: usize,
    pub max_held_total: usize,
    pub sweep_secs: u64,
    pub sweep_batch: usize,
    pub preview_max_bytes: usize,
    pub note_max_chars: usize,
    pub list_page_size: usize,
    pub max_list_page_size: usize,
    /// ACT-15b: an `as_of` newer than this is refused; later commits can still land behind it.
    /// MUST be >= the write path's statement timeout (`limits.call_timeout_secs`, 120) plus a
    /// clock-skew allowance (30): 150. A write that began before T cannot commit after T+150.
    pub register_as_of_min_age_secs: i64,
    /// ACT-15b: `statement_timeout` for the register's read-only transaction.
    pub register_read_timeout_secs: u64,
    /// ACT-41: an approve needs the approver's signed `auth_time` within this many seconds.
    /// A security parameter, not a workspace setting (`specs/ACT-41-approver-step-up.md` §1);
    /// 900 = 15 min (unverified industry practice). The refusal body carries it to the dashboard.
    pub approver_auth_max_age_secs: i64,
    pub capacity_retry_secs: u32,
    pub paused_refusal_attempts_per_key_epoch: usize,
    pub paused_refusal_queue_capacity: usize,
    pub paused_refusal_dedup_entries: usize,
    pub paused_refusal_budget_entries: usize,
    pub paused_refusal_queued_per_tenant: usize,
    pub paused_refusal_queue_bytes: usize,
    pub paused_refusal_timeout_ms: u64,
}
/// A malformed embedded reference table fails closed; never guess a security cap.
pub fn settings() -> anyhow::Result<&'static Settings> {
    static CONFIG: std::sync::OnceLock<Result<Settings, String>> = std::sync::OnceLock::new();
    CONFIG
        .get_or_init(|| parse_settings(include_str!("../mcp_policy.v1.json")))
        .as_ref()
        .map_err(|_| anyhow::anyhow!("MCP reference table unavailable"))
}
fn parse_settings(raw: &str) -> Result<Settings, String> {
    let settings: Settings = serde_json::from_str(raw).map_err(|e| e.to_string())?;
    let p = &settings.principal;
    if p.max_lifetime_secs <= 0
        || p.clock_skew_secs < 0
        || p.clock_skew_secs > p.max_lifetime_secs
        || p.jwks_ttl_secs == 0
        || p.max_issuers == 0
        || p.max_roles == 0
        || p.max_claim_chars == 0
        || p.max_token_bytes == 0
        || p.max_jwks_bytes == 0
        || p.cache_entries == 0
        || p.max_claim_chars > p.max_token_bytes
        || p.max_token_bytes > settings.limits.max_request_bytes
        || p.max_jwks_bytes > settings.limits.max_response_bytes
        || settings.approvals.approver_auth_max_age_secs <= 0
        || !(1..=600).contains(&settings.chat.replay_window_secs)
        || !(1..=65536).contains(&settings.chat.max_interaction_bytes)
    {
        return Err("invalid principal limits".into());
    }
    Ok(settings)
}
pub fn valid_glob(glob: &str) -> bool {
    settings().is_ok_and(|l| {
        !glob.is_empty()
            && glob.len() <= l.policy.tool_glob_max_chars
            && glob
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"*_.:/-".contains(&c))
    })
}

pub fn refusal(status: u16, code: &'static str) -> crate::admission::Refusal {
    crate::admission::Refusal::Control(crate::admission::ControlDenial {
        status,
        code,
        message: code.replace('_', " "),
        detail: vec![],
        retry_after_secs: None,
    })
}
/// The single Tools admission step, for MCP tool and ordinary model requests.
/// Fail CLOSED on missing control state, invalid rules or an unconsumed approval.
pub async fn enforce(
    state: &crate::server::AppState,
    headers: &axum::http::HeaderMap,
    claims: &crate::auth::Claims,
    parsed: ToolsRequest,
    entitlements: Option<&std::sync::Arc<crate::entitlement_cache::ResolvedEntitlements>>,
    trace: Uuid,
) -> Result<Option<String>, crate::admission::Refusal> {
    use tracelane_shared::key_policy::Fact;
    let Some(snapshot) = entitlements.and_then(|e| e.mcp.as_ref()) else {
        return if parsed.mcp.is_some() || state.pg.is_some() {
            Err(refusal(403, "mcp_policy_invalid"))
        } else {
            Ok(None)
        };
    };
    if snapshot.rules.iter().any(|r| !valid_glob(&r.tool_glob))
        || snapshot
            .model_rules
            .iter()
            .any(|r| !valid_glob(&r.model_glob))
    {
        return Err(refusal(403, "mcp_policy_invalid"));
    }
    let key = claims.api_key_id().and_then(|k| Uuid::parse_str(k).ok());
    let supplied = headers
        .get("x-tracelane-approval-id")
        .and_then(|v| v.to_str().ok());
    if let Some(mcp) = parsed.mcp.as_ref() {
        let server = snapshot
            .servers
            .iter()
            .find(|s| s.slug == mcp.slug)
            .ok_or_else(|| refusal(404, "mcp_server_not_found"))?;
        if !server.enabled {
            return Err(refusal(403, "mcp_server_disabled"));
        }
        if mcp.method != "tools/call" {
            return Ok(None);
        }
        let tool = mcp.envelope["params"]["name"]
            .as_str()
            .ok_or_else(|| refusal(400, "invalid_tool_name"))?;
        let timeout = std::time::Duration::from_secs(
            settings()
                .map_err(|_| refusal(503, "mcp_policy_invalid"))?
                .limits
                .call_timeout_secs,
        );
        let protected = tokio::time::timeout(
            timeout,
            crate::mcp_proxy::protected::classify(
                state,
                claims,
                entitlements.map(|e| e.as_ref()),
                mcp,
                server,
                tool,
            ),
        )
        .await
        .map_err(|_| refusal(503, "protected_execution_unavailable"))?
        .map_err(|e| {
            if e.to_string() == "invalid_protected_request" {
                refusal(400, "invalid_protected_request")
            } else if e.to_string() == "mcp_tool_protected_elsewhere" {
                refusal(403, "mcp_tool_protected_elsewhere")
            } else {
                refusal(503, "protected_execution_unavailable")
            }
        })?;
        if protected {
            return Ok(None);
        }
        match evaluate(&snapshot.policy, &snapshot.rules, server.id, key, tool) {
            Action::Deny if snapshot.policy.rules_mode == Mode::Enforce => {
                let mut denied = crate::admission::ControlDenial {
                    status: 403,
                    code: "mcp_tool_denied",
                    message: "mcp tool denied".into(),
                    detail: Vec::new(),
                    retry_after_secs: None,
                };
                if let Some(rule) = snapshot.rules.iter().find(|r| {
                    r.action == Action::Deny
                        && r.server_id.is_none_or(|s| s == server.id)
                        && r.key_id.is_none_or(|k| Some(k) == key)
                        && tracelane_shared::key_policy::glob_match(&r.tool_glob, tool)
                }) {
                    denied.detail.push(("rule_id", serde_json::json!(rule.id)));
                }
                Err(crate::admission::Refusal::Control(denied))
            }
            Action::RequireApproval if snapshot.policy.rules_mode == Mode::Enforce => {
                let rule = snapshot
                    .rules
                    .iter()
                    .find(|r| {
                        r.action == Action::RequireApproval
                            && r.server_id.is_none_or(|s| s == server.id)
                            && r.key_id.is_none_or(|k| Some(k) == key)
                            && tracelane_shared::key_policy::glob_match(&r.tool_glob, tool)
                    })
                    .map(|r| r.id);
                use secrecy::ExposeSecret;
                let key = crate::tool_fingerprint::workspace_key(&claims.tenant_id)
                    .ok_or_else(|| refusal(503, "approval_unavailable"))?;
                let binding = execution_binding(mcp, server, headers, key.expose_secret());
                crate::approvals::gate(
                    state,
                    claims,
                    crate::approvals::Request {
                        kind: "tool",
                        server: Some(server.id),
                        subject: tool,
                        rule,
                        ttl_secs: snapshot.approval_settings.default_ttl_secs,
                        body: &binding,
                        trace_id: trace,
                    },
                    supplied,
                    headers,
                    entitlements,
                )
                .await
                .map(Some)
                .map_err(crate::admission::Refusal::Control)
            }
            _ => Ok(None),
        }
    } else {
        let request = &parsed.policy_request;
        for rule in snapshot
            .model_rules
            .iter()
            .filter(|r| r.key_id.is_none_or(|k| Some(k) == key))
        {
            if request
                .subjects
                .iter()
                .any(|s| matches!(s.model, Fact::Unknown))
            {
                return Err(refusal(403, "approval_unenforceable"));
            }
            if request.subjects.iter().any(|s| match &s.model {
                Fact::Known(model) => {
                    tracelane_shared::key_policy::glob_match(&rule.model_glob, model)
                }
                _ => false,
            }) {
                if parsed.body.is_null() {
                    return Err(refusal(403, "approval_unenforceable"));
                }
                let targets: Vec<_> = request
                    .subjects
                    .iter()
                    .map(|s| {
                        let model = match &s.model {
                            Fact::Known(model) => Some(model),
                            _ => None,
                        };
                        serde_json::json!({"model":model,"provider":s.provider,"line":s.line})
                    })
                    .collect();
                let binding = serde_json::json!({"request":parsed.body,"targets":targets});
                return crate::approvals::gate(
                    state,
                    claims,
                    crate::approvals::Request {
                        kind: "model",
                        server: None,
                        subject: &parsed.model,
                        rule: Some(rule.id),
                        ttl_secs: rule
                            .ttl_secs
                            .unwrap_or(snapshot.approval_settings.default_ttl_secs),
                        body: &binding,
                        trace_id: trace,
                    },
                    supplied,
                    headers,
                    entitlements,
                )
                .await
                .map(Some)
                .map_err(crate::admission::Refusal::Control);
            }
        }
        Ok(None)
    }
}

pub struct ToolsRequest {
    pub model: String,
    pub body: serde_json::Value,
    pub policy_request: tracelane_shared::key_policy::PolicyRequest,
    pub mcp: Option<crate::mcp_proxy::McpRequest>,
}

pub(crate) fn execution_binding(
    mcp: &crate::mcp_proxy::McpRequest,
    server: &crate::mcp_store::Server,
    headers: &axum::http::HeaderMap,
    key: &[u8; 32],
) -> serde_json::Value {
    let mut context = blake3::Hasher::new_keyed(key);
    context.update(b"mcp-execution-context-v1");
    let server_config =
        serde_json::json!({"server":server,"ciphertext":server.credential_ct}).to_string();
    for value in [
        server_config.as_bytes(),
        headers.get("mcp-session-id").map_or(&[], |v| v.as_bytes()),
        headers
            .get("x-tracelane-upstream-authorization")
            .map_or(&[], |v| v.as_bytes()),
        headers
            .get("mcp-protocol-version")
            .map_or(&[], |v| v.as_bytes()),
    ] {
        context.update(&(value.len() as u64).to_le_bytes());
        context.update(value);
    }
    serde_json::json!({"method":mcp.method,"params":mcp.envelope.get("params"),"execution_context":context.finalize().to_hex().to_string()})
}
#[cfg(test)]
mod security_tests {
    use super::*;
    use axum::http::{HeaderMap, Method};
    use serde_json::json;
    fn server() -> crate::mcp_store::Server {
        serde_json::from_value(json!({"id":Uuid::new_v4(),"slug":"example","name":"Example","url":"https://example.com/mcp","transport":"streamable_http","auth_mode":"passthrough","credential_kind":"bearer","credential_header":null,"credential_ct":null,"credential_last4":null,"enabled":true})).unwrap()
    }
    fn request() -> crate::mcp_proxy::McpRequest {
        crate::mcp_proxy::McpRequest {
            raw_body: None,
            protected: Default::default(),
            slug: "example".into(),
            method: "tools/call".into(),
            envelope: json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"delete","arguments":{"name":"same"}}}),
            http_method: Method::POST,
        }
    }
    #[test]
    fn approval_binding_rejects_changed_account() {
        crate::tool_fingerprint::init_from_existing_pepper(&"07".repeat(32)).unwrap();
        let r = request();
        let s = server();
        let mut a = HeaderMap::new();
        let mut b = HeaderMap::new();
        a.insert(
            "x-tracelane-upstream-authorization",
            "Bearer account-a".parse().unwrap(),
        );
        b.insert(
            "x-tracelane-upstream-authorization",
            "Bearer account-b".parse().unwrap(),
        );
        assert_ne!(
            execution_binding(&r, &s, &a, &[7; 32]),
            execution_binding(&r, &s, &b, &[7; 32])
        );
    }
    #[test]
    fn approval_binding_rejects_changed_session() {
        let r = request();
        let s = server();
        let mut a = HeaderMap::new();
        let mut b = HeaderMap::new();
        a.insert("mcp-session-id", "session-a".parse().unwrap());
        b.insert("mcp-session-id", "session-b".parse().unwrap());
        assert_ne!(
            execution_binding(&r, &s, &a, &[7; 32]),
            execution_binding(&r, &s, &b, &[7; 32])
        );
    }
    #[test]
    fn approval_binding_rejects_changed_server() {
        let r = request();
        let a = server();
        let mut b = a.clone();
        b.url = "https://different.example.com/mcp".into();
        assert_ne!(
            execution_binding(&r, &a, &HeaderMap::new(), &[7; 32]),
            execution_binding(&r, &b, &HeaderMap::new(), &[7; 32])
        );
    }
    #[test]
    fn approval_binding_allows_new_rpc_id() {
        let a = request();
        let mut b = a.clone();
        b.envelope["id"] = json!(2);
        let s = server();
        assert_eq!(
            execution_binding(&a, &s, &HeaderMap::new(), &[7; 32]),
            execution_binding(&b, &s, &HeaderMap::new(), &[7; 32])
        );
    }
}

pub async fn ensure_fresh(
    state: &crate::server::AppState,
    headers: &axum::http::HeaderMap,
    claims: &crate::auth::Claims,
    expected: Option<&std::sync::Arc<crate::entitlement_cache::ResolvedEntitlements>>,
) -> Result<(), crate::admission::Refusal> {
    let credential = crate::offpath::key_credential(headers);
    match crate::offpath::key_liveness(claims, credential.as_deref()).await {
        crate::offpath::KeyLiveness::Live(governance) if governance == claims.governance => {}
        crate::offpath::KeyLiveness::Revoked => return Err(refusal(401, "key_revoked")),
        _ => return Err(refusal(503, "control_unverifiable")),
    }
    if let (Some(cache), Some(expected)) = (&state.entitlements, expected) {
        if !cache.is_current(*claims.tenant_id.as_uuid(), expected) {
            return Err(refusal(503, "control_changed"));
        }
        if let Some(snapshot) = &expected.mcp {
            crate::kms::KeyVault::global()
                .map_err(|_| refusal(503, "credential_configuration_changed"))?
                .check_revision(&claims.tenant_id, snapshot.kms_revision)
                .map_err(|_| refusal(503, "credential_configuration_changed"))?;
        }
    } else if state.pg.is_some() {
        return Err(refusal(503, "control_unverifiable"));
    }
    Ok(())
}
#[cfg(test)]
mod freshness_tests {
    use super::*;
    #[tokio::test]
    async fn mcp_revoked_key_cannot_resume() {
        let state =
            crate::handler_harness::test_state(crate::providers::ProviderRegistry::new().unwrap());
        let mut claims = crate::auth::dev_stub_claims(crate::auth::AuthMethod::ApiKey);
        claims.sub = format!("apikey:{}", Uuid::new_v4());
        crate::offpath::test_revoked()
            .lock()
            .insert(claims.api_key_id().unwrap().into());
        let denied = ensure_fresh(&state, &axum::http::HeaderMap::new(), &claims, None).await;
        crate::offpath::test_revoked()
            .lock()
            .remove(claims.api_key_id().unwrap());
        assert!(
            denied.is_err(),
            "A revoked key must not resume after approval"
        );
    }
}

/// Resolve every declared route target through the same aliases used by policy admission.
pub fn resolved_request(
    request: tracelane_shared::key_policy::PolicyRequest,
    entitlements: Option<&crate::entitlement_cache::ResolvedEntitlements>,
    plan: Option<&crate::routing::RoutePlan>,
) -> tracelane_shared::key_policy::PolicyRequest {
    use tracelane_shared::key_policy::Fact;
    let mut request = crate::routing::expand(request, plan);
    request.subjects = request
        .subjects
        .into_iter()
        .flat_map(|subject| {
            if let Fact::Known(model) = &subject.model {
                let resolved = crate::admission::routed_policy_resolve(
                    model,
                    subject.workspace_alias,
                    entitlements,
                    plan,
                );
                resolved
                    .names
                    .into_iter()
                    .map(|name| {
                        let mut s = subject.clone();
                        s.model = Fact::Known(name);
                        s.provider.clone_from(&resolved.provider);
                        s.workspace_alias = false;
                        s
                    })
                    .collect::<Vec<_>>()
            } else {
                vec![subject]
            }
        })
        .collect();
    request
}
#[cfg(test)]
#[test]
fn principal_limits_reject_zero() {
    let value: serde_json::Value =
        serde_json::from_str(include_str!("../mcp_policy.v1.json")).unwrap();
    for key in [
        "max_lifetime_secs",
        "jwks_ttl_secs",
        "max_issuers",
        "max_roles",
        "max_claim_chars",
        "max_token_bytes",
        "max_jwks_bytes",
        "cache_entries",
    ] {
        let mut candidate = value.clone();
        candidate["principal"][key] = serde_json::json!(0);
        assert!(
            parse_settings(&candidate.to_string()).is_err(),
            "zero {key} accepted"
        );
    }
}

#[cfg(test)]
#[test]
fn principal_clock_skew_settings_bounds() {
    let original: serde_json::Value =
        serde_json::from_str(include_str!("../mcp_policy.v1.json")).unwrap();
    let lifetime = original["principal"]["max_lifetime_secs"].as_i64().unwrap();
    for (skew, accepted) in [
        (-1, false),
        (0, true),
        (lifetime, true),
        (lifetime + 1, false),
    ] {
        let mut value = original.clone();
        value["principal"]["clock_skew_secs"] = serde_json::json!(skew);
        assert_eq!(parse_settings(&value.to_string()).is_ok(), accepted);
    }
}

#[cfg(test)]
#[test]
fn act41_approver_auth_window_bounds() {
    let original: serde_json::Value =
        serde_json::from_str(include_str!("../mcp_policy.v1.json")).unwrap();
    assert_eq!(original["approvals"]["approver_auth_max_age_secs"], 900);
    for (window, accepted) in [(-1, false), (0, false), (1, true), (900, true)] {
        let mut value = original.clone();
        value["approvals"]["approver_auth_max_age_secs"] = serde_json::json!(window);
        assert_eq!(
            parse_settings(&value.to_string()).is_ok(),
            accepted,
            "{window}"
        );
    }
    let mut value = original;
    value["approvals"]
        .as_object_mut()
        .unwrap()
        .remove("approver_auth_max_age_secs");
    assert!(
        parse_settings(&value.to_string()).is_err(),
        "missing window accepted"
    );
}
#[cfg(test)]
#[test]
#[rustfmt::skip]
fn chat_limits_are_bounded() {
    let value: serde_json::Value =
        serde_json::from_str(include_str!("../mcp_policy.v1.json")).unwrap();
    for (key, value_in, accepted) in [("replay_window_secs", 0, false), ("replay_window_secs", 1, true), ("replay_window_secs", 600, true), ("replay_window_secs", 601, false),
        ("max_interaction_bytes", 0, false), ("max_interaction_bytes", 65536, true), ("max_interaction_bytes", 65537, false)] {
        let mut candidate = value.clone();
        candidate["chat"][key] = serde_json::json!(value_in);
        assert_eq!(
            parse_settings(&candidate.to_string()).is_ok(),
            accepted,
            "chat.{key} = {value_in}"
        );
    }
}
