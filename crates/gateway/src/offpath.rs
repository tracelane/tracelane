//! rev5 `H2` / `M1` — the Wave C/D controls for provider calls that do NOT run
//! `admission::run`: eval-run cases and their judges (`prompt_eval.rs`), experiment arms
//! (the same executor), the online-eval judge (`online_eval.rs`), and the realtime
//! session's mid-session re-check (`realtime.rs`).
//!
//! **Not a parallel implementation.** Every check here is the admission step's own
//! function, called with what an off-path caller knows:
//!
//! | Wave C/D control | function (shared with admission) |
//! |---|---|
//! | `OG-25` pause, model / provider blocks | `controls::check_request` |
//! | `OG-20` key / project policy | `Governance::evaluate` |
//! | `OG-21` RPM / TPM limits | `admission::limit_checks` + `limits::table().admit` |
//! | `OG-22` policy budgets | `admission::applicable_budgets` + `admission::check_budget` |
//! | `GWY-43` per-key budget | the `spend` tracker, seeded as admission seeds it |
//!
//! **What an off-path call cannot know, and how that resolves (fail-CLOSED).** There is no
//! inbound request body for the provider call (so a `max_body_bytes` rule is
//! `policy_unenforceable`), no caller labels (a `required_tags` / `required_metadata_keys`
//! rule refuses `policy_required_*_missing`), no end user, and the eval executors declare
//! no output cap (a `max_output_tokens` rule refuses `policy_max_output_tokens`). A key
//! carrying any of those rules therefore cannot start or run an eval; the refusal names the
//! rule. The model, its provider and the input estimate ARE known, so the model / provider
//! / input-token rules, the blocks and the budgets are evaluated exactly as admission does.
//!
//! **Freshness.** The workspace controls are re-read through the entitlement cache on
//! EVERY call (a warm read; every control write invalidates it), so a pause or a block
//! stops a run that is already in flight at its next provider call.
//!
//! **TPM accounting.** An off-path call's TPM debit is its admission estimate (input + the
//! `default_output_reserve_tokens` reserve) and is not reconciled to actual usage — eval
//! spans do not run the chat path's `limits::reconcile_span`. RPM is exact.

use std::sync::Arc;

use tracelane_shared::key_policy::{Fact, PolicyRequest};
use tracelane_shared::{ChatRequest, TenantId};
use uuid::Uuid;

use crate::admission::Refusal;
use crate::auth::{AuthMethod, Claims};
use crate::entitlement_cache::{EntitlementCache, ResolvedEntitlements};

/// The two handles the checks read: the entitlement cache (controls, workspace policy,
/// budget tiers) and the ClickHouse URL the budget baselines are seeded from. An executor
/// holds its own copies, taken from the same `AppState` fields admission reads.
#[derive(Clone, Default)]
pub(crate) struct OffPathEnv {
    pub entitlements: Option<Arc<EntitlementCache>>,
    pub quota_ch_url: Option<String>,
}

impl OffPathEnv {
    pub(crate) fn of(state: &crate::server::AppState) -> Self {
        Self {
            entitlements: state.entitlements.clone(),
            quota_ch_url: state.quota_ch_url.clone(),
        }
    }

    fn spend_source(&self) -> crate::budgets::SpendSource<'_> {
        crate::budgets::SpendSource {
            quota_ch_url: self.quota_ch_url.as_deref(),
            entitlements: self.entitlements.as_ref(),
        }
    }
}

/// The principal a WORKSPACE-level background call runs as — the online-eval judge, which
/// an admin configured for the workspace and which no key made. No key, no key policy: the
/// workspace's own controls, limits and budgets bind it. Never handed to a capability or
/// scope check (it is not a credential).
pub(crate) fn workspace_principal(tenant: &TenantId) -> Claims {
    Claims {
        tenant_id: tenant.clone(),
        sub: "tracelane:workspace-background".to_owned(),
        auth_method: AuthMethod::Mtls,
        role: None,
        key_scope: crate::auth::scope::KeyScope::Scoped(std::collections::BTreeSet::new()),
        budget_usd_monthly: None,
        rate_limit_rpm: None,
        budget_reset: crate::spend::BudgetReset::Monthly,
        governance: None,
    }
}

/// What an off-path call reports to the policy: ONE generating chat call on the model it
/// will dispatch (no workspace alias is applied off-path), its input estimate and declared
/// output cap; the inbound body is unknown.
pub(crate) fn policy_request(req: &ChatRequest) -> PolicyRequest {
    PolicyRequest {
        subjects: vec![crate::admission::chat_subject(req, false, None)],
        body_bytes: Fact::Unknown,
    }
}

/// The refusing checks, charging nothing: `OG-25` pause and blocks, `OG-20` policy, the
/// `GWY-43` key budget and every `OG-22` budget that applies. Returns the entitlements it
/// read so [`admit`] does not read them twice.
///
/// # Errors
/// The first control that refuses — fail-CLOSED (a hard budget whose spend cannot be read
/// refuses, a rule the call cannot evaluate refuses).
pub(crate) async fn check(
    env: &OffPathEnv,
    claims: &Claims,
    req: &ChatRequest,
) -> Result<Option<Arc<ResolvedEntitlements>>, Refusal> {
    let tenant = &claims.tenant_id;
    // No control plane ⇒ no controls, no workspace policy (nothing can have been set) —
    // `.claude/rules/tenancy.md`: these are restrictions an owner adds, never grants.
    let ent = match &env.entitlements {
        Some(c) => Some(c.resolved(*tenant.as_uuid()).await),
        None => None,
    };
    let request = policy_request(req);
    let resolve = |m: &str, ws: bool| crate::admission::policy_resolve(m, ws, ent.as_deref());
    if let Some(c) = ent.as_deref().map(|e| &*e.controls)
        && c.restricts()
    {
        crate::controls::check_request(c, &request, None, &resolve).map_err(|r| match r {
            crate::controls::ControlRefusal::Paused { since } => {
                Refusal::Control(crate::admission::paused_denial(since))
            }
            crate::controls::ControlRefusal::Blocked(d) => Refusal::Policy(d),
        })?;
    }
    // rev5 M6: the workspace policy's model / provider rules (no `source_ips` here: the
    // call is the gateway's own, made for a request that authentication already judged).
    if let Some(ws) = ent
        .as_deref()
        .and_then(|e| crate::controls::WorkspaceControls::policy(&e.controls))
        .filter(|p| p.models.is_some() || p.providers.is_some())
    {
        ws.check_request(
            tracelane_shared::key_policy::Origin::Workspace,
            &request,
            &resolve,
        )
        .map_err(Refusal::Policy)?;
    }
    if let Some(gov) = claims.governance.as_deref().filter(|g| g.has_policy()) {
        gov.evaluate(
            &request,
            &resolve,
            &tracelane_shared::labels::Labels::default,
        )
        .map_err(Refusal::Policy)?;
    }
    check_key_budget(env, claims).await?;
    let ws_policy = ent
        .as_deref()
        .and_then(|e| crate::controls::WorkspaceControls::policy(&e.controls));
    for a in crate::admission::applicable_budgets(claims, ws_policy, None) {
        crate::admission::check_budget(env.spend_source(), tenant, &a).await?;
    }
    Ok(ent)
}

/// [`check`], then charge the `OG-21` RPM / TPM buckets of every layer that sets limits
/// (all-or-none, the same table admission charges). Call once per provider call.
///
/// # Errors
/// As [`check`], plus `429 rpm_limit_*` / `tpm_limit_*`. Fail-CLOSED.
pub(crate) async fn admit(
    env: &OffPathEnv,
    claims: &Claims,
    req: &ChatRequest,
) -> Result<(), Refusal> {
    let ent = check(env, claims, req).await?;
    let ws_policy = ent
        .as_deref()
        .and_then(|e| crate::controls::WorkspaceControls::policy(&e.controls));
    let has_limits = ws_policy.is_some_and(|p| p.limits.is_some())
        || claims
            .governance
            .as_deref()
            .is_some_and(|g| g.policies().any(|(_, p)| p.limits.is_some()));
    if !has_limits {
        return Ok(());
    }
    let request = policy_request(req);
    let checks =
        crate::admission::limit_checks(claims, ws_policy, &request, None, ent.as_deref(), None)
            .map_err(Refusal::Policy)?;
    crate::limits::table()
        .admit(
            *claims.tenant_id.as_uuid(),
            &checks,
            std::time::Instant::now(),
        )
        .map(|_debits| ())
        .map_err(|d| Refusal::Control(crate::admission::limit_denial(&d)))
}

/// `GWY-43`: the key's own ceiling, seeded from ClickHouse as admission seeds it.
pub(crate) async fn check_key_budget(env: &OffPathEnv, claims: &Claims) -> Result<(), Refusal> {
    let (Some(key_id), Some(budget)) = (claims.api_key_id(), claims.budget_usd_monthly) else {
        return Ok(());
    };
    let Ok(key_uuid) = Uuid::parse_str(key_id) else {
        return Ok(());
    };
    let who = crate::spend::Subject::Key(key_uuid);
    let spend = crate::spend::tracker();
    let window = crate::spend::window_key(claims.budget_reset, chrono::Utc::now());
    if spend.needs_seed(who, window) {
        let baseline = if spend.seed_backing_off(who) {
            None
        } else {
            crate::server::spend_baseline_from_clickhouse(
                env.spend_source(),
                &claims.tenant_id,
                key_id,
                claims.budget_reset,
            )
            .await
        };
        let Some(baseline) = baseline else {
            spend.note_seed_failed(who);
            return Err(Refusal::Control(crate::admission::spend_unknown_denial(
                "API key",
            )));
        };
        spend.seed_if_needed(who, window, baseline);
    }
    if let crate::spend::BudgetDecision::Exceeded {
        budget_usd,
        spent_usd,
    } = spend.check(who, Some(budget))
    {
        return Err(Refusal::KeyBudgetExceeded {
            budget_usd,
            spent_usd,
        });
    }
    Ok(())
}

/// After an off-path call: add its cost to the `OG-22` counters (workspace, the key's
/// project, the key) and the key's `GWY-43` counter. The WORKSPACE `spend` tracker is the
/// caller's to record (each executor already does, once).
pub(crate) fn record_spend(claims: &Claims, cost_usd: Option<f64>) {
    let Some(cost) = cost_usd.filter(|c| c.is_finite() && *c > 0.0) else {
        return;
    };
    let key = claims.api_key_id().and_then(|k| Uuid::parse_str(k).ok());
    let project = claims.governance.as_deref().and_then(|g| g.project_id);
    crate::budgets::table().record(
        *claims.tenant_id.as_uuid(),
        project,
        key,
        None,
        (cost * 1_000_000.0).round() as u64,
        chrono::Utc::now(),
        &crate::spend_alerts::enqueue,
    );
    if let Some(k) = key {
        crate::spend::tracker().record(crate::spend::Subject::Key(k), Some(cost));
    }
}

/// The refusal's stable code (`workspace_paused`, `model_blocked`, `policy_model_denied`,
/// `budget_exceeded_key`, …) — what an eval run's error and a 4xx body name.
pub(crate) fn code(r: &Refusal) -> &'static str {
    match r {
        Refusal::Policy(d) => d.code,
        Refusal::Control(c) => c.code,
        Refusal::KeyBudgetExceeded { .. } => "key_budget_exceeded",
        Refusal::WorkspaceBudgetExceeded { .. } => "workspace_budget_exceeded",
        Refusal::RateLimited { .. } => "rate_limited",
        Refusal::Unpriced { code, .. } => code,
        Refusal::InsufficientScope => "insufficient_scope",
        Refusal::MissingCredentials | Refusal::AuthFailed { .. } => "unauthorized",
        Refusal::Malformed(m) => m.code,
        Refusal::PredictiveBlock { .. } => "predictive_block",
        Refusal::AuditUnavailable => "audit_unavailable",
    }
}

/// `"<code>: <message>"`, for an eval case's error column and a run's stop reason.
pub(crate) fn describe(r: &Refusal) -> String {
    let message = match r {
        Refusal::Policy(d) => d.message.clone(),
        Refusal::Control(c) => c.message.clone(),
        Refusal::KeyBudgetExceeded {
            budget_usd,
            spent_usd,
        } => format!("this API key's budget is spent (${spent_usd:.2} of ${budget_usd:.2})"),
        Refusal::WorkspaceBudgetExceeded {
            budget_usd,
            spent_usd,
        } => format!("this workspace's budget is spent (${spent_usd:.2} of ${budget_usd:.2})"),
        Refusal::Unpriced { message, .. } => message.clone(),
        other => format!("refused ({})", code(other)),
    };
    format!("{}: {message}", code(r))
}

/// The error an off-path executor carries when a control refused a call — typed, so the
/// run can tell "the workspace stopped this" from a provider failure and stop early.
#[derive(Debug)]
pub(crate) struct OffPathRefused {
    /// The status admission would have answered (`423`, `403`, `402`, `429`, `503`).
    pub status: u16,
    pub code: &'static str,
    pub message: String,
}

impl std::fmt::Display for OffPathRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for OffPathRefused {}

impl From<&Refusal> for OffPathRefused {
    fn from(r: &Refusal) -> Self {
        Self {
            status: r.status().as_u16(),
            code: code(r),
            message: describe(r),
        }
    }
}

// ── rev5 M1 / rev6 H2 residual: is the starting API key still live? ────────────

/// The CURRENT state of the API key a long-running call (a realtime session, an eval or
/// experiment run) was started with.
pub(crate) enum KeyLiveness {
    /// Live, with its CURRENT policy layers (`None` = none, or not a key).
    Live(Option<Arc<tracelane_shared::key_policy::Governance>>),
    Revoked,
    /// The key store could not answer (after the auth cache's own stale-serving).
    Unknown,
}

/// Re-validate `claims`' key through the SAME lookup authentication uses (the auth cache
/// first; a revoke — single, revoke-all or a finished rotation — invalidates the entry, so
/// a revoked key misses and the store answers "not found"), returning its CURRENT policy.
/// No API key, no control plane, or no kept credential ⇒ nothing to re-validate (`Live`
/// with the claims' own policy). `credential` is the `Authorization` value the call
/// started with ([`key_credential`]).
///
/// Fail-CLOSED for a kept credential: one that is not a `tlane_` bearer, or a store that
/// cannot answer, is `Unknown`, which every caller treats as a stop.
pub(crate) async fn key_liveness(
    claims: &Claims,
    credential: Option<&secrecy::SecretString>,
) -> KeyLiveness {
    let Some(key_id) = claims.api_key_id() else {
        return KeyLiveness::Live(None);
    };
    #[cfg(test)]
    if test_revoked().lock().contains(key_id) {
        return KeyLiveness::Revoked;
    }
    #[cfg(test)]
    if let Some(g) = test_policy().lock().get(key_id) {
        return KeyLiveness::Live(g.clone());
    }
    let (Some(pool), Some(cred)) = (crate::db::global_pool(), credential) else {
        return KeyLiveness::Live(claims.governance.clone());
    };
    use secrecy::ExposeSecret as _;
    let Some(body) = cred
        .expose_secret()
        .strip_prefix("Bearer ")
        .and_then(|k| k.trim().strip_prefix("tlane_"))
    else {
        return KeyLiveness::Unknown;
    };
    match crate::db::api_keys::lookup_tenant_by_key_body(pool, body).await {
        Ok(Some(auth)) if auth.key_id.to_string() == key_id => KeyLiveness::Live(auth.governance),
        Ok(_) => KeyLiveness::Revoked,
        Err(_) => KeyLiveness::Unknown,
    }
}

/// rev6 H2 residual: the `tlane_` bearer a long-running call keeps so [`key_liveness`] can
/// re-validate it (zeroized on drop). Any other credential has nothing to revoke.
pub(crate) fn key_credential(
    headers: &axum::http::HeaderMap,
) -> Option<Arc<secrecy::SecretString>> {
    headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .filter(|v| v.trim_start().starts_with("Bearer tlane_"))
        .map(|v| Arc::new(secrecy::SecretString::from(v.trim().to_owned())))
}

/// rev6 H2 residual: re-validate a run's starting principal BETWEEN chunks, as the
/// realtime session does mid-session. `Ok` carries the principal with its CURRENT policy
/// (a policy tightened mid-run binds the next call); `Err` is the stop reason
/// (`"<code>: <message>"`) — the key was revoked (`key_revoked`, revoke-all included) or
/// could not be re-validated (`control_unverifiable`, fail-CLOSED).
pub(crate) async fn revalidate_caller(
    caller: &Arc<Claims>,
    credential: Option<&secrecy::SecretString>,
) -> Result<Arc<Claims>, String> {
    match key_liveness(caller, credential).await {
        KeyLiveness::Live(governance) => {
            if caller.api_key_id().is_none() || governance == caller.governance {
                Ok(Arc::clone(caller))
            } else {
                Ok(Arc::new(Claims {
                    governance,
                    ..(**caller).clone()
                }))
            }
        }
        KeyLiveness::Revoked => Err(
            "key_revoked: the API key that started this run was revoked — mint a new key and \
             start the run again"
                .to_owned(),
        ),
        KeyLiveness::Unknown => Err(
            "control_unverifiable: the API key that started this run could not be re-validated \
             (the key store did not answer), so the run stopped"
                .to_owned(),
        ),
    }
}

/// TEST-ONLY: key ids a test has "revoked" (the unit-test state has no key store).
#[cfg(test)]
pub(crate) fn test_revoked() -> &'static parking_lot::Mutex<std::collections::HashSet<String>> {
    static S: std::sync::OnceLock<parking_lot::Mutex<std::collections::HashSet<String>>> =
        std::sync::OnceLock::new();
    S.get_or_init(Default::default)
}

/// TEST-ONLY: what the key store would now answer for a key's policy (a policy tightened
/// mid-run), by key id.
#[cfg(test)]
type TestPolicies =
    std::collections::HashMap<String, Option<Arc<tracelane_shared::key_policy::Governance>>>;

#[cfg(test)]
pub(crate) fn test_policy() -> &'static parking_lot::Mutex<TestPolicies> {
    static S: std::sync::OnceLock<parking_lot::Mutex<TestPolicies>> = std::sync::OnceLock::new();
    S.get_or_init(Default::default)
}
