//! Live security checks at each provider attempt, including same-provider retries.
use crate::admission::{ControlDenial, Refusal};
use secrecy::ExposeSecret as _;
use std::sync::Arc;
use tracelane_shared::key_policy::{Fact, PolicyRequest};

pub(crate) struct Context {
    state: crate::server::AppState,
    claims: crate::auth::Claims,
    credential: Option<Arc<secrecy::SecretString>>,
    request: PolicyRequest,
    plan: Option<Arc<super::RoutePlan>>,
    end_user: Option<String>,
    labels: tracelane_shared::labels::Labels,
    zdr: bool,
}

#[derive(Debug, Clone, thiserror::Error)]
#[error("provider attempt refused by live controls")]
pub(crate) struct Denied(pub Refusal);

impl Denied {
    pub(crate) fn code(&self) -> &'static str {
        match &self.0 {
            Refusal::Control(c) => c.code,
            Refusal::Policy(d) => d.code,
            Refusal::KeyBudgetExceeded { .. } => "key_budget_exceeded",
            Refusal::WorkspaceBudgetExceeded { .. } => "workspace_budget_exceeded",
            Refusal::Unpriced { code, .. } => code,
            _ => "policy_denied",
        }
    }
}

fn denied(status: u16, code: &'static str) -> Refusal {
    Refusal::Control(ControlDenial {
        status,
        code,
        message: code.replace('_', " "),
        detail: vec![],
        retry_after_secs: None,
    })
}

impl Context {
    pub(crate) fn new(
        state: &crate::server::AppState,
        claims: &crate::auth::Claims,
        headers: &axum::http::HeaderMap,
        request: PolicyRequest,
        plan: Option<Arc<super::RoutePlan>>,
        end_user: Option<String>,
        credential: Option<Arc<secrecy::SecretString>>,
    ) -> Self {
        Self {
            state: state.clone(),
            claims: claims.clone(),
            credential,
            request,
            plan,
            end_user,
            labels: crate::server::request_labels::read(
                headers,
                &state.rate_card.load().policy.request_labels,
            )
            .0,
            zdr: matches!(
                crate::zdr::constraint_from_headers(headers),
                Ok(Some(crate::zdr::Constraint::Required))
            ),
        }
    }

    pub(crate) async fn check(
        &self,
        provider: &str,
        model: &str,
        label: &str,
        key: &secrecy::SecretString,
    ) -> Result<(), Denied> {
        let ent = self.check_controls(provider, model).await.map_err(Denied)?;
        // Resolve again AFTER the potentially waiting control checks. A rotated or
        // deleted key must not be sent by a request that selected it earlier.
        let env = crate::providers::ProviderRegistry::env_var_for_provider_id(provider);
        let (current, _) = crate::server::resolve_provider_key_labeled(
            &self.claims.tenant_id,
            provider,
            label,
            env,
        )
        .await;
        match current {
            // L4: constant-time — an early-exit `==` leaks how much of the key matched.
            crate::server::ProviderKey::Found(current)
                if crate::auth::constant_time_eq(
                    current.expose_secret().as_bytes(),
                    key.expose_secret().as_bytes(),
                ) =>
            {
                if let (Some(cache), Some(ent)) = (&self.state.entitlements, ent.as_ref())
                    && !cache.is_current(*self.claims.tenant_id.as_uuid(), ent)
                {
                    return Err(Denied(denied(503, "control_unverifiable")));
                }
                if self.state.kill_switch.upstream_killed(provider) {
                    return Err(Denied(denied(503, "upstream_killed")));
                }
                if self.zdr && !self.state.zdr.load().eligible(provider) {
                    return Err(Denied(denied(400, "zdr_unsatisfiable")));
                }
                Ok(())
            }
            _ => Err(Denied(denied(503, "provider_key_unavailable"))),
        }
    }

    async fn check_controls(
        &self,
        provider: &str,
        model: &str,
    ) -> Result<Option<Arc<crate::entitlement_cache::ResolvedEntitlements>>, Refusal> {
        let mut claims = self.claims.clone();
        match crate::offpath::key_liveness(&claims, self.credential.as_deref()).await {
            crate::offpath::KeyLiveness::Live(governance) => claims.governance = governance,
            crate::offpath::KeyLiveness::Revoked => return Err(denied(401, "key_revoked")),
            crate::offpath::KeyLiveness::Unknown => {
                return Err(denied(503, "control_unverifiable"));
            }
        }
        if self.state.kill_switch.upstream_killed(provider) {
            return Err(denied(503, "upstream_killed"));
        }
        if self.zdr && !self.state.zdr.load().eligible(provider) {
            return Err(denied(400, "zdr_unsatisfiable"));
        }
        let ent = match &self.state.entitlements {
            Some(cache) => Some(cache.resolved(*claims.tenant_id.as_uuid()).await),
            None => None,
        };
        if ent
            .as_ref()
            .is_some_and(|e| matches!(*e.routing, super::RoutingState::Invalid))
        {
            return Err(denied(503, "routing_invalid"));
        }
        let mut request = super::expand(self.request.clone(), self.plan.as_deref());
        // Legacy fallback targets also face the same rules as the declared targets.
        if !request
            .subjects
            .iter()
            .any(|s| matches!(&s.model, Fact::Known(m) if m == model))
            && let Some(mut subject) = request.subjects.first().cloned()
        {
            subject.model = Fact::Known(model.to_owned());
            subject.workspace_alias = false;
            subject.provider = None;
            subject.input_tokens = Fact::NotApplicable;
            subject.output_cap = Fact::NotApplicable;
            request.subjects.push(subject);
        }
        let resolve = |m: &str, ws| {
            crate::admission::routed_policy_resolve(m, ws, ent.as_deref(), self.plan.as_deref())
        };
        let controls = ent.as_ref().map(|e| e.controls.as_ref());
        if let Some(c) = controls {
            crate::controls::check_request(c, &request, self.end_user.as_deref(), &resolve)
                .map_err(|r| match r {
                    crate::controls::ControlRefusal::Paused { since } => {
                        Refusal::Control(crate::admission::paused_denial(since))
                    }
                    crate::controls::ControlRefusal::Blocked(d) => Refusal::Policy(d),
                })?;
        }
        let ws = controls.and_then(crate::controls::WorkspaceControls::policy);
        if let Some(ws) = ws {
            ws.check_request(
                tracelane_shared::key_policy::Origin::Workspace,
                &request,
                &resolve,
            )
            .map_err(Refusal::Policy)?;
        }
        if let Some(g) = claims.governance.as_deref() {
            g.evaluate(&request, &resolve, &|| self.labels.clone())
                .map_err(Refusal::Policy)?;
        }
        crate::offpath::check_key_budget(&crate::offpath::OffPathEnv::of(&self.state), &claims)
            .await?;
        if let Some(e) = ent.as_ref().filter(|e| e.workspace_budget_micro_usd > 0) {
            let who = crate::spend::Subject::Workspace(*claims.tenant_id.as_uuid());
            let spend = crate::spend::tracker();
            if spend.needs_seed(who, crate::server::current_year_month()) {
                return Err(denied(503, "budget_spend_unknown"));
            }
            if let crate::spend::BudgetDecision::Exceeded {
                budget_usd,
                spent_usd,
            } = spend.check(who, Some(e.workspace_budget_micro_usd as f64 / 1_000_000.0))
            {
                return Err(Refusal::WorkspaceBudgetExceeded {
                    budget_usd,
                    spent_usd,
                });
            }
        }
        if crate::admission::caller_is_budgeted(&claims, ent.as_deref())
            && let crate::admission::Pricing::Unpriced { code, message } =
                crate::admission::token_pricing(model)
        {
            return Err(Refusal::Unpriced { code, message });
        }
        for a in crate::admission::applicable_budgets(&claims, ws, self.end_user.as_deref()) {
            crate::admission::check_budget(
                crate::budgets::SpendSource::of(&self.state),
                &claims.tenant_id,
                &a,
            )
            .await?;
        }
        Ok(ent)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handler_harness::test_state;
    use crate::providers::ProviderRegistry;

    #[tokio::test]
    async fn og11_attempt_rechecks_zdr_key_revocation_tenant_and_budget() {
        let tenant = tracelane_shared::TenantId::from_jwt_claim(uuid::Uuid::new_v4());
        let other = tracelane_shared::TenantId::from_jwt_claim(uuid::Uuid::new_v4());
        let key = Arc::new(secrecy::SecretString::from("test-own-key".to_owned()));
        crate::db::provider_keys::cache_decrypted_labeled(&tenant, "openai", "named", key.clone());
        let state = test_state(ProviderRegistry::new().unwrap());
        state
            .zdr
            .store(Arc::new(crate::zdr::ZdrCapabilities::from_rows([(
                "openai".to_owned(),
                "default".to_owned(),
            )])));
        let id = uuid::Uuid::new_v4();
        let mut claims = crate::offpath::workspace_principal(&tenant);
        claims.auth_method = crate::auth::AuthMethod::ApiKey;
        claims.sub = format!("apikey:{id}");
        claims.budget_usd_monthly = Some(1.0);
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("x-tracelane-zdr", "required".parse().unwrap());
        let chat = serde_json::from_value(
            serde_json::json!({"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}),
        )
        .unwrap();
        let request = crate::offpath::policy_request(&chat);
        let context = Context::new(&state, &claims, &headers, request.clone(), None, None, None);
        let who = crate::spend::Subject::Key(id);
        crate::spend::tracker().seed_if_needed(who, crate::server::current_year_month(), 0.0);
        context
            .check("openai", "gpt-4o-mini", "named", &key)
            .await
            .unwrap();
        state
            .zdr
            .store(Arc::new(crate::zdr::ZdrCapabilities::unavailable()));
        assert_eq!(
            context
                .check("openai", "gpt-4o-mini", "named", &key)
                .await
                .unwrap_err()
                .code(),
            "zdr_unsatisfiable"
        );
        state
            .zdr
            .store(Arc::new(crate::zdr::ZdrCapabilities::from_rows([(
                "openai".to_owned(),
                "default".to_owned(),
            )])));
        crate::db::provider_keys::invalidate(&tenant, "openai", "named");
        crate::db::provider_keys::cache_decrypted_labeled(&other, "openai", "named", key.clone());
        assert_eq!(
            context
                .check("openai", "gpt-4o-mini", "named", &key)
                .await
                .unwrap_err()
                .code(),
            "provider_key_unavailable",
            "another tenant's identical label must not fill the gap"
        );
        crate::db::provider_keys::cache_decrypted_labeled(&tenant, "openai", "named", key.clone());
        crate::offpath::test_revoked().lock().insert(id.to_string());
        assert_eq!(
            context
                .check("openai", "gpt-4o-mini", "named", &key)
                .await
                .unwrap_err()
                .code(),
            "key_revoked"
        );
        crate::offpath::test_revoked()
            .lock()
            .remove(&id.to_string());
        crate::spend::tracker().record(who, Some(1.0));
        assert_eq!(
            context
                .check("openai", "gpt-4o-mini", "named", &key)
                .await
                .unwrap_err()
                .code(),
            "key_budget_exceeded"
        );
    }

    /// L4 (security review, 2026-10-05): the pre-send re-check compared the selected
    /// provider key with the current one using `==` on the secret strings — an early-exit
    /// comparison whose timing depends on how many leading bytes match. It must use the
    /// constant-time helper. Source-pinned: a timing property no behavioural test sees.
    #[test]
    fn l4_the_key_recheck_compares_secrets_in_constant_time() {
        let src = include_str!("attempt.rs");
        let body = src.split("#[cfg(test)]").next().unwrap_or(src);
        let leaky = concat!("expose_secret()", " ==");
        assert!(
            !body.contains(leaky),
            "routing/attempt.rs compares a secret with `==` (not constant-time)"
        );
        assert!(body.contains("crate::auth::constant_time_eq("));
        assert!(crate::auth::constant_time_eq(b"same", b"same"));
        assert!(!crate::auth::constant_time_eq(b"same", b"sane"));
        assert!(!crate::auth::constant_time_eq(b"short", b"longer"));
    }
}
