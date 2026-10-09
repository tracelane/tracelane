//! `OG-11` — the attempt loop of the NATIVE RELAY wires (`/v1/messages`, Gemini
//! `generateContent`, Responses mode N): one provider's own wire, so a virtual model's
//! targets are that provider's models and every attempt goes through the same relay.
//!
//! A key failure (401 / 403 / 429) moves to the NEXT pool key for the same target; a
//! transport failure or a 5xx moves to the next target (when the wire falls through);
//! anything else is final and relayed to the caller as the provider sent it. Each pool
//! key is its own breaker credential (OG-13) and is checked with the real `allow`
//! before each attempt. Bounded by `routing.max_attempts`.

use std::sync::Arc;

use tracelane_shared::{DispatchAttempt, TenantId};

/// How the loop ended.
pub(crate) enum RelayOutcome {
    /// A 2xx: relay it.
    Served {
        upstream: reqwest::Response,
        /// Index into the targets.
        target: usize,
        label: String,
        key: Arc<secrecy::SecretString>,
    },
    /// The last attempt never reached the provider.
    Transport,
    Refused(super::attempt::Denied),
    Timeout(super::deadlines::Timeout),
    /// The last attempt's non-2xx — relayed by the caller, scrubbed of `key`.
    Status {
        upstream: reqwest::Response,
        key: Arc<secrecy::SecretString>,
    },
    /// Every remaining key's breaker was Open: nothing was sent.
    BreakerOpen,
}

/// What the loop runs over.
pub(crate) struct RelayPlan<'a> {
    pub attempt_security: &'a Arc<super::attempt::Context>,
    pub tenant_id: &'a TenantId,
    pub provider_id: &'static str,
    /// The breaker's provider name (the span family).
    pub family: &'a str,
    pub region: &'a str,
    /// Concrete models, in dispatch order (one when not routed).
    pub targets: &'a [String],
    /// The pool chose the keys (labels go on the ledger).
    pub pooled: bool,
    pub fallthrough: bool,
    pub max_attempts: usize,
    pub entitlements: Option<&'a crate::entitlement_cache::ResolvedEntitlements>,
    pub request_start: chrono::DateTime<chrono::Utc>,
}

fn attempt(
    provider: &str,
    model: &str,
    outcome: &str,
    status: Option<u16>,
    reason: Option<&str>,
    took: std::time::Duration,
    label: Option<&str>,
) -> DispatchAttempt {
    DispatchAttempt {
        key_label: label.map(str::to_owned),
        attempt: 0,
        provider: provider.to_owned(),
        model: model.to_owned(),
        outcome: outcome.to_owned(),
        status,
        reason: reason.map(str::to_owned),
        took_ms: u32::try_from(took.as_millis()).unwrap_or(u32::MAX),
    }
}

/// Run the attempts. `first` is the key admission/selection already resolved; `cursor`
/// yields the rest of the pool. `send(target, key)` performs ONE relay of the request to
/// `targets[target]` with `key`. The ledger gets one element per attempt or skip.
///
/// # Errors
/// None: every way the loop can end is a [`RelayOutcome`] the caller renders on its
/// wire. Fail-CLOSED on the breaker (an Open key is never used).
pub(crate) async fn run<F, Fut>(
    state: &crate::server::AppState,
    plan: RelayPlan<'_>,
    first: (String, Arc<secrecy::SecretString>),
    cursor: &mut crate::server::KeyCursor,
    ledger: &mut Vec<DispatchAttempt>,
    mut send: F,
) -> RelayOutcome
where
    F: FnMut(usize, Arc<secrecy::SecretString>) -> Fut,
    Fut: std::future::Future<Output = anyhow::Result<reqwest::Response>>,
{
    let env = crate::providers::ProviderRegistry::env_var_for_provider_id(plan.provider_id);
    let (mut label, mut key) = first;
    let mut used = 0usize;
    let mut outcome = RelayOutcome::BreakerOpen;
    let label_of = |l: &str| plan.pooled.then(|| l.to_owned());
    'targets: for (ti, target) in plan.targets.iter().enumerate() {
        loop {
            if used >= plan.max_attempts {
                break 'targets;
            }
            let cred = crate::server::breaker_cred(
                plan.tenant_id,
                plan.provider_id,
                &label,
                plan.entitlements.map(|e| e.routing.as_ref()),
            );
            if !state.circuit_breaker.allow(plan.family, plan.region, &cred) {
                ledger.push(attempt(
                    plan.family,
                    target,
                    "skipped",
                    None,
                    Some("breaker_open"),
                    std::time::Duration::ZERO,
                    label_of(&label).as_deref(),
                ));
                match next_key(cursor, plan.tenant_id, plan.provider_id, env).await {
                    Some((l, k)) => {
                        label = l;
                        key = k;
                        continue;
                    }
                    None => break 'targets,
                }
            }
            used += 1;
            let started = std::time::Instant::now();
            let deadlines = super::deadlines::Budget::for_request(
                plan.entitlements,
                plan.provider_id,
                target,
                plan.request_start,
            );
            let deadlines = deadlines
                .with_breaker(&state.circuit_breaker, plan.family, plan.region, &cred)
                .with_attempt(
                    plan.attempt_security,
                    plan.provider_id,
                    target,
                    &label,
                    &key,
                );
            match deadlines.scope(send(ti, Arc::clone(&key))).await {
                Err(error) => {
                    if let Some(denied) = error.downcast_ref::<super::attempt::Denied>() {
                        ledger.push(attempt(
                            plan.family,
                            target,
                            "skipped",
                            None,
                            Some(denied.code()),
                            started.elapsed(),
                            label_of(&label).as_deref(),
                        ));
                        return RelayOutcome::Refused(denied.clone());
                    }
                    if let Some(ok) = crate::server::transport_outcome(&error) {
                        crate::routing::deadlines::record_legacy(
                            &state.circuit_breaker,
                            plan.family,
                            plan.region,
                            &cred,
                            ok,
                            plan.entitlements,
                            target,
                        );
                    }
                    ledger.push(attempt(
                        plan.family,
                        target,
                        "error",
                        None,
                        Some("provider_unavailable"),
                        started.elapsed(),
                        label_of(&label).as_deref(),
                    ));
                    if let Some(timeout) = super::deadlines::Timeout::find(error.as_ref()) {
                        timeout.record_attempt(ledger);
                    }
                    outcome = super::deadlines::Timeout::find(error.as_ref())
                        .map_or(RelayOutcome::Transport, RelayOutcome::Timeout);
                    if plan.fallthrough {
                        continue 'targets;
                    }
                    break 'targets;
                }
                Ok(up) => {
                    let status = up.status().as_u16();
                    if let Some(ok) = crate::openai_responses::breaker_observation(Some(status)) {
                        crate::routing::deadlines::record_legacy(
                            &state.circuit_breaker,
                            plan.family,
                            plan.region,
                            &cred,
                            ok,
                            plan.entitlements,
                            target,
                        );
                    }
                    if up.status().is_success() {
                        super::stats::record(
                            plan.tenant_id.as_uuid(),
                            plan.entitlements
                                .map(|e| &*e.routing)
                                .unwrap_or(&super::RoutingState::None),
                            plan.provider_id,
                            target,
                            started.elapsed(),
                        );
                        ledger.push(attempt(
                            plan.family,
                            target,
                            "ok",
                            None,
                            None,
                            started.elapsed(),
                            label_of(&label).as_deref(),
                        ));
                        return RelayOutcome::Served {
                            upstream: up,
                            target: ti,
                            label,
                            key,
                        };
                    }
                    ledger.push(attempt(
                        plan.family,
                        target,
                        "error",
                        Some(status),
                        Some(if super::is_key_failure_status(status) {
                            "provider_key_rejected"
                        } else if status >= 500 {
                            "provider_unavailable"
                        } else {
                            "provider_request_rejected"
                        }),
                        started.elapsed(),
                        label_of(&label).as_deref(),
                    ));
                    if super::is_key_failure_status(status)
                        && used < plan.max_attempts
                        && let Some((l, k)) =
                            next_key(cursor, plan.tenant_id, plan.provider_id, env).await
                    {
                        // The next key of the pool, same target. The rejected answer is
                        // dropped unread — it is not what the caller gets.
                        label = l;
                        key = k;
                        continue;
                    }
                    let retargetable = status >= 500 || super::is_key_failure_status(status);
                    outcome = RelayOutcome::Status {
                        upstream: up,
                        key: Arc::clone(&key),
                    };
                    if plan.fallthrough && retargetable {
                        continue 'targets;
                    }
                    break 'targets;
                }
            }
        }
    }
    outcome
}

/// The next usable (non-empty) key of the pool.
async fn next_key(
    cursor: &mut crate::server::KeyCursor,
    tenant_id: &TenantId,
    provider_id: &str,
    env: &str,
) -> Option<(String, Arc<secrecy::SecretString>)> {
    use secrecy::ExposeSecret as _;
    while let Some((l, k)) = cursor.next_key(tenant_id, provider_id, env).await {
        if !k.expose_secret().is_empty() {
            return Some((l, k));
        }
    }
    None
}
