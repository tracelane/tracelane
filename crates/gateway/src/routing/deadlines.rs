//! Per-attempt transport deadlines. The body owns its deadlines after the handler
//! returns, so returning response headers cannot retire an idle or total bound.

use std::{sync::OnceLock, time::Duration};

use axum::http;
use futures::StreamExt as _;
use serde::{Deserialize, Serialize};
use tokio::time::Instant;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub(crate) struct Match {
    pub provider: Option<String>,
    pub model: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub(crate) struct Phases {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub headers_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_chunk_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idle_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_ms: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Rule {
    #[serde(rename = "match")]
    pub matcher: Match,
    pub headers_ms: Option<u64>,
    pub first_chunk_ms: Option<u64>,
    pub idle_ms: Option<u64>,
    pub total_ms: Option<u64>,
}

impl Rule {
    fn phases(&self) -> Phases {
        Phases {
            headers_ms: self.headers_ms,
            first_chunk_ms: self.first_chunk_ms,
            idle_ms: self.idle_ms,
            total_ms: self.total_ms,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BreakerOverride {
    pub consecutive_failures: u32,
    pub cooldown_secs: u64,
}

#[derive(Debug, Deserialize)]
pub(crate) struct Bounds {
    /// Floor for `headers_ms` / `first_chunk_ms` / `idle_ms` (S1).
    pub min_ms: u64,
    /// Floor for `total_ms` (S1).
    pub total_min_ms: u64,
    pub max_ms: u64,
    pub max_rules: usize,
    pub consecutive_failures_min: u32,
    pub consecutive_failures_max: u32,
    pub cooldown_secs_min: u64,
    pub cooldown_secs_max: u64,
}

pub(crate) fn bounds() -> &'static Bounds {
    static LIMITS: OnceLock<Bounds> = OnceLock::new();
    LIMITS.get_or_init(|| {
        serde_json::from_str::<serde_json::Value>(include_str!("../../translation_policy.v1.json"))
            .ok()
            .and_then(|v| serde_json::from_value(v["timeouts"].clone()).ok())
            // A malformed table grants no configuration writes.
            .unwrap_or(Bounds {
                min_ms: 0,
                total_min_ms: 0,
                max_ms: 0,
                max_rules: 0,
                consecutive_failures_min: 0,
                consecutive_failures_max: 0,
                cooldown_secs_min: 0,
                cooldown_secs_max: 0,
            })
    })
}

pub(crate) fn validate(doc: &super::RoutingDoc) -> Result<(), super::FieldError> {
    let b = bounds();
    if doc.timeouts.len() > b.max_rules {
        return Err(super::field(
            "timeouts",
            format!("at most {} rules", b.max_rules),
        ));
    }
    for (i, r) in doc.timeouts.iter().enumerate() {
        if r.matcher
            .provider
            .as_deref()
            .is_some_and(|p| !crate::byok_api::provider_keys_api::known_provider(p))
        {
            return Err(super::field(
                format!("timeouts[{i}].match.provider"),
                "unknown provider",
            ));
        }
        if r.matcher
            .model
            .as_deref()
            .is_some_and(|m| m.is_empty() || m.len() > super::limits().doc_max_bytes)
        {
            return Err(super::field(
                format!("timeouts[{i}].match.model"),
                "invalid model pattern",
            ));
        }
        for (name, n, min) in [
            ("headers_ms", r.headers_ms, b.min_ms),
            ("first_chunk_ms", r.first_chunk_ms, b.min_ms),
            ("idle_ms", r.idle_ms, b.min_ms),
            ("total_ms", r.total_ms, b.total_min_ms),
        ] {
            if n.is_some_and(|n| b.max_ms == 0 || !(min..=b.max_ms).contains(&n)) {
                return Err(super::field(
                    format!("timeouts[{i}].{name}"),
                    format!("min {min}, max {}", b.max_ms),
                ));
            }
        }
    }
    if let Some(t) = doc.breaker {
        if b.consecutive_failures_max == 0
            || !(b.consecutive_failures_min..=b.consecutive_failures_max)
                .contains(&t.consecutive_failures)
        {
            return Err(super::field(
                "breaker.consecutive_failures",
                format!(
                    "min {}, max {}",
                    b.consecutive_failures_min, b.consecutive_failures_max
                ),
            ));
        }
        if b.cooldown_secs_max == 0
            || !(b.cooldown_secs_min..=b.cooldown_secs_max).contains(&t.cooldown_secs)
        {
            return Err(super::field(
                "breaker.cooldown_secs",
                format!("min {}, max {}", b.cooldown_secs_min, b.cooldown_secs_max),
            ));
        }
    }
    Ok(())
}

pub(crate) fn resolve(state: &super::RoutingState, provider: &str, model: &str) -> Phases {
    state
        .doc()
        .and_then(|d| {
            d.timeouts.iter().find(|r| {
                r.matcher.provider.as_deref().is_none_or(|p| p == provider)
                    && r.matcher
                        .model
                        .as_deref()
                        .is_none_or(|p| tracelane_shared::key_policy::glob_match(p, model))
            })
        })
        .map_or_else(Phases::default, Rule::phases)
}

pub(crate) fn tune(cred: &mut crate::circuit_breaker::Cred, state: &super::RoutingState) {
    // Environment credentials are shared: a workspace cannot tune that breaker.
    if cred.owner.is_some() {
        cred.tuning = state
            .doc()
            .and_then(|d| d.breaker)
            .map(|b| crate::circuit_breaker::Tuning {
                consecutive_failure_threshold: b.consecutive_failures,
                cooldown: Duration::from_secs(b.cooldown_secs),
            });
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("upstream_timeout: {phase} ({limit_ms} ms)")]
pub(crate) struct Timeout {
    pub phase: &'static str,
    pub limit_ms: u64,
}

impl Timeout {
    pub(crate) fn find(mut error: &(dyn std::error::Error + 'static)) -> Option<Self> {
        loop {
            if let Some(t) = error.downcast_ref::<Self>() {
                return Some(*t);
            }
            error = error.source()?;
        }
    }

    pub(crate) fn record_attempt(self, ledger: &mut [tracelane_shared::DispatchAttempt]) {
        if let Some(attempt) = ledger.last_mut() {
            attempt.outcome = "error".to_owned();
            attempt.status = Some(504);
            attempt.reason = Some(format!("upstream_timeout:{}", self.phase));
        }
    }

    pub(crate) fn record_guard(self, guard: &mut crate::server::DispatchGuard, provider: &str) {
        guard.record_timeout(self, provider);
    }

    pub(crate) fn attempt(self, provider: &str, model: &str) -> tracelane_shared::DispatchAttempt {
        tracelane_shared::DispatchAttempt {
            attempt: 0,
            provider: provider.to_owned(),
            model: model.to_owned(),
            outcome: "error".to_owned(),
            status: Some(504),
            reason: Some(format!("upstream_timeout:{}", self.phase)),
            took_ms: 0,
            key_label: None,
        }
    }

    pub(crate) fn error_json(self) -> serde_json::Value {
        serde_json::json!({"type":"upstream_timeout", "code":"upstream_timeout", "message":"the upstream deadline elapsed", "phase":self.phase, "limit_ms":self.limit_ms})
    }

    pub(crate) fn event(self, wire: &str) -> bytes::Bytes {
        let error = self.error_json();
        let (event, payload) = match wire {
            "messages" => (
                "event: error\n",
                serde_json::json!({"type":"error", "error":error}),
            ),
            _ => (
                "",
                serde_json::json!({"error":{"code":504,"status":"DEADLINE_EXCEEDED", "message":"the upstream deadline elapsed", "details":[error]}}),
            ),
        };
        bytes::Bytes::from(format!("{event}data: {payload}\n\n"))
    }

    pub(crate) fn response(self) -> axum::response::Response {
        use axum::response::IntoResponse as _;
        (
            axum::http::StatusCode::GATEWAY_TIMEOUT,
            axum::Json(serde_json::json!({
                "error": "upstream_timeout", "phase": self.phase, "limit_ms": self.limit_ms
            })),
        )
            .into_response()
    }
}

#[derive(Debug, thiserror::Error)]
enum BodyError {
    #[error("{0}")]
    Timeout(#[source] Timeout),
    #[error("upstream body transport error")]
    Transport(#[source] reqwest::Error),
}

/// Copied into each transport future, never shared between requests or tenants.
#[derive(Clone, Default)]
pub(crate) struct Budget {
    phases: Phases,
    total_started: Option<Instant>,
    observer: Option<std::sync::Arc<Observation>>,
    record_success: bool,
    attempt: Option<Attempt>,
}

#[derive(Clone)]
struct Attempt {
    context: std::sync::Arc<super::attempt::Context>,
    provider: String,
    model: String,
    label: String,
    key: std::sync::Arc<secrecy::SecretString>,
}

struct Observation {
    breaker: std::sync::Arc<crate::circuit_breaker::CircuitBreaker>,
    provider: String,
    region: String,
    credential: crate::circuit_breaker::Cred,
    recorded: std::sync::atomic::AtomicBool,
}

impl Observation {
    fn finish(&self, outcome: Option<crate::circuit_breaker::Outcome>) {
        if !self
            .recorded
            .swap(true, std::sync::atomic::Ordering::AcqRel)
            && let Some(outcome) = outcome
        {
            self.breaker
                .record(&self.provider, &self.region, &self.credential, outcome);
        }
    }
}

/// A cleanly consumed or deliberately dropped success body keeps the existing head-
/// success semantics; a body fault wins first. No early success resets a streak of
/// body timeouts before the fault arrives. One HTTP attempt supplies one observation.
struct BodyObservation {
    observer: Option<std::sync::Arc<Observation>>,
    record_success: bool,
}
impl Drop for BodyObservation {
    fn drop(&mut self) {
        if self.record_success
            && let Some(o) = &self.observer
        {
            o.finish(Some(crate::circuit_breaker::Outcome::Success));
        }
    }
}

/// Unconfigured transports retain the existing dispatch observation. Configured
/// transports record once in send/body, including a timeout after headers arrived.
pub(crate) fn record_legacy(
    breaker: &crate::circuit_breaker::CircuitBreaker,
    provider: &str,
    region: &str,
    cred: &crate::circuit_breaker::Cred,
    outcome: crate::circuit_breaker::Outcome,
    entitlements: Option<&crate::entitlement_cache::ResolvedEntitlements>,
    model: &str,
) {
    // The rule lookup uses the provider ID the deadline budget used, whatever name the
    // breaker is keyed by (LOW round 2).
    let rule_provider = crate::server::provider_id_from_name(provider);
    if entitlements.is_none_or(|e| resolve(&e.routing, rule_provider, model) == Phases::default()) {
        breaker.record(provider, region, cred, outcome);
    }
}

tokio::task_local! { static ACTIVE: Budget; }

impl Budget {
    pub(crate) fn for_request(
        entitlements: Option<&crate::entitlement_cache::ResolvedEntitlements>,
        provider: &str,
        model: &str,
        request_start: chrono::DateTime<chrono::Utc>,
    ) -> Self {
        let phases =
            entitlements.map_or_else(Phases::default, |e| resolve(&e.routing, provider, model));
        let elapsed = (chrono::Utc::now() - request_start)
            .to_std()
            .unwrap_or_default();
        Self {
            phases,
            total_started: Instant::now().checked_sub(elapsed),
            observer: None,
            record_success: true,
            attempt: None,
        }
    }

    pub(crate) fn with_attempt(
        mut self,
        context: &std::sync::Arc<super::attempt::Context>,
        provider: &str,
        model: &str,
        label: &str,
        key: &std::sync::Arc<secrecy::SecretString>,
    ) -> Self {
        self.attempt = Some(Attempt {
            context: context.clone(),
            provider: provider.to_owned(),
            model: model.to_owned(),
            label: label.to_owned(),
            key: key.clone(),
        });
        self
    }

    pub(crate) fn with_breaker(
        mut self,
        breaker: &std::sync::Arc<crate::circuit_breaker::CircuitBreaker>,
        provider: &str,
        region: &str,
        credential: &crate::circuit_breaker::Cred,
    ) -> Self {
        if self.phases == Phases::default() {
            return self;
        }
        // S1: this transport runs under a WORKSPACE-set deadline, so its timeouts (and
        // every other outcome it observes) are about that workspace's configuration and
        // may open only its own credential — never the provider-wide tier.
        let mut credential = credential.clone();
        credential.deadline_scoped = true;
        self.observer = Some(std::sync::Arc::new(Observation {
            breaker: breaker.clone(),
            provider: provider.to_owned(),
            region: region.to_owned(),
            credential,
            recorded: std::sync::atomic::AtomicBool::new(false),
        }));
        self
    }

    pub(crate) async fn scope<F: std::future::Future>(self, f: F) -> F::Output {
        if let Some(o) = &self.observer {
            o.recorded
                .store(false, std::sync::atomic::Ordering::Release);
        }
        ACTIVE.scope(self, f).await
    }

    fn deadline(
        &self,
        phase: &'static str,
        limit: Option<u64>,
        start: Instant,
    ) -> Option<(Instant, Timeout)> {
        let phase = limit.map(|limit_ms| {
            (
                start + Duration::from_millis(limit_ms),
                Timeout { phase, limit_ms },
            )
        });
        let total = self
            .phases
            .total_ms
            .zip(self.total_started)
            .map(|(limit_ms, start)| {
                (
                    start + Duration::from_millis(limit_ms),
                    Timeout {
                        phase: "total",
                        limit_ms,
                    },
                )
            });
        match (phase, total) {
            (Some(p), Some(t)) => Some(if t.0 <= p.0 { t } else { p }),
            (p, t) => p.or(t),
        }
    }

    async fn wait<F: std::future::Future>(
        &self,
        phase: &'static str,
        limit: Option<u64>,
        start: Instant,
        f: F,
    ) -> Result<F::Output, Timeout> {
        match self.deadline(phase, limit, start) {
            Some((at, error)) => tokio::time::timeout_at(at, f).await.map_err(|_| error),
            None => Ok(f.await),
        }
    }

    pub(crate) async fn send(
        self,
        request: reqwest::RequestBuilder,
    ) -> anyhow::Result<reqwest::Response> {
        let sent = self
            .wait("headers", self.phases.headers_ms, Instant::now(), async {
                if let Some(a) = &self.attempt {
                    a.context
                        .check(&a.provider, &a.model, &a.label, &a.key)
                        .await?;
                }
                request
                    .send()
                    .await
                    .map_err(reqwest::Error::without_url)
                    .map_err(anyhow::Error::from)
            })
            .await;
        let response = match sent {
            Ok(Ok(response)) => response,
            Ok(Err(err)) => {
                if let Some(o) = &self.observer {
                    o.finish(if err.is::<super::attempt::Denied>() {
                        None
                    } else {
                        crate::server::transport_outcome(&err)
                    });
                }
                return Err(err);
            }
            Err(timeout) => {
                // The WORKSPACE's own deadline (S1): that credential only.
                if let Some(o) = &self.observer {
                    o.finish(Some(crate::circuit_breaker::Outcome::CredentialFault));
                }
                return Err(timeout.into());
            }
        };
        if !response.status().is_success()
            && let Some(o) = &self.observer
        {
            o.finish(crate::openai_responses::breaker_observation(Some(
                response.status().as_u16(),
            )));
        }

        Ok(self.body(response))
    }

    fn body(self, response: reqwest::Response) -> reqwest::Response {
        if self.phases == Phases::default() {
            return response;
        }
        let response: http::Response<reqwest::Body> = response.into();
        let (parts, body) = response.into_parts();
        let response = reqwest::Response::from(http::Response::new(body));
        let mut stream = response.bytes_stream();
        let received = Instant::now();
        let observation = BodyObservation {
            observer: self.observer.clone(),
            record_success: self.record_success,
        };
        let bounded = async_stream::try_stream! {
            let _observation = observation;
            let mut first = true;
            let mut last = received;
            loop {
                let (phase, limit) = if first { ("first_chunk", self.phases.first_chunk_ms) } else { ("idle", self.phases.idle_ms) };
                let next = self.wait(phase, limit, last, stream.next()).await;
                if (next.is_err() || matches!(&next, Ok(Some(Err(_))))) && let Some(o) = &self.observer {
                    o.finish(Some(crate::circuit_breaker::Outcome::CredentialFault));
                }
                let Some(chunk) = next.map_err(BodyError::Timeout)? else { break; };
                let chunk = chunk.map_err(|err| BodyError::Transport(err.without_url()))?;
                if !chunk.is_empty() { first = false; last = Instant::now(); }
                yield chunk;
            }
        };
        // The original status and headers survive; errors retain the typed Timeout
        // in their source chain, even through reqwest's Body error wrapper.
        reqwest::Response::from(http::Response::from_parts(
            parts,
            reqwest::Body::wrap_stream(Box::pin(bounded)
                as std::pin::Pin<
                    Box<dyn futures::Stream<Item = Result<bytes::Bytes, BodyError>> + Send>,
                >),
        ))
    }
}

/// Companions bypass generation admission but must not ignore a corrupt routing document.
pub(crate) fn invalid_document(
    entitlements: Option<&crate::entitlement_cache::ResolvedEntitlements>,
) -> Option<axum::response::Response> {
    use axum::response::IntoResponse as _;
    entitlements
        .filter(|e| matches!(*e.routing, super::RoutingState::Invalid))
        .map(|_| {
            (
                http::StatusCode::SERVICE_UNAVAILABLE,
                axum::Json(serde_json::json!({"error":"routing_invalid"})),
            )
                .into_response()
        })
}

/// Adapter sends inherit only the scope of their own dispatch; the returned body
/// captures it before that scope ends. Unconfigured calls retain their old bounds.
pub(crate) async fn send(request: reqwest::RequestBuilder) -> anyhow::Result<reqwest::Response> {
    ACTIVE
        .try_with(Clone::clone)
        .unwrap_or_default()
        .send(request)
        .await
}

/// Vertex's credential exchange shares the request deadline, but its successful
/// body must not count as a successful generation before the generation is sent.
pub(crate) async fn send_auxiliary(
    request: reqwest::RequestBuilder,
) -> anyhow::Result<reqwest::Response> {
    let mut budget = ACTIVE.try_with(Clone::clone).unwrap_or_default();
    budget.record_success = false;
    budget.send(request).await
}

/// Preserve deadlines while retaining the adapters' treatment of unreadable error bodies.
pub(crate) async fn error_text(response: reqwest::Response) -> anyhow::Result<String> {
    match response.text().await {
        Ok(text) => Ok(text),
        Err(err) if Timeout::find(&err).is_some() => Err(err.without_url().into()),
        Err(_) => Ok(String::new()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn each_phase_and_the_absolute_total_deadline_stop_pending_work() {
        for (phase, phases) in [
            (
                "headers",
                Phases {
                    headers_ms: Some(20),
                    ..Default::default()
                },
            ),
            (
                "first_chunk",
                Phases {
                    first_chunk_ms: Some(20),
                    ..Default::default()
                },
            ),
            (
                "idle",
                Phases {
                    idle_ms: Some(20),
                    ..Default::default()
                },
            ),
            (
                "total",
                Phases {
                    total_ms: Some(10),
                    idle_ms: Some(20),
                    ..Default::default()
                },
            ),
        ] {
            let b = Budget {
                phases,
                total_started: Some(Instant::now()),
                observer: None,
                record_success: true,
                attempt: None,
            };
            let t = b
                .wait(
                    phase,
                    Some(20),
                    Instant::now(),
                    std::future::pending::<()>(),
                )
                .await
                .unwrap_err();
            assert_eq!(t.phase, phase);
            assert_eq!(t.limit_ms, if phase == "total" { 10 } else { 20 });
        }
    }

    #[tokio::test(start_paused = true)]
    async fn body_deadline_survives_scope_and_reqwest_error_wrapping() {
        let b = Budget {
            phases: Phases {
                first_chunk_ms: Some(20),
                ..Default::default()
            },
            total_started: Some(Instant::now()),
            observer: None,
            record_success: true,
            attempt: None,
        };
        let body = reqwest::Body::wrap_stream(futures::stream::pending::<
            Result<bytes::Bytes, std::io::Error>,
        >());
        let r = b.body(reqwest::Response::from(http::Response::new(body)));
        let error = r.bytes().await.unwrap_err();
        assert_eq!(
            Timeout::find(&error),
            Some(Timeout {
                phase: "first_chunk",
                limit_ms: 20
            })
        );
    }
    #[tokio::test(start_paused = true)]
    async fn og13_body_deadlines_reset_idle_but_never_reset_total_and_record_fault_once() {
        use crate::circuit_breaker::{BreakerConfig, CircuitBreaker, Cred};
        for (total, phase, delivered) in [(None, "idle", 3), (Some(25), "total", 2)] {
            let breaker = std::sync::Arc::new(CircuitBreaker::new(BreakerConfig::default()));
            let cred = Cred::byok(&uuid::Uuid::new_v4(), "openai", "default");
            let b = Budget {
                phases: Phases {
                    first_chunk_ms: Some(15),
                    idle_ms: Some(15),
                    total_ms: total,
                    ..Default::default()
                },
                total_started: Some(Instant::now()),
                observer: None,
                record_success: true,
                attempt: None,
            }
            .with_breaker(&breaker, "openai", "default", &cred);
            let body = reqwest::Body::wrap_stream(async_stream::stream! {
                for _ in 0..3 {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                    yield Ok::<_, std::io::Error>(bytes::Bytes::from_static(b"x"));
                }
                std::future::pending::<()>().await;
            });
            let response = b
                .clone()
                .scope(async { b.body(reqwest::Response::from(http::Response::new(body))) })
                .await;
            let mut stream = response.bytes_stream();
            for _ in 0..delivered {
                assert_eq!(stream.next().await.unwrap().unwrap(), "x");
            }
            let err = stream.next().await.unwrap().unwrap_err();
            assert_eq!(Timeout::find(&err).unwrap().phase, phase);
            assert_eq!(breaker.outcomes("openai", "default", &cred.id), vec![false]);
            assert!(stream.next().await.is_none());
        }
    }

    #[test]
    fn og13_invalid_bounds_and_first_match_and_tenant_override() {
        for bad in [
            serde_json::json!({"timeouts":[{"match":{},"total_ms":300001}]}),
            serde_json::json!({"breaker":{"consecutive_failures":0,"cooldown_secs":20}}),
        ] {
            let doc: super::super::RoutingDoc = serde_json::from_value(bad).unwrap();
            assert!(validate(&doc).is_err());
        }
        let doc: super::super::RoutingDoc = serde_json::from_value(serde_json::json!({"timeouts":[{"match":{"model":"gpt-*"},"headers_ms":20},{"match":{},"headers_ms":40}],"breaker":{"consecutive_failures":3,"cooldown_secs":20}})).unwrap();
        let state = super::super::RoutingState::Valid(std::sync::Arc::new(doc));
        assert_eq!(resolve(&state, "openai", "gpt-4o").headers_ms, Some(20));
        assert_eq!(
            resolve(&state, "anthropic", "claude-sonnet-4-5").headers_ms,
            Some(40)
        );
        let mut env = crate::circuit_breaker::Cred::env();
        tune(&mut env, &state);
        assert!(env.tuning.is_none());
        let mut byok = crate::circuit_breaker::Cred::byok(&uuid::Uuid::new_v4(), "openai", "a");
        tune(&mut byok, &state);
        assert_eq!(byok.tuning.unwrap().consecutive_failure_threshold, 3);
    }
    #[tokio::test(start_paused = true)]
    async fn og13_repeated_body_timeouts_open_the_credential_without_head_success_resets() {
        use crate::circuit_breaker::{BreakerConfig, CircuitBreaker, Cred, State};
        let cb = std::sync::Arc::new(CircuitBreaker::new(BreakerConfig {
            consecutive_failure_threshold: 3,
            ..Default::default()
        }));
        let cred = Cred::byok(&uuid::Uuid::new_v4(), "openai", "default");
        for _ in 0..3 {
            let b = Budget {
                phases: Phases {
                    first_chunk_ms: Some(10),
                    ..Default::default()
                },
                total_started: Some(Instant::now()),
                observer: None,
                record_success: true,
                attempt: None,
            }
            .with_breaker(&cb, "openai", "default", &cred);
            let body = reqwest::Body::wrap_stream(futures::stream::pending::<
                Result<bytes::Bytes, std::io::Error>,
            >());
            let response = b
                .clone()
                .scope(async { b.body(reqwest::Response::from(http::Response::new(body))) })
                .await;
            assert!(Timeout::find(&response.bytes().await.unwrap_err()).is_some());
        }
        assert_eq!(cb.outcomes("openai", "default", &cred.id), vec![false; 3]);
        assert_eq!(cb.state("openai", "default", &cred.id), State::Open);
    }
    /// S1 (security review, 2026-10-05): three workspaces each set their OWN deadline
    /// and drive their own credential Open with timeouts. A fourth, healthy tenant on the
    /// same provider must still be served — a workspace-set deadline is not evidence the
    /// provider is down.
    #[tokio::test(start_paused = true)]
    async fn s1_workspace_deadline_timeouts_never_open_the_shared_provider_tier() {
        use crate::circuit_breaker::{CircuitBreaker, Cred, State};
        let cb = std::sync::Arc::new(CircuitBreaker::default());
        for _tenant in 0..3 {
            let cred = Cred::byok(&uuid::Uuid::new_v4(), "openai", "default");
            for _ in 0..5 {
                let b = Budget {
                    phases: Phases {
                        first_chunk_ms: Some(bounds().min_ms),
                        ..Default::default()
                    },
                    total_started: Some(Instant::now()),
                    observer: None,
                    record_success: true,
                    attempt: None,
                }
                .with_breaker(&cb, "openai", "default", &cred);
                let body = reqwest::Body::wrap_stream(futures::stream::pending::<
                    Result<bytes::Bytes, std::io::Error>,
                >());
                let response = b
                    .clone()
                    .scope(async { b.body(reqwest::Response::from(http::Response::new(body))) })
                    .await;
                assert!(Timeout::find(&response.bytes().await.unwrap_err()).is_some());
            }
            assert_eq!(cb.state("openai", "default", &cred.id), State::Open);
        }
        let healthy = Cred::byok(&uuid::Uuid::new_v4(), "openai", "default");
        assert!(
            cb.allow("openai", "default", &healthy),
            "workspace-set deadlines shed only their own credentials"
        );
    }

    /// S1: the reference table's deadline floor is a sane minimum — a 1 ms deadline is a
    /// tool for manufacturing failures, not a latency bound.
    #[test]
    fn s1_deadline_floor_refuses_millisecond_bounds() {
        let parse = |v: serde_json::Value| -> super::super::RoutingDoc {
            serde_json::from_value(v).unwrap()
        };
        for bad in [
            serde_json::json!({"timeouts":[{"match":{},"headers_ms":1}]}),
            serde_json::json!({"timeouts":[{"match":{},"headers_ms":999}]}),
            serde_json::json!({"timeouts":[{"match":{},"first_chunk_ms":999}]}),
            serde_json::json!({"timeouts":[{"match":{},"idle_ms":999}]}),
            serde_json::json!({"timeouts":[{"match":{},"total_ms":4999}]}),
        ] {
            assert!(validate(&parse(bad.clone())).is_err(), "must refuse {bad}");
        }
        assert!(
            validate(&parse(serde_json::json!({"timeouts":[{"match":{},
                "headers_ms":1000,"first_chunk_ms":1000,"idle_ms":1000,"total_ms":5000}]})))
            .is_ok()
        );
    }
}
