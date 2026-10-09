//! `POST /v1/chat/completions` — the chat hot path (B-385 §2d split of `server.rs`).
//!
//! `chat_completions_handler` and the helpers only it needs: the prompt-promotion
//! observation the auto-rollback engine feeds on, and the streaming-request probe.
//! Admission (auth → … → audit publish) is `crate::admission`; the provider
//! round-trip is `super::dispatch`; the two response assemblies are
//! `super::stream` (SSE) and `super::buffered` (JSON).

use std::sync::Arc;

use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, sse::Sse},
};
use secrecy::ExposeSecret as _;
use tracelane_shared::{DispatchAttempt, TenantId, span::extend_dispatch_attempts};
use tracing::instrument;
use uuid::Uuid;

use super::AppState;
use super::buffered::buffer_provider_stream;
use super::dispatch::{
    BENCH_MOCK_PROVIDER_ID, ProviderKey, breaker_outcome, dispatch_with_retry,
    provider_name_from_model,
};
use super::errors::{
    invalid_zdr_constraint_response, provider_error_response, provider_error_response_with_detail,
    unroutable_model_response, zdr_unsatisfiable_response,
};
use super::spans::{
    CapturedInput, CapturedOutput, GatewayTiming, RequestConfig, SpanUsageMeta, build_gateway_span,
    spawn_span_publish,
};
use super::stream::{StreamContext, provider_stream_to_sse};
use crate::admission::Route as _;

/// Does the request ask for SSE? Read from the raw body because the cache
/// decision happens before the typed request is re-serialised anywhere.
fn is_streaming_request(body: &serde_json::Value) -> bool {
    body.get("stream").and_then(serde_json::Value::as_bool) == Some(true)
}

/// `OG-20`: may this request be moved to `model` on `provider` (a ZDR re-route, a
/// cross-provider failover)? `true` for a caller with no policy.
fn policy_allows(
    claims: &crate::auth::Claims,
    controls: Option<&crate::controls::WorkspaceControls>,
    model: &str,
    provider: &str,
) -> bool {
    claims
        .governance
        .as_deref()
        .is_none_or(|g| g.allows_dispatch(model, provider))
        // OG-25: nor onto a model or provider the workspace has blocked.
        && controls.is_none_or(|c| crate::controls::allows_dispatch(c, model, provider))
}

/// rev6 N3 — the embedding models the semantic cache tier may send THIS request's text
/// to, in the configured order. Empty (the tier is off) when R2 redacted the request;
/// otherwise every configured model whose provider is routable and that
/// [`policy_allows`] (workspace blocks, the workspace policy, the key's policy) and —
/// when the request requires ZDR (`zdr` is `Some`) — whose provider is ZDR-eligible.
/// Fail-CLOSED: an unroutable embedding model is left out.
fn semantic_tier_models(
    configured: &[String],
    redacted: bool,
    claims: &crate::auth::Claims,
    controls: Option<&crate::controls::WorkspaceControls>,
    zdr: Option<&crate::zdr::ZdrCapabilities>,
) -> Vec<String> {
    if redacted {
        return Vec::new();
    }
    configured
        .iter()
        .filter(|m| {
            crate::providers::ProviderRegistry::provider_id_for_model(m).is_some_and(|pid| {
                policy_allows(claims, controls, m, pid) && zdr.is_none_or(|caps| caps.eligible(pid))
            })
        })
        .cloned()
        .collect()
}

/// RI-05 M4 — one ledger element for a failover candidate that was SKIPPED
/// without ever being dispatched. Factored out as a pure constructor (rather
/// than four inline struct literals at the four `continue` sites in the
/// failover loop below) so the closed token vocabulary — `no_byok_key` |
/// `breaker_open` | `killed` | `unroutable` | `zdr_ineligible` (GWY-49) |
/// `policy_denied` (OG-20) — is unit-testable without a
/// `ChatRequest`, an `AppState`, or a fake circuit breaker.
///
/// `attempt: 0` is a placeholder — `tracelane_shared::span::extend_dispatch_attempts`
/// renumbers every element to its position in the request's full sequence
/// when the caller merges this in.
fn skipped_failover_attempt(provider: &str, model: &str, reason: &'static str) -> DispatchAttempt {
    DispatchAttempt {
        key_label: None,
        attempt: 0,
        provider: provider.to_string(),
        model: model.to_string(),
        outcome: "skipped".to_string(),
        status: None,
        reason: Some(reason.to_string()),
        took_ms: 0,
    }
}

/// `OG-11`: stamp each attempt of one dispatch with the pool label it used (only when a
/// pool chose it — a single `default` key records nothing new).
fn label_attempts(attempts: &mut [DispatchAttempt], pooled: bool, label: &str) {
    if pooled {
        for a in attempts {
            a.key_label = Some(label.to_owned());
        }
    }
}

/// `OG-11`: the key a routed request's chosen candidate dispatches with, and the rest of
/// its pool for a key failure.
struct RoutedKey {
    label: String,
    key: Arc<secrecy::SecretString>,
    cursor: super::KeyCursor,
    pooled: bool,
    cold: bool,
}

/// `OG-11`: why a candidate was skipped (ledger elements) and whether the key store was
/// unreadable while trying it.
struct CandidateSkip {
    attempts: Vec<DispatchAttempt>,
    lookup_failed: bool,
}

/// What [`select_candidate`] judges a candidate against.
struct SelectInput<'a> {
    tenant_id: &'a TenantId,
    claims: &'a crate::auth::Claims,
    controls: Option<&'a crate::controls::WorkspaceControls>,
    caller_budgeted: bool,
    zdr_required: bool,
    request: &'a tracelane_shared::ChatRequest,
    routing: &'a crate::routing::RoutingState,
    family: &'static str,
    model: &'a str,
    provider_id: &'static str,
}

/// `OG-11`: can this candidate serve the request right now? Killed, ZDR-ineligible,
/// policy-denied, unpriced under a budget, unsupported, keyless, or breaker-open on
/// every pool key → `Err` with the skip recorded. Otherwise the first pool key whose
/// breaker would admit the call. The breaker is only PEEKED here (`would_allow`); the
/// real `allow` runs at dispatch.
async fn select_candidate(
    state: &AppState,
    i: SelectInput<'_>,
    rng: crate::routing::Rng<'_>,
) -> Result<RoutedKey, CandidateSkip> {
    let skip = |reason: &'static str| CandidateSkip {
        attempts: vec![skipped_failover_attempt(i.family, i.model, reason)],
        lookup_failed: false,
    };
    if state.kill_switch.upstream_killed(i.family) {
        return Err(skip("killed"));
    }
    if i.zdr_required && !state.zdr.load().eligible(i.provider_id) {
        return Err(skip("zdr_ineligible"));
    }
    if !policy_allows(i.claims, i.controls, i.model, i.provider_id) {
        return Err(skip("policy_denied"));
    }
    if i.caller_budgeted
        && matches!(
            crate::admission::token_pricing(i.model),
            crate::admission::Pricing::Unpriced { .. }
        )
    {
        return Err(skip("unpriced_under_budget"));
    }
    let mut probe = i.request.clone();
    probe.model = super::config::alias(i.model)
        .map_or_else(|| i.model.to_owned(), |a| a.upstream_model.clone());
    if crate::request_support::check_supported(i.provider_id, &probe).is_err() {
        return Err(skip("unsupported_request"));
    }
    let pool = crate::routing::pool_labels(
        &crate::admission::Chat::ROUTING,
        i.routing,
        i.provider_id,
        rng,
    );
    let pooled = pool.pooled;
    let mut cursor = super::KeyCursor::new(pool.labels);
    let env = crate::providers::ProviderRegistry::env_var_for_provider_id(i.provider_id);
    let region = state.providers.upstream_region(i.provider_id);
    let mut skips: Vec<DispatchAttempt> = Vec::new();
    while let Some((label, key)) = cursor.next_key(i.tenant_id, i.provider_id, env).await {
        let cred =
            super::dispatch::breaker_cred(i.tenant_id, i.provider_id, &label, Some(i.routing));
        if state.circuit_breaker.would_allow(i.family, region, &cred) {
            let cold = cursor.cold;
            return Ok(RoutedKey {
                label,
                key,
                cursor,
                pooled,
                cold,
            });
        }
        let mut s = skipped_failover_attempt(i.family, i.model, "breaker_open");
        if pooled {
            s.key_label = Some(label);
        }
        skips.push(s);
    }
    if skips.is_empty() {
        let lookup_failed = matches!(cursor.into_failure(), ProviderKey::LookupFailed);
        return Err(CandidateSkip {
            attempts: vec![skipped_failover_attempt(i.family, i.model, "no_byok_key")],
            lookup_failed,
        });
    }
    Err(CandidateSkip {
        attempts: skips,
        lookup_failed: false,
    })
}

/// `OG-11` §4: every candidate of a routed request was skipped — refuse with the
/// STRICTEST skip's refusal (a control's 403 before a budget's 402 before a 400 before
/// an outage's 503), so the caller is told the most actionable reason. The skips ride
/// the error span.
fn routed_refusal(
    guard: &mut super::DispatchGuard,
    skips: Vec<DispatchAttempt>,
    model: &str,
    lookup_failed: bool,
    state: &AppState,
) -> axum::response::Response {
    let has = |r: &str| skips.iter().any(|a| a.reason.as_deref() == Some(r));
    let provider = skips.first().map(|a| a.provider.clone());
    let (status, code, message): (StatusCode, &'static str, String) = if has("policy_denied") {
        (
            StatusCode::FORBIDDEN,
            "policy_model_denied",
            "every target of this virtual model is denied by this API key's or workspace's policy"
                .to_owned(),
        )
    } else if has("unpriced_under_budget") {
        (
            StatusCode::PAYMENT_REQUIRED,
            crate::admission::UNPRICED_UNDER_BUDGET,
            "every remaining target of this virtual model is unpriced, and this key or workspace has a budget".to_owned(),
        )
    } else if has("zdr_ineligible")
        && !has("unsupported_request")
        && !has("no_byok_key")
        && !has("breaker_open")
        && !has("killed")
    {
        guard.record_attempts(skips);
        guard.abort("zdr_unsatisfiable", None);
        return zdr_unsatisfiable_response(
            model,
            provider.as_deref().unwrap_or("unknown"),
            state.zdr.load().default_count(),
        );
    } else if has("zdr_ineligible") || has("unsupported_request") {
        (
            StatusCode::BAD_REQUEST,
            "unsupported_request",
            "no target of this virtual model can serve this request (zero-data-retention or an unsupported field)".to_owned(),
        )
    } else if has("no_byok_key") && lookup_failed {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "provider_key_unavailable",
            "the key store could not be reached — nothing was sent to a provider; retry shortly"
                .to_owned(),
        )
    } else if has("no_byok_key") && !has("breaker_open") && !has("killed") {
        (
            StatusCode::BAD_REQUEST,
            "provider_not_configured",
            "no API key is configured for any target of this virtual model — add one in Settings → LLM Providers".to_owned(),
        )
    } else {
        guard.record_attempts(skips);
        guard.abort("upstream_circuit_open", None);
        let mut resp = (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "error": "upstream_circuit_open",
                "message": "every target of this virtual model is temporarily unavailable through this gateway",
                "retry_after_seconds": 10
            })),
        )
            .into_response();
        resp.headers_mut().insert(
            axum::http::header::RETRY_AFTER,
            axum::http::HeaderValue::from_static("10"),
        );
        return resp;
    };
    guard.record_attempts(skips);
    guard.abort(code, None);
    provider_error_response(status, code, Some(&message), provider.as_deref(), None)
}

/// Optional prompt-promotion correlation extracted from the request body so
/// the auto-rollback engine can attribute a request's metrics to a specific
/// prompt version. Absent for ad-hoc (non-managed-prompt) traffic.
///
/// **`name` and `env` used to live here and are gone deliberately.** Their only
/// consumer was the flip inside `observe_and_maybe_rollback` — `env` chose
/// whether to touch production and `name` chose which pointer to move — and the
/// hot path no longer has the authority to flip anything (see
/// `PromptRouter::observe_only`). Two things follow, and the second is why they
/// were deleted rather than left inert:
///
///   * `env` defaulted to `Production` whenever the field was absent **or**
///     unparseable, conflating "not stated" with "not understood" and resolving
///     both to the one value that mutates. With no flip there is nothing left to
///     default.
///   * A struct that still carried a name and an env would be an invitation to
///     re-wire the flipping call, since the arguments would be sitting right
///     there. Removing them makes the capability unreachable rather than merely
///     unused.
#[derive(Clone)]
pub(super) struct PromptObservation {
    pub(super) version_id: Uuid,
}

impl PromptObservation {
    /// Returns `Some` only when the body carries a parseable
    /// `tracelane_prompt_version_id`.
    ///
    /// `tracelane_prompt_name` is no longer required: it selected a flip target
    /// and there is no flip. The version id alone attributes the metric, and
    /// `PromptRouter::feed_engine` refuses any id the tenant does not own.
    pub(super) fn from_body(body: &serde_json::Value) -> Option<Self> {
        let version_id = body
            .get("tracelane_prompt_version_id")
            .and_then(|v| v.as_str())
            .and_then(|s| Uuid::parse_str(s).ok())?;
        Some(Self { version_id })
    }
}

/// Fire-and-forget: feed one request's metrics to the auto-rollback engine,
/// OFF the response path (zero added client latency). On objective drift in
/// production the router flips the production pointer back to the previous
/// version (closing the B1 auto-rollback loop, ADR-009 §7.4.3).
#[allow(clippy::too_many_arguments)]
pub(super) fn spawn_prompt_metric_observation(
    router: Arc<crate::prompt_router::PromptRouter>,
    tenant_id: TenantId,
    obs: PromptObservation,
    latency_ms: f64,
    is_error: bool,
    guardrail_fired: bool,
    total_tokens: u64,
) {
    tokio::spawn(async move {
        let metrics = crate::auto_rollback::PromptMetrics {
            // Auto-rollback's EWMA detects *relative* cost drift, so it needs a
            // signal that is consistent across ALL requests. Token volume is that
            // proxy. The model price catalog (`crate::pricing`) now powers the
            // customer-facing span cost, but is deliberately NOT mixed in here: a
            // known-model request (~$0.01) and an unknown-model one (raw tokens)
            // are different scales that would corrupt the EWMA. Migrating this
            // signal to catalog dollars end-to-end is a clean follow-up.
            cost_usd: total_tokens as f64,
            latency_ms,
            error: is_error,
            guardrail_fired,
            // Subjective metrics are populated by a post-hoc eval / SLM-judge
            // pass, not the inline gateway path.
            accuracy: None,
            hallucination: None,
        };
        // `observe_only` — NOT `observe_and_maybe_rollback`. The chat request
        // body carries `tracelane_prompt_*`, so feeding the flipping variant
        // from here made the body a prompt-WRITE surface with none of the gates
        // the HTTP write routes carry. The hot path may move the EWMA; only
        // `/v1/prompts/{name}/observe` may move production. See
        // `PromptRouter::observe_only`.
        //
        // Only the version id is carried now; `name`/`env` existed only to
        // choose a flip target and have been removed from the struct.
        if let Err(e) = router
            .observe_only(tenant_id, obs.version_id, &metrics)
            .await
        {
            // Expected and cheap for the common case: a body naming a version
            // this tenant does not own is refused by `feed_engine`. DEBUG, not
            // WARN — an untrusted field must not be able to drive log volume
            // (`.claude/rules/logging.md`).
            tracing::debug!(error = %e, "prompt metric observation not recorded");
        }
    });
}

/// Chat completions handler — hot path.
///
/// Pipeline:
///   1. ADMISSION (`crate::admission`, one typed pipeline shared with
///      `/v1/embeddings` and `/v1/messages`): auth → scope → parse →
///      entitlements + rate limit → monthly quota → key + workspace budgets →
///      predictive (observe-first) → audit publish (fail-CLOSED). Returns the
///      parsed request and an ARMED `DispatchGuard` (B-375 b).
///   2. Online-eval sampling (EVL-28), provider resolve + BYOK key (fail-CLOSED)
///   3. Inline guardrails (fail-CLOSED) → untrusted-data wrap
///   4. Kill-switch + circuit breaker → dispatch (A7 retry, opt-in failover)
///   5. Response: SSE stream passthrough when `"stream": true`, else buffered JSON
///   6. NATS span publish (fire-and-forget, post-response)
///   7. x402 payment event record (fire-and-forget)
///
/// SSE chunks use OpenAI's `chat.completion.chunk` format for drop-in compatibility.
/// `POST /v1/chat/completions` as mounted: the body through the strict parse (`M-A`,
/// security re-review 2026-10-03 — a key repeated in any object is a 400
/// `duplicate_json_key` before anything else runs, where `axum::Json` silently kept the
/// last copy), then [`chat_completions_handler`].
pub(crate) async fn chat_completions_route(
    state: State<AppState>,
    headers: HeaderMap,
    crate::strict_json::StrictJson(body): crate::strict_json::StrictJson,
) -> axum::response::Response {
    chat_completions_handler(state, headers, Json(body)).await
}

#[instrument(skip(state, headers, body), fields(tenant_id = tracing::field::Empty))]
pub(crate) async fn chat_completions_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> axum::response::Response {
    let labels =
        super::request_labels::read(&headers, &state.rate_card.load().policy.request_labels);
    // Boxed: this future is the biggest on the hot path (admission, cache, routing, guardrails,
    // KMS key resolve, dispatch and failover in one state machine). Awaited inline it overflowed
    // a 2 MiB stack in the handler tests after the OG-11/OG-30/OG-37 merge.
    let result = Box::pin(chat_completions_handler_with_labels(
        State(state),
        headers,
        Json(body),
        &labels,
    ))
    .await;
    super::request_labels::response(result, &labels)
}

async fn chat_completions_handler_with_labels(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
    labels: &super::request_labels::BoundedLabels,
) -> axum::response::Response {
    use crate::admission::{Chat, Route as _};
    let cache_control = match crate::semantic_cache::CacheControl::parse(&headers) {
        Ok(control) => control,
        Err(err) => return err.response(false),
    };
    // OG-51: the optional namespace header is validated with the cache header — a bad one is
    // a 400 before anything is charged, exactly like a bad `x-tracelane-cache`.
    let cache_namespace_header = match crate::cache_controls::namespace_header(&headers) {
        Ok(v) => v,
        Err(()) => {
            return crate::semantic_cache::CacheRefusal {
                status: StatusCode::BAD_REQUEST,
                code: "invalid_cache_control",
            }
            .response(false);
        }
    };
    // --- Step 1: ADMISSION. Nothing above this line resolves a credential. ---
    // Every refusal (401 / 403 / 400 / 429 / 402 / 503) is rendered on this wire
    // by `Chat::refuse`; an `Err` here means NO ledger row landed.
    let mut admitted = match crate::admission::admit::<Chat>(&state, &headers, body).await {
        Ok(a) => a,
        Err(refusal) => return Chat::refuse(refusal),
    };
    super::request_labels::attach(&mut admitted, labels);
    let crate::admission::Admitted {
        attempt_security,
        claims,
        mut identity,
        request_start,
        trace_id,
        inbound_parent,
        parsed,
        entitlements,
        route_plan,
        bench_mock,
        warn_aft_id,
        correlation_id,
        mut dispatch_guard,
        mut timer,
        ..
    } = admitted;
    let crate::admission::ChatParsed {
        body,
        request: mut chat_request,
    } = parsed;
    let tenant_id = &claims.tenant_id;
    tracing::Span::current().record("tenant_id", tenant_id.to_string());
    // `mut`: on a successful cross-provider failover below we reassign this to
    // the provider that actually served the request, so the span, the echoed
    // response model, and billing all attribute to the real server. Bound
    // BEFORE the GWY-39 alias rewrite so it stays the CALLER's string.
    let mut model = chat_request.model.clone();

    // GWY-27: a WORKSPACE alias resolves to its one target HERE, at entry, before
    // anything keys on the model — deliberately earlier than the operator rewrite
    // below. The response-cache key (`request_key`, below) hashes
    // `chat_request.model`; resolving later would key an alias's answers under the
    // alias, and repointing `fast` from A to B would keep serving A's cached answers.
    // Provider resolution, failover, billing and the deployment id therefore all see
    // the TARGET. What the caller sent survives on `identity.requested_model`
    // (`gen_ai_request_model`), and `tenant_alias_applied` makes the span say
    // `tracelane_model_substitution = "alias"` — nothing about the swap is silent.
    // One map probe on the already-resolved entitlements; no alias ⇒ no change. A
    // target that no longer routes fails CLOSED below (`unroutable_model`) — never a
    // default target.
    //
    // OG-11: a VIRTUAL model is resolved by the routing plan instead (its targets are
    // concrete models, never aliases — the write refuses one), so the alias map is not
    // consulted for it.
    if route_plan.as_ref().is_none_or(|p| !p.dispatches())
        && let Some(target) = entitlements
            .as_deref()
            .and_then(|e| crate::db::model_aliases::resolve(&e.model_aliases, &model))
    {
        let target = target.to_owned();
        chat_request.model.clone_from(&target);
        model = target;
        identity.tenant_alias_applied = true;
    }
    // OG-51: decided ONCE, before the cache policy: whether this workspace records both prompt
    // and response text. The privacy default reads it — a workspace that records nothing is not
    // cached unless it explicitly opted in. The same decision every span site below reads.
    let capture = super::config::capture_decision(
        super::config::trace_content(),
        entitlements.as_deref().map(|e| e.content_capture),
        tenant_id,
    );
    let cache_end_user = identity.end_user_id.clone();
    let cache_caller = crate::cache_controls::CacheCaller {
        model: &chat_request.model,
        key_id: claims
            .api_key_id()
            .and_then(|k| uuid::Uuid::parse_str(k).ok()),
        project_id: claims.governance.as_deref().and_then(|g| g.project_id),
        end_user: cache_end_user.as_deref(),
        captured: capture.judge_may_read(),
        namespace_header: cache_namespace_header.as_deref(),
    };
    let cache_policy = match cache_control.resolve(
        entitlements.as_deref(),
        state.semantic_cache.as_deref(),
        !body
            .get("stream")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false),
        &cache_caller,
    ) {
        Ok(policy) => policy,
        Err(err) => {
            dispatch_guard.abort(err.code, None);
            return err.response(false);
        }
    };
    // A scoped rail policy may change output enforcement. Neither exact nor semantic
    // answers computed under another policy can satisfy it; suspend both tiers.
    let cache_policy = if state
        .guardrail
        .policy_for(
            *claims.tenant_id.as_uuid(),
            claims.api_key_id(),
            claims.governance.as_ref().and_then(|g| g.project_id),
        )
        .await
        .has_controls()
    {
        cache_policy.suspend()
    } else {
        cache_policy
    };
    let cache_context = state.prompt_router.canary_cache_context(&claims.tenant_id);
    if cache_context.suspended
        && matches!(
            cache_control,
            crate::semantic_cache::CacheControl::Use | crate::semantic_cache::CacheControl::Ttl(_)
        )
    {
        dispatch_guard.abort("response_cache_suspended_for_canary", None);
        return crate::semantic_cache::CacheRefusal {
            status: StatusCode::CONFLICT,
            code: "response_cache_suspended_for_canary",
        }
        .response(false);
    }
    let cache_policy = if cache_context.suspended {
        cache_policy.suspend()
    } else {
        cache_policy
    };
    // OG-11: the routing document (for key pools) and the plan's span facts.
    let routing_state: Arc<crate::routing::RoutingState> = entitlements
        .as_deref()
        .map(|e| Arc::clone(&e.routing))
        .unwrap_or_default();
    let mut route_rng = crate::routing::thread_rng;
    identity.route = super::RouteMeta::from_plan(route_plan.as_deref());
    dispatch_guard.record_route(identity.route.clone());

    // H2 / re-review H-3 (2026-10-02): does this caller carry a key or workspace budget?
    // Read by every POST-admission model change below (ZDR re-route, failover) so none of
    // them can move a budgeted request onto spend the gateway cannot price.
    let caller_budgeted = crate::admission::caller_is_budgeted(&claims, entitlements.as_deref());
    // OG-25: the workspace block lists, for the post-admission model moves below.
    let ws_controls = entitlements.as_deref().map(|e| Arc::clone(&e.controls));

    // --- Step 2e: ONLINE-EVAL ADMISSION (EVL-28, item 11) ---
    //
    // THE CHEAPEST THING THAT COULD POSSIBLY DECIDE THIS, and it is placed here
    // for a reason: AFTER every admission refusal (429 / 402 / 403 / 503), so a
    // request that is about to be refused never draws a sample and never spends
    // judge money on an answer that will not exist.
    //
    // NO I/O ON A CACHE HIT. One cached entitlement read (already resolved by
    // admission), one cached policy read (15-min TTL), one blake3 of
    // `salt || trace_id`. `None` — not entitled, no policy, disabled, or simply
    // not in the sample — is the overwhelmingly common answer and costs a hash.
    //
    // `Some` does NOT dispatch anything here. It only records that this request
    // is in the sample, so the response path knows to keep the answer. The judge
    // runs after the response is sent (`online_eval::spawn`).
    // B-299 (founder-ruled 2026-09-03): the judge is a CONSUMER of the tenant's
    // content and obeys the SAME capture policy as storage. A capture-off tenant's
    // request body is never flattened, never sent to a judge model, and no
    // derivative of it is persisted — `admission` refuses before `question` exists.
    //
    // GWY-53: decided ONCE for the whole request — the operator allowlist OR the
    // workspace owner's opt-in (the entitlement cache's copy; `None` = no control
    // plane = the workspace half OFF). Every span site below and the judge read
    // THIS value; nothing re-decides later in the request.
    // `capture` was decided above, before the response-cache policy needed it (OG-51);
    // error spans share this workspace capture decision.
    dispatch_guard.record_input(CapturedInput::build(capture, &chat_request));
    let (online_eval_policy, policy_round_trip) = crate::online_eval::admission(
        tenant_id,
        trace_id,
        entitlements.as_deref(),
        capture.judge_may_read(),
    )
    .await;
    // B-568 I5: the policy cache has a 15-minute TTL and no stale serve, so an
    // entitled sparse tenant reads Postgres here — the `online_eval_admission`
    // stage the prod slow lines showed. A fifth cold source beside the spec's four.
    if policy_round_trip {
        timer.note_cold();
        identity.cold_start = true;
    }
    let online_eval_pending = match online_eval_policy {
        Some(policy) => Some(crate::online_eval::Pending {
            entitlements: state.entitlements.clone(),
            policy,
            providers: Arc::clone(&state.providers),
            clickhouse_url: state.quota_ch_url.clone(),
            // The judge publishes its OWN cost span so `/v1/costs` can price
            // it; the two spend counters are in-memory and no read surface
            // consults them.
            nats: state.nats.clone(),
            // Flattened HERE because the request body does not survive to the
            // completion site, and the judge cannot grade an answer without the
            // question it answered.
            question: crate::online_eval::flatten_request_text(&body),
        }),
        None => None,
    };
    timer.mark("online_eval_admission");

    // B1 auto-rollback feed context — extracted once here while `body` is in
    // scope (dispatch below consumes it). Fed to the auto-rollback engine off
    // the response path at completion; `None` for non-managed-prompt traffic.
    let prompt_obs = PromptObservation::from_body(&body);
    let guardrail_fired = warn_aft_id.is_some();

    // --- Step 2: Provider resolve + BYOK key ---

    // x402: extract payment event if present and record async.
    // Runs before provider dispatch so intent is captured even on provider error.
    if let Some(ev) = crate::payment::extract_payment_event(
        &body,
        tenant_id,
        identity.agent_id.as_deref(),
        trace_id,
    ) && let Some(pool) = state.pg.clone()
    {
        tokio::spawn(async move {
            if let Err(e) = crate::payment::record_payment_event(&pool, ev).await {
                tracing::warn!(error = %e, "payment event record failed");
            }
        });
    }

    // Resolve the provider ONCE from the single canonical map and FAIL
    // CLOSED on an unmatched model. There is NO default provider — routing an
    // unknown model to Anthropic (or any provider) would fetch that provider's
    // BYOK key for a model the caller never asked for (credential misrouting).
    // Rejecting is categorically safer than shipping the wrong provider's key.
    // Bench-mock bypass for routing + BYOK.
    //
    // POSITION IS THE SECURITY PROPERTY. `bench_mock` was decided by the
    // admission pipeline AFTER auth and after `tenant_id` was taken from
    // `claims` (`admission::Step::Auth` < `Step::Entitlements`, a compile-time
    // fact), so an unauthenticated request can never reach the mock arm — it is
    // rejected upstream with 401 exactly as before. Asserted by
    // `the_bench_grant_is_unreachable_without_a_credential`, not by this comment.
    //
    // DOUBLE-GATED, both directions fail closed:
    //   flag ON  + `__bench_mock*`  -> bypass (the only way in)
    //   flag ON  + real model       -> normal path, untouched
    //   flag OFF + `__bench_mock*`  -> falls through -> 400 unroutable_model
    //   flag OFF + real model       -> normal path, untouched
    //
    // Why the bypass is needed at all: `provider_id_for_model` fails closed and
    // `providers/mod.rs` has no `__bench_mock` arm, so the reserved model was
    // rejected 211 lines BEFORE the mock branch at :1358 — the benchmark has
    // never been reachable. BYOK resolution below is a second blocker on the
    // same path, so both are bypassed together.
    // OG-11: a ROUTED request starts at the first candidate that can be dispatched. A
    // candidate that is killed, ZDR-ineligible, policy-denied, unpriced under a budget,
    // unsupported, keyless or breaker-open on every pool key is SKIPPED and recorded on
    // the attempt ledger; nothing about the choice is silent. The candidates after the
    // chosen one are the fallthrough targets. Every candidate is the CALLER'S OWN
    // tenant's: the plan came from its document and each key is `(tenant, provider,
    // label)`.
    let mut route_skips: Vec<DispatchAttempt> = route_plan
        .as_deref()
        .map_or_else(Vec::new, crate::routing::RoutePlan::skipped_attempts);
    let mut plan_rest: Vec<crate::routing::Candidate> = Vec::new();
    let mut primary_pool: Option<RoutedKey> = None;
    if let Some(plan) = route_plan.as_deref().filter(|p| p.dispatches()) {
        let zdr_required = matches!(
            crate::zdr::constraint_from_headers(&headers),
            Ok(Some(crate::zdr::Constraint::Required))
        );
        let mut chosen: Option<usize> = None;
        let mut lookup_failed = false;
        for (i, c) in plan.candidates.iter().enumerate() {
            let family = provider_name_from_model(&c.model);
            match select_candidate(
                &state,
                SelectInput {
                    tenant_id,
                    claims: &claims,
                    controls: ws_controls.as_deref(),
                    caller_budgeted,
                    zdr_required,
                    request: &chat_request,
                    routing: &routing_state,
                    family,
                    model: &c.model,
                    provider_id: c.provider_id,
                },
                &mut route_rng,
            )
            .await
            {
                Ok(k) => {
                    if k.cold {
                        timer.note_cold();
                        identity.cold_start = true;
                    }
                    primary_pool = Some(k);
                    chosen = Some(i);
                    break;
                }
                Err(skip) => {
                    lookup_failed |= skip.lookup_failed;
                    route_skips.extend(skip.attempts);
                }
            }
        }
        let Some(i) = chosen else {
            return routed_refusal(
                &mut dispatch_guard,
                route_skips,
                &model,
                lookup_failed,
                &state,
            );
        };
        let c = &plan.candidates[i];
        chat_request.model.clone_from(&c.model);
        model.clone_from(&c.model);
        identity.route.target_index = Some(c.target_index);
        dispatch_guard.record_route(identity.route.clone());
        plan_rest = plan.candidates[i + 1..].to_vec();
    }

    let mut provider_id = if bench_mock {
        BENCH_MOCK_PROVIDER_ID
    } else {
        match crate::providers::ProviderRegistry::provider_id_for_model(&model) {
            Some(p) => p,
            None => {
                // R13, and I did not find this one by reading — the guard did, on its
                // first run. made the model map fail closed, which is right, but
                // the ledger row is already published by here, so an unroutable model
                // produced a ledger entry and no trace. It is also the single most
                // likely error a new customer hits (a typo'd or unsupported model name),
                // which makes it the worst one to be invisible.
                dispatch_guard.abort("unroutable_model", None);
                return unroutable_model_response(&model);
            }
        }
    };
    // GWY-49: the zero-data-retention constraint is judged HERE — after the provider is
    // known, before any credential is resolved or any byte leaves for a provider. A
    // header this gateway cannot read is refused rather than guessed. The router PRUNES
    // (the roadmap's word): the primary is used if the table vouches for it; otherwise,
    // and ONLY when the customer also opted into cross-provider failover, the first
    // eligible candidate in their chain serves the request as if it had been asked for
    // — recorded as a `zdr_ineligible` skip of the primary in the attempt ledger and as
    // `failover_from` on the span, so nothing about the swap is silent. Tracelane never
    // sends to a provider the customer did not name, directly or by that opt-in. Nothing
    // eligible → 400 `zdr_unsatisfiable`. Fail-CLOSED: an unloaded table makes nothing
    // eligible (`zdr.rs`).
    let zdr_constraint = match crate::zdr::constraint_from_headers(&headers) {
        Ok(c) => c,
        Err(bad) => {
            dispatch_guard.abort("invalid_zdr_constraint", None);
            return invalid_zdr_constraint_response(&bad);
        }
    };
    // Opt-in CROSS-PROVIDER failover, per request. Read here because the ZDR prune
    // consults it; the failover loop further down uses the same value.
    //
    // GWY-52: a workspace may turn it ON for all its requests; a per-request
    // `X-Tracelane-Failover: off` still wins, and the header's `cross-provider` works
    // exactly as before. `None` entitlements (no control plane) = the operator default.
    let failover_header = headers
        .get("x-tracelane-failover")
        .and_then(|v| v.to_str().ok());
    let header_on = failover_header.is_some_and(|v| v.eq_ignore_ascii_case("cross-provider"));
    let header_off = failover_header.is_some_and(|v| v.eq_ignore_ascii_case("off"));
    let workspace_failover_on = entitlements.as_deref().is_some_and(|e| e.failover_enabled);
    let cross_provider_failover = header_on || (workspace_failover_on && !header_off);
    // The workspace's own fallback models (empty = the operator chain).
    let workspace_failover_models: Arc<Vec<String>> = entitlements
        .as_deref()
        .map(|e| Arc::clone(&e.failover_models))
        .unwrap_or_default();
    // Set when the ZDR prune re-pointed the request at a failover candidate: the
    // primary's ledger element (merged into `dispatch_attempts` once it exists) and the
    // primary family for the span's `failover_from`.
    let mut zdr_primary_skipped: Option<DispatchAttempt> = None;
    let mut zdr_failover_from: Option<&'static str> = None;
    let zdr_eligible: Option<Vec<String>> = match zdr_constraint {
        None => None,
        Some(crate::zdr::Constraint::Required) => {
            let caps = state.zdr.load();
            let primary_eligible = bench_mock || caps.eligible(provider_id);
            // The providers the chain WOULD accept under the constraint, primary first —
            // recorded on the span so an auditor can see the pruned set, not only the pick.
            let mut eligible: Vec<String> = Vec::new();
            if primary_eligible {
                eligible.push(provider_id.to_string());
            }
            // OG-11: the virtual model's fallthrough targets the constraint leaves standing.
            for c in &plan_rest {
                if caps.eligible(c.provider_id) {
                    eligible.push(c.provider_id.to_string());
                }
            }
            // (provider, model, provider_id) of the first candidate that is BOTH vouched
            // for and routable — an unroutable one is not a candidate (its key would be
            // the wrong one), same as the failover loop's own `unroutable` skip.
            let mut first_candidate: Option<(&'static str, String, &'static str)> = None;
            if cross_provider_failover {
                let primary_family = provider_name_from_model(&model);
                for (fo_provider, fo_model_owned) in crate::providers::failover::candidates_for(
                    primary_family,
                    &workspace_failover_models,
                    state.failover,
                ) {
                    let fo_model: &str = &fo_model_owned;
                    if !caps.eligible(fo_provider) {
                        continue;
                    }
                    // Re-review H-3: the ZDR re-route happens AFTER admission priced the
                    // primary; a budgeted caller must not be moved onto a model the
                    // gateway cannot price (it would spend past the budget unseen).
                    if caller_budgeted
                        && matches!(
                            crate::admission::token_pricing(fo_model),
                            crate::admission::Pricing::Unpriced { .. }
                        )
                    {
                        continue;
                    }
                    let Some(fo_pid) =
                        crate::providers::ProviderRegistry::provider_id_for_model(fo_model)
                    else {
                        continue;
                    };
                    // OG-20: the key's policy judged the PRIMARY at admission; a re-route
                    // must not land on a model or provider it denies.
                    if !policy_allows(&claims, ws_controls.as_deref(), fo_model, fo_pid) {
                        continue;
                    }
                    if first_candidate.is_none() {
                        first_candidate = Some((fo_provider, fo_model.to_owned(), fo_pid));
                    }
                    eligible.push(fo_provider.to_string());
                }
            }
            if eligible.is_empty() {
                // Per-request, so no log line (`.claude/rules/logging.md`): the refusal
                // is on the error span (`zdr_unsatisfiable`, with `zdr_required` and the
                // EMPTY eligible set) and in the 400 body, and
                // `/health.zdr.capabilities_loaded` says whether the table ever loaded.
                dispatch_guard.record_zdr(Vec::new());
                dispatch_guard.abort("zdr_unsatisfiable", None);
                return zdr_unsatisfiable_response(&model, provider_id, caps.default_count());
            }
            // Every later refusal (no key, breaker, guardrail…) and a client cancel
            // carries the constraint too.
            dispatch_guard.record_zdr(eligible.clone());
            if !primary_eligible {
                // `eligible` is non-empty and the primary is not in it, so a candidate is.
                if let Some((fo_provider, fo_model, fo_pid)) = first_candidate {
                    zdr_primary_skipped = Some(skipped_failover_attempt(
                        provider_id,
                        &model,
                        "zdr_ineligible",
                    ));
                    zdr_failover_from = Some(provider_name_from_model(&model));
                    tracing::debug!(
                        from = provider_id,
                        to = fo_provider,
                        fo_model = %fo_model,
                        "zdr: primary pruned — routing to the first eligible failover candidate"
                    );
                    // From here on the request is the candidate's: span provider, echoed
                    // model, BYOK key, breaker and billing all follow `model`/`provider_id`,
                    // exactly as a post-failure failover re-attributes them below.
                    chat_request.model.clone_from(&fo_model);
                    model = fo_model;
                    provider_id = fo_pid;
                }
            }
            Some(eligible)
        }
    };

    // OG-03: can THIS provider honour every field and part the request carries? The
    // provider is final here (ZDR prune ran) and nothing has touched a credential yet, so a
    // refusal costs no key lookup and no upstream call. A field an adapter cannot map is a
    // 400 naming it — fail CLOSED, never a different answer with no signal. A cross-provider
    // failover candidate re-runs the same check for ITS provider (below). The bench mock
    // never dispatches upstream, so it has nothing to translate.
    //
    // The `reasoning_effort` mapping keys on the model that will reach the WIRE, which a
    // `tracelane.yaml` alias rewrites only later (after the cache key is derived, so it
    // cannot move). Probe with the alias target — a clone, and only when an alias applies.
    if !bench_mock {
        let verdict = match super::config::alias(&model) {
            Some(a) => {
                let mut probe = chat_request.clone();
                probe.model.clone_from(&a.upstream_model);
                crate::request_support::check_supported(provider_id, &probe)
            }
            None => crate::request_support::check_supported(provider_id, &chat_request),
        };
        if let Err(unsupported) = verdict {
            dispatch_guard.abort(unsupported.code, None);
            return unsupported.into_response();
        }
    }

    // A4: BYOK lookup first — per-tenant ciphertext in `provider_keys` decrypted
    // with AAD bound to (tenant_id, provider_id[, label]). On miss (no row, decrypt
    // fail, pool unavailable) fall back to the legacy env var — `default` label only.
    // The env var is derived from THIS provider_id, so a miss yields an empty key
    // (upstream 401), never another provider's key.
    // The bench mock never dispatches upstream, so there is no credential
    // to resolve. Skipping the lookup also keeps the benchmark honest — it must
    // not measure a Postgres round-trip the mocked request would never make.
    //
    // OG-11: the key comes from the provider's POOL (`default` alone when the routing
    // document gives the provider none): the first label whose key resolves and whose
    // breaker would admit the call. A routed request already chose its key above.
    let mut served_label = crate::db::provider_keys::DEFAULT_LABEL.to_owned();
    let mut served_pooled = false;
    let mut key_cursor: Option<super::KeyCursor> = None;
    let provider_key = if bench_mock {
        std::sync::Arc::new(secrecy::SecretString::from(String::new()))
    } else if let Some(k) = primary_pool.take() {
        served_label = k.label;
        served_pooled = k.pooled;
        key_cursor = Some(k.cursor);
        k.key
    } else {
        let key_env = crate::providers::ProviderRegistry::env_var_for_provider_id(provider_id);
        let pool = crate::routing::pool_labels(
            &crate::admission::Chat::ROUTING,
            &routing_state,
            provider_id,
            &mut route_rng,
        );
        served_pooled = pool.pooled;
        let mut cursor = super::KeyCursor::new(pool.labels);
        let family = provider_name_from_model(&model);
        let region_for_pick = state.providers.upstream_region(provider_id);
        let mut first_found: Option<(String, Arc<secrecy::SecretString>)> = None;
        let mut picked: Option<(String, Arc<secrecy::SecretString>)> = None;
        while let Some((label, k)) = cursor.next_key(tenant_id, provider_id, key_env).await {
            let cred =
                super::dispatch::breaker_cred(tenant_id, provider_id, &label, Some(&routing_state));
            if !served_pooled
                || state
                    .circuit_breaker
                    .would_allow(family, region_for_pick, &cred)
            {
                picked = Some((label, k));
                break;
            }
            if first_found.is_none() {
                first_found = Some((label, k));
            }
        }
        // B-568 I5: a BYOK cache miss read the control plane on the request path.
        if cursor.cold {
            timer.note_cold();
            identity.cold_start = true;
        }
        // Every pool key breaker-open: keep the first, so the breaker check below
        // answers 503 exactly as a single key does.
        match picked.or(first_found) {
            Some((label, k)) => {
                served_label = label;
                key_cursor = Some(cursor);
                k
            }
            None => {
                // First-value path: a launch-day user who has not added BYOK yet must be
                // told to ADD a key, not that their key was "rejected". Dispatching an
                // empty credential and relaying the upstream 401 read as "my key is
                // broken" for a user who had no key at all. Fail here, before the
                // upstream round-trip.
                let (status, code, message) = match cursor.into_failure() {
                    ProviderKey::NotConfigured => (
                        StatusCode::BAD_REQUEST,
                        "provider_not_configured",
                        "no API key is configured for this provider — add one in Settings → LLM Providers, then retry",
                    ),
                    ProviderKey::LookupFailed => (
                        StatusCode::SERVICE_UNAVAILABLE,
                        "provider_key_unavailable",
                        "the key store could not be reached — nothing was sent to the provider; retry shortly",
                    ),
                    ProviderKey::KmsUnavailable => (
                        StatusCode::SERVICE_UNAVAILABLE,
                        "kms_unavailable",
                        "customer key service unavailable",
                    ),
                    ProviderKey::KmsDenied => (
                        StatusCode::FORBIDDEN,
                        "kms_access_denied",
                        "customer key service refused access",
                    ),
                    ProviderKey::Unusable | ProviderKey::Found(_) => (
                        StatusCode::BAD_GATEWAY,
                        "provider_key_unusable",
                        "a stored key for this provider could not be decrypted — rotate it in Settings → LLM Providers",
                    ),
                };
                tracing::warn!(provider = provider_id, code, "provider key unresolvable");
                // Emit the ERROR span so this is visible in /traces and countable —
                // same reason the dispatch-failure path does (#3). Without it,
                // the most common first-run failure is invisible in the product.
                dispatch_guard.abort(code, None);
                return provider_error_response(
                    status,
                    code,
                    Some(message),
                    Some(provider_id),
                    None,
                );
            }
        }
    };
    if served_pooled {
        identity.route.key_label = Some(served_label.clone());
        dispatch_guard.record_route(identity.route.clone());
    }

    // GWY-24: the cache identity is derived HERE — after the parse, BEFORE the
    // guardrail redaction at `redact_request_in_place`.
    //
    // The ordering is load-bearing and not obvious. `crates/policy/src/pii.rs`
    // builds its placeholder as `{REDACT_OPEN}{category}:{idx}}}` — a category
    // and a running index, carrying no secret and no tenant material. Two
    // DIFFERENT secrets in the same position therefore redact to a
    // BYTE-IDENTICAL string, so hashing after redaction would treat two
    // genuinely different requests as one and serve the wrong answer to the
    // second. Hashing before redaction is the only correct window.
    // OG-51 / OG-38: a request that REQUIRES zero data retention neither reads from nor writes
    // into the response cache — a stored answer is a retained answer, on both tiers.
    let cache_policy = if zdr_constraint.is_some() {
        cache_policy.suspend()
    } else {
        cache_policy
    };
    let cache_key = state.semantic_cache.as_ref().map(|cache| {
        cache.bind_key(
            tenant_id,
            cache_policy.key(crate::semantic_cache::request_key(&chat_request)),
            route_plan
                .as_deref()
                .and_then(crate::routing::RoutePlan::cache_namespace),
        )
    });

    // GWY-48: built in the SAME pre-redaction window, and for a related reason.
    // The span must record what the CLIENT sent; `redact_request_in_place` below
    // rewrites request text, and a tool description it touched would change the
    // `def_hash` — so a span built after it would report a tool-set identity the
    // caller never had, and a customer's join to `observed_tools.def_hash` would
    // miss. Built ONCE here and cloned to the four span sites rather than
    // rebuilt per site, so the per-tool hashing happens once per request.
    //
    // `with_policy_flags` is OBS-52 and is applied here too: the policy reads
    // only what this struct already holds, so evaluating it once beside the
    // build keeps the detector's input identical at every site by construction.
    //
    // AND it is deliberately BEFORE the GWY-39 alias rewrite immediately below,
    // so `tracelane_request_deployment_id` is derived from the string the CALLER
    // sent — the same string `gen_ai_request_model` records, for the same stated
    // reason ("the span, the ledger and the echoed response all say what the
    // caller actually asked for"). Moving this after the rewrite would make one
    // attribute describe the resolved model while its neighbour describes the
    // alias, which is worse than either choice made consistently.
    let request_config = RequestConfig::build(&chat_request).with_policy_flags();
    let request_config = match &zdr_eligible {
        Some(eligible) => request_config.with_zdr(eligible.clone()),
        None => request_config,
    };

    // GWY-39: a `tracelane.yaml` alias names the provider (resolved above, via
    // the canonical map) AND the upstream model. Only the OUTGOING request is
    // rewritten. `model` deliberately keeps the caller's alias so the span, the
    // ledger and the echoed response all say what the caller actually asked
    // for — and so `dispatch_to_provider`'s defence-in-depth re-resolve lands on
    // the same provider this handler already chose.
    if let Some(a) = super::config::alias(&model) {
        tracing::debug!(
            alias = %model,
            upstream_model = %a.upstream_model,
            provider = %a.provider_id,
            "tracelane.yaml model alias applied"
        );
        chat_request.model.clone_from(&a.upstream_model);
    }

    timer.mark("route_byok");

    // --- Step 3: Inline guardrails (the guardrail spec) ---
    // Request-side rail dispatch over the parsed request (R4 lethal-trifecta +
    // future rails). A security block short-circuits the upstream call with 403;
    // the verdict is recorded to the tamper-evident ledger (+ ClickHouse mirror
    // when configured) regardless of the decision — fail-open-loud on a missing
    // sink (the request always reaches a decision). Runs before the
    // untrusted-data wrap so rails see the request content as the caller sent it.
    // `correlation_id` was minted by admission so the response-side streaming
    // seam reuses the SAME id + the request-side R2 redaction map (built here,
    // re-inserted in the streamed response).
    let mut guardrail_redaction_map: Vec<tracelane_policy::pii::RedactionEntry> = Vec::new();
    let request_hooks;
    // rev6 N3: set when R2 redacted the request — its text then reaches no embedding
    // provider (the semantic cache tier is off for it; see `semantic_tier_models`).
    let mut request_redacted = false;
    {
        let rag_context = crate::guardrail::context::extract_rag_context(&body);
        let session = crate::guardrail::SessionState::fresh(identity.conversation_id.clone());
        let mut gr = state
            .guardrail
            .evaluate_request(crate::guardrail::RequestInputs {
                tenant_id,
                api_key_id: claims.api_key_id(),
                project_id: claims.governance.as_ref().and_then(|g| g.project_id),
                correlation_id,
                request: &chat_request,
                rag_context,
                session,
                actor: claims.sub.as_str(),
                egress_json: None,
            })
            .await;
        request_hooks = gr.hooks.clone();
        identity.hook_events.record(&gr.hook_events);
        if !gr.is_block() && !gr.hook_redactions.is_empty() {
            let rewritten = crate::guardrail::egress::redact_hook_request(
                &mut chat_request,
                &gr.hook_redactions,
            );
            match rewritten {
                Ok(()) => {
                    request_redacted = true;
                    // CAP: an error span must not keep the pre-hook raw text.
                    dispatch_guard.record_input(CapturedInput::build(capture, &chat_request));
                }
                Err(_) => {
                    dispatch_guard.record_input(None); // never retain unredacted raw input
                    crate::guardrail::hooks::block(&mut gr.outcome, "HOOK_REDACTION_UNSUPPORTED")
                }
            }
        }
        // ADR-069 fail-closed: the guardrail verdict could not be durably captured
        // (async publish failed) — refuse rather than serve an unrecorded request.
        if gr.audit_publish_failed {
            tracing::error!(
                correlation_id = %correlation_id,
                "guardrail verdict audit publish failed — refusing request (fail-closed)"
            );
            // R13. The CHAT ledger row landed (that publish is upstream of here and
            // fail-closed in its own right); it is the GUARDRAIL VERDICT that could not
            // be captured. So the ledger attests to a request that was then refused,
            // and without this the refusal is invisible in the product.
            dispatch_guard.abort("audit_unavailable", None);
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({ "error": "audit_unavailable" })),
            )
                .into_response();
        }
        if gr.is_block() {
            let blocking = gr
                .outcome
                .records
                .iter()
                .find(|r| r.outcome.outcome == crate::guardrail::Outcome::Block);
            let rail = blocking.map_or("guardrail", |r| r.rail);
            let reason = blocking
                .and_then(|r| r.outcome.reason_code)
                .unwrap_or("guardrail_block");
            tracing::warn!(
                rail,
                reason_code = reason,
                correlation_id = %correlation_id,
                "request blocked by inline guardrail"
            );
            //  #5: if the blocking reason maps to a canonical AFT-1 signature
            // (tool-description injection → AFT-TOOL-POISON-001), emit an
            // error-status span carrying that `aft_id` BEFORE the 403 short-circuit
            // — otherwise the blocked hit is invisible on /signatures (the very
            // #3 gap, recreated for the injection case). Schema/drift no longer
            // reach this branch (they observe); injection is the live mapping.
            // R13. The AFT id is now an ATTRIBUTE of the span, not a CONDITION on
            // emitting one. It used to gate the whole block: `if let Some(aft_id) =
            // reason_to_aft(reason)`, with the 403 returning unconditionally below —
            // and injection is the only live mapping (see the comment above), so
            // **every other blocking rail produced a ledger row, a guardrail_verdicts
            // row, a 403, and nothing in /traces.** The customer was told their request
            // was blocked and could not see the block. Found by the verifier on the
            // B-245 pass, inside a path I had already credited as covered.
            dispatch_guard.abort(
                "guardrail_block",
                crate::guardrail::rails::r3_tool_safety::reason_to_aft(reason),
            );
            return (
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({
                    "error": "request blocked by Tracelane inline guardrail",
                    "rail": rail,
                    "reason_code": reason,
                    "correlation_id": correlation_id.to_string(),
                })),
            )
                .into_response();
        }
        // R2 request-side egress-apply: when the request-side verdict redacted,
        // rewrite the OUTGOING request (secrets/PII → reversible placeholders)
        // before it leaves the gateway, and keep the map so the streamed
        // response can re-insert the user's originals. Runs before the untrusted
        // wrap + dispatch, so the redacted form is what egresses upstream.
        // M-1: every text R2 read is rewritten — tool descriptions and schemas, tool-call
        // arguments, `response_format`, `user`, `metadata`, extras, not only message text —
        // and a secret left where no rewrite is possible (a tool name, a URL, an object
        // key) BLOCKS the request instead of egressing (fail-CLOSED, §10).
        if gr.outcome.records.iter().any(|r| {
            r.rail == "R2_secrets_pii" && r.outcome.outcome == crate::guardrail::Outcome::Redact
        }) {
            request_redacted = true;
            match crate::guardrail::egress::redact_request_with_policy(
                &mut chat_request,
                gr.pii_policy.as_ref(),
            ) {
                Ok(map) => {
                    guardrail_redaction_map = map;
                    dispatch_guard.record_input(CapturedInput::build(capture, &chat_request));
                }
                Err(crate::guardrail::egress::Unredactable) => {
                    tracing::warn!(
                        correlation_id = %correlation_id,
                        "R2 redact could not cover the egress request — blocking"
                    ); // Never retain unredactable raw input.
                    dispatch_guard.record_input(None);
                    dispatch_guard.abort("guardrail_block", None);
                    return (
                        StatusCode::FORBIDDEN,
                        Json(serde_json::json!({
                            "error": "request blocked by Tracelane inline guardrail",
                            "rail": crate::guardrail::egress::UNREDACTABLE_RAIL,
                            "reason_code": crate::guardrail::egress::UNREDACTABLE_REASON,
                            "correlation_id": correlation_id.to_string(),
                        })),
                    )
                        .into_response();
                }
            }
        }
    }

    // A5: wrap every tool-result message / block in `<UNTRUSTED_USER_DATA>`
    // before any LLM consumes it. CLAUDE.md security non-negotiable #4.
    // Idempotent — a retry that re-enters this code path will not
    // accumulate sentinels.
    crate::untrusted_data::wrap_untrusted_content(&mut chat_request);

    // A7: one retry against the same provider on transient failure, within the
    // FT-01 200ms budget. This is the DEFAULT path. Opt-in cross-provider
    // failover runs AFTER this, only when the request sets
    // `X-Tracelane-Failover: cross-provider` and the primary still failed —
    // re-dispatching the universal ChatRequest to the next provider (no schema
    // translation needed; each adapter translates the canonical request).
    // ADR-036 / OG-13: per-(provider, region, credential) circuit breaker. The region
    // is the adapter's own (Bedrock's AWS region, Vertex's location, Azure's host;
    // "default" elsewhere) and the credential is THIS tenant's key, so one tenant's
    // failures open its own breaker and nobody else's. If the breaker is Open we fail
    // fast with 503 + Retry-After rather than tying up a worker slot on a known-bad
    // upstream.
    let upstream = provider_name_from_model(&model);
    let region = state.providers.upstream_region(provider_id);
    let breaker_cred =
        super::dispatch::breaker_cred(tenant_id, provider_id, &served_label, Some(&routing_state));
    // ADR-038 kill.upstream.<provider> force-opens the breaker (operator
    // disable / provider incident), in addition to the breaker's own state.
    let upstream_killed = state.kill_switch.upstream_killed(upstream);
    if upstream_killed || !state.circuit_breaker.allow(upstream, region, &breaker_cred) {
        tracing::warn!(
            provider = upstream,
            killed = upstream_killed,
            "upstream unavailable (circuit open or killed) — short-circuiting with 503"
        );
        // R13. A breaker-open 503 is the single most useful error span there is: it is
        // the shape a customer most wants to see on their own timeline, and it fires in
        // bursts. The ledger recorded every one of these requests; before this, none of
        // them appeared in /traces.
        dispatch_guard.abort(
            if upstream_killed {
                "upstream_killed"
            } else {
                "upstream_circuit_open"
            },
            None,
        );
        let mut resp = (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "error": "upstream_circuit_open",
                "provider": upstream,
                "retry_after_seconds": 10
            })),
        )
            .into_response();
        resp.headers_mut().insert(
            axum::http::header::RETRY_AFTER,
            axum::http::HeaderValue::from_static("10"),
        );
        resp.headers_mut().insert(
            axum::http::HeaderName::from_static("tracelane-upstream-circuit"),
            axum::http::HeaderValue::from_static("open"),
        );
        return resp;
    }

    // B-375 (b): `dispatch_guard` has been ARMED since admission published the
    // ledger row. From here until a span is recorded by one of the normal paths
    // the request is "in flight with the provider" and a client that hangs up
    // drops this handler future — which recorded NOTHING before the guard
    // existed (the prod proof for B-375 found it: a cancel at 1.5 s against a
    // 1.25 s time-to-first-chunk landed no span at all). Disarmed at every site
    // that records its own span; if it is still armed when the future is
    // dropped, `Drop` records a `client_cancelled` error span.
    timer.mark("guardrails");
    // A7: one retry against the same provider on transient failure.
    //  (verifier finding a): consume the SAME `bench_mock` computed at the
    // routing bypass rather than re-deriving the condition here. A second inline
    // copy of the gate is the drift the unified gate exists to prevent — extend
    // `bench_mock_active` and only one of the two decisions would follow it.
    // ── GWY-24: the cache lookup. THE PLACEMENT IS THE ANSWER TO GWY-25. ────
    //
    // Everything above this line has already run: auth, quota, both budget
    // ceilings, detection, guardrails, and the fail-CLOSED audit publish. So a
    // hit is served AFTER the ledger append, not instead of it — `audit.rs`'s
    // invariant ("the audit product does not serve unrecorded requests") is
    // untouched, which is exactly the objection that killed the exact-match
    // cache in `specs/GWY-25`.
    //
    // Only the DISPATCH is replaced. Not the ledger, not the guardrails, not the
    // budgets.
    //
    // rev6 N3: the semantic tier SENDS the request's text to an embedding provider with
    // the tenant's key, so it is gated like a dispatch: off when R2 redacted the request
    // (the key holds the PRE-redaction text — see `request_key` — and embedding the
    // redacted form instead would let two different secrets match each other), and
    // limited to embedding models the workspace blocks / policy and the key's policy
    // allow, and under ZDR-required to ZDR-eligible providers. The exact tier sends
    // nothing and is unaffected.
    let cache_key = cache_key.map(|mut key| {
        if let Some(cache) = state.semantic_cache.as_deref() {
            let zdr_caps = zdr_constraint.is_some().then(|| state.zdr.load_full());
            key.restrict_semantic_tier(semantic_tier_models(
                cache.config().embedding_models(),
                // OG-51: the workspace may switch the semantic (embedding) tier off; the exact
                // tier is a hash that sends nothing anywhere and is unaffected.
                request_redacted || !cache_policy.semantic_allowed(),
                &claims,
                ws_controls.as_deref(),
                zdr_caps.as_deref(),
            ));
        }
        key
    });
    let cache_hit: Option<crate::semantic_cache::CacheHit> = match (
        state.semantic_cache.as_ref(),
        cache_key.as_ref(),
        is_streaming_request(&body),
    ) {
        // Streaming is never served from cache: `provider_stream_to_sse` has no
        // text accumulator, and replaying a buffered body as SSE would fabricate
        // timing the recorder never saw.
        (Some(cache), Some(key), false) => cache.lookup(tenant_id, &model, key).await,
        _ => None,
    };
    timer.mark("cache_lookup");

    // Latency-split boundary: everything before this mark is gateway overhead
    // (auth, quota, predictive, guardrail engine + the Step-4 audit append,
    // untrusted-wrap, and — B-568 I3 — the response-cache lookup); everything
    // after, up to provider-complete, is the provider round-trip (incl. A7 retry
    // / cross-provider failover). Stamped once, here.
    //
    // B-568 I3 (2026-09-27) moved this stamp from BEFORE the cache lookup to
    // after it. On a MISS the lookup used to be counted as PROVIDER time; it is
    // the gateway's. On prod the exact tier is an in-process `moka` read (µs), so
    // the number barely moves — but a semantic-tier lookup (an embedding call) is
    // now charged to the gateway, where it belongs. A hit is unchanged: its span
    // stamps both boundaries at `now`, so its whole duration is overhead.
    let dispatch_ts = chrono::Utc::now();
    // Emit against the SAME interval the span's overhead number opens with —
    // `dispatch_ts - request_start` — so the log line and the span agree by
    // construction instead of by two similar-looking clocks. A hit emits here
    // too: its pre-dispatch cost is exactly what a slow hit needs explained.
    timer.emit_if_slow(
        &state.hotpath,
        u64::try_from(
            (dispatch_ts - request_start)
                .num_microseconds()
                .unwrap_or(0),
        )
        .unwrap_or(0),
    );

    // SERVE THE HIT — and emit its span before returning, because a served
    // request that produced no span is precisely the "trace gap" GWY-25 refused
    // this feature over.
    if let Some(hit) = cache_hit {
        let mut span = build_gateway_span(
            tenant_id,
            trace_id,
            inbound_parent,
            &model,
            &identity,
            request_start,
            hit.prompt_tokens,
            hit.completion_tokens,
            None,
            SpanUsageMeta {
                cache_read_input_tokens: None,
                cache_creation_input_tokens: None,
                stream: false,
                // EXPLICIT Some(0.0), never None. `build_gateway_span` falls back
                // to `pricing::cost_usd(model, tokens)` when cost is None — with
                // replayed tokens that would invent LIST PRICE for a call that
                // never happened, and the customer would be shown a charge for
                // an answer we did not buy. `SpendTracker::record` drops
                // non-positive cost, so 0.0 also adds nothing to spend.
                cost_usd: Some(0.0),
                // RI-05: a cache hit made no provider call — nothing was SERVED,
                // so the served model stays absent rather than echoing the request.
                served: super::spans::ServedMeta::default(),
                finish_reason: None,
                // RI-05 M1 + M4: a cache hit never reaches `dispatch_with_retry` —
                // no attempt was made, so the ledger is empty (absent on the span).
                dispatch_attempts: Vec::new(),
                reasoning_output_tokens: None,
            },
            None,
            // REAL TIMING, not `None`. `build_gateway_span` only emits
            // `tracelane_gateway_overhead_us` when timing is present, so passing
            // `None` made a cache hit the ONE request shape that reports no
            // overhead at all.
            //
            // That is not cosmetic: deploy **Proof E** reads exactly this
            // attribute, and on the deploy that shipped this feature its two
            // identical requests meant the MEASURED one was a cache hit — so the
            // gate reported "0.0 ms" and passed on a missing value rather than a
            // fast one. The latency gate went vacuous on the very path this
            // feature exists to make fast. Zero and unknown must never render the
            // same, least of all inside the control that guards the number.
            //
            // For a hit there is no provider round trip, so both boundary stamps
            // are NOW: overhead becomes (now − received) + (end − now) ≈ the
            // whole request, which is exactly right — on this path the gateway IS
            // the entire cost.
            Some(GatewayTiming {
                dispatch_ts: chrono::Utc::now(),
                provider_complete_ts: chrono::Utc::now(),
                ttft_us: None,
            }),
            None,
            claims.api_key_id(),
        );
        span.attributes.tracelane_semantic_cache_hit = Some(true);
        span.attributes.tracelane_semantic_cache_tier = Some(hit.tier.to_owned());
        span.attributes.tracelane_semantic_cache_similarity = hit.similarity;
        span.attributes.tracelane_semantic_cache_source_trace_id =
            Some(hit.source_trace_id.to_string());
        span.attributes.tracelane_semantic_cache_cost_saved_usd = Some(hit.cost_saved_usd);
        // GWY-45: a cache hit is a real served request and must carry the same
        // captured input as a miss. Omitting it here would silently bias every
        // eval case set AWAY from repeated prompts — exactly the ones a cache
        // makes common.
        if let Some(captured) = CapturedInput::build(capture, &chat_request) {
            captured.apply(&mut span.attributes);
        }
        capture_cached_answer(&mut span.attributes, capture, &hit.response_json);
        // GWY-48: a hit records this caller's config, not the source request's.
        // That explains why this answer was served without a provider call.
        // The cached answer itself was captured from the JSON returned below.
        request_config.clone().apply(&mut span.attributes);
        spawn_span_publish(&state, span);

        // A cache hit meters ONLY its span bytes (BILL-01 meter 1, stamped in
        // `spawn_span_publish`'s path) — never provider tokens or cost: the
        // provider was not called, and the retired per-request token recorder
        // that once made a hit look like a provider call is deleted.
        tracing::debug!(
            tier = hit.tier,
            similarity = ?hit.similarity,
            lookup_us = hit.lookup_us,
            saved_usd = hit.cost_saved_usd,
            "semantic cache hit — served without a provider call"
        );
        // `content-type: application/json` EXPLICITLY. The body is a JSON string
        // and a bare `String` body would go out as `text/plain`, which every
        // OpenAI-compatible client parses differently or not at all — a cache hit
        // must be byte-and-header indistinguishable from a real answer, or the
        // cache becomes a compatibility bug that only appears under load.
        // The hit recorded its own span (site 1 of 4) above.
        dispatch_guard.disarm();
        return cache_policy.response(
            (
                StatusCode::OK,
                axum::response::AppendHeaders([
                    (axum::http::header::CONTENT_TYPE, "application/json"),
                    (
                        axum::http::HeaderName::from_static("x-tracelane-cache"),
                        hit.tier,
                    ),
                ]),
                hit.response_json,
            )
                .into_response(),
        );
    }

    // RI-05 M1 + M4: this request's dispatch ledger — same-provider retries,
    // then any cross-provider failover hops/skips, in the order they
    // happened. Stays empty (and therefore ABSENT on the span, spec §2.1) for
    // a bench-mock call and for a clean single attempt.
    let mut dispatch_attempts: Vec<DispatchAttempt> = Vec::new();
    // OG-11: the candidates a routed request skipped before it found one to dispatch.
    extend_dispatch_attempts(&mut dispatch_attempts, std::mem::take(&mut route_skips));
    if let Some(skip) = zdr_primary_skipped.take() {
        extend_dispatch_attempts(&mut dispatch_attempts, vec![skip]);
    }
    let mut provider_result = if bench_mock {
        // Bench-only instant upstream (TRACELANE_BENCH_MOCK_UPSTREAM). Replaces
        // ONLY the network dispatch with an instant canned stream, so a load
        // test's measured latency is gateway overhead (auth, parse, untrusted
        // wrap, breaker, span emit) with ~0 provider time. Double-gated — the
        // flag is off by default and the model must be `__bench_mock*`, so a
        // normal tenant request can never reach here. See bench/gateway/README.
        crate::providers::MockProvider::new("ok")
            .chat_mock(&chat_request, provider_key.expose_secret(), tenant_id)
            .await
    } else {
        let started = std::time::Instant::now();
        let (result, mut attempts) = dispatch_with_retry(
            &state.providers,
            &chat_request,
            provider_key.expose_secret(),
            upstream,
            &model,
            tenant_id,
            crate::routing::retry_policy(
                state.failover,
                route_plan.as_ref().is_some_and(|p| p.dispatches()) || served_pooled,
            ),
            crate::routing::deadlines::Budget::for_request(
                entitlements.as_deref(),
                provider_id,
                &model,
                request_start,
            )
            .with_breaker(&state.circuit_breaker, upstream, region, &breaker_cred)
            .with_attempt(
                &attempt_security,
                provider_id,
                &model,
                &served_label,
                &provider_key,
            ),
        )
        .await;
        label_attempts(&mut attempts, served_pooled, &served_label);
        extend_dispatch_attempts(&mut dispatch_attempts, attempts);
        if result.is_ok() {
            crate::routing::stats::record(
                tenant_id.as_uuid(),
                &routing_state,
                provider_id,
                &chat_request.model,
                started.elapsed(),
            );
        }
        result
    };

    // Feed the breaker: any dispatch error (timeout / 5xx / connection) is a
    // failure outcome; the gen_ai.client.operation.exception event (ADR-032)
    // is the matching telemetry surface.
    //
    // GWY-24: a cache hit must NOT feed the breaker — it would report SUCCESS
    // for a provider that was never contacted and could hold the breaker CLOSED
    // over a dead upstream for as long as the cache kept serving. That is
    // guaranteed by control flow, not by a check here: the hit path `return`s
    // above (`if let Some(hit) = cache_hit`), so `cache_hit` is `None` on every
    // line below it. B-391 deleted the `if cache_hit.is_none()` that used to
    // wrap this — a guard the compiler could prove always true, defended by a
    // comment for a case the code excluded.
    if let Some(ok) = breaker_outcome(&provider_result) {
        crate::routing::deadlines::record_legacy(
            &state.circuit_breaker,
            upstream,
            region,
            &breaker_cred,
            ok,
            entitlements.as_deref(),
            &model,
        );
    }

    // OG-11: how many more dispatches this request may make across pool keys and
    // targets (`routing.max_attempts`). Unbounded only for a request routing never
    // touched, which keeps the pre-OG-11 failover chain exactly as it was.
    let mut attempt_budget = if route_plan.as_ref().is_some_and(|p| p.dispatches()) || served_pooled
    {
        crate::routing::limits().max_attempts.saturating_sub(1)
    } else {
        usize::MAX
    };
    // OG-11: a KEY failure (401 / 403 / 429) on one pool key moves to the NEXT key of
    // the same provider — never to another model first. Each key is its own breaker
    // credential (OG-13).
    if !bench_mock && let Some(cursor) = key_cursor.as_mut() {
        let key_env = crate::providers::ProviderRegistry::env_var_for_provider_id(provider_id);
        loop {
            let key_failure =
                matches!(&provider_result, Err(e) if crate::routing::is_key_failure(e));
            if !key_failure || attempt_budget == 0 {
                break;
            }
            let Some((label, key)) = cursor.next_key(tenant_id, provider_id, key_env).await else {
                break;
            };
            let cred =
                super::dispatch::breaker_cred(tenant_id, provider_id, &label, Some(&routing_state));
            if !state.circuit_breaker.allow(upstream, region, &cred) {
                let mut skip = skipped_failover_attempt(upstream, &model, "breaker_open");
                skip.key_label = Some(label);
                extend_dispatch_attempts(&mut dispatch_attempts, vec![skip]);
                continue;
            }
            attempt_budget -= 1;
            let started = std::time::Instant::now();
            let (result, mut attempts) = dispatch_with_retry(
                &state.providers,
                &chat_request,
                key.expose_secret(),
                upstream,
                &model,
                tenant_id,
                crate::routing::retry_policy(
                    state.failover,
                    route_plan.as_ref().is_some_and(|p| p.dispatches()) || served_pooled,
                ),
                crate::routing::deadlines::Budget::for_request(
                    entitlements.as_deref(),
                    provider_id,
                    &model,
                    request_start,
                )
                .with_breaker(&state.circuit_breaker, upstream, region, &cred)
                .with_attempt(&attempt_security, provider_id, &model, &label, &key),
            )
            .await;
            label_attempts(&mut attempts, true, &label);
            extend_dispatch_attempts(&mut dispatch_attempts, attempts);
            if let Some(ok) = breaker_outcome(&result) {
                crate::routing::deadlines::record_legacy(
                    &state.circuit_breaker,
                    upstream,
                    region,
                    &cred,
                    ok,
                    entitlements.as_deref(),
                    &model,
                );
            }
            if result.is_ok() {
                crate::routing::stats::record(
                    tenant_id.as_uuid(),
                    &routing_state,
                    provider_id,
                    &chat_request.model,
                    started.elapsed(),
                );
                identity.route.key_label = Some(label);
            }
            provider_result = result;
        }
    }

    // Opt-in CROSS-PROVIDER failover. Default OFF — the same-provider
    // path above is unchanged. Enable per request with
    // `X-Tracelane-Failover: cross-provider`. Works with no schema translation
    // because every adapter translates the universal `ChatRequest`: we simply
    // re-dispatch the same canonical request to the next provider in the chain
    // with a model that routes there. The failover provider needs the tenant's
    // own BYOK key (skipped otherwise) and must pass its own circuit breaker.
    // No new infra/state — reuses dispatch_with_retry + the per-provider key
    // store + the existing breakers. When opted in we fail over on any primary
    // error (the caller has chosen resilience over a possible extra call).
    // `Some(primary_provider)` once a cross-provider failover actually served the
    // request — threaded onto the span so the Gateway-ops rollup can count it and
    // name the primary that errored (or, GWY-49, that the ZDR prune skipped).
    let mut failover_from: Option<&'static str> = zdr_failover_from;
    // OG-11: a 5xx / timeout moves to the virtual model's NEXT target, then — only when
    // the caller opted in — the cross-provider failover chain, within the attempt
    // budget. Every hop re-checks price, ZDR, the kill switch, its breakers, the key's
    // and the workspace's policy and the request's support, exactly as failover does.
    if provider_result
        .as_ref()
        .is_err_and(|e| !e.is::<crate::routing::attempt::Denied>())
        && (cross_provider_failover || !plan_rest.is_empty())
    {
        let primary_family = provider_name_from_model(&model);
        let mut hops: Vec<(&'static str, String, Option<usize>)> = plan_rest
            .iter()
            .map(|c| {
                (
                    provider_name_from_model(&c.model),
                    c.model.clone(),
                    Some(c.target_index),
                )
            })
            .collect();
        if cross_provider_failover {
            hops.extend(
                crate::providers::failover::candidates_for(
                    primary_family,
                    &workspace_failover_models,
                    state.failover,
                )
                .into_iter()
                .map(|(p, m)| (p, m, None)),
            );
        }
        // H2 follow-up (2026-10-02): admission refused an UNPRICED primary for a budgeted
        // caller; a failover hop must not reintroduce one (`caller_budgeted`, above).
        for (fo_provider, fo_model_owned, target_index) in hops {
            if attempt_budget == 0 {
                break;
            }
            let fo_model: &str = &fo_model_owned;
            // H2: a budgeted caller never fails over to spend the gateway cannot price —
            // skipped and recorded like the other skips (fail-CLOSED on money, §10).
            if caller_budgeted
                && matches!(
                    crate::admission::token_pricing(fo_model),
                    crate::admission::Pricing::Unpriced { .. }
                )
            {
                extend_dispatch_attempts(
                    &mut dispatch_attempts,
                    vec![skipped_failover_attempt(
                        fo_provider,
                        fo_model,
                        "unpriced_under_budget",
                    )],
                );
                continue;
            }
            // GWY-49: under the constraint, a failover candidate the table does not vouch
            // for is not a candidate — skipped and recorded like the other four skips.
            if zdr_constraint.is_some() && !state.zdr.load().eligible(fo_provider) {
                extend_dispatch_attempts(
                    &mut dispatch_attempts,
                    vec![skipped_failover_attempt(
                        fo_provider,
                        fo_model,
                        "zdr_ineligible",
                    )],
                );
                continue;
            }
            if state.kill_switch.upstream_killed(fo_provider) {
                extend_dispatch_attempts(
                    &mut dispatch_attempts,
                    vec![skipped_failover_attempt(fo_provider, fo_model, "killed")],
                );
                continue;
            }
            // Fail closed on an unroutable failover candidate — skip it,
            // never default to a provider (its key would be the wrong one).
            let Some(fo_pid) = crate::providers::ProviderRegistry::provider_id_for_model(fo_model)
            else {
                extend_dispatch_attempts(
                    &mut dispatch_attempts,
                    vec![skipped_failover_attempt(
                        fo_provider,
                        fo_model,
                        "unroutable",
                    )],
                );
                continue;
            };
            // OG-20: a failover hop must not reach a model or provider the key's policy
            // denies — skipped and recorded like the other skips (fail-CLOSED).
            if !policy_allows(&claims, ws_controls.as_deref(), fo_model, fo_pid) {
                extend_dispatch_attempts(
                    &mut dispatch_attempts,
                    vec![skipped_failover_attempt(
                        fo_provider,
                        fo_model,
                        "policy_denied",
                    )],
                );
                continue;
            }
            // OG-03: the primary passed `check_supported` for ITS wire, not this one. A
            // candidate that cannot honour a field or part the request carries is not a
            // candidate — skipped and recorded like the other skips, never sent a request
            // that silently differs from the one the caller made.
            let mut fo_request = chat_request.clone();
            fo_request.model = fo_model.to_string();
            if crate::request_support::check_supported(fo_pid, &fo_request).is_err() {
                extend_dispatch_attempts(
                    &mut dispatch_attempts,
                    vec![skipped_failover_attempt(
                        fo_provider,
                        fo_model,
                        "unsupported_request",
                    )],
                );
                continue;
            }
            // OG-13: the hop's own region; OG-11: its own pool, key by key — a key
            // failure moves to the next key, a 5xx / timeout to the next hop.
            let fo_region = state.providers.upstream_region(fo_pid);
            let fo_env = crate::providers::ProviderRegistry::env_var_for_provider_id(fo_pid);
            let fo_pool = crate::routing::pool_labels(
                &crate::admission::Chat::ROUTING,
                &routing_state,
                fo_pid,
                &mut route_rng,
            );
            let mut fo_cursor = super::KeyCursor::new(fo_pool.labels);
            let mut fo_result: Option<anyhow::Result<crate::providers::ProviderStream>> = None;
            let mut fo_label = crate::db::provider_keys::DEFAULT_LABEL.to_owned();
            let mut keyed = false;
            while attempt_budget > 0 {
                // Failover keeps its skip-on-unresolvable behaviour: a provider we
                // cannot key for is simply not a failover candidate.
                let Some((label, fo_key)) = fo_cursor.next_key(tenant_id, fo_pid, fo_env).await
                else {
                    break;
                };
                if fo_key.expose_secret().is_empty() {
                    continue;
                }
                keyed = true;
                let fo_cred =
                    super::dispatch::breaker_cred(tenant_id, fo_pid, &label, Some(&routing_state));
                if !state
                    .circuit_breaker
                    .allow(fo_provider, fo_region, &fo_cred)
                {
                    let mut skip = skipped_failover_attempt(fo_provider, fo_model, "breaker_open");
                    if fo_pool.pooled {
                        skip.key_label = Some(label);
                    }
                    extend_dispatch_attempts(&mut dispatch_attempts, vec![skip]);
                    continue;
                }
                attempt_budget = attempt_budget.saturating_sub(1);
                let started = std::time::Instant::now();
                let (r, mut fo_attempts) = dispatch_with_retry(
                    &state.providers,
                    &fo_request,
                    fo_key.expose_secret(),
                    fo_provider,
                    fo_model,
                    tenant_id,
                    crate::routing::retry_policy(
                        state.failover,
                        route_plan.as_ref().is_some_and(|p| p.dispatches()) || served_pooled,
                    ),
                    crate::routing::deadlines::Budget::for_request(
                        entitlements.as_deref(),
                        fo_pid,
                        fo_model,
                        request_start,
                    )
                    .with_breaker(&state.circuit_breaker, fo_provider, fo_region, &fo_cred)
                    .with_attempt(
                        &attempt_security,
                        fo_pid,
                        fo_model,
                        &label,
                        &fo_key,
                    ),
                )
                .await;
                label_attempts(&mut fo_attempts, fo_pool.pooled, &label);
                extend_dispatch_attempts(&mut dispatch_attempts, fo_attempts);
                if let Some(ok) = breaker_outcome(&r) {
                    crate::routing::deadlines::record_legacy(
                        &state.circuit_breaker,
                        fo_provider,
                        fo_region,
                        &fo_cred,
                        ok,
                        entitlements.as_deref(),
                        fo_model,
                    );
                }
                if r.is_ok() {
                    crate::routing::stats::record(
                        tenant_id.as_uuid(),
                        &routing_state,
                        fo_pid,
                        fo_model,
                        started.elapsed(),
                    );
                }
                let next_key = matches!(&r, Err(e) if crate::routing::is_key_failure(e))
                    && fo_cursor.has_more();
                fo_label = label;
                fo_result = Some(r);
                if !next_key {
                    break;
                }
            }
            if !keyed {
                // OG-37: a customer-key-service refusal is not "no key for this provider" —
                // it is the tenant's own control saying no, so it refuses the request.
                match fo_cursor.into_failure() {
                    ProviderKey::KmsUnavailable => {
                        dispatch_guard.record_attempts(dispatch_attempts);
                        dispatch_guard.abort("kms_unavailable", None);
                        return provider_error_response(
                            StatusCode::SERVICE_UNAVAILABLE,
                            "kms_unavailable",
                            Some("customer key service unavailable"),
                            Some(fo_pid),
                            None,
                        );
                    }
                    ProviderKey::KmsDenied => {
                        dispatch_guard.record_attempts(dispatch_attempts);
                        dispatch_guard.abort("kms_access_denied", None);
                        return provider_error_response(
                            StatusCode::FORBIDDEN,
                            "kms_access_denied",
                            Some("customer key service refused access"),
                            Some(fo_pid),
                            None,
                        );
                    }
                    _ => {}
                }
                tracing::debug!(
                    provider = fo_provider,
                    "cross-provider failover skipped — no BYOK key for this provider"
                );
                extend_dispatch_attempts(
                    &mut dispatch_attempts,
                    vec![skipped_failover_attempt(
                        fo_provider,
                        fo_model,
                        "no_byok_key",
                    )],
                );
                continue;
            }
            let Some(fo_result) = fo_result else {
                continue;
            };
            if fo_result.is_ok() {
                tracing::info!(
                    from = primary_family,
                    to = fo_provider,
                    fo_model = fo_model,
                    "tracelane.failover.cross_provider.activated=true"
                );
                // Attribute everything downstream (span provider, echoed model,
                // billing) to the provider that actually served the request, and
                // mark the span so the ops rollup counts the failover + names the
                // primary that failed.
                model = fo_model.to_string();
                failover_from = Some(primary_family);
                if let Some(i) = target_index {
                    identity.route.target_index = Some(i);
                }
                identity.route.key_label = fo_pool.pooled.then(|| fo_label.clone());
                provider_result = fo_result;
                break;
            }
            provider_result = fo_result;
        }
    }
    dispatch_guard.record_route(identity.route.clone());

    let provider_stream = match provider_result {
        Ok(s) => s,
        Err(err) => {
            // Recover the typed upstream status (if any) so we can both classify
            // the failure and attach it to the telemetry.
            let http = err.downcast_ref::<crate::providers::ProviderHttpError>();
            let status_code = http.map(|e| e.status);

            //  GW-SPAN-002: a dispatch failure MUST emit the
            // gen_ai.client.operation.exception event (ADR-032/036) — the breaker
            // trip input and the observability surface. This path was previously
            // silent (no span, no event), so a hard provider outage was invisible
            // to /traces + /slo while the API returned an opaque 502.
            crate::otlp_emit::emit_operation_exception(
                tenant_id,
                upstream,
                region,
                "dispatch_failed",
                status_code,
            );

            //  #3: also publish an ERROR-status span so this failure is COUNTABLE
            // by the error-rate metric (countIf(status_code = 2)). The event above is
            // the breaker trip input; a span is what /slo + /traces actually render.
            // Without it a hard dispatch failure was invisible — a structural 0% error
            // rate regardless of real provider 401/429/404/5xx. One span here covers
            // all four typed returns below.
            let err_reason = if let Some(denied) =
                err.downcast_ref::<crate::routing::attempt::Denied>()
            {
                denied.code()
            } else if crate::routing::deadlines::Timeout::find(err.as_ref()).is_some() {
                "upstream_timeout"
            } else if http.is_some_and(crate::providers::ProviderHttpError::is_auth_rejection) {
                "provider_key_rejected"
            } else if http.is_some_and(crate::providers::ProviderHttpError::is_rate_limited) {
                "provider_rate_limited"
            } else if http.is_some_and(crate::providers::ProviderHttpError::is_model_not_found) {
                "model_not_found"
            } else if http
                .is_some_and(crate::providers::ProviderHttpError::is_unclassified_client_error)
            {
                // Countable as its own class — an upstream 4xx we could not
                // classify is NOT an outage, and folding it into
                // `provider_unavailable` inflated the error-rate metric with
                // client-side failures.
                "provider_request_rejected"
            } else {
                "provider_unavailable"
            };
            // That is this request's span; the four typed returns below must
            // not be followed by a second, `client_cancelled` one — `abort`
            // records it and disarms in one step.
            // RI-05 M1: the failure span is the one an operator opens — it carries
            // every attempt and skip that led here, not only the terminal reason.
            dispatch_guard.record_attempts(std::mem::take(&mut dispatch_attempts));
            dispatch_guard.abort(err_reason, None);
            if let Some(denied) = err.downcast_ref::<crate::routing::attempt::Denied>() {
                return Chat::refuse(denied.0.clone());
            }
            if let Some(timeout) = crate::routing::deadlines::Timeout::find(err.as_ref()) {
                return timeout.response();
            }

            // An upstream 401/403 means the tenant's BYOK provider key was
            // rejected — surface that distinctly instead of an opaque 502 (a
            // mangled/expired key otherwise read as "provider unavailable", with
            // no signal the *key* was wrong). The body carries no upstream detail.
            if http.is_some_and(crate::providers::ProviderHttpError::is_auth_rejection) {
                tracing::warn!(
                    provider = upstream,
                    status = ?status_code,
                    "provider rejected the tenant's key"
                );
                return provider_error_response(
                    StatusCode::UNAUTHORIZED,
                    "provider_key_rejected",
                    Some(
                        "the configured provider key was rejected by the upstream provider — verify the key for this provider",
                    ),
                    Some(upstream),
                    None,
                );
            }

            // An upstream 429 is NOT an outage — the caller is over quota or
            // rate-limited. Reporting "provider unavailable" sends them to debug
            // the wrong system entirely. Mirrors the breaker's 503 + Retry-After
            // shape (ADR-036/037), but 429 because the limit is the caller's, not
            // ours. Observed live: AI Studio 429s a free-tier key on gemini-2.5-pro.
            if http.is_some_and(crate::providers::ProviderHttpError::is_rate_limited) {
                tracing::warn!(
                    provider = upstream,
                    "upstream rate-limited / quota exhausted"
                );
                return super::errors::provider_error_response_retry(
                    StatusCode::TOO_MANY_REQUESTS,
                    "provider_rate_limited",
                    Some(
                        "the upstream provider rate-limited or quota-exhausted this request — retry later, or check the provider account's plan and billing",
                    ),
                    Some(upstream),
                    // OG-03 §3.4: scrubbed, truncated, and None for anything auth-shaped.
                    http.and_then(|e| e.message.as_deref()),
                    // OG-10: the PROVIDER's own wait when it gave one (header + body), so
                    // the client's backoff works; the gateway's 60 s guess only when it did not.
                    super::errors::upstream_retry_after_secs(&err),
                    Some("60"),
                );
            }

            // An upstream 404 means the model does not exist for this
            // account — the caller must change the model string, not retry. As a
            // 502 it read as a Tracelane outage. Observed live: AI Studio 404s
            // gemini-2.5-flash as "no longer available to new users".
            if http.is_some_and(crate::providers::ProviderHttpError::is_model_not_found) {
                tracing::warn!(provider = upstream, "upstream reports model not found");
                return provider_error_response_with_detail(
                    StatusCode::NOT_FOUND,
                    "model_not_found",
                    Some(
                        "the upstream provider does not recognise this model for this account — check the model name and that your provider account has access to it",
                    ),
                    Some(upstream),
                    http.and_then(|e| e.message.as_deref()),
                    None,
                );
            }

            // Any OTHER upstream 4xx. We cannot say *why* it was rejected
            // (see `is_unclassified_client_error` — a 400 is a dead key on xAI and
            // a malformed payload everywhere, and the discriminating text is in a
            // body we must not propagate), but a 4xx does prove the upstream
            // rejected the REQUEST. Reporting that as `502 provider unavailable`
            // blamed Tracelane for a client-side problem and sent callers to check
            // our status page. Mirror the upstream 4xx and name both candidates.
            if let Some(e) = http.filter(|e| e.is_unclassified_client_error()) {
                tracing::warn!(
                    provider = upstream,
                    status = e.status,
                    "upstream rejected the request (unclassified 4xx)"
                );
                let message = format!(
                    "the upstream provider rejected this request with HTTP {}. \
                     This is not a Tracelane outage — it is usually either a provider \
                     key that is invalid or expired for this account, or a request the \
                     provider could not accept (model, parameters, or payload). \
                     Verify the key for this provider, then the request itself.",
                    e.status
                );
                return provider_error_response_with_detail(
                    // Mirror the upstream status so the caller sees exactly what the
                    // provider said. 401/403/404/429 are claimed by the branches
                    // above and can never reach here; anything unrepresentable
                    // degrades to 400 (still client-class, never 5xx).
                    StatusCode::from_u16(e.status).unwrap_or(StatusCode::BAD_REQUEST),
                    "provider_request_rejected",
                    Some(&message),
                    Some(upstream),
                    // OG-03 §3.4: the upstream's own reason ("Unsupported parameter:
                    // max_tokens"), scrubbed and truncated. `None` for 407 and for anything
                    // `ProviderHttpError::from_response` judged auth-shaped.
                    e.message.as_deref(),
                    None,
                );
            }

            tracing::error!(error = %err, "provider dispatch failed after retry");
            // OG-10: a 503 that said how long to wait still maps to 502 (the existing
            // status mapping), but carries the provider's `Retry-After`.
            return super::errors::provider_error_response_retry(
                StatusCode::BAD_GATEWAY,
                "provider unavailable",
                None,
                None,
                None,
                super::errors::upstream_retry_after_secs(&err),
                None,
            );
        }
    };

    // --- Step 6: Response ---
    let is_streaming = body
        .get("stream")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let response = if is_streaming {
        // The generator's `StreamFinalizer` owns the record from its first poll
        // (B-375 a). The dispatch guard is handed INTO the generator and
        // disarmed there, once the finalizer exists — a client that hangs up
        // between this return and hyper's first poll of the body would
        // otherwise be recorded by nothing (security review M-4, 2026-09-12).
        let completion_id = format!("chatcmpl-{}", Uuid::new_v4());
        // Response-side guardrail seam inputs (owned — the SSE stream is
        // `'static` and cannot borrow the request). `system_prompt` is the
        // redacted form (what the model sees, hence what it can leak — correct
        // for R6).
        let response_inputs = crate::guardrail::ResponseInputs {
            hooks: Some(request_hooks.clone()),
            hook_events: identity.hook_events.clone(),
            tenant_id: tenant_id.clone(),
            api_key_id: claims.api_key_id().map(str::to_owned),
            project_id: claims.governance.as_ref().and_then(|g| g.project_id),
            correlation_id,
            system_prompt: crate::guardrail::context::extract_system_prompt(&chat_request)
                .map(str::to_owned),
            model: model.clone(),
            session: crate::guardrail::SessionState::fresh(identity.conversation_id.clone()),
            actor: claims.sub.clone(),
            expected_format: crate::guardrail::context::extract_expected_format(&body),
        };
        let sse = provider_stream_to_sse(
            provider_stream,
            StreamContext {
                // B-375 (b) / M-4: the armed guard rides INTO the generator.
                handover: Some(dispatch_guard),
                completion_id,
                model,
                nats: state.nats.clone(),
                tenant_id: tenant_id.clone(),
                trace_id,
                parent_span_id: inbound_parent,
                start_time: request_start,
                dispatch_ts,
                identity: identity.clone(),
                prompt_router: state.prompt_router.clone(),
                prompt_obs: prompt_obs.clone(),
                guardrail_fired,
                warn_aft_id,
                guardrail: state.guardrail.clone(),
                response_inputs,
                redaction_map: guardrail_redaction_map,
                failover_from,
                // RI-05 M1 + M4: the request's full dispatch ledger, built
                // above across the primary call and any failover hops/skips.
                dispatch_attempts,
                // GWY-43: the api_keys row id, and ONLY when an API key authorised
                // the request. A session has no key, and `claims.sub` would hand back
                // a WorkOS user id — a different namespace in the same column.
                api_key_id: claims.api_key_id().map(str::to_owned),
                // GWY-48, span site 3 of 4 — THE ONE THAT DID NOT EXIST. This
                // function carried no request content at all before; if the streamed
                // span lacks `gen_ai_request_max_tokens`, OBS-52's missing-max_tokens
                // check fires on every streamed request, and a detector that flags
                // the absence of its own instrumentation is worse than none.
                request_config: request_config.clone(),
                online_eval: online_eval_pending,
                meters: state.meters.clone(),
                // OBS-51 step 3a: the input half of the deterministic
                // token-count fallback, computed ONCE here rather than
                // carrying the message text itself into the generator.
                input_bytes_for_estimate: serde_json::to_vec(&chat_request.messages)
                    .map(|v| v.len())
                    .unwrap_or(0),
                // GWY-53: the same decision the buffered path gets.
                capture,
                captured_input: CapturedInput::build(capture, &chat_request),
            },
        );
        Sse::new(sse).into_response()
    } else {
        let response_inputs = crate::guardrail::ResponseInputs {
            hooks: Some(request_hooks.clone()),
            hook_events: identity.hook_events.clone(),
            tenant_id: tenant_id.clone(),
            api_key_id: claims.api_key_id().map(str::to_owned),
            project_id: claims.governance.as_ref().and_then(|g| g.project_id),
            correlation_id,
            system_prompt: crate::guardrail::context::extract_system_prompt(&chat_request)
                .map(str::to_owned),
            model: model.clone(),
            session: crate::guardrail::SessionState::fresh(identity.conversation_id.clone()),
            actor: claims.sub.clone(),
            expected_format: crate::guardrail::context::extract_expected_format(&body),
        };
        let resp = buffer_provider_stream(
            provider_stream,
            &model,
            &state,
            tenant_id,
            trace_id,
            inbound_parent,
            request_start,
            dispatch_ts,
            &identity,
            prompt_obs,
            guardrail_fired,
            warn_aft_id,
            state.guardrail.clone(),
            response_inputs,
            guardrail_redaction_map,
            failover_from,
            // RI-05 M1 + M4: the request's full dispatch ledger, built above
            // across the primary call and any failover hops/skips.
            dispatch_attempts,
            claims.api_key_id(),
            state.semantic_cache.clone(),
            cache_key,
            CapturedInput::build(capture, &chat_request),
            // GWY-48, span site 2 of 4.
            request_config,
            online_eval_pending,
            capture,
        )
        .await;
        // The buffered path recorded its span (success or error) inside
        // `buffer_provider_stream`; a client that hung up DURING that await
        // dropped this future above this line, and the guard's `Drop` recorded
        // the cancellation instead.
        dispatch_guard.disarm();
        resp.into_response()
    };
    cache_policy.response(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const UUID_AB: &str = "00000000-0000-0000-0000-0000000000ab";

    // ── rev6 N3: what the semantic cache tier may embed with, per request ──

    fn embed_models() -> Vec<String> {
        vec![
            "text-embedding-3-small".to_owned(),
            "mistral-embed".to_owned(),
        ]
    }

    #[test]
    fn rev6_n3_a_redacted_request_reaches_no_embedding_provider() {
        let claims = crate::auth::dev_stub_claims(crate::auth::AuthMethod::ApiKey);
        assert_eq!(
            semantic_tier_models(&embed_models(), false, &claims, None, None),
            embed_models(),
            "the control: an unredacted request with no policy may use every model"
        );
        assert!(
            semantic_tier_models(&embed_models(), true, &claims, None, None).is_empty(),
            "R2 redacted the request: its text must reach no embedding provider"
        );
    }

    #[test]
    fn rev6_n3_workspace_blocks_and_policy_gate_the_embedding_provider() {
        let claims = crate::auth::dev_stub_claims(crate::auth::AuthMethod::ApiKey);
        let blocked_provider = crate::controls::WorkspaceControls::from_row(
            None,
            None,
            vec![],
            vec!["openai".into()],
            vec![],
        );
        assert_eq!(
            semantic_tier_models(
                &embed_models(),
                false,
                &claims,
                Some(&blocked_provider),
                None
            ),
            vec!["mistral-embed".to_owned()]
        );
        let blocked_model = crate::controls::WorkspaceControls::from_row(
            None,
            None,
            vec!["mistral*".into()],
            vec![],
            vec![],
        );
        assert_eq!(
            semantic_tier_models(&embed_models(), false, &claims, Some(&blocked_model), None),
            vec!["text-embedding-3-small".to_owned()]
        );
        let ws_policy = crate::controls::WorkspaceControls::from_row(
            Some(&json!({"providers": {"deny": ["openai", "mistral"]}})),
            None,
            vec![],
            vec![],
            vec![],
        );
        assert!(
            semantic_tier_models(&embed_models(), false, &claims, Some(&ws_policy), None)
                .is_empty(),
            "the workspace policy denies both embedding providers"
        );
    }

    #[test]
    fn rev6_n3_the_keys_policy_denial_gates_the_embedding_provider() {
        let mut claims = crate::auth::dev_stub_claims(crate::auth::AuthMethod::ApiKey);
        claims.governance = tracelane_shared::key_policy::Governance::from_columns(
            None,
            None,
            None,
            Some(&json!({"models": {"deny": ["text-embedding*"]}})),
        )
        .map(std::sync::Arc::new);
        assert!(claims.governance.is_some());
        assert_eq!(
            semantic_tier_models(&embed_models(), false, &claims, None, None),
            vec!["mistral-embed".to_owned()]
        );
    }

    #[test]
    fn rev6_n3_zdr_required_admits_only_zdr_eligible_embedding_providers() {
        let claims = crate::auth::dev_stub_claims(crate::auth::AuthMethod::ApiKey);
        let caps = crate::zdr::ZdrCapabilities::from_rows([
            ("openai".to_owned(), "default".to_owned()),
            ("mistral".to_owned(), "none".to_owned()),
        ]);
        assert_eq!(
            semantic_tier_models(&embed_models(), false, &claims, None, Some(&caps)),
            vec!["text-embedding-3-small".to_owned()]
        );
        assert!(
            semantic_tier_models(
                &embed_models(),
                false,
                &claims,
                None,
                Some(&crate::zdr::ZdrCapabilities::unavailable())
            )
            .is_empty(),
            "an unloaded ZDR table vouches for nothing (fail-closed)"
        );
        assert!(
            semantic_tier_models(
                &["nosuchvendor-embed-x".to_owned()],
                false,
                &claims,
                None,
                None
            )
            .is_empty(),
            "an unroutable embedding model is left out"
        );
    }

    // ── RI-05 M4: the failover-skip token mapping, as a pure function ──
    //
    // NOT COVERED here: which of the four causes actually FIRES at which of
    // the four `continue` sites in the real failover loop (a killed
    // upstream, a denying breaker, an unroutable model, an empty BYOK key) —
    // that needs a live/mocked `AppState` per cause and is integration-level
    // work this slice does not add. What IS covered: the four tokens this
    // spec names are exactly the four the constructor can produce, and each
    // one round-trips through the struct correctly.
    #[test]
    fn skipped_failover_attempt_carries_the_closed_token_set() {
        for reason in [
            "no_byok_key",
            "breaker_open",
            "killed",
            "unroutable",
            "zdr_ineligible",
            "unsupported_request",
            "unpriced_under_budget",
        ] {
            let a = skipped_failover_attempt("openai", "gpt-4o", reason);
            assert_eq!(a.outcome, "skipped");
            assert_eq!(a.provider, "openai");
            assert_eq!(a.model, "gpt-4o");
            assert_eq!(a.reason.as_deref(), Some(reason));
            assert_eq!(
                a.status, None,
                "a skipped candidate was never dispatched — no status"
            );
            assert_eq!(
                a.took_ms, 0,
                "a skipped candidate was never dispatched — no elapsed time"
            );
        }
    }

    #[test]
    fn prompt_observation_carries_only_the_version_id() {
        let body = json!({
            "model": "claude-sonnet-4-6",
            "tracelane_prompt_version_id": UUID_AB,
            "tracelane_prompt_name": "support-bot",
            "tracelane_prompt_env": "staging"
        });
        let obs = PromptObservation::from_body(&body).expect("should parse");
        assert_eq!(obs.version_id, Uuid::parse_str(UUID_AB).unwrap());
    }

    /// `tracelane_prompt_name` is no longer required, because it only ever
    /// selected a flip target and the hot path can no longer flip.
    #[test]
    fn prompt_observation_parses_without_a_name() {
        let body = json!({ "tracelane_prompt_version_id": UUID_AB });
        let obs = PromptObservation::from_body(&body).expect("should parse");
        assert_eq!(obs.version_id, Uuid::parse_str(UUID_AB).unwrap());
    }

    /// THE ENV FIELD IS INERT AND MUST STAY INERT. It used to decide whether an
    /// observation could mutate production, and it defaulted to `Production`
    /// when absent OR unparseable. Nothing on the chat path reads it now; this
    /// asserts a body claiming production cannot be distinguished from one that
    /// says nothing, because neither can reach a flip.
    #[test]
    fn prompt_observation_ignores_a_claimed_env() {
        let claims_prod = PromptObservation::from_body(&json!({
            "tracelane_prompt_version_id": UUID_AB,
            "tracelane_prompt_env": "production"
        }))
        .expect("should parse");
        let says_nothing =
            PromptObservation::from_body(&json!({ "tracelane_prompt_version_id": UUID_AB }))
                .expect("should parse");
        assert_eq!(claims_prod.version_id, says_nothing.version_id);
    }

    #[test]
    fn prompt_observation_none_without_correlation() {
        // Ad-hoc traffic — no prompt fields → no observation.
        assert!(PromptObservation::from_body(&json!({ "model": "x" })).is_none());
        // Unparseable uuid → None (never feeds a garbage version id).
        assert!(
            PromptObservation::from_body(&json!({
                "tracelane_prompt_version_id": "not-a-uuid",
                "tracelane_prompt_name": "p"
            }))
            .is_none()
        );
    }

    // BILL-01 / ADR-076 (2026-09-13): the Slack quota-webhook SSRF gate tests
    // that used to sit here tested `notify_quota_exceeded_async`, which is
    // DELETED along with the whole monthly trace-count hard cap — ingest is
    // never blocked by billing state, on any tier, so there is no more
    // quota-exceeded Slack notification to validate the URL of. The comment
    // header describing them is removed with them rather than left dangling
    // over an empty section.
}

#[cfg(all(test, debug_assertions))]
mod route_tests {
    use super::*;
    use serde_json::json;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// The three cancel tests read and assert on ONE process-wide counter
    /// (`REQUESTS_CANCELLED_IN_DISPATCH`). Run in parallel — CI's 8 threads,
    /// not the 2 the local gate uses — one test's cancellation lands between
    /// another's `before` read and its assertion (the CI runner's first run,
    /// 2026-09-12: `a_request_that_completes…` read 1 where it expected 0).
    /// One lock, held for the whole test.
    static CANCEL_COUNTER: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    use super::super::dispatch::REQUESTS_CANCELLED_IN_DISPATCH;
    use crate::handler_harness::{
        LoopbackBypassGuard, authed, body_json, registry_pointing_ollama_at, test_state,
    };

    #[test]
    fn cached_answer_capture_obeys_output_policy_and_field_cap() {
        let body = json!({
            "id": "cached-id",
            "choices": [{"finish_reason": "stop", "message": {"content": "a".repeat(70_000)}}]
        })
        .to_string();
        let mut attrs = tracelane_shared::SpanAttributes::default();
        capture_cached_answer(
            &mut attrs,
            crate::server::config::ContentCapture::OFF,
            &body,
        );
        assert!(attrs.gen_ai_output_messages.is_none());
        assert_eq!(attrs.gen_ai_response_id.as_deref(), Some("cached-id"));
        let capture = crate::server::config::ContentCapture {
            input: false,
            output: true,
            max_field_bytes: 64 * 1024,
        };
        capture_cached_answer(&mut attrs, capture, &body);
        let text = attrs.gen_ai_output_messages.as_ref().unwrap()[0]["content"]
            .as_str()
            .unwrap();
        assert!(text.len() <= 64 * 1024);
        assert!(text.ends_with("…[truncated]"));
    }

    /// rev6 N3, through the REAL handler: the semantic tier embeds the request's text
    /// with the tenant's key, so a key whose policy denies the embedding model sends
    /// NOTHING to the embeddings endpoint — while the same request from an unrestricted
    /// caller does (the control). RED before the fix: the tier embedded with every
    /// configured model regardless of the caller's policy.
    #[tokio::test]
    async fn rev6_n3_the_semantic_tier_honours_the_keys_policy_on_the_embedding_model() {
        let _serial = CANCEL_COUNTER.lock().await;
        let _bypass = LoopbackBypassGuard::new();
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/chat/completions"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id": "n3", "object": "chat.completion", "model": "ollama/llama3",
                "choices": [{"index": 0, "finish_reason": "stop", "message": {"role": "assistant", "content": "ok"}}],
                "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}
            })))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/v1/embeddings"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "object": "list", "model": "ollama/embed",
                "data": [{"object": "embedding", "index": 0, "embedding": [1.0, 0.0, 0.0]}],
                "usage": {"prompt_tokens": 1, "total_tokens": 1}
            })))
            .mount(&server)
            .await;
        let mut state = test_state(registry_pointing_ollama_at(server.uri()));
        let cfg =
            crate::server::config::parse("semantic_cache:\n  embedding_models: ollama/embed\n")
                .unwrap();
        state.semantic_cache = Some(Arc::new(crate::semantic_cache::SemanticCache::new(
            crate::clickhouse_query::ch_client(server.uri()),
            state.providers.clone(),
            cfg.semantic_cache().unwrap().clone(),
        )));
        with_capture_entitlements(&mut state);
        async fn embeddings(server: &MockServer) -> usize {
            server
                .received_requests()
                .await
                .unwrap_or_default()
                .iter()
                .filter(|r| r.url.path() == "/v1/embeddings")
                .count()
        }

        let mut denied = crate::auth::dev_stub_claims(crate::auth::AuthMethod::ApiKey);
        denied.governance = tracelane_shared::key_policy::Governance::from_columns(
            None,
            None,
            None,
            Some(&json!({"models": {"deny": ["ollama/embed"]}})),
        )
        .map(Arc::new);
        {
            let _c = crate::auth::test_claims::Guard::set(denied);
            let body =
                json!({"model":"ollama/llama3","messages":[{"role":"user","content":"n3 denied"}]});
            let r = chat_completions_handler(State(state.clone()), authed(), Json(body)).await;
            assert_eq!(r.status(), StatusCode::OK);
        }
        for _ in 0..20 {
            tokio::task::yield_now().await;
        }
        assert_eq!(
            embeddings(&server).await,
            0,
            "the key's policy denies the embedding model — its text must not be embedded"
        );

        // The control: an unrestricted caller's miss does embed.
        let body =
            json!({"model":"ollama/llama3","messages":[{"role":"user","content":"n3 control"}]});
        let r = chat_completions_handler(State(state), authed(), Json(body)).await;
        assert_eq!(r.status(), StatusCode::OK);
        assert!(embeddings(&server).await >= 1, "the control must embed");
    }

    /// OG-51: the response cache is private by default — a workspace is cached only while it
    /// records both prompt and response text — so a test that expects a hit says so.
    fn with_capture_entitlements(state: &mut AppState) {
        use crate::entitlement_cache::{EntitlementCache, ResolvedEntitlements};
        let mut e = ResolvedEntitlements::deny_all();
        e.content_capture = crate::db::workspace_capture::WorkspaceCapture {
            input: true,
            output: true,
        };
        state.entitlements = Some(Arc::new(EntitlementCache::new(Arc::new(move |_t| {
            let e = e.clone();
            Box::pin(async move { Ok(e) })
        }))));
    }

    #[tokio::test]
    async fn request_cache_bypass_never_serves_a_warm_answer() {
        let _serial = CANCEL_COUNTER.lock().await;
        let _bypass = LoopbackBypassGuard::new();
        let server = MockServer::start().await;
        let reply = |content: &str| {
            json!({
                "id": "cache-control-proof", "object": "chat.completion", "model": "ollama/llama3",
                "choices": [{"index": 0, "finish_reason": "stop", "message": {"role": "assistant", "content": content}}],
                "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}
            })
        };
        Mock::given(method("POST"))
            .and(path("/v1/chat/completions"))
            .respond_with(ResponseTemplate::new(200).insert_header("content-type", "text/event-stream").set_body_string("data: {\"choices\":[{\"delta\":{\"content\":\"fresh\"},\"finish_reason\":\"stop\"}]}\n\ndata: [DONE]\n\n"))
            .expect(1)
            .mount(&server)
            .await;
        let mut state = test_state(registry_pointing_ollama_at(server.uri()));
        let cfg =
            crate::server::config::parse("semantic_cache:\n  embedding_models: ollama/llama3\n")
                .unwrap();
        let cache = Arc::new(crate::semantic_cache::SemanticCache::new(
            crate::clickhouse_query::ch_client(server.uri()),
            state.providers.clone(),
            cfg.semantic_cache().unwrap().clone(),
        ));
        let body = json!({"model":"ollama/llama3","messages":[{"role":"user","content":"hi"}]});
        let request: tracelane_shared::ChatRequest = serde_json::from_value(body.clone()).unwrap();
        let key = crate::semantic_cache::request_key(&request);
        cache
            .store(
                &crate::handler_harness::dev_tenant(),
                "ollama/llama3",
                &key,
                &reply("cached").to_string(),
                1,
                1,
                0.0,
                Uuid::new_v4(),
            )
            .await;
        state.semantic_cache = Some(cache);
        with_capture_entitlements(&mut state);
        // The span sink is process-wide and every handler test shares the dev tenant, so the
        // hit's span is found by THIS request's trace id, never by "any hit for the tenant".
        let trace = Uuid::new_v4();
        let mut first_headers = authed();
        first_headers.insert("x-trace-id", trace.to_string().parse().unwrap());
        let first =
            chat_completions_handler(State(state.clone()), first_headers, Json(body.clone())).await;
        assert_eq!(first.headers().get("x-tracelane-cache").unwrap(), "exact");
        assert_eq!(
            body_json(first).await["choices"][0]["message"]["content"],
            "cached"
        );
        let cached_span = crate::otlp_emit::test_sink::for_trace(trace)
            .into_iter()
            .find(|s| s.attributes.tracelane_semantic_cache_hit == Some(true))
            .expect("cache hit span");
        assert_eq!(
            cached_span.attributes.gen_ai_response_id.as_deref(),
            Some("cache-control-proof")
        );
        assert_eq!(
            cached_span.attributes.gen_ai_response_finish_reasons,
            Some(vec!["stop".into()])
        );
        let mut headers = authed();
        headers.insert("x-tracelane-cache", "bypass".parse().unwrap());
        let fresh =
            chat_completions_handler(State(state.clone()), headers, Json(body.clone())).await;
        assert_eq!(fresh.status(), StatusCode::OK);
        assert_eq!(
            fresh.headers().get("x-tracelane-cache").unwrap(),
            "bypass",
            "request opt-out must not reuse a warm response"
        );
        assert_eq!(
            body_json(fresh).await["choices"][0]["message"]["content"],
            "fresh"
        );
        // Bypass must not overwrite the shared entry either.
        let after = chat_completions_handler(State(state), authed(), Json(body)).await;
        assert_eq!(
            body_json(after).await["choices"][0]["message"]["content"],
            "cached"
        );
    }

    // ── B-375 (b): a client that hangs up while the provider is still being
    // awaited leaves a record. Driven through the REAL handler — the first
    // in-process test of `chat_completions_handler` (B-385 wants more). ──

    #[tokio::test]
    async fn client_cancel_during_dispatch_records_a_cancelled_request() {
        let _serial = CANCEL_COUNTER.lock().await;
        let _bypass = LoopbackBypassGuard::new();
        let server = MockServer::start().await;
        // The provider answers after 1.5 s; the client gives up at 300 ms.
        Mock::given(method("POST"))
            .and(path("/v1/chat/completions"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_delay(std::time::Duration::from_millis(1500))
                    .set_body_json(json!({
                        "id": "chatcmpl-x", "object": "chat.completion", "model": "ollama/llama3",
                        "choices": [{"index": 0, "finish_reason": "stop",
                                     "message": {"role": "assistant", "content": "late"}}],
                        "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}
                    })),
            )
            .mount(&server)
            .await;
        let state = test_state(registry_pointing_ollama_at(server.uri()));
        let body = json!({
            "model": "ollama/llama3",
            "messages": [{"role": "user", "content": "hi"}]
        });

        let before = REQUESTS_CANCELLED_IN_DISPATCH.load(std::sync::atomic::Ordering::Relaxed);
        let handler = Box::pin(chat_completions_handler(State(state), authed(), Json(body)));
        // `select!` DROPS the losing future — exactly what hyper does to the
        // handler when the connection closes.
        tokio::select! {
            _ = handler => panic!("the provider answers after 1.5 s; the handler must still be in flight at 300 ms"),
            () = tokio::time::sleep(std::time::Duration::from_millis(300)) => {}
        }
        assert_eq!(
            REQUESTS_CANCELLED_IN_DISPATCH.load(std::sync::atomic::Ordering::Relaxed) - before,
            1,
            "dropping the handler mid-dispatch must record exactly one cancelled request"
        );
    }

    /// Security review M-4 (2026-09-12): the streaming branch used to disarm the
    /// dispatch guard on the way out and build the `StreamFinalizer` inside the
    /// generator on its FIRST POLL — so a client that hung up between the
    /// handler's return and hyper's first poll of the body was recorded by
    /// nothing. Now the guard rides into the generator and disarms only once the
    /// finalizer exists; a never-polled body drops the guard armed, and that
    /// records the cancellation.
    #[tokio::test]
    async fn a_stream_dropped_before_its_first_poll_is_recorded_as_cancelled() {
        let _serial = CANCEL_COUNTER.lock().await;
        let _bypass = LoopbackBypassGuard::new();
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/chat/completions"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "text/event-stream")
                    .set_body_string(
                        "data: {\"id\":\"chatcmpl-z\",\"object\":\"chat.completion.chunk\",\"model\":\"ollama/llama3\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"hi\"},\"finish_reason\":null}]}\n\n\
                         data: [DONE]\n\n",
                    ),
            )
            .mount(&server)
            .await;
        let state = test_state(registry_pointing_ollama_at(server.uri()));
        let body = json!({
            "model": "ollama/llama3",
            "stream": true,
            "messages": [{"role": "user", "content": "hi"}]
        });
        let before = REQUESTS_CANCELLED_IN_DISPATCH.load(std::sync::atomic::Ordering::Relaxed);
        let resp = chat_completions_handler(State(state), authed(), Json(body)).await;
        assert_eq!(resp.status(), StatusCode::OK);
        // Hang up WITHOUT polling the body once: hyper drops the response, the
        // generator is never entered, no finalizer is ever built.
        drop(resp);
        assert_eq!(
            REQUESTS_CANCELLED_IN_DISPATCH.load(std::sync::atomic::Ordering::Relaxed) - before,
            1,
            "a streamed response dropped before its first poll must record exactly one cancelled request"
        );
    }

    /// BILL-01 / ADR-076 §5, spec §0.4: **ingest is NEVER blocked by billing state.**
    /// The tenant here resolves `deny_all()` — every included allowance is ZERO,
    /// `overage_allowed` is false, the outage-default plan — and two consecutive chats
    /// are still served 200. Before BILL-01 the admission pipeline carried a
    /// `Step::Quota` that returned 429 above a hard cap; that step, its type and its
    /// refusal no longer exist, and this test is what keeps them from coming back:
    /// there is no allowance a request can exhaust on the request path.
    /// (`evals/pain-points/PP-RATELIMIT-OVERAGE.eval.ts` asserts this test EXISTS.)
    #[tokio::test]
    async fn ingest_is_never_blocked_by_billing_state() {
        let _serial = CANCEL_COUNTER.lock().await;
        let _bypass = LoopbackBypassGuard::new();
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/chat/completions"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id": "chatcmpl-nb", "object": "chat.completion", "model": "ollama/llama3",
                "choices": [{"index": 0, "finish_reason": "stop",
                             "message": {"role": "assistant", "content": "served"}}],
                "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}
            })))
            .mount(&server)
            .await;
        let mut state = test_state(registry_pointing_ollama_at(server.uri()));
        let zero_allowance: crate::entitlement_cache::ResolveFn = Arc::new(|_t| {
            Box::pin(async {
                let e = crate::entitlement_cache::ResolvedEntitlements::deny_all();
                assert_eq!(
                    e.ingest_bytes_included,
                    Some(0),
                    "the fixture must be a zero allowance"
                );
                assert!(!e.overage_allowed, "the fixture must forbid overage");
                Ok(e)
            })
        });
        state.entitlements = Some(Arc::new(crate::entitlement_cache::EntitlementCache::new(
            zero_allowance,
        )));
        let body = json!({
            "model": "ollama/llama3",
            "messages": [{"role": "user", "content": "hi"}]
        });
        for i in 1..=2 {
            let resp =
                chat_completions_handler(State(state.clone()), authed(), Json(body.clone())).await;
            assert_eq!(
                resp.status(),
                StatusCode::OK,
                "request {i} at zero allowance must be served: {:?}",
                body_json(resp).await
            );
        }
    }

    #[tokio::test]
    async fn a_request_that_completes_does_not_count_as_cancelled() {
        let _serial = CANCEL_COUNTER.lock().await;
        let _bypass = LoopbackBypassGuard::new();
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/chat/completions"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id": "chatcmpl-y", "object": "chat.completion", "model": "ollama/llama3",
                "choices": [{"index": 0, "finish_reason": "stop",
                             "message": {"role": "assistant", "content": "on time"}}],
                "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}
            })))
            .mount(&server)
            .await;
        let state = test_state(registry_pointing_ollama_at(server.uri()));
        let body = json!({
            "model": "ollama/llama3",
            "messages": [{"role": "user", "content": "hi"}]
        });
        let before = REQUESTS_CANCELLED_IN_DISPATCH.load(std::sync::atomic::Ordering::Relaxed);
        let resp = chat_completions_handler(State(state), authed(), Json(body)).await;
        assert_eq!(resp.status(), StatusCode::OK, "{:?}", body_json(resp).await);
        assert_eq!(
            REQUESTS_CANCELLED_IN_DISPATCH.load(std::sync::atomic::Ordering::Relaxed) - before,
            0,
            "a completed request must not trip the dispatch guard"
        );
    }

    #[tokio::test]
    async fn an_unroutable_model_error_span_keeps_opted_in_request_input() {
        let mut state = test_state(crate::providers::ProviderRegistry::new().unwrap());
        let mut grant = crate::entitlement_cache::ResolvedEntitlements::deny_all();
        grant.content_capture = crate::db::workspace_capture::WorkspaceCapture {
            input: true,
            output: true,
        };
        state.entitlements = Some(Arc::new(crate::entitlement_cache::EntitlementCache::new(
            Arc::new(move |_| {
                let resolved = grant.clone();
                Box::pin(async move { Ok(resolved) })
            }),
        )));
        let trace = Uuid::new_v4();
        let mut headers = authed();
        headers.insert("x-trace-id", trace.to_string().parse().unwrap());
        let body = json!({
            "model":"no-such-model-xyz-9",
            "messages":[{"role":"user","content":"CANARY_ERROR_INPUT"}]
        });
        let resp = chat_completions_handler(State(state), headers, Json(body)).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let spans = crate::otlp_emit::test_sink::for_trace(trace);
        assert_eq!(spans.len(), 1);
        let input = spans[0]
            .attributes
            .gen_ai_input_messages
            .as_ref()
            .expect("error span input");
        assert!(input.to_string().contains("CANARY_ERROR_INPUT"));
    }

    #[tokio::test]
    async fn a_provider_client_error_span_keeps_opted_in_request_input() {
        let _bypass = LoopbackBypassGuard::new();
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/chat/completions"))
            .respond_with(ResponseTemplate::new(400).set_body_json(json!({
                "error": {"message":"bad request"}
            })))
            .mount(&server)
            .await;
        let mut state = test_state(registry_pointing_ollama_at(server.uri()));
        let mut grant = crate::entitlement_cache::ResolvedEntitlements::deny_all();
        grant.content_capture = crate::db::workspace_capture::WorkspaceCapture {
            input: true,
            output: true,
        };
        state.entitlements = Some(Arc::new(crate::entitlement_cache::EntitlementCache::new(
            Arc::new(move |_| {
                let resolved = grant.clone();
                Box::pin(async move { Ok(resolved) })
            }),
        )));
        let trace = Uuid::new_v4();
        let mut headers = authed();
        headers.insert("x-trace-id", trace.to_string().parse().unwrap());
        let body = json!({
            "model":"ollama/llama3",
            "messages":[{"role":"user","content":"CANARY_PROVIDER_4XX"}]
        });
        let resp = chat_completions_handler(State(state), headers, Json(body)).await;
        assert!(!resp.status().is_success());
        let spans = crate::otlp_emit::test_sink::for_trace(trace);
        assert_eq!(spans.len(), 1);
        let input = spans[0]
            .attributes
            .gen_ai_input_messages
            .as_ref()
            .expect("error span input");
        assert!(input.to_string().contains("CANARY_PROVIDER_4XX"));
    }
}

/// A cache hit serves this exact JSON body. Derive the span's response facts from it,
/// while leaving output content behind the request's capture decision.
fn capture_cached_answer(
    attrs: &mut tracelane_shared::SpanAttributes,
    capture: super::config::ContentCapture,
    body: &str,
) {
    let Ok(response) = serde_json::from_str::<serde_json::Value>(body) else {
        return;
    };
    attrs.gen_ai_response_id = response
        .get("id")
        .and_then(|v| v.as_str())
        .map(str::to_owned);
    let choice = &response["choices"][0];
    attrs.gen_ai_response_finish_reasons = choice["finish_reason"]
        .as_str()
        .map(|reason| vec![reason.to_owned()]);
    let text = choice["message"]["content"].as_str().unwrap_or_default();
    let calls: Vec<(Option<String>, Option<String>, String)> = choice["message"]["tool_calls"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|call| {
            (
                call["id"].as_str().map(str::to_owned),
                call["function"]["name"].as_str().map(str::to_owned),
                call["function"]["arguments"]
                    .as_str()
                    .unwrap_or_default()
                    .to_owned(),
            )
        })
        .collect();
    if let Some(output) = CapturedOutput::build(capture, text, &calls) {
        output.apply(attrs);
    }
}
